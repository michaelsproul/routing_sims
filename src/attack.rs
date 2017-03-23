// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.1.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

// Attack strategies

use node::{Prefix, NodeName, NodeData};
use net::{Network, Groups, Group};
use rand::{thread_rng, Rng};

// Number of attacking nodes.
const ATTACK_SIZE: usize = 300;

// Target number of old nodes.
const VANGUARD_SIZE: usize = 100;

// Target number of middle-aged nodes.
const INFANTRY_SIZE: usize = 100;

// Age for a node to be considered old/part of the vanguard.
const VANGUARD_AGE: u32 = 5;

const INFANTRY_AGE: u32 = 3;

// If a node reaches this age, consider killing it off more aggressively.
const TOO_OLD: u32 = 8;

const YOUNG_CUTOFF: u32 = 3;

// Number of top groups to leave alone during churn.
// const CUTOFF: u32 = 3;

/// Determines a few things about how attacks work.
///
/// A clone is made for each simulation, which may hold mutable state.
/// This state is lost at the end of the simulation.
pub trait AttackStrategy {
    /// Called when splitting occurs on all malicious nodes, with their old and new names and
    /// prefixes.
    ///
    /// Default implementation: do nothing.
    fn on_split(&mut self,
                _old_prefix: Prefix,
                _new_prefix: Prefix,
                _node_name: NodeName,
                _node_data: &NodeData) {
    }

    /// Called when a malicious node is added or moved and told its new name. If moved, the method
    /// is also passed the old name. This should return true only
    /// if the attacker decides to reset this malicious node now (before doing proof-of-work).
    ///
    /// Group prefix can be obtained via `net.find_prefix(name)`.
    ///
    /// Default implementation: return false (do not split).
    fn reset_on_new_name(&mut self,
                         _net: &Network,
                         _old_name: Option<NodeName>,
                         _new_name: NodeName,
                         _node_data: &NodeData)
                         -> bool {
        false
    }

    fn force_to_rejoin(&mut self, _net: &Network, _ddos: bool) -> Option<(Prefix, NodeName)> {
        None
    }
}

/// Strategy which does not involve any targetting.
#[derive(Clone)]
pub struct UntargettedAttack;

impl AttackStrategy for UntargettedAttack {
    fn reset_on_new_name(&mut self,
        net: &Network,
        old_name: Option<NodeName>,
        new_name: NodeName,
        node_data: &NodeData) -> bool {

        if old_name.is_none() {
            // Work out whether to accept this name for this new node.
            !keep_fodder_name(net, new_name)
        } else {
            // Work out whether to keep this node alive now that it's relocating.
            !accept_relocation(net, new_name, *node_data)
        }
    }

    fn force_to_rejoin(&mut self, net: &Network, allow_ddos: bool) -> Option<(Prefix, NodeName)> {
        if allow_ddos {
            // TODO: inter-section collusion.
            select_node_to_evict_ddos(net)
        } else {
            select_node_to_evict_no_ddos(net)
        }
    }
}

fn malicious_nodes(group: &Group) -> Vec<(NodeName, NodeData)> {
    group.iter()
        .filter(|&(_, data)| data.is_malicious())
        .map(|(&name, &data)| (name, data))
        .collect()
}

fn num_infantry(nodes: &[(NodeName, NodeData)]) -> usize {
    nodes.iter()
        .filter(|&&(_, data)| data.age() >= INFANTRY_AGE && data.age() < VANGUARD_AGE)
        .count()
}

fn num_vanguard(nodes: &[(NodeName, NodeData)]) -> usize {
    nodes.iter()
        .filter(|&&(_, data)| data.age() >= VANGUARD_AGE)
        .count()
}

fn keep_fodder_name(net: &Network, name: NodeName) -> bool {
    let prefix = net.find_prefix(name);

    let most_malicious = most_malicious_groups(net.groups());

    if most_malicious.len() < 4 {
        // TODO: ??
        return true;
    }

    let q3 = most_malicious.len() / 4;
    let q1 = q3 + most_malicious.len() / 2;

    most_malicious[q3..q1].iter().find(|&&(p, _)| p == prefix).is_some()
}

fn total_infantry_and_vanguard(groups: &Groups) -> (usize, usize) {
    groups.values()
        .map(|group| {
            let our_nodes = malicious_nodes(group);
            (num_infantry(&our_nodes), num_vanguard(&our_nodes))
        })
        .fold((0, 0), |(x1, y1), (x2, y2)| (x1 + x2, y1 + y2))
}

fn accept_relocation(net: &Network, name: NodeName, data: NodeData) -> bool {
    let prefix = net.find_prefix(name);

    let most_malicious = most_malicious_groups(net.groups());

    if most_malicious.len() < 4 {
        // potentially dodgy
        return true;
    }

    let q3 = most_malicious.len() / 4;
    let q2 = most_malicious.len();
    let q1 = q3 + most_malicious.len() / 2;
    let top_40 = (4 * most_malicious.len()) / 10;

    if data.age() <= YOUNG_CUTOFF {
        // Keep if in middle 50%.
        most_malicious[q3..q1].iter().find(|&&(p, _)| p == prefix).is_some()
    } else if data.age() <= 6 {
        most_malicious[..q2].iter().find(|&&(p, _)| p == prefix).is_some()
    } else {
        most_malicious[..top_40].iter().find(|&&(p, _)| p == prefix).is_some()
    }
}

fn select_node_to_evict_ddos(_net: &Network) -> Option<(Prefix, NodeName)> {
    None
}

fn select_node_to_evict_no_ddos(net: &Network) -> Option<(Prefix, NodeName)> {
    // Select a young node from amongst the bottom 50% of controlled sections.
    let mut most_malicious = most_malicious_groups(net.groups());

    if most_malicious.len() < 4 {
        return None;
    }

    let half = most_malicious.len() / 4;
    let mut bottom_half = most_malicious.split_off(half);
    let mut rng = thread_rng();
    rng.shuffle(&mut bottom_half);

    for (prefix, _) in bottom_half {
        for (&name, data) in &net.groups()[&prefix] {
            if data.age() <= 5 || true {
                return Some((prefix, name));
            }
        }
    }

    None
}

pub fn most_malicious_groups(groups: &Groups) -> Vec<(Prefix, f64)> {
    let mut malicious = groups.iter().filter_map(|(&prefix, group)| {
        let malicious_count = group.values().filter(|x| x.is_malicious()).count();
        if malicious_count > 0 {
            Some((prefix, malicious_count as f64 / group.len() as f64))
        } else {
            None
        }
    }).collect::<Vec<_>>();
    malicious.sort_by(|&(_, m1), &(_, ref m2)| m1.partial_cmp(m2).unwrap().reverse());
    if malicious.len() >= 2 {
        assert!(malicious[0].1 >= malicious[1].1, "got the order reversed");
    }
    malicious
}

// Work out the best subtrees to target with joins and node removals (when join-leave attack allowed).
//pub fn best_subtrees() {
//
//}

/// Strategy which targets a group. This is very simple and ignores node ageing, thus it will
/// probably be worse than `UntargettedAttack` if node age is used in quorum.
#[derive(Clone)]
pub struct SimpleTargettedAttack {
    target: Option<Prefix>,
}

impl SimpleTargettedAttack {
    pub fn new() -> Self {
        SimpleTargettedAttack { target: None }
    }
}

impl AttackStrategy for SimpleTargettedAttack {
    fn on_split(&mut self,
                old_prefix: Prefix,
                new_prefix: Prefix,
                _node_name: NodeName,
                _node_data: &NodeData) {
        if self.target == Some(old_prefix) {
            self.target = Some(new_prefix);
        }
    }

    fn reset_on_new_name(&mut self,
                         net: &Network,
                         _old_name: Option<NodeName>,
                         new_name: NodeName,
                         _node_data: &NodeData)
                         -> bool {
        let prefix = net.find_prefix(new_name);
        if let Some(target) = self.target {
            // reset any nodes not joining the target group
            prefix != target
        } else {
            // First node: set target group
            self.target = Some(prefix);
            false
        }
    }
}
