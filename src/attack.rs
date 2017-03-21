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
use net::{Network, Groups};

const CUTOFF: usize = 6;

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
        _old_name: Option<NodeName>,
        new_name: NodeName,
        node_data: &NodeData) -> bool {

        if net.avail_malicious > 0 {
            return false;
        }
        /*
        if node_data.age() >= 2 {
            return false;
        }
        */

        let cutoff = CUTOFF;

        let mut most_malicious = most_malicious_groups(net.groups());
        if most_malicious.len() <= cutoff {
            return false;
        }
        most_malicious.split_off(cutoff);

        let prefix = net.find_prefix(new_name);

        // If node prefix is amongst the most malicious, that's ok.
        if let Some(_) = most_malicious.iter().map(|&(p, _)| p).find(|x| *x == prefix) {
            false
        } else {
            true
        }
    }

    fn force_to_rejoin(&mut self, net: &Network, allow_ddos: bool) -> Option<(Prefix, NodeName)> {
        // TODO: inter-section collusion.
        if allow_ddos {
            select_node_to_evict_ddos(net)
        } else {
            select_node_to_evict_no_ddos(net)
        }
    }
}

fn select_node_to_evict_ddos(_net: &Network) -> Option<(Prefix, NodeName)> {
    /*
    // Find group with the highest fraction of malicious nodes and remove an honest node.
    let groups = most_malicious_groups(net.groups());

    let (target_prefix, _) = groups[0];

    for (node_name, node_data) in net.groups().get(&target_prefix).unwrap().iter() {
        if !node_data.is_malicious() {
            return Some((target_prefix, *node_name));
        }
    }
    error!("yo, this case shouldn't be happening!");
    */
    None
}

fn select_node_to_evict_no_ddos(net: &Network) -> Option<(Prefix, NodeName)> {
    if net.avail_malicious > 0 {
        return None;
    }

    let mut groups = most_malicious_groups(net.groups());

    if groups.len() <= CUTOFF {
        return None;
    }

    groups.reverse();

    let cutoff = groups.len() - CUTOFF;

    for &(prefix, fraction) in &groups[..cutoff] {
        let node = net.groups()[&prefix]
            .iter()
            .filter_map(|(&name, data)| {
                if data.is_malicious() /*&& data.age() <= 4*/ {
                    Some((prefix, name))
                } else {
                    None
                }
            })
            .next();

        if node.is_some() {
            return node;
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
