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

//! Quorum

use super::{NN, RR};
use super::sim::{Prefix, NodeName, NodeData, Network};
use std::collections::HashMap;


/// Describes the "quorum" algorithm
pub trait Quorum {
    /// Get number of nodes needed for a quorum, given group size k.
    ///
    /// Get the number of messages needed for quorum. If the quorum algorithm
    /// does anything more complicated (e.g. check node age) then this will
    /// return `None`.
    fn quorum_size(&self, k: NN) -> Option<NN>;

    /// Specify proportion of group agreement required, range 0-1. Use slightly
    /// greater than half if number must be greater than 50%.
    fn set_quorum_proportion(&mut self, prop: RR);

    /// Returns true if there is not a quorum of good nodes in the passed group.
    fn quorum_disrupted(&self, group: &HashMap<NodeName, NodeData>) -> bool;

    /// Returns true if there is a quorum of bad nodes in the passed group.
    fn quorum_compromised(&self, group: &HashMap<NodeName, NodeData>) -> bool;
}

/// Quorum based on simply meeting some minimum proportion of the group.
pub struct SimpleQuorum {
    proportion: RR,
}

impl SimpleQuorum {
    /// New structure. Default to requiring a quorum of the entire group.
    pub fn new() -> Self {
        SimpleQuorum { proportion: 1.0 }
    }

    /// New structure, with specified proportion requried.
    pub fn from(prop: RR) -> Self {
        SimpleQuorum { proportion: prop }
    }
}

impl Quorum for SimpleQuorum {
    fn quorum_size(&self, k: NN) -> Option<NN> {
        Some((k as RR * self.proportion).ceil() as NN)
    }

    fn set_quorum_proportion(&mut self, prop: RR) {
        self.proportion = prop;
    }

    fn quorum_disrupted(&self, group: &HashMap<NodeName, NodeData>) -> bool {
        let good = group.iter().filter(|node| !node.1.is_malicious()).count() as RR;
        let all = group.len() as RR;
        good / all < self.proportion
    }

    fn quorum_compromised(&self, group: &HashMap<NodeName, NodeData>) -> bool {
        let bad = group.iter().filter(|node| node.1.is_malicious()).count() as RR;
        let all = group.len() as RR;
        bad / all >= self.proportion
    }
}

/// Quorum which requires some proportion of group age as well as number
///
/// We require the same proportion of age as of the number of nodes (although
/// these could be separated).
pub struct AgeQuorum {
    proportion: RR,
}

impl AgeQuorum {
    /// New structure. Default to requiring a quorum of the entire group.
    pub fn new() -> Self {
        AgeQuorum { proportion: 1.0 }
    }
}

impl Quorum for AgeQuorum {
    fn quorum_size(&self, _: NN) -> Option<NN> {
        None
    }

    fn set_quorum_proportion(&mut self, prop: RR) {
        self.proportion = prop;
    }

    fn quorum_disrupted(&self, group: &HashMap<NodeName, NodeData>) -> bool {
        let n_nodes = group.len() as RR;
        let mut sum_age = 0;
        let mut n_good = 0;
        let mut good_age = 0;
        for data in group.values() {
            sum_age += data.age();
            if !data.is_malicious() {
                n_good += 1;
                good_age += data.age();
            }
        }
        (n_good as RR) / n_nodes < self.proportion ||
        (good_age as RR) / (sum_age as RR) < self.proportion
    }

    fn quorum_compromised(&self, group: &HashMap<NodeName, NodeData>) -> bool {
        let n_nodes = group.len() as RR;
        let mut sum_age = 0;
        let mut n_bad = 0;
        let mut bad_age = 0;
        for data in group.values() {
            sum_age += data.age();
            if data.is_malicious() {
                n_bad += 1;
                bad_age += data.age();
            }
        }
        (n_bad as RR) / n_nodes >= self.proportion &&
        (bad_age as RR) / (sum_age as RR) >= self.proportion
    }
}


/// Determines a few things about how attacks work.
///
/// A clone is made for each simulation, which may hold mutable state.
/// This state is lost at the end of the simulation.
pub trait AttackStrategy {
    /// Called when splitting occurs
    ///
    /// Default implementation: do nothing.
    fn split(&mut self,
             _old_prefix: Prefix,
             _new_prefix: Prefix,
             _node_name: NodeName,
             _node_data: &NodeData) {
    }

    /// Called when a malicious node is added and told its name (when new or when an
    /// "add restriction" forces it to take a different name). This should return true only
    /// if the attacker decides to reset this malicious node now (before doing proof-of-work).
    ///
    /// Group prefix can be obtained via `net.find_prefix(name)`.
    ///
    /// Default implementation: return false (do not split).
    fn reset_node(&mut self, _net: &Network, _new_name: NodeName, _node_data: &NodeData) -> bool {
        false
    }

    /// The method is called when a node is aged via churning. This should return true only if
    /// the attacker decides to reset this malicious node now (before doing proof-of-work).
    ///
    /// Group prefix can be obtained via `net.find_prefix(name)`.
    ///
    /// Default implemention: ignore the old name and call `reset_node`.
    fn reset_on_move(&mut self,
                     net: &Network,
                     _old_name: NodeName,
                     new_name: NodeName,
                     node_data: &NodeData)
                     -> bool {
        self.reset_node(net, new_name, node_data)
    }
}

/// Strategy which does not involve any targetting.
#[derive(Clone)]
pub struct UntargettedAttack;

impl AttackStrategy for UntargettedAttack {}

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
    fn split(&mut self,
             old_prefix: Prefix,
             new_prefix: Prefix,
             _node_name: NodeName,
             _node_data: &NodeData) {
        if self.target == Some(old_prefix) {
            self.target = Some(new_prefix);
        }
    }

    fn reset_node(&mut self, net: &Network, new_name: NodeName, _node_data: &NodeData) -> bool {
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
