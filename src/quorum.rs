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
use super::sim::{Prefix, Node, NodeName, NodeData};
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
        (n_good as RR) / n_nodes < self.proportion &&
        (good_age as RR) / (sum_age as RR) < self.proportion
    }
}


/// Determines a few things about how attacks work.
///
/// A clone is made for each simulation, which may hold mutable state.
/// This state is lost at the end of the simulation.
pub trait AttackStrategy: Clone {
    /// This should return true if the attacker decides to reset this malicious node.
    fn reset_node(&mut self, node: &Node, prefix: Prefix) -> bool;
}

/// Strategy which does not involve any targetting.
#[derive(Clone)]
pub struct UntargettedAttack;

impl AttackStrategy for UntargettedAttack {
    fn reset_node(&mut self, _node: &Node, _prefix: Prefix) -> bool {
        false
    }
}
