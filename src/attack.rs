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
use net::Network;


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
