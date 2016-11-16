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

//! Simulation tools
//!
//! These have a number of simplifications over the real network. Notably:
//!
//! *   Node join/leave and group split/merge are instantaneous.
//! *   Node names are simply random numbers
//! *   Node leaving and group merging are not simulated

// For now, because lots of stuff isn't implemented yet:
#![allow(dead_code)]

use std::mem;
use std::collections::HashMap;
use std::collections::hash_map::Entry;

use rand::{thread_rng, Rng};

use {NN, RR, ToolArgs, Error, Result};
use attack::AttackStrategy;
use node::{Prefix, NodeName, NodeData, new_node_name};


pub trait AddRestriction {
    // May prevent add operation, for example if the group has too many nodes
    // of this age.
    fn can_add(_node_data: &NodeData, _group: &HashMap<NodeName, NodeData>) -> bool {
        true
    }
}

pub struct NoAddRestriction;
impl AddRestriction for NoAddRestriction {}

pub struct RestrictOnePerAge;
impl AddRestriction for RestrictOnePerAge {
    fn can_add(node_data: &NodeData, group: &HashMap<NodeName, NodeData>) -> bool {
        let age = node_data.age();
        if age > 1 {
            return true;
        }
        group.values().filter(|data| data.age() == age).count() < 2
    }
}

pub type Group = HashMap<NodeName, NodeData>;

pub struct Network {
    min_group_size: usize,
    groups: HashMap<Prefix, Group>,
    // these are accumulated between steps, not simply reset each step:
    to_join: RR,
    p_leave: RR,
    // nodes pending joining a group this step, and those joining next step:
    pending_nodes: Vec<NodeData>,
    moved_nodes: Vec<NodeData>,
    net_size: NN,
    target_good: NN,
}

impl Network {
    /// Create. Specify minimum group size.
    ///
    /// An initial, empty, group is created.
    pub fn new(min_group_size: usize) -> Self {
        let mut groups = HashMap::new();
        groups.insert(Prefix::new(0, 0), HashMap::new());
        Network {
            min_group_size: min_group_size,
            groups: groups,
            to_join: 0.0,
            p_leave: 0.0,
            pending_nodes: vec![],
            moved_nodes: vec![],
            net_size: 0,
            target_good: 0,
        }
    }

    /// Set target number of nodes
    pub fn set_target(&mut self, n_good: NN) {
        self.target_good = n_good;
    }

    /// Run a step in the simulation. Return true if we're not done yet.
    pub fn do_step<AR: AddRestriction>(&mut self,
                                       args: &ToolArgs,
                                       attack: &mut AttackStrategy)
                                       -> bool {
        self.to_join += args.join_good;
        self.p_leave += args.leave_good;

        while self.to_join >= 1.0 || !self.pending_nodes.is_empty() {
            let node_name = new_node_name();
            let node_data = if let Some(data) = self.pending_nodes.pop() {
                // We have a moved node; add that first.
                // This _doesn't_ count as a joining node, so don't decrement to_join
                data
            } else {
                self.to_join -= 1.0;
                NodeData::new()
            };
            let age = node_data.age();

            match self.add_node::<AR>(node_name, node_data) {
                Ok(prefix) => {
                    trace!("Added node {} with age {}", node_name, age);
                    let prefix = self.maybe_split(prefix, node_name, attack);
                    // Add successful: do churn event. The churn may cause a removal from a
                    // group; however, either that was an old group which just got a new
                    // member, or it is a split result with at least one node more than the
                    // minimum number. Either way merging is not required.
                    if let Some((_old_name, node_data)) = self.churn(prefix, node_name) {
                        self.moved_nodes.push(node_data);
                    }

                    self.net_size += 1;
                    if self.net_size >= self.target_good {
                        return false;
                    }
                }
                Err(Error::AlreadyExists) |
                Err(Error::AddRestriction) => {}
                Err(e) => {
                    panic!("Error adding node: {}", e);
                }
            }
        }

        // only do anything if probability is significant, otherwise accumulate
        if self.p_leave >= 0.001 {
            let p_leave = self.p_leave;
            let n = self.probabilistic_drop(p_leave) as NN;
            self.net_size -= n;
            self.p_leave = 0.0;
        }

        mem::swap(&mut self.pending_nodes, &mut self.moved_nodes);

        true
    }

    /// Access groups
    pub fn groups(&self) -> &HashMap<Prefix, HashMap<NodeName, NodeData>> {
        &self.groups
    }

    /// Get the prefix for the group to which this name belongs.
    pub fn find_prefix(&self, name: NodeName) -> Prefix {
        // There are two strategies here:
        // 1) iterate through all groups, checking for prefix match
        // 2) iterate through all possible prefixes of name, looking each up in the group table
        // The second scales much better with large numbers of groups, and should
        // still be fairly fast with few groups because in this case the prefixes will be small.
        for bits in 0..(mem::size_of::<NN>() * 8) {
            let prefix = Prefix::new(bits, name);
            if self.groups.contains_key(&prefix) {
                return prefix;
            }
        }
        unreachable!()
    }

    /// Insert a node. Returns the prefix of the group added to.
    pub fn add_node<AR: AddRestriction>(&mut self,
                                        node_name: NodeName,
                                        node_data: NodeData)
                                        -> Result<Prefix> {
        let prefix = self.find_prefix(node_name);
        let mut group = self.groups.get_mut(&prefix).expect("network must include all groups");
        if group.len() > self.min_group_size && !AR::can_add(&node_data, group) {
            return Err(Error::AddRestriction);
        }
        match group.entry(node_name) {
            Entry::Vacant(e) => e.insert(node_data),
            Entry::Occupied(_) => {
                return Err(Error::AlreadyExists);
            }
        };
        Ok(prefix)
    }

    /// Probabilistically drop nodes (`p` is the chance of each node being dropped).
    /// Return the number of nodes dropped.
    pub fn probabilistic_drop(&mut self, p: RR) -> usize {
        let thresh = (p * (NN::max_value() as RR)).round() as NN;
        #[allow(non_snake_case)]
        let sample_NN = || -> NN { thread_rng().gen() };
        let mut need_merge = vec![];
        let mut num = 0;
        for (prefix, ref mut group) in &mut self.groups {
            let to_remove: Vec<_> =
                group.keys().filter(|_| sample_NN() < thresh).cloned().collect();
            for key in to_remove {
                group.remove(&key);
                num += 1;
            }
            if group.len() < self.min_group_size {
                need_merge.push(*prefix);
            }
        }

        // Do any merges needed (after all removals)
        while let Some(prefix) = need_merge.pop() {
            if prefix.bit_count() == 0 {
                // Not enough members in network yet; nothing we can do
                continue;
            }
            let mut group = match self.groups.remove(&prefix) {
                Some(g) => g,
                None => {
                    // we marked it twice and handled it already?
                    continue;
                }
            };
            let parent = prefix.popped();
            // Groups are disjoint, so all "compatibles" should be descendents of the new "parent"
            let compatible_prefixes: Vec<_> =
                self.groups.keys().filter(|k| k.is_compatible(parent)).cloned().collect();
            for p in compatible_prefixes {
                let other_group = self.groups.remove(&p).expect("has group");
                group.extend(other_group);
            }
            self.groups.insert(parent, group);
        }

        num
    }

    /// Check need_split and if true call do_split. Return the prefix matching
    /// `name` (the input prefix, if no split occurs).
    pub fn maybe_split(&mut self,
                       prefix: Prefix,
                       name: NodeName,
                       attack: &mut AttackStrategy)
                       -> Prefix {
        if !self.need_split(prefix) {
            return prefix;
        }
        match self.do_split(prefix, attack) {
            Ok((p0, p1)) => {
                if p0.matches(name) {
                    p0
                } else {
                    assert!(p1.matches(name));
                    p1
                }
            }
            Err(e) => {
                panic!("Error during split: {}", e);
            }
        }
    }

    /// Check whether some group needs splitting.
    pub fn need_split(&self, prefix: Prefix) -> bool {
        let group = match self.groups.get(&prefix) {
            Some(g) => g,
            None => {
                return false;   // ignore "not found" error
            }
        };
        let prefix0 = prefix.pushed(false);
        let size_all = group.len();
        let size0 = group.iter().filter(|node| prefix0.matches(*node.0)).count();
        size0 >= self.min_new_group_size() && size_all - size0 >= self.min_new_group_size()
    }

    /// Do a split. Return prefixes of new groups.
    pub fn do_split(&mut self,
                    prefix: Prefix,
                    attack: &mut AttackStrategy)
                    -> Result<(Prefix, Prefix)> {
        let old_group = match self.groups.remove(&prefix) {
            Some(g) => g,
            None => {
                return Err(Error::NotFound);
            }
        };
        let prefix0 = prefix.pushed(false);
        let prefix1 = prefix.pushed(true);
        let (group0, group1): (Group, Group) = old_group.into_iter()
            .partition(|node| prefix0.matches(node.0));
        for (name, data) in &group0 {
            if data.is_malicious() {
                attack.split(prefix, prefix0, *name, data);
            }
        }
        for (name, data) in &group1 {
            if data.is_malicious() {
                attack.split(prefix, prefix1, *name, data);
            }
        }
        let inserted = self.groups.insert(prefix0, group0).is_none();
        assert!(inserted);
        let inserted = self.groups.insert(prefix1, group1).is_none();
        assert!(inserted);
        Ok((prefix0, prefix1))
    }

    /// Do a group churn event. The churn affects all members of a group specified
    /// by `prefix` except the node causing the churn, `new_node`.
    ///
    /// TODO: we could possibly make churn happen to a random group instead.
    /// The advantage is it makes it impossible for the attacker to target churn events
    /// at some group.
    ///
    /// The simulation driver chooses when
    /// to trigger this. What we do is (1) age each node by 1, (2) pick the oldest node
    /// whose age is a power of 2 (there may be none) and relocate it.
    /// On relocation, the node is returned (with its old name); the driver should
    /// create a new name and call add_node with the new name.
    pub fn churn(&mut self, prefix: Prefix, new_node: NodeName) -> Option<(NodeName, NodeData)> {
        let mut group = self.groups.get_mut(&prefix).expect("churn called with invalid group");
        // Increment churn counters and see if any is ready to be relocated.
        let mut to_relocate: Option<(NodeName, u32)> = None;
        for (node_name, ref mut node_data) in group.iter_mut() {
            if *node_name == new_node {
                continue;   // skip this node
            }
            if node_data.churn_and_can_age() {
                if to_relocate.map_or(true, |n| node_data.churns() > n.1) {
                    to_relocate = Some((*node_name, node_data.churns()));
                }
            }
        }
        let to_relocate = match to_relocate {
            Some(r) => r.0,
            None => return None,
        };

        if group.len() <= self.min_group_size {
            // Relocation is blocked to prevent the group from becoming too small,
            // but we still need the node to age.
            group.get_mut(&to_relocate).expect("have node").incr_age();
            return None;
        }

        // Remove node, age and return:
        let mut node_data = group.remove(&to_relocate).expect("have node");
        node_data.incr_age();
        trace!("Relocating a node with age {} and churns {}",
               node_data.age(),
               node_data.churns());
        Some((to_relocate, node_data))
    }

    fn min_new_group_size(&self) -> usize {
        // mirrors RoutingTable
        self.min_group_size + 1
    }
}
