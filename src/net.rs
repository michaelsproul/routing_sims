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

use std::collections::hash_map::{HashMap};
use std::collections::btree_map::{BTreeMap};
use std::mem;

use {NN, ToolArgs};
use attack::AttackStrategy;
use node::{Prefix, NodeName, NodeData, new_node_name, random_data_id};
use quorum::Quorum;

/// Maximum number of iterations to run when adding pending nodes.
const PENDING_NODE_LIMIT: usize = 100;

/// Maximum number of iterations to run when searching for a name and a section to accept us.
const FIND_NAME_LIMIT: usize = 100;

/// Controls whether a node can get added to a group
pub trait AddRestriction {
    /// May prevent add operation, for example if the group has too many nodes of this age.
    fn can_add(_node_data: &NodeData, _group: &Group) -> bool {
        true
    }
}

/// As the name says: never reject nodes.
pub struct NoAddRestriction;
impl AddRestriction for NoAddRestriction {}

/// Limit the number of nodes of certain ages.
pub struct RestrictOnePerAge;
impl AddRestriction for RestrictOnePerAge {
    fn can_add(node_data: &NodeData, group: &Group) -> bool {
        let age = node_data.age();
        if age >= 1 {
            return true;
        }
        // Number of existing nodes with this age (which is 0, must be 0 or 1).
        group.values().filter(|data| data.age() == age).count() <= 1
    }
}

/// A `Group` is a collection of named nodes.
pub type Group = BTreeMap<NodeName, NodeData>;

pub type Groups = HashMap<Prefix, Group>;

/// A `Network` is a collection of groups.
///
/// This struct implements both the low-level network structure code and the high-level code used
/// to simulate network creation.
pub struct Network {
    min_section_size: usize,
    groups: HashMap<Prefix, Group>,
    // Nodes to be joined to the network on the current step.
    pending_nodes: Vec<(NodeName, NodeData)>,
}

impl Network {
    /// Create. Specify minimum group size.
    ///
    /// An initial, empty, group is created.
    pub fn new(min_section_size: usize) -> Self {
        let mut groups = HashMap::new();
        groups.insert(Prefix::new(0, 0), Group::new());
        Network {
            min_section_size: min_section_size,
            groups: groups,
            pending_nodes: vec![],
        }
    }

    /// Are any nodes available to be added still?
    pub fn has_avail(&self) -> bool {
        unimplemented!()
    }

    /// Add (good, malicious) nodes to the queue of "available" nodes waiting to be added.
    pub fn add_avail(&mut self, _: NN, _: NN) {
        unimplemented!()
    }

    /// Run a step in the simulation.
    ///
    /// Note: if a node has done proof-of-work but its original target group splits, it
    /// simply joins whichever group it would now be in. If a node has done proof of work and
    /// is not accepted due to age restrictions, it is given a new name and must redo work.
    pub fn do_step<AR: AddRestriction>(&mut self, _: &ToolArgs, attack: &mut AttackStrategy,
        allow_join_leave: bool
    ) {
        let allow_ddos = false;

        // Add all the pending nodes from the last iteration.
        self.add_pending_nodes::<AR>();

        // Let the attacker do a join-leave attack.
        if allow_join_leave {
            self.process_join_leave(attack, allow_ddos);
        }
    }

    pub fn add_pending_nodes<AR: AddRestriction>(&mut self) {
        let pending_nodes = mem::replace(&mut self.pending_nodes, vec![]);

        for (_, node_data) in pending_nodes {
            self.add_node::<AR>(node_data);
        }
    }

    pub fn add_all_pending_nodes<AR: AddRestriction>(&mut self) {
        for _ in 0..PENDING_NODE_LIMIT {
            if self.pending_nodes.is_empty() {
                return;
            }
            self.add_pending_nodes::<AR>();
        }
        warn!("Couldn't add all pending nodes this step");
    }

    pub fn find_name<AR: AddRestriction>(&self, node_data: &NodeData) -> (Prefix, NodeName) {
        for _ in 0..FIND_NAME_LIMIT {
            let name = new_node_name();
            let prefix = self.find_prefix(name);

            let group = &self.groups[&prefix];

            if group.len() <= self.min_section_size || AR::can_add(node_data, group) {
                return (prefix, name);
            }
        }
        panic!("Couldn't find a name after {} iterations, age is: {}",
            FIND_NAME_LIMIT,
            node_data.age()
        );
    }

    // Add a single node with a random name and add any relocated nodes to pending_nodes.
    pub fn add_node<AR: AddRestriction>(&mut self, node_data: NodeData) {
        // Find a name that works for this node.
        let (prefix, name) = self.find_name::<AR>(&node_data);

        // Add the node to its group.
        {
            let mut group = self.groups.get_mut(&prefix).unwrap();
            group.insert(name, node_data);
        }

        // Split the group if necessary.
        let prefix = self.maybe_split(prefix, name);

        // Store any relocated node.
        if let Some(to_reloc) = self.churn(prefix, name) {
            self.pending_nodes.push(to_reloc);
        }
    }

    // Remove a single node from the network permanently (don't use upon relocation).
    pub fn remove_node(&mut self, prefix: Prefix, node_name: NodeName) -> NodeData {
        let removed = self.groups.get_mut(&prefix).unwrap().remove(&node_name).unwrap();

        // FIXME: merging could change prefix, so need to fix its interaction with churn here.
        self.do_merges();

        let churn_removed = false;

        if churn_removed {
            if let Some((_, reloc_data)) = self.churn(prefix, node_name) {
                self.add_node::<RestrictOnePerAge>(reloc_data);
                //self.pending_next.push((new_name, reloc_data));
            }
        }

        removed
    }

    pub fn process_join_leave(&mut self, attack: &mut AttackStrategy, allow_ddos: bool) {
        if let Some((prefix, node_name)) = attack.force_to_rejoin(self, allow_ddos) {
            let removed = self.remove_node(prefix, node_name);

            self.add_node::<RestrictOnePerAge>(NodeData::new(removed.is_malicious()));
        }
    }

    /// Access groups
    pub fn groups(&self) -> &HashMap<Prefix, BTreeMap<NodeName, NodeData>> {
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

    pub fn do_merges(&mut self) {
        for prefix in self.need_merge() {
            self.do_merge(prefix);
        }
    }

    /// Get all prefixes in need of a merge.
    pub fn need_merge(&self) -> Vec<Prefix> {
        let mut result = vec![];
        for (prefix, group) in &self.groups {
            if group.len() <= self.min_section_size {
                result.push(*prefix);
            }
        }
        result
    }

    /// Execute a merge for the given prefix.
    pub fn do_merge(&mut self, prefix: Prefix) {
        info!("Merging {:?}", prefix);
        if prefix.bit_count() == 0 {
            // Not enough members in network yet; nothing we can do
            return;
        }
        let mut group = match self.groups.remove(&prefix) {
            Some(g) => g,
            None => {
                // we marked it twice and handled it already?
                return;
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

    /// Check need_split and if true call do_split. Return the prefix matching
    /// `name` (the input prefix, if no split occurs).
    pub fn maybe_split(&mut self,
                       prefix: Prefix,
                       name: NodeName)
                       -> Prefix {
        if !self.need_split(prefix) {
            return prefix;
        }
        let (p0, p1) = self.do_split(prefix);
        if p0.matches(name) {
            p0
        } else {
            assert!(p1.matches(name));
            p1
        }
    }

    /// Check whether some group needs splitting.
    pub fn need_split(&self, prefix: Prefix) -> bool {
        let group = &self.groups[&prefix];
        let prefix0 = prefix.pushed(false);
        let size_all = group.len();
        let size0 = group.iter().filter(|node| prefix0.matches(*node.0)).count();
        size0 >= self.min_new_section_size() && size_all - size0 >= self.min_new_section_size()
    }

    /// Do a split. Return prefixes of new groups.
    pub fn do_split(&mut self, prefix: Prefix) -> (Prefix, Prefix) {
        let old_group = match self.groups.remove(&prefix) {
            Some(g) => g,
            None => {
                panic!("Error during split: prefix {:?} not found", prefix);
            }
        };
        let prefix0 = prefix.pushed(false);
        let prefix1 = prefix.pushed(true);
        let (group0, group1): (Group, Group) = old_group.into_iter()
            .partition(|node| prefix0.matches(node.0));

        let inserted = self.groups.insert(prefix0, group0).is_none();
        assert!(inserted);
        let inserted = self.groups.insert(prefix1, group1).is_none();
        assert!(inserted);
        (prefix0, prefix1)
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
        // Increment churn counters and see if any is ready to be relocated.
        let mut group = self.groups.get_mut(&prefix).unwrap();
        let mut to_relocate: Option<(NodeName, u32)> = None;
        for (node_name, ref mut node_data) in group.iter_mut() {
            if *node_name == new_node {
                continue;   // skip this node
            }
            if node_data.churn_and_can_age() {
                if to_relocate.map_or(true, |(_, churns)| node_data.churns() > churns) {
                    // consider graphing this event.
                    to_relocate = Some((*node_name, node_data.churns()));
                }
            }
        }
        let to_relocate = match to_relocate {
            Some(r) => r.0,
            None => return None,
        };

        if group.len() <= self.min_section_size {
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

    /// Return the estimated proportion of compromised data on the network.
    pub fn compromised_data_fraction(&self, group_size: NN, group_quorum: &Box<Quorum + Sync>) -> Option<f64> {
        let num_samples = 5000;

        let mut num_compromised = 0;

        for _ in 0..num_samples {
            let data_id = random_data_id();

            let section_pfx = self.groups
                .keys()
                .max_by_key(|prefix| prefix.common_prefix(data_id))
                .expect("non-empty set of sections");

            let section = &self.groups[section_pfx];
            let closest_names = closest(group_size, data_id, section.keys());

            // FIXME(michael): this is probably a bit slow and unnecessary.
            let close_group: Group = closest_names.into_iter()
                .map(|name| (name, section[&name].clone()))
                .collect();

            if group_quorum.quorum_compromised(&close_group) {
                num_compromised += 1;
            }
        }

        if num_compromised > 0 {
            Some(num_compromised as f64 / num_samples as f64)
        } else {
            None
        }
    }

    fn min_new_section_size(&self) -> usize {
        // mirrors RoutingTable
        self.min_section_size + 1
    }
}

/// Get the closest n names to val.
fn closest<'a, S>(n: u64, val: NN, section: S) -> Vec<NN>
    where S: IntoIterator<Item=&'a NN>
{
    let mut nodes = section.into_iter().map(|&x| x).collect::<Vec<_>>();
    nodes.sort_by_key(|point| point ^ val);
    nodes.truncate(n as usize);
    nodes
}
