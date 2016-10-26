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

use super::{NN, Error, Result};

use std::cmp::{Ordering, min};
use std::mem;
use std::hash::{Hash, Hasher};
use std::fmt::{self, Formatter, Binary, Debug};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::marker::PhantomData;
use std::u64;

use rand::{thread_rng, Rng};
use rand::distributions::{Range, IndependentSample};


// In the future, we may be able to do this:
// const RANGE_NN: Range<NN> = Range::new(0, NN::max_value());
#[allow(non_snake_case)]
fn sample_NN() -> NN {
    thread_rng().gen()
}
fn sample_ub(ub: NN) -> NN {
    let range = Range::new(0, ub);
    range.ind_sample(&mut thread_rng())
}


/// Name type (Xorable in routing library).
trait NameT: Ord {
    /// Returns the length of the common prefix with the `other` name; e. g.
    /// the when `other = 11110000` and `self = 11111111` this is 4.
    fn common_prefix(&self, other: Self) -> usize;

    /// Compares the distance of the arguments to `self`. Returns `Less` if `lhs` is closer,
    /// `Greater` if `rhs` is closer, and `Equal` if `lhs == rhs`. (The XOR distance can only be
    /// equal if the arguments ar equal.)
    fn cmp_distance(&self, lhs: Self, rhs: Self) -> Ordering;

    /// Returns `true` if the `i`-th bit is `1`.
    fn bit(&self, i: usize) -> bool;

    /// Returns a copy of `self`, with the `index`-th bit set to `bit`.
    ///
    /// If `index` exceeds the number of bits in `self`, an unmodified copy of `self` is returned.
    fn with_bit(self, i: usize, bit: bool) -> Self;

    /// Returns a binary format string, with leading zero bits included.
    fn binary(&self) -> String;

    /// Returns a copy of self with first `n` bits preserved, and remaining bits
    /// set to 0 (val == false) or 1 (val == true).
    fn set_remaining(self, n: usize, val: bool) -> Self;
}

impl NameT for NN {
    fn common_prefix(&self, other: Self) -> usize {
        (self ^ other).leading_zeros() as usize
    }

    fn cmp_distance(&self, lhs: Self, rhs: Self) -> Ordering {
        Ord::cmp(&(lhs ^ self), &(rhs ^ self))
    }

    fn bit(&self, i: usize) -> bool {
        let pow_i = 1 << (mem::size_of::<Self>() * 8 - 1 - i); // 1 on bit i.
        self & pow_i != 0
    }

    fn with_bit(mut self, i: usize, bit: bool) -> Self {
        if i >= mem::size_of::<Self>() * 8 {
            return self;
        }
        let pow_i = 1 << (mem::size_of::<Self>() * 8 - 1 - i); // 1 on bit i.
        if bit {
            self |= pow_i;
        } else {
            self &= !pow_i;
        }
        self
    }

    fn binary(&self) -> String {
        format!("{1:00$b}", mem::size_of::<Self>() * 8, self)
    }

    fn set_remaining(self, n: usize, val: bool) -> Self {
        let bits = mem::size_of::<NN>() * 8;
        if n >= bits {
            self
        } else {
            let mask = !0 >> n;
            if val { self | mask } else { self & !mask }
        }
    }
}


// A group prefix, i.e. a sequence of bits specifying the part of the network's name space
// consisting of all names that start with this sequence.
#[derive(Clone, Copy, Default, Eq, Ord)]
pub struct Prefix {
    bit_count: usize,
    name: NN,
}

impl Prefix {
    /// Creates a new `Prefix` with the first `bit_count` bits of `name`.
    /// Insignificant bits are all set to 0.
    fn new(bit_count: usize, name: NN) -> Prefix {
        Prefix {
            bit_count: bit_count,
            name: name.set_remaining(bit_count, false),
        }
    }

    /// Returns `self` with an appended bit: `0` if `bit` is `false`, and `1` if `bit` is `true`.
    fn pushed(mut self, bit: bool) -> Prefix {
        self.name = self.name.with_bit(self.bit_count, bit);
        self.bit_count += 1;
        self
    }

    /// Returns a prefix copying the first `bitcount() - 1` bits from `self`,
    /// or `self` if it is already empty.
    fn popped(mut self) -> Prefix {
        if self.bit_count > 0 {
            self.bit_count -= 1;
            // unused bits should be zero:
            self.name = self.name.with_bit(self.bit_count, false);
        }
        self
    }

    /// Returns the number of bits in the prefix.
    fn bit_count(&self) -> usize {
        self.bit_count
    }

    /// Returns `true` if `self` is a prefix of `other` or vice versa.
    fn is_compatible(&self, other: Prefix) -> bool {
        let i = self.name.common_prefix(other.name);
        i >= self.bit_count || i >= other.bit_count
    }

    fn common_prefix(&self, name: NN) -> usize {
        min(self.bit_count, self.name.common_prefix(name))
    }

    /// Returns `true` if this is a prefix of the given `name`.
    fn matches(&self, name: NN) -> bool {
        self.name.common_prefix(name) >= self.bit_count
    }
}

impl PartialEq<Prefix> for Prefix {
    fn eq(&self, other: &Self) -> bool {
        self.is_compatible(*other) && self.bit_count == other.bit_count
    }
}

impl PartialOrd<Prefix> for Prefix {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self == other {
            Some(Ordering::Equal)
        } else if self.is_compatible(*other) {
            None
        } else {
            Some(self.name.cmp(&other.name))
        }
    }
}

impl Hash for Prefix {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for i in 0..self.bit_count {
            self.name.bit(i).hash(state);
        }
    }
}

impl Binary for Prefix {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        let mut binary = self.name.binary();
        binary.truncate(self.bit_count);
        write!(formatter, "Prefix({})", binary)
    }
}

impl Debug for Prefix {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        Binary::fmt(self, formatter)
    }
}


/// Type of a node name
pub type NodeName = u64;

/// Generate a new node name
pub fn new_node_name() -> NodeName {
    sample_NN()
}

/// Data stored for a node
#[derive(Clone, Copy)]
pub struct NodeData {
    age: u32, // initial age is 0
    churns: u32, // initial churns is 0
    is_malicious: bool,
}

impl NodeData {
    /// New data (initial age and churns, not malicious)
    pub fn new() -> Self {
        NodeData {
            age: 0,
            churns: 0,
            is_malicious: false,
        }
    }

    /// New data (initial age and churns, is malicious)
    pub fn new_malicious() -> Self {
        NodeData {
            age: 0,
            churns: 0,
            is_malicious: true,
        }
    }

    /// Get the age
    pub fn age(&self) -> u32 {
        self.age
    }

    // Increment churns, and return whether this is high enough for relocation
    fn churn_and_can_age(&mut self) -> bool {
        self.churns += 1;
        self.churns >= 2u32.pow(self.age)
    }

    /// Is this node malicous?
    pub fn is_malicious(&self) -> bool {
        self.is_malicious
    }
}

/// Type of a node
pub type Node = (NodeName, NodeData);


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
        let age = node_data.age;
        if age > 1 {
            return true;
        }
        group.values().filter(|data| data.age == age).count() < 2
    }
}

pub struct Network<AddRestriction> {
    min_group_size: usize,
    groups: HashMap<Prefix, HashMap<NodeName, NodeData>>,
    _dummy: PhantomData<AddRestriction>,
}

impl<AR: AddRestriction> Network<AR> {
    /// Create. Specify minimum group size.
    ///
    /// An initial, empty, group is created.
    pub fn new(min_group_size: usize) -> Self {
        let mut groups = HashMap::new();
        groups.insert(Prefix::new(0, 0), HashMap::new());
        Network {
            min_group_size: min_group_size,
            groups: groups,
            _dummy: PhantomData {},
        }
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
    pub fn add_node(&mut self, node_name: NodeName, node_data: NodeData) -> Result<Prefix> {
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

    /// Check need_split and if true call do_split. Return the prefix matching
    /// `name` (the input prefix, if no split occurs).
    pub fn maybe_split(&mut self, prefix: Prefix, name: NodeName) -> Prefix {
        if !self.need_split(prefix) {
            return prefix;
        }
        match self.do_split(prefix) {
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
    pub fn do_split(&mut self, prefix: Prefix) -> Result<(Prefix, Prefix)> {
        let old_group = match self.groups.remove(&prefix) {
            Some(g) => g,
            None => {
                return Err(Error::NotFound);
            }
        };
        let prefix0 = prefix.pushed(false);
        let prefix1 = prefix.pushed(true);
        let (group0, group1) = old_group.into_iter()
            .partition(|node| prefix0.matches(node.0));
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
    /// On relocation, the node is returned (the driver should call add_node with it).
    pub fn churn(&mut self, prefix: Prefix, new_node: NodeName) -> Option<(NodeName, NodeData)> {
        let mut group = self.groups.get_mut(&prefix).expect("churn called with invalid group");
        // Increment churn counters and see if any is ready to be relocated.
        let mut to_relocate: Option<(NodeName, u32)> = None;
        for (node_name, ref mut node_data) in group.iter_mut() {
            if *node_name == new_node {
                continue;   // skip this node
            }
            if node_data.churn_and_can_age() {
                if to_relocate.map_or(true, |n| node_data.churns > n.1) {
                    to_relocate = Some((*node_name, node_data.churns));
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
            group.get_mut(&to_relocate).expect("have node").age += 1;
            return None;
        }

        // Remove node, age and return:
        let mut node_data = group.remove(&to_relocate).expect("have node");
        node_data.age += 1;
        trace!("Relocating a node with age {} and churns {}",
               node_data.age,
               node_data.churns);
        Some((new_node_name(), node_data))
    }

    fn min_new_group_size(&self) -> usize {
        // mirrors RoutingTable
        self.min_group_size + 1
    }
}
