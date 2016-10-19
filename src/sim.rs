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

use super::{NN};

use std::cmp::{Ordering, min};
use std::mem;
use std::hash::{Hash, Hasher};
use std::fmt::{self, Formatter, Binary, Debug};
use std::collections::{HashSet, HashMap};
use std::result;

use rand::thread_rng;
use rand::distributions::{Range, IndependentSample};


/// Name type (Xorable in routing library).
//TODO: which methods do we actually need?
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
            if val {
                self | mask
            } else {
                self & !mask
            }
        }
    }
}


// A group prefix, i.e. a sequence of bits specifying the part of the network's name space
// consisting of all names that start with this sequence.
#[derive(Clone, Copy, Default, Eq, Ord)]
struct Prefix {
    bit_count: usize,
    name: NN,
}

//TODO: which methods do we need?
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


fn rand_mod(n: NN) -> NN {
    Range::new(0, n).ind_sample(&mut thread_rng())
}


/// Error type
pub enum Error {
    AlreadyExists,
    NotFound,
}
/// Result type
pub type Result<T> = result::Result<T, Error>;

/// Churn type
pub enum ChurnType {
    NodeAdd,
    GroupSplit,
}

/// A node in the network.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Node {
    name: NN,
    age: NN,
}
impl Node {
    /// Create a new node with random name and age 0
    pub fn new() -> Self {
        Node {
            name: rand_mod(NN::max_value()),
            age: 0,
        }
    }
}

struct Network {
    min_group_size: usize,
    groups: HashMap<Prefix, HashSet<Node>>,
}

impl Network {
    /// Create. Specify minimum group size.
    /// 
    /// An initial, empty, group is created.
    pub fn new(min_group_size: usize) -> Self {
        let mut groups = HashMap::new();
        groups.insert(Prefix::new(0, 0), HashSet::new());
        Network {
            min_group_size: min_group_size,
            groups: groups,
        }
    }
    /// Insert a node. Returns the prefix of the group added to.
    pub fn add(&mut self, node: Node) -> Result<Prefix> {
        let prefix = *self.groups.keys().find(|prefix| prefix.matches(node.name)).expect("some prefix must match every name");
        let mut group = self.groups.get_mut(&prefix).expect("network must include all groups");
        if !group.insert(node) {
            return Err(Error::AlreadyExists);
        }
        Ok(prefix)
    }
    /// Check whether some group needs splitting.
    pub fn need_split(&self, prefix: Prefix) -> Result<bool> {
        let group = match self.groups.get(&prefix) {
            Some(g) => g,
            None => { return Err(Error::NotFound); }
        };
        let prefix0 = prefix.pushed(false);
        let size_all = group.len();
        let size0 = group.iter().filter(|node| prefix0.matches(node.name)).count();
        Ok(size0 >= self.min_new_group_size() && size_all - size0 >= self.min_new_group_size())
    }
    /// Do a split. Return prefixes of new groups.
    pub fn do_split(&mut self, prefix: Prefix) -> Result<(Prefix, Prefix)> {
        let old_group = match self.groups.remove(&prefix) {
            Some(g) => g,
            None => { return Err(Error::NotFound); }
        };
        let prefix0 = prefix.pushed(false);
        let prefix1 = prefix.pushed(true);
        let (group0, group1) = old_group.into_iter()
            .partition::<HashSet<_>, _>(|node| prefix0.matches(node.name));
        let inserted = self.groups.insert(prefix0, group0).is_none();
        assert!(inserted);
        let inserted = self.groups.insert(prefix1, group1).is_none();
        assert!(inserted);
        Ok((prefix0, prefix1))
    }
    /// Actions happening on a churn event on group specified by prefix
    pub fn churn(&mut self, _type: ChurnType, _prefix: Prefix) -> Result<()> {
        panic!("churn event has not yet been implemented");
    }
    fn min_new_group_size(&self) -> usize {
        // mirrors RoutingTable
        self.min_group_size + 1
    }
}
