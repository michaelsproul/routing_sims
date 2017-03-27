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

use ToolArgs;
use node::{Prefix, NodeName, NodeData};
use net::{Network, Groups, Group};
use rand::{weak_rng, XorShiftRng, Rng};
use std::collections::HashMap;
use metadata::Data;

// TODO: optimise over these parameters.
const LEARNING_RATE: f64 = 0.5;
const DISCOUNT_FACTOR: f64 = 0.8;
const GROUP_FOCUS: usize = 1;
const INIT_QUALITY: f64 = 2.0;
// Size of buckets that malicious fractions are divided into.
const BUCKET_SIZE: f64 = 10.0;
const CHURN_ROUNDING: u32 = 1;

pub trait AttackStrategy {
    fn create(_params: &ToolArgs, _run_num: u32) -> Self where Self: Sized;

    fn force_to_rejoin(&mut self, _net: &Network, _ddos: bool) -> Option<(Prefix, NodeName)> {
        None
    }
}

/// Strategy which does not involve any targetting.
pub type UntargettedAttack =
    Random
    //YoungestFromWorstGroup
    //OldestFromWorstGroup
    //QLearningAttack
;

#[derive(Clone)]
pub struct Random {
    rng: XorShiftRng,
}

impl AttackStrategy for Random {
    fn create(_: &ToolArgs, _: u32) -> Self {
        Random {
            rng: weak_rng()
        }
    }

    fn force_to_rejoin(&mut self, net: &Network, _ddos: bool) -> Option<(Prefix, NodeName)> {
        let malicious_nodes = all_malicious_nodes(net.groups());
        if malicious_nodes.is_empty() {
            return None;
        }
        let i = self.rng.gen_range(0, malicious_nodes.len());
        Some(malicious_nodes[i])
    }
}

fn all_malicious_nodes(groups: &Groups) -> Vec<(Prefix, NodeName)> {
    groups.iter()
    .flat_map(|(prefix, group)| {
        group.iter()
        .filter_map(move |(name, data)| {
            if data.is_malicious() {
                Some((*prefix, *name))
            } else {
                None
            }
        })
    })
    .collect()
}

#[derive(Clone)]
pub struct OldestFromWorstGroup;

impl AttackStrategy for OldestFromWorstGroup {
    fn create(_: &ToolArgs, _: u32) -> Self {
        OldestFromWorstGroup
    }

    fn force_to_rejoin(&mut self, net: &Network, _ddos: bool) -> Option<(Prefix, NodeName)> {
        let mut most_malicious = most_malicious_groups(net.groups());

        most_malicious.pop().map(|(prefix, _)| {
            let (name, _) = youngest_nodes(&net.groups()[&prefix]).pop().unwrap();
            (prefix, name)
        })
    }
}

#[derive(Clone)]
pub struct YoungestFromWorstGroup;

impl AttackStrategy for YoungestFromWorstGroup {
    fn create(_: &ToolArgs, _: u32) -> Self {
        YoungestFromWorstGroup
    }

    fn force_to_rejoin(&mut self, net: &Network, _ddos: bool) -> Option<(Prefix, NodeName)> {
        let mut most_malicious = most_malicious_groups(net.groups());

        most_malicious.pop().map(|(prefix, _)| {
            let &(name, _) = youngest_nodes(&net.groups()[&prefix]).first().unwrap();
            (prefix, name)
        })
    }
}

pub fn youngest_nodes(group: &Group) -> Vec<(NodeName, NodeData)> {
    let mut result = group.iter().map(|(&n, &d)| (n, d)).collect::<Vec<_>>();
    result.sort_by_key(|&(_, node)| node.age());
    result
}

pub fn malicious_groups(groups: &Groups) -> Vec<(Prefix, f64)> {
    groups.iter().filter_map(|(&prefix, group)| {
        let malicious_count = group.values().filter(|x| x.is_malicious()).count();
        if malicious_count > 0 {
            Some((prefix, malicious_count as f64 / group.len() as f64))
        } else {
            None
        }
    }).collect()
}

pub fn most_malicious_groups(groups: &Groups) -> Vec<(Prefix, f64)> {
    let mut malicious = malicious_groups(groups);
    malicious.sort_by(|&(_, m1), &(_, ref m2)| m1.partial_cmp(m2).unwrap().reverse());
    if malicious.len() >= 2 {
        assert!(malicious[0].1 >= malicious[1].1, "got the order reversed");
    }
    malicious
}

#[derive(Clone)]
pub struct QLearningAttack {
    q: HashMap<State, f64>,
    // Action taken on the step previous to `force_to_rejoin` being called.
    prev_action: Option<State>,
    // Malicious fraction(s) for previous step.
    prev_fraction: f64,
    pub stats: Data<usize>,
    states_explored: usize,
    step: usize,
}

// Compression of (state, action) pairs into essential information.
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
struct State {
    // Age of the node that we could choose to rejoin.
    age: u32,
    // Number of churns the potential evictee has endured.
    churns: u32,
    // Malicious fraction of the group that the evictee is part of.
    mal_fraction: u32,
    // Size of evictee's group (so we can beware of merges).
    group_size: usize,
    // Max mal fraction of a neighbouring group (so we don't merge badly).
    neighbour_fraction: u32,
}

impl AttackStrategy for QLearningAttack {
    fn create(_args: &ToolArgs, run_num: u32) -> Self {
        let data = Data::new(&format!("run{:02}", run_num), "qlearn_stats", "y");
        QLearningAttack {
            q: HashMap::new(),
            prev_action: None,
            prev_fraction: 0.0,
            stats: data,
            states_explored: 0,
            step: 0,
        }
    }

    fn force_to_rejoin(&mut self, net: &Network, _ddos: bool) -> Option<(Prefix, NodeName)> {
        // Choose an action to take next (a node to rejoin).
        // This incidentally computes max{a} Q(s_{t + 1}, a) in result_quality.
        let malicious_node_idx = all_malicious_nodes(net.groups());
        let mut result = None;
        let mut result_quality = 0.0;
        let mut result_action = None;
        let mut new_state = false;

        for (prefix, node_name) in malicious_node_idx {
            let group = &net.groups()[&prefix];
            let node_data = &group[&node_name];

            let id = State {
                age: node_data.age(),
                churns: (node_data.churns() / CHURN_ROUNDING) * CHURN_ROUNDING,
                mal_fraction: int_percent(group),
                group_size: group.len(),
                neighbour_fraction: compute_neighbour_fraction(prefix, net.groups()),
            };

            let mut new_state_this_iter = false;
            let quality = *self.q.entry(id.clone()).or_insert_with(|| {
                new_state_this_iter = true;
                INIT_QUALITY
            });

            if quality > result_quality {
                result = Some((prefix, node_name));
                result_quality = quality;
                result_action = Some(id);
                new_state = new_state_this_iter;
            }
        }

        if new_state {
            self.states_explored += 1;
        }

        self.stats.add_point(self.step, self.states_explored);
        self.step += 1;

        // Update prev action.
        let previous_action = self.prev_action.take();
        self.prev_action = result_action;

        // Extract reward for previous time-step from net.
        // Update q.
        if let Some(action) = previous_action {
            // TODO: determine whether differential or cumulative rewards work better...
            let new_frac: f64 = malicious_fractions(net.groups(), GROUP_FOCUS).into_iter().sum();
            let r = new_frac; // - self.prev_fraction;
            self.prev_fraction = new_frac;

            let old_value = self.q[&action];
            let opt_future_est = result_quality;

            let updated_val = old_value + LEARNING_RATE * (
                r + DISCOUNT_FACTOR * opt_future_est - old_value
            );

            self.q.insert(action, updated_val);
        }

        // FIXME: result doesn't take into account most recently learnt value,
        // does that matter?
        result
    }
}

pub fn malicious_fractions(groups: &Groups, n: usize) -> Vec<f64> {
    most_malicious_groups(groups).into_iter()
        .map(|(_, frac)| frac)
        .take(n)
        .collect()
}

pub fn compute_neighbour_fraction(our_prefix: Prefix, groups: &Groups) -> u32 {
    if our_prefix.bit_count() == 0 {
        return 0;
    }
    let parent_prefix = our_prefix.popped();
    let neighbour_prefix = if parent_prefix.pushed(true) == our_prefix {
        parent_prefix.pushed(false)
    } else {
        parent_prefix.pushed(true)
    };

    groups.iter()
        .filter(|&(&prefix, _)| neighbour_prefix.is_prefix_of(prefix))
        .map(|(_, ref group)| int_percent(group))
        .max()
        .unwrap()
}

pub fn int_percent(group: &Group) -> u32 {
    let num_malicious = group.values().filter(|d| d.is_malicious()).count();
    let frac = num_malicious as f64 / group.len() as f64;
    let rounded = (BUCKET_SIZE * frac).round();
    rounded as u32
}
