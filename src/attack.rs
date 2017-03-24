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
use rand::{weak_rng, XorShiftRng, Rng};
use std::collections::HashMap;
use metadata::Data;

const LEARNING_RATE: f64 = 0.5;
const DISCOUNT_FACTOR: f64 = 1.0;

pub trait AttackStrategy {
    fn force_to_rejoin(&mut self, _net: &Network, _ddos: bool) -> Option<(Prefix, NodeName)> {
        None
    }
}

/// Strategy which does not involve any targetting.
pub type UntargettedAttack =
    //Random
    //YoungestFromWorstGroup
    //OldestFromWorstGroup
    QLearningAttack
;

#[derive(Clone)]
pub struct Random {
    rng: XorShiftRng,
}

impl Default for Random {
    fn default() -> Self { Random { rng: weak_rng() } }
}

impl AttackStrategy for Random {
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
    // Map (age, churns, fraction of group as int/100, group size) => quality
    q: HashMap<(u32, u32, u32, usize), f64>,
    last_action: Option<(u32, u32, u32, usize)>,
    last_fraction: f64,
    stats: Data<usize>,
    step: usize,
}

impl Default for QLearningAttack {
    fn default() -> Self {
        let mut data = Data::new("qlearn", "stats", "y");
        data.write_out = false;
        QLearningAttack {
            q: HashMap::new(),
            last_action: None,
            last_fraction: 0.0,
            stats: data,
            step: 0,
        }
    }
}

use std::cell::RefCell;
thread_local! {
    static SHITTY_RNG: RefCell<XorShiftRng> = RefCell::new(weak_rng());
}

impl AttackStrategy for QLearningAttack {
    fn force_to_rejoin(&mut self, net: &Network, _ddos: bool) -> Option<(Prefix, NodeName)> {
        // Choose an action to take next (a node to rejoin).
        // This incidentally computes max{a} Q(s_{t + 1}, a) in result_quality.
        let malicious_node_idx = all_malicious_nodes(net.groups());
        let mut result = None;
        let mut result_quality = 0.0;

        let mut wat = 0;

        self.stats.write_out = true;

        for (prefix, node_name) in malicious_node_idx {
            let group = &net.groups()[&prefix];
            let node_data = &group[&node_name];

            let age = node_data.age();
            let churns = node_data.churns();
            let percentage = int_percent(group);
            let group_size = group.len();

            let id = (age, churns, percentage, group_size);

            let quality = *self.q.entry(id).or_insert_with(|| {
                wat += 1;
                //thread_rng().next_f64()
                //SHITTY_RNG.with(|rng| rng.borrow_mut().next_f64())
                0.8
            });

            if quality > result_quality {
                result = Some((prefix, node_name));
                result_quality = quality;
                self.last_action = Some(id);
            }
        }

        self.stats.add_point(self.step, wat);
        self.step += 1;

        // Extract reward for previous time-step from net.
        // Update q.
        if let Some(action) = self.last_action {
            //let new_fraction = malicious_fraction(net.groups());
            // let r = new_fraction; //- self.last_fraction;
            let r: f64 = malicious_fractions(net.groups(), 5).into_iter().sum();
            //self.last_fraction = new_fraction;

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

pub fn malicious_fraction(groups: &Groups) -> f64 {
    malicious_groups(groups).into_iter()
        .map(|(_, f)| f)
        .max_by(|x, y| x.partial_cmp(y).unwrap())
        .unwrap()
}

pub fn malicious_fractions(groups: &Groups, n: usize) -> Vec<f64> {
    most_malicious_groups(groups).into_iter()
        .map(|(_, frac)| frac)
        .take(n)
        .collect()
}

pub fn int_percent(group: &Group) -> u32 {
    let num_malicious = group.values().filter(|d| d.is_malicious()).count();
    let frac = num_malicious as f64 / group.len() as f64;
    let rounded = (10.0 * frac).round();
    rounded as u32
}
