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

/// Drivers of the simulations / calculations


use rayon::prelude::*;

use {NN, RR, ToolArgs};
use quorum::{Quorum, SimpleQuorum};
use attack::{AttackStrategy, Random};
use prob::{prob_disruption, prob_compromise};
use net::{Network, NoAddRestriction, RestrictOnePerAge};
use node::NodeData;
use metadata::Metadata;
use std::marker::PhantomData;

/// Result of a simulation, carrying probabilities of different types of compromise.
#[derive(Clone, Copy)]
pub struct SimResult {
    /// Honest nodes can't form quorum in a section.
    p_disrupt: f64,
    /// Attacker can form quorum in a section.
    p_compromise: f64,
    /// Attacker can double-vote with non-zero probability.
    p_double_vote: f64,
    /// Attacker can form quorum in a data group with non-zero probability.
    p_data_compromise: f64,
}

impl SimResult {
    pub fn legacy(p_disrupt: f64, p_compromise: f64) -> Self {
        Self::new(p_disrupt, p_compromise, 0.0, 0.0)
    }

    pub fn new(p_disrupt: f64,
               p_compromise: f64,
               p_double_vote: f64,
               p_data_compromise: f64) -> Self {
        SimResult {
            p_disrupt,
            p_compromise,
            p_double_vote,
            p_data_compromise
        }
    }

    pub fn p_disrupt(&self) -> RR {
        self.p_disrupt
    }

    pub fn p_compromise(&self) -> RR {
        self.p_compromise
    }

    pub fn p_double_vote(&self) -> f64 {
        self.p_double_vote
    }

    pub fn p_data_compromise(&self) -> RR {
        self.p_data_compromise
    }
}


pub trait Tool {
    /// Print a message about the computation (does not include parameters).
    fn print_message(&self);

    /// Calculate the probability of compromise (range: 0 to 1).
    ///
    /// `repetitions` is how many times to repeat the simulation; this is only applicable to the
    /// full sim.
    fn calc_p_compromise(&self, repetitions: u32) -> SimResult;
}


/// Simplest tool: assumes all groups have minimum size; cannot simulate
/// targeting or ageing.
pub struct DirectCalcTool<'a> {
    args: &'a ToolArgs,
    quorum: SimpleQuorum,
}

impl<'a> DirectCalcTool<'a> {
    pub fn new(args: &'a ToolArgs) -> Self {
        let quorum = SimpleQuorum::from(args.section_quorum_prop);
        DirectCalcTool {
            args: args,
            quorum: quorum,
        }
    }
}

impl<'a> Tool for DirectCalcTool<'a> {
    fn print_message(&self) {
        println!("Tool: calculate probability of compromise, assuming all groups have minimum \
                  size");
        let any_group = true;   // only support this now
        if any_group {
            println!("Output: the probability that at least one group is compromised");
        } else {
            println!("Output: chance of a randomly selected group being compromised");
        }
    }

    fn calc_p_compromise(&self, _: u32) -> SimResult {
        let k = self.args.min_section_size;
        let q = self.quorum.quorum_size(k).expect("simple quorum size");
        let n = self.args.num_initial + self.args.num_attacking;
        let pd = prob_disruption(n, self.args.num_attacking, k, q);
        let pc = prob_compromise(n, self.args.num_attacking, k, q);

        trace!("n: {}, r: {}, k: {}, q: {}, pd: {:.e}, pc: {:.e}",
               n,
               self.args.num_attacking,
               k,
               q,
               pd,
               pc);

        let n_groups = (n as RR) / (self.args.min_section_size as RR);
        SimResult::legacy(1.0 - (1.0 - pd).powf(n_groups),
                          1.0 - (1.0 - pc).powf(n_groups))
    }
}


/// A tool which simulates the group structure (division of nodes in the
/// network between groups), then does direct calculations based on these
/// groups. This should be more accurate than DirectCalcTool in "any group"
/// mode, but has the same limitations.
///
/// Does not relocate nodes (node ageing).
pub struct SimStructureTool<'a> {
    args: &'a ToolArgs,
    quorum: SimpleQuorum,
}

impl<'a> SimStructureTool<'a> {
    pub fn new(args: &'a ToolArgs) -> Self {
        let quorum = SimpleQuorum::from(args.section_quorum_prop);
        SimStructureTool {
            args: args,
            quorum: quorum,
        }
    }
}

impl<'a> Tool for SimStructureTool<'a> {
    fn print_message(&self) {
        println!("Tool: simulate allocation of nodes to groups; each has size at least the \
                  specified minimum size");
        let any_group = true;   // only support this now
        if any_group {
            println!("Output: the probability that at least one group is compromised");
        } else {
            println!("Output: chance of a randomly selected group being compromised");
        }
    }

    fn calc_p_compromise(&self, _: u32) -> SimResult {
        // We need an "attack" strategy, though we only support one here
        let mut attack = Random::create(self.args, "");

        // Create a network of good nodes (this tool assumes all nodes are good in the sim then
        // assumes some are bad in subsequent calculations).
        let mut net = Network::new(self.args.min_section_size as usize);
        // Yes, *attacking* nodes are *good* for this network initialisation!
        net.add_avail(self.args.num_initial + self.args.num_attacking, 0);
        while net.has_avail() {
            net.do_step::<NoAddRestriction>(&self.args, &mut attack, false);
        }
        // The above got all available nodes ready for insert, but the last step will have left
        // some pending insert, so do one more step. Note that we can't wait until the queues are
        // empty because background-leaving may result in a constant churn.
        net.do_step::<NoAddRestriction>(&self.args, &mut attack, false);

        // This isn't quite right, since one group not compromised does
        // tell you _something_ about the distribution of malicious nodes,
        // thus probabilities are not indepedent. But unless there are a lot
        // of malicious nodes it should be close.
        let mut p_no_disruption = 1.0;
        let mut p_no_compromise = 1.0;
        for (_, group) in net.groups() {
            let k = group.len() as NN;
            let q = self.quorum.quorum_size(k).expect("simple quorum size");
            let n = self.args.num_initial + self.args.num_attacking;
            let pd = prob_disruption(n, self.args.num_attacking, k, q);
            let pc = prob_compromise(n, self.args.num_attacking, k, q);
            p_no_disruption *= 1.0 - pd;
            p_no_compromise *= 1.0 - pc;
        }
        SimResult::legacy(1.0 - p_no_disruption, 1.0 - p_no_compromise)
    }
}


/// A tool which simulates group operations.
///
/// Can relocate nodes according to the node ageing RFC (roughly).
pub struct FullSimTool<'a, A: AttackStrategy> {
    args: &'a ToolArgs,
    section_quorum: Box<Quorum + Sync>,
    group_quorum: Box<Quorum + Sync>,
    _phantom: PhantomData<A>,
}

impl<'a, A: AttackStrategy> FullSimTool<'a, A> {
    pub fn new(args: &'a ToolArgs,
               mut section_quorum: Box<Quorum + Sync>,
               mut group_quorum: Box<Quorum + Sync>)
               -> Self
    {
        section_quorum.set_quorum_proportion(args.section_quorum_prop);
        group_quorum.set_quorum_proportion(args.group_quorum_prop);
        FullSimTool {
            args: args,
            section_quorum: section_quorum,
            group_quorum: group_quorum,
            _phantom: PhantomData,
        }
    }

    // Run a simulation. Result has either 0 or 1 in each field, `(any_disruption, any_compromise)`.
    fn run_sim(&self, i: u32) -> SimResult {
        let spec_str = self.args.spec_str(i);
        let mut attack = A::create(self.args, &spec_str);
        let mut metadata = Metadata::new(&spec_str, self.args.write_metadata);

        // 1. Create an initial network of good nodes.
        let mut net = Network::new(self.args.min_section_size as usize);
        metadata.update(&net, 0.0, 0.0);

        for i in 0..self.args.num_initial {
            trace!("adding node: {}", i);
            net.add_node::<RestrictOnePerAge>(NodeData::new(false));
            metadata.update(&net, 0.0, 0.0);
            net.add_all_pending_nodes::<RestrictOnePerAge>();
            metadata.update(&net, 0.0, 0.0);
        }

        // 2. Join the malicious nodes.
        for _ in 0..self.args.num_attacking {
            net.add_node::<RestrictOnePerAge>(NodeData::new(true));
            net.add_all_pending_nodes::<RestrictOnePerAge>();
            metadata.update(&net, 0.0, 0.0);
        }

        // 2. Start attack
        // In this model, malicious nodes are added once while good nodes can be added
        // continuously.
        // net.add_avail(0, self.args.num_attacking);
        // let mut to_add_good = 0.0;

        let mut disruption = false;
        let mut data_corrupted = false;
        let mut double_vote = false;

        let allow_join_leave = true;

        for _ in 0..self.args.max_steps {
            /*
            to_add_good += self.args.add_rate_good;
            let n_new = to_add_good.floor();
            net.add_avail(n_new as NN, 0);
            to_add_good -= n_new;
            */

            net.do_step::<RestrictOnePerAge>(&self.args, &mut attack, allow_join_leave);

            let corrupt_fraction = net.compromised_data_fraction(
                self.args.group_size,
                &self.group_quorum
            );

            data_corrupted |= corrupt_fraction.is_some();

            let double_vote_prob = net.max_double_vote_prob(&self.section_quorum);
            double_vote |= double_vote_prob > 0.0;

            metadata.update(&net, double_vote_prob, corrupt_fraction.unwrap_or(0.0));

            // Check if disruption or compromise occurred:
            // TODO(michael): rename groups => sections everywhere
            for (_, ref group) in net.groups() {
                if self.section_quorum.quorum_compromised(group) {
                    // Compromise implies disruption!
                    return SimResult::new(1.0, 1.0, bool_prob(double_vote), bool_prob(data_corrupted));
                } else if self.section_quorum.quorum_disrupted(group) {
                    disruption = true;
                }
            }
        }

        SimResult::new(bool_prob(disruption), 0.0, bool_prob(double_vote), bool_prob(data_corrupted))
    }
}

fn bool_prob(value: bool) -> f64 {
    if value { 1.0 } else { 0.0 }
}

impl<'a, A: AttackStrategy> Tool for FullSimTool<'a, A>
    where A: Sync
{
    fn print_message(&self) {
        println!("Tool: simulate group operations");
        let any_group = true;   // only support this now
        if any_group {
            println!("Output: the probability that at least one group is compromised");
        } else {
            println!("Output: chance of a randomly selected group being compromised");
        }
    }

    fn calc_p_compromise(&self, repetitions: u32) -> SimResult {
        let result = (0..repetitions)
            .into_par_iter()
            .map(|i| self.run_sim(i))
            .reduce(|| SimResult::new(0.0, 0.0, 0.0, 0.0),
                    |v1, v2| {
                        SimResult::new(
                            v1.p_disrupt + v2.p_disrupt,
                            v1.p_compromise + v2.p_compromise,
                            v1.p_double_vote + v2.p_double_vote,
                            v1.p_data_compromise + v2.p_data_compromise
                        )
                    });

        let denom = repetitions as RR;
        let res = SimResult::new(
            result.p_disrupt / denom,
            result.p_compromise / denom,
            result.p_double_vote / denom,
            result.p_data_compromise / denom
        );
        println!("{} {:.05} {:.05} {:.05} {:.05}",
            self.args.spec_str(0), res.p_disrupt(), res.p_compromise(),
            res.p_double_vote(), res.p_data_compromise()
        );
        res
    }
}
