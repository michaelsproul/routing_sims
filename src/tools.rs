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


use super::{NN, RR, ToolArgs, Error};
use super::quorum::{Quorum, SimpleQuorum, AttackStrategy, UntargettedAttack};
use super::prob::{prob_disruption, prob_compromise};
use super::sim::{Network, new_node_name, NodeData, NoAddRestriction, RestrictOnePerAge};

use std::iter;
use std::collections::VecDeque;


pub struct SimResult {
    pub p_disrupt: RR,
    pub p_compromise: RR,
}


pub trait Tool {
    /// Print a message about the computation (does not include parameters).
    fn print_message(&self);

    /// Calculate the probability of compromise (range: 0 to 1).
    fn calc_p_compromise(&self) -> SimResult;
}


/// Simplest tool: assumes all groups have minimum size; cannot simulate
/// targeting or ageing.
pub struct DirectCalcTool {
    args: ToolArgs,
    quorum: SimpleQuorum,
}

impl DirectCalcTool {
    pub fn new(args: ToolArgs) -> Self {
        let quorum = SimpleQuorum::from(args.quorum_prop);
        DirectCalcTool {
            args: args,
            quorum: quorum,
        }
    }
}

impl Tool for DirectCalcTool {
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

    fn calc_p_compromise(&self) -> SimResult {
        let k = self.args.min_group_size;
        let q = self.quorum.quorum_size(k).expect("simple quorum size");
        let pd = prob_disruption(self.args.num_nodes, self.args.num_malicious, k, q);
        let pc = prob_compromise(self.args.num_nodes, self.args.num_malicious, k, q);

        trace!("n: {}, r: {}, k: {}, q: {}, pd: {:.e}, pc: {:.e}",
               self.args.num_nodes,
               self.args.num_malicious,
               k,
               q,
               pd,
               pc);

        let any_group = true;   // only support this now
        if any_group {
            let n_groups = (self.args.num_nodes as RR) / (self.args.min_group_size as RR);
            SimResult {
                p_disrupt: 1.0 - (1.0 - pd).powf(n_groups),
                p_compromise: 1.0 - (1.0 - pc).powf(n_groups),
            }
        } else {
            SimResult {
                p_disrupt: pd,
                p_compromise: pc,
            }
        }
    }
}


/// A tool which simulates the group structure (division of nodes in the
/// network between groups), then does direct calculations based on these
/// groups. This should be more accurate than DirectCalcTool in "any group"
/// mode, but has the same limitations.
///
/// Does not relocate nodes (node ageing).
pub struct SimStructureTool {
    args: ToolArgs,
    quorum: SimpleQuorum,
}

impl SimStructureTool {
    pub fn new(args: ToolArgs) -> Self {
        let quorum = SimpleQuorum::from(args.quorum_prop);
        SimStructureTool {
            args: args,
            quorum: quorum,
        }
    }
}

impl Tool for SimStructureTool {
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

    fn calc_p_compromise(&self) -> SimResult {
        // We need an "attack" strategy, though we only support one here
        let mut attack = UntargettedAttack {};

        // Create a network
        let mut net = Network::<NoAddRestriction>::new(self.args.min_group_size as usize);
        // Number of nodes to join/leave each step (can be fractional)
        let mut to_join = 0.0;
        let mut to_leave = 0.0;
        // Network size and target size
        let mut net_size = 0;
        let target_size = self.args.num_nodes;
        'outer: loop {
            to_join += self.args.join_good;
            to_leave += self.args.leave_good;
            
            while to_join >= 1.0 {
                to_join -= 1.0;
                let name = new_node_name();
                match net.add_node(name, NodeData::new()) {
                    Ok(prefix) => {
                        let _prefix = net.maybe_split(prefix, name, &mut attack);
                        net_size += 1;
                        if net_size >= target_size {
                            break 'outer;
                        }
                    }
                    Err(Error::AlreadyExists) => {
                        continue;
                    }
                    Err(e) => {
                        panic!("Error adding node: {}", e);
                    }
                }
            };
            
            // only do anything if we expect at least one node to leave
            if to_leave >= 1.0 {
                let p_leave = to_leave / (net_size as RR);
                net_size -= net.probabilistic_drop(p_leave) as NN;
                to_leave = 0.0;
            }
        }

        let any_group = true;   // only support this now
        if any_group {
            // This isn't quite right, since one group not compromised does
            // tell you _something_ about the distribution of malicious nodes,
            // thus probabilities are not indepedent. But unless there are a lot
            // of malicious nodes it should be close.
            let mut p_no_disruption = 1.0;
            let mut p_no_compromise = 1.0;
            for (_, group) in net.groups() {
                let k = group.len() as NN;
                let q = self.quorum.quorum_size(k).expect("simple quorum size");
                let pd = prob_disruption(self.args.num_nodes, self.args.num_malicious, k, q);
                let pc = prob_compromise(self.args.num_nodes, self.args.num_malicious, k, q);
                p_no_disruption *= 1.0 - pd;
                p_no_compromise *= 1.0 - pc;
            }
            SimResult {
                p_disrupt: 1.0 - p_no_disruption,
                p_compromise: 1.0 - p_no_compromise,
            }
        } else {
            // Calculate probability of compromise of one selected group.

            // Take the group appearing first in self.groups. Since hash-maps
            // are randomly ordered in Rust, there should be nothing special
            // about this group.
            let (_, group) =
                net.groups().iter().next().expect("there should be at least one group");
            let k = group.len() as NN;
            let q = self.quorum.quorum_size(k).expect("simple quorum size");

            // We already have code to do the rest:
            let pd = prob_disruption(self.args.num_nodes, self.args.num_malicious, k, q);
            let pc = prob_compromise(self.args.num_nodes, self.args.num_malicious, k, q);

            trace!("n: {}, r: {}, k: {}, q: {}, pd: {:.e}, pc: {:.e}",
                   self.args.num_nodes,
                   self.args.num_malicious,
                   k,
                   q,
                   pd,
                   pc);

            SimResult {
                p_disrupt: pd,
                p_compromise: pc,
            }
        }
    }
}


/// A tool which simulates group operations.
///
/// Can relocate nodes according to the node ageing RFC (roughly).
pub struct FullSimTool<Q: Quorum, A: AttackStrategy + Clone> {
    args: ToolArgs,
    quorum: Q,
    attack: A,
}

impl<Q: Quorum, A: AttackStrategy + Clone> FullSimTool<Q, A> {
    pub fn new(args: ToolArgs, mut quorum: Q, strategy: A) -> Self {
        quorum.set_quorum_proportion(args.quorum_prop);
        FullSimTool {
            args: args,
            quorum: quorum,
            attack: strategy,
        }
    }

    // Run a simulation. Result is a pair of booleans, `(any_disruption, any_compromise)`.
    fn run_sim(&self) -> (bool, bool) {
        info!("Starting sim");
        let mut disruption = false;
        let mut attack = self.attack.clone();

        // 1. Create initial network.
        //TODO: use join_rate and leave_rate as in SimStructureTool
        // For simplicity, we ignore all add-attempts which fail due to age restrictions
        // (these do not affect the network and would simply be re-added later).
        // Because of this and the assumption that all these nodes are "good",
        // we do not need to simulate proof-of-work here.
        let mut net = Network::<RestrictOnePerAge>::new(self.args.min_group_size as usize);
        let num_initial = self.args.num_nodes - self.args.num_malicious;
        // Pre-generate all nodes to be added, in a Vec.
        // We can pop from this and on relocation push.
        let mut to_add: Vec<_> = iter::repeat(0)
            .take(num_initial as usize)
            .map(|_| (new_node_name(), NodeData::new()))
            .collect();
        let mut n_ops = 0;
        let mut n_relocates = 0;
        let mut n_rejects = 0;
        while let Some((node_name, node_data)) = to_add.pop() {
            n_ops += 1;
            trace!("Adding from a queue of length {} with {} groups",
                   to_add.len() + 1,
                   net.groups().len());
            let age = node_data.age();
            match net.add_node(node_name, node_data) {
                Ok(prefix) => {
                    trace!("Added node {} with age {}", node_name, age);
                    let prefix = net.maybe_split(prefix, node_name, &mut attack);
                    // Add successful: do churn event.
                    // The churn may cause a removal from a group; however, either that was an
                    // old group which just got a new member, or it is a split result with at least
                    // one node more than the minimum number. Either way merging is not required.
                    if let Some(node) = net.churn(prefix, node_name) {
                        n_relocates += 1;
                        to_add.push(node);
                    }
                }
                Err(Error::AlreadyExists) |
                Err(Error::AddRestriction) => {
                    n_rejects += 1;
                    // We fixed the number of initial nodes. If this one is incompatible,
                    // find another.
                    to_add.push((new_node_name(), NodeData::new()));
                }
                Err(e) => {
                    panic!("Error adding node: {}", e);
                }
            }
        }
        info!("Init done: added {} nodes in {} steps involving {} relocates and {} rejections",
              num_initial,
              n_ops,
              n_relocates,
              n_rejects);

        // 2. Start attack
        // TODO: use join rate (both good and bad nodes), leave rate and limit resets
        // Assumption: all nodes in the network (malicious or not) have the same performance.
        // Proof-of-work time-outs can be used to filter out any nodes with slow CPU/network.
        // We use a step, which is how long proof-of-work takes. We don't set a value here, but
        // for example 10000 × 1-hour steps is over a year.

        // Assumption: only malicious nodes are added after this time, and a fixed number. This
        // is a worst case scenario; if there were background-adding of other nodes or if all the
        // attacking nodes were not added simultaneously, the attack would be harder.

        // Assumption: the network gives joining nodes a group immediately, but does not
        // accept the node as a member until after proof-of-work. Nodes can choose to reset before
        // doing the work. We assume nodes will not try to reset at any other time.
        // We assume that nodes can reset and try to join again (with age 0) instantly. This may
        // be problematic if some nodes target groups purely to cause churn events.

        // Unlike above, we now use a two-step join process: (1) nodes are "pre-added": they are
        // given a name and group, then either reset or wait until (2) nodes have done
        // proof-of-work and can join.

        // Assumption: if a node has done proof-of-work but its original target group splits, it
        // simply joins whichever group it would now be in. If a node has done proof of work and
        // is not accepted due to age restrictions, it is given a new name and must redo work.
        let mut n_new_malicious = self.args.num_malicious;
        // Queue of nodes doing proof-of-work. Push to back, pop from front.
        let mut waiting = VecDeque::new();
        for _ in 0..self.args.max_steps {
            // Each round, we firstly deal with all "waiting" nodes, then add any new/reset nodes.
            while let Some((node_name, node_data)) = waiting.pop_front() {
                match net.add_node(node_name, node_data) {
                    Ok(prefix) => {
                        let prefix = net.maybe_split(prefix, node_name, &mut attack);
                        // Add successful: do churn event.
                        // The churn may cause a removal from a group; however, either that was an
                        // old group which just got a new member, or it is a split result with at
                        // least one node more than the minimum number. Either way merging
                        // is not required.
                        if let Some(node) = net.churn(prefix, node_name) {
                            if node.1.is_malicious() &&
                               attack.reset_node(&node, net.find_prefix(node_name)) {
                                n_new_malicious += 1;
                            } else {
                                waiting.push_back(node);
                            }
                        }
                    }
                    Err(Error::AlreadyExists) |
                    Err(Error::AddRestriction) => {
                        // Cannot be added: rename and try again next round.
                        let node = (new_node_name(), node_data);
                        waiting.push_back(node);
                    }
                    Err(e) => {
                        panic!("Error adding node: {}", e);
                    }
                }
            }

            while n_new_malicious > 0 {
                let node = (new_node_name(), NodeData::new_malicious());
                let prefix = net.find_prefix(node.0);
                if !attack.reset_node(&node, prefix) {
                    n_new_malicious -= 1;
                    waiting.push_back(node);
                }
            }

            // Finally, we check if disruption or compromise occurred:
            for (_, ref group) in net.groups() {
                if self.quorum.quorum_compromised(group) {
                    // Compromise implies disruption!
                    return (true, true);
                } else if self.quorum.quorum_disrupted(group) {
                    disruption = true;
                }
            }
        }

        // If we didn't return already, no compromise occurred, but disruption may have
        (disruption, false)
    }
}

impl<Q: Quorum, A: AttackStrategy + Clone> Tool for FullSimTool<Q, A> {
    fn print_message(&self) {
        println!("Tool: simulate group operations");
        let any_group = true;   // only support this now
        if any_group {
            println!("Output: the probability that at least one group is compromised");
        } else {
            println!("Output: chance of a randomly selected group being compromised");
        }
    }

    fn calc_p_compromise(&self) -> SimResult {
        let mut n_disruptions = 0;
        let mut n_compromises = 0;
        for _ in 0..self.args.repetitions {
            let r = self.run_sim();
            if r.0 {
                n_disruptions += 1;
            }
            if r.1 {
                n_compromises += 1;
            }
        }
        let denom = self.args.repetitions as RR;
        SimResult {
            p_disrupt: (n_disruptions as RR) / denom,
            p_compromise: (n_compromises as RR) / denom,
        }
    }
}
