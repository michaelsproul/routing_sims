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
use super::quorum::{Quorum, SimpleQuorum, AttackStrategy};
use super::prob::prob_compromise;
use super::sim::{Network, new_node_name, NodeData, NoAddRestriction, RestrictOnePerAge};

use std::io::{Write, stderr};
use std::iter;
use std::collections::VecDeque;


pub trait Tool {
    /// Get the wrapped arguments struct
    fn args_mut(&mut self) -> &mut ToolArgs;

    /// Adjust the quorum
    fn quorum_mut(&mut self) -> &mut Quorum;

    /// Print a message about the computation (does not include parameters).
    fn print_message(&self);

    /// Calculate the probability of compromise (range: 0 to 1).
    fn calc_p_compromise(&self) -> RR;
}


/// Simplest tool: assumes all groups have minimum size; cannot simulate
/// targeting or ageing.
pub struct DirectCalcTool {
    args: ToolArgs,
    quorum: SimpleQuorum,
}

impl DirectCalcTool {
    pub fn new() -> Self {
        DirectCalcTool {
            args: ToolArgs::new(),
            quorum: SimpleQuorum::new(),
        }
    }
}

impl Tool for DirectCalcTool {
    fn args_mut(&mut self) -> &mut ToolArgs {
        &mut self.args
    }

    fn quorum_mut(&mut self) -> &mut Quorum {
        &mut self.quorum
    }

    fn print_message(&self) {
        println!("Tool: calculate probability of compromise, assuming all groups have minimum \
                  size");
        if self.args.any_group() {
            println!("Output: the probability that at least one group is compromised");
        } else {
            println!("Output: chance of a randomly selected group being compromised");
        }
    }

    fn calc_p_compromise(&self) -> RR {
        let k = self.args.min_group_size();
        let q = self.quorum.quorum_size(k).expect("simple quorum size");
        let p = prob_compromise(self.args.total_nodes(), self.args.malicious_nodes(), k, q);

        if self.args.verbose() {
            writeln!(stderr(),
                     "n: {}, r: {}, k: {}, q: {}, P(single group) = {:.e}",
                     self.args.total_nodes(),
                     self.args.malicious_nodes(),
                     k,
                     q,
                     p)
                .expect("writing to stderr to work");
        }

        if self.args.any_group() {
            let n_groups = (self.args.total_nodes() as RR) / (self.args.min_group_size() as RR);
            1.0 - (1.0 - p).powf(n_groups)
        } else {
            p
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
    pub fn new() -> Self {
        SimStructureTool {
            args: ToolArgs::new(),
            quorum: SimpleQuorum::new(),
        }
    }
}

impl Tool for SimStructureTool {
    fn args_mut(&mut self) -> &mut ToolArgs {
        &mut self.args
    }

    fn quorum_mut(&mut self) -> &mut Quorum {
        &mut self.quorum
    }

    fn print_message(&self) {
        println!("Tool: simulate allocation of nodes to groups; each has size at least the \
                  specified minimum size");
        if self.args.any_group() {
            println!("Output: the probability that at least one group is compromised");
        } else {
            println!("Output: chance of a randomly selected group being compromised");
        }
    }

    fn calc_p_compromise(&self) -> RR {
        // Create a network
        let mut net = Network::<NoAddRestriction>::new(self.args.min_group_size() as usize);
        let mut remaining = self.args.total_nodes();
        while remaining > 0 {
            let name = new_node_name();
            match net.add_node(name, NodeData::new()) {
                Ok(prefix) => {
                    remaining -= 1;
                    let _prefix = net.maybe_split(prefix, name);
                }
                Err(Error::AlreadyExists) => {
                    continue;
                }
                Err(e) => {
                    panic!("Error adding node: {}", e);
                }
            };
        }

        if self.args.any_group() {
            // This isn't quite right, since one group not compromised does
            // tell you _something_ about the distribution of malicious nodes,
            // thus probabilities are not indepedent. But unless there are a lot
            // of malicious nodes it should be close.
            let mut p_no_compromise = 1.0;
            for (_, group) in net.groups() {
                let k = group.len() as NN;
                let q = self.quorum.quorum_size(k).expect("simple quorum size");
                let p = prob_compromise(self.args.total_nodes(), self.args.malicious_nodes(), k, q);
                p_no_compromise *= 1.0 - p;
            }
            1.0 - p_no_compromise
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
            let p = prob_compromise(self.args.total_nodes(), self.args.malicious_nodes(), k, q);

            if self.args.verbose() {
                writeln!(stderr(),
                         "n: {}, r: {}, k: {}, q: {}, P(single group) = {:.e}",
                         self.args.total_nodes(),
                         self.args.malicious_nodes(),
                         k,
                         q,
                         p)
                    .expect("writing to stderr to work");
            }

            p
        }
    }
}


/// A tool which simulates group operations.
///
/// Can relocate nodes according to the node ageing RFC (roughly).
pub struct FullSimTool<Q: Quorum, A: AttackStrategy> {
    args: ToolArgs,
    quorum: Q,
    attack: A,
}

impl<Q: Quorum, A: AttackStrategy> FullSimTool<Q, A> {
    pub fn new(quorum: Q, strategy: A) -> Self {
        FullSimTool {
            args: ToolArgs::new(),
            quorum: quorum,
            attack: strategy,
        }
    }

    // Run a simulation. Return true if a compromise occurred. Only supports
    // "any group" mode.
    fn run_sim(&self) -> bool {
        info!("Starting sim");
        assert!(self.args.any_group);
        let mut attack = self.attack.clone();

        // 1. Create initial network.
        // For simplicity, we ignore all add-attempts which fail due to age restrictions
        // (these do not affect the network and would simply be re-added later).
        // Because of this and the assumption that all these nodes are "good",
        // we do not need to simulate proof-of-work here.
        let mut net = Network::<RestrictOnePerAge>::new(self.args.min_group_size() as usize);
        let num_initial = self.args.total_nodes() - self.args.malicious_nodes();
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
            trace!("Adding from a queue of length {} with {} groups", to_add.len(), net.groups().len());
            let age = node_data.age();
            match net.add_node(node_name, node_data) {
                Ok(prefix) => {
                    trace!("Added node {} with age {}", node_name, age);
                    let prefix = net.maybe_split(prefix, node_name);
                    // Add successful: do churn event.
                    // The churn may cause a removal from a group; however, either that was an
                    // old group which just got a new member, or it is a split result with at least
                    // one node more than the minimum number. Either way merging is not required.
                    if let Some(node) = net.churn(prefix) {
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
        info!("Init done: added {} nodes in {} steps involving {} relocates and {} rejections", num_initial, n_ops, n_relocates, n_rejects);

        // 2. Start attack
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
        let mut n_new_malicious = self.args.malicious_nodes();
        // Queue of nodes doing proof-of-work. Push to back, pop from front.
        let mut waiting = VecDeque::new();
        for _ in 0..self.args.max_steps {
            // Each round, we firstly deal with all "waiting" nodes, then add any new/reset nodes.
            while let Some((node_name, node_data)) = waiting.pop_front() {
                match net.add_node(node_name, node_data) {
                    Ok(prefix) => {
                        let prefix = net.maybe_split(prefix, node_name);
                        // Add successful: do churn event.
                        // The churn may cause a removal from a group; however, either that was an
                        // old group which just got a new member, or it is a split result with at
                        // least one node more than the minimum number. Either way merging
                        // is not required.
                        if let Some(node) = net.churn(prefix) {
                            if attack.reset_node(&node, net.find_prefix(node_name)) {
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

            // Finally, we check if a compromise-of-quorum occurred.
            for (_, ref group) in net.groups() {
                if self.quorum.quorum_disrupted(group) {
                    return true;
                }
            }
        }

        // If we didn't return already, no compromise occurred
        false
    }
}

impl<Q: Quorum, A: AttackStrategy> Tool for FullSimTool<Q, A> {
    fn args_mut(&mut self) -> &mut ToolArgs {
        &mut self.args
    }

    fn quorum_mut(&mut self) -> &mut Quorum {
        &mut self.quorum
    }

    fn print_message(&self) {
        println!("Tool: simulate group operations");
        if self.args.any_group() {
            println!("Output: the probability that at least one group is compromised");
        } else {
            println!("Output: chance of a randomly selected group being compromised");
        }
    }

    fn calc_p_compromise(&self) -> RR {
        let compromises = iter::repeat(0)
            .take(self.args.repetitions as usize)
            .filter(|_| self.run_sim())
            .count() as RR;
        compromises / (self.args.repetitions as RR)
    }
}
