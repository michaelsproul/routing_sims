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
use super::quorum::{Quorum, SimpleQuorum};
use super::prob::prob_compromise;
use super::sim::{Network, ChurnType};

use std::io::{Write, stderr};


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
        let mut net = Network::new(self.args.min_group_size() as usize);
        let mut remaining = self.args.total_nodes();
        while remaining > 0 {
            match net.add_node() {
                Ok(prefix) => {
                    net.churn(ChurnType::AddInitial, prefix);
                    remaining -= 1;
                    if net.need_split(prefix) {
                        net.churn(ChurnType::AddPreSplit, prefix);
                        match net.do_split(prefix) {
                            Ok(_) => {}
                            Err(e) => {
                                panic!("Error during split: {}", e);
                            }
                        };
                        net.churn(ChurnType::AddPostSplit, prefix);
                    } else {
                        net.churn(ChurnType::AddNoSplit, prefix);
                    }
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
