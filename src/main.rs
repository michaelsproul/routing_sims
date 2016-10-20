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

// Calculations to do with security of routing system

#![feature(inclusive_range_syntax)]

extern crate rand;
extern crate rustc_serialize;
extern crate docopt;

mod prob;
pub mod sim;
mod args;
mod quorum;

use std::process::exit;
use quorum::Quorum;


// We could use templating but there's no reason not to do the easy thing and
// fix types.

pub type NN = u64;
pub type RR = f64;


pub trait Tool {
    /// Get the total number of nodes
    fn total_nodes(&self) -> NN;
    /// Set the total number of nodes
    fn set_total_nodes(&mut self, n: NN);

    /// Get the number of malicious nodes
    fn malicious_nodes(&self) -> NN;
    /// Set the number of malicious nodes
    fn set_malicious_nodes(&mut self, n: NN);

    /// Get the minimum group size
    fn min_group_size(&self) -> NN;
    /// Set the minimum group size
    fn set_min_group_size(&mut self, n: NN);

    /// Get the quorum algorithm
    fn quorum(&self) -> &Quorum;
    /// Adjust the quorum
    fn quorum_mut(&mut self) -> &mut Quorum;

    /// Set whether the probabilities of compromise returned should be from the
    /// point of view of a single group (any=false) or any group within the
    /// entire network (any=true).
    ///
    /// On creation this should be set to false.
    fn set_any(&mut self, any: bool);

    /// Set verbose flag
    fn set_verbose(&mut self, verbose: bool);

    /// Print a message about the computation (does not include parameters).
    fn print_message(&self);

    /// Calculate the probability of compromise (range: 0 to 1).
    fn calc_p_compromise(&self) -> RR;
}

fn main() {
    let args = args::ArgProc::read_args();
    let mut tool: Box<Tool> = match args.tool() {
        "calc" | "DirectCalcTool" => Box::new(prob::DirectCalcTool::new()),
        "sim" | "SimTool" => Box::new(sim::SimTool::new()),
        other => {
            if other.trim().len() == 0 {
                println!("No tool specified!");
            } else {
                println!("Tool not recognised: {}", other);
            }
            println!("Tools available: DirectCalcTool (\"calc\"), SimTool (\"sim\")");
            exit(1);
        }
    };
    args.apply(&mut *tool);
    let k_range = args.group_size_range().unwrap_or((8, 10));
    let q_range = args.quorum_size_range().unwrap_or(((0.5, 0.9), 0.2));

    tool.print_message();
    println!("Total nodes n = {}", tool.total_nodes());
    println!("Compromised nodes r = {}", tool.malicious_nodes());
    println!("Min group size k on horizontal axis (cols)");
    println!("Qurom size (proportion) q on vertical axis (rows)");

    const W0: usize = 3;      // width first column
    const W1: usize = 24;     // width other columns

    // header:
    print!("{1:0$}", W0 + 2, "");
    for ki in k_range.0...k_range.1 {
        print!("{1:0$}", W1, ki);
    }
    println!("");
    // rest:
    let mut q = (q_range.0).0;
    while q <= (q_range.0).1 {
        print!("{1:.0$}", W0, q);
        tool.quorum_mut().set_quorum_proportion(q);
        for ki in k_range.0...k_range.1 {
            tool.set_min_group_size(ki);
            let p = tool.calc_p_compromise();
            print!("{1:0$.e}", W1, p);
        }
        println!("");
        q += q_range.1;
    }
}
