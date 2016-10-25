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
#[macro_use]
extern crate log;
extern crate env_logger;

mod prob;
mod sim;
mod args;
mod quorum;
mod tools;

use std::process::exit;
use std::result;
use std::fmt::{self, Formatter};

use tools::{Tool, DirectCalcTool, SimStructureTool, FullSimTool};
use args::QuorumRange;
use quorum::*;


// We could use templating but there's no reason not to do the easy thing and
// fix types.

pub type NN = u64;
pub type RR = f64;

/// Error type
pub enum Error {
    AddRestriction,
    AlreadyExists,
    NotFound,
}
/// Result type
pub type Result<T> = result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            &Error::AddRestriction => write!(f, "addition prevented by AddRestriction"),
            &Error::AlreadyExists => write!(f, "already exists"),
            &Error::NotFound => write!(f, "not found"),
        }
    }
}

pub struct ToolArgs {
    num_nodes: NN,
    num_malicious: NN,
    min_group_size: NN,
    any_group: bool,
    verbose: bool,
    max_steps: NN,
    repetitions: NN,
}
impl ToolArgs {
    fn new() -> Self {
        ToolArgs {
            num_nodes: 5000,
            num_malicious: 500,
            min_group_size: 10,
            any_group: false,
            verbose: false,
            max_steps: 10000,
            repetitions: 100,
        }
    }

    fn total_nodes(&self) -> NN {
        self.num_nodes
    }

    fn set_total_nodes(&mut self, n: NN) {
        self.num_nodes = n;
    }

    fn malicious_nodes(&self) -> NN {
        self.num_malicious
    }

    fn min_group_size(&self) -> NN {
        self.min_group_size
    }

    fn set_min_group_size(&mut self, n: NN) {
        self.min_group_size = n;
    }

    fn any_group(&self) -> bool {
        self.any_group
    }

    fn set_any_group(&mut self, any: bool) {
        self.any_group = any;
    }

    fn verbose(&self) -> bool {
        self.verbose
    }

    fn set_verbose(&mut self, v: bool) {
        self.verbose = v;
    }
    
    fn check_invariant(&self) {
        assert!(self.num_nodes >= self.num_malicious);
    }
}


fn main() {
    env_logger::init().unwrap();
    let args = args::ArgProc::read_args();
    let mut tool: Box<Tool> = match args.tool() {
        "calc" | "simple" => Box::new(DirectCalcTool::new()),
        "structure" => Box::new(SimStructureTool::new()),
        "age_only" => Box::new(FullSimTool::new(SimpleQuorum::new(), UntargettedAttack {})),
        other => {
            if other.trim().len() == 0 {
                println!("No tool specified!");
            } else {
                println!("Tool not recognised: {}", other);
            }
            println!("Run with --help for a list of tools.");
            exit(1);
        }
    };
    args.apply(tool.args_mut());
    let group_size_range = args.group_size_range().unwrap_or((8, 10));
    let quorum_range = match args.quorum_size_range() {
        Some(r) => r,
        None => {
            QuorumRange {
                range: (0.5, 0.9),
                step: 0.2,
            }
        }
    };

    tool.print_message();
    println!("Total nodes n = {}", tool.args_mut().total_nodes());
    println!("Compromised nodes r = {}",
             tool.args_mut().malicious_nodes());
    println!("Min group size k on horizontal axis (cols)");
    println!("Qurom size (proportion) q on vertical axis (rows)");

    const W0: usize = 3;      // width first column
    const W1: usize = 24;     // width other columns

    // header:
    print!("{1:0$}", W0 + 2, "");
    for group_size in group_size_range.0...group_size_range.1 {
        print!("{1:0$}", W1, group_size);
    }
    println!("");
    // rest:
    let mut quorum_size = quorum_range.range.0;
    while quorum_size <= quorum_range.range.1 {
        print!("{1:.0$}", W0, quorum_size);
        tool.quorum_mut().set_quorum_proportion(quorum_size);
        for group_size in group_size_range.0...group_size_range.1 {
            tool.args_mut().set_min_group_size(group_size);
            let p = tool.calc_p_compromise();
            print!("{1:0$.e}", W1, p);
        }
        println!("");
        quorum_size += quorum_range.step;
    }
}
