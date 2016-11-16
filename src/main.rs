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

extern crate rand;
extern crate rustc_serialize;
#[macro_use]
extern crate clap;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate rayon;

mod prob;
mod sim;
mod args;
mod quorum;
mod tools;

use std::result;
use std::fmt::{self, Formatter};
use std::cmp::max;

use rayon::prelude::*;
use rayon::par_iter::collect::collect_into;

use args::{ArgProc, SimParams, PARAM_TITLES};


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
    join_good: RR,
    // join_bad: RR,
    leave_good: RR,
    min_group_size: NN,
    quorum_prop: RR,
    max_steps: NN,
    repetitions: NN,
}

impl ToolArgs {
    pub fn from_params(params: &SimParams) -> Self {
        let nn = params.num_nodes;
        let nm = params.num_malicious.from_base(nn as RR);
        assert!(nn >= nm);

        // Step length in days:
        let step_len = params.proof_time;

        assert!(params.quorum_prop >= 0.0 && params.quorum_prop <= 1.0);

        let join_good = params.join_good.from_base(nn as RR) / step_len;
        // Convert from num/1000/day to p/step:
        let leave_good = params.leave_good / (1000.0 * step_len);
        assert!(join_good > leave_good);
        if (nn as RR) / (join_good - leave_good) > 1000.0 {
            warn!("Join rate ({} nodes/step) - leave rate ({} nodes/step) requires many steps \
                   for init (estimate: {})",
                  join_good,
                  leave_good,
                  ((nn as RR) / (join_good - leave_good)).round() as NN);
        }
        if leave_good > 0.0 {
            warn!("Leave rate ({} nodes/step) > 0: this might leave groups too small since we \
                   don't simulate merging",
                  leave_good);
        }

        ToolArgs {
            num_nodes: nn,
            num_malicious: nm,
            join_good: join_good,
            // join_bad: params.join_bad.map_or(join_good, |rate| rate.from_base(nn as RR) / step_len),
            leave_good: leave_good,
            min_group_size: params.min_group_size,
            quorum_prop: params.quorum_prop,
            max_steps: (params.max_days / step_len).round() as NN,
            repetitions: params.repetitions,
        }
    }
}


fn main() {
    env_logger::init().unwrap();

    let param_sets = ArgProc::make_sim_params();
    // TODO: print number of sims and/or progress

    info!("Starting to simulate {} different parameter sets",
          param_sets.len());
    let mut results = Vec::new();
    collect_into(param_sets.par_iter().map(|item| item.result()),
                 &mut results);

    //     tool.print_message();
    let col_widths: Vec<usize> = PARAM_TITLES.iter().map(|name| max(name.len(), 8)).collect();
    for col in 0..col_widths.len() {
        print!("{1:<0$}", col_widths[col], PARAM_TITLES[col]);
        print!(" ");
    }
    println!("");

    for (params, results) in param_sets.iter().zip(results) {
        print!("{1:<0$}", col_widths[0], params.sim_type.name());
        print!(" ");
        print!("{1:<0$}", col_widths[1], params.age_quorum);
        print!(" ");
        print!("{1:<0$}", col_widths[2], params.targetting.name());
        print!(" ");
        print!("{1:<0$}", col_widths[3], params.num_nodes);
        print!(" ");
        print!("{1:<0$}",
               col_widths[4],
               params.num_malicious.from_base(params.num_nodes as RR));
        print!(" ");
        print!("{1:<0$}", col_widths[5], params.min_group_size);
        print!(" ");
        print!("{1:<.*}", col_widths[6] - 2, params.quorum_prop);
        print!(" ");
        print!("{1:<.*}", col_widths[7] - 2, results.p_disrupt);
        print!(" ");
        print!("{1:<.*}", col_widths[8] - 2, results.p_compromise);
        println!("");
    }
}
