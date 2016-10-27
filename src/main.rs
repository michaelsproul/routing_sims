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
extern crate rayon;

mod prob;
mod sim;
mod args;
mod quorum;
mod tools;

use std::result;
use std::fmt::{self, Formatter};


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
    quorum_prop: RR,
    any_group: bool,
    max_steps: NN,
    repetitions: NN,
}

impl ToolArgs {
    fn check_invariant(&self) {
        assert!(self.num_nodes >= self.num_malicious);
        assert!(self.quorum_prop >= 0.0 && self.quorum_prop <= 1.0);
    }
}


fn main() {
    env_logger::init().unwrap();
    args::main();
}
