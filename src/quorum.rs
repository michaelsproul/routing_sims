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

//! Quorum

use super::{NN, RR};


pub trait Quorum {
    /// Get number of nodes needed for a quorum, given group size k.
    ///
    /// Get the number of messages needed for quorum. If the quorum algorithm
    /// does anything more complicated (e.g. check node age) then this will
    /// return `None`.
    fn quorum_size(&self, k: NN) -> Option<NN>;

    /// Specify proportion of group agreement required, range 0-1. Use slightly
    /// greater than half if number must be greater than 50%.
    fn set_quorum_proportion(&mut self, prop: RR);
}

pub struct SimpleQuorum {
    proportion: RR,
}

impl SimpleQuorum {
    /// New structure. Default to requiring a quorum of the entire group.
    pub fn new() -> Self {
        SimpleQuorum { proportion: 1.0 }
    }
}

impl Quorum for SimpleQuorum {
    fn quorum_size(&self, k: NN) -> Option<NN> {
        Some((k as RR * self.proportion).ceil() as NN)
    }

    fn set_quorum_proportion(&mut self, prop: RR) {
        self.proportion = prop;
    }
}
