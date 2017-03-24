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
use rand::{thread_rng, Rng};

pub trait AttackStrategy {
    fn force_to_rejoin(&mut self, _net: &Network, _ddos: bool) -> Option<(Prefix, NodeName)> {
        None
    }
}

/// Strategy which does not involve any targetting.
pub type UntargettedAttack =
    //Random
    //YoungestFromWorstGroup
    OldestFromWorstGroup
;

#[derive(Clone)]
pub struct Random;

impl AttackStrategy for Random {
    fn force_to_rejoin(&mut self, net: &Network, _ddos: bool) -> Option<(Prefix, NodeName)> {
        let malicious_nodes = all_malicious_nodes(net.groups());
        if malicious_nodes.is_empty() {
            return None;
        }
        let mut rng = thread_rng();
        let i = rng.gen_range(0, malicious_nodes.len());
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

pub fn most_malicious_groups(groups: &Groups) -> Vec<(Prefix, f64)> {
    let mut malicious = groups.iter().filter_map(|(&prefix, group)| {
        let malicious_count = group.values().filter(|x| x.is_malicious()).count();
        if malicious_count > 0 {
            Some((prefix, malicious_count as f64 / group.len() as f64))
        } else {
            None
        }
    }).collect::<Vec<_>>();
    malicious.sort_by(|&(_, m1), &(_, ref m2)| m1.partial_cmp(m2).unwrap().reverse());
    if malicious.len() >= 2 {
        assert!(malicious[0].1 >= malicious[1].1, "got the order reversed");
    }
    malicious
}
