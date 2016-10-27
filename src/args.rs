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

//! Argument processing

use docopt::Docopt;
use super::{ToolArgs, NN, RR};
use super::tools::{Tool, DirectCalcTool, SimStructureTool, FullSimTool};
use super::quorum::*;

use std::str::FromStr;
use std::fmt::Debug;
use std::process::exit;
use std::cmp::max;


const USAGE: &'static str =
    "
Probability computation tool.

Usage:
    routing-sims [-h | --help]
    routing-sims \
     <tool> [-n NUM] [-r VAL] [-k RANGE] [-q RANGE] [-s VAL] [-p VAL]

Tools:
    calc        \
     Direct calculation: all groups have min size, no ageing or targetting
    structure   \
     Simulate group structure, but no ageing or targetting
    age_simple  Simulate node ageing, \
     but not targetting. Simple quorum.
    age_quorum  Simulate node ageing, but not targetting. \
     Quorum uses age.
    targetted_age_simple    Simulate node ageing, a simple targetted \
     attack, with the simple quorum
    targetted_age_quorum    Simulate node ageing, a simple \
     targetted attack, using age in the quorum

Options:
    -h --help   Show this message
    -n \
     NUM      Number of nodes, total.
    -r VAL      Either number of compromised nodes (e.g. \
     50) or percentage (default is 10%).
    -k RANGE    Minimum group size, e.g. 10-20.
    -q \
     RANGE    Quorum size as a percentage with step size, e.g. 50-90:10.
    -s VAL      Maximum \
     number of steps, each the length of one proof-of-work.
    -p VAL      Number of times to \
     repeat a true/false simulation to calculate
                an attack success probability.
";

#[derive(RustcDecodable)]
struct Args {
    arg_tool: String,
    flag_n: Option<NN>,
    flag_r: Option<String>,
    flag_k: Option<String>,
    flag_q: Option<String>,
    flag_s: Option<NN>,
    flag_p: Option<NN>,
}

pub struct QuorumRange {
    pub range: (RR, RR),
    pub step: RR,
}

pub struct ArgProc {
    args: Args,
}

impl ArgProc {
    fn read_args() -> ArgProc {
        let args: Args = Docopt::new(USAGE)
            .and_then(|dopt| dopt.decode())
            .unwrap_or_else(|e| e.exit());

        ArgProc { args: args }
    }

    // TODO: is Vec suitable for this use?
    fn make_sim_params(&self) -> Vec<SimParams> {
        let mut v = Vec::new();

        let group_size_range =
            self.args.flag_k.as_ref().map(|s| Self::parse_range(&s)).unwrap_or((10, 10));
        let quorum_range = self.quorum_range();

        // Create initial parameter set
        let tool = match self.args.arg_tool.as_str() {
            "calc" | "simple" => (SimType::DirectCalc, false, false),
            "structure" => (SimType::Structure, false, false),
            "age_simple" => (SimType::FullSim, false, false),
            "age_quorum" => (SimType::FullSim, true, false),
            "targetted_age_simple" => (SimType::FullSim, false, true),
            "targetted_age_quorum" => (SimType::FullSim, true, true),
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
        v.push(SimParams {
            sim_type: tool.0,
            node_ageing: tool.1,
            targetting: tool.2,
            num_nodes: self.args.flag_n.unwrap_or(1000),
            num_malicious: self.num_malicious(),
            min_group_size: group_size_range.0,
            quorum_prop: quorum_range.range.0,
            max_steps: self.args.flag_s.unwrap_or(1000),
            repetitions: self.args.flag_p.unwrap_or(100),
        });

        // Replicate for all group sizes
        let range = 0..v.len();
        for g in (group_size_range.0 + 1)...group_size_range.1 {
            for i in range.clone() {
                let mut s = v[i].clone();
                s.min_group_size = g;
                v.push(s);
            }
        }

        // Replicate for all quorum sizes
        let range = 0..v.len();
        let mut q = quorum_range.range.0 + quorum_range.step;
        while q <= quorum_range.range.1 {
            for i in range.clone() {
                let mut s = v[i].clone();
                s.quorum_prop = q;
                v.push(s);
            }
            q += quorum_range.step;
        }

        v
    }

    fn num_malicious(&self) -> RelOrAbs {
        if let Some(mut s) = self.args.flag_r.clone() {
            if s.ends_with('%') {
                let _ = s.pop();
                let perc = s.parse::<RR>().expect("In '-r x%', x should be a real number");
                RelOrAbs::Rel(perc * 0.01)
            } else {
                RelOrAbs::Abs(s.parse::<NN>()
                    .expect("In '-r N', N should be a whole number or percentage"))
            }
        } else {
            RelOrAbs::Rel(0.1)
        }
    }

    fn quorum_range(&self) -> QuorumRange {
        let s: &str = match self.args.flag_q {
            Some(ref s) => s.as_ref(),
            None => {
                // Default: only 50%
                return QuorumRange {
                    range: (0.5, 0.5),
                    step: 1.0,
                };
            }
        };
        let i = s.find(':').expect("Syntax should be a-b:step");
        let step = s[i + 1..].parse::<RR>().expect("step in a-b:step should be a valid number");
        let (a, b): (RR, RR) = Self::parse_range(&s[..i]);
        // Convert from percentages:
        QuorumRange {
            range: (a * 0.01, b * 0.01),
            step: step * 0.01,
        }
    }

    // Group size and quorum have ranges:
    fn parse_range<T: FromStr>(s: &str) -> (T, T)
        where T::Err: Debug
    {
        const ERR: &'static str = "In a range, syntax should be 'x-y'";
        let i = s.find('-').expect(ERR);
        let lb = s[..i].parse::<T>().expect(ERR);
        let ub = s[i + 1..].parse::<T>().expect(ERR);
        (lb, ub)
    }
}

#[derive(Clone, Copy)]
enum SimType {
    DirectCalc,
    Structure,
    FullSim,
}

impl SimType {
    fn name(self) -> &'static str {
        match self {
            SimType::DirectCalc => "dir_calc",
            SimType::Structure => "structure",
            SimType::FullSim => "full_sim",
        }
    }
}

#[derive(Clone, Copy)]
enum RelOrAbs {
    Rel(RR),
    Abs(NN),
}

impl RelOrAbs {
    fn from_base(self, base: NN) -> NN {
        match self {
            RelOrAbs::Rel(r) => ((base as RR) * r) as NN,
            RelOrAbs::Abs(n) => n,
        }
    }
}

const PARAM_TITLES: [&'static str; 8] = ["Type",
                                         "Ageing",
                                         "Targetting",
                                         "Nodes",
                                         "Malicious",
                                         "MinGroupSize",
                                         "QuorumProp",
                                         "P(disruption)"];
#[derive(Clone)]
struct SimParams {
    sim_type: SimType,
    node_ageing: bool,
    targetting: bool,
    num_nodes: NN,
    num_malicious: RelOrAbs,
    min_group_size: NN,
    quorum_prop: RR,
    max_steps: NN,
    repetitions: NN,
}

impl SimParams {
    fn make_tool(&self) -> Box<Tool> {
        let args = ToolArgs {
            num_nodes: self.num_nodes,
            num_malicious: self.num_malicious.from_base(self.num_nodes),
            min_group_size: self.min_group_size,
            quorum_prop: self.quorum_prop,
            any_group: true, // only support this mode now
            max_steps: self.max_steps,
            repetitions: self.repetitions,
        };
        args.check_invariant();

        match self.sim_type {
            SimType::DirectCalc => Box::new(DirectCalcTool::new(args)),
            SimType::Structure => Box::new(SimStructureTool::new(args)),
            SimType::FullSim => {
                // note: FullSimTool is templated on quorum and attack strategy parameters, so
                // we need to create the whole thing at once (not create parameters first)
                match (self.node_ageing, self.targetting) {
                    (false, false) => {
                        Box::new(FullSimTool::new(args, SimpleQuorum::new(), UntargettedAttack {}))
                    }
                    (true, false) => {
                        Box::new(FullSimTool::new(args, AgeQuorum::new(), UntargettedAttack {}))
                    }
                    (false, true) => {
                        Box::new(FullSimTool::new(args,
                                                  SimpleQuorum::new(),
                                                  SimpleTargettedAttack::new()))
                    }
                    // TODO: isn't this combination going to involve infinite
                    // node rejoining? Strategy may need changing.
                    (true, true) => {
                        Box::new(FullSimTool::new(args,
                                                  AgeQuorum::new(),
                                                  SimpleTargettedAttack::new()))
                    }
                }
            }
        }
    }
}



pub fn main() {
    let args = ArgProc::read_args();
    let params = args.make_sim_params();

    info!("Starting to simulate {} different parameter sets",
          params.len());
    // TODO: par_iter with Rayon:
    let results: Vec<_> = params.iter()
        .map(|p| (p, p.make_tool().calc_p_compromise()))
        .collect();

    //     tool.print_message();
    let col_widths: Vec<usize> = PARAM_TITLES.iter().map(|name| max(name.len(), 10)).collect();
    for col in 0..col_widths.len() {
        print!("{1:0$}", col_widths[col], PARAM_TITLES[col]);
        print!(" ");
    }
    println!();

    for result in results {
        print!("{1:0$}", col_widths[0], result.0.sim_type.name());
        print!(" ");
        print!("{1:0$}", col_widths[1], result.0.node_ageing);
        print!(" ");
        print!("{1:0$}", col_widths[2], result.0.targetting);
        print!(" ");
        print!("{1:0$}", col_widths[3], result.0.num_nodes);
        print!(" ");
        print!("{1:0$}",
               col_widths[4],
               result.0.num_malicious.from_base(result.0.num_nodes));
        print!(" ");
        print!("{1:0$}", col_widths[5], result.0.min_group_size);
        print!(" ");
        print!("{1:0$}", col_widths[6], result.0.quorum_prop);
        print!(" ");
        print!("{1:0$}", col_widths[7], result.1);
        println!();
    }
}
