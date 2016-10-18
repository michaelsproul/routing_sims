// Calculations to do with security of routing system

#![feature(inclusive_range_syntax)]
#![allow(non_snake_case)]   // this is maths

extern crate rustc_serialize;
extern crate docopt;

use std::cmp::min;
use docopt::Docopt;

type NN = u64;
type RR = f64;

/// Calculate `n chose k`, i.e. `n! / (k! (n-k)!)`.
pub fn choose(n: NN, mut k: NN) -> RR {
    let mut result: RR = 1 as RR;
    k = min(k, n - k);
    for kp in 1...k {
        // kp goes from 1 to k
        result *= ((n - kp + 1) as RR) / (kp as RR);
    }
    result
}
#[test]
fn test_choose() {
    assert_eq!(choose(15, 0) as NN, 1);
    assert_eq!(choose(1563, 1563) as NN, 1);
    assert_eq!(choose(65, 1) as NN, 65);
    assert_eq!(choose(16, 2) as NN, (8 * 15));
    assert_eq!(choose(35, 3) as NN, (35 * 17 * 11));
    assert_eq!(choose(56, 7) as NN, (8 * 11 * 9 * 53 * 13 * 17 * 25));
}


/// Calculate the probability of choosing at least `q` "red" nodes, where there
/// are `n` total nodes, `r` red, and we choose `k`.
pub fn probQRChosen(n: NN, r: NN, k: NN, q: NN) -> RR {
    // In this we consider each node from n/r distinct, and consider recruiting
    // k nodes into a set (so order doesn't matter).
    
    // First, calculate the number of ways of choosing less than q red nodes
    let mut combs_compr: RR = 0 as RR;
    for x in q...k {
        if x > r {
            continue;   // impossible: 0 combinations to add
        }
        // x is the number of red nodes that get picked; this is the number of
        // possible combinations:
        combs_compr += choose(r, x) * choose(n-r, k-x);
    }
    
    // Now, the total number of combinations in the set is
    let total_combs = choose(n, k);
    combs_compr / total_combs
}


const USAGE: &'static str = "
Proofs / probablity computation tool.

Sim = probability of one specific group being compromised.

Usage:
    proofs [-h | --help]
    proofs [-n NUM] [-r VAL] [-k RANGE] [-q RANGE]

Options:
    -h --help   Show this message
    -n NUM      Number of nodes, total.
    -r VAL      Either number of compromised nodes (e.g. 50) or percentage (default is 10%).
    -k RANGE    Group size, e.g. 10-20.
    -q RANGE    Quorum size, e.g. 5-20.
";

#[derive(RustcDecodable)]
struct Args {
    flag_n: Option<NN>,
    flag_r: Option<String>,
    flag_k: Option<String>,
    flag_q: Option<String>,
}
    
fn main(){
    let args: Args = Docopt::new(USAGE)
            .and_then(|dopt| dopt.decode())
            .unwrap_or_else(|e| e.exit());
    
    let n = args.flag_n.unwrap_or(1000);
    let r = if let Some(mut s) = args.flag_r {
        if s.ends_with('%') {
            let _ = s.pop();
            (n as RR * s.parse::<RR>().expect("In '-r x%', x should be a real number")) as NN
        } else {
            s.parse::<NN>().expect("In '-r N', N should be a whole number or percentage")
        }
    } else {
        (n as RR * 0.1) as NN
    };
    fn parse_range(s: &str) -> (NN, NN) {
        let ERR: &'static str = "In a range, syntax should be 'x-y' where x and y are whole numbers";
        let i = s.find('-').expect(ERR);
        let lb = s[0..i].parse::<NN>().expect(ERR);
        let ub = s[i+1..s.len()].parse::<NN>().expect(ERR);
        (lb, ub)
    }
    let k = args.flag_k.map_or((8, 12), |s| parse_range(&s));
    let q = args.flag_q.map_or((5, 12), |s| parse_range(&s));
    
    println!("Probability of one specific group being compromised, where");
    println!("Total nodes n = {}", n);
    println!("Compromised nodes r = {}", r);
    println!("Group size on horizontal axis (cols)");
    println!("Qurom size on vertical axis (rows)");
    
    let W0: usize = 3;      // width first column
    let W1: usize = 24;     // width other columns
    
    // header:
    print!("{1:0$}", W0, "");
    for ki in k.0 ... k.1 {
        print!("{1:0$}", W1, ki);
    }
    println!("");
    //rest:
    for qi in q.0 ... q.1 {
        print!("{1:0$}", W0, qi);
        for ki in k.0 ... k.1 {
            if qi > ki {
                print!("{1:>0$}", W1, "-");
                continue;
            }
            let p = probQRChosen(n, r, ki, qi);
            print!("{1:0$.e}", W1, p);
        }
        println!("");
    }
}
