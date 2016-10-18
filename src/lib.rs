// Routing sims library.

// Actual simulations are examples.

#![feature(inclusive_range_syntax)]
#![allow(non_snake_case)]   // this is maths

pub type NN = u64;
pub type RR = f64;

use std::cmp::min;

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
