//! Node-level integer comparison tests (`MPCTypeOps`)
//! On this branch `ltz_int`/`eqz_int` size
//! their own preprocessing from the operand's bit length, so every node here
//! starts with all preprocessing targets at 0 and the full stack runs for real.

use crate::utils::comparison_utils::share_signed_fixed;
use crate::utils::test_utils::{create_global_nodes, receive, setup_tracing, test_setup};
use ark_bls12_381::Fr;
use std::sync::Arc;
use std::time::Duration;
use stoffelcrypto::{
    common::{rbc::rbc::Avid, types::integer::SecretInt, MPCTypeOps, SecretSharingScheme},
    honeybadger::{
        robust_interpolate::robust_interpolate::RobustShare, HoneyBadgerMPCNode, SessionId,
    },
};
use stoffelmpc_network::fake_network::FakeNetwork;

mod utils;

/// Signed range of the tested integer width: k=8 → [-128, 127].
const K: usize = 8;
const N_PARTIES: usize = 4;
const T: usize = 1;

type Node = HoneyBadgerMPCNode<Fr, Avid<SessionId>>;

/// Builds nodes whose only preprocessing configuration is the **declared
/// workload**: one LTZ and one EQZ at width `K`. Every raw pool size is derived
/// from that by `run_preprocessing`, so no test hand-computes triple/random-
/// share counts. Each case below builds fresh nodes and runs a single op, and
/// the derived ops (`lt`/`gt`/`le`/`ge`/`gtz`/`lez`/`gez`, `eq`) each cost
/// exactly one LTZ or one EQZ.
fn make_nodes() -> (Vec<Node>, Vec<Arc<FakeNetwork>>) {
    let (network, receivers, _, _) = test_setup(N_PARTIES, vec![]);
    let mut nodes = create_global_nodes::<Fr, Avid<SessionId>, RobustShare<Fr>, FakeNetwork>(
        N_PARTIES,
        T,
        333,
        0,
        0,
        Duration::from_secs(30),
        vec![],
    );
    for node in nodes.iter_mut() {
        node.params.add_ltz_ops(K, 1);
        node.params.add_eqz_ops(K, 1);
    }
    receive::<Fr, Avid<SessionId>, RobustShare<Fr>, FakeNetwork>(
        receivers,
        nodes.clone(),
        network.clone(),
        None,
    );
    (nodes, network)
}

fn expect_bit(b: bool) -> Fr {
    if b {
        Fr::from(1u64)
    } else {
        Fr::from(0u64)
    }
}

async fn reconstruct(outputs: Vec<SecretInt<Fr, RobustShare<Fr>>>) -> Fr {
    let shares: Vec<_> = outputs.iter().map(|s| s.share().clone()).collect();
    RobustShare::recover_secret(&shares, N_PARTIES, T)
        .expect("interpolate failed")
        .1
}

/// Runs a unary comparison (`x ⋈ 0`) over every listed `(value, expected)` case.
async fn run_unary<Op, Fut>(name: &str, cases: &[(i128, bool)], op: Op)
where
    Op: Fn(Node, SecretInt<Fr, RobustShare<Fr>>, Arc<FakeNetwork>) -> Fut + Copy + Send + 'static,
    Fut: std::future::Future<Output = SecretInt<Fr, RobustShare<Fr>>> + Send + 'static,
{
    setup_tracing();
    for &(x, expected) in cases {
        let (nodes, network) = make_nodes();
        let shares = share_signed_fixed(x, N_PARTIES, T);
        let mut handles = Vec::new();
        for pid in 0..N_PARTIES {
            let node = nodes[pid].clone();
            let net = network[pid].clone();
            let a = SecretInt::new(shares[pid].clone(), K);
            handles.push(tokio::spawn(op(node, a, net)));
        }
        let outputs: Vec<_> = futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.expect("task panicked"))
            .collect();
        assert_eq!(
            reconstruct(outputs).await,
            expect_bit(expected),
            "{name}({x}) should be {expected}"
        );
    }
}

/// Runs a binary comparison (`a ⋈ b`) over every listed `(a, b, expected)` case.
async fn run_binary<Op, Fut>(name: &str, cases: &[(i128, i128, bool)], op: Op)
where
    Op: Fn(
            Node,
            SecretInt<Fr, RobustShare<Fr>>,
            SecretInt<Fr, RobustShare<Fr>>,
            Arc<FakeNetwork>,
        ) -> Fut
        + Copy
        + Send
        + 'static,
    Fut: std::future::Future<Output = SecretInt<Fr, RobustShare<Fr>>> + Send + 'static,
{
    setup_tracing();
    for &(a_val, b_val, expected) in cases {
        let (nodes, network) = make_nodes();
        let a_shares = share_signed_fixed(a_val, N_PARTIES, T);
        let b_shares = share_signed_fixed(b_val, N_PARTIES, T);
        let mut handles = Vec::new();
        for pid in 0..N_PARTIES {
            let node = nodes[pid].clone();
            let net = network[pid].clone();
            let a = SecretInt::new(a_shares[pid].clone(), K);
            let b = SecretInt::new(b_shares[pid].clone(), K);
            handles.push(tokio::spawn(op(node, a, b, net)));
        }
        let outputs: Vec<_> = futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.expect("task panicked"))
            .collect();
        assert_eq!(
            reconstruct(outputs).await,
            expect_bit(expected),
            "{name}({a_val}, {b_val}) should be {expected}"
        );
    }
}

// ── Unary ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn ltz_int_cases() {
    run_unary(
        "ltz_int",
        &[
            (-3, true),
            (-128, true), // most negative in Z<8>
            (-1, true),
            (0, false),
            (1, false),
            (42, false),
            (127, false), // max positive in Z<8>
        ],
        |mut node, x, net| async move { node.ltz_int(x, net).await.expect("ltz_int failed") },
    )
    .await;
}

#[tokio::test]
async fn gtz_int_cases() {
    run_unary(
        "gtz_int",
        &[(7, true), (-5, false), (0, false), (-1, false)],
        |mut node, x, net| async move { node.gtz_int(x, net).await.expect("gtz_int failed") },
    )
    .await;
}

#[tokio::test]
async fn lez_int_cases() {
    run_unary(
        "lez_int",
        &[(-5, true), (0, true), (7, false), (-1, true)],
        |mut node, x, net| async move { node.lez_int(x, net).await.expect("lez_int failed") },
    )
    .await;
}

#[tokio::test]
async fn gez_int_cases() {
    run_unary(
        "gez_int",
        &[(7, true), (-5, false), (0, true), (-1, false)],
        |mut node, x, net| async move { node.gez_int(x, net).await.expect("gez_int failed") },
    )
    .await;
}

#[tokio::test]
async fn eqz_int_cases() {
    run_unary(
        "eqz_int",
        &[
            (0, true),
            (5, false),
            (1, false),
            (-1, false),
            (127, false),
            (-128, false),
        ],
        |mut node, x, net| async move { node.eqz_int(x, net).await.expect("eqz_int failed") },
    )
    .await;
}

// ── Binary: a . b ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn lt_int_cases() {
    run_binary(
        "lt_int",
        &[
            (3, 7, true),
            (10, 4, false),
            (5, 5, false),
            (-7, -3, true),
            (-5, 5, true),
        ],
        |mut node, a, b, net| async move { node.lt_int(a, b, net).await.expect("lt_int failed") },
    )
    .await;
}

#[tokio::test]
async fn gt_int_cases() {
    run_binary(
        "gt_int",
        &[(7, 3, true), (4, 10, false), (5, 5, false), (5, -5, true)],
        |mut node, a, b, net| async move { node.gt_int(a, b, net).await.expect("gt_int failed") },
    )
    .await;
}

#[tokio::test]
async fn le_int_cases() {
    run_binary(
        "le_int",
        &[(3, 7, true), (5, 5, true), (10, 4, false), (-3, -3, true)],
        |mut node, a, b, net| async move { node.le_int(a, b, net).await.expect("le_int failed") },
    )
    .await;
}

#[tokio::test]
async fn ge_int_cases() {
    run_binary(
        "ge_int",
        &[(7, 3, true), (5, 5, true), (4, 10, false), (-7, -7, true)],
        |mut node, a, b, net| async move { node.ge_int(a, b, net).await.expect("ge_int failed") },
    )
    .await;
}

#[tokio::test]
async fn eq_int_cases() {
    run_binary(
        "eq_int",
        &[
            (5, 5, true),
            (0, 0, true),
            (-7, -7, true),
            (3, 7, false),
            (5, -5, false),
            (10, 11, false),
        ],
        |mut node, a, b, net| async move { node.eq_int(a, b, net).await.expect("eq_int failed") },
    )
    .await;
}

// ── Fixed-point comparison ────────────────────────────────────────────────────
//
// A `SecretFixedPoint` at precision (K, F_BITS) stores `round(v * 2^F_BITS)` as
// a K-bit signed integer, so these exercise the same LTZ/EQZ protocols the
// integer ops use. Results come back as fixed-point `0.0` / `1.0`.

use stoffelcrypto::common::types::fixed::{FixedPointPrecision, SecretFixedPoint};

const F_BITS: usize = 4;

type Sfix = SecretFixedPoint<Fr, RobustShare<Fr>>;

fn precision() -> FixedPointPrecision {
    FixedPointPrecision::new(K, F_BITS)
}

/// Shares `v` (a real number) at the test precision.
fn share_fixed(v: f64, n: usize, t: usize) -> Vec<Sfix> {
    let scaled = (v * (1u64 << F_BITS) as f64).round() as i128;
    share_signed_fixed(scaled, n, t)
        .into_iter()
        .map(|s| SecretFixedPoint::new_with_precision(s, precision()))
        .collect()
}

/// Reconstructs a fixed-point comparison result, which must be exactly 0.0 or 1.0.
async fn reconstruct_fixed_bit(outputs: Vec<Sfix>) -> bool {
    let shares: Vec<_> = outputs.iter().map(|s| s.value().clone()).collect();
    let (_, val) = RobustShare::recover_secret(&shares, N_PARTIES, T).expect("interpolate failed");
    let one = Fr::from(1u64 << F_BITS as u64);
    if val == one {
        true
    } else if val == Fr::from(0u64) {
        false
    } else {
        panic!("comparison result was neither 0.0 nor 1.0 (raw {val:?})");
    }
}

/// Nodes provisioned for one unary comparison at width K and one binary at K+1
/// (a binary op compares `a - b`, which needs the extra bit).
fn make_fixed_nodes() -> (Vec<Node>, Vec<Arc<FakeNetwork>>) {
    let (network, receivers, _, _) = test_setup(N_PARTIES, vec![]);
    let mut nodes = create_global_nodes::<Fr, Avid<SessionId>, RobustShare<Fr>, FakeNetwork>(
        N_PARTIES,
        T,
        555,
        0,
        0,
        Duration::from_secs(30),
        vec![],
    );
    for node in nodes.iter_mut() {
        node.params.add_ltz_ops(K, 1);
        node.params.add_ltz_ops(K + 1, 1);
    }
    receive::<Fr, Avid<SessionId>, RobustShare<Fr>, FakeNetwork>(
        receivers,
        nodes.clone(),
        network.clone(),
        None,
    );
    (nodes, network)
}

async fn run_unary_fixed<Op, Fut>(name: &str, cases: &[(f64, bool)], op: Op)
where
    Op: Fn(Node, Sfix, Arc<FakeNetwork>) -> Fut + Copy + Send + 'static,
    Fut: std::future::Future<Output = Sfix> + Send + 'static,
{
    setup_tracing();
    for &(x, expected) in cases {
        let (nodes, network) = make_fixed_nodes();
        let shares = share_fixed(x, N_PARTIES, T);
        let mut handles = Vec::new();
        for pid in 0..N_PARTIES {
            handles.push(tokio::spawn(op(
                nodes[pid].clone(),
                shares[pid].clone(),
                network[pid].clone(),
            )));
        }
        let outputs: Vec<_> = futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.expect("task panicked"))
            .collect();
        assert_eq!(
            reconstruct_fixed_bit(outputs).await,
            expected,
            "{name}({x}) should be {expected}"
        );
    }
}

async fn run_binary_fixed<Op, Fut>(name: &str, cases: &[(f64, f64, bool)], op: Op)
where
    Op: Fn(Node, Sfix, Sfix, Arc<FakeNetwork>) -> Fut + Copy + Send + 'static,
    Fut: std::future::Future<Output = Sfix> + Send + 'static,
{
    setup_tracing();
    for &(a_val, b_val, expected) in cases {
        let (nodes, network) = make_fixed_nodes();
        let a = share_fixed(a_val, N_PARTIES, T);
        let b = share_fixed(b_val, N_PARTIES, T);
        let mut handles = Vec::new();
        for pid in 0..N_PARTIES {
            handles.push(tokio::spawn(op(
                nodes[pid].clone(),
                a[pid].clone(),
                b[pid].clone(),
                network[pid].clone(),
            )));
        }
        let outputs: Vec<_> = futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.expect("task panicked"))
            .collect();
        assert_eq!(
            reconstruct_fixed_bit(outputs).await,
            expected,
            "{name}({a_val}, {b_val}) should be {expected}"
        );
    }
}

#[tokio::test]
async fn ltz_fixed_cases() {
    run_unary_fixed(
        "ltz_fixed",
        &[
            (-1.5, true),
            (-0.25, true),
            (0.0, false),
            (0.25, false),
            (3.0, false),
        ],
        |mut node, x, net| async move { node.ltz_fixed(x, net).await.expect("ltz_fixed failed") },
    )
    .await;
}

#[tokio::test]
async fn gtz_fixed_cases() {
    run_unary_fixed(
        "gtz_fixed",
        &[(1.5, true), (0.25, true), (0.0, false), (-0.25, false)],
        |mut node, x, net| async move { node.gtz_fixed(x, net).await.expect("gtz_fixed failed") },
    )
    .await;
}

#[tokio::test]
async fn lez_gez_fixed_cases() {
    run_unary_fixed(
        "lez_fixed",
        &[(-1.5, true), (0.0, true), (0.25, false)],
        |mut node, x, net| async move { node.lez_fixed(x, net).await.expect("lez_fixed failed") },
    )
    .await;
    run_unary_fixed(
        "gez_fixed",
        &[(1.5, true), (0.0, true), (-0.25, false)],
        |mut node, x, net| async move { node.gez_fixed(x, net).await.expect("gez_fixed failed") },
    )
    .await;
}

#[tokio::test]
async fn lt_gt_fixed_cases() {
    run_binary_fixed(
        "lt_fixed",
        &[(0.5, 1.25, true), (1.25, 0.5, false), (0.5, 0.5, false), (-2.0, -0.5, true)],
        |mut node, a, b, net| async move {
            node.lt_fixed(a, b, net).await.expect("lt_fixed failed")
        },
    )
    .await;
    run_binary_fixed(
        "gt_fixed",
        &[(1.25, 0.5, true), (0.5, 1.25, false), (0.5, 0.5, false), (0.5, -0.5, true)],
        |mut node, a, b, net| async move {
            node.gt_fixed(a, b, net).await.expect("gt_fixed failed")
        },
    )
    .await;
}

#[tokio::test]
async fn le_ge_fixed_cases() {
    run_binary_fixed(
        "le_fixed",
        &[(0.5, 1.25, true), (0.5, 0.5, true), (1.25, 0.5, false)],
        |mut node, a, b, net| async move {
            node.le_fixed(a, b, net).await.expect("le_fixed failed")
        },
    )
    .await;
    run_binary_fixed(
        "ge_fixed",
        &[(1.25, 0.5, true), (0.5, 0.5, true), (0.5, 1.25, false)],
        |mut node, a, b, net| async move {
            node.ge_fixed(a, b, net).await.expect("ge_fixed failed")
        },
    )
    .await;
}

// ── Tolerance-based equality ──────────────────────────────────────────────────
//
// `|x| < 2^tol_bits` in scaled units, as a two-sided comparison: two LTZ calls
// at `width`, combined locally. With f = 4, tol_bits = 2 admits differences
// strictly below 4 scaled units = 0.25.

const TOL_BITS: usize = 2; // 2^2 scaled units = 0.25

/// Nodes for a tolerance test: two LTZ at `width`, nothing else — the two
/// comparison bits are combined without a multiplication.
fn make_tolerance_nodes(width: usize) -> (Vec<Node>, Vec<Arc<FakeNetwork>>) {
    let (network, receivers, _, _) = test_setup(N_PARTIES, vec![]);
    let mut nodes = create_global_nodes::<Fr, Avid<SessionId>, RobustShare<Fr>, FakeNetwork>(
        N_PARTIES,
        T,
        666,
        0,
        0,
        Duration::from_secs(30),
        vec![],
    );
    for node in nodes.iter_mut() {
        node.params.add_ltz_ops(width, 2);
    }
    receive::<Fr, Avid<SessionId>, RobustShare<Fr>, FakeNetwork>(
        receivers,
        nodes.clone(),
        network.clone(),
        None,
    );
    (nodes, network)
}

#[tokio::test]
async fn eqz_fixed_tolerance_cases() {
    setup_tracing();
    // (value, |value| < 0.25)
    for &(x, expected) in &[
        (0.0, true),
        (0.125, true),
        (-0.125, true),
        (0.25, false), // exactly at the tolerance is not "equal"
        (-0.25, false),
        (1.0, false),
        (-1.0, false),
    ] {
        let (nodes, network) = make_tolerance_nodes(K + 1);
        let shares = share_fixed(x, N_PARTIES, T);
        let mut handles = Vec::new();
        for pid in 0..N_PARTIES {
            let mut node = nodes[pid].clone();
            let s = shares[pid].clone();
            let net = network[pid].clone();
            handles.push(tokio::spawn(async move {
                node.eqz_fixed(s, TOL_BITS, net)
                    .await
                    .expect("eqz_fixed failed")
            }));
        }
        let outputs: Vec<_> = futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.expect("task panicked"))
            .collect();
        assert_eq!(
            reconstruct_fixed_bit(outputs).await,
            expected,
            "eqz_fixed({x}) should be {expected}"
        );
    }
}

#[tokio::test]
async fn eq_fixed_tolerance_cases() {
    setup_tracing();
    // (a, b, |a - b| < 0.25). Cases come in swapped pairs: the window is
    // symmetric, so the result cannot depend on operand order.
    for &(a_val, b_val, expected) in &[
        (1.0, 1.0, true),
        (1.0, 1.125, true),
        (1.125, 1.0, true),
        (1.0, 1.25, false), // difference is exactly the tolerance
        (1.25, 1.0, false), // ... and the same with the operands swapped
        (1.0, 1.5, false),
        (-1.0, -1.0, true),
        (-1.0, 1.0, false),
    ] {
        let (nodes, network) = make_tolerance_nodes(K + 2);
        let a = share_fixed(a_val, N_PARTIES, T);
        let b = share_fixed(b_val, N_PARTIES, T);
        let mut handles = Vec::new();
        for pid in 0..N_PARTIES {
            let mut node = nodes[pid].clone();
            let (x, y) = (a[pid].clone(), b[pid].clone());
            let net = network[pid].clone();
            handles.push(tokio::spawn(async move {
                node.eq_fixed(x, y, TOL_BITS, net)
                    .await
                    .expect("eq_fixed failed")
            }));
        }
        let outputs: Vec<_> = futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.expect("task panicked"))
            .collect();
        assert_eq!(
            reconstruct_fixed_bit(outputs).await,
            expected,
            "eq_fixed({a_val}, {b_val}) should be {expected}"
        );
    }
}
