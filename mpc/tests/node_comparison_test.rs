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

/// Builds nodes with every preprocessing target at 0 — the comparison ops
/// self-size, so a caller that configures nothing must still work.
fn make_nodes() -> (Vec<Node>, Vec<Arc<FakeNetwork>>) {
    let (network, receivers, _, _) = test_setup(N_PARTIES, vec![]);
    let nodes = create_global_nodes::<Fr, Avid<SessionId>, RobustShare<Fr>, FakeNetwork>(
        N_PARTIES,
        T,
        0,
        0,
        333,
        0,
        0,
        0,
        0,
        Duration::from_secs(30),
        vec![],
    );
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
