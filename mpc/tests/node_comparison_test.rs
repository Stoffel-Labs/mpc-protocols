pub mod utils;

use crate::utils::test_utils::{create_global_nodes, receive, setup_tracing, test_setup};
use ark_bls12_381::Fr;
use ark_ff::{Field, UniformRand};
use ark_std::{
    rand::{
        rngs::{OsRng, StdRng},
        Rng, SeedableRng,
    },
    test_rng,
};
use futures::future::join_all;
use std::{sync::Arc, time::Duration};
use stoffelmpc_mpc::{
    common::{
        rbc::rbc::Avid, types::integer::SecretInt, MPCTypeOps, PreprocessingMPCProtocol,
        SecretSharingScheme,
    },
    honeybadger::{
        comparison::{PRandMPrep, PreMulCPrep},
        fpmul::f256::Gf2568,
        robust_interpolate::robust_interpolate::RobustShare,
        triple_gen::ShamirBeaverTriple,
        HoneyBadgerMPCNode, SessionId,
    },
};
use stoffelmpc_network::fake_network::FakeNetwork;
use tokio::sync::mpsc;

const N: usize = 4;
const T: usize = 1;
const K: usize = 8; // 8-bit signed integers: [-128, 127]

fn to_field(v: i64) -> Fr {
    if v < 0 {
        -Fr::from((-v) as u64)
    } else {
        Fr::from(v as u64)
    }
}

// ── Synthetic preprocessing generators ────────────────────────────────────────
// Copied from comparison_test.rs — same math, no network round-trips.

fn share_value(v: Fr, n: usize, t: usize) -> Vec<RobustShare<Fr>> {
    let mut rng = test_rng();
    RobustShare::compute_shares(v, n, t, None, &mut rng).unwrap()
}

fn make_triples(n: usize, t: usize, k: usize) -> Vec<Vec<ShamirBeaverTriple<Fr>>> {
    let mut rng = test_rng();
    let mut per_party: Vec<Vec<ShamirBeaverTriple<Fr>>> = vec![vec![]; n];
    for _ in 0..k {
        let a = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);
        let c = a * b;
        let sa = RobustShare::compute_shares(a, n, t, None, &mut rng).unwrap();
        let sb = RobustShare::compute_shares(b, n, t, None, &mut rng).unwrap();
        let sc = RobustShare::compute_shares(c, n, t, None, &mut rng).unwrap();
        for p in 0..n {
            per_party[p].push(ShamirBeaverTriple {
                a: sa[p].clone(),
                b: sb[p].clone(),
                mult: sc[p].clone(),
            });
        }
    }
    per_party
}

fn make_premulc_prep(pk: usize, n: usize, t: usize) -> Vec<PreMulCPrep<Fr>> {
    let mut rng = test_rng();
    let r_vals: Vec<Fr> = (0..pk)
        .map(|_| loop {
            let v = Fr::rand(&mut rng);
            if v != Fr::from(0u64) {
                break v;
            }
        })
        .collect();
    let w_vals: Vec<Fr> = (0..pk)
        .map(|i| {
            if i == 0 {
                r_vals[0]
            } else {
                r_vals[i] * r_vals[i - 1].inverse().unwrap()
            }
        })
        .collect();
    let z_vals: Vec<Fr> = r_vals.iter().map(|r| r.inverse().unwrap()).collect();
    let triples = make_triples(n, t, pk);
    let mut w_pp = vec![vec![]; n];
    let mut z_pp = vec![vec![]; n];
    for i in 0..pk {
        let sw = share_value(w_vals[i], n, t);
        let sz = share_value(z_vals[i], n, t);
        for p in 0..n {
            w_pp[p].push(sw[p].clone());
            z_pp[p].push(sz[p].clone());
        }
    }
    (0..n)
        .map(|i| PreMulCPrep {
            w: w_pp[i].clone(),
            z: z_pp[i].clone(),
            triples: triples[i].clone(),
        })
        .collect()
}

fn make_prandm_prep(dp_bits: usize, m: usize, n: usize, t: usize) -> Vec<PRandMPrep<Fr>> {
    let mut rng = test_rng();
    let r_dp = Fr::from(rng.gen::<u64>() % (1u64 << dp_bits as u64));
    let r_prime_int = rng.gen::<u64>() % (1u64 << m as u64);
    let r_dp_shares = share_value(r_dp, n, t);
    let r_prime_shares = share_value(Fr::from(r_prime_int), n, t);
    let mut r_prime_bits_pp: Vec<Vec<RobustShare<Fr>>> = vec![vec![]; n];
    for i in 0..m {
        let bit = Fr::from((r_prime_int >> i) & 1);
        let shares = share_value(bit, n, t);
        for p in 0..n {
            r_prime_bits_pp[p].push(shares[p].clone());
        }
    }
    (0..n)
        .map(|i| PRandMPrep {
            r_double_prime: r_dp_shares[i].clone(),
            r_prime: r_prime_shares[i].clone(),
            r_prime_bits: r_prime_bits_pp[i].clone(),
        })
        .collect()
}

fn make_mod2_prep(k: usize, n: usize, t: usize) -> Vec<PRandMPrep<Fr>> {
    let mut rng = test_rng();
    let r_dp = Fr::from(rng.gen::<u64>() % (1u64 << (k as u64 - 1)));
    let r_zp = Fr::from(rng.gen::<u64>() & 1);
    let r_dp_shares = share_value(r_dp, n, t);
    let r_zp_shares = share_value(r_zp, n, t);
    (0..n)
        .map(|i| PRandMPrep {
            r_double_prime: r_dp_shares[i].clone(),
            r_prime: r_zp_shares[i].clone(),
            r_prime_bits: vec![],
        })
        .collect()
}

/// m random invertible pairs ([r_j], [r_j^{-1}]).
fn make_rand_inv_pairs(
    n: usize,
    t: usize,
    m: usize,
) -> Vec<Vec<(RobustShare<Fr>, RobustShare<Fr>)>> {
    let mut rng = test_rng();
    let mut per_party: Vec<Vec<(RobustShare<Fr>, RobustShare<Fr>)>> = vec![vec![]; n];
    for _ in 0..m {
        let r = loop {
            let v = Fr::rand(&mut rng);
            if v != Fr::from(0u64) {
                break v;
            }
        };
        let r_inv = r.inverse().unwrap();
        let sr = share_value(r, n, t);
        let sr_inv = share_value(r_inv, n, t);
        for p in 0..n {
            per_party[p].push((sr[p].clone(), sr_inv[p].clone()));
        }
    }
    per_party
}

// ── Node setup ─────────────────────────────────────────────────────────────────

fn make_nodes() -> (
    Vec<HoneyBadgerMPCNode<Fr, Avid<SessionId>>>,
    Vec<Arc<FakeNetwork>>,
) {
    let chunk = T + 1;
    let pk = ((K - 1 + chunk - 1) / chunk) * chunk;
    let (network, receivers, _, _) = test_setup(N, vec![]);
    let nodes = create_global_nodes::<Fr, Avid<SessionId>, RobustShare<Fr>, FakeNetwork>(
        N,
        T,
        pk,
        pk,
        333u32,
        K,
        2,
        8,
        4,
        Duration::from_secs(30),
        1,
        K,
        0,
        0,
        0,
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

fn make_nodes_with_eqz() -> (
    Vec<HoneyBadgerMPCNode<Fr, Avid<SessionId>>>,
    Vec<Arc<FakeNetwork>>,
) {
    let n_eqz = 1;
    let m = (K as u32).ilog2() as usize + 1; // 4 for K=8
    let n_zero_shares = n_eqz * m; // 4 — consumed by ensure_rand_inv_pairs_for_eqz
                                   // n_triples: prandbit generation consumes ~12, runtime ~7 → need ≥19
                                   // (RandInvPair no longer uses triples — uses MulPub + zero shares instead)
    let n_triples = 19; // PRandBit: 12, eqz_int runtime: 7
    let n_random_shares = 60;
    let n_prandbit = K + m; // 12 — exactly what one eqz_int call needs
    let n_prandint = 4;
    let (network, receivers, _, _) = test_setup(N, vec![]);
    let nodes = create_global_nodes::<Fr, Avid<SessionId>, RobustShare<Fr>, FakeNetwork>(
        N,
        T,
        n_triples,
        n_random_shares,
        334u32,
        n_prandbit,
        n_prandint,
        8,
        4,
        Duration::from_secs(60),
        0,
        0,
        n_eqz,
        K,
        n_zero_shares,
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

async fn do_run_preprocessing(
    nodes: &[HoneyBadgerMPCNode<Fr, Avid<SessionId>>],
    network: &[Arc<FakeNetwork>],
) {
    let mut handles = Vec::new();
    for pid in 0..N {
        let mut node = nodes[pid].clone();
        let net = network[pid].clone();
        let mut rng = StdRng::from_rng(OsRng).unwrap();
        handles.push(tokio::spawn(async move {
            node.run_preprocessing(net, &mut rng)
                .await
                .expect("preprocessing failed");
        }));
    }
    join_all(handles).await;
}

/// Injects synthetic LTZ preprocessing — skips network round-trips.
async fn inject_synthetic_ltz_prep(nodes: &[HoneyBadgerMPCNode<Fr, Avid<SessionId>>]) {
    let chunk = T + 1;
    let pk = ((K - 1 + chunk - 1) / chunk) * chunk;
    let m = K - 1; // Mod2m dimension

    let premulc = make_premulc_prep(pk, N, T);
    let prandm = make_prandm_prep(1, m, N, T); // r'' for Mod2m prandint, r'_bits are k-1 prandbits
    let mod2 = make_mod2_prep(K, N, T); // r'' for Mod2 prandint, r' is 1 prandbit

    for pid in 0..N {
        let mut store = nodes[pid].preprocessing_material.lock().await;

        store.add_premulc_ltz(premulc[pid].clone());

        // 2 prandint shares: one for Mod2m, one for Mod2
        store.add(
            None,
            None,
            None,
            Some(vec![
                prandm[pid].r_double_prime.clone(),
                mod2[pid].r_double_prime.clone(),
            ]),
        );

        // k prandbit shares: (k-1) from Mod2m's r'_bits + 1 from Mod2's r'
        // Gf2568 is ignored by ltz_int — zero is a valid placeholder
        let mut prandbit: Vec<(RobustShare<Fr>, Gf2568)> = prandm[pid]
            .r_prime_bits
            .iter()
            .map(|s| (s.clone(), Gf2568::zero()))
            .collect();
        prandbit.push((mod2[pid].r_prime.clone(), Gf2568::zero()));
        store.add(None, None, Some(prandbit), None);
    }
}

/// Injects synthetic EQZ preprocessing — skips network round-trips.
///
/// Injects into each node's store:
///   - m rand_inv_pairs (for KOrCSPrep)
///   - 2m-1 beaver triples (m-1 for KOrCS round 1, m for round 2)
///   - 2 prandint shares (r'' for EQZ masking and KOrCL masking)
///   - k+m prandbit shares (k bits for EQZ r'_bits, m bits for KOrCL r'_bits)
async fn inject_synthetic_eqz_prep(nodes: &[HoneyBadgerMPCNode<Fr, Avid<SessionId>>]) {
    let k = K;
    let m = (k as u32).ilog2() as usize + 1; // 4 for K=8

    // Properly structured prandm preps so r_prime_bits are real bit shares.
    // prandm_eqz: k-bit r' → k prandbit entries
    // prandm_korcl: m-bit r' → m prandbit entries
    let prandm_eqz = make_prandm_prep(k, k, N, T);
    let prandm_korcl = make_prandm_prep(k, m, N, T);

    // m random invertible pairs for KOrCSPrep
    let pairs = make_rand_inv_pairs(N, T, m);

    // (m-1) + m = 2m-1 triples for KOrCS
    let kor_triples = make_triples(N, T, 2 * m - 1);

    for pid in 0..N {
        let mut store = nodes[pid].preprocessing_material.lock().await;

        // rand_inv_pairs_eqz pool
        store.add_rand_inv_pairs_eqz(pairs[pid].clone());

        // beaver_triples pool: 2m-1 triples
        store.add(Some(kor_triples[pid].clone()), None, None, None);

        // prandint_shares pool: [r''_eqz, r''_korcl]
        store.add(
            None,
            None,
            None,
            Some(vec![
                prandm_eqz[pid].r_double_prime.clone(),
                prandm_korcl[pid].r_double_prime.clone(),
            ]),
        );

        // prandbit_shares pool: k bits then m bits (order matters — eqz_int takes k first)
        let mut prandbits: Vec<(RobustShare<Fr>, Gf2568)> = prandm_eqz[pid]
            .r_prime_bits
            .iter()
            .map(|s| (s.clone(), Gf2568::zero()))
            .collect();
        for s in &prandm_korcl[pid].r_prime_bits {
            prandbits.push((s.clone(), Gf2568::zero()));
        }
        store.add(None, None, Some(prandbits), None);
    }
}

async fn gather(mut fin_recv: mpsc::Receiver<(usize, RobustShare<Fr>)>) -> Fr {
    let mut shares = Vec::new();
    while let Ok((_, share)) = fin_recv.try_recv() {
        shares.push(share);
    }
    let (_, v) = RobustShare::recover_secret(&shares, N, T).expect("recover_secret failed");
    v
}

// ── Run helpers ────────────────────────────────────────────────────────────────

async fn run_unary_ltz<F, Fut>(
    nodes: &[HoneyBadgerMPCNode<Fr, Avid<SessionId>>],
    network: &[Arc<FakeNetwork>],
    a_signed: i64,
    expected: bool,
    label: &str,
    op: F,
) where
    F: Fn(
            HoneyBadgerMPCNode<Fr, Avid<SessionId>>,
            SecretInt<Fr, RobustShare<Fr>>,
            Arc<FakeNetwork>,
        ) -> Fut
        + Clone
        + Send
        + 'static,
    Fut: std::future::Future<Output = SecretInt<Fr, RobustShare<Fr>>> + Send + 'static,
{
    let mut rng = test_rng();
    let shares = RobustShare::compute_shares(to_field(a_signed), N, T, None, &mut rng).unwrap();
    let inputs: Vec<SecretInt<Fr, RobustShare<Fr>>> =
        shares.into_iter().map(|s| SecretInt::new(s, K)).collect();

    let (fin_send, fin_recv) = mpsc::channel::<(usize, RobustShare<Fr>)>(N * 2);
    let mut handles = Vec::new();
    for pid in 0..N {
        let node = nodes[pid].clone();
        let net = network[pid].clone();
        let x = inputs[pid].clone();
        let tx = fin_send.clone();
        let op = op.clone();
        handles.push(tokio::spawn(async move {
            let r = op(node, x, net).await;
            tx.send((pid, r.share().clone())).await.unwrap();
        }));
    }
    join_all(handles).await;

    let result = gather(fin_recv).await;
    let expected_field = Fr::from(expected as u64);
    assert_eq!(
        result, expected_field,
        "{label}({a_signed}): got {result:?}"
    );
}

async fn run_binary_ltz<F, Fut>(
    nodes: &[HoneyBadgerMPCNode<Fr, Avid<SessionId>>],
    network: &[Arc<FakeNetwork>],
    a_signed: i64,
    b_signed: i64,
    expected: bool,
    label: &str,
    op: F,
) where
    F: Fn(
            HoneyBadgerMPCNode<Fr, Avid<SessionId>>,
            SecretInt<Fr, RobustShare<Fr>>,
            SecretInt<Fr, RobustShare<Fr>>,
            Arc<FakeNetwork>,
        ) -> Fut
        + Clone
        + Send
        + 'static,
    Fut: std::future::Future<Output = SecretInt<Fr, RobustShare<Fr>>> + Send + 'static,
{
    let mut rng = test_rng();
    let a_shares = RobustShare::compute_shares(to_field(a_signed), N, T, None, &mut rng).unwrap();
    let b_shares = RobustShare::compute_shares(to_field(b_signed), N, T, None, &mut rng).unwrap();
    let a_inputs: Vec<SecretInt<Fr, RobustShare<Fr>>> =
        a_shares.into_iter().map(|s| SecretInt::new(s, K)).collect();
    let b_inputs: Vec<SecretInt<Fr, RobustShare<Fr>>> =
        b_shares.into_iter().map(|s| SecretInt::new(s, K)).collect();

    let (fin_send, fin_recv) = mpsc::channel::<(usize, RobustShare<Fr>)>(N * 2);
    let mut handles = Vec::new();
    for pid in 0..N {
        let node = nodes[pid].clone();
        let net = network[pid].clone();
        let a = a_inputs[pid].clone();
        let b = b_inputs[pid].clone();
        let tx = fin_send.clone();
        let op = op.clone();
        handles.push(tokio::spawn(async move {
            let r = op(node, a, b, net).await;
            tx.send((pid, r.share().clone())).await.unwrap();
        }));
    }
    join_all(handles).await;

    let result = gather(fin_recv).await;
    let expected_field = Fr::from(expected as u64);
    assert_eq!(
        result, expected_field,
        "{label}({a_signed}, {b_signed}): got {result:?}"
    );
}

// ── ltz_int ────────────────────────────────────────────────────────────────────
// ltz_int(x) = 1 if x < 0, else 0

#[tokio::test]
async fn ltz_int_negative_e2e() {
    // Full preprocessing — validates the whole stack end-to-end.
    setup_tracing();
    let (nodes, network) = make_nodes();
    do_run_preprocessing(&nodes, &network).await;
    run_unary_ltz(
        &nodes,
        &network,
        -3,
        true,
        "ltz_int",
        |mut node, x, net| async move { node.ltz_int(x, net).await.expect("ltz_int failed") },
    )
    .await;
}

#[tokio::test]
async fn ltz_int_most_negative() {
    setup_tracing();
    let (nodes, network) = make_nodes(); // single call — nodes and network are paired
    inject_synthetic_ltz_prep(&nodes).await;
    run_unary_ltz(
        &nodes,
        &network, // same network the receive tasks are listening on
        -128,
        true,
        "ltz_int",
        |mut node, x, net| async move { node.ltz_int(x, net).await.expect("ltz_int failed") },
    )
    .await;
}

#[tokio::test]
async fn ltz_int_negative_one() {
    setup_tracing();
    let (nodes, network) = make_nodes();
    inject_synthetic_ltz_prep(&nodes).await;
    run_unary_ltz(
        &nodes,
        &network,
        -1,
        true,
        "ltz_int",
        |mut node, x, net| async move { node.ltz_int(x, net).await.expect("ltz_int failed") },
    )
    .await;
}

#[tokio::test]
async fn ltz_int_zero() {
    setup_tracing();
    let (nodes, network) = make_nodes();
    inject_synthetic_ltz_prep(&nodes).await;
    run_unary_ltz(
        &nodes,
        &network,
        0,
        false,
        "ltz_int",
        |mut node, x, net| async move { node.ltz_int(x, net).await.expect("ltz_int failed") },
    )
    .await;
}

#[tokio::test]
async fn ltz_int_one() {
    setup_tracing();
    let (nodes, network) = make_nodes();
    inject_synthetic_ltz_prep(&nodes).await;
    run_unary_ltz(
        &nodes,
        &network,
        1,
        false,
        "ltz_int",
        |mut node, x, net| async move { node.ltz_int(x, net).await.expect("ltz_int failed") },
    )
    .await;
}

#[tokio::test]
async fn ltz_int_positive() {
    setup_tracing();
    let (nodes, network) = make_nodes();
    inject_synthetic_ltz_prep(&nodes).await;
    run_unary_ltz(
        &nodes,
        &network,
        42,
        false,
        "ltz_int",
        |mut node, x, net| async move { node.ltz_int(x, net).await.expect("ltz_int failed") },
    )
    .await;
}

#[tokio::test]
async fn ltz_int_max_positive() {
    setup_tracing();
    let (nodes, network) = make_nodes();
    inject_synthetic_ltz_prep(&nodes).await;
    run_unary_ltz(
        &nodes,
        &network,
        127,
        false,
        "ltz_int",
        |mut node, x, net| async move { node.ltz_int(x, net).await.expect("ltz_int failed") },
    )
    .await;
}

// ── gtz_int ────────────────────────────────────────────────────────────────────
// gtz_int(x) = ltz_int(-x) = 1 if x > 0, else 0

#[tokio::test]
async fn gtz_int_e2e() {
    setup_tracing();
    let (nodes, network) = make_nodes();
    do_run_preprocessing(&nodes, &network).await;
    run_unary_ltz(
        &nodes,
        &network,
        7,
        true,
        "gtz_int",
        |mut node, x, net| async move { node.gtz_int(x, net).await.expect("gtz_int failed") },
    )
    .await;
}

#[tokio::test]
async fn gtz_int_negative() {
    setup_tracing();
    let (nodes, network) = make_nodes();
    inject_synthetic_ltz_prep(&nodes).await;
    run_unary_ltz(
        &nodes,
        &network,
        -5,
        false,
        "gtz_int",
        |mut node, x, net| async move { node.gtz_int(x, net).await.expect("gtz_int failed") },
    )
    .await;
}

#[tokio::test]
async fn gtz_int_zero() {
    setup_tracing();
    let (nodes, network) = make_nodes();
    inject_synthetic_ltz_prep(&nodes).await;
    run_unary_ltz(
        &nodes,
        &network,
        0,
        false,
        "gtz_int",
        |mut node, x, net| async move { node.gtz_int(x, net).await.expect("gtz_int failed") },
    )
    .await;
}

#[tokio::test]
async fn gtz_int_negative_one() {
    setup_tracing();
    let (nodes, network) = make_nodes();
    inject_synthetic_ltz_prep(&nodes).await;
    run_unary_ltz(
        &nodes,
        &network,
        -1,
        false,
        "gtz_int",
        |mut node, x, net| async move { node.gtz_int(x, net).await.expect("gtz_int failed") },
    )
    .await;
}

// ── lez_int ────────────────────────────────────────────────────────────────────
// lez_int(x) = 1 - ltz_int(-x) = 1 if x <= 0, else 0

#[tokio::test]
async fn lez_int_e2e() {
    setup_tracing();
    let (nodes, network) = make_nodes();
    do_run_preprocessing(&nodes, &network).await;
    run_unary_ltz(
        &nodes,
        &network,
        -5,
        true,
        "lez_int",
        |mut node, x, net| async move { node.lez_int(x, net).await.expect("lez_int failed") },
    )
    .await;
}

#[tokio::test]
async fn lez_int_zero() {
    setup_tracing();
    let (nodes, network) = make_nodes();
    inject_synthetic_ltz_prep(&nodes).await;
    run_unary_ltz(
        &nodes,
        &network,
        0,
        true,
        "lez_int",
        |mut node, x, net| async move { node.lez_int(x, net).await.expect("lez_int failed") },
    )
    .await;
}

#[tokio::test]
async fn lez_int_positive() {
    setup_tracing();
    let (nodes, network) = make_nodes();
    inject_synthetic_ltz_prep(&nodes).await;
    run_unary_ltz(
        &nodes,
        &network,
        7,
        false,
        "lez_int",
        |mut node, x, net| async move { node.lez_int(x, net).await.expect("lez_int failed") },
    )
    .await;
}

#[tokio::test]
async fn lez_int_negative_one() {
    setup_tracing();
    let (nodes, network) = make_nodes();
    inject_synthetic_ltz_prep(&nodes).await;
    run_unary_ltz(
        &nodes,
        &network,
        -1,
        true,
        "lez_int",
        |mut node, x, net| async move { node.lez_int(x, net).await.expect("lez_int failed") },
    )
    .await;
}

// ── gez_int ────────────────────────────────────────────────────────────────────
// gez_int(x) = 1 - ltz_int(x) = 1 if x >= 0, else 0

#[tokio::test]
async fn gez_int_e2e() {
    setup_tracing();
    let (nodes, network) = make_nodes();
    do_run_preprocessing(&nodes, &network).await;
    run_unary_ltz(
        &nodes,
        &network,
        7,
        true,
        "gez_int",
        |mut node, x, net| async move { node.gez_int(x, net).await.expect("gez_int failed") },
    )
    .await;
}

#[tokio::test]
async fn gez_int_negative() {
    setup_tracing();
    let (nodes, network) = make_nodes();
    inject_synthetic_ltz_prep(&nodes).await;
    run_unary_ltz(
        &nodes,
        &network,
        -5,
        false,
        "gez_int",
        |mut node, x, net| async move { node.gez_int(x, net).await.expect("gez_int failed") },
    )
    .await;
}

#[tokio::test]
async fn gez_int_zero() {
    setup_tracing();
    let (nodes, network) = make_nodes();
    inject_synthetic_ltz_prep(&nodes).await;
    run_unary_ltz(
        &nodes,
        &network,
        0,
        true,
        "gez_int",
        |mut node, x, net| async move { node.gez_int(x, net).await.expect("gez_int failed") },
    )
    .await;
}

#[tokio::test]
async fn gez_int_negative_one() {
    setup_tracing();
    let (nodes, network) = make_nodes();
    inject_synthetic_ltz_prep(&nodes).await;
    run_unary_ltz(
        &nodes,
        &network,
        -1,
        false,
        "gez_int",
        |mut node, x, net| async move { node.gez_int(x, net).await.expect("gez_int failed") },
    )
    .await;
}

// ── lt_int ─────────────────────────────────────────────────────────────────────
// lt_int(a, b) = ltz_int(a - b) = 1 if a < b, else 0

#[tokio::test]
async fn lt_int_e2e() {
    setup_tracing();
    let (nodes, network) = make_nodes();
    do_run_preprocessing(&nodes, &network).await;
    run_binary_ltz(
        &nodes,
        &network,
        3,
        7,
        true,
        "lt_int",
        |mut node, a, b, net| async move { node.lt_int(a, b, net).await.expect("lt_int failed") },
    )
    .await;
}

#[tokio::test]
async fn lt_int_greater_than() {
    setup_tracing();
    let (nodes, network) = make_nodes();
    inject_synthetic_ltz_prep(&nodes).await;
    run_binary_ltz(
        &nodes,
        &network,
        10,
        4,
        false,
        "lt_int",
        |mut node, a, b, net| async move { node.lt_int(a, b, net).await.expect("lt_int failed") },
    )
    .await;
}

#[tokio::test]
async fn lt_int_equal() {
    setup_tracing();
    let (nodes, network) = make_nodes();
    inject_synthetic_ltz_prep(&nodes).await;
    run_binary_ltz(
        &nodes,
        &network,
        5,
        5,
        false,
        "lt_int",
        |mut node, a, b, net| async move { node.lt_int(a, b, net).await.expect("lt_int failed") },
    )
    .await;
}

#[tokio::test]
async fn lt_int_both_negative() {
    setup_tracing();
    let (nodes, network) = make_nodes();
    inject_synthetic_ltz_prep(&nodes).await;
    run_binary_ltz(
        &nodes,
        &network,
        -7,
        -3,
        true,
        "lt_int",
        |mut node, a, b, net| async move { node.lt_int(a, b, net).await.expect("lt_int failed") },
    )
    .await;
}

#[tokio::test]
async fn lt_int_negative_vs_positive() {
    setup_tracing();
    let (nodes, network) = make_nodes();
    inject_synthetic_ltz_prep(&nodes).await;
    run_binary_ltz(
        &nodes,
        &network,
        -5,
        5,
        true,
        "lt_int",
        |mut node, a, b, net| async move { node.lt_int(a, b, net).await.expect("lt_int failed") },
    )
    .await;
}

// ── gt_int ─────────────────────────────────────────────────────────────────────
// gt_int(a, b) = ltz_int(b - a) = 1 if a > b, else 0

#[tokio::test]
async fn gt_int_e2e() {
    setup_tracing();
    let (nodes, network) = make_nodes();
    do_run_preprocessing(&nodes, &network).await;
    run_binary_ltz(
        &nodes,
        &network,
        7,
        3,
        true,
        "gt_int",
        |mut node, a, b, net| async move { node.gt_int(a, b, net).await.expect("gt_int failed") },
    )
    .await;
}

#[tokio::test]
async fn gt_int_less_than() {
    setup_tracing();
    let (nodes, network) = make_nodes();
    inject_synthetic_ltz_prep(&nodes).await;
    run_binary_ltz(
        &nodes,
        &network,
        4,
        10,
        false,
        "gt_int",
        |mut node, a, b, net| async move { node.gt_int(a, b, net).await.expect("gt_int failed") },
    )
    .await;
}

#[tokio::test]
async fn gt_int_equal() {
    setup_tracing();
    let (nodes, network) = make_nodes();
    inject_synthetic_ltz_prep(&nodes).await;
    run_binary_ltz(
        &nodes,
        &network,
        5,
        5,
        false,
        "gt_int",
        |mut node, a, b, net| async move { node.gt_int(a, b, net).await.expect("gt_int failed") },
    )
    .await;
}

#[tokio::test]
async fn gt_int_positive_vs_negative() {
    setup_tracing();
    let (nodes, network) = make_nodes();
    inject_synthetic_ltz_prep(&nodes).await;
    run_binary_ltz(
        &nodes,
        &network,
        5,
        -5,
        true,
        "gt_int",
        |mut node, a, b, net| async move { node.gt_int(a, b, net).await.expect("gt_int failed") },
    )
    .await;
}

// ── le_int ─────────────────────────────────────────────────────────────────────
// le_int(a, b) = 1 - ltz_int(b - a) = 1 if a <= b, else 0

#[tokio::test]
async fn le_int_e2e() {
    setup_tracing();
    let (nodes, network) = make_nodes();
    do_run_preprocessing(&nodes, &network).await;
    run_binary_ltz(
        &nodes,
        &network,
        3,
        7,
        true,
        "le_int",
        |mut node, a, b, net| async move { node.le_int(a, b, net).await.expect("le_int failed") },
    )
    .await;
}

#[tokio::test]
async fn le_int_equal() {
    setup_tracing();
    let (nodes, network) = make_nodes();
    inject_synthetic_ltz_prep(&nodes).await;
    run_binary_ltz(
        &nodes,
        &network,
        5,
        5,
        true,
        "le_int",
        |mut node, a, b, net| async move { node.le_int(a, b, net).await.expect("le_int failed") },
    )
    .await;
}

#[tokio::test]
async fn le_int_greater_than() {
    setup_tracing();
    let (nodes, network) = make_nodes();
    inject_synthetic_ltz_prep(&nodes).await;
    run_binary_ltz(
        &nodes,
        &network,
        10,
        4,
        false,
        "le_int",
        |mut node, a, b, net| async move { node.le_int(a, b, net).await.expect("le_int failed") },
    )
    .await;
}

#[tokio::test]
async fn le_int_both_negative_equal() {
    setup_tracing();
    let (nodes, network) = make_nodes();
    inject_synthetic_ltz_prep(&nodes).await;
    run_binary_ltz(
        &nodes,
        &network,
        -3,
        -3,
        true,
        "le_int",
        |mut node, a, b, net| async move { node.le_int(a, b, net).await.expect("le_int failed") },
    )
    .await;
}

// ── ge_int ─────────────────────────────────────────────────────────────────────
// ge_int(a, b) = 1 - ltz_int(a - b) = 1 if a >= b, else 0

#[tokio::test]
async fn ge_int_e2e() {
    setup_tracing();
    let (nodes, network) = make_nodes();
    do_run_preprocessing(&nodes, &network).await;
    run_binary_ltz(
        &nodes,
        &network,
        7,
        3,
        true,
        "ge_int",
        |mut node, a, b, net| async move { node.ge_int(a, b, net).await.expect("ge_int failed") },
    )
    .await;
}

#[tokio::test]
async fn ge_int_equal() {
    setup_tracing();
    let (nodes, network) = make_nodes();
    inject_synthetic_ltz_prep(&nodes).await;
    run_binary_ltz(
        &nodes,
        &network,
        5,
        5,
        true,
        "ge_int",
        |mut node, a, b, net| async move { node.ge_int(a, b, net).await.expect("ge_int failed") },
    )
    .await;
}

#[tokio::test]
async fn ge_int_less_than() {
    setup_tracing();
    let (nodes, network) = make_nodes();
    inject_synthetic_ltz_prep(&nodes).await;
    run_binary_ltz(
        &nodes,
        &network,
        4,
        10,
        false,
        "ge_int",
        |mut node, a, b, net| async move { node.ge_int(a, b, net).await.expect("ge_int failed") },
    )
    .await;
}

#[tokio::test]
async fn ge_int_both_negative_equal() {
    setup_tracing();
    let (nodes, network) = make_nodes();
    inject_synthetic_ltz_prep(&nodes).await;
    run_binary_ltz(
        &nodes,
        &network,
        -7,
        -7,
        true,
        "ge_int",
        |mut node, a, b, net| async move { node.ge_int(a, b, net).await.expect("ge_int failed") },
    )
    .await;
}

// ── eqz_int ────────────────────────────────────────────────────────────────────
// eqz_int(a) = 1 if a = 0, else 0

#[tokio::test]
async fn eqz_int_zero_e2e() {
    // Full preprocessing — validates the whole stack including rand_inv_pair generation.
    setup_tracing();
    let (nodes, network) = make_nodes_with_eqz();
    do_run_preprocessing(&nodes, &network).await;
    run_unary_ltz(
        &nodes,
        &network,
        0,
        true,
        "eqz_int",
        |mut node, x, net| async move { node.eqz_int(x, net).await.expect("eqz_int failed") },
    )
    .await;
}

#[tokio::test]
async fn eqz_int_nonzero_e2e() {
    setup_tracing();
    let (nodes, network) = make_nodes_with_eqz();
    do_run_preprocessing(&nodes, &network).await;
    run_unary_ltz(
        &nodes,
        &network,
        5,
        false,
        "eqz_int",
        |mut node, x, net| async move { node.eqz_int(x, net).await.expect("eqz_int failed") },
    )
    .await;
}

#[tokio::test]
async fn eqz_int_one() {
    setup_tracing();
    let (nodes, network) = make_nodes_with_eqz();
    inject_synthetic_eqz_prep(&nodes).await;
    run_unary_ltz(
        &nodes,
        &network,
        1,
        false,
        "eqz_int",
        |mut node, x, net| async move { node.eqz_int(x, net).await.expect("eqz_int failed") },
    )
    .await;
}

#[tokio::test]
async fn eqz_int_negative_one() {
    setup_tracing();
    let (nodes, network) = make_nodes_with_eqz();
    inject_synthetic_eqz_prep(&nodes).await;
    run_unary_ltz(
        &nodes,
        &network,
        -1,
        false,
        "eqz_int",
        |mut node, x, net| async move { node.eqz_int(x, net).await.expect("eqz_int failed") },
    )
    .await;
}

#[tokio::test]
async fn eqz_int_max_positive() {
    setup_tracing();
    let (nodes, network) = make_nodes_with_eqz();
    inject_synthetic_eqz_prep(&nodes).await;
    run_unary_ltz(
        &nodes,
        &network,
        127,
        false,
        "eqz_int",
        |mut node, x, net| async move { node.eqz_int(x, net).await.expect("eqz_int failed") },
    )
    .await;
}

#[tokio::test]
async fn eqz_int_most_negative() {
    setup_tracing();
    let (nodes, network) = make_nodes_with_eqz();
    inject_synthetic_eqz_prep(&nodes).await;
    run_unary_ltz(
        &nodes,
        &network,
        -128,
        false,
        "eqz_int",
        |mut node, x, net| async move { node.eqz_int(x, net).await.expect("eqz_int failed") },
    )
    .await;
}

// ── eq_int ─────────────────────────────────────────────────────────────────────
// eq_int(a, b) = eqz_int(a - b) = 1 if a = b, else 0

#[tokio::test]
async fn eq_int_equal_e2e() {
    setup_tracing();
    let (nodes, network) = make_nodes_with_eqz();
    do_run_preprocessing(&nodes, &network).await;
    run_binary_ltz(
        &nodes,
        &network,
        5,
        5,
        true,
        "eq_int",
        |mut node, a, b, net| async move { node.eq_int(a, b, net).await.expect("eq_int failed") },
    )
    .await;
}

#[tokio::test]
async fn eq_int_equal_zero() {
    setup_tracing();
    let (nodes, network) = make_nodes_with_eqz();
    inject_synthetic_eqz_prep(&nodes).await;
    run_binary_ltz(
        &nodes,
        &network,
        0,
        0,
        true,
        "eq_int",
        |mut node, a, b, net| async move { node.eq_int(a, b, net).await.expect("eq_int failed") },
    )
    .await;
}

#[tokio::test]
async fn eq_int_equal_negative() {
    setup_tracing();
    let (nodes, network) = make_nodes_with_eqz();
    inject_synthetic_eqz_prep(&nodes).await;
    run_binary_ltz(
        &nodes,
        &network,
        -7,
        -7,
        true,
        "eq_int",
        |mut node, a, b, net| async move { node.eq_int(a, b, net).await.expect("eq_int failed") },
    )
    .await;
}

#[tokio::test]
async fn eq_int_unequal() {
    setup_tracing();
    let (nodes, network) = make_nodes_with_eqz();
    inject_synthetic_eqz_prep(&nodes).await;
    run_binary_ltz(
        &nodes,
        &network,
        3,
        7,
        false,
        "eq_int",
        |mut node, a, b, net| async move { node.eq_int(a, b, net).await.expect("eq_int failed") },
    )
    .await;
}

#[tokio::test]
async fn eq_int_unequal_signs() {
    setup_tracing();
    let (nodes, network) = make_nodes_with_eqz();
    inject_synthetic_eqz_prep(&nodes).await;
    run_binary_ltz(
        &nodes,
        &network,
        5,
        -5,
        false,
        "eq_int",
        |mut node, a, b, net| async move { node.eq_int(a, b, net).await.expect("eq_int failed") },
    )
    .await;
}

#[tokio::test]
async fn eq_int_close_values() {
    setup_tracing();
    let (nodes, network) = make_nodes_with_eqz();
    inject_synthetic_eqz_prep(&nodes).await;
    run_binary_ltz(
        &nodes,
        &network,
        10,
        11,
        false,
        "eq_int",
        |mut node, a, b, net| async move { node.eq_int(a, b, net).await.expect("eq_int failed") },
    )
    .await;
}
