//! End-to-end tests of share conversion wired directly onto `HoneyBadgerMPCNode`, driven purely
//! through `node.process`'s dispatch — the `B2A`, `A2B` and `A2BGfMul` arms added for this work,
//! and the drains behind them.
//!
//! The conversion *preprocessing* is supplied by a trusted dealer here rather than by
//! `PrssDaBitNode`, for the same reason `gf_node_mul_test.rs` sizes its triple pool by hand:
//! isolation. What these tests pin is the *wiring* — session-id allocation, the dispatch arms,
//! the drains, material accounting, and store cleanup — and a failure in any of that should not
//! be reachable from a fault in preprocessing.
//!
//! This used to carry a second justification, that a real daBit batch could not be smaller than
//! the dealt protocol's bucketing soundness floor of 1024 outputs. That is obsolete: PRSS daBits
//! have soundness error 0 and no floor. Only the isolation argument still holds.

pub mod utils;

use crate::utils::test_utils::{
    create_global_nodes, receive, setup_tracing, test_setup, unused_precision,
};
use ark_ff::{Field, One, UniformRand};
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use std::time::Duration;
use stoffelcrypto::{
    common::{
        convert::{bit_to_gf, canonical_bits, field_bit_width},
        gf2k::field::{BinaryField, Gf256},
        gf2k::share::GfShare,
        rbc::rbc::Avid,
        ConversionPreprocessingProtocol, SecretSharingScheme, ShareConversionProtocol,
    },
    honeybadger::{
        a2b::a2b::A2BNode,
        dabit::{DaBit, EdaBit},
        gf_triple_gen::GfBeaverTriple,
        robust_interpolate::robust_interpolate::RobustShare,
        SessionId, MIN_STATISTICAL_SECURITY,
    },
};
use stoffelmpc_network::fake_network::FakeNetwork;

type F = ark_bls12_381::Fr;
type K = Gf256;

/// Trusted-dealer daBits: one Shamir sharing of the same bit in each domain, at degree `t`.
fn deal_dabits(
    n_parties: usize,
    t: usize,
    count: usize,
    rng: &mut StdRng,
) -> Vec<Vec<DaBit<F, K>>> {
    let mut per_party: Vec<Vec<DaBit<F, K>>> = vec![Vec::new(); n_parties];
    for index in 0..count {
        let bit = index % 2 == 0;
        let arith =
            RobustShare::compute_shares(F::from(bit as u64), n_parties, t, None, rng).unwrap();
        let bin = GfShare::compute_shares(bit_to_gf::<K>(bit), n_parties, t, rng).unwrap();
        for party in 0..n_parties {
            per_party[party].push(DaBit::new(arith[party].clone(), bin[party].clone(), t).unwrap());
        }
    }
    per_party
}

/// Trusted-dealer stand-in for `PrssDaBitNode` + the modulus-overflow filter: one full-range edaBit
/// per conversion, with `r` rejection-sampled below `p` exactly as the filter guarantees.
fn deal_edabits(
    n_parties: usize,
    t: usize,
    count: usize,
    rng: &mut StdRng,
) -> Vec<Vec<EdaBit<F, K>>> {
    let width = field_bit_width::<F>();
    let mut per_party: Vec<Vec<EdaBit<F, K>>> = vec![Vec::new(); n_parties];
    for _ in 0..count {
        let bits = canonical_bits::<F>(F::rand(rng), width).unwrap();
        let mut per_party_dabits: Vec<Vec<DaBit<F, K>>> = vec![Vec::new(); n_parties];
        for bit in bits {
            let arith =
                RobustShare::compute_shares(F::from(bit as u64), n_parties, t, None, rng).unwrap();
            let bin = GfShare::compute_shares(bit_to_gf::<K>(bit), n_parties, t, rng).unwrap();
            for party in 0..n_parties {
                per_party_dabits[party]
                    .push(DaBit::new(arith[party].clone(), bin[party].clone(), t).unwrap());
            }
        }
        for party in 0..n_parties {
            per_party[party]
                .push(EdaBit::compose_full_width(&per_party_dabits[party], false).unwrap());
        }
    }
    per_party
}

fn deal_gf_triples(
    n_parties: usize,
    t: usize,
    count: usize,
    rng: &mut StdRng,
) -> Vec<Vec<GfBeaverTriple<K>>> {
    let mut per_party: Vec<Vec<GfBeaverTriple<K>>> = vec![Vec::new(); n_parties];
    for _ in 0..count {
        let a = K::random(rng);
        let b = K::random(rng);
        let a_shares = GfShare::compute_shares(a, n_parties, t, rng).unwrap();
        let b_shares = GfShare::compute_shares(b, n_parties, t, rng).unwrap();
        let c_shares = GfShare::compute_shares(a * b, n_parties, t, rng).unwrap();
        for party in 0..n_parties {
            per_party[party].push(GfBeaverTriple::new(
                a_shares[party].clone(),
                b_shares[party].clone(),
                c_shares[party].clone(),
            ));
        }
    }
    per_party
}

fn deal_field(
    n_parties: usize,
    t: usize,
    values: &[F],
    rng: &mut StdRng,
) -> Vec<Vec<RobustShare<F>>> {
    let mut per_party: Vec<Vec<RobustShare<F>>> = vec![Vec::new(); n_parties];
    for value in values {
        let shares = RobustShare::compute_shares(*value, n_parties, t, None, rng).unwrap();
        for party in 0..n_parties {
            per_party[party].push(shares[party].clone());
        }
    }
    per_party
}

fn nodes_for(
    n_parties: usize,
    t: usize,
    instance_id: u32,
) -> Vec<stoffelcrypto::honeybadger::HoneyBadgerMPCNode<F, Avid<SessionId>>> {
    create_global_nodes::<F, Avid<SessionId>, RobustShare<F>, FakeNetwork>(
        n_parties,
        t,
        1,
        2,
        instance_id,
        0,
        0,
        unused_precision(),
        MIN_STATISTICAL_SECURITY,
        Duration::from_secs(60),
        vec![],
    )
}

/// `[x_0..x_{l-1}]_K -> [sum 2^i x_i]_F` through `HoneyBadgerMPCNode::b2a`.
///
/// Exercises the `GfBatchRecon` / `Some(B2A)` dispatch arm and `drain_gf_open_output`, the
/// `b2a_counter` session allocation, the daBit draw from `conv_preprocessing_material`, and
/// `clear_store` on the way out.
#[tokio::test]
async fn b2a_e2e_through_node_dispatch() {
    setup_tracing();

    let n_parties = 4;
    let t = 1;
    let widths = [1usize, 8, 32];
    let total_bits: usize = widths.iter().sum();

    let (network, receivers, _, _) = test_setup(n_parties, vec![]);
    let mut nodes = nodes_for(n_parties, t, 121);

    let mut rng = StdRng::seed_from_u64(11);
    let dabits = deal_dabits(n_parties, t, total_bits, &mut rng);
    for (party, node) in nodes.iter_mut().enumerate() {
        node.conv_preprocessing_material
            .lock()
            .await
            .add(Some(dabits[party].clone()), None);
    }

    // Value `v` is `2^width - 1`, i.e. every bit set: the largest value each width can carry, and
    // the one a width-by-one overshoot would get wrong.
    let mut expected = Vec::new();
    let mut per_party_bits: Vec<Vec<Vec<GfShare<K>>>> = vec![Vec::new(); n_parties];
    for width in widths {
        expected.push(F::from(2u64).pow([width as u64]) - F::one());
        let mut columns: Vec<Vec<GfShare<K>>> = vec![Vec::new(); n_parties];
        for _ in 0..width {
            let shares = GfShare::compute_shares(K::one(), n_parties, t, &mut rng).unwrap();
            for party in 0..n_parties {
                columns[party].push(shares[party].clone());
            }
        }
        for party in 0..n_parties {
            per_party_bits[party].push(columns[party].clone());
        }
    }

    receive::<F, Avid<SessionId>, RobustShare<F>, FakeNetwork>(
        receivers,
        nodes.clone(),
        network.clone(),
        None,
    );

    let mut handles = Vec::new();
    for pid in 0..n_parties {
        let mut node = nodes[pid].clone();
        let net = network[pid].clone();
        let bits = per_party_bits[pid].clone();
        handles.push(tokio::spawn(async move { node.b2a(bits, net).await }));
    }

    let mut per_party_results = Vec::with_capacity(n_parties);
    for handle in handles {
        let result = handle.await.unwrap().expect("b2a failed");
        assert_eq!(result.len(), widths.len());
        per_party_results.push(result);
    }

    for (index, want) in expected.iter().enumerate() {
        let shares: Vec<RobustShare<F>> =
            per_party_results.iter().map(|r| r[index].clone()).collect();
        // Deliberately only `2t + 1` shares: the opening this conversion performs is degree `t`,
        // so a quorum suffices and no party is depended upon.
        let (_, got) = RobustShare::recover_secret(&shares[0..=2 * t], n_parties, t).unwrap();
        assert_eq!(got, *want, "mismatch at value {index}");
    }

    // Every store the conversion touched is retired on the way out (C7).
    for node in &nodes {
        assert_eq!(node.conv.b2a.store_len().await, 0);
        assert_eq!(node.conv.b2a.gf_open.store_len().await, 0);
        assert_eq!(
            node.conv_preprocessing_material
                .lock()
                .await
                .length()
                .dabits,
            0,
            "daBits are drain-only: every one handed to a conversion must be gone"
        );
    }
}

/// A value wider than `max_width::<F>()` is refused **before** any daBit leaves the pool.
///
/// A drained daBit is gone — the pools are drain-only by design — so validating the width only
/// inside `B2ANode` would burn one pad per bit of a request that was never going to run.
#[tokio::test]
async fn b2a_rejects_an_overwide_value_without_consuming_dabits() {
    setup_tracing();

    let n_parties = 4;
    let t = 1;
    let width = field_bit_width::<F>(); // 64 — one above the bound.

    let (network, _receivers, _, _) = test_setup(n_parties, vec![]);
    let mut nodes = nodes_for(n_parties, t, 122);

    let mut rng = StdRng::seed_from_u64(12);
    let dabits = deal_dabits(n_parties, t, width, &mut rng);
    nodes[0]
        .conv_preprocessing_material
        .lock()
        .await
        .add(Some(dabits[0].clone()), None);

    let bits: Vec<GfShare<K>> = (0..width).map(|_| GfShare::new(K::zero(), 0, t)).collect();

    let err = nodes[0]
        .b2a(vec![bits], network[0].clone())
        .await
        .expect_err("width 64 must be refused");
    assert!(
        format!("{err:?}").contains("WidthTooLarge"),
        "unexpected error: {err:?}"
    );
    assert_eq!(
        nodes[0]
            .conv_preprocessing_material
            .lock()
            .await
            .length()
            .dabits,
        width,
        "a refused conversion must not have drained the daBit pool"
    );
}

/// A conversion never preprocesses on demand.
///
/// Conversion preprocessing is synchronous and may abort, and each party would decide for itself
/// whether its pool was short; running it from inside `a2b`/`b2a` would make those calls
/// abortable. So a short pool is an error, raised before anything is drained and before a single
/// message is sent — no receive loop is running here, so a call that tried to preprocess would
/// hang until its timeout instead of returning.
#[tokio::test]
async fn a_short_pool_is_refused_rather_than_topped_up() {
    setup_tracing();

    let n_parties = 4;
    let t = 1;
    let (network, _receivers, _, _) = test_setup(n_parties, vec![]);
    let mut nodes = nodes_for(n_parties, t, 123);
    for node in &mut nodes {
        // Demand is configured, so the old behaviour would have had something to generate.
        node.params.n_edabits = 1;
        node.params.n_dabits = 8;
    }

    let mut rng = StdRng::seed_from_u64(13);
    let x = deal_field(n_parties, t, &[F::from(7u64)], &mut rng);
    let err = tokio::time::timeout(
        Duration::from_secs(5),
        nodes[0].a2b(vec![x[0][0].clone()], network[0].clone()),
    )
    .await
    .expect("a2b with an empty pool must return at once, not start preprocessing")
    .expect_err("a2b with an empty edaBit pool must be refused");
    assert!(
        format!("{err:?}").contains("NotEnoughPreprocessing"),
        "unexpected error: {err:?}"
    );

    let bits: Vec<GfShare<K>> = (0..8).map(|_| GfShare::new(K::zero(), 0, t)).collect();
    let err = tokio::time::timeout(
        Duration::from_secs(5),
        nodes[0].b2a(vec![bits], network[0].clone()),
    )
    .await
    .expect("b2a with an empty pool must return at once, not start preprocessing")
    .expect_err("b2a with an empty daBit pool must be refused");
    assert!(
        format!("{err:?}").contains("NotEnoughPreprocessing"),
        "unexpected error: {err:?}"
    );

    let produced = nodes[0].conv_preprocessing_material.lock().await;
    assert_eq!(
        produced.dabits_produced(),
        0,
        "no daBit may have been generated"
    );
    assert_eq!(
        produced.edabits_produced(),
        0,
        "no edaBit may have been generated"
    );
}

/// An aborted preprocessing batch seals this party's pools.
///
/// Abort is not unanimous: another party may have completed the batch this one aborted, so a
/// retry would leave the positional pools out of step. Once sealed, the party refuses to convert
/// and refuses to preprocess until the pools are reset everywhere — a stall, never a wrong value.
#[tokio::test]
async fn an_aborted_batch_seals_conversion_until_reset() {
    setup_tracing();

    let n_parties = 4;
    let t = 1;
    let width = 8;
    let (network, _receivers, _, _) = test_setup(n_parties, vec![]);
    let mut nodes = nodes_for(n_parties, t, 124);

    let mut rng = StdRng::seed_from_u64(14);
    let dabits = deal_dabits(n_parties, t, width, &mut rng);
    {
        let mut store = nodes[0].conv_preprocessing_material.lock().await;
        store.add(Some(dabits[0].clone()), None);
        assert_eq!(store.length().dabits, width);
        store.mark_aborted();
    }

    // Material that was in the pool before the abort is not handed out afterwards.
    let bits: Vec<GfShare<K>> = (0..width).map(|_| GfShare::new(K::zero(), 0, t)).collect();
    let err = tokio::time::timeout(
        Duration::from_secs(5),
        nodes[0].b2a(vec![bits.clone()], network[0].clone()),
    )
    .await
    .expect("a sealed b2a must return at once")
    .expect_err("a sealed pool must refuse to convert");
    assert!(
        format!("{err:?}").contains("Aborted"),
        "unexpected error: {err:?}"
    );

    // Nor may the party quietly start another batch.
    let err = tokio::time::timeout(
        Duration::from_secs(5),
        nodes[0].run_conversion_preprocessing(network[0].clone(), &mut rng),
    )
    .await
    .expect("sealed preprocessing must return at once")
    .expect_err("a sealed party must refuse to preprocess");
    assert!(
        format!("{err:?}").contains("Aborted"),
        "unexpected error: {err:?}"
    );

    // An explicit reset clears the seal and the stale material with it.
    let mut store = nodes[0].conv_preprocessing_material.lock().await;
    store.reset();
    assert!(!store.is_aborted());
    assert_eq!(
        store.length().dabits,
        0,
        "a reset must not keep misaligned material"
    );
}

/// `[x]_F -> ([x_0]_K, .., [x_63]_K)` through `HoneyBadgerMPCNode::a2b`.
///
/// Exercises the `BatchRecon` / `Some(A2B)` arm, the `GfBatchRecon` and `GfMult` /
/// `Some(A2BGfMul)` arms, both drains, the `a2b_counter` allocation, and the edaBit and GF-triple
/// draws. `x = -1` pins the output convention: the bits of the canonical representative `p - 1`,
/// **not** a two's-complement `u64::MAX`.
#[tokio::test]
async fn a2b_e2e_through_node_dispatch() {
    setup_tracing();

    let n_parties = 4;
    let t = 1;
    let width = field_bit_width::<F>();
    let values = [F::from(0u64), F::from(1u64), F::from(0u64) - F::from(1u64)];

    let (network, receivers, _, _) = test_setup(n_parties, vec![]);
    let mut nodes = nodes_for(n_parties, t, 123);

    let mut rng = StdRng::seed_from_u64(13);
    let per_conversion = A2BNode::<F, K>::gf_triples_per_conversion().unwrap();
    let inputs = deal_field(n_parties, t, &values, &mut rng);
    let edabits = deal_edabits(n_parties, t, values.len(), &mut rng);
    let gf_triples = deal_gf_triples(n_parties, t, per_conversion * values.len(), &mut rng);

    for (party, node) in nodes.iter_mut().enumerate() {
        node.conv_preprocessing_material
            .lock()
            .await
            .add(None, Some(edabits[party].clone()));
        node.gf_preprocessing_material
            .lock()
            .await
            .add(Some(gf_triples[party].clone()), None);
    }

    receive::<F, Avid<SessionId>, RobustShare<F>, FakeNetwork>(
        receivers,
        nodes.clone(),
        network.clone(),
        None,
    );

    let mut handles = Vec::new();
    for pid in 0..n_parties {
        let mut node = nodes[pid].clone();
        let net = network[pid].clone();
        let x = inputs[pid].clone();
        handles.push(tokio::spawn(async move { node.a2b(x, net).await }));
    }

    let mut per_party_results = Vec::with_capacity(n_parties);
    for handle in handles {
        let result = handle.await.unwrap().expect("a2b failed");
        assert_eq!(result.len(), values.len());
        for bits in &result {
            assert_eq!(bits.len(), width);
        }
        per_party_results.push(result);
    }

    for (index, value) in values.iter().enumerate() {
        let want = canonical_bits::<F>(*value, width).unwrap();
        for bit in 0..width {
            let shares: Vec<GfShare<K>> = per_party_results
                .iter()
                .map(|r| r[index][bit].clone())
                .collect();
            let (_, got) = GfShare::recover_secret(&shares[0..=2 * t], n_parties, t).unwrap();
            assert_eq!(
                got,
                bit_to_gf::<K>(want[bit]),
                "value {index} bit {bit} mismatch"
            );
        }
    }

    // `-1` is `p - 1` as a canonical representative, and emphatically not all ones. A caller
    // wanting a sign bit shifts by `2^(k-1)` first.
    let minus_one = canonical_bits::<F>(-F::one(), width).unwrap();
    assert!(minus_one.iter().any(|bit| !*bit));

    for node in &nodes {
        assert_eq!(node.conv.a2b.store_len().await, 0);
        assert_eq!(node.conv.a2b.open.store_len().await, 0);
        assert_eq!(node.conv.a2b.gf_mul.store_len().await, 0);
        assert_eq!(
            node.conv_preprocessing_material
                .lock()
                .await
                .length()
                .edabits,
            0,
            "edaBits are drain-only"
        );
    }
}

/// `a2b` then `b2a_full_width_unchecked`'s node-level equivalent is not exported, so this pins the
/// half of the round trip that is: the bits `a2b` emits feed straight back into `b2a` for any
/// value below `2^(w-1)`, with no re-encoding in between.
#[tokio::test]
async fn a2b_then_b2a_round_trips_below_the_width_bound() {
    setup_tracing();

    let n_parties = 4;
    let t = 1;
    let bound = stoffelcrypto::honeybadger::b2a::b2a::max_width::<F>();
    let value = F::from(1u64 << 32);

    let (network, receivers, _, _) = test_setup(n_parties, vec![]);
    let mut nodes = nodes_for(n_parties, t, 124);

    let mut rng = StdRng::seed_from_u64(14);
    let per_conversion = A2BNode::<F, K>::gf_triples_per_conversion().unwrap();
    let inputs = deal_field(n_parties, t, &[value], &mut rng);
    let edabits = deal_edabits(n_parties, t, 1, &mut rng);
    let gf_triples = deal_gf_triples(n_parties, t, per_conversion, &mut rng);
    let dabits = deal_dabits(n_parties, t, bound, &mut rng);

    for (party, node) in nodes.iter_mut().enumerate() {
        node.conv_preprocessing_material
            .lock()
            .await
            .add(Some(dabits[party].clone()), Some(edabits[party].clone()));
        node.gf_preprocessing_material
            .lock()
            .await
            .add(Some(gf_triples[party].clone()), None);
    }

    receive::<F, Avid<SessionId>, RobustShare<F>, FakeNetwork>(
        receivers,
        nodes.clone(),
        network.clone(),
        None,
    );

    let mut handles = Vec::new();
    for pid in 0..n_parties {
        let mut node = nodes[pid].clone();
        let net = network[pid].clone();
        let x = inputs[pid].clone();
        handles.push(tokio::spawn(async move {
            let bits = node.a2b(x, net.clone()).await?;
            // Truncate to the B2A width bound: the top bit of a full-width decomposition cannot be
            // carried back, and for a value below `2^(w-1)` it is zero anyway.
            let narrowed: Vec<Vec<GfShare<K>>> =
                bits.into_iter().map(|b| b[0..bound].to_vec()).collect();
            node.b2a(narrowed, net).await
        }));
    }

    let mut per_party_results = Vec::with_capacity(n_parties);
    for handle in handles {
        let result = handle.await.unwrap().expect("a2b/b2a round trip failed");
        assert_eq!(result.len(), 1);
        per_party_results.push(result);
    }

    let shares: Vec<RobustShare<F>> = per_party_results.iter().map(|r| r[0].clone()).collect();
    let (_, got) = RobustShare::recover_secret(&shares[0..=2 * t], n_parties, t).unwrap();
    assert_eq!(got, value);
}
