//! Arithmetic-to-binary conversion through `HoneyBadgerMPCNode` (blueprint §7.4).
//!
//! Tier B: every message goes through `node.process`'s dispatch, so this exercises the wiring the
//! standalone `a2b_test.rs` bypasses — the `BatchRecon`/`Some(A2B)`, `GfBatchRecon`/`Some(A2BGfMul)`,
//! `GfMult`/`Some(A2BGfMul)` and `GfBatchRecon`/`Some(B2A)` arms, the drains behind them, the
//! `a2b_counter`/`b2a_counter` session allocation, and the draws from
//! `conv_preprocessing_material` and `gf_preprocessing_material`. It keeps the same full-range
//! corpus as `a2b_test.rs` so that a regression confined to the node path — a mis-tagged session,
//! a missing drain, a material draw of the wrong length — shows up as a wrong *value*, not merely
//! as a hang.
//!
//! Conversion preprocessing is dealt honestly by [`utils::a2b_utils`] rather than generated, for
//! the reason given in that file's header, and the pools are filled before each call so that
//! `HoneyBadgerMPCNode::a2b`'s "top up if short" branch never fires. A short pool here would drag
//! in a full preprocessing run — a `PrssDaBitNode` batch plus the `RandBit`s it consumes and the
//! GF triples the `r < p` filter needs — which is a preprocessing-scale exercise rather than a
//! test of the conversion.

pub mod utils;

#[path = "utils/a2b_utils.rs"]
mod a2b_utils;

#[path = "utils/conv_width_utils.rs"]
mod conv_width_utils;

use crate::a2b_utils::{
    boundary_values, deal_bits, deal_dabits, deal_edabits, deal_field, deal_gf_triples,
    expected_bits, random_values, recompose_u128, recover_bit, recover_field, F, K,
};
use crate::conv_width_utils::{
    as_integer, fixed_point_corpus, fixed_point_width, shift_to_unsigned,
};
use crate::utils::test_utils::{
    create_global_nodes, receive, setup_tracing, test_setup, unused_precision,
};
use ark_std::rand::rngs::StdRng;
use ark_std::rand::{Rng, SeedableRng};
use std::sync::Arc;
use std::time::Duration;
use stoffelcrypto::common::convert::field_bit_width;
use stoffelcrypto::common::gf2k::share::GfShare;
use stoffelcrypto::common::{rbc::rbc::Avid, ShareConversionProtocol};
use stoffelcrypto::honeybadger::{
    a2b::a2b::A2BNode, b2a::b2a::max_width, robust_interpolate::robust_interpolate::RobustShare,
    HoneyBadgerMPCNode, SessionId, MIN_STATISTICAL_SECURITY,
};
use stoffelmpc_network::fake_network::FakeNetwork;

type Node = HoneyBadgerMPCNode<F, Avid<SessionId>>;

/// `n = 3t + 1` at its smallest, matching every other node-level test in this crate.
const N_PARTIES: usize = 4;
const T: usize = 1;

fn nodes_for(instance_id: u32) -> Vec<Node> {
    create_global_nodes::<F, Avid<SessionId>, RobustShare<F>, FakeNetwork>(
        N_PARTIES,
        T,
        1, // F-domain preprocessing is untouched here: A2B and B2A consume zero `F` triples.
        2,
        instance_id,
        0,
        0,
        unused_precision(),
        MIN_STATISTICAL_SECURITY,
        Duration::from_secs(120),
        vec![],
    )
}

/// Everything one node-level conversion needs, dealt and installed in the nodes' own pools.
///
/// `create_global_nodes` hard-codes `n_gf_triples = 0` and leaves `n_dabits`/`n_edabits` at zero,
/// which is what keeps the "top up if short" branches of `a2b`/`b2a` from starting a real
/// preprocessing run; the pools are filled here instead.
async fn install_material(nodes: &mut [Node], conversions: usize, dabits: usize, rng: &mut StdRng) {
    let per_conversion = A2BNode::<F, K>::gf_triples_per_conversion().unwrap();
    let edabits = deal_edabits(N_PARTIES, T, conversions, rng);
    let triples = deal_gf_triples(N_PARTIES, T, per_conversion * conversions, rng);
    let pads = deal_dabits(N_PARTIES, T, dabits, rng);

    for (party, node) in nodes.iter_mut().enumerate() {
        node.conv_preprocessing_material.lock().await.add(
            if dabits > 0 {
                Some(pads[party].clone())
            } else {
                None
            },
            if conversions > 0 {
                Some(edabits[party].clone())
            } else {
                None
            },
        );
        if conversions > 0 {
            node.gf_preprocessing_material
                .lock()
                .await
                .add(Some(triples[party].clone()), None);
        }
    }
}

/// Asserts that every conversion store the batch touched is retired and every pool it drew from is
/// empty — the two things a node-level test can check that a standalone one cannot.
async fn assert_drained(nodes: &[Node], expect_edabits: usize, expect_dabits: usize) {
    for node in nodes {
        assert_eq!(node.conv.a2b.store_len().await, 0, "A2B store not retired");
        assert_eq!(
            node.conv.a2b.open.store_len().await,
            0,
            "A2B mask-opening store not retired"
        );
        assert_eq!(
            node.conv.a2b.gf_mul.store_len().await,
            0,
            "A2B multiplication store not retired"
        );
        assert_eq!(node.conv.b2a.store_len().await, 0, "B2A store not retired");
        assert_eq!(
            node.conv.b2a.gf_open.store_len().await,
            0,
            "B2A opening store not retired"
        );

        let length = node.conv_preprocessing_material.lock().await.length();
        // Drain-only pools (C15): a daBit or edaBit handed to a conversion must be gone, because
        // returning one would turn two openings into `c XOR c' = x XOR x'`.
        assert_eq!(length.edabits, expect_edabits, "edaBit pool not drained");
        assert_eq!(length.dabits, expect_dabits, "daBit pool not drained");
    }
}

/// Runs `node.a2b` on every party and returns the bit shares, indexed `[party][value][bit]`.
async fn run_a2b(
    nodes: &[Node],
    network: &[Arc<FakeNetwork>],
    inputs: Vec<Vec<RobustShare<F>>>,
) -> Vec<Vec<Vec<GfShare<K>>>> {
    let mut handles = Vec::with_capacity(N_PARTIES);
    for party in 0..N_PARTIES {
        let mut node = nodes[party].clone();
        let net = network[party].clone();
        let x = inputs[party].clone();
        handles.push(tokio::spawn(async move { node.a2b(x, net).await }));
    }
    let mut results = Vec::with_capacity(N_PARTIES);
    for (party, handle) in handles.into_iter().enumerate() {
        results.push(
            handle
                .await
                .expect("a2b task panicked")
                .unwrap_or_else(|e| panic!("a2b failed on party {party}: {e:?}")),
        );
    }
    results
}

/// Runs `node.b2a` on every party and returns the arithmetic shares, indexed `[party][value]`.
async fn run_b2a(
    nodes: &[Node],
    network: &[Arc<FakeNetwork>],
    bits: Vec<Vec<Vec<GfShare<K>>>>,
) -> Vec<Vec<RobustShare<F>>> {
    let mut handles = Vec::with_capacity(N_PARTIES);
    for party in 0..N_PARTIES {
        let mut node = nodes[party].clone();
        let net = network[party].clone();
        let value_bits = bits[party].clone();
        handles.push(tokio::spawn(async move { node.b2a(value_bits, net).await }));
    }
    let mut results = Vec::with_capacity(N_PARTIES);
    for (party, handle) in handles.into_iter().enumerate() {
        results.push(
            handle
                .await
                .expect("b2a task panicked")
                .unwrap_or_else(|e| panic!("b2a failed on party {party}: {e:?}")),
        );
    }
    results
}

/// Reconstructs a whole batch of A2B output from a quorum and checks it against the canonical
/// decompositions.
fn assert_bits_match(label: &str, values: &[F], results: &[Vec<Vec<GfShare<K>>>]) {
    let width = field_bit_width::<F>();
    for (party, per_value) in results.iter().enumerate() {
        assert_eq!(per_value.len(), values.len(), "{label}: wrong batch length");
        for bits in per_value {
            assert_eq!(bits.len(), width, "{label}: wrong output width");
            for bit in bits {
                assert_eq!(bit.degree, T, "{label}: output share is not degree t");
                assert_eq!(
                    bit.id, party,
                    "{label}: output share carries a foreign index"
                );
            }
        }
    }
    for (index, value) in values.iter().enumerate() {
        let want = expected_bits(*value);
        let got: Vec<bool> = (0..width)
            .map(|bit| {
                let column: Vec<GfShare<K>> =
                    results.iter().map(|r| r[index][bit].clone()).collect();
                recover_bit(&column, N_PARTIES, T)
            })
            .collect();
        assert_eq!(got, want, "{label}: value {index} decomposed wrongly");
    }
}

// -------------------------------------------------------------------------------------------

/// The full-range corpus through the node dispatcher.
///
/// Same values as `a2b_test.rs`'s standalone run: `0`, `1`, the `2^32` neighbourhood that the
/// `2^64 - p = 2^32 - 1` identity turns into a carry boundary, the `2^63` neighbourhood that
/// straddles B2A's width bound, the `p - 2^32` neighbourhood that drives the `c1 = 1` branch, and
/// `-1`.
#[tokio::test]
async fn a2b_full_range_through_node_dispatch() {
    setup_tracing();

    let corpus = boundary_values();
    let values: Vec<F> = corpus.iter().map(|(_, value)| *value).collect();

    let (network, receivers, _, _) = test_setup(N_PARTIES, vec![]);
    let mut nodes = nodes_for(301);
    let mut rng = StdRng::seed_from_u64(3_001);

    install_material(&mut nodes, values.len(), 0, &mut rng).await;
    let inputs = deal_field(N_PARTIES, T, &values, &mut rng);

    receive::<F, Avid<SessionId>, RobustShare<F>, FakeNetwork>(
        receivers,
        nodes.clone(),
        network.clone(),
        None,
    );

    let results = run_a2b(&nodes, &network, inputs).await;
    assert_bits_match("node-boundary", &values, &results);
    assert_drained(&nodes, 0, 0).await;
}

/// A random batch, so the node path is not exercised solely on special cases.
#[tokio::test]
async fn a2b_random_batch_through_node_dispatch() {
    setup_tracing();

    let mut rng = StdRng::seed_from_u64(3_002);
    let values = random_values(9, &mut rng);

    let (network, receivers, _, _) = test_setup(N_PARTIES, vec![]);
    let mut nodes = nodes_for(302);

    install_material(&mut nodes, values.len(), 0, &mut rng).await;
    let inputs = deal_field(N_PARTIES, T, &values, &mut rng);

    receive::<F, Avid<SessionId>, RobustShare<F>, FakeNetwork>(
        receivers,
        nodes.clone(),
        network.clone(),
        None,
    );

    let results = run_a2b(&nodes, &network, inputs).await;
    assert_bits_match("node-random", &values, &results);
    assert_drained(&nodes, 0, 0).await;
}

/// `b2a(a2b([x])) == [x]` through the node, for every `x` below `2^63`.
///
/// `HoneyBadgerMPCNode::b2a` is the *checked-width* entry point — 63 bits, not 64 — so the round
/// trip at node level is the one a mixed circuit actually performs: A2B's top bit is dropped,
/// which is exact precisely because a value below `2^63` cannot set it. The full-width variant is
/// only reachable on `B2ANode` directly and is covered in `a2b_test.rs`.
#[tokio::test]
async fn a2b_then_b2a_round_trips_through_node_dispatch() {
    setup_tracing();

    let bound = max_width::<F>();
    let values = vec![
        F::from(0u64),
        F::from(1u64),
        F::from(0xFFFF_FFFFu64),
        F::from(1u64 << 32),
        F::from((1u64 << 63) - 1),
    ];

    let (network, receivers, _, _) = test_setup(N_PARTIES, vec![]);
    let mut nodes = nodes_for(303);
    let mut rng = StdRng::seed_from_u64(3_003);

    install_material(&mut nodes, values.len(), bound * values.len(), &mut rng).await;
    let inputs = deal_field(N_PARTIES, T, &values, &mut rng);

    receive::<F, Avid<SessionId>, RobustShare<F>, FakeNetwork>(
        receivers,
        nodes.clone(),
        network.clone(),
        None,
    );

    let bits = run_a2b(&nodes, &network, inputs).await;
    assert_bits_match("node-roundtrip-forward", &values, &bits);

    // Every one of these values is below `2^63`, so A2B left bit 63 clear and dropping it is
    // exact. A value at or above `2^63` could not be carried back through the checked entry point
    // at all, which is the width bound doing its job rather than a limitation of the round trip.
    for index in 0..values.len() {
        let top: Vec<GfShare<K>> = bits.iter().map(|r| r[index][bound].clone()).collect();
        assert!(
            !recover_bit(&top, N_PARTIES, T),
            "value {index} unexpectedly set bit {bound}"
        );
    }
    let narrowed: Vec<Vec<Vec<GfShare<K>>>> = bits
        .iter()
        .map(|per_value| {
            per_value
                .iter()
                .map(|value_bits| value_bits[0..bound].to_vec())
                .collect()
        })
        .collect();

    let back = run_b2a(&nodes, &network, narrowed).await;
    for (index, want) in values.iter().enumerate() {
        let column: Vec<RobustShare<F>> = back.iter().map(|r| r[index].clone()).collect();
        assert_eq!(
            recover_field(&column, N_PARTIES, T),
            *want,
            "round trip lost value {index}"
        );
    }
    assert_drained(&nodes, 0, 0).await;
}

/// `a2b(b2a(bits)) == bits` through the node.
#[tokio::test]
async fn b2a_then_a2b_round_trips_through_node_dispatch() {
    setup_tracing();

    let ell = max_width::<F>();
    let values = 3usize;

    let (network, receivers, _, _) = test_setup(N_PARTIES, vec![]);
    let mut nodes = nodes_for(304);
    let mut rng = StdRng::seed_from_u64(3_004);

    install_material(&mut nodes, values, ell * values, &mut rng).await;

    // One all-ones vector, so the largest value B2A can carry (`2^63 - 1`) is in the batch.
    let clear: Vec<Vec<bool>> = (0..values)
        .map(|index| {
            (0..ell)
                .map(|_| index == values - 1 || rng.gen::<bool>())
                .collect()
        })
        .collect();
    let mut per_party_bits: Vec<Vec<Vec<GfShare<K>>>> = vec![Vec::new(); N_PARTIES];
    for value_bits in &clear {
        let columns = deal_bits(N_PARTIES, T, value_bits, &mut rng);
        for party in 0..N_PARTIES {
            per_party_bits[party].push(columns[party].clone());
        }
    }

    receive::<F, Avid<SessionId>, RobustShare<F>, FakeNetwork>(
        receivers,
        nodes.clone(),
        network.clone(),
        None,
    );

    let arithmetic = run_b2a(&nodes, &network, per_party_bits).await;
    let recovered: Vec<F> = (0..values)
        .map(|index| {
            let column: Vec<RobustShare<F>> = arithmetic.iter().map(|r| r[index].clone()).collect();
            let value = recover_field(&column, N_PARTIES, T);
            assert_eq!(
                value,
                F::from(recompose_u128(&clear[index]) as u64),
                "B2A recomposed value {index} wrongly"
            );
            value
        })
        .collect();

    let bits = run_a2b(&nodes, &network, arithmetic).await;
    assert_bits_match("node-roundtrip-reverse", &recovered, &bits);
    for (index, want) in clear.iter().enumerate() {
        for bit in 0..ell {
            let column: Vec<GfShare<K>> = bits.iter().map(|r| r[index][bit].clone()).collect();
            assert_eq!(
                recover_bit(&column, N_PARTIES, T),
                want[bit],
                "value {index} bit {bit} did not survive the round trip"
            );
        }
    }
    assert_drained(&nodes, 0, 0).await;
}

/// An empty batch is a no-op that touches neither the network nor the pools.
///
/// Worth pinning at node level because `A2BNode::init` rejects an empty batch outright (C13: an
/// empty one makes every downstream length check pass vacuously), so the node has to filter it
/// before it gets there — and a node that instead forwarded it would fail a conversion of zero
/// values with `EmptyBatch`, which is a confusing way to say "nothing to do".
#[tokio::test]
async fn a2b_of_an_empty_batch_is_a_no_op() {
    setup_tracing();

    let (network, _receivers, _, _) = test_setup(N_PARTIES, vec![]);
    let mut nodes = nodes_for(305);
    let mut rng = StdRng::seed_from_u64(3_005);

    install_material(&mut nodes, 1, 0, &mut rng).await;

    let out = nodes[0]
        .a2b(Vec::new(), network[0].clone())
        .await
        .expect("an empty conversion must succeed");
    assert!(out.is_empty());
    assert_eq!(
        nodes[0]
            .conv_preprocessing_material
            .lock()
            .await
            .length()
            .edabits,
        1,
        "an empty conversion must not draw from the pool"
    );
}

/// The fixed-point round trip through the node dispatcher: `b2a(narrow_to_33(a2b([x]))) == [x]`.
///
/// `ell = 33` is what `FixedPointPrecision::new(32, 16)` carries (plan §2.4), and this is the
/// shape a fixed-point mixed circuit actually runs: decompose the whole field element, work on 33
/// bits, recompose. `HoneyBadgerMPCNode::b2a` is the checked-width entry point, and 33 is well
/// inside its bound, so nothing here needs the full-width variant.
///
/// Narrowing is only sound because A2B leaves bits `33..64` clear for an in-range payload, which
/// is asserted before the narrowing rather than assumed by it — a conversion that left rubbish
/// above bit 32 would round-trip correctly here (B2A never sees those bits) and lose the value
/// everywhere else, so checking it on the way past is the point.
///
/// The material accounting is the node-level half: A2B draws one full-width edaBit per value
/// whatever `ell` is, while B2A draws `33 * values` daBits rather than `63 * values`. Both pools
/// are filled to exactly that and `assert_drained` checks both are empty afterwards, so a draw of
/// the wrong length fails here rather than starving the next conversion.
#[tokio::test]
async fn a2b_then_b2a_round_trips_at_the_fixed_point_width_through_node_dispatch() {
    setup_tracing();

    let ell = fixed_point_width();
    assert_eq!(ell, 33);
    let width = field_bit_width::<F>();

    let corpus = fixed_point_corpus();
    let values: Vec<F> = corpus
        .iter()
        .map(|(_, payload)| F::from(*payload))
        .collect();

    let (network, receivers, _, _) = test_setup(N_PARTIES, vec![]);
    let mut nodes = nodes_for(306);
    let mut rng = StdRng::seed_from_u64(3_006);

    install_material(&mut nodes, values.len(), ell * values.len(), &mut rng).await;
    let inputs = deal_field(N_PARTIES, T, &values, &mut rng);

    receive::<F, Avid<SessionId>, RobustShare<F>, FakeNetwork>(
        receivers,
        nodes.clone(),
        network.clone(),
        None,
    );

    let bits = run_a2b(&nodes, &network, inputs).await;
    assert_bits_match("node-fixed-point", &values, &bits);

    for (index, (label, payload)) in corpus.iter().enumerate() {
        let got: Vec<bool> = (0..width)
            .map(|bit| {
                let column: Vec<GfShare<K>> = bits.iter().map(|r| r[index][bit].clone()).collect();
                recover_bit(&column, N_PARTIES, T)
            })
            .collect();
        assert!(
            got[ell..].iter().all(|bit| !bit),
            "{label}: narrowing to {ell} bits would not be lossless"
        );
        assert_eq!(as_integer(&got[0..ell]), *payload as u128, "{label}");
    }

    let narrowed: Vec<Vec<Vec<GfShare<K>>>> = bits
        .iter()
        .map(|per_value| {
            per_value
                .iter()
                .map(|value_bits| value_bits[0..ell].to_vec())
                .collect()
        })
        .collect();

    let back = run_b2a(&nodes, &network, narrowed).await;
    for (index, (label, payload)) in corpus.iter().enumerate() {
        let column: Vec<RobustShare<F>> = back.iter().map(|r| r[index].clone()).collect();
        assert_eq!(
            recover_field(&column, N_PARTIES, T),
            F::from(*payload),
            "{label}: the fixed-point round trip lost the value"
        );
    }
    assert_drained(&nodes, 0, 0).await;
}

/// A signed fixed-point value only narrows *after* the `+2^(k-1)` shift, through the node path.
///
/// The same negative result `a2b_test.rs` pins standalone, repeated here because it is the one a
/// caller gets wrong: the repo encodes `-v` as `p - v`, so `-1` reaches A2B as
/// `0xFFFF_FFFF_0000_0000`, whose low 33 bits are **all zero**. Narrowing it to the fixed-point
/// width reads `-1` as `0`, silently and with no error anywhere. The free shift `truncpr` already
/// applies is what makes narrowing legitimate, and the two conversions are run side by side in one
/// batch so the difference is visible in a single output.
#[tokio::test]
async fn a2b_narrows_a_fixed_point_value_only_after_the_shift_through_node_dispatch() {
    setup_tracing();

    let ell = fixed_point_width();
    let width = field_bit_width::<F>();
    let signed: Vec<i64> = vec![-1, -(1i64 << 31), 1 << 16];

    let unshifted: Vec<F> = signed
        .iter()
        .map(|v| {
            if *v >= 0 {
                F::from(*v as u64)
            } else {
                F::from(0u64) - F::from(v.unsigned_abs())
            }
        })
        .collect();
    let shifted: Vec<F> = signed
        .iter()
        .map(|v| F::from(shift_to_unsigned(*v)))
        .collect();
    let values: Vec<F> = unshifted.iter().chain(shifted.iter()).copied().collect();

    let (network, receivers, _, _) = test_setup(N_PARTIES, vec![]);
    let mut nodes = nodes_for(307);
    let mut rng = StdRng::seed_from_u64(3_007);

    install_material(&mut nodes, values.len(), 0, &mut rng).await;
    let inputs = deal_field(N_PARTIES, T, &values, &mut rng);

    receive::<F, Avid<SessionId>, RobustShare<F>, FakeNetwork>(
        receivers,
        nodes.clone(),
        network.clone(),
        None,
    );

    let bits = run_a2b(&nodes, &network, inputs).await;
    assert_bits_match("node-fixed-point-shift", &values, &bits);

    let decompose = |index: usize| -> Vec<bool> {
        (0..width)
            .map(|bit| {
                let column: Vec<GfShare<K>> = bits.iter().map(|r| r[index][bit].clone()).collect();
                recover_bit(&column, N_PARTIES, T)
            })
            .collect()
    };

    for (i, v) in signed.iter().enumerate() {
        let raw = decompose(i);
        let after = decompose(signed.len() + i);
        assert!(
            after[ell..].iter().all(|bit| !bit),
            "shift({v}) must fit the fixed-point width"
        );
        assert_eq!(
            as_integer(&after[0..ell]),
            shift_to_unsigned(*v) as u128,
            "shift({v}) narrowed wrongly"
        );
        if *v < 0 {
            assert!(
                raw[ell..].iter().any(|bit| *bit),
                "{v} encodes as p - |v| and must overflow the width"
            );
            // What narrowing produces is not an obviously broken value — it is some other
            // perfectly well-formed 33-bit payload, which is exactly why the loss is silent.
            // `-1` lands on `2^32`, the headroom bit alone, which reads back as `+2^31`: one past
            // the largest representable positive, at the opposite end of the range.
            assert_ne!(
                as_integer(&raw[0..ell]),
                shift_to_unsigned(*v) as u128,
                "{v} must not narrow to its own shifted form"
            );
            if *v == -1 {
                assert_eq!(as_integer(&raw[0..ell]), 1u128 << 32);
            }
        } else {
            assert_eq!(as_integer(&raw[0..ell]), *v as u128);
        }
    }
    assert_drained(&nodes, 0, 0).await;
}
