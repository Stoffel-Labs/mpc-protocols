use crate::utils::prandint_utils::spawn_receiver_tasks;
use crate::utils::test_utils::{setup_tracing, test_setup};
use ark_bls12_381::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use num_bigint::BigUint;
use num_integer::binomial;
use std::time::Duration;
use stoffelcrypto::common::rbc::rbc::Avid;
use stoffelcrypto::common::{ProtocolSessionId, SecretSharingScheme};
use stoffelcrypto::honeybadger::fpmul::prandint::PRandIntNode;
use stoffelcrypto::honeybadger::fpmul::{PRandIntMessage, PRANDINT_NONCE_LEN};
use stoffelcrypto::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelcrypto::honeybadger::{ProtocolType, SessionId, WrappedMessage};
use tokio::task::JoinSet;

mod utils;

/// PRandInt masks must actually carry the width they are declared to have.
///
/// `HoneyBadgerMPCNode::mul_fixed`/`div_with_const_fixed` reject a configured mask width narrower
/// than `2k - f`, but that is a config check — it says nothing about the randomness preprocessing
/// really produces. TruncPr broadcasts `b + 2^m*r_int + r'` in the clear and `r_int` is the only
/// thing hiding `b` above bit `m`, so if generation silently produced a small value the declared
/// bound would be satisfied while the mask leaked. This exercises the same `generate_riss` /
/// `wait_for_int_result` path `ensure_prandint_shares` uses, and checks the reconstructed masks
/// are actually large.
#[tokio::test]
async fn prandint_masks_have_their_declared_width() {
    setup_tracing();

    let num_parties = 5;
    let threshold = 1;
    let batch_size = threshold + 1;
    let value_bits = 16;
    let kappa = 20;
    let nu = f64::log2(binomial(num_parties, threshold) as f64).ceil() as usize;
    let mask_bits = value_bits + kappa + nu;

    let session_id = SessionId::new(ProtocolType::PRandInt, SessionId::pack_slot(77, 0, 0), 111);
    let (network, receivers, _, _) = test_setup(num_parties, vec![]);

    let nodes: Vec<PRandIntNode<Fr, Avid<SessionId>>> = (0..num_parties)
        .map(|i| PRandIntNode::new(i, num_parties, threshold, threshold + 1).unwrap())
        .collect();
    let _set = spawn_receiver_tasks(num_parties, receivers, nodes.clone(), network.clone()).await;

    let mut set = JoinSet::new();
    for node in &nodes {
        let id = node.id;
        set.spawn({
            let network = network[id].clone();
            let mut node = node.clone();
            async move {
                node.generate_riss(session_id, mask_bits, batch_size, network)
                    .await
                    .unwrap();
                node.wait_for_int_result(session_id, Duration::from_secs(30))
                    .await
                    .unwrap()
            }
        });
    }

    let mut per_party = vec![Vec::new(); num_parties];
    let mut collected = Vec::new();
    while let Some(result) = set.join_next().await {
        collected.push(result.unwrap());
    }
    for shares in collected {
        for share in shares {
            per_party[share.id].push(share);
        }
    }

    // Reconstruct each mask and confirm it is genuinely wide, not a small or constant value.
    // A degenerate generator (the failure mode this guards) yields tiny reconstructions.
    let produced = per_party[0].len();
    assert!(produced > 0, "no PRandInt masks were produced");

    // Deliberately loose. RISS sums C(n,t) contributions of `mask_bits` each, so a mask lands
    // around `mask_bits + log2(C(n,t))` bits (~59 observed for mask_bits = 39 here) but is
    // near-uniform below that — asserting `>= mask_bits` would fail whenever a draw happens to
    // land low, roughly one time in eight. `value_bits` is far under the distribution while still
    // orders of magnitude above the degenerate values this exists to catch (a constant mask is a
    // handful of bits), giving a false-failure probability around 2^-26.
    let min_acceptable_bits = value_bits as u32;
    for idx in 0..produced {
        let shares: Vec<_> = (0..num_parties)
            .map(|p| per_party[p][idx].clone())
            .collect();
        let (_, mask) = RobustShare::recover_secret(&shares, num_parties, threshold).unwrap();

        assert!(!mask.is_zero(), "PRandInt mask {idx} reconstructed to zero");
        // Bit width = index of the highest set byte, refined to the highest set bit.
        let bytes = mask.into_bigint().to_bytes_le();
        let bits = bytes
            .iter()
            .rposition(|b| *b != 0)
            .map(|i| (i as u32) * 8 + (8 - bytes[i].leading_zeros()))
            .unwrap_or(0);
        assert!(
            bits >= min_acceptable_bits,
            "PRandInt mask {idx} is {bits} bits, far below the declared width {mask_bits}; \
             a mask this narrow cannot hide a 2k-bit TruncPr intermediate"
        );
    }
}

/// The RISS capacity check has to count the `C(n,t)` sets the secret sums over, not just the `n`
/// contributions folded into one set.
///
/// At n=4 the gap is only two bits, which is why this needs a mask parked in the window that the
/// undercount admitted: 250 bits passes `mask_bits + 2 + log2(n) < 255` and fails
/// `mask_bits + 2 + log2(n) + log2(C(4,1)) < 255`. Nothing observable happens when the bound is
/// wrong — the sum wraps the modulus and TruncPr silently truncates a value that is no longer
/// `b + r` over the integers — so the error is the only signal there is.
#[tokio::test]
async fn riss_capacity_check_counts_every_unqualified_set() {
    setup_tracing();

    let n = 4;
    let t = 1;
    let batch_size = t + 1;
    let (network, _receivers, _, _) = test_setup(n, vec![]);

    // Overhead is 2 (for `b`) + log2(n) + log2(C(n,t)) = 2 + 2 + 2 = 6 against Fr's 255 bits.
    let session = |slot| {
        SessionId::new(
            ProtocolType::PRandInt,
            SessionId::pack_slot(slot, 0, 0),
            111,
        )
    };

    let mut node = PRandIntNode::<Fr, Avid<SessionId>>::new(0, n, t, t + 1).unwrap();
    let err = node
        .generate_riss(session(1), 250, batch_size, network[0].clone())
        .await
        .expect_err("a 250-bit mask cannot fit C(n,t) * n * 2^250 into a 255-bit field");
    assert!(
        format!("{err:?}").contains("SurpassedFieldCapacity"),
        "expected SurpassedFieldCapacity, got {err:?}"
    );

    // Guard against the check becoming vacuously strict: 248 bits still fits, and the widths the
    // node is actually configured for are far below either boundary.
    let mut node = PRandIntNode::<Fr, Avid<SessionId>>::new(0, n, t, t + 1).unwrap();
    node.generate_riss(session(2), 248, batch_size, network[0].clone())
        .await
        .expect("248 bits leaves room for the 6 bits of overhead");
}

/// A peer's contribution must be rejected at `2^mask_bits`, not just above it.
///
/// The endpoint is the single value that satisfies an `L`-bit declaration while needing `L+1`
/// bits to represent, so it is exactly the input the width accounting in `generate_riss` does not
/// budget for. Honest parties never produce it — `gen_big_uint_range` is half-open — which is why
/// only a hand-built message reaches this.
#[tokio::test]
async fn riss_rejects_a_contribution_at_the_bound() {
    setup_tracing();

    let n = 4;
    let t = 1;
    let batch_size = t + 1;
    let mask_bits = 32u32;
    let session_id = SessionId::new(ProtocolType::PRandInt, SessionId::pack_slot(9, 0, 0), 111);
    let (network, _receivers, _, _) = test_setup(n, vec![]);

    // Sets `r_t_bound`, without which `process` queues the message instead of checking it.
    let mut node = PRandIntNode::<Fr, Avid<SessionId>>::new(0, n, t, t + 1).unwrap();
    node.generate_riss(
        session_id,
        mask_bits as usize,
        batch_size,
        network[0].clone(),
    )
    .await
    .unwrap();

    let at_bound = BigUint::from(2u32).pow(mask_bits);
    let msg = PRandIntMessage::new(
        1,
        session_id,
        vec![1],
        vec![at_bound.clone(); batch_size],
        [0u8; PRANDINT_NONCE_LEN],
    );
    let err = node
        .process(msg)
        .await
        .expect_err("2^mask_bits is outside a half-open [0, 2^mask_bits)");
    assert!(
        format!("{err:?}").contains("InvalidMessage"),
        "expected InvalidMessage, got {err:?}"
    );

    // One below is legal, so the check is rejecting the endpoint rather than the whole top bit.
    // It gets no further than the range gate here — with no commitment broadcast from party 2 the
    // opening simply parks, which is the correct outcome and still distinguishes it from rejection.
    let below = at_bound - BigUint::from(1u32);
    let msg = PRandIntMessage::new(
        2,
        session_id,
        vec![1],
        vec![below; batch_size],
        [0u8; PRANDINT_NONCE_LEN],
    );
    node.process(msg)
        .await
        .expect("2^mask_bits - 1 is the largest legal contribution");
}

/// The barrier: no opening may leave a party until every party has committed.
///
/// This is the whole anti-rushing property. Without it a corrupt party withholds its own
/// broadcast, watches the honest openings land, picks its `r_T` to steer the sum, and only then
/// commits — a commitment made after seeing the inputs binds it to nothing.
///
/// Guard the guard: releasing openings straight from `generate_riss` passes every other test in
/// this file, because with all parties honest the values are correct either way. Only the *timing*
/// differs, so timing is what this asserts.
#[tokio::test]
async fn riss_holds_openings_until_every_party_has_committed() {
    setup_tracing();

    let n = 4;
    let t = 1;
    let batch_size = t + 1;
    let mask_bits = 40;
    let session_id = SessionId::new(ProtocolType::PRandInt, SessionId::pack_slot(31, 0, 0), 111);
    let (network, mut receivers, _, _) = test_setup(n, vec![]);

    let mut nodes: Vec<PRandIntNode<Fr, Avid<SessionId>>> = (0..n)
        .map(|i| PRandIntNode::new(i, n, t, t + 1).unwrap())
        .collect();

    // Every party commits. No receiver task is running, so nothing is delivered and no party can
    // see another's commitment yet — exactly the window in which a rushing adversary would act.
    for node in &mut nodes {
        node.generate_riss(session_id, mask_bits, batch_size, network[node.id].clone())
            .await
            .unwrap();
    }

    // Drain what is actually in flight to party 0 and classify it.
    let mut commitments = 0;
    let mut openings = 0;
    for rx in receivers[0].iter_mut() {
        while let Ok(bytes) = rx.try_recv() {
            match bincode::deserialize::<WrappedMessage>(&bytes).unwrap() {
                WrappedMessage::Rbc(_) => commitments += 1,
                WrappedMessage::PRandInt(_) => openings += 1,
                _ => {}
            }
        }
    }

    assert!(
        commitments > 0,
        "no commitment traffic at all — the test is not exercising the protocol"
    );
    assert_eq!(
        openings, 0,
        "{openings} opening(s) were sent before any commitment was delivered; the barrier is not \
         holding and a rushing party could choose its contribution after seeing these"
    );

    // And the barrier must not be a deadlock: once commitments are delivered the openings go out.
    assert!(
        !nodes[0].missing_committers(session_id).await.is_empty(),
        "no commitment has been delivered yet, so every party should still be outstanding"
    );
}

/// An opening that does not match its sender's committed value must be rejected, and blamed on the
/// sender.
///
#[tokio::test]
async fn riss_rejects_an_opening_that_does_not_match_its_commitment() {
    setup_tracing();

    let n = 4;
    let t = 1;
    let batch_size = t + 1;
    let mask_bits = 40;
    let session_id = SessionId::new(ProtocolType::PRandInt, SessionId::pack_slot(32, 0, 0), 111);
    let (network, receivers, _, _) = test_setup(n, vec![]);

    let nodes: Vec<PRandIntNode<Fr, Avid<SessionId>>> = (0..n)
        .map(|i| PRandIntNode::new(i, n, t, t + 1).unwrap())
        .collect();
    let _set = spawn_receiver_tasks(n, receivers, nodes.clone(), network.clone()).await;

    let mut set = JoinSet::new();
    for node in &nodes {
        let id = node.id;
        let net = network[id].clone();
        let mut node = node.clone();
        set.spawn(async move {
            node.generate_riss(session_id, mask_bits, batch_size, net)
                .await
                .unwrap();
        });
    }
    while set.join_next().await.is_some() {}

    // Let the commitments land, so party 0 holds party 1's commitment vector.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut victim = nodes[0].clone();
    assert!(
        victim.missing_committers(session_id).await.is_empty(),
        "commitments did not all arrive; the tampered opening below would park, not be checked"
    );

    // Party 1 opens a value it never committed to. `vec![1]` is a real unqualified set that
    // excludes party 0, so this reaches the commitment check rather than a shape guard.
    let forged = PRandIntMessage::new(
        1,
        session_id,
        vec![1],
        vec![BigUint::from(7u32); batch_size],
        [0u8; PRANDINT_NONCE_LEN],
    );
    let err = victim
        .process(forged)
        .await
        .expect_err("an opening that does not match the committed value must be rejected");

    let rendered = format!("{err:?}");
    assert!(
        rendered.contains("EquivocationDetected"),
        "expected EquivocationDetected, got {rendered}"
    );
    // The blame must name the sender — the whole point is that it is unambiguous now.
    assert!(
        rendered.contains("EquivocationDetected(1"),
        "equivocation must be attributed to sender 1, got {rendered}"
    );
}
