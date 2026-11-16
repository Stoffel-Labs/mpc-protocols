//! daBit generation, end to end: the object every consumer relies on, and what a cheating party
//! can and cannot do to it.
//!
//! The generator is [`ReplicatedDaBitNode`](stoffelcrypto::honeybadger::dabit::replicated) —
//! information-theoretic, built from per-set one-time bits that are dealt, echoed, and folded.
//! These tests run it over a real `FakeNetwork`.
//!
//! # What is asserted
//!
//! * **One bit, two domains.** Both halves reconstruct to the same value, and that value is 0 or
//!   1 in each field.
//! * **Degree `t` as form.** Every `t+1`-subset of shares interpolates to the same secret.
//! * **Uniformity and independence**, as two-sided statistical bands.
//! * **Abort, never a wrong output.** A dealer that equivocates, a holder that echoes something
//!   else, and a malformed dealing all end in an error at every party — no party is left holding
//!   a daBit from a tampered batch.
//!
//! # Phase: PREPROCESSING
//!
//! Synchronous, abort permitted. The adversarial tests use a short timeout because a party that
//! did not itself detect the cheating learns of it by the batch stalling.

mod utils;

use std::sync::Arc;
use std::time::Duration;

use stoffelcrypto::honeybadger::batch_recon::{BatchReconMsg, BatchReconMsgType};
use stoffelcrypto::honeybadger::dabit::{DaBit, DaBitError, DaBitPayload, EdaBit};

use crate::utils::dabit_utils::{
    assert_bits_look_uniform, assert_degree_t_form, assert_same_bit_in_both_domains, deal_dabits,
    expect_all_err, expect_all_ok, hamming, DaBitHarness, OpenTamper, Tamper, F, K,
};
use crate::utils::test_utils::{catch_expected_panic, setup_tracing};

use ark_ff::PrimeField;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use num_bigint::BigUint;
use stoffelcrypto::common::{gf2k::share::GfShare, SecretSharingScheme};
use stoffelcrypto::honeybadger::robust_interpolate::robust_interpolate::RobustShare;

/// Long enough for an honest run many times over, short enough that a stalled batch fails fast.
const ABORT_TIMEOUT: Duration = Duration::from_secs(3);

async fn one_bit_in_two_domains(n: usize, t: usize, count: usize, seed: u64) {
    let mut harness = DaBitHarness::new(n, t, seed);
    let batch = expect_all_ok(harness.generate(count).await);
    let bits = assert_same_bit_in_both_domains(&batch, n, t);
    assert_degree_t_form(&batch, n, t);
    assert_bits_look_uniform(&bits, &format!("n={n} t={t}"));
    // Nothing stays resident: the dealing session and every XOR-fold child are retired.
    for party in 0..n {
        assert_eq!(harness.node(party).store_len().await, 0, "party {party}");
        assert_eq!(
            harness.node(party).dn07.store_len().await,
            0,
            "party {party}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn dabits_are_one_bit_in_two_domains_n4_t1() {
    setup_tracing();
    one_bit_in_two_domains(4, 1, 128, 0x0DAB_0004).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn dabits_are_one_bit_in_two_domains_n7_t2() {
    setup_tracing();
    one_bit_in_two_domains(7, 2, 64, 0x0DAB_0007).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn dabits_are_one_bit_in_two_domains_n10_t3() {
    setup_tracing();
    one_bit_in_two_domains(10, 3, 32, 0x0DAB_0010).await;
}

/// A batch of one is as sound as a batch of many: there is no statistical check to amortise.
#[tokio::test(flavor = "multi_thread")]
async fn a_single_dabit_batch_is_well_formed() {
    setup_tracing();
    let mut harness = DaBitHarness::new(4, 1, 0x0DAB_0001);
    let batch = expect_all_ok(harness.generate(1).await);
    assert_same_bit_in_both_domains(&batch, 4, 1);
    assert_degree_t_form(&batch, 4, 1);
}

/// Every batch draws fresh randomness: two batches must not repeat their bits.
#[tokio::test(flavor = "multi_thread")]
async fn two_batches_are_independent() {
    setup_tracing();
    let mut harness = DaBitHarness::new(4, 1, 0x0DAB_0020);

    let first = expect_all_ok(harness.generate(64).await);
    let second = expect_all_ok(harness.generate(64).await);

    let a = assert_same_bit_in_both_domains(&first, 4, 1);
    let b = assert_same_bit_in_both_domains(&second, 4, 1);
    assert_bits_look_uniform(&a, "batch 1");
    assert_bits_look_uniform(&b, "batch 2");

    let distance = hamming(&a, &b);
    assert!(
        (12..=52).contains(&distance),
        "two independent 64-bit batches differed in {distance} positions, which is outside a \
         five-sigma band around 32"
    );
}

/// `[r]_F = Σ 2^i [b_i]_F` over a batch's arithmetic halves is the integer the binary halves
/// spell — the property edaBit composition, and through it A2B, rests on.
#[tokio::test(flavor = "multi_thread")]
async fn an_edabit_composed_from_dabits_is_the_integer_its_bits_spell() {
    setup_tracing();
    const WIDTH: usize = 32;
    let (n, t) = (7, 2);
    let mut harness = DaBitHarness::new(n, t, 0x0DAB_0030);

    let batch = expect_all_ok(harness.generate(WIDTH).await);
    let bits = assert_same_bit_in_both_domains(&batch, n, t);

    let composed: Vec<EdaBit<F, K>> = batch
        .iter()
        .map(|dabits| EdaBit::compose(dabits, WIDTH).expect("edaBit composition"))
        .collect();

    for (party, edabit) in composed.iter().enumerate() {
        assert_eq!(edabit.width, WIDTH);
        assert_eq!(edabit.bits.len(), WIDTH);
        for (i, bit) in edabit.bits.iter().enumerate() {
            assert_eq!(
                *bit, batch[party][i].bin,
                "party {party} edaBit bit {i} is not the daBit's binary half"
            );
        }
    }

    let value_shares: Vec<RobustShare<F>> = composed.iter().map(|e| e.value.clone()).collect();
    let (_, value) = RobustShare::recover_secret(&value_shares, n, t).expect("value");

    let expected: u64 = bits
        .iter()
        .enumerate()
        .map(|(i, b)| *b << i)
        .fold(0u64, |acc, term| acc | term);
    assert_eq!(
        value,
        F::from(expected),
        "the composed edaBit is not the integer its {WIDTH} bits spell out"
    );
    let modulus: BigUint = F::MODULUS.into();
    assert!(BigUint::from(expected) < modulus);
}

fn flip_first_bit(sets: &mut [(u32, Vec<u8>)]) {
    if let Some((_, bits)) = sets.first_mut() {
        if let Some(byte) = bits.first_mut() {
            *byte ^= 1;
        }
    }
}

/// **The dealer equivocates.** Party 0 deals one set's bits to party 2 with a bit flipped, and
/// the true bits to that set's other holders. The echo exposes it: every holder of the set
/// aborts with a mismatch, the party outside the set stalls, and nobody outputs a daBit.
#[tokio::test(flavor = "multi_thread")]
async fn an_equivocating_dealer_aborts_the_batch() {
    setup_tracing();
    let tamper: Tamper = Arc::new(|recipient, msg| {
        if recipient == 2 && msg.sender_id == 0 {
            if let DaBitPayload::Deal { sets, .. } = &mut msg.payload {
                flip_first_bit(sets);
            }
        }
    });
    let mut harness = DaBitHarness::with_tamper(4, 1, 0x0DAB_0040, Some(tamper));
    let errors = expect_all_err(harness.generate_within(16, ABORT_TIMEOUT).await);

    assert!(
        matches!(errors[2], DaBitError::DealingMismatch { .. }),
        "the party that was dealt the wrong bits must see the mismatch, got {:?}",
        errors[2]
    );
    let detected = errors
        .iter()
        .filter(|e| matches!(e, DaBitError::DealingMismatch { .. }))
        .count();
    assert!(
        detected >= 2,
        "an equivocation is seen by both sides of at least one echo, got {errors:?}"
    );
}

/// **A holder echoes something it was not dealt.** The party it lies to aborts.
#[tokio::test(flavor = "multi_thread")]
async fn a_lying_echo_aborts_the_batch() {
    setup_tracing();
    let tamper: Tamper = Arc::new(|recipient, msg| {
        if recipient == 0 && msg.sender_id == 1 {
            if let DaBitPayload::Echo { sets, .. } = &mut msg.payload {
                flip_first_bit(sets);
            }
        }
    });
    let mut harness = DaBitHarness::with_tamper(4, 1, 0x0DAB_0041, Some(tamper));
    let errors = expect_all_err(harness.generate_within(16, ABORT_TIMEOUT).await);
    assert!(
        matches!(errors[0], DaBitError::DealingMismatch { with: 1 }),
        "got {:?}",
        errors[0]
    );
}

/// **A dealing no honest party would send** — here, bits for a set the sender does not deal —
/// fails the batch at the recipient instead of being absorbed.
#[tokio::test(flavor = "multi_thread")]
async fn a_dealing_for_a_set_the_sender_does_not_deal_aborts_the_batch() {
    setup_tracing();
    // Party 3 deals no set at n = 4 except the one excluding the three parties below it, so any
    // entry it sends party 0 under another rank is one it has no right to deal.
    let tamper: Tamper = Arc::new(|recipient, msg| {
        if recipient == 1 && msg.sender_id == 0 {
            if let DaBitPayload::Deal { sets, .. } = &mut msg.payload {
                // Rank 0 is the set {0}: party 0 is inside it and cannot be its dealer.
                if let Some((rank, _)) = sets.first_mut() {
                    *rank = 0;
                }
            }
        }
    });
    let mut harness = DaBitHarness::with_tamper(4, 1, 0x0DAB_0042, Some(tamper));
    let errors = expect_all_err(harness.generate_within(16, ABORT_TIMEOUT).await);
    assert!(
        matches!(errors[1], DaBitError::InvalidDealing(_)),
        "got {:?}",
        errors[1]
    );
}

/// Unused high bits of the last byte must be zero: the echo compares bytes, so padding a dealer
/// could vary would let it make honest holders disagree without changing a single bit.
#[tokio::test(flavor = "multi_thread")]
async fn dirty_padding_in_a_dealing_aborts_the_batch() {
    setup_tracing();
    let tamper: Tamper = Arc::new(|recipient, msg| {
        if recipient == 1 && msg.sender_id == 0 {
            if let DaBitPayload::Deal { sets, .. } = &mut msg.payload {
                if let Some((_, bits)) = sets.first_mut() {
                    if let Some(last) = bits.last_mut() {
                        *last |= 0x80;
                    }
                }
            }
        }
    });
    let mut harness = DaBitHarness::with_tamper(4, 1, 0x0DAB_0043, Some(tamper));
    // 13 bits: the last byte has three unused high bits.
    let errors = expect_all_err(harness.generate_within(13, ABORT_TIMEOUT).await);
    assert!(
        matches!(errors[1], DaBitError::InvalidDealing(_)),
        "got {:?}",
        errors[1]
    );
}

/// Adds one to every field element an opening message carries, whichever shape it has.
fn corrupt_opening(msg: &mut BatchReconMsg) {
    use ark_ff::One;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    let mut out = Vec::new();
    match msg.msg_type {
        BatchReconMsgType::Eval | BatchReconMsgType::Reveal => {
            let value = F::deserialize_compressed(msg.payload.as_slice()).expect("element");
            (value + F::one()).serialize_compressed(&mut out).unwrap();
        }
        BatchReconMsgType::EvalBatch | BatchReconMsgType::RevealBatch => {
            let values = Vec::<F>::deserialize_compressed(msg.payload.as_slice()).expect("batch");
            let values: Vec<F> = values.into_iter().map(|v| v + F::one()).collect();
            values.serialize_compressed(&mut out).unwrap();
        }
    }
    msg.payload = out;
}

/// **A party lies inside the XOR fold.** The fold's products are opened at degree `2t`, where a
/// shifted share would shift the product — and with it the arithmetic half, leaving a daBit that
/// is one bit in `K` and something else in `F`. At `n = 3t + 1` that opening has no slack: every
/// share must lie on one polynomial, so the lie is a detected abort, never an accepted value.
///
/// The assertion is deliberately two-sided: either a party errors, or what it output is still a
/// correct daBit. What must never happen is a party holding an inconsistent one.
async fn a_lie_in_the_xor_fold_never_yields_a_wrong_dabit(n: usize, t: usize, liar: usize) {
    let open_tamper: OpenTamper = Arc::new(move |_recipient, msg| {
        if msg.sender_id == liar {
            corrupt_opening(msg);
        }
    });
    let mut harness = DaBitHarness::with_tampers(n, t, 0x0DAB_0060, None, Some(open_tamper));
    let results = harness.generate_within(16, ABORT_TIMEOUT).await;

    let honest: Vec<usize> = (0..n).filter(|p| *p != liar).collect();
    let finished: Vec<usize> = honest
        .iter()
        .copied()
        .filter(|p| results[*p].is_ok())
        .collect();
    assert!(
        finished.is_empty(),
        "at n = 3t + 1 a degree-2t opening with one wrong share must not complete, but parties \
         {finished:?} accepted it"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lie_in_the_xor_fold_aborts_n4_t1() {
    setup_tracing();
    a_lie_in_the_xor_fold_never_yields_a_wrong_dabit(4, 1, 3).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lie_in_the_xor_fold_aborts_n7_t2() {
    setup_tracing();
    a_lie_in_the_xor_fold_never_yields_a_wrong_dabit(7, 2, 0).await;
}

/// A failed batch leaves nothing resident, so the next one is not starved of session slots.
#[tokio::test(flavor = "multi_thread")]
async fn an_aborted_batch_retires_its_sessions_and_the_next_batch_succeeds() {
    setup_tracing();
    let armed = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let flag = Arc::clone(&armed);
    let tamper: Tamper = Arc::new(move |recipient, msg| {
        if flag.load(std::sync::atomic::Ordering::SeqCst) && recipient == 2 && msg.sender_id == 0 {
            if let DaBitPayload::Deal { sets, .. } = &mut msg.payload {
                flip_first_bit(sets);
            }
        }
    });
    let mut harness = DaBitHarness::with_tamper(4, 1, 0x0DAB_0044, Some(tamper));
    expect_all_err(harness.generate_within(8, ABORT_TIMEOUT).await);
    for party in 0..4 {
        assert_eq!(harness.node(party).store_len().await, 0, "party {party}");
        assert_eq!(
            harness.node(party).dn07.store_len().await,
            0,
            "party {party}"
        );
    }

    armed.store(false, std::sync::atomic::Ordering::SeqCst);
    let batch = expect_all_ok(harness.generate(32).await);
    assert_same_bit_in_both_domains(&batch, 4, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn malformed_requests_are_refused_before_anything_is_sent() {
    setup_tracing();
    let mut harness = DaBitHarness::new(4, 1, 0x0DAB_0050);
    let errors = expect_all_err(harness.generate(0).await);
    assert!(matches!(errors[0], DaBitError::NotEnoughMaterial(_)));

    let too_many = harness.node(0).max_batch_size() + 1;
    let errors = expect_all_err(harness.generate(too_many).await);
    assert!(matches!(errors[0], DaBitError::BatchTooLarge { .. }));
}

/// `DaBit::new` is the only constructor, and it refuses the two pairings that would silently
/// produce a "daBit" of two unrelated bits: one that pairs this party's `F` share with another
/// party's `K` share, and one whose halves are not both at the protocol degree.
///
/// This is T1 at the type boundary rather than at the protocol boundary. It matters because a
/// mismatched pair is exactly what a confused-deputy message path would hand a consumer, and
/// nothing downstream of the constructor re-checks it.
#[test]
fn the_dabit_constructor_refuses_a_cross_domain_mispairing() {
    setup_tracing();
    let arith = RobustShare::new(F::from(1u64), 3, 2);
    let bin = GfShare::new(K::new(1), 3, 2);

    DaBit::new(arith.clone(), bin.clone(), 2).expect("a matched pair");

    let err = DaBit::new(arith.clone(), GfShare::new(K::new(1), 4, 2), 2)
        .expect_err("mismatched indices");
    assert!(matches!(&err, DaBitError::IdMismatch), "got {err:?}");

    let err = DaBit::new(RobustShare::new(F::from(1u64), 3, 3), bin.clone(), 2)
        .expect_err("arith degree above the threshold");
    assert!(matches!(&err, DaBitError::DegreeMismatch), "got {err:?}");

    let err = DaBit::new(arith, GfShare::new(K::new(1), 3, 3), 2)
        .expect_err("bin degree above the threshold");
    assert!(matches!(&err, DaBitError::DegreeMismatch), "got {err:?}");
}

// -------------------------------------------------------------------------------------------
// Negative controls
// -------------------------------------------------------------------------------------------

/// The assertions above are only worth their runtime if they fail on a broken daBit. Each case
/// here is something the real generator *cannot* produce — which is the argument for why the
/// certification protocols were deleted, and therefore exactly what has to be shown to still be
/// caught if a future construction reintroduced it.
///
/// The second case is the one that matters most. A degree-`t+1` sharing of the right bit passes
/// every other check in this file: both halves reconstruct, both are bits, they agree, and
/// `RobustShare::degree` says whatever the dealer wrote. Only interpolating from `t+1`-subsets
/// separates it — which is the plan's §5 point that share *form* cannot be established by
/// comparing metadata.
#[test]
fn the_contract_assertions_fail_when_the_contract_is_broken() {
    setup_tracing();
    let mut rng = StdRng::seed_from_u64(0x0DAB_0070);

    // 1. The two halves are different bits.
    let batch = deal_dabits(&[(0, 1)], 10, 3, &mut rng);
    let err = catch_expected_panic(|| assert_same_bit_in_both_domains(&batch, 10, 3))
        .expect_err("halves that disagree must be caught");
    assert!(err.contains("not the same bit"), "got {err}");

    // 2. T3 in `F`: an arithmetic half that is not a bit at all.
    let batch = deal_dabits(&[(2, 0)], 10, 3, &mut rng);
    let err = catch_expected_panic(|| assert_same_bit_in_both_domains(&batch, 10, 3))
        .expect_err("a non-bit arithmetic half must be caught");
    assert!(err.contains("which is not a bit"), "got {err}");

    // 3. T2: degree `t+1`, the right bit in both domains. Every value-level check passes.
    let batch = deal_dabits(&[(1, 1)], 10, 4, &mut rng);
    assert_eq!(
        assert_same_bit_in_both_domains(&batch, 10, 3),
        vec![1],
        "a degree-t+1 sharing still reconstructs to the right bit: that is the point"
    );
    let err = catch_expected_panic(|| assert_degree_t_form(&batch, 10, 3))
        .expect_err("a degree-t+1 sharing must be caught by the form check");
    assert!(err.contains("is not a degree-3 polynomial"), "got {err}");

    // 4. A constant batch, and a heavily biased one.
    let err = catch_expected_panic(|| assert_bits_look_uniform(&[0u64; 64], "control"))
        .expect_err("a constant batch must be caught");
    assert!(err.contains("were constant"), "got {err}");

    let mut biased = [1u64; 64];
    biased[..4].fill(0);
    let err = catch_expected_panic(|| assert_bits_look_uniform(&biased, "control"))
        .expect_err("60 ones out of 64 must be caught");
    assert!(err.contains("four-sigma band"), "got {err}");
}
