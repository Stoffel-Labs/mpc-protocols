//! The daBit **contract**, end to end, at the two party counts a deployment is sized for.
//!
//! A daBit is the only object in this crate that ties the prime field and `GF(2^k)` together, and
//! it ties them *by value*. Everything downstream — A2B's mask, B2A's per-bit affine step, the
//! edaBit composition — is correct only if four things hold of every output:
//!
//! | | property | where it is checked |
//! |---|---|---|
//! | the tie | both halves reconstruct to **the same bit** | [`assert_same_bit_in_both_domains`] |
//! | T1 domain | both halves carry the holder's own party index, and nothing but that index crosses | same |
//! | T2 form | each half really is a polynomial of degree `<= t` | [`assert_degree_t_form`] |
//! | T3 value | the secret is a bit in `F` (`0`/`1`) and in `K` (`b^2 = b`) | [`assert_same_bit_in_both_domains`] |
//!
//! plus two properties of a *batch* rather than of one daBit: the bits are **uniform**, and two
//! batches drawn at different `exec_id`s are **independent**.
//!
//! The plan's §5 argues all of T1, T2 and T3 hold *by construction* and at zero certification
//! cost, precisely because no value is ever dealt. That argument is the reason there is no
//! bit-ness check, no bucketing and no cross-domain consistency protocol left to test — so these
//! tests are what stands in their place, and a deviation that reintroduced a dealt value would
//! show up here as a broken invariant rather than as a missing sub-protocol.
//!
//! # Phase: PREPROCESSING
//!
//! `PrssDaBitNode` is preprocessing. Its single opening is nevertheless degree-`t` and robust, so
//! no test in this file can reach a degree-`2t` opening, a timeout-driven abort or a broadcast.
//!
//! # Relationship to `prss_dabit_test.rs`
//!
//! That file exercises the *generator*: the honest run at `n = 4 / 7 / 10`, a corrupt opener, and
//! the `beta`/`psi` keystream separation. This file exercises the *object* and the *budget*, and
//! adds the `n = 13, t = 4` party count, the `t+1`-subset form check, the uniformity band, the
//! cross-batch independence check and the lifetime leak budget. The two overlap only in the
//! honest `n = 10` run, which both need as a base.
//!
//! # What is dealt
//!
//! The PRSS key family and the `RandBit`s, for the reasons given in
//! [`crate::utils::dabit_utils`]. Everything the daBit protocol itself does is real.

mod utils;

use stoffelcrypto::honeybadger::{
    dabit::{
        prss_dabit::{DaBitLeakBudget, PrssDaBitNode},
        DaBit, DaBitError, EdaBit,
    },
    MIN_STATISTICAL_SECURITY,
};

use crate::utils::dabit_utils::{
    assert_bits_look_uniform, assert_degree_t_form, assert_same_bit_in_both_domains, deal_dabits,
    deal_rand_bits, expect_all_err, expect_all_ok, hamming, DaBitHarness, F, K,
};
use crate::utils::test_utils::{catch_expected_panic, setup_tracing};

use ark_ff::PrimeField;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use num_bigint::BigUint;
use stoffelcrypto::common::{gf2k::share::GfShare, SecretSharingScheme};
use stoffelcrypto::honeybadger::robust_interpolate::robust_interpolate::RobustShare;

// -------------------------------------------------------------------------------------------
// The contract, end to end
// -------------------------------------------------------------------------------------------

/// `n = 10, t = 3`: `C(10,3) = 120`, `ceil = 7`, so the production default is `k = 4` and each
/// daBit bills five `RandBit`s.
#[tokio::test(flavor = "multi_thread")]
async fn dabits_are_one_bit_in_two_domains_n10_t3() {
    setup_tracing();
    let mut harness = DaBitHarness::new(10, 3, None, MIN_STATISTICAL_SECURITY, 0x0DAB_0010);
    assert_eq!(harness.node(0).rand_bits_per_dabit(), 5);

    let batch = expect_all_ok(harness.generate(64).await);
    let bits = assert_same_bit_in_both_domains(&batch, 10, 3);
    assert_degree_t_form(&batch, 10, 3);
    assert_bits_look_uniform(&bits, "n=10 t=3");
}

/// `n = 13, t = 4`: `C(13,4) = 715`, `ceil = 10`, default `k = 7`, eight `RandBit`s per daBit —
/// and `C(12,4) = 495` PRF streams per party per call, which is the largest PRSS load this
/// construction supports in practice.
#[tokio::test(flavor = "multi_thread")]
async fn dabits_are_one_bit_in_two_domains_n13_t4() {
    setup_tracing();
    let mut harness = DaBitHarness::new(13, 4, None, MIN_STATISTICAL_SECURITY, 0x0DAB_0013);
    assert_eq!(harness.node(0).rand_bits_per_dabit(), 8);

    let batch = expect_all_ok(harness.generate(48).await);
    let bits = assert_same_bit_in_both_domains(&batch, 13, 4);
    assert_degree_t_form(&batch, 13, 4);
    assert_bits_look_uniform(&bits, "n=13 t=4");
}

/// Two batches from the same nodes at **different `exec_id`s** must be independent.
///
/// The `exec_id` is the high half of the PRSS position. If it failed to reach the derivation — a
/// rewound cursor, or a session id assembled without it — the two batches would be bit-identical
/// while every other test in this file still passed, and the adversary, who knows every `beta_T`
/// but its own, would learn `x XOR x'` for every pair of values the two batches masked. That is
/// the VERIA-222 class and it is one of the three errors the plan flags as otherwise silent.
///
/// The band is generous on purpose: what is being caught is `0` (identical) or `count`
/// (complementary), not a subtle bias.
#[tokio::test(flavor = "multi_thread")]
async fn two_batches_at_different_exec_ids_are_independent() {
    setup_tracing();
    let mut harness = DaBitHarness::new(10, 3, None, MIN_STATISTICAL_SECURITY, 0x0DAB_0020);

    let first = expect_all_ok(harness.generate(64).await);
    let second = expect_all_ok(harness.generate(64).await);

    let a = assert_same_bit_in_both_domains(&first, 10, 3);
    let b = assert_same_bit_in_both_domains(&second, 10, 3);
    assert_bits_look_uniform(&a, "batch 1");
    assert_bits_look_uniform(&b, "batch 2");

    let distance = hamming(&a, &b);
    assert!(
        distance > 0,
        "two batches at different exec ids produced identical bits: the exec id is not reaching \
         the PRSS position"
    );
    // 5 sigma of Binomial(64, 1/2): sigma = 4, so [12, 52].
    assert!(
        (12..=52).contains(&distance),
        "two independent 64-bit batches differed in {distance} positions, which is outside a \
         five-sigma band around 32"
    );
    assert_eq!(harness.produced().await, 128, "lifetime counter");
}

/// The composed edaBit — the object A2B actually consumes — inherits the daBits' tie.
///
/// `EdaBit::compose` is purely local: `[r]_F = sum 2^i [b_i]_F`, with the binary halves carried
/// through unchanged. What has to hold afterwards is that the arithmetic share is the *integer*
/// `sum 2^i b_i`, which is only true if every `[b_i]_F` really was the same bit as `[b_i]_K` and
/// carried the right weight. A daBit whose two halves had drifted apart would still compose
/// without error and would still reconstruct to *some* field element — it would just not be the
/// integer the bits spell out.
#[tokio::test(flavor = "multi_thread")]
async fn an_edabit_composed_from_dabits_is_the_integer_its_bits_spell() {
    setup_tracing();
    const WIDTH: usize = 32;
    let mut harness = DaBitHarness::new(10, 3, None, MIN_STATISTICAL_SECURITY, 0x0DAB_0030);

    let batch = expect_all_ok(harness.generate(WIDTH).await);
    let bits = assert_same_bit_in_both_domains(&batch, 10, 3);

    let composed: Vec<EdaBit<F, K>> = batch
        .iter()
        .map(|dabits| EdaBit::compose(dabits, WIDTH).expect("edaBit composition"))
        .collect();

    // The binary halves ride through untouched — the composition is arithmetic-side only.
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
    let (_, value) = RobustShare::recover_secret(&value_shares, 10, 3).expect("value");

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
    // `width < 64` is the branch that needs no `r < p` filter: the sum cannot reach the modulus.
    let modulus: BigUint = F::MODULUS.into();
    assert!(BigUint::from(expected) < modulus);
}

// -------------------------------------------------------------------------------------------
// The `k` knob and the lifetime leak budget
// -------------------------------------------------------------------------------------------

/// `k` prices three things at once, and they must move together: the `RandBit` bill `1 + k`, the
/// per-daBit leak `2^-(lambda+k+1)`, and the lifetime cap `Q = 2^(lambda+k+1-kappa)`.
///
/// `lambda` and `k` are one budget — both follow from the single no-wrap inequality — so a `k`
/// raised without re-deriving `lambda` would let `S + 2r'' + r'_0` wrap `p`, and `p` is odd, so a
/// wrap flips the extracted bit. The implementation evaluates that inequality rather than assuming
/// it; this checks the knob's *observable* consequences at the two party counts of this file,
/// including that the one value above the admissible range is refused rather than clamped.
#[test]
fn the_k_knob_prices_the_randbit_bill_and_the_lifetime_budget() {
    setup_tracing();
    type Node = PrssDaBitNode<F, K>;

    // (n, t, lambda, ceil(log2 C(n,t)), default k)
    for (n, t, lambda, ceil, default_k) in [
        (10usize, 3usize, 55usize, 7usize, 4usize),
        (13, 4, 52, 10, 7),
    ] {
        let mut previous_budget = 0u64;
        for k in 0..=ceil - 1 {
            let node = Node::new(0, n, t, MIN_STATISTICAL_SECURITY, Some(k))
                .unwrap_or_else(|e| panic!("n={n} k={k}: {e:?}"));
            let budget = node.budget;

            assert_eq!(budget.mask_bits, lambda, "lambda at n={n}");
            assert_eq!(budget.set_bits, ceil, "ceil(log2 C) at n={n}");
            assert_eq!(budget.topup_bits, k);
            assert_eq!(
                budget.leak_exponent(),
                lambda + k + 1,
                "leak at n={n} k={k}"
            );
            assert_eq!(node.rand_bits_per_dabit(), 1 + k, "bill at n={n} k={k}");
            assert_eq!(
                budget.max_dabits,
                1u64 << (lambda + k + 1 - MIN_STATISTICAL_SECURITY),
                "Q at n={n} k={k}"
            );
            assert!(
                budget.max_dabits > previous_budget,
                "Q did not grow from k={} to k={k} at n={n}",
                k.saturating_sub(1)
            );
            previous_budget = budget.max_dabits;
        }

        // The default is `ceil - 3`, which is what buys `Q >= 2^20` at every supported n.
        let node = Node::new(0, n, t, MIN_STATISTICAL_SECURITY, None).expect("default k");
        assert_eq!(node.budget.topup_bits, default_k, "default k at n={n}");
        assert!(
            node.budget.max_dabits >= 1 << 20,
            "default k at n={n} buys only {} daBits",
            node.budget.max_dabits
        );

        // One past the admissible range is a hard error, never a clamp.
        let err = Node::new(0, n, t, MIN_STATISTICAL_SECURITY, Some(ceil))
            .expect_err("k = ceil must be refused");
        assert!(
            matches!(&err, DaBitError::TopUpTooLarge { requested, max } if *requested == ceil && *max == ceil - 1),
            "n={n}: expected TopUpTooLarge, got {err:?}"
        );
    }
}

/// `kappa` above `lambda + k + 1` admits no positive number of daBits, and that is a construction
/// error rather than a node that silently produces none.
#[test]
fn a_budget_that_admits_no_dabits_is_refused_at_construction() {
    setup_tracing();
    // n = 10: lambda = 55, k = 0, so the leak exponent is 56.
    let err = DaBitLeakBudget::new::<F>(10, 3, 56, Some(0)).expect_err("kappa = 56 at n=10");
    assert!(
        matches!(
            err,
            DaBitError::LeakBudgetUnreachable {
                leak_exponent: 56,
                statistical_security: 56
            }
        ),
        "expected LeakBudgetUnreachable, got {err:?}"
    );
    // One below is the smallest reachable budget, `Q = 2`.
    let budget = DaBitLeakBudget::new::<F>(10, 3, 55, Some(0)).expect("kappa = 55 at n=10");
    assert_eq!(budget.max_dabits, 2);
}

/// The lifetime budget is **enforced**, and running past it is a clean typed error rather than a
/// wrap.
///
/// The cap is not hygiene: past `Q` the union bound `Q * 2^-(lambda+k+1)` on the per-daBit Mod2
/// leak exceeds the configured `kappa`, so the node has spent its whole privacy argument and the
/// fix is a re-key or a larger `k`, not another batch. A counter that wrapped, saturated, or was
/// rolled back on failure would keep producing daBits that are no longer covered by any bound —
/// and nothing downstream would notice, because the daBits themselves stay perfectly correct.
///
/// `kappa = 55` at `n = 10, k = 0` gives `Q = 2`, which is the only way to reach the cap inside a
/// test: at the minimum `kappa = 40` the smallest budget any supported party count admits is
/// `2^13`.
#[tokio::test(flavor = "multi_thread")]
async fn the_lifetime_budget_is_enforced_and_exhaustion_is_a_clean_error() {
    setup_tracing();
    let mut harness = DaBitHarness::new(10, 3, Some(0), 55, 0x0DAB_0040);
    assert_eq!(harness.node(0).budget.max_dabits, 2);
    assert_eq!(harness.node(0).remaining_budget().await, 2);

    // Spend the budget exactly.
    let first = expect_all_ok(harness.generate(1).await);
    assert_same_bit_in_both_domains(&first, 10, 3);
    assert_eq!(harness.produced().await, 1);
    assert_eq!(harness.node(0).remaining_budget().await, 1);

    let second = expect_all_ok(harness.generate(1).await);
    assert_same_bit_in_both_domains(&second, 10, 3);
    assert_eq!(harness.produced().await, 2);
    assert_eq!(harness.node(0).remaining_budget().await, 0);

    // Past it: a typed error from every party, not a wrap, not a panic, not a short batch.
    for attempt in 3..=4u64 {
        let errors = expect_all_err(harness.generate(1).await);
        for (party, err) in errors.iter().enumerate() {
            assert!(
                matches!(
                    err,
                    DaBitError::LeakBudgetExhausted {
                        produced: 2,
                        requested: 1,
                        budget: 2
                    }
                ),
                "party {party} attempt {attempt}: expected LeakBudgetExhausted, got {err:?}"
            );
        }
        // The counter is pinned, not advanced and not wrapped, by a refused call.
        assert_eq!(
            harness.produced().await,
            2,
            "after refused attempt {attempt}"
        );
        assert_eq!(harness.node(0).remaining_budget().await, 0);
    }

    // No session was left resident by either the spent batches or the refusals.
    for party in 0..10 {
        assert_eq!(
            harness.node(party).store_len().await,
            0,
            "party {party} left a Mod2 session behind"
        );
    }
}

/// A batch larger than what is left of the budget is refused **whole**, and the refusal costs
/// nothing.
///
/// Half a batch would be worse than none: the caller would have to know which daBits it got, and
/// the ones it did get would already be outside the bound. And a refusal that still charged the
/// budget would let an over-large request burn a node's remaining capacity without producing
/// anything — a free denial of service against every later caller.
#[tokio::test(flavor = "multi_thread")]
async fn an_over_budget_batch_is_refused_whole_and_costs_nothing() {
    setup_tracing();
    let mut harness = DaBitHarness::new(10, 3, Some(0), 55, 0x0DAB_0050);
    assert_eq!(harness.node(0).budget.max_dabits, 2);

    let errors = expect_all_err(harness.generate(3).await);
    for (party, err) in errors.iter().enumerate() {
        assert!(
            matches!(
                err,
                DaBitError::LeakBudgetExhausted {
                    produced: 0,
                    requested: 3,
                    budget: 2
                }
            ),
            "party {party}: expected LeakBudgetExhausted, got {err:?}"
        );
    }
    assert_eq!(
        harness.produced().await,
        0,
        "a refused batch charged the budget"
    );

    // The budget really is intact: the whole of it is still spendable afterwards.
    let batch = expect_all_ok(harness.generate(2).await);
    let bits = assert_same_bit_in_both_domains(&batch, 10, 3);
    assert_eq!(bits.len(), 2);
    assert_eq!(harness.produced().await, 2);
}

/// The `RandBit` bill is checked for **exact** length, in both directions, before the budget is
/// touched.
///
/// A short bill is a caller bug; a long one is worse, because the surplus `RandBit`s are silently
/// dropped here while the caller still believes they are unused — and the next thing that hands
/// them out reuses a one-time pad. Neither may charge the leak budget, since neither derives
/// anything.
#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_length_randbit_bill_is_refused_without_charging_the_budget() {
    setup_tracing();
    const COUNT: usize = 4;
    let mut harness = DaBitHarness::new(10, 3, Some(0), MIN_STATISTICAL_SECURITY, 0x0DAB_0060);
    // `k = 0`, so the bill is exactly one RandBit per daBit.
    assert_eq!(harness.node(0).rand_bits_per_dabit(), 1);

    let mut rng = StdRng::seed_from_u64(0x0DAB_0061);
    // A fresh `exec_id` per attempt even though a refused call derives nothing: the PRSS position
    // is burned by the attempt, not by the success, and a test that modelled it the other way
    // would be documenting the cursor rewind the implementation forbids.
    for supplied in [COUNT - 1, COUNT + 1] {
        let bits = deal_rand_bits(supplied, 10, 3, &mut rng);
        let errors = expect_all_err(harness.generate_with(COUNT, bits).await);
        for (party, err) in errors.iter().enumerate() {
            assert!(
                matches!(
                    err,
                    DaBitError::MaterialLengthMismatch {
                        what: "dabit rand bits",
                        expected: COUNT,
                        got
                    } if *got == supplied
                ),
                "party {party} with {supplied} RandBits: expected MaterialLengthMismatch, got {err:?}"
            );
        }
        assert_eq!(
            harness.produced().await,
            0,
            "a refused bill of {supplied} RandBits charged the leak budget"
        );
    }

    // The exact bill still works afterwards.
    let bits = deal_rand_bits(COUNT, 10, 3, &mut rng);
    let batch = expect_all_ok(harness.generate_with(COUNT, bits).await);
    assert_eq!(assert_same_bit_in_both_domains(&batch, 10, 3).len(), COUNT);
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
