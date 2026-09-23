//! PRSS daBits via `Mod2` — doubly-shared bits with **no dealing, no multiplication and no
//! soundness error**.
//!
//! # The algebra
//!
//! Let `T` range over the `C(n,t)` maximal unqualified sets and let party `i` hold the CDI05 key
//! `k_T` exactly when `i ∉ T`. For each daBit index `ν`, derive **one** pseudorandom bit per set:
//!
//! ```text
//! β_T  =  derive_ints_at(k_T, sid_beta, ν, 1, bits = 1)
//! ```
//!
//! `derive_ints_at` is field-independent, so both domains consume the *same bytes* and the
//! "derivation-label split" failure mode is structurally impossible rather than a discipline
//! requirement. One derivation, two conversions:
//!
//! ```text
//! F side:   [S]_F  =  Σ_{T ∌ i}  β_T · f_T(x_i)        secret S = Σ_T β_T  over the INTEGERS
//! K side:   [b]_K  =  Σ_{T ∌ i}  β_T · f^K_T(x^K_i)    secret   = ⊕_T β_T  =  S mod 2
//! ```
//!
//! Both are **0 rounds and 0 bytes**. `C(n,t)` is far below `p`, so the `F` secret really is the
//! integer `S`; and in characteristic 2 the replicated-to-Shamir sum *is* an XOR, so the `K`
//! secret really is the parity. The two agree modulo 2 by *arithmetic*, not by protocol.
//!
//! The cross-domain tie is then a single-domain parity extraction, which is one
//! [`Mod2`](crate::honeybadger::mod2) opening:
//!
//! ```text
//! [c]   = [S]_F + 2·[r'']_F + [r'_0]_F     local
//! c     = Open_t([c])                       ONE degree-t batched opening, robust
//! [b]_F = (c mod 2) XOR [r'_0]_F            local, public-affine
//! ```
//!
//! This does **not** contradict the cross-domain impossibility result: no share is converted
//! locally between the domains. What is shared between them is the *seed*, and the two
//! conversions of a seed are each linear in their own field.
//!
//! # Phase: PREPROCESSING
//!
//! Synchronous, abort permitted. Two of the three moving parts are local, and the third (Mod2) is
//! a **degree-`t`, robust, abort-free** opening — so this protocol puts nothing on the online path
//! and could not smuggle a degree-`2t` opening there even by accident (see
//! [`Mod2Node::new`](crate::honeybadger::mod2::mod2::Mod2Node::new), which pins its child's
//! degree).
//!
//! The one place abort enters is the `RandBit`s this node **consumes**: `RandBit` rides `MulPub`'s
//! degree-`2t` opening, which is detect-with-probability-1 and aborts on a bad share. That is the
//! only abort trigger in the whole construction, and it is inherited from a pre-existing
//! preprocessing primitive rather than introduced here.
//!
//! # Share-type soundness — T1, T2 and T3 are free
//!
//! | Obligation | How it is discharged | Cost |
//! |---|---|---|
//! | **T1 domain** | Vacuous. Both halves come from one protocol step over one `derive_ints_at` call; "is this arithmetic or binary?" never arises, because it is both, tied by value. | 0 |
//! | **T2 form**, `[S]_F` / `[b]_K` | By construction. A PRSS share is a deterministic function of keys held by `n − t >= 2t+1` parties, and `Σ_T β_T f_T` has degree exactly `t` because each `f_T` does. A corrupt party cannot emit a malformed sharing; its only freedom is to lie at an opening, which the degree-`t` code's distance `2t+1` corrects. | 0 |
//! | **T2 form**, `[b]_F` | By provenance: `c_0 + (1−2c_0)[r'_0]` is a public-affine image of a `RandBit` sharing, and `from_scalar_sub` preserves `id` and `degree`. | 0 |
//! | **T3 value**, `b ∈ {0,1}` in `K` | Structural: `β_T ∈ GF(2) ⊆ K`, and `GF(2)` is closed under `+` in characteristic 2, so `⊕_T β_T` is a bit *as a field element*. | 0 |
//! | **T3 value**, `b ∈ {0,1}` in `F` | By provenance: `b = c_0 ⊕ r'_0` with `c_0` a **public** bit — agreed, because `c` was robustly opened — and `r'_0` a `RandBit`, whose bit-ness is itself free (`b = (a/√(a²)+1)/2`). | 0 |
//!
//! **There is no dealt value anywhere in this path**, which is what makes all three free. Any
//! variant that reintroduces one loses all three at once and must add certification back.
//!
//! # The three implementation errors that would be silent
//!
//! None of these is detectable by an all-honest test suite. Each is guarded here.
//!
//! 1. **`β`/`ψ` PRF-stream collision.** If the daBit seeds and the Mod2 mask were drawn from the
//!    same `(key, context, position)`, `ψ_A`'s low bit would equal `β_A`, giving
//!    `V = 3β_A + 4κ + r'_0`, and `V mod 4` would reveal the daBit with probability ~3/4. The two
//!    draws here take **distinct `SessionId`s** — `sub_id = 0` for `β`,
//!    [`PSI_SUB_ID`] for `ψ` — which lands in `prss::context_bytes`' `ctx[13]` and makes them
//!    independent keystreams. One byte to get wrong, catastrophic to miss.
//! 2. **A rewound PRSS cursor.** Two daBits drawn from the same position share the same unknown
//!    `β_A`; it cancels in their difference and the adversary learns `x ⊕ x'`. Positions here are
//!    addressed by `(session exec_id, index in batch)` and the exec id comes from a monotone
//!    counter that is advanced **before** the batch runs and never rolled back on failure — so a
//!    retry burns its range rather than rewinding it. This is the VERIA-222 class.
//! 3. **A one-dimensional PRZS.** Not reachable from this module: nothing here draws a zero
//!    sharing. It is guarded where it lives, in [`przs`](crate::honeybadger::przs).
//!
//! # What was deleted, and why the replacement is sound without it
//!
//! This replaces the dealt daBit protocol (`dabit_gen.rs`, 3 383 lines) in its entirety: masked
//! dealing, the XOR fold over a dealer set, the per-candidate exact-zero bit-ness checks in both
//! domains, the single-use coin, the Fisher–Yates permutation, the bucketed cross-domain check,
//! per-bucket containment and the dealer-exclusion state machine. Every one of those existed to
//! certify a *dealt* value; with nothing dealt, all of them are vacuous. The bucketing soundness
//! error `M^-(B-1) = 2^-44` becomes **0**, and `DaBitError::BatchTooSmall` / `BucketTooSmall` go
//! with the parameters they policed.
//!
//! What it costs instead is stated in [`DaBitLeakBudget`]: computational rather than perfect
//! privacy of the preprocessing randomness, under the same HMAC-SHA256 PRF `PRandInt` already
//! assumes, plus a quantified statistical leak of `2^-(λ+k+1)` per daBit that imposes a **lifetime
//! budget** on how many daBits a node may ever produce.

use std::sync::Arc;

use ark_ff::PrimeField;
use num_bigint::BigUint;
use stoffelnet::network_utils::{Network, PartyId};
use tokio::sync::Mutex;
use tokio::time::Duration;
use tracing::warn;

use crate::common::gf2k::field::BinaryField;
use crate::common::ProtocolSessionId;
use crate::honeybadger::dabit::{DaBit, DaBitError};
use crate::honeybadger::gf_prss::gf_prss::GfPrssKeys;
use crate::honeybadger::mod2::mod2::Mod2Node;
use crate::honeybadger::prss::prss::{binomial, PrssKeys};
use crate::honeybadger::prss::DaBitWindows;
use crate::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use crate::honeybadger::{ProtocolType, SessionId, MIN_STATISTICAL_SECURITY};

/// `sub_id` the Mod2 mask `ψ` is derived under.
///
/// **Not** a real session: no store is ever admitted at this id. It exists solely to land a
/// different byte in `prss::context_bytes`' `ctx[13]` than the daBit seeds `β`, which are drawn
/// under the parent session's own `sub_id = 0`. That one byte is the difference between two
/// independent keystreams and two streams whose low bits are equal — see the module docs.
pub const PSI_SUB_ID: u8 = 1;

/// Largest `C(n, t)` this module will work with.
///
/// PRSS spends one PRF stream per held key per call (`C(n-1,t)`: 3 / 15 / 84 / 495 / 3003 at
/// `n = 4 / 7 / 10 / 13 / 16` with `n = 3t+1`), so the useful range ends well below this. The cap
/// exists so a mis-parameterised caller gets an error rather than an unbounded computation.
///
/// The same number as every other store over this key family, because it *is* that number:
/// widened from [`prss::MAX_UNQUALIFIED_SETS`](crate::honeybadger::prss::MAX_UNQUALIFIED_SETS)
/// rather than restated. The widening is load-bearing here — this module compares it against a
/// `u128` count and then takes `ceil_log2` of that count to size `lambda`, so the comparison must
/// not be the thing that truncates.
pub const MAX_UNQUALIFIED_SETS: u128 = crate::honeybadger::prss::MAX_UNQUALIFIED_SETS as u128;

/// `ceil(log2 v)`, with `ceil(log2 0) = ceil(log2 1) = 0`.
fn ceil_log2(v: u128) -> usize {
    if v <= 1 {
        0
    } else {
        (u128::BITS - (v - 1).leading_zeros()) as usize
    }
}

/// The Mod2 mask width `λ`, the `RandBit` top-up `k`, and the lifetime daBit budget `Q` they imply.
///
/// # Derivation
///
/// Write `C = C(n,t)` and `ceil = ceil(log2 C)`. The mask is
///
/// ```text
/// [r'']_F  =  PrssKeys::shares_at(sid_psi, ν, 1, bits = λ)      Σ_T ψ_T,  ψ_T ∈ [0, 2^λ)
///           +  2^λ · Σ_{i<k} 2^i [rb_i]_F                        k extra RandBits
/// ```
///
/// with `λ = MODULUS_BIT_SIZE − 2 − ceil` and `0 <= k <= ceil − 1`.
///
/// **No wrap.** The Mod2 opening is an integer identity only while
/// `C + 1 + 2^(λ+1)·(C + 2^k − 1) < p`. `p` is odd, so a single wrap flips the extracted bit —
/// this is a *correctness* condition, not a tightness preference. It is not merely asserted from
/// the formula: [`DaBitLeakBudget::new`] evaluates it over `BigUint` against the actual modulus
/// and hard-errors if it fails.
///
/// **Leak.** The adversary `A` (`|A| = t`, itself a maximal unqualified set) holds `k_T` for every
/// `T != A` — since `|A| = |T| = t`, `A ⊆ T` iff `T = A` — so it knows `S − β_A` and
/// `Σ_{T!=A} ψ_T` exactly, and its own `t` evaluations of `φ_{r'_0}`. The opened `c` reveals the
/// whole degree-`t` polynomial `φ_c`; writing `φ_c = K(X) + α·f_A(X) + φ_{r'_0}(X)`, the
/// adversary's own evaluations already pin `φ_{r'_0}|_A` (because `f_A|_A = 0`), so exactly **one**
/// new scalar comes out:
///
/// ```text
/// V = β_A + r'_0 + 2ψ_A + 2^(λ+1)·R
/// ```
///
/// `r'_0 + 2ψ_A + 2^(λ+1)R` is uniform on `[0, 2^(λ+k+1))`, so the two hypotheses `β_A ∈ {0,1}`
/// give uniform distributions on `M = 2^(λ+k+1)` consecutive integers offset by one, and
/// `Δ = 1/M = 2^-(λ+k+1)` **exactly**. Over `Q` daBits the union bound is `Q · 2^-(λ+k+1)`, so a
/// `2^-κ` budget caps the node's **lifetime** output at `Q = 2^(λ+k+1−κ)`.
///
/// ```text
///                            n=4      n=7     n=10     n=13
///   C(n,t)                     4       21      120      715
///   λ = 62 − ceil             60       57       55       52
///   Q at k = 0              2^21     2^18     2^16     2^13
///   default k = ceil − 3       0        2        4        7
///   Q at the default k      2^21     2^20     2^20     2^20
///   max k = ceil − 1           1        4        6        9
///   Q at max k              2^22     2^22     2^22     2^22
/// ```
///
/// The top-up works because a `RandBit` carries **no** `C(n,t)` multiplicity: it adds one bit to
/// the *unknown* width and one bit to the *total* width, whereas widening the PRSS draw adds one
/// bit to the unknown width and `1 + ceil` to the total. It is ~10x cheaper than composing the
/// whole mask out of `RandBit`s.
///
/// # Reviewer's note
///
/// The `k` extension is the least-reviewed part of the plan this implements: the plan's own
/// "honest uncertainty" section records that no independent reviewer saw it, only the `k = 0`
/// case. Two consequences are handled defensively here rather than trusted:
///
/// * the no-wrap inequality is **evaluated**, not assumed, so a wrong `λ`/`k` pair fails at
///   construction rather than silently flipping bits;
/// * `k` and `λ` are one budget, and both are hard errors — never a `warn!`. This is the exact
///   `l`/`kappa` misconfiguration class this repo has already shipped once.
///
/// If the `k` derivation is wrong, the safe fallback is `k = 0`, whose `Q` column above stands on
/// its own (it is the `λ`-only leak, which *was* reviewed).
///
/// Three further things worth a second reader's eye, none of them papered over:
///
/// * **`k <= ceil - 1` is enforced ahead of the numeric check, not by it.** The no-wrap
///   inequality is the real constraint and it is evaluated below, so `ceil - 1` is a *derived*
///   bound rather than an axiom. Enforcing it first is deliberately conservative: it refuses a
///   `k` the inequality might in principle still admit, and it cannot admit one the inequality
///   rejects.
/// * **The leak derivation is stated for the worst case where the opening reveals the whole
///   degree-`t` polynomial.** This repo's batch reconstruction publishes only the secret, so the
///   real adversary learns no more than the analysis assumes.
/// * **The budget is per key family, not per process.** See [`PrssDaBitNode::produced`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DaBitLeakBudget {
    pub n_parties: usize,
    pub threshold: usize,
    /// `C(n, t)`, the number of maximal unqualified sets.
    pub unqualified_sets: u128,
    /// `ceil(log2 C(n,t))`.
    pub set_bits: usize,
    /// `λ`, the width of each per-set PRSS draw `ψ_T`.
    pub mask_bits: usize,
    /// `k`, the number of extra `RandBit`s folded into the mask above `2^λ`.
    pub topup_bits: usize,
    /// `κ`, the statistical-security budget the lifetime cap is derived against.
    pub statistical_security: usize,
    /// `Q = 2^(λ+k+1−κ)`, the **lifetime** number of daBits this parameterisation admits.
    pub max_dabits: u64,
}

impl DaBitLeakBudget {
    /// Derives `λ`, `k` and `Q` for `(n, t)` at statistical security `κ`.
    ///
    /// `topup_bits = None` takes the production default `k = ceil(log2 C(n,t)) − 3`, which buys
    /// `Q >= 2^20` daBits (16 384 full-width A2B conversions) at every party count this module
    /// supports. `Some(0)` is the minimum-cost setting and is correct for `n = 4` and for
    /// low-volume deployments.
    ///
    /// # Errors
    /// Every one of these is a hard error and none is a `warn!`.
    /// - [`DaBitError::DegenerateThreshold`] for `t == 0`, [`DaBitError::ThresholdOutOfRange`] for
    ///   `t >= n`.
    /// - [`DaBitError::InsufficientStatisticalSecurity`] below [`MIN_STATISTICAL_SECURITY`].
    /// - [`DaBitError::TooManyUnqualifiedSets`] above [`MAX_UNQUALIFIED_SETS`].
    /// - [`DaBitError::MaskWidthUnavailable`] if the field is too narrow to carry `λ >= 1`.
    /// - [`DaBitError::TopUpTooLarge`] for `k > ceil − 1`.
    /// - [`DaBitError::NoWrapViolated`] if the derived `(λ, k)` does not satisfy the integer
    ///   inequality against this field's actual modulus.
    /// - [`DaBitError::LeakBudgetUnreachable`] if `λ + k + 1 <= κ`, i.e. no positive number of
    ///   daBits fits the budget.
    pub fn new<F: PrimeField>(
        n_parties: usize,
        threshold: usize,
        statistical_security: usize,
        topup_bits: Option<usize>,
    ) -> Result<Self, DaBitError> {
        if threshold == 0 {
            return Err(DaBitError::DegenerateThreshold);
        }
        if threshold >= n_parties {
            return Err(DaBitError::ThresholdOutOfRange {
                n: n_parties,
                t: threshold,
            });
        }
        if statistical_security < MIN_STATISTICAL_SECURITY {
            return Err(DaBitError::InsufficientStatisticalSecurity {
                requested: statistical_security,
                minimum: MIN_STATISTICAL_SECURITY,
            });
        }

        let unqualified_sets =
            binomial(n_parties, threshold).ok_or(DaBitError::TooManyUnqualifiedSets {
                n: n_parties,
                t: threshold,
                max: MAX_UNQUALIFIED_SETS,
            })?;
        if unqualified_sets == 0 || unqualified_sets > MAX_UNQUALIFIED_SETS {
            return Err(DaBitError::TooManyUnqualifiedSets {
                n: n_parties,
                t: threshold,
                max: MAX_UNQUALIFIED_SETS,
            });
        }
        let set_bits = ceil_log2(unqualified_sets);

        // `− 2` rather than `− 1`: the no-wrap sum carries a `2^(λ+1)·C` term, which is already
        // `2^(λ+1+ceil)`, plus the top-up's `2^(λ+k+1) <= 2^(λ+ceil)`. Together they reach
        // `1.5 · 2^(MODULUS_BIT_SIZE−1)`, i.e. three quarters of the field, which is what leaves
        // the inequality below with room at every admissible `k`.
        let modulus_bits = F::MODULUS_BIT_SIZE as usize;
        let mask_bits = modulus_bits
            .checked_sub(2 + set_bits)
            .filter(|bits| *bits > 0)
            .ok_or(DaBitError::MaskWidthUnavailable {
                modulus_bits,
                set_bits,
            })?;

        let max_topup = set_bits.saturating_sub(1);
        let topup_bits = topup_bits.unwrap_or_else(|| set_bits.saturating_sub(3));
        if topup_bits > max_topup {
            return Err(DaBitError::TopUpTooLarge {
                requested: topup_bits,
                max: max_topup,
            });
        }

        // The no-wrap inequality, evaluated rather than assumed:
        //     C + 1 + 2^(λ+1) · (C + 2^k − 1)  <  p
        let one = BigUint::from(1u8);
        let c = BigUint::from(unqualified_sets);
        let lhs = &c + &one + ((&one << (mask_bits + 1)) * (&c + (&one << topup_bits) - &one));
        let modulus: BigUint = F::MODULUS.into();
        if lhs >= modulus {
            return Err(DaBitError::NoWrapViolated {
                mask_bits,
                topup_bits,
                set_bits,
            });
        }

        let leak_exponent = mask_bits + topup_bits + 1;
        let budget_exponent = leak_exponent
            .checked_sub(statistical_security)
            .filter(|e| *e > 0)
            .ok_or(DaBitError::LeakBudgetUnreachable {
                leak_exponent,
                statistical_security,
            })?;
        let max_dabits = if budget_exponent >= u64::BITS as usize {
            u64::MAX
        } else {
            1u64 << budget_exponent
        };

        Ok(Self {
            n_parties,
            threshold,
            unqualified_sets,
            set_bits,
            mask_bits,
            topup_bits,
            statistical_security,
            max_dabits,
        })
    }

    /// `RandBit`s one daBit consumes: `[r'_0]` plus the `k` top-up bits.
    pub fn rand_bits_per_dabit(&self) -> usize {
        1 + self.topup_bits
    }

    /// `λ + k + 1`, so that the per-daBit statistical distance is `2^-leak_exponent`.
    pub fn leak_exponent(&self) -> usize {
        self.mask_bits + self.topup_bits + 1
    }
}

/// The two PRSS key stores a PRSS daBit needs, cross-checked against each other.
///
/// The checks are not ceremony: the halves of a daBit are tied *only* by the two conversions
/// consuming the same `β_T`. Two stores built over different key families, ranks or thresholds
/// produce an `[S]_F` and a `[b]_K` of two **unrelated** bits, which is not a daBit at all, is not
/// detectable at the Mod2 opening (the opened `c` is simply a different perfectly valid value),
/// and yields silently wrong conversions downstream. Construction is the only place it can be
/// caught.
#[derive(Clone, Debug)]
pub struct PrssDaBitKeys<F: PrimeField, K: BinaryField> {
    prss: PrssKeys<F>,
    gf_prss: GfPrssKeys<K>,
}

impl<F: PrimeField, K: BinaryField> PrssDaBitKeys<F, K> {
    /// # Errors
    /// - [`DaBitError::KeyStoreMismatch`] if the two stores disagree on held-key count, or if the
    ///   `F` store's party index or threshold disagrees with the node's.
    pub fn new(
        id: PartyId,
        threshold: usize,
        prss: PrssKeys<F>,
        gf_prss: GfPrssKeys<K>,
    ) -> Result<Self, DaBitError> {
        if prss.id() != id {
            return Err(DaBitError::KeyStoreMismatch {
                what: "party index",
                left: prss.id(),
                right: id,
            });
        }
        if prss.threshold() != threshold {
            return Err(DaBitError::KeyStoreMismatch {
                what: "threshold",
                left: prss.threshold(),
                right: threshold,
            });
        }
        // `GfPrssKeys` exposes no `id`/`t` accessor, so its held-key count is the one thing that
        // can be cross-checked — and it is the thing that would differ if the two were built over
        // different `(n, t)`.
        if prss.len() != gf_prss.len() {
            return Err(DaBitError::KeyStoreMismatch {
                what: "held-key count",
                left: prss.len(),
                right: gf_prss.len(),
            });
        }
        Ok(Self { prss, gf_prss })
    }

    /// Keys held — `C(n-1, t)`, and the number of PRF streams one batch spends per domain.
    pub fn len(&self) -> usize {
        self.prss.len()
    }

    /// Never true for a store built by [`Self::new`]. Present because `len` without it is a
    /// clippy error under `-D warnings`.
    pub fn is_empty(&self) -> bool {
        self.prss.is_empty()
    }
}

/// Node producing daBits from PRSS seeds and one `Mod2` opening.
///
/// # Phase: PREPROCESSING
///
/// See the [module docs](self). The only network step is [`Mod2Node`]'s degree-`t` opening.
///
/// # One tag per owning node instance
///
/// The Mod2 child mints its batch-reconstruction session under
/// [`ProtocolType::DaBitOpen`](crate::honeybadger::ProtocolType::DaBitOpen) while the parent batch
/// is [`ProtocolType::DaBit`](crate::honeybadger::ProtocolType::DaBit), because the node
/// dispatcher demuxes `WrappedMessage::BatchRecon` on `calling_protocol()` alone.
#[derive(Clone, Debug)]
pub struct PrssDaBitNode<F: PrimeField, K: BinaryField> {
    pub id: PartyId,
    pub n_parties: usize,
    pub threshold: usize,
    /// `λ`, `k` and the lifetime cap `Q`, fixed at construction.
    pub budget: DaBitLeakBudget,
    /// The single opening. Pinned at degree `t`.
    pub mod2: Mod2Node<F>,
    /// `None` until `setup_prss_keys` has run. Every `generate` call fails loudly while it is,
    /// rather than falling back to anything.
    pub keys: Option<PrssDaBitKeys<F, K>>,
    /// daBits produced over this node's **lifetime**, against [`DaBitLeakBudget::max_dabits`].
    ///
    /// Advanced by `generate` *before* the batch runs and **never rolled back**: a failed batch
    /// has already derived (and possibly opened) its PRSS positions, so returning them to the
    /// budget would both under-count the leak and invite a cursor rewind.
    ///
    /// Shared across clones (`Arc`), so a cloned handle spends the same budget as the original.
    ///
    /// # The one thing this counter cannot see
    ///
    /// The budget is a property of the **key family**, not of this process. A node restarted with
    /// the *same* `k_T` would reset this counter to zero and spend `Q` a second time, doubling the
    /// leak. It is safe today only because nothing in this crate persists PRSS keys —
    /// `setup_prss_keys` re-runs RISS on every start, so a restart is a re-key. **If key
    /// persistence is ever added, this counter has to be persisted with it**, and the epoch
    /// ratchet (`k_T <- H("STOFFEL-PRSS-EPOCH" || k_T)`, zero communication) becomes mandatory
    /// rather than hygienic.
    produced: Arc<Mutex<u64>>,
}

impl<F: PrimeField, K: BinaryField> PrssDaBitNode<F, K> {
    /// # Errors
    /// - [`DaBitError::InvalidPartyId`] for `id >= n_parties`, or for `n_parties` above the number
    ///   of distinct evaluation points `K` has (`Gf256` addresses 255).
    /// - everything [`DaBitLeakBudget::new`] returns.
    /// - [`DaBitError::Mod2Error`] for a degenerate threshold or `n < 3t+1`.
    pub fn new(
        id: PartyId,
        n_parties: usize,
        threshold: usize,
        statistical_security: usize,
        topup_bits: Option<usize>,
    ) -> Result<Self, DaBitError> {
        if id >= n_parties {
            return Err(DaBitError::InvalidPartyId);
        }
        // The binary domain has only `K::MAX_DOMAIN_SIZE` distinct evaluation points, so a party
        // count above it cannot be shared in `K` at all.
        if n_parties > K::MAX_DOMAIN_SIZE {
            return Err(DaBitError::InvalidPartyId);
        }
        let budget =
            DaBitLeakBudget::new::<F>(n_parties, threshold, statistical_security, topup_bits)?;
        let mod2 = Mod2Node::<F>::new(id, n_parties, threshold)?;
        Ok(Self {
            id,
            n_parties,
            threshold,
            budget,
            mod2,
            keys: None,
            produced: Arc::new(Mutex::new(0)),
        })
    }

    /// Installs the PRSS key family. Idempotent replacement is deliberate: `setup_prss_keys` runs
    /// once and is a no-op afterwards.
    pub fn install_keys(&mut self, keys: PrssDaBitKeys<F, K>) {
        self.keys = Some(keys);
    }

    /// Whether [`Self::generate`] can run at all.
    pub fn has_keys(&self) -> bool {
        self.keys.is_some()
    }

    /// `RandBit`s one daBit consumes.
    pub fn rand_bits_per_dabit(&self) -> usize {
        self.budget.rand_bits_per_dabit()
    }

    /// Largest `count` one [`Self::generate`] call accepts — the Mod2 session's own ceiling.
    /// `lambda`, the Mod2 mask width, fixed at construction.
    ///
    /// Read by the caller so that [`PrssAllocator::claim_dabit_batch`] can pin
    /// [`PrssStream::DaBitPsi`]'s width on the first claim. The budget cannot change after
    /// construction, so the allocator's P2 guard will reject any later drift loudly rather than
    /// letting two widths address overlapping bytes on one keystream.
    pub fn mask_bits(&self) -> usize {
        self.budget.mask_bits
    }

    pub fn max_batch_size(&self) -> usize {
        self.mod2.max_batch_size()
    }

    /// daBits produced over this node's lifetime.
    pub async fn produced(&self) -> u64 {
        *self.produced.lock().await
    }

    /// daBits still inside the lifetime leak budget.
    pub async fn remaining_budget(&self) -> u64 {
        self.budget
            .max_dabits
            .saturating_sub(*self.produced.lock().await)
    }

    /// Number of live Mod2 sessions. Used by the node's preprocessing trace.
    pub async fn store_len(&self) -> usize {
        self.mod2.store_len().await
    }

    /// Retires the Mod2 session this batch minted. Safe to call twice.
    pub async fn clear_store(&self, session_id: SessionId) -> bool {
        match Self::mod2_session_id(session_id) {
            Ok(child) => self.mod2.clear_store(child).await,
            Err(_) => false,
        }
    }

    /// The Mod2 child session for a batch: same `exec_id`, its own tag.
    fn mod2_session_id(parent: SessionId) -> Result<SessionId, DaBitError> {
        if parent.calling_protocol() != Some(ProtocolType::DaBit)
            || parent.sub_id() != 0
            || parent.round_id() != 0
        {
            return Err(DaBitError::SessionIdError(parent));
        }
        Ok(SessionId::new(
            ProtocolType::DaBitOpen,
            SessionId::pack_slot(parent.exec_id(), 0, 0),
            parent.instance_id(),
        ))
    }

    /// Produces `count` daBits.
    ///
    /// This is a **driver**, in the shape `RandBit::init` already uses: it awaits its own child
    /// protocol, so it must not be polled on the task that pumps the network — the dispatcher's
    /// `process` / `drain_open_output` calls are what unblock it.
    ///
    /// `rand_bits` is `count * (1 + k)` degree-`t` bit sharings laid out per daBit as
    /// `[r'_0, rb_0, .., rb_{k-1}]`, drained from the node's shared pool in pool order — which is
    /// also what makes the material agree across parties.
    ///
    /// # Positions
    ///
    /// `windows` is one [`PrssAllocator::claim_dabit_batch`] claim: the `beta` window and the
    /// `psi` window on **one** `exec_id`, burned before this was called and never returned. There
    /// is no `count` parameter — the number of daBits is `windows.len()`, so deriving more than
    /// was claimed is not expressible. There is no `session_id` parameter either: the parent
    /// session is the seed window's own, which is what stops a caller minting an exec the
    /// allocator has not burned.
    ///
    /// Every exit path below — the budget check, the length checks, a failed Mod2 opening —
    /// leaves the claimed range **burned**. That is deliberate: rolling a cursor back on failure
    /// is precisely the rewind that re-derives an already-opened position.
    ///
    /// # Errors
    /// - [`DaBitError::PrssKeysMissing`] if `setup_prss_keys` has not run.
    /// - [`DaBitError::LeakBudgetExhausted`] when this batch would take the node past `Q`. This is
    ///   an error and never a silent wrap: past `Q` the union bound `Q · 2^-(λ+k+1)` exceeds the
    ///   configured `κ`, and the fix is a re-keyed node or a larger `k`, not another batch.
    /// - [`DaBitError::MaterialLengthMismatch`], [`DaBitError::BatchTooLarge`],
    ///   [`DaBitError::SessionIdError`], [`DaBitError::ZeroWidth`].
    pub async fn generate<N>(
        &mut self,
        windows: DaBitWindows,
        rand_bits: Vec<RobustShare<F>>,
        duration: Duration,
        network: Arc<N>,
    ) -> Result<Vec<DaBit<F, K>>, DaBitError>
    where
        N: Network + Send + Sync + 'static,
    {
        let session_id = windows.parent_session();
        let count = windows.len();
        let mod2_session = Self::mod2_session_id(session_id)?;

        if count > self.max_batch_size() {
            return Err(DaBitError::BatchTooLarge {
                requested: count,
                max: self.max_batch_size(),
            });
        }
        let per_dabit = self.budget.rand_bits_per_dabit();
        let expected_bits = count.checked_mul(per_dabit).ok_or(DaBitError::LimitError)?;
        // Exact, never `>=`: a surplus RandBit silently dropped here is a RandBit the caller
        // believes is still unused, i.e. one-time-pad reuse the next time it is handed out.
        if rand_bits.len() != expected_bits {
            return Err(DaBitError::MaterialLengthMismatch {
                what: "dabit rand bits",
                expected: expected_bits,
                got: rand_bits.len(),
            });
        }

        // Reserve against the lifetime leak budget *before* deriving anything, and never roll
        // back: the positions are burned by the attempt, not by the success.
        {
            let mut produced = self.produced.lock().await;
            let next = produced
                .checked_add(count as u64)
                .ok_or(DaBitError::LimitError)?;
            if next > self.budget.max_dabits {
                return Err(DaBitError::LeakBudgetExhausted {
                    produced: *produced,
                    requested: count,
                    budget: self.budget.max_dabits,
                });
            }
            *produced = next;
        }

        let keys = self.keys.as_ref().ok_or(DaBitError::PrssKeysMissing)?;

        // One derivation, two conversions. Both calls take the *same window*, and
        // `derive_ints_at` is field-independent, so they consume byte-identical `β_T`. That
        // aliasing is the daBit's whole trick and the one legitimate exception to invariant P.
        let value = keys.prss.shares_at_in(windows.seed())?;
        let bin = keys.gf_prss.bit_shares_at_in(windows.seed())?;
        // A different *keystream*, not a different position in the same one: `psi`'s window
        // differs from `beta`'s in `ctx[13]` (`PSI_SUB_ID`) and in `ctx[15]`
        // (`PrssDomain::DaBitPsi`). Two independent bytes, because the widths differ and a merge
        // would be a partial overlap that produces no equal value for a ledger to spot.
        let psi = keys.prss.shares_at_in(windows.psi())?;

        if value.len() != count || bin.len() != count || psi.len() != count {
            return Err(DaBitError::MaterialLengthMismatch {
                what: "prss draws",
                expected: count,
                got: value.len().min(bin.len()).min(psi.len()),
            });
        }

        // [r''] = Σ_T ψ_T + 2^λ · Σ_{i<k} 2^i [rb_i]
        let two = F::one() + F::one();
        let two_pow_lambda = F::from(BigUint::from(1u8) << self.budget.mask_bits);
        let mut masks = Vec::with_capacity(count);
        let mut zeroth_bits = Vec::with_capacity(count);
        for (nu, psi_nu) in psi.into_iter().enumerate() {
            let chunk = rand_bits.get(nu * per_dabit..(nu + 1) * per_dabit).ok_or(
                DaBitError::MaterialLengthMismatch {
                    what: "dabit rand bits",
                    expected: expected_bits,
                    got: rand_bits.len(),
                },
            )?;
            let (r0, topup) = chunk.split_first().ok_or(DaBitError::ZeroWidth)?;
            zeroth_bits.push(r0.clone());
            let mut mask = psi_nu;
            let mut weight = two_pow_lambda;
            for bit in topup {
                mask = (mask + (bit.clone() * weight)?)?;
                weight *= two;
            }
            masks.push(mask);
        }

        self.mod2
            .init(mod2_session, value, masks, zeroth_bits, network)
            .await?;
        let arith = self.mod2.wait_for_bits(mod2_session, duration).await;
        // Cleared on every exit path, before the `?`: a session abandoned mid-flight must not stay
        // resident just because an error would have skipped past the cleanup.
        if !self.mod2.clear_store(mod2_session).await {
            warn!(?mod2_session, "failed to clear Mod2 state");
        }
        let arith = arith?;

        if arith.len() != count {
            return Err(DaBitError::MaterialLengthMismatch {
                what: "mod2 output bits",
                expected: count,
                got: arith.len(),
            });
        }

        let mut dabits = Vec::with_capacity(count);
        for (a, b) in arith.into_iter().zip(bin) {
            dabits.push(DaBit::new(a, b, self.threshold)?);
        }
        Ok(dabits)
    }

    /// Drains completed Mod2 openings. Call after feeding a `BatchRecon` message whose session's
    /// calling protocol routes here.
    pub async fn drain_open_output(&mut self) -> Result<(), DaBitError> {
        self.mod2.drain_open_output().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::gf2k::field::Gf256;
    use crate::common::math::goldilocks::GoldilocksField;
    use crate::honeybadger::prss::prss::PrssDomain;
    use crate::honeybadger::prss::{PrssAllocator, PrssError, PrssStream};

    type F = GoldilocksField;
    type K = Gf256;

    const KAPPA: usize = MIN_STATISTICAL_SECURITY;

    #[test]
    fn binomial_and_ceil_log2_agree_with_the_plan_table() {
        for (n, t, c, bits) in [
            (4usize, 1usize, 4u128, 2usize),
            (7, 2, 21, 5),
            (10, 3, 120, 7),
            (13, 4, 715, 10),
        ] {
            assert_eq!(binomial(n, t), Some(c), "C({n},{t})");
            assert_eq!(ceil_log2(c), bits, "ceil log2 C({n},{t})");
        }
        assert_eq!(ceil_log2(0), 0);
        assert_eq!(ceil_log2(1), 0);
        assert_eq!(ceil_log2(2), 1);
        assert_eq!(ceil_log2(3), 2);
    }

    /// The `λ` / `Q` column of §1.4, at `k = 0`, reproduced exactly.
    #[test]
    fn the_k_zero_budget_matches_the_derivation() {
        for (n, t, lambda, q_exp) in [
            (4usize, 1usize, 60usize, 21u32),
            (7, 2, 57, 18),
            (10, 3, 55, 16),
            (13, 4, 52, 13),
        ] {
            let b = DaBitLeakBudget::new::<F>(n, t, KAPPA, Some(0)).unwrap();
            assert_eq!(b.mask_bits, lambda, "lambda at n={n}");
            assert_eq!(b.topup_bits, 0);
            assert_eq!(b.leak_exponent(), lambda + 1);
            assert_eq!(b.max_dabits, 1u64 << q_exp, "Q at n={n}");
            assert_eq!(b.rand_bits_per_dabit(), 1);
        }
    }

    /// The production default `k = ceil − 3` and its `Q >= 2^20` promise.
    #[test]
    fn the_default_topup_buys_at_least_a_million_dabits() {
        for (n, t, k) in [(4usize, 1usize, 0usize), (7, 2, 2), (10, 3, 4), (13, 4, 7)] {
            let b = DaBitLeakBudget::new::<F>(n, t, KAPPA, None).unwrap();
            assert_eq!(b.topup_bits, k, "default k at n={n}");
            assert_eq!(b.rand_bits_per_dabit(), 1 + k);
            assert!(
                b.max_dabits >= 1 << 20,
                "n={n}: Q = {} below 2^20",
                b.max_dabits
            );
        }
    }

    /// `λ + k + 1` tops out at `MODULUS_BIT_SIZE − 2` for every party count, which is what makes
    /// the maximum budget `2^22` independent of `n`.
    #[test]
    fn the_maximum_topup_gives_the_same_leak_exponent_everywhere() {
        for (n, t) in [(4usize, 1usize), (7, 2), (10, 3), (13, 4)] {
            let ceil = ceil_log2(binomial(n, t).unwrap());
            let b = DaBitLeakBudget::new::<F>(n, t, KAPPA, Some(ceil - 1)).unwrap();
            assert_eq!(b.leak_exponent(), F::MODULUS_BIT_SIZE as usize - 2);
            assert_eq!(b.max_dabits, 1u64 << 22);
        }
    }

    /// The no-wrap inequality is the correctness condition, so it is re-checked here directly
    /// against the modulus for every admissible `(n, t, k)` rather than trusted from the formula.
    #[test]
    fn no_wrap_holds_at_every_admissible_topup() {
        let modulus: BigUint = F::MODULUS.into();
        for (n, t) in [(4usize, 1usize), (7, 2), (10, 3), (13, 4)] {
            let c = binomial(n, t).unwrap();
            let ceil = ceil_log2(c);
            for k in 0..=(ceil - 1) {
                let b = DaBitLeakBudget::new::<F>(n, t, KAPPA, Some(k)).unwrap();
                let one = BigUint::from(1u8);
                let c_big = BigUint::from(c);
                let lhs =
                    &c_big + &one + ((&one << (b.mask_bits + 1)) * (&c_big + (&one << k) - &one));
                assert!(lhs < modulus, "n={n} k={k}: S + 2r'' + r'_0 can wrap p");
            }
        }
    }

    #[test]
    fn a_topup_above_ceil_minus_one_is_refused() {
        // n = 10, t = 3: ceil = 7, so k <= 6.
        assert!(DaBitLeakBudget::new::<F>(10, 3, KAPPA, Some(6)).is_ok());
        assert!(matches!(
            DaBitLeakBudget::new::<F>(10, 3, KAPPA, Some(7)),
            Err(DaBitError::TopUpTooLarge {
                requested: 7,
                max: 6
            })
        ));
    }

    /// Misconfiguration is a hard error everywhere, never a `warn!`.
    #[test]
    fn degenerate_parameters_are_hard_errors() {
        assert!(matches!(
            DaBitLeakBudget::new::<F>(10, 0, KAPPA, None),
            Err(DaBitError::DegenerateThreshold)
        ));
        assert!(matches!(
            DaBitLeakBudget::new::<F>(4, 4, KAPPA, None),
            Err(DaBitError::ThresholdOutOfRange { n: 4, t: 4 })
        ));
        assert!(matches!(
            DaBitLeakBudget::new::<F>(10, 3, KAPPA - 1, None),
            Err(DaBitError::InsufficientStatisticalSecurity { .. })
        ));
        assert!(matches!(
            DaBitLeakBudget::new::<F>(200, 60, KAPPA, None),
            Err(DaBitError::TooManyUnqualifiedSets { .. })
        ));
    }

    #[test]
    fn node_refuses_out_of_range_party_indices() {
        assert!(matches!(
            PrssDaBitNode::<F, K>::new(10, 10, 3, KAPPA, None),
            Err(DaBitError::InvalidPartyId)
        ));
        assert!(matches!(
            PrssDaBitNode::<F, K>::new(0, 256, 3, KAPPA, None),
            Err(DaBitError::InvalidPartyId)
        ));
        assert!(PrssDaBitNode::<F, K>::new(0, 10, 3, KAPPA, None).is_ok());
    }

    /// The one line the whole phase argument rests on: the daBit's only opening is degree `t`.
    #[test]
    fn the_only_opening_is_pinned_at_degree_t() {
        let node = PrssDaBitNode::<F, K>::new(2, 13, 4, KAPPA, None).unwrap();
        assert_eq!(node.mod2.open.degree, 4);
    }

    /// `β` and `ψ` must not share a `(label, key, ctx16)` stream.
    ///
    /// The separation is minted by `claim_dabit_batch` now, not by a private session-id helper, so
    /// it is pinned here as a property of the two **windows** one claim returns: same exec (the
    /// structural fact that `ψ` hangs off the parent), different `ctx[13]`, different `ctx[15]`.
    /// Two independent bytes, which matters because the widths differ — a merge would be a
    /// *partial* overlap producing no equal value for a ledger to notice.
    #[tokio::test]
    async fn the_mask_derives_under_a_different_context_than_the_seeds() {
        let alloc = PrssAllocator::new(9, [0xD0; 32]);
        let w = alloc.claim_dabit_batch(4, 40).await.unwrap();
        let (parent, psi) = (w.seed().session_id(), w.psi().session_id());

        assert_ne!(parent, psi);
        assert_eq!(psi.sub_id(), PSI_SUB_ID);
        assert_ne!(parent.sub_id(), psi.sub_id());
        assert_eq!(psi.exec_id(), parent.exec_id());
        assert_eq!(psi.instance_id(), parent.instance_id());

        // The second separator: `ctx[15]`.
        assert_eq!(w.seed().domain(), PrssDomain::Default);
        assert_eq!(w.psi().domain(), PrssDomain::DaBitPsi);
        assert_ne!(
            PrssDomain::Default.context_tag(),
            PrssDomain::DaBitPsi.context_tag()
        );

        // And the widths the two keystreams are pinned at.
        assert_eq!(w.seed().bits(), 1);
        assert_eq!(w.psi().bits(), 40);
        assert_eq!(w.len(), 4);
        assert_eq!(w.parent_session(), parent);

        let mod2 = PrssDaBitNode::<F, K>::mod2_session_id(parent).unwrap();
        assert_eq!(mod2.calling_protocol(), Some(ProtocolType::DaBitOpen));
        assert_eq!(mod2.sub_id(), 0);
        assert_eq!(mod2.exec_id(), parent.exec_id());
    }

    /// `DaBitPsi` is a follower: it has no cursor, and the only route to a `ψ` window is through
    /// the leader's claim. A direct claim would hand it an exec the leader has not burned.
    #[tokio::test]
    async fn the_mod2_mask_stream_cannot_be_claimed_on_its_own() {
        let alloc = PrssAllocator::new(9, [0xD1; 32]);
        assert!(matches!(
            alloc.claim(PrssStream::DaBitPsi, 4, 40).await.unwrap_err(),
            PrssError::FollowerStream {
                stream: "DaBitPsi",
                leader: "DaBitSeed",
            }
        ));
        assert!(matches!(
            alloc.claim_exec(PrssStream::DaBitPsi).await.unwrap_err(),
            PrssError::FollowerStream { .. }
        ));
    }

    #[test]
    fn a_non_root_or_wrongly_tagged_parent_session_is_refused() {
        for bad in [
            SessionId::new(ProtocolType::DaBit, SessionId::pack_slot(1, 1, 0), 9),
            SessionId::new(ProtocolType::DaBit, SessionId::pack_slot(1, 0, 1), 9),
            SessionId::new(ProtocolType::Mul, SessionId::pack_slot(1, 0, 0), 9),
        ] {
            assert!(matches!(
                PrssDaBitNode::<F, K>::mod2_session_id(bad),
                Err(DaBitError::SessionIdError(_))
            ));
        }
    }

    #[tokio::test]
    async fn generate_without_keys_fails_loudly_and_never_silently_degrades() {
        use stoffelmpc_network::fake_network::{FakeInnerNetwork, FakeNetwork, FakeNetworkConfig};
        let (inner, _inboxes, _) = FakeInnerNetwork::new(10, None, FakeNetworkConfig::new(10));
        let network = Arc::new(FakeNetwork::new(0, inner));

        let mut node = PrssDaBitNode::<F, K>::new(0, 10, 3, KAPPA, Some(0)).unwrap();
        let alloc = PrssAllocator::new(9, [0xD2; 32]);
        let w = alloc.claim_dabit_batch(1, node.mask_bits()).await.unwrap();
        let bits = vec![RobustShare::<F>::new(F::from(1u64), 0, 3)];
        assert!(matches!(
            node.generate(w, bits, Duration::from_millis(10), network)
                .await,
            Err(DaBitError::PrssKeysMissing)
        ));
    }

    /// Exhaustion is an error, never a wrap, and the counter is **not** rolled back by a failed
    /// batch: the positions were burned by the attempt.
    #[tokio::test]
    async fn the_lifetime_budget_is_enforced_and_never_wraps() {
        use stoffelmpc_network::fake_network::{FakeInnerNetwork, FakeNetwork, FakeNetworkConfig};
        let (inner, _inboxes, _) = FakeInnerNetwork::new(10, None, FakeNetworkConfig::new(10));
        let network = Arc::new(FakeNetwork::new(0, inner));

        let mut node = PrssDaBitNode::<F, K>::new(0, 10, 3, KAPPA, Some(0)).unwrap();
        let budget = node.budget.max_dabits;
        assert_eq!(node.produced().await, 0);
        assert_eq!(node.remaining_budget().await, budget);

        // Push the counter to one short of the cap without running any batch.
        {
            let mut produced = node.produced.lock().await;
            *produced = budget - 1;
        }
        assert_eq!(node.remaining_budget().await, 1);

        let alloc = PrssAllocator::new(9, [0xD3; 32]);
        let w = alloc.claim_dabit_batch(2, node.mask_bits()).await.unwrap();
        let bits = vec![RobustShare::<F>::new(F::from(1u64), 0, 3); 2];
        let err = node
            .generate(w, bits, Duration::from_millis(10), network)
            .await
            .unwrap_err();
        match err {
            DaBitError::LeakBudgetExhausted {
                produced,
                requested,
                budget: cap,
            } => {
                assert_eq!(produced, budget - 1);
                assert_eq!(requested, 2);
                assert_eq!(cap, budget);
            }
            other => panic!("expected LeakBudgetExhausted, got {other:?}"),
        }
        // Refused, so nothing was reserved.
        assert_eq!(node.produced().await, budget - 1);
    }

    #[tokio::test]
    async fn a_wrong_rand_bit_count_is_refused_exactly() {
        use stoffelmpc_network::fake_network::{FakeInnerNetwork, FakeNetwork, FakeNetworkConfig};
        let (inner, _inboxes, _) = FakeInnerNetwork::new(10, None, FakeNetworkConfig::new(10));
        let network = Arc::new(FakeNetwork::new(0, inner));

        // k = 4 at n = 10, so five RandBits per daBit.
        let mut node = PrssDaBitNode::<F, K>::new(0, 10, 3, KAPPA, None).unwrap();
        assert_eq!(node.rand_bits_per_dabit(), 5);
        let alloc = PrssAllocator::new(9, [0xD4; 32]);
        // A surplus is refused as firmly as a shortfall: one silently dropped here is one the
        // caller still believes is unused. A fresh claim per attempt, because a rejected batch
        // burns its range rather than returning it.
        for supplied in [9usize, 11] {
            let w = alloc.claim_dabit_batch(2, node.mask_bits()).await.unwrap();
            let bits = vec![RobustShare::<F>::new(F::from(1u64), 0, 3); supplied];
            assert!(matches!(
                node.generate(w, bits, Duration::from_millis(10), network.clone())
                    .await,
                Err(DaBitError::MaterialLengthMismatch {
                    what: "dabit rand bits",
                    expected: 10,
                    ..
                })
            ));
        }
        assert_eq!(node.produced().await, 0);
    }
}
