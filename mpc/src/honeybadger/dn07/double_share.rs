//! Random double sharings `([r]_t, [r]_2t)` from PRSS + PRZS — **zero rounds, zero bytes**.
//!
//! This is the piece that makes a DN07 preprocessing multiplication cost one degree-`2t` opening
//! and nothing else. `ran_dou_sha` / `gf_ran_dou_sha` produce the same object interactively, with
//! perfect privacy and real wire traffic; these two sources produce it from replicated PRF keys
//! that were established once, with no traffic at all.
//!
//! ```text
//!   [r]_t   =  sum_{T not containing i}  beta_T · f_T(x_i)          PRSS, uniform over F (or K)
//!   [r]_2t  =  [r]_t  +  h(x_i)                                     PRZS, deg <= 2t, h(0) = 0
//! ```
//!
//! Both halves share a constant term because `h(0) = 0` **structurally** (every PRZS basis
//! polynomial carries a factor `X`), so the pair is a genuine double sharing on one `r` for every
//! coefficient assignment — there is nothing to check and no failure mode where the halves
//! disagree.
//!
//! # Phase: PREPROCESSING only
//!
//! Nothing here sends a message, so these types are phase-neutral in isolation. Their *output* is
//! not: a degree-`2t` sharing can only be spent by a degree-`2t` opening, which is legal in
//! synchronous preprocessing and illegal on the asynchronous robust online path. Both entry points
//! therefore take a [`PreprocessingSessionId`], for the same reason the DN07 nodes do — see the
//! [module docs](super).
//!
//! # What it costs, and what it costs you
//!
//! It buys: `18.857 -> 2.857` bytes of **payload** per `Gf256` Beaver triple at `n = 10`
//! (**6.6x**), and it deletes `RanDouSha` from the DN07 multiplication's bill entirely.
//!
//! Quote that 6.6x only with its two measured qualifications ([`dn07` module docs](super)): the
//! `18.857` baseline is the *fully dealt* one, which this tree had already left (the real
//! predecessor was `2·P1_K + O2`, so the improvement is **3.25x / 3.62x / 3.80x / 3.91x** at
//! `n = 4/7/10/13`) and which does not run above `n = 4`; and `2.857` is the **marginal** cost,
//! on top of a fixed `2n * 48` bytes/party of framing per batch.
//!
//! It costs, and these are not hidden:
//!
//! * **Computational rather than perfect privacy of preprocessing randomness**, under HMAC-SHA256
//!   as a PRF. Every "privacy is perfect" claim about a protocol that consumes these downgrades to
//!   computational. It is the same assumption `PRandInt` already runs on, not a new class.
//! * **A party-count ceiling.** Each party holds `C(n-1, t)` keys, and PRZS spends `t` PRF streams
//!   per key per sharing: `t · C(n-1,t)` = 3 / 30 / 252 / 1980 streams at `n` = 4 / 7 / 10 / 13.
//!   Comfortable to `n = 13`, tolerable at `n = 16`, unusable above.
//! * **A cursor obligation.** The derivation is position-addressed and stateless, so the cursor
//!   lives in the caller. A position must be **burned, never rewound**, including on abort or
//!   retry: re-deriving an already-opened position hands the adversary the mask in advance. This
//!   is the VERIA-222 class (`prandint.rs:132-139`) and it is the caller's to get right.
//!
//! # Domain separation between the two halves
//!
//! `[r]_t` and `[r]_2t`'s mask are derived from the **same key set**, so they must not collide.
//! Three separators are in place, any one of which would suffice:
//!
//! | | `[r]_t` (PRSS uniform) | `h` (PRZS) |
//! |---|---|---|
//! | SP 800-108 label | `STOFFEL-PRSS-UNIFORM-v2` | `STOFFEL-PRZS-v2` |
//! | context byte `ctx[15]` | `0x01` | `0x02` (F) / `0x03` (K) |
//! | position stride | 1 value per index | `t` values per index |
//!
//! Two are belt-and-braces on purpose: a future refactor that unifies one of them must not
//! silently merge the two keystreams. Note that the PRSS *uniform* label is also distinct from the
//! PRSS *mask* label (`STOFFEL-PRSS-v2`), so a DN07 mask cannot collide with a `PRandInt` mask or
//! a daBit seed either, whatever session id they are drawn under.

use ark_ff::PrimeField;

use crate::common::gf2k::field::BinaryField;
use crate::common::gf2k::share::GfShare;
use crate::common::share::shamir::NonRobustShare;
use crate::honeybadger::dn07::{Dn07Error, PreprocessingSessionId};
use crate::honeybadger::double_share::DoubleShamirShare;
use crate::honeybadger::gf_double_share::GfDoubleShamirShare;
use crate::honeybadger::gf_prss::gf_prss::{extension_degree, GfPrssKeys};
use crate::honeybadger::prss::prss::{PrssKeys, PRSS_UNIFORM_SLACK_BITS};
use crate::honeybadger::prss::{PrssAllocator, PrssStream, PrssWindow};
use crate::honeybadger::przs::gf_przs::GfPrzsKeys;
use crate::honeybadger::przs::przs::PrzsKeys;
use crate::honeybadger::przs::{PrzsCoefficient, PRZS_REDUCTION_SLACK_BITS};
use crate::honeybadger::robust_interpolate::robust_interpolate::RobustShare;

/// One batch of `F` Beaver-triple inputs from PRSS + PRZS, as
/// [`PrssDoubleShareSource::triple_material`] returns them.
///
/// `a[i]`, `b[i]` and `doubles[i]` are drawn at three disjoint position ranges of one keystream,
/// so the three are independent. All three are **derived, never dealt**, which is the precondition
/// [`Dn07MulNode::init_mul`](crate::honeybadger::dn07::dn07::Dn07MulNode::init_mul) states for
/// feeding it an operand: a degree-`2t` opening puts no codeword constraint on the honest
/// sub-word, so a *dealt* operand at degree `t+1` would be recoverable from it without any abort.
#[derive(Clone, Debug)]
pub struct TripleMaterial<F: PrimeField> {
    /// The triples' `[a]_t`, uniform over `F`.
    pub a: Vec<RobustShare<F>>,
    /// The triples' `[b]_t`, uniform over `F` and independent of `a`.
    pub b: Vec<RobustShare<F>>,
    /// One `([r]_t, [r]_2t)` per triple, the mask the DN07 degree reduction spends.
    pub doubles: Vec<DoubleShamirShare<F>>,
}

/// Non-interactive source of `([r]_t, [r]_2t)` over the arithmetic field `F`.
///
/// **Phase: PREPROCESSING.** See the [module docs](self).
#[derive(Clone, Debug)]
pub struct PrssDoubleShareSource<F: PrimeField> {
    prss: PrssKeys<F>,
    przs: PrzsKeys<F>,
}

impl<F: PrimeField> PrssDoubleShareSource<F> {
    /// Pairs a PRSS store with a PRZS store built over **the same keys, ranks and threshold**.
    ///
    /// The cross-checks are not ceremony. The two stores each carry their own `id`, `t` and key
    /// count, and a pair that disagrees on any of them produces a `[r]_t` and a `[r]_2t` of two
    /// *different* secrets — which is not a double sharing at all, is not detectable at the
    /// opening (the opened `d` is simply wrong by `r_t - r_2t`), and yields a silently wrong
    /// product. Rejecting at construction is the only place it can be caught.
    ///
    /// # Errors
    /// - [`Dn07Error::KeyStoreMismatch`] if the two stores disagree on party index, threshold or
    ///   held-key count.
    /// - [`Dn07Error::DegenerateThreshold`] for `t == 0`.
    pub fn new(prss: PrssKeys<F>, przs: PrzsKeys<F>) -> Result<Self, Dn07Error> {
        if prss.threshold() == 0 {
            return Err(Dn07Error::DegenerateThreshold);
        }
        if prss.id() != przs.id() {
            return Err(Dn07Error::KeyStoreMismatch {
                what: "party index",
                left: prss.id(),
                right: przs.id(),
            });
        }
        if przs.degree() != 2 * prss.threshold() {
            return Err(Dn07Error::KeyStoreMismatch {
                what: "threshold",
                left: prss.threshold(),
                right: przs.degree(),
            });
        }
        if prss.len() != przs.len() {
            return Err(Dn07Error::KeyStoreMismatch {
                what: "held-key count",
                left: prss.len(),
                right: przs.len(),
            });
        }
        // The invariant the whole PRZS module exists to protect. `PrzsKeys::new` establishes it;
        // re-asserting it here is cheap and this is the last place a caller-assembled store can be
        // caught before its masks go on the wire.
        if przs.coefficients_per_set() != prss.threshold() {
            return Err(Dn07Error::KeyStoreMismatch {
                what: "PRZS coefficients per set (a one-coefficient mask is a privacy break)",
                left: przs.coefficients_per_set(),
                right: prss.threshold(),
            });
        }
        Ok(Self { prss, przs })
    }

    /// This party's index.
    pub fn id(&self) -> usize {
        self.prss.id()
    }

    /// The threshold, i.e. the degree of the `[r]_t` half.
    pub fn threshold(&self) -> usize {
        self.prss.threshold()
    }

    /// Fingerprint of the key family this source derives from. A
    /// [`PrssWindow`] must carry the same one or [`Self::randbit_material_at`] refuses it.
    pub fn key_family_id(&self) -> [u8; 32] {
        self.prss.key_family_id()
    }

    /// `count` double sharings at absolute positions `start .. start + count`.
    ///
    /// Every party must pass the identical `session_id`, `start` and `count`. Positions must be
    /// burned rather than rewound — see the [module docs](self).
    pub fn double_shares_at(
        &self,
        session_id: PreprocessingSessionId,
        start: usize,
        count: usize,
    ) -> Result<Vec<DoubleShamirShare<F>>, Dn07Error> {
        let sid = session_id.get();
        let t = self.prss.threshold();
        let id = self.prss.id();

        let r_t = self
            .prss
            .uniform_shares_at(sid, start, count)
            .map_err(|e| Dn07Error::Prss(format!("{e:?}")))?;
        let h = self
            .przs
            .zero_shares_at(sid, start, count)
            .map_err(|e| Dn07Error::Przs(format!("{e:?}")))?;
        if r_t.len() != count || h.len() != count {
            return Err(Dn07Error::LengthMismatch {
                what: "PRSS/PRZS draw",
                expected: count,
                got: r_t.len().min(h.len()),
            });
        }

        Ok(r_t
            .into_iter()
            .zip(h.into_iter())
            .map(|(lo, hi)| {
                // The degree labels are the local protocol constants, not anything read back from
                // the two stores.
                DoubleShamirShare::new(
                    NonRobustShare::new(lo.share[0], id, t),
                    NonRobustShare::new(lo.share[0] + hi.share[0], id, 2 * t),
                )
            })
            .collect())
    }

    /// Width of one draw on [`PrssStream::Dn07Double`], in bits.
    ///
    /// The stream's PRSS half is [`PrssKeys::uniform_shares_at`], so this is the uniform width —
    /// the same number [`Self::randbit_a_bits`] returns, on a *different* keystream. The PRZS half
    /// rides the same window; it is a separate keystream (distinct SP 800-108 label and distinct
    /// `ctx[15]`) and needs no width of its own, because the two halves of a double sharing are
    /// always claimed and spent together.
    pub fn double_bits() -> usize {
        F::MODULUS_BIT_SIZE as usize + PRSS_UNIFORM_SLACK_BITS
    }

    /// A Beaver triple's three inputs, `([a]_t, [b]_t, ([r]_t, [r]_2t))` per triple, all from this
    /// key family — **zero rounds, zero bytes** — claiming every position from `alloc`.
    ///
    /// This is what replaces `2 x RanSha + RanDouSha` on the `F` triple path. A triple's whole
    /// remaining cost is then the one degree-`2t` DN07 opening that multiplies `a` by `b`.
    ///
    /// # Why one window of `3 * count` and not three windows of `count`
    ///
    /// [`PrssStream::Dn07Double`] is a fresh-exec stream: every [`PrssAllocator::claim`] burns a
    /// whole keystream and hands back `start = 0`. Three claims would therefore give three
    /// *different* sessions, which is also sound — but one claim of `3 * count` gives three
    /// provably disjoint sub-ranges of one session, which is cheaper to reason about and makes
    /// the "`a`, `b` and `r` are independent" argument a statement about `start` offsets rather
    /// than about three cursors staying in step.
    ///
    /// `a` and `b` take the PRSS-uniform halves of the first two thirds and **ignore** the PRZS
    /// halves at those positions; those PRZS positions are simply never derived, which costs
    /// nothing and leaves the PRZS keystream's own monotonicity untouched.
    ///
    /// # Errors
    /// Whatever [`PrssAllocator::claim`] returns, plus the checks in [`Self::triple_material_in`].
    pub async fn triple_material(
        &self,
        alloc: &PrssAllocator,
        count: usize,
    ) -> Result<TripleMaterial<F>, Dn07Error> {
        let width = count.checked_mul(3).ok_or(Dn07Error::LengthMismatch {
            what: "DN07 triple material",
            expected: count,
            got: usize::MAX,
        })?;
        let window = alloc
            .claim(PrssStream::Dn07Double, width, Self::double_bits())
            .await
            .map_err(|e| Dn07Error::Prss(format!("{e}")))?;
        self.triple_material_in(&window)
    }

    /// The primitive under [`Self::triple_material`], at one explicitly-claimed range whose length
    /// must be a multiple of three.
    ///
    /// # Errors
    /// - [`Dn07Error::WrongPrssStream`] / [`Dn07Error::KeyFamilyMismatch`] as for
    ///   [`Self::randbit_material_at`].
    /// - [`Dn07Error::LengthMismatch`] if the window's length is not `3 * count`.
    pub fn triple_material_in(&self, window: &PrssWindow) -> Result<TripleMaterial<F>, Dn07Error> {
        if window.stream() != PrssStream::Dn07Double {
            return Err(Dn07Error::WrongPrssStream {
                expected: PrssStream::Dn07Double.name(),
                got: window.stream().name(),
            });
        }
        if window.key_family_id() != self.key_family_id() {
            return Err(Dn07Error::KeyFamilyMismatch);
        }
        if window.len() % 3 != 0 {
            return Err(Dn07Error::LengthMismatch {
                what: "DN07 triple material window",
                expected: window.len().next_multiple_of(3),
                got: window.len(),
            });
        }
        let count = window.len() / 3;
        let sid = window.session_id();
        let pre_sid = PreprocessingSessionId::new(sid)?;
        let base = window.start();

        let draw = |start: usize| -> Result<Vec<RobustShare<F>>, Dn07Error> {
            let v = self
                .prss
                .uniform_shares_at(sid, start, count)
                .map_err(|e| Dn07Error::Prss(format!("{e:?}")))?;
            if v.len() != count {
                return Err(Dn07Error::LengthMismatch {
                    what: "DN07 triple PRSS draw",
                    expected: count,
                    got: v.len(),
                });
            }
            Ok(v)
        };

        let a = draw(base)?;
        let b = draw(base + count)?;
        let doubles = self.double_shares_at(pre_sid, base + 2 * count, count)?;
        Ok(TripleMaterial { a, b, doubles })
    }

    /// Width of one `[a]` draw, in bits. `MODULUS_BIT_SIZE + PRSS_UNIFORM_SLACK_BITS`, matching
    /// [`PrssKeys::uniform_shares_at`] exactly — the allocator records it so that a second
    /// consumer of this stream at a different width is refused rather than silently overlapping.
    pub fn randbit_a_bits() -> usize {
        F::MODULUS_BIT_SIZE as usize + PRSS_UNIFORM_SLACK_BITS
    }

    /// Width of one PRZS coefficient draw, in bits, matching
    /// [`PrzsKeys::zero_shares_at`](crate::honeybadger::przs::przs::PrzsKeys::zero_shares_at).
    pub fn randbit_zero_bits() -> usize {
        F::MODULUS_BIT_SIZE as usize + PRZS_REDUCTION_SLACK_BITS
    }

    /// `RandBit`'s two inputs from this key family — **zero rounds, zero bytes** — claiming both
    /// positions from `alloc`.
    ///
    /// This is the entry point callers should use: it pins both widths itself, so the P2 hazard
    /// (one stream claimed at two widths, addressing overlapping bytes) is not expressible at the
    /// call site. [`Self::randbit_material_at`] is the primitive underneath, for tests that need
    /// to name a position explicitly.
    ///
    /// Both claims advance monotone cursors **before** anything is derived, so a batch that
    /// subsequently fails burns its ranges rather than rewinding onto them — see
    /// [`window`](crate::honeybadger::prss::window). The `A` claim can succeed and the `Zero`
    /// claim then fail; the two cursors drift by one, which is harmless because they are
    /// different keystreams and both remain monotone.
    ///
    /// # Errors
    /// Whatever [`PrssAllocator::claim`] returns, plus the checks in
    /// [`Self::randbit_material_at`].
    pub async fn randbit_material(
        &self,
        alloc: &PrssAllocator,
        count: usize,
    ) -> Result<(Vec<RobustShare<F>>, Vec<RobustShare<F>>), Dn07Error> {
        let a_window = alloc
            .claim(PrssStream::RandBitA, count, Self::randbit_a_bits())
            .await
            .map_err(|e| Dn07Error::Prss(format!("{e}")))?;
        let zero_window = alloc
            .claim(PrssStream::RandBitZero, count, Self::randbit_zero_bits())
            .await
            .map_err(|e| Dn07Error::Przs(format!("{e}")))?;
        self.randbit_material_at(&a_window, &zero_window)
    }

    /// `RandBit`'s two inputs at two explicitly-claimed positions: `[a]` uniform over `F` at
    /// degree `t`, and an **independent** degree-`2t` sharing of zero that re-randomises
    /// `MulPub`'s opening of `a^2`.
    ///
    /// # This is not [`Self::double_shares_at`]
    ///
    /// `double_shares_at` returns `([r]_t, [r]_2t)` — *one* secret carried at two degrees, the
    /// PRSS half and the PRZS half **summed**. `RandBit` needs the two halves taken **apart**:
    /// `[a]` is the value whose square gets opened, and the zero sharing is a mask that must be
    /// independent of it. Summing them here would make the mask a function of `a`, which is not a
    /// mask at all.
    ///
    /// # Why `[a]` is the uniform stream and not the mask stream
    ///
    /// [`PrssKeys::shares_at`] sums `beta_T` over the **integers** into `[0, C(n,t) * 2^bits)`,
    /// which is a statistical mask and is not uniform on `F`. `RandBit` takes a square root of
    /// this value and divides by it; a non-uniform `a` biases the resulting bit. The uniform
    /// stream also carries a distinct SP 800-108 label, so `[a]` cannot collide with a
    /// `PRandInt` mask or a daBit seed whatever session id it is drawn under.
    ///
    /// # Privacy, in one paragraph, because it differs from the dealt-`RanSha` proof
    ///
    /// Let `A` be the corrupt set, `|A| = t`. `A` holds every key but `k_A`, so write
    /// `phi_a = K + beta_A f_A` with `K` known to `A`, and let `g = sum_{l=1..t} a_l X^l` be the
    /// unknown part of the PRZS mask. `MulPub` opens `P = phi_a^2 + h`; subtracting what `A`
    /// knows and dividing by the known `f_A` leaves
    /// `W(X) = 2 beta_A K(X) + beta_A^2 f_A(X) + g(X)` of degree `<= t`. Its constant term is
    /// `a^2 - k_0^2`, which `A` already knows because `a^2` is public. Its other `t` coefficients
    /// are each `(known) + g_l` with `g_l` uniform and independent. So the construction is
    /// **tight**: `t` free PRZS coefficients mask exactly the `t` coefficients that would
    /// otherwise be revealed. A PRZS carrying `t - 1` coefficients would hand `A` one unmasked
    /// linear equation in `beta_A`, which with the public `a^2` determines `beta_A` and hence the
    /// bit. Do not reduce the CDI05 coefficient count.
    ///
    /// # Errors
    /// - [`Dn07Error::WrongPrssStream`] if either window names the wrong keystream.
    /// - [`Dn07Error::KeyFamilyMismatch`] if a window was claimed against other key material.
    /// - [`Dn07Error::LengthMismatch`] if the two windows disagree on length, or a derivation
    ///   returns short.
    /// - [`Dn07Error::Prss`] / [`Dn07Error::Przs`] from the derivations themselves —
    ///   in particular [`PrzsError::BatchTooLarge`](crate::honeybadger::przs::PrzsError::BatchTooLarge)
    ///   once `count * t` exceeds
    ///   [`MAX_PRZS_COEFFS_PER_CALL`](crate::honeybadger::przs::MAX_PRZS_COEFFS_PER_CALL), which
    ///   is why callers chunk against `MAX_PRZS_COEFFS_PER_CALL / t` as well as against
    ///   `MulPub`'s own ceiling.
    pub fn randbit_material_at(
        &self,
        a_window: &PrssWindow,
        zero_window: &PrssWindow,
    ) -> Result<(Vec<RobustShare<F>>, Vec<RobustShare<F>>), Dn07Error> {
        if a_window.stream() != PrssStream::RandBitA {
            return Err(Dn07Error::WrongPrssStream {
                expected: PrssStream::RandBitA.name(),
                got: a_window.stream().name(),
            });
        }
        if zero_window.stream() != PrssStream::RandBitZero {
            return Err(Dn07Error::WrongPrssStream {
                expected: PrssStream::RandBitZero.name(),
                got: zero_window.stream().name(),
            });
        }
        let family = self.prss.key_family_id();
        if a_window.key_family_id() != family || zero_window.key_family_id() != family {
            return Err(Dn07Error::KeyFamilyMismatch);
        }
        let count = a_window.len();
        if zero_window.len() != count {
            return Err(Dn07Error::LengthMismatch {
                what: "RandBit PRSS/PRZS windows",
                expected: count,
                got: zero_window.len(),
            });
        }

        let a = self
            .prss
            .uniform_shares_at(a_window.session_id(), a_window.start(), count)
            .map_err(|e| Dn07Error::Prss(format!("{e:?}")))?;
        let zero = self
            .przs
            .zero_shares_at(zero_window.session_id(), zero_window.start(), count)
            .map_err(|e| Dn07Error::Przs(format!("{e:?}")))?;
        if a.len() != count || zero.len() != count {
            return Err(Dn07Error::LengthMismatch {
                what: "RandBit PRSS/PRZS draw",
                expected: count,
                got: a.len().min(zero.len()),
            });
        }
        Ok((a, zero))
    }
}

/// One batch of `Gf2k` Beaver-triple inputs from PRSS + PRZS, as
/// [`GfPrssDoubleShareSource::triple_material`] returns them. Binary-field twin of
/// [`TripleMaterial`]; keep the two in step.
///
/// `a[i]`, `b[i]` and `doubles[i]` come from three disjoint position ranges of **one**
/// [`PrssStream::GfDn07Double`] window, so the three are independent. All three are **derived,
/// never dealt** — the precondition a degree-`2t` opening imposes on its operands, and the reason
/// this may replace the `GfRanSha` pair `GfTripleGenNode` used to be handed. A dealt `[a]` at
/// degree `t+1` would survive the opening and hand its dealer the honest `b` in the clear; a
/// PRSS-derived one is a deterministic function of keys held by `n - t >= 2t+1` parties, so a
/// corrupt party's only freedom is to lie at the opening, which the `[3t+1, 2t+1]` code's
/// distance `t+1` detects with probability 1.
#[derive(Clone, Debug)]
pub struct GfTripleMaterial<K: BinaryField + PrzsCoefficient> {
    /// The triples' `[a]_t`, uniform over the whole of `K`.
    pub a: Vec<GfShare<K>>,
    /// The triples' `[b]_t`, uniform over `K` and independent of `a`.
    pub b: Vec<GfShare<K>>,
    /// One `([r]_t, [r]_2t)` per triple, the mask the degree reduction spends.
    pub doubles: Vec<GfDoubleShamirShare<K>>,
}

/// Non-interactive source of `([r]_t, [r]_2t)` over a binary field `K`. Structural port of
/// [`PrssDoubleShareSource`]; keep the two in step.
///
/// **Phase: PREPROCESSING.** See the [module docs](self).
#[derive(Clone, Debug)]
pub struct GfPrssDoubleShareSource<K: BinaryField + PrzsCoefficient> {
    prss: GfPrssKeys<K>,
    przs: GfPrzsKeys<K>,
    /// `GfPrssKeys` exposes no `id`/`t` accessor, so the pair's identity is taken from the PRZS
    /// store (which does) and the PRSS store is cross-checked on the one thing it does expose,
    /// its held-key count. Recorded here so the source does not have to re-derive it.
    id: usize,
    threshold: usize,
}

impl<K: BinaryField + PrzsCoefficient> GfPrssDoubleShareSource<K> {
    /// Pairs a `gf_prss` store with a `gf_przs` store built over the same keys and threshold.
    ///
    /// # Errors
    /// - [`Dn07Error::KeyStoreMismatch`] on a held-key-count disagreement or a PRZS store whose
    ///   mask is not `t`-dimensional.
    /// - [`Dn07Error::DegenerateThreshold`] for `t == 0`.
    pub fn new(prss: GfPrssKeys<K>, przs: GfPrzsKeys<K>) -> Result<Self, Dn07Error> {
        let threshold = przs.coefficients_per_set();
        if threshold == 0 {
            return Err(Dn07Error::DegenerateThreshold);
        }
        if przs.degree() != 2 * threshold {
            return Err(Dn07Error::KeyStoreMismatch {
                what: "PRZS degree",
                left: przs.degree(),
                right: 2 * threshold,
            });
        }
        if prss.len() != przs.len() {
            return Err(Dn07Error::KeyStoreMismatch {
                what: "held-key count",
                left: prss.len(),
                right: przs.len(),
            });
        }
        Ok(Self {
            id: przs.id(),
            threshold,
            prss,
            przs,
        })
    }

    pub fn id(&self) -> usize {
        self.id
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Fingerprint of the key family this source derives from. See
    /// [`GfPrssKeys::key_family_id`]; it is the same digest the `F` store produces, because
    /// `setup_prss_keys` builds both from one key list.
    pub fn key_family_id(&self) -> [u8; 32] {
        self.prss.key_family_id()
    }

    /// Width of one `[r]_t` draw, in bits: `extension_degree::<K>()`, matching
    /// [`GfPrssKeys::uniform_shares_at`] exactly.
    ///
    /// The allocator records it on the first claim, so a second consumer of this stream at a
    /// different width is refused rather than silently reading overlapping bytes (P2). It is the
    /// *PRSS* half's width; the PRZS half rides the same window, as it does on the `F` side's
    /// `double_shares_at`, because the two halves of one double sharing are always claimed and
    /// spent together and there is no position either could take without the other.
    ///
    /// # Errors
    /// - [`Dn07Error::Prss`] if `K::MAX_DOMAIN_SIZE` does not determine an extension degree.
    pub fn double_bits() -> Result<usize, Dn07Error> {
        extension_degree::<K>().map_err(|e| Dn07Error::Prss(format!("{e:?}")))
    }

    /// `count` double sharings, claiming their positions from `alloc`.
    ///
    /// This is the entry point production callers should use. It pins the width itself, so the P2
    /// hazard is not expressible at the call site, and the cursor advances **before** anything is
    /// derived — a batch that subsequently fails burns its range rather than rewinding onto it.
    /// See [`window`](crate::honeybadger::prss::window).
    ///
    /// # One stream, every `GfDn07` consumer
    ///
    /// [`PrssStream::GfDn07Double`] is a single keystream shared by *every* `Gf2k` DN07 caller —
    /// GF triple generation and the edaBit modulus-overflow filter today. That is exactly why they
    /// must all claim through one allocator: two callers each running their own monotone counter
    /// are individually monotone and jointly colliding, and a collision here means one `[r]` masks
    /// two different degree-`2t` openings.
    ///
    /// # Errors
    /// Whatever [`PrssAllocator::claim`] returns, plus the checks in [`Self::double_shares_in`].
    pub async fn double_shares(
        &self,
        alloc: &PrssAllocator,
        count: usize,
    ) -> Result<Vec<GfDoubleShamirShare<K>>, Dn07Error> {
        let window = alloc
            .claim(PrssStream::GfDn07Double, count, Self::double_bits()?)
            .await
            .map_err(|e| Dn07Error::Prss(format!("{e}")))?;
        self.double_shares_in(&window)
    }

    /// `count` double sharings at one explicitly-claimed position range.
    ///
    /// The primitive under [`Self::double_shares`], separated so that a test can name a position
    /// and demonstrate that reusing one is fatal.
    ///
    /// # Errors
    /// - [`Dn07Error::WrongPrssStream`] if the window names another keystream.
    /// - [`Dn07Error::KeyFamilyMismatch`] if it was claimed against other key material — its
    ///   position count would say nothing about what these keys have already derived.
    /// - [`Dn07Error::MalformedSessionId`] / [`Dn07Error::OnlinePhaseForbidden`] from
    ///   [`PreprocessingSessionId::new`], which cannot fire for a window this allocator issued on
    ///   this stream (`GfDn07Double` addresses `(GfDn07, 0, 0)`) but is checked rather than
    ///   assumed, because it is the barrier that keeps a degree-`2t` opening off the online path.
    /// - [`Dn07Error::LengthMismatch`] if a derivation returns short.
    pub fn double_shares_in(
        &self,
        window: &PrssWindow,
    ) -> Result<Vec<GfDoubleShamirShare<K>>, Dn07Error> {
        if window.stream() != PrssStream::GfDn07Double {
            return Err(Dn07Error::WrongPrssStream {
                expected: PrssStream::GfDn07Double.name(),
                got: window.stream().name(),
            });
        }
        if window.key_family_id() != self.key_family_id() {
            return Err(Dn07Error::KeyFamilyMismatch);
        }
        let session_id = PreprocessingSessionId::new(window.session_id())?;
        self.double_shares_at(session_id, window.start(), window.len())
    }

    /// `count` `Gf2k` double sharings at absolute positions `start .. start + count`.
    ///
    /// The `[r]_t` half is `GfPrssKeys::uniform_shares_at`, whose secret is `XOR_T beta_T` — in
    /// characteristic 2 the replicated-to-Shamir sum *is* an XOR, so a full-width draw gives a
    /// secret uniform on the whole of `K` with no `C(n,t)` multiplicity to budget for. That is why
    /// the binary side needs no analogue of the `F` side's modulus-slack argument.
    pub fn double_shares_at(
        &self,
        session_id: PreprocessingSessionId,
        start: usize,
        count: usize,
    ) -> Result<Vec<GfDoubleShamirShare<K>>, Dn07Error> {
        let sid = session_id.get();

        let r_t = self
            .prss
            .uniform_shares_at(sid, start, count)
            .map_err(|e| Dn07Error::Prss(format!("{e:?}")))?;
        let h = self
            .przs
            .zero_shares_at(sid, start, count)
            .map_err(|e| Dn07Error::Przs(format!("{e:?}")))?;
        if r_t.len() != count || h.len() != count {
            return Err(Dn07Error::LengthMismatch {
                what: "GF PRSS/PRZS draw",
                expected: count,
                got: r_t.len().min(h.len()),
            });
        }

        Ok(r_t
            .into_iter()
            .zip(h.into_iter())
            .map(|(lo, hi)| {
                GfDoubleShamirShare::new(
                    GfShare::new(lo.share, self.id, self.threshold),
                    // `+` is XOR here, which is what lifts the degree-t sharing to degree 2t
                    // without moving its constant term.
                    GfShare::new(lo.share + hi.share, self.id, 2 * self.threshold),
                )
            })
            .collect())
    }

    /// A `Gf2k` Beaver triple's three inputs, `([a]_t, [b]_t, ([r]_t, [r]_2t))` per triple, all
    /// from this key family — **zero rounds, zero bytes** — claiming every position from `alloc`.
    ///
    /// This is what replaces `2 x GfRanSha + GfRanDouSha` on the GF triple path, and it is the
    /// binary twin of [`PrssDoubleShareSource::triple_material`]; the two are deliberately the
    /// same shape, because they are the same argument over two fields. A GF triple's whole
    /// remaining cost after this is the one degree-`2t` opening that multiplies `a` by `b`.
    ///
    /// # Why one window of `3 * count` and not three windows of `count`
    ///
    /// [`PrssStream::GfDn07Double`] is a fresh-exec stream: every [`PrssAllocator::claim`] burns a
    /// whole keystream and hands back `start = 0`. Three claims would be three *different*
    /// sessions, which is also sound — but one claim of `3 * count` makes "`a`, `b` and `r` are
    /// independent" a statement about `start` offsets inside one session rather than about three
    /// cursors staying in step.
    ///
    /// `a` and `b` take the PRSS-uniform halves of the first two thirds and **ignore** the PRZS
    /// halves at those positions; those PRZS positions are simply never derived, which costs
    /// nothing and leaves the PRZS keystream's own monotonicity untouched.
    ///
    /// # The range is burned, not rewound
    ///
    /// [`PrssAllocator::claim`] advances the cursor before anything is derived, so every failure
    /// below — a short PRSS draw, a PRZS error, a malformed session id — leaves this range spent.
    /// That is the intended behaviour and not a leak of positions worth reclaiming: re-deriving a
    /// position that has already masked a degree-`2t` opening is a total privacy break that no
    /// all-honest test can see, and "the error path rewinds" is exactly how it happens.
    ///
    /// # Errors
    /// Whatever [`PrssAllocator::claim`] returns, plus [`Self::double_bits`]'s
    /// [`Dn07Error::Prss`] when `K::MAX_DOMAIN_SIZE` determines no extension degree, plus the
    /// checks in [`Self::triple_material_in`]. Never panics; `K`'s domain ceiling and `gf_prss`'s
    /// `n` ceiling are already enforced by [`GfPrssKeys::new`], so a source that exists at all is
    /// within both.
    pub async fn triple_material(
        &self,
        alloc: &PrssAllocator,
        count: usize,
    ) -> Result<GfTripleMaterial<K>, Dn07Error> {
        let width = count.checked_mul(3).ok_or(Dn07Error::LengthMismatch {
            what: "GF DN07 triple material",
            expected: count,
            got: usize::MAX,
        })?;
        let window = alloc
            .claim(PrssStream::GfDn07Double, width, Self::double_bits()?)
            .await
            .map_err(|e| Dn07Error::Prss(format!("{e}")))?;
        self.triple_material_in(&window)
    }

    /// The primitive under [`Self::triple_material`], at one explicitly-claimed range whose
    /// length must be a multiple of three.
    ///
    /// Separated so that a test can name a position and demonstrate that reusing one is fatal.
    ///
    /// # Errors
    /// - [`Dn07Error::WrongPrssStream`] if the window names another keystream.
    /// - [`Dn07Error::KeyFamilyMismatch`] if it was claimed against other key material.
    /// - [`Dn07Error::LengthMismatch`] if the window's length is not `3 * count`, or if a
    ///   derivation returns short.
    /// - [`Dn07Error::MalformedSessionId`] / [`Dn07Error::OnlinePhaseForbidden`] from
    ///   [`PreprocessingSessionId::new`] — the barrier that keeps this material, and the
    ///   degree-`2t` opening it feeds, off the online A2B/B2A path. It cannot fire for a window
    ///   this allocator issued on this stream (`GfDn07Double` addresses `(GfDn07, 0, 0)`), and is
    ///   checked rather than assumed for precisely that reason.
    pub fn triple_material_in(
        &self,
        window: &PrssWindow,
    ) -> Result<GfTripleMaterial<K>, Dn07Error> {
        if window.stream() != PrssStream::GfDn07Double {
            return Err(Dn07Error::WrongPrssStream {
                expected: PrssStream::GfDn07Double.name(),
                got: window.stream().name(),
            });
        }
        if window.key_family_id() != self.key_family_id() {
            return Err(Dn07Error::KeyFamilyMismatch);
        }
        if window.len() % 3 != 0 {
            return Err(Dn07Error::LengthMismatch {
                what: "GF DN07 triple material window",
                expected: window.len().next_multiple_of(3),
                got: window.len(),
            });
        }
        let count = window.len() / 3;
        let sid = window.session_id();
        let pre_sid = PreprocessingSessionId::new(sid)?;
        let base = window.start();

        let draw = |start: usize| -> Result<Vec<GfShare<K>>, Dn07Error> {
            let v = self
                .prss
                .uniform_shares_at(sid, start, count)
                .map_err(|e| Dn07Error::Prss(format!("{e:?}")))?;
            if v.len() != count {
                return Err(Dn07Error::LengthMismatch {
                    what: "GF DN07 triple PRSS draw",
                    expected: count,
                    got: v.len(),
                });
            }
            Ok(v)
        };

        let a = draw(base)?;
        let b = draw(base + count)?;
        let doubles = self.double_shares_at(pre_sid, base + 2 * count, count)?;
        Ok(GfTripleMaterial { a, b, doubles })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::gf2k::field::Gf256;
    use crate::common::gf2k::share::GfShare as GfS;
    use crate::common::{ProtocolSessionId, SecretSharingScheme};
    use crate::honeybadger::prss::prss::{all_tsets, held_ranks};
    use crate::honeybadger::prss::PRSS_KEY_LEN;
    use crate::honeybadger::{ProtocolType, SessionId};
    use ark_bls12_381::Fr;
    use ark_ff::Zero;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    /// One shared key per unqualified set, handed to every party outside that set — the same
    /// shape `setup_prss_keys` establishes over the network.
    fn key_family(n: usize, t: usize) -> Vec<[u8; PRSS_KEY_LEN]> {
        let mut rng = StdRng::seed_from_u64(0xD0_07);
        (0..all_tsets(n, t).len())
            .map(|_| {
                let mut k = [0u8; PRSS_KEY_LEN];
                rng.fill(&mut k);
                k
            })
            .collect()
    }

    fn party_keys(
        n: usize,
        t: usize,
        id: usize,
        family: &[[u8; PRSS_KEY_LEN]],
    ) -> Vec<(usize, [u8; PRSS_KEY_LEN])> {
        held_ranks(n, t, id)
            .into_iter()
            .map(|r| (r, family[r]))
            .collect()
    }

    fn sid() -> PreprocessingSessionId {
        PreprocessingSessionId::new(SessionId::new(
            ProtocolType::Dn07,
            SessionId::pack_slot(1, 0, 0),
            7,
        ))
        .unwrap()
    }

    fn f_sources(n: usize, t: usize) -> Vec<PrssDoubleShareSource<Fr>> {
        let family = key_family(n, t);
        (0..n)
            .map(|id| {
                let keys = party_keys(n, t, id, &family);
                PrssDoubleShareSource::new(
                    PrssKeys::<Fr>::new(id, n, t, &keys).unwrap(),
                    PrzsKeys::<Fr>::new(id, n, t, &keys).unwrap(),
                )
                .unwrap()
            })
            .collect()
    }

    #[test]
    fn f_halves_agree_on_one_secret_and_carry_the_right_degrees() {
        let (n, t) = (10, 3);
        let sources = f_sources(n, t);
        let count = 4;

        let per_party: Vec<Vec<DoubleShamirShare<Fr>>> = sources
            .iter()
            .map(|s| s.double_shares_at(sid(), 0, count).unwrap())
            .collect();

        for nu in 0..count {
            let lo: Vec<RobustShare<Fr>> = (0..n)
                .map(|i| RobustShare::new(per_party[i][nu].degree_t.share[0], i, t))
                .collect();
            let hi: Vec<RobustShare<Fr>> = (0..n)
                .map(|i| RobustShare::new(per_party[i][nu].degree_2t.share[0], i, 2 * t))
                .collect();

            assert_eq!(per_party[0][nu].degree_t.degree, t);
            assert_eq!(per_party[0][nu].degree_2t.degree, 2 * t);

            let (_, r_lo) = RobustShare::recover_secret(&lo, n, t).unwrap();
            let (_, r_hi) = RobustShare::recover_secret(&hi, n, t).unwrap();
            assert_eq!(
                r_lo, r_hi,
                "the two halves of a double sharing must be the same secret"
            );
        }
    }

    #[test]
    fn f_the_degree_2t_half_really_needs_degree_2t() {
        // If the lift were degree t (i.e. if the PRZS mask were the zero polynomial, or if the
        // halves were accidentally identical) this would pass at degree t too. It must not: the
        // whole point of the second half is that it is a *different*, higher-degree polynomial
        // through the same constant term.
        let (n, t) = (10, 3);
        let sources = f_sources(n, t);
        let pairs: Vec<DoubleShamirShare<Fr>> = sources
            .iter()
            .map(|s| s.double_shares_at(sid(), 0, 1).unwrap().remove(0))
            .collect();
        assert!(
            (0..n).any(|i| pairs[i].degree_t.share[0] != pairs[i].degree_2t.share[0]),
            "the PRZS lift must actually move the shares"
        );
    }

    #[test]
    fn f_positions_are_independent() {
        let (n, t) = (7, 2);
        let sources = f_sources(n, t);
        let a = sources[0].double_shares_at(sid(), 0, 2).unwrap();
        assert_ne!(
            a[0].degree_t.share[0], a[1].degree_t.share[0],
            "two positions must not derive the same value"
        );
        // And a later window must agree with the big one at the same absolute positions.
        let b = sources[0].double_shares_at(sid(), 1, 1).unwrap();
        assert_eq!(a[1].degree_t.share[0], b[0].degree_t.share[0]);
        assert_eq!(a[1].degree_2t.share[0], b[0].degree_2t.share[0]);
    }

    #[test]
    fn f_the_uniform_stream_is_not_the_mask_stream() {
        // The hazard this guards: a uniform draw and a `shares_at` mask draw at the same
        // (session, position) reading overlapping bytes of one keystream. Distinct SP 800-108
        // labels make them independent families.
        let (n, t) = (7, 2);
        let family = key_family(n, t);
        let keys = party_keys(n, t, 0, &family);
        let prss = PrssKeys::<Fr>::new(0, n, t, &keys).unwrap();
        let uniform = prss.uniform_shares_at(sid().get(), 0, 1).unwrap();
        let masked = prss.shares_at(sid().get(), 0, 1, 40).unwrap();
        assert_ne!(uniform[0].share[0], masked[0].share[0]);
    }

    // ---- RandBit's PRSS/PRZS material -------------------------------------------------------
    //
    // `randbit_material*` is the GAP-3 entry point: `RandBit`'s `[a]` and its degree-`2t`
    // re-randomiser, taken from one key family at zero rounds and zero bytes, replacing a dealt
    // `RanSha` share and a dealt `ZeroSha` sharing per output bit.

    fn allocators(sources: &[PrssDoubleShareSource<Fr>]) -> Vec<PrssAllocator> {
        // One allocator per party, each stamped with that party's own key-family fingerprint.
        // The fingerprint is deliberately per-party (every party holds a different `C(n-1,t)`
        // subset), because its job is local: "is this window counted against the keys I am about
        // to derive with?" Positions still agree across parties, because every allocator starts
        // at zero and every party claims in the same order.
        sources
            .iter()
            .map(|s| PrssAllocator::new(7, s.key_family_id()))
            .collect()
    }

    #[tokio::test]
    async fn randbit_material_gives_a_degree_t_value_and_an_independent_degree_2t_zero() {
        let (n, t) = (10, 3);
        let sources = f_sources(n, t);
        let allocs = allocators(&sources);
        let count = 4;

        let mut per_party: Vec<(Vec<RobustShare<Fr>>, Vec<RobustShare<Fr>>)> = Vec::new();
        for (s, a) in sources.iter().zip(&allocs) {
            per_party.push(s.randbit_material(a, count).await.unwrap());
        }

        for nu in 0..count {
            let a: Vec<RobustShare<Fr>> = (0..n)
                .map(|i| RobustShare::new(per_party[i].0[nu].share[0], i, t))
                .collect();
            let z: Vec<RobustShare<Fr>> = (0..n)
                .map(|i| RobustShare::new(per_party[i].1[nu].share[0], i, 2 * t))
                .collect();

            // Degrees are what MulPub checks: `[a]` at `t`, the re-randomiser at exactly `2t`.
            assert_eq!(per_party[0].0[nu].degree, t);
            assert_eq!(per_party[0].1[nu].degree, 2 * t);

            // The zero sharing opens to zero *structurally* — every PRZS basis polynomial carries
            // a factor `X` — so it moves the opened `a^2` not at all while still randomising the
            // degree-`2t` polynomial the parties actually send.
            let (_, zero) = RobustShare::recover_secret(&z, n, t).unwrap();
            assert!(zero.is_zero(), "the re-randomiser must open to zero");

            // And `[a]` is a real, non-degenerate sharing.
            let (_, a_val) = RobustShare::recover_secret(&a, n, t).unwrap();
            assert!(!a_val.is_zero());
        }

        // Distinct positions give distinct values; if they did not, RandBit would hand out the
        // same bit repeatedly.
        let a_vals: std::collections::BTreeSet<_> =
            (0..count).map(|nu| per_party[0].0[nu].share[0]).collect();
        assert_eq!(a_vals.len(), count);
    }

    #[tokio::test]
    async fn randbit_material_is_not_the_double_sharing() {
        // The distinction the doc comment insists on, asserted rather than described:
        // `double_shares_at` sums the PRSS and PRZS halves onto one secret; `randbit_material`
        // keeps them apart, because a mask that is a function of `a` masks nothing.
        let (n, t) = (7, 2);
        let sources = f_sources(n, t);
        let allocs = allocators(&sources);
        let (a, z) = sources[0].randbit_material(&allocs[0], 1).await.unwrap();
        assert_ne!(
            a[0].share[0] + z[0].share[0],
            a[0].share[0],
            "the zero half must actually move the degree-2t share"
        );
        assert!(!z[0].share[0].is_zero());
    }

    #[tokio::test]
    async fn randbit_material_refuses_a_window_from_another_key_family() {
        // A window's position count is only meaningful against the keys it was counted for. A
        // node that resumed under stale keys with a zeroed allocator would have to pass this.
        let (n, t) = (7, 2);
        let sources = f_sources(n, t);
        let foreign = PrssAllocator::new(7, [0u8; 32]);
        let err = sources[0].randbit_material(&foreign, 1).await.unwrap_err();
        assert!(matches!(err, Dn07Error::KeyFamilyMismatch), "got {err:?}");
    }

    #[tokio::test]
    async fn randbit_material_refuses_windows_wired_to_the_wrong_stream() {
        let (n, t) = (7, 2);
        let sources = f_sources(n, t);
        let family = sources[0].key_family_id();
        let a_win = PrssWindow::for_test(PrssStream::RandBitA, 0, 0, 1, 300, 7, family);
        let z_win = PrssWindow::for_test(PrssStream::RandBitZero, 0, 0, 1, 300, 7, family);
        // Swapped: the PRZS window offered as `[a]` and vice versa. Without the stream tag this
        // would derive happily, at two different strides on one address.
        let err = sources[0].randbit_material_at(&z_win, &a_win).unwrap_err();
        assert!(
            matches!(err, Dn07Error::WrongPrssStream { .. }),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn randbit_material_refuses_windows_of_different_lengths() {
        let (n, t) = (7, 2);
        let sources = f_sources(n, t);
        let family = sources[0].key_family_id();
        let a_win = PrssWindow::for_test(PrssStream::RandBitA, 0, 0, 4, 300, 7, family);
        let z_win = PrssWindow::for_test(PrssStream::RandBitZero, 0, 0, 3, 300, 7, family);
        assert!(matches!(
            sources[0].randbit_material_at(&a_win, &z_win).unwrap_err(),
            Dn07Error::LengthMismatch { .. }
        ));
    }

    /// **T3 — the attack the allocator exists to prevent.**
    ///
    /// A rewound cursor re-derives an already-opened position. PRSS is stateless and
    /// position-addressed, so the second derivation returns *the identical value*: the same `a`,
    /// hence the same `a^2` on the wire, hence the same bit. The second RandBit carries **zero**
    /// entropy, and nothing in an all-honest run notices — the protocol succeeds, the pool fills,
    /// every share is well-formed.
    ///
    /// This is why [`PrssWindow`] has no public constructor and is not `Clone`: outside
    /// `#[cfg(test)]` the two overlapping windows below cannot be built.
    #[tokio::test]
    async fn reusing_a_randbit_position_yields_the_same_bit_twice() {
        let (n, t) = (7, 2);
        let sources = f_sources(n, t);
        let family = sources[0].key_family_id();
        let a_bits = PrssDoubleShareSource::<Fr>::randbit_a_bits();
        let z_bits = PrssDoubleShareSource::<Fr>::randbit_zero_bits();

        let draw = |exec: u64, start: usize| {
            let aw = PrssWindow::for_test(PrssStream::RandBitA, exec, start, 1, a_bits, 7, family);
            let zw =
                PrssWindow::for_test(PrssStream::RandBitZero, exec, start, 1, z_bits, 7, family);
            sources[0].randbit_material_at(&aw, &zw).unwrap()
        };

        // Two batches at the SAME position — a rewind.
        let (a1, z1) = draw(0, 0);
        let (a2, z2) = draw(0, 0);
        assert_eq!(
            a1[0].share[0], a2[0].share[0],
            "position reuse must be exactly value reuse — that is the whole failure"
        );
        assert_eq!(a1[0].share[0] - a2[0].share[0], Fr::from(0u64));
        assert_eq!(z1[0].share[0], z2[0].share[0]);

        // Disjoint positions, under both schemes the allocator issues: a fresh exec, and a moved
        // start. Either separation is enough.
        let (a3, _) = draw(1, 0);
        let (a4, _) = draw(0, 1);
        assert_ne!(a1[0].share[0], a3[0].share[0]);
        assert_ne!(a1[0].share[0], a4[0].share[0]);
        assert_ne!(a3[0].share[0], a4[0].share[0]);
    }

    /// **T4 — the PRZS mask, measured on the RandBit path specifically.**
    ///
    /// `MulPub` opens `P(X) = phi_a(X)^2 + h(X)` at degree `2t`. The security argument in
    /// [`PrssDoubleShareSource::randbit_material_at`] turns on `h` covering the *non-constant*
    /// coefficients of that polynomial and only those: its constant term must be untouched (or
    /// the opened `a^2` would be wrong), and its other `2t` coefficients must move with the mask
    /// (or the adversary reads `beta_A` out of a coefficient the mask failed to reach, which with
    /// the public `a^2` determines the bit).
    ///
    /// Measured here by interpolating what the parties actually send, rather than inferred from
    /// the primitive's own dimension tests.
    #[tokio::test]
    async fn the_randbit_opening_is_masked_in_every_coefficient_but_the_constant() {
        use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
        let (n, t) = (4, 1);
        let sources = f_sources(n, t);
        let family: Vec<[u8; 32]> = sources.iter().map(|s| s.key_family_id()).collect();
        let a_bits = PrssDoubleShareSource::<Fr>::randbit_a_bits();
        let z_bits = PrssDoubleShareSource::<Fr>::randbit_zero_bits();
        let domain = GeneralEvaluationDomain::<Fr>::new(n).unwrap();

        // The degree-2t polynomial the parties open, for a fixed `[a]` and a chosen mask position.
        let opened = |zero_exec: u64| -> Vec<Fr> {
            let evals: Vec<Fr> = (0..n)
                .map(|i| {
                    let aw =
                        PrssWindow::for_test(PrssStream::RandBitA, 0, 0, 1, a_bits, 7, family[i]);
                    let zw = PrssWindow::for_test(
                        PrssStream::RandBitZero,
                        zero_exec,
                        0,
                        1,
                        z_bits,
                        7,
                        family[i],
                    );
                    let (a, z) = sources[i].randbit_material_at(&aw, &zw).unwrap();
                    a[0].share[0] * a[0].share[0] + z[0].share[0]
                })
                .collect();
            domain.ifft(&evals)
        };

        let p0 = opened(0);
        let p1 = opened(1);

        // The constant term is `a^2` and is the same under both masks: the re-randomiser must not
        // move the value being opened.
        assert_eq!(p0[0], p1[0], "the mask moved the opened value");
        let a_shares: Vec<RobustShare<Fr>> = (0..n)
            .map(|i| {
                let aw = PrssWindow::for_test(PrssStream::RandBitA, 0, 0, 1, a_bits, 7, family[i]);
                let zw =
                    PrssWindow::for_test(PrssStream::RandBitZero, 0, 0, 1, z_bits, 7, family[i]);
                let (a, _) = sources[i].randbit_material_at(&aw, &zw).unwrap();
                RobustShare::new(a[0].share[0], i, t)
            })
            .collect();
        let (_, a_val) = RobustShare::recover_secret(&a_shares, n, t).unwrap();
        assert_eq!(p0[0], a_val * a_val, "the opened constant term must be a^2");

        // Every other coefficient up to degree `2t` moves with the mask. A coefficient that did
        // not would be a residual the adversary reads `beta_A` out of.
        for l in 1..=2 * t {
            assert_ne!(
                p0[l], p1[l],
                "coefficient {l} of the opened polynomial is not covered by the PRZS mask"
            );
        }
        // Above degree `2t` the polynomial is identically zero, which is the statement that the
        // mask adds no degree of its own beyond what `a^2` already has.
        for l in (2 * t + 1)..n {
            assert!(p0[l].is_zero() && p1[l].is_zero());
        }
    }

    #[test]
    fn the_source_refuses_a_przs_store_that_is_not_t_dimensional() {
        // The tightness argument needs exactly `t` free coefficients: `t - 1` leaves the
        // adversary one unmasked linear equation in `beta_A`, which with the public `a^2`
        // determines the bit. `PrzsKeys::new` cannot build such a store, so this asserts the
        // last line of defence — the cross-check inside `PrssDoubleShareSource::new` — still
        // agrees with `PrzsKeys`' own invariant for every `t` RandBit runs at.
        // Stops at `n = 10`: `f_sources` rebuilds every party's Lagrange basis, and `C(12,4)`
        // sets at `n = 13` costs more suite time than the extra data point is worth.
        for (n, t) in [(4usize, 1usize), (7, 2), (10, 3)] {
            let source = &f_sources(n, t)[0];
            assert_eq!(source.threshold(), t);
        }
    }

    #[test]
    fn f_mismatched_stores_are_refused() {
        let (n, t) = (7, 2);
        let family = key_family(n, t);
        let prss = PrssKeys::<Fr>::new(0, n, t, &party_keys(n, t, 0, &family)).unwrap();
        let przs = PrzsKeys::<Fr>::new(1, n, t, &party_keys(n, t, 1, &family)).unwrap();
        assert!(matches!(
            PrssDoubleShareSource::new(prss, przs).unwrap_err(),
            Dn07Error::KeyStoreMismatch { .. }
        ));
    }

    fn gf_sources(n: usize, t: usize) -> Vec<GfPrssDoubleShareSource<Gf256>> {
        let family = key_family(n, t);
        (0..n)
            .map(|id| {
                let keys = party_keys(n, t, id, &family);
                GfPrssDoubleShareSource::new(
                    GfPrssKeys::<Gf256>::new(id, n, t, &keys).unwrap(),
                    GfPrzsKeys::<Gf256>::new(id, n, t, &keys).unwrap(),
                )
                .unwrap()
            })
            .collect()
    }

    #[test]
    fn gf_halves_agree_on_one_secret_and_carry_the_right_degrees() {
        let (n, t) = (10, 3);
        let sources = gf_sources(n, t);
        let count = 4;
        let per_party: Vec<Vec<GfDoubleShamirShare<Gf256>>> = sources
            .iter()
            .map(|s| s.double_shares_at(sid(), 0, count).unwrap())
            .collect();

        for nu in 0..count {
            let lo: Vec<GfS<Gf256>> = (0..n)
                .map(|i| GfS::new(per_party[i][nu].degree_t.share, i, t))
                .collect();
            let hi: Vec<GfS<Gf256>> = (0..n)
                .map(|i| GfS::new(per_party[i][nu].degree_2t.share, i, 2 * t))
                .collect();
            assert_eq!(per_party[0][nu].degree_t.degree, t);
            assert_eq!(per_party[0][nu].degree_2t.degree, 2 * t);
            assert_eq!(
                GfS::recover_secret(&lo, n, t).unwrap().1,
                GfS::recover_secret(&hi, n, t).unwrap().1,
                "the two halves of a GF double sharing must be the same secret"
            );
        }
    }

    #[test]
    fn gf_the_lift_actually_moves_the_shares() {
        let (n, t) = (10, 3);
        let sources = gf_sources(n, t);
        let pairs: Vec<GfDoubleShamirShare<Gf256>> = sources
            .iter()
            .map(|s| s.double_shares_at(sid(), 0, 1).unwrap().remove(0))
            .collect();
        assert!((0..n).any(|i| pairs[i].degree_t.share != pairs[i].degree_2t.share));
    }

    #[test]
    fn gf_mismatched_stores_are_refused() {
        let (n, t) = (7, 2);
        let family = key_family(n, t);
        let prss = GfPrssKeys::<Gf256>::new(0, n, t, &party_keys(n, t, 0, &family)).unwrap();
        // A store built at a different threshold holds a different number of keys.
        let przs =
            GfPrzsKeys::<Gf256>::new(0, 10, 3, &party_keys(10, 3, 0, &key_family(10, 3))).unwrap();
        assert!(matches!(
            GfPrssDoubleShareSource::new(prss, przs).unwrap_err(),
            Dn07Error::KeyStoreMismatch { .. }
        ));
    }

    // ---- GAP 1: the windowed entry points the two production DN07 callers use ---------------
    //
    // `gf_triple_gen` and the edaBit modulus-overflow filter both claim `PrssStream::GfDn07Double`
    // now. They are two consumers of **one** keystream, which is sound only because they claim
    // from one allocator; the tests below pin both halves of that.

    fn gf_allocators(sources: &[GfPrssDoubleShareSource<Gf256>]) -> Vec<PrssAllocator> {
        sources
            .iter()
            .map(|s| PrssAllocator::new(7, s.key_family_id()))
            .collect()
    }

    /// The coupling that lets one allocator govern both domains: `setup_prss_keys` builds the `F`
    /// and `K` stores from one key list, and the allocator is stamped with the `F` store's
    /// fingerprint. If these two digests ever diverged, every `K`-side window would be rejected as
    /// a family mismatch — a loud failure, but one this assertion catches at the source.
    #[test]
    fn the_two_domains_report_the_same_key_family() {
        let (n, t) = (7, 2);
        let family = key_family(n, t);
        let keys = party_keys(n, t, 0, &family);
        let f = PrssKeys::<Fr>::new(0, n, t, &keys).unwrap();
        let k = GfPrssKeys::<Gf256>::new(0, n, t, &keys).unwrap();
        assert_eq!(f.key_family_id(), k.key_family_id());
        // And a different party's store is a different family: the fingerprint is local, and must
        // never be compared across parties or put on the wire.
        let other = GfPrssKeys::<Gf256>::new(1, n, t, &party_keys(n, t, 1, &family)).unwrap();
        assert_ne!(k.key_family_id(), other.key_family_id());
    }

    #[tokio::test]
    async fn gf_double_shares_are_a_genuine_double_sharing_and_agree_across_parties() {
        let (n, t) = (10, 3);
        let sources = gf_sources(n, t);
        let allocs = gf_allocators(&sources);
        let count = 3;

        let mut per_party = Vec::new();
        for (s, a) in sources.iter().zip(&allocs) {
            per_party.push(s.double_shares(a, count).await.unwrap());
        }

        // Every party claimed first, so every party is on the same window: the shares interpolate.
        for nu in 0..count {
            let lo: Vec<GfS<Gf256>> = (0..n)
                .map(|i| GfS::new(per_party[i][nu].degree_t.share, i, t))
                .collect();
            let hi: Vec<GfS<Gf256>> = (0..n)
                .map(|i| GfS::new(per_party[i][nu].degree_2t.share, i, 2 * t))
                .collect();
            assert_eq!(
                GfS::recover_secret(&lo, n, t).unwrap().1,
                GfS::recover_secret(&hi, n, t).unwrap().1
            );
        }
    }

    /// **The bug this change had to fix before it could add a second consumer.**
    ///
    /// GF triple generation used to mint its own `GfDn07`-tagged session from
    /// `gf_ran_dou_sha_counter`, which was monotone and therefore fine while it was the *only*
    /// consumer of `PrssStream::GfDn07Double`. The edaBit filter is now a second consumer. Two
    /// independent monotone counters on one keystream are individually monotone and jointly
    /// colliding — both start at zero — and a collision means one `[r]` masks two different
    /// degree-`2t` openings.
    ///
    /// Through the allocator, two consecutive claims cannot land on one position no matter which
    /// caller makes them.
    #[tokio::test]
    async fn two_gf_dn07_consumers_on_one_allocator_never_share_a_position() {
        let (n, t) = (7, 2);
        let sources = gf_sources(n, t);
        let allocs = gf_allocators(&sources);

        // "GF triple generation" claims, then "the edaBit filter" claims, on the same allocator.
        let triples = sources[0].double_shares(&allocs[0], 2).await.unwrap();
        let filter = sources[0].double_shares(&allocs[0], 2).await.unwrap();

        let seen: std::collections::BTreeSet<_> = triples
            .iter()
            .chain(filter.iter())
            .map(|p| p.degree_t.share.0)
            .collect();
        assert_eq!(seen.len(), 4, "four claims must be four distinct sharings");

        // The failure mode, written down: two *separate* counters both starting at zero.
        let their_own_counter = PrssAllocator::new(7, sources[0].key_family_id());
        let collided = sources[0]
            .double_shares(&their_own_counter, 2)
            .await
            .unwrap();
        assert_eq!(
            collided[0].degree_t.share, triples[0].degree_t.share,
            "a second allocator over one key family re-issues position zero — this is the fork \
             the single allocator exists to make unreachable"
        );
    }

    #[tokio::test]
    async fn gf_double_shares_refuse_a_foreign_key_family() {
        let (n, t) = (7, 2);
        let sources = gf_sources(n, t);
        let foreign = PrssAllocator::new(7, [0u8; 32]);
        let err = sources[0].double_shares(&foreign, 1).await.unwrap_err();
        assert!(matches!(err, Dn07Error::KeyFamilyMismatch), "got {err:?}");
    }

    #[test]
    fn gf_double_shares_refuse_a_window_on_another_stream() {
        let (n, t) = (7, 2);
        let sources = gf_sources(n, t);
        let family = sources[0].key_family_id();
        let bits = GfPrssDoubleShareSource::<Gf256>::double_bits().unwrap();
        // The `F`-side DN07 stream offered to the `K`-side source. Same shape, different
        // keystream, and without the tag it would derive happily.
        let wrong = PrssWindow::for_test(PrssStream::Dn07Double, 0, 0, 1, bits, 7, family);
        assert!(matches!(
            sources[0].double_shares_in(&wrong).unwrap_err(),
            Dn07Error::WrongPrssStream { .. }
        ));
    }

    /// Position reuse is value reuse on the GF side too, and an all-honest run cannot see it: the
    /// filter's AND layers succeed, the edaBits compose, and two different degree-`2t` openings
    /// went out under one mask.
    #[test]
    fn reusing_a_gf_dn07_position_reuses_the_mask() {
        let (n, t) = (7, 2);
        let sources = gf_sources(n, t);
        let family = sources[0].key_family_id();
        let bits = GfPrssDoubleShareSource::<Gf256>::double_bits().unwrap();
        let draw = |exec: u64, start: usize| {
            let w = PrssWindow::for_test(PrssStream::GfDn07Double, exec, start, 1, bits, 7, family);
            sources[0].double_shares_in(&w).unwrap()
        };
        let first = draw(0, 0);
        let again = draw(0, 0);
        assert_eq!(first[0].degree_t.share, again[0].degree_t.share);
        assert_eq!(first[0].degree_2t.share, again[0].degree_2t.share);

        // Either separation the allocator offers is enough.
        assert_ne!(first[0].degree_t.share, draw(1, 0)[0].degree_t.share);
        assert_ne!(first[0].degree_t.share, draw(0, 1)[0].degree_t.share);
    }

    // ---- GAP 4: a GF Beaver triple's whole input set, from PRSS ----------------------------
    //
    // `[a]` and `[b]` used to be dealt `GfRanSha` while only the doubles were derived, which
    // priced a GF triple at `2 x R1 + O2` instead of `O2`. These pin the replacement: three
    // independent secrets out of one window, and the same allocator the filter draws from.

    #[tokio::test]
    async fn gf_triple_material_draws_a_b_and_r_at_three_disjoint_positions() {
        let (n, t) = (10, 3);
        let sources = gf_sources(n, t);
        let allocs = gf_allocators(&sources);
        let count = 3;

        let mut per_party = Vec::new();
        for (s, a) in sources.iter().zip(&allocs) {
            per_party.push(s.triple_material(a, count).await.unwrap());
        }

        for nu in 0..count {
            let a: Vec<GfS<Gf256>> = (0..n)
                .map(|i| GfS::new(per_party[i].a[nu].share, i, t))
                .collect();
            let b: Vec<GfS<Gf256>> = (0..n)
                .map(|i| GfS::new(per_party[i].b[nu].share, i, t))
                .collect();
            let lo: Vec<GfS<Gf256>> = (0..n)
                .map(|i| GfS::new(per_party[i].doubles[nu].degree_t.share, i, t))
                .collect();
            let hi: Vec<GfS<Gf256>> = (0..n)
                .map(|i| GfS::new(per_party[i].doubles[nu].degree_2t.share, i, 2 * t))
                .collect();

            // Every party claimed first and in the same order, so all four interpolate.
            let a_val = GfS::recover_secret(&a, n, t).unwrap().1;
            let b_val = GfS::recover_secret(&b, n, t).unwrap().1;
            let r_lo = GfS::recover_secret(&lo, n, t).unwrap().1;
            let r_hi = GfS::recover_secret(&hi, n, t).unwrap().1;

            // The double sharing is genuine...
            assert_eq!(r_lo, r_hi);
            // ...and `a`, `b` and `r` are three different secrets. If any two coincided the
            // triple would leak: `a = r` makes the opened `ab - r` a function the adversary can
            // invert once it learns one of them.
            assert_ne!(a_val, b_val);
            assert_ne!(a_val, r_lo);
            assert_ne!(b_val, r_lo);

            // And the degrees `GfTripleGenNode::init_batch` will multiply at.
            assert_eq!(per_party[0].a[nu].degree, t);
            assert_eq!(per_party[0].b[nu].degree, t);
            assert_eq!(per_party[0].doubles[nu].degree_2t.degree, 2 * t);
        }
    }

    /// The three thirds are exactly `[0, count)`, `[count, 2count)` and `[2count, 3count)` of one
    /// window, not three separate claims. Pinned against the underlying derivation so that a
    /// future refactor that re-slices them has to say so.
    #[test]
    fn gf_triple_material_thirds_are_the_documented_sub_ranges() {
        let (n, t) = (7, 2);
        let sources = gf_sources(n, t);
        let family = sources[0].key_family_id();
        let bits = GfPrssDoubleShareSource::<Gf256>::double_bits().unwrap();
        let count = 2;
        let window =
            PrssWindow::for_test(PrssStream::GfDn07Double, 5, 0, 3 * count, bits, 7, family);
        let material = sources[0].triple_material_in(&window).unwrap();
        let sid = window.session_id();

        let direct_a = sources[0].prss.uniform_shares_at(sid, 0, count).unwrap();
        let direct_b = sources[0]
            .prss
            .uniform_shares_at(sid, count, count)
            .unwrap();
        let direct_r = sources[0]
            .double_shares_at(PreprocessingSessionId::new(sid).unwrap(), 2 * count, count)
            .unwrap();
        for nu in 0..count {
            assert_eq!(material.a[nu].share, direct_a[nu].share);
            assert_eq!(material.b[nu].share, direct_b[nu].share);
            assert_eq!(
                material.doubles[nu].degree_2t.share,
                direct_r[nu].degree_2t.share
            );
        }
    }

    #[test]
    fn gf_triple_material_refuses_a_window_that_is_not_three_positions_per_triple() {
        let (n, t) = (7, 2);
        let sources = gf_sources(n, t);
        let family = sources[0].key_family_id();
        let bits = GfPrssDoubleShareSource::<Gf256>::double_bits().unwrap();
        let window = PrssWindow::for_test(PrssStream::GfDn07Double, 0, 0, 4, bits, 7, family);
        assert!(matches!(
            sources[0].triple_material_in(&window).unwrap_err(),
            Dn07Error::LengthMismatch { .. }
        ));
    }

    #[test]
    fn gf_triple_material_refuses_a_window_on_another_stream() {
        let (n, t) = (7, 2);
        let sources = gf_sources(n, t);
        let family = sources[0].key_family_id();
        let bits = GfPrssDoubleShareSource::<Gf256>::double_bits().unwrap();
        // The `F`-side DN07 stream offered to the `K`-side source: same shape, different
        // keystream, and without the tag it would derive happily.
        let wrong = PrssWindow::for_test(PrssStream::Dn07Double, 0, 0, 3, bits, 7, family);
        assert!(matches!(
            sources[0].triple_material_in(&wrong).unwrap_err(),
            Dn07Error::WrongPrssStream { .. }
        ));
    }

    #[tokio::test]
    async fn gf_triple_material_refuses_a_foreign_key_family() {
        let (n, t) = (7, 2);
        let sources = gf_sources(n, t);
        let foreign = PrssAllocator::new(7, [0u8; 32]);
        let err = sources[0].triple_material(&foreign, 1).await.unwrap_err();
        assert!(matches!(err, Dn07Error::KeyFamilyMismatch), "got {err:?}");
    }

    /// **The reason `[a]`/`[b]` had to come off the allocator rather than a counter of the triple
    /// path's own.** GF triple material and the edaBit filter's doubles are two consumers of one
    /// keystream; through the single allocator a `3 * count` claim and a `count` claim cannot
    /// address a shared position, whichever order they come in.
    ///
    /// Asserted on the *windows*, not on the derived values: `Gf256` has 256 elements, so a
    /// handful of independent draws collide by birthday often enough that value-distinctness
    /// would be testing the field's size rather than the allocator's discipline.
    #[tokio::test]
    async fn gf_triple_material_and_the_filter_claim_disjoint_windows() {
        let (n, t) = (7, 2);
        let sources = gf_sources(n, t);
        let alloc = PrssAllocator::new(7, sources[0].key_family_id());
        let bits = GfPrssDoubleShareSource::<Gf256>::double_bits().unwrap();

        // "GF triple generation" claims three positions per triple, then "the edaBit filter"
        // claims its doubles — one allocator, one keystream, one cursor.
        let triple_w = alloc
            .claim(PrssStream::GfDn07Double, 3 * 2, bits)
            .await
            .unwrap();
        let filter_w = alloc
            .claim(PrssStream::GfDn07Double, 4, bits)
            .await
            .unwrap();

        assert_eq!(triple_w.stream(), filter_w.stream());
        // `GfDn07Double` is a fresh-exec stream, so the separation is by session; the offset
        // clause is there so that a future change of that policy still leaves this test meaning
        // what it says.
        assert!(
            triple_w.session_id() != filter_w.session_id()
                || triple_w.start() + triple_w.len() <= filter_w.start()
                || filter_w.start() + filter_w.len() <= triple_w.start(),
            "two claims off one allocator addressed overlapping positions of one session"
        );

        // And the material really does derive out of the window it was handed.
        let material = sources[0].triple_material_in(&triple_w).unwrap();
        assert_eq!(material.a.len(), 2);
        assert_eq!(material.b.len(), 2);
        assert_eq!(material.doubles.len(), 2);

        // The failure mode this exists to make unreachable, written down: a second cursor over
        // the same key family re-issues position zero. An equality, so the field's size cannot
        // make it pass by accident.
        let its_own_counter = PrssAllocator::new(7, sources[0].key_family_id());
        let collided = sources[0]
            .triple_material(&its_own_counter, 2)
            .await
            .unwrap();
        let fresh = PrssAllocator::new(7, sources[0].key_family_id());
        let twin = sources[0].triple_material(&fresh, 2).await.unwrap();
        assert_eq!(
            collided.a[0].share, twin.a[0].share,
            "a second allocator over one key family re-issues position zero — this is the fork \
             the single allocator exists to make unreachable"
        );
    }

    /// Consecutive GF triple batches are different derivations, so an `[a]` is never a mask the
    /// adversary has already seen spent.
    ///
    /// Compared as whole vectors rather than as a set of values, for the `Gf256` birthday reason
    /// above: two six-element draws over a 256-element field share *a* value often, and share
    /// every value only if they are the same derivation.
    #[tokio::test]
    async fn consecutive_gf_triple_batches_are_different_derivations() {
        let (n, t) = (7, 2);
        let sources = gf_sources(n, t);
        let allocs = gf_allocators(&sources);
        let first = sources[0].triple_material(&allocs[0], 3).await.unwrap();
        let second = sources[0].triple_material(&allocs[0], 3).await.unwrap();

        let vals = |m: &GfTripleMaterial<Gf256>| -> Vec<u8> {
            m.a.iter()
                .chain(m.b.iter())
                .map(|v| v.share.0)
                .chain(m.doubles.iter().map(|p| p.degree_t.share.0))
                .collect()
        };
        assert_ne!(vals(&first), vals(&second));

        // A rewound cursor, on the other hand, reproduces the batch exactly.
        let rewound = PrssAllocator::new(7, sources[0].key_family_id());
        let again = sources[0].triple_material(&rewound, 3).await.unwrap();
        let fresh = PrssAllocator::new(7, sources[0].key_family_id());
        let twin = sources[0].triple_material(&fresh, 3).await.unwrap();
        assert_eq!(vals(&again), vals(&twin));
    }

    // ---- GAP 1, `F` side: a Beaver triple's whole input set, from PRSS -----------------------

    #[tokio::test]
    async fn triple_material_draws_a_b_and_r_at_three_disjoint_positions() {
        let (n, t) = (7, 2);
        let sources = f_sources(n, t);
        let allocs = allocators(&sources);
        let count = 3;

        let mut per_party = Vec::new();
        for (s, a) in sources.iter().zip(&allocs) {
            per_party.push(s.triple_material(a, count).await.unwrap());
        }

        for nu in 0..count {
            let a: Vec<RobustShare<Fr>> = (0..n)
                .map(|i| RobustShare::new(per_party[i].a[nu].share[0], i, t))
                .collect();
            let b: Vec<RobustShare<Fr>> = (0..n)
                .map(|i| RobustShare::new(per_party[i].b[nu].share[0], i, t))
                .collect();
            let lo: Vec<RobustShare<Fr>> = (0..n)
                .map(|i| RobustShare::new(per_party[i].doubles[nu].degree_t.share[0], i, t))
                .collect();
            let hi: Vec<RobustShare<Fr>> = (0..n)
                .map(|i| RobustShare::new(per_party[i].doubles[nu].degree_2t.share[0], i, 2 * t))
                .collect();

            let (_, a_val) = RobustShare::recover_secret(&a, n, t).unwrap();
            let (_, b_val) = RobustShare::recover_secret(&b, n, t).unwrap();
            let (_, r_lo) = RobustShare::recover_secret(&lo, n, t).unwrap();
            let (_, r_hi) = RobustShare::recover_secret(&hi, n, t).unwrap();

            // The double sharing is genuine...
            assert_eq!(r_lo, r_hi);
            // ...and `a`, `b` and `r` are three different secrets. If any two coincided the
            // triple would leak: `a = r` makes the opened `ab - r` a function the adversary can
            // invert once it learns one of them.
            assert_ne!(a_val, b_val);
            assert_ne!(a_val, r_lo);
            assert_ne!(b_val, r_lo);
            assert_eq!(per_party[0].a[nu].degree, t);
            assert_eq!(per_party[0].doubles[nu].degree_2t.degree, 2 * t);
        }
    }

    /// The three thirds are exactly `[0, count)`, `[count, 2count)` and `[2count, 3count)` of one
    /// window, not three separate claims. Pinned against the underlying derivation so that a
    /// future refactor that re-slices them has to say so.
    #[tokio::test]
    async fn triple_material_thirds_are_the_documented_sub_ranges() {
        let (n, t) = (7, 2);
        let sources = f_sources(n, t);
        let family = sources[0].key_family_id();
        let bits = PrssDoubleShareSource::<Fr>::double_bits();
        let count = 2;
        let window = PrssWindow::for_test(PrssStream::Dn07Double, 5, 0, 3 * count, bits, 7, family);
        let material = sources[0].triple_material_in(&window).unwrap();
        let sid = window.session_id();

        let direct_a = sources[0].prss.uniform_shares_at(sid, 0, count).unwrap();
        let direct_b = sources[0]
            .prss
            .uniform_shares_at(sid, count, count)
            .unwrap();
        for nu in 0..count {
            assert_eq!(material.a[nu].share[0], direct_a[nu].share[0]);
            assert_eq!(material.b[nu].share[0], direct_b[nu].share[0]);
        }
        let direct_r = sources[0]
            .double_shares_at(PreprocessingSessionId::new(sid).unwrap(), 2 * count, count)
            .unwrap();
        for nu in 0..count {
            assert_eq!(
                material.doubles[nu].degree_2t.share[0],
                direct_r[nu].degree_2t.share[0]
            );
        }
    }

    #[test]
    fn triple_material_refuses_a_window_that_is_not_three_positions_per_triple() {
        let (n, t) = (7, 2);
        let sources = f_sources(n, t);
        let family = sources[0].key_family_id();
        let bits = PrssDoubleShareSource::<Fr>::double_bits();
        let window = PrssWindow::for_test(PrssStream::Dn07Double, 0, 0, 4, bits, 7, family);
        assert!(matches!(
            sources[0].triple_material_in(&window).unwrap_err(),
            Dn07Error::LengthMismatch { .. }
        ));
    }

    #[test]
    fn triple_material_refuses_a_window_on_another_stream() {
        let (n, t) = (7, 2);
        let sources = f_sources(n, t);
        let family = sources[0].key_family_id();
        let bits = PrssDoubleShareSource::<Fr>::double_bits();
        let wrong = PrssWindow::for_test(PrssStream::GfDn07Double, 0, 0, 3, bits, 7, family);
        assert!(matches!(
            sources[0].triple_material_in(&wrong).unwrap_err(),
            Dn07Error::WrongPrssStream { .. }
        ));
    }

    #[tokio::test]
    async fn triple_material_refuses_a_foreign_key_family() {
        let (n, t) = (7, 2);
        let sources = f_sources(n, t);
        let foreign = PrssAllocator::new(7, [0u8; 32]);
        assert!(matches!(
            sources[0].triple_material(&foreign, 1).await.unwrap_err(),
            Dn07Error::KeyFamilyMismatch
        ));
    }

    /// Consecutive triple batches are disjoint, so `a` never repeats across batches. A repeated
    /// `a` in a Beaver triple is a mask the adversary has already seen used.
    #[tokio::test]
    async fn consecutive_triple_batches_share_no_value() {
        let (n, t) = (7, 2);
        let sources = f_sources(n, t);
        let allocs = allocators(&sources);
        let first = sources[0].triple_material(&allocs[0], 2).await.unwrap();
        let second = sources[0].triple_material(&allocs[0], 2).await.unwrap();
        let seen: std::collections::BTreeSet<_> = first
            .a
            .iter()
            .chain(first.b.iter())
            .chain(second.a.iter())
            .chain(second.b.iter())
            .map(|s| s.share[0])
            .collect();
        assert_eq!(seen.len(), 8);
    }
}
