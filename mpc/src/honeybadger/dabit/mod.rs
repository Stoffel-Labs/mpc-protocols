//! Doubly-shared bits (daBits) — the single cross-domain primitive behind A2B and B2A.
//!
//! A daBit is a pair `([b]_F, [b]_K)` of degree-`t` sharings of the *same* bit `b`, one in the
//! prime field `F` and one in `GF(2^k)`. It is the only object in this crate that ties the two
//! domains together, and it ties them **by value**: the two halves share nothing but the party
//! index. [`crate::common::convert`] carries the same invariant at the level of clear values.
//!
//! # Construction
//!
//! [`prss_dabit::PrssDaBitNode`] generates them from CDI05 pseudorandom secret sharing plus one
//! Catrina–Saxena `Mod2` opening:
//!
//! 1. **One PRSS derivation, two conversions.** The same `C(n,t)` pseudorandom bits `β_T` convert
//!    to `[S]_F = Σ_T β_T` (an *integer* sum, because that map is `F`-linear) and to
//!    `[b]_K = ⊕_T β_T` (an XOR, because in characteristic 2 addition *is* XOR). Both are **zero
//!    rounds and zero bytes**, and the two agree modulo 2 by arithmetic rather than by protocol.
//! 2. **One `Mod2` opening** lifts `S mod 2` into `F`: a single degree-`t` batched opening and
//!    **zero multiplications**. See [`crate::honeybadger::mod2`].
//!
//! There is **no dealing anywhere**, and therefore no masked dealing, no XOR fold, no bit-ness
//! check, no coin, no permutation and no bucketing. The cross-domain soundness error is **0**, not
//! `M^-(B-1)`, and the share-type obligations T1 (domain), T2 (form) and T3 (value) all hold by
//! construction at zero certification cost — see the [`prss_dabit`] module docs for the table and
//! for the two costs this buys them with (computational rather than perfect privacy of the
//! preprocessing randomness, and a quantified lifetime daBit budget).
//!
//! edaBits are **composed from daBits locally** ([`EdaBit::compose`]); there is no native edaBit
//! generation, because `[r]_F = sum 2^i [b_i]_F` is free while a native candidate costs an
//! `(n-1)`-deep tree of binary adders. Full-range composition additionally needs the `r < p`
//! filter, which is [`edabit::EdaBitFilterNode`] — the only interactive certification left in this
//! stack.
//!
//! # Phase
//!
//! **PREPROCESSING** throughout. Every opening in this module tree is nevertheless at degree `t`
//! and is robust: the only abort trigger in the whole construction is the degree-`2t` `MulPub`
//! opening inside the `RandBit`s the daBit generator *consumes*, which is a pre-existing
//! preprocessing primitive rather than anything introduced here.
//!
//! # Liveness (documented, not fixed)
//!
//! daBit generation inherits the liveness posture of the preprocessing it consumes: `RandBit`
//! rides `MulPub`, whose degree-`2t` opening needs every honest share, so a crashed party stalls
//! it exactly as it already stalls RanSha and RanDouSha. Closing that gap needs agreement on a
//! core set of `>= 2t + 1` contributors (ACS); doing it for daBits alone while RanSha keeps the
//! same gap would be incoherent. It is deliberately out of scope, and it is not a regression.
//!
//! The generation step itself no longer waits for anyone: PRSS is local, and the `Mod2` opening is
//! degree-`t` robust, so it completes on `2t+1` honest shares with no timeout.

pub mod edabit;
pub mod prss_dabit;

use ark_ff::PrimeField;
use bincode::ErrorKind;
use serde::{Deserialize, Serialize};
use stoffelnet::network_utils::{NetworkError, PartyId};
use thiserror::Error;

use crate::{
    common::{
        convert::ConvertError,
        gf2k::{field::BinaryField, share::GfShare, Gf2kError},
        rbc::RbcError,
        share::ShareError,
    },
    honeybadger::{
        batch_recon::BatchReconError,
        dn07::Dn07Error,
        gf_batch_recon::GfBatchReconError,
        gf_mul::GfMulError,
        mul::MulError,
        robust_interpolate::{robust_interpolate::RobustShare, InterpolateError},
        SessionId,
    },
};

/// A doubly-shared bit: the same bit `b`, shared at degree `t` in both domains.
///
/// INVARIANT (C5/C20): `arith.id == bin.id` and both degrees equal `t`. The two ids index
/// *unrelated* point sets — `RobustShare::id` indexes the FFT evaluation domain while
/// `GfShare::id` indexes the powers of the `GF(2^k)` multiplicative generator — so only the party
/// index crosses between the domains, never an x-coordinate. [`DaBit::new`] is the only
/// constructor that enforces this, and every path that produces a daBit goes through it.
#[derive(Clone, Debug, PartialEq)]
pub struct DaBit<F: PrimeField, K: BinaryField> {
    /// Degree-`t` sharing of `b` as an element of `{0, 1} ⊂ F`.
    pub arith: RobustShare<F>,
    /// Degree-`t` sharing of `b` as an element of the canonical `GF(2)` subfield of `K`.
    pub bin: GfShare<K>,
}

impl<F: PrimeField, K: BinaryField> DaBit<F, K> {
    /// Pairs the two halves, refusing a cross-domain pair whose indices or degrees disagree.
    ///
    /// A mismatched index would silently pair this party's `F` share with another party's `K`
    /// share; a mismatched degree would make one half undecodable at the degree every consumer
    /// opens at. Both are caller bugs, but both are also exactly what a confused-deputy message
    /// path would produce, so they are rejected rather than asserted.
    pub fn new(
        arith: RobustShare<F>,
        bin: GfShare<K>,
        threshold: usize,
    ) -> Result<Self, DaBitError> {
        if arith.id != bin.id {
            return Err(DaBitError::IdMismatch);
        }
        if arith.degree != threshold || bin.degree != threshold {
            return Err(DaBitError::DegreeMismatch);
        }
        Ok(Self { arith, bin })
    }

    /// The party index both halves are indexed by.
    pub fn id(&self) -> usize {
        self.arith.id
    }
}

/// An extended doubly-shared bit: one arithmetic sharing of `r` together with the binary sharings
/// of its bits, LSB first.
///
/// `value` shares `r` **as an integer**, i.e. `r = sum_i 2^i * bits[i]` holds over the integers
/// and not merely modulo `p`. For `width < field_bit_width::<F>()` that is automatic; at full
/// width it is only true after the modulus-overflow filter has rejected `r >= p`, which is why
/// full-width composition goes through [`EdaBit::compose_full_width`] and takes the opened
/// overflow bit as an argument.
#[derive(Clone, Debug, PartialEq)]
pub struct EdaBit<F: PrimeField, K: BinaryField> {
    /// Degree-`t` sharing of `r = sum_i 2^i bits[i]` as an integer in `[0, p)`.
    pub value: RobustShare<F>,
    /// Degree-`t` binary sharings of the bits of `r`, LSB first. `bits.len() == width`.
    pub bits: Vec<GfShare<K>>,
    /// Number of bits. Always `<= field_bit_width::<F>()`.
    pub width: usize,
}

impl<F: PrimeField, K: BinaryField> EdaBit<F, K> {
    /// Composes an edaBit from `width` daBits, LSB first. Purely local: no communication, no
    /// preprocessing beyond the daBits themselves.
    ///
    /// Restricted to `width < field_bit_width::<F>()`, where `sum 2^i b_i <= 2^width - 1 <
    /// 2^(w-1) <= p` holds unconditionally and no filter is needed. Full-range composition — the
    /// one A2B consumes — goes through [`EdaBit::compose_full_width`], which cannot be called
    /// without the opened overflow bit.
    pub fn compose(dabits: &[DaBit<F, K>], width: usize) -> Result<Self, DaBitError> {
        let capacity = crate::common::convert::field_bit_width::<F>();
        if width == 0 {
            // C13: an empty bit vector makes every downstream verification loop pass vacuously.
            return Err(DaBitError::ZeroWidth);
        }
        if width >= capacity {
            return Err(DaBitError::WidthTooLarge {
                width,
                max: capacity.saturating_sub(1),
            });
        }
        Self::compose_inner(dabits, width)
    }

    /// Composes a **full-range** edaBit of `field_bit_width::<F>()` bits.
    ///
    /// `overflow` is the opened output of
    /// [`ModulusOverflowCircuit`](crate::honeybadger::binary_circuits::ModulusOverflowCircuit)
    /// on the same bits: `true` exactly when `sum 2^i b_i >= p`, in which case `value` would share
    /// `r mod p` rather than `r` and the edaBit must be discarded together with **all** of its
    /// daBits (the opened bit correlates with them).
    ///
    /// Skipping the filter is a correctness break, not a privacy one, and its rejection rate on
    /// Goldilocks is `(2^32 - 1) / 2^64 ≈ 2^-32` — far above any budget this crate tolerates.
    pub fn compose_full_width(dabits: &[DaBit<F, K>], overflow: bool) -> Result<Self, DaBitError> {
        if overflow {
            return Err(DaBitError::ModulusOverflow);
        }
        Self::compose_inner(dabits, crate::common::convert::field_bit_width::<F>())
    }

    fn compose_inner(dabits: &[DaBit<F, K>], width: usize) -> Result<Self, DaBitError> {
        // C13: exact length, never `>=` — a surplus daBit silently dropped here is a daBit
        // reused by the next composition, i.e. one-time-pad reuse.
        if dabits.len() != width {
            return Err(DaBitError::MaterialLengthMismatch {
                what: "edabit dabits",
                expected: width,
                got: dabits.len(),
            });
        }
        // `first()`, not `[0]`: the length check above already rules an empty slice out for
        // every reachable `width`, but a raw index here would be the only panic left in this
        // module if a future caller ever reached it with `width == 0` (C12).
        let head = dabits.first().ok_or(DaBitError::ZeroWidth)?;
        let id = head.arith.id;
        let degree = head.arith.degree;
        let mut value = RobustShare::new(F::zero(), id, degree);
        let mut bits = Vec::with_capacity(width);
        let mut weight = F::one();
        let two = F::one() + F::one();
        for dabit in dabits {
            if dabit.arith.id != id || dabit.bin.id != id {
                return Err(DaBitError::IdMismatch);
            }
            if dabit.arith.degree != degree || dabit.bin.degree != degree {
                return Err(DaBitError::DegreeMismatch);
            }
            value = (value + (dabit.arith.clone() * weight)?)?;
            bits.push(dabit.bin.clone());
            weight = weight * two;
        }
        Ok(Self { value, bits, width })
    }
}

/// Maximum concurrent child batch-reconstruction sessions before a peer's *per-peer* quota in
/// `BatchReconNode::get_or_create_store` (`MAX_BATCH_RECON_SESSIONS / n`) starts rejecting its
/// `Eval` messages — at which point those openings silently never complete.
///
/// Capping depth rather than raising the existing quota also bounds the 200-slot `mpsc` backlog
/// inside `Multiply`/`GfMultiply`, whose `send().await` runs inline on the single
/// message-handling path: a full channel stalls the whole node.
///
/// Lives here rather than in a protocol module because both [`edabit::EdaBitFilterNode`] and
/// `b2a` size their pipelines against it, and the two must not drift apart.
pub fn conv_pipeline_depth(n_parties: usize) -> usize {
    (crate::honeybadger::batch_recon::batch_recon::MAX_BATCH_RECON_SESSIONS / n_parties.max(1))
        .max(1)
}

/// Values opened in one batch-reconstruction session. Same bound as the multiplication track's
/// per-session pair count: both produce one field element per slot in a single eval/reveal
/// message pair, so the same figure keeps both well inside `MAX_MESSAGE_SIZE`.
pub(crate) fn max_values_per_open(threshold: usize) -> usize {
    crate::honeybadger::max_mul_pairs_per_session(threshold)
}

/// Payload of a [`DaBitMessage`].
///
/// # UNREACHABLE — retained for wire-format stability only
///
/// This payload belonged to the dealt daBit protocol, which PRSS daBits replaced: the generator is
/// now purely local plus one `Mod2` opening, and puts **nothing** of its own on the wire. The type
/// survives because `WrappedMessage` is an unversioned `bincode` enum in which variant *order* is
/// the wire format — deleting `WrappedMessage::DaBit` would silently renumber every variant after
/// it. The node dispatcher rejects the variant rather than routing it.
///
/// Both halves ride as separately-encoded **opaque blobs**: `ShamirShare` derives the `ark`
/// `Canonical(De)Serialize` traits while `GfShare` derives `serde`, so a single `serde` struct
/// holding both does not exist. This is the same split `MultMessage` / `GfMultMessage` already
/// uses. Every blob is deserialized with an explicit, locally-known length bound — never with a
/// peer-supplied length.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum DaBitPayload {
    /// Step 1a: this party's shares of dealer `j`'s masks, sent point-to-point to `j` only.
    ///
    /// `arith` is an `ark`-compressed `Vec<RobustShare<F>>`, `bin` a `bincode` `Vec<GfShare<K>>`.
    MaskShares { arith: Vec<u8>, bin: Vec<u8> },
    /// Step 1b, RBC'd by dealer `j`: the public affine shifts that turn the verified random masks
    /// into sharings of the dealer's candidate bits.
    ///
    /// `arith` is an `ark`-compressed `Vec<F>`, `bin` a `bincode` `Vec<K>`.
    Deltas { arith: Vec<u8>, bin: Vec<u8> },
}

impl DaBitPayload {
    /// Wire size of the two blobs, for the pending-queue byte budget (C9).
    pub fn byte_len(&self) -> usize {
        match self {
            DaBitPayload::MaskShares { arith, bin } | DaBitPayload::Deltas { arith, bin } => {
                arith.len().saturating_add(bin.len())
            }
        }
    }
}

/// Message of the retired dealt daBit protocol.
///
/// **UNREACHABLE.** See [`DaBitPayload`] for why the type still exists. No code sends one, and the
/// node dispatcher rejects any that arrives.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DaBitMessage {
    /// ID of the sender of the message.
    pub sender_id: PartyId,
    /// Session ID of the execution.
    pub session_id: SessionId,
    /// Contents of the message.
    pub payload: DaBitPayload,
}

impl DaBitMessage {
    pub fn new(sender_id: PartyId, session_id: SessionId, payload: DaBitPayload) -> Self {
        Self {
            sender_id,
            session_id,
            payload,
        }
    }
}

/// Errors raised by daBit generation.
///
/// Every variant is returned rather than panicked: each of the inputs that can trigger one is
/// reachable from the network, and an honest party must never be abortable by a peer (C12).
#[derive(Debug, Error)]
pub enum DaBitError {
    #[error("there was an error in the network: {0:?}")]
    NetworkError(#[from] NetworkError),
    #[error("error while serializing/deserializing bytes: {0:?}")]
    SerializationError(#[from] Box<ErrorKind>),
    #[error("error while serializing/deserializing field elements: {0:?}")]
    ArkSerialization(#[from] ark_serialize::SerializationError),
    #[error("Rbc error: {0:?}")]
    RbcError(#[from] RbcError),
    #[error("Share error: {0:?}")]
    ShareError(#[from] ShareError),
    #[error("interpolation error: {0:?}")]
    InterpolateError(#[from] InterpolateError),
    #[error("GF(2^k) error: {0:?}")]
    Gf2kError(#[from] Gf2kError),
    #[error("conversion error: {0:?}")]
    ConvertError(#[from] ConvertError),
    #[error("binary circuit error: {0:?}")]
    CircuitError(#[from] crate::honeybadger::binary_circuits::CircuitError),
    #[error("multiplication error: {0:?}")]
    MulError(#[from] MulError),
    #[error("GF(2^k) multiplication error: {0:?}")]
    GfMulError(#[from] GfMulError),
    /// The edaBit modulus-overflow filter's AND layers run on DN07 degree reduction, which is
    /// **preprocessing-only** and may abort. See [`crate::honeybadger::dn07`].
    #[error("DN07 error: {0:?}")]
    Dn07Error(#[from] Dn07Error),
    #[error("batch reconstruction error: {0:?}")]
    BatchReconError(#[from] BatchReconError),
    #[error("GF(2^k) batch reconstruction error: {0:?}")]
    GfBatchReconError(#[from] GfBatchReconError),
    #[error("error sending the result: {0:?}")]
    SendError(SessionId),
    #[error("error receiving the result: {0:?}")]
    ReceiveError(SessionId),
    #[error("daBit generation {0:?} did not complete in time")]
    Timeout(SessionId),
    #[error("received abort signal")]
    Abort,
    #[error("Party Id is out of bounds")]
    InvalidPartyId,
    #[error("session ID {0:?} malformed")]
    SessionIdError(SessionId),
    #[error("limit reached")]
    LimitError,
    #[error("no such session ID exists: {0:?}")]
    NoSuchSessionId(SessionId),
    #[error("result already received: {0:?}")]
    ResultAlreadyReceived(SessionId),
    #[error("share index mismatch across the two domains")]
    IdMismatch,
    #[error("share degree does not match the threshold")]
    DegreeMismatch,
    #[error("batch of {requested} outputs exceeds the maximum of {max}")]
    BatchTooLarge { requested: usize, max: usize },
    #[error("preprocessing material `{what}` has length {got}, expected {expected}")]
    MaterialLengthMismatch {
        what: &'static str,
        expected: usize,
        got: usize,
    },
    #[error("not enough conversion preprocessing: {0}")]
    NotEnoughMaterial(&'static str),
    /// A composed full-range edaBit had `r >= p`. Its daBits must all be discarded.
    #[error("composed mask is not less than the modulus")]
    ModulusOverflow,
    #[error("a zero-width edaBit was requested")]
    ZeroWidth,
    #[error("width {width} exceeds the maximum of {max}")]
    WidthTooLarge { width: usize, max: usize },
    #[error("unexpected payload for this message path")]
    UnexpectedPayload,
    #[error("statistical security parameter {requested} is below the minimum of {minimum}")]
    InsufficientStatisticalSecurity { requested: usize, minimum: usize },

    // ---- PRSS daBit generation -----------------------------------------------------------
    #[error("Mod2 error: {0:?}")]
    Mod2Error(#[from] crate::honeybadger::mod2::Mod2Error),
    #[error("PRSS error: {0:?}")]
    PrssError(#[from] crate::honeybadger::prss::PrssError),
    #[error("GF(2^k) PRSS error: {0:?}")]
    GfPrssError(#[from] crate::honeybadger::gf_prss::GfPrssError),
    /// `setup_prss_keys` has not run. A PRSS daBit has no dealt fallback by design — falling back
    /// would reintroduce every certification obligation the construction exists to delete — so
    /// this is an error rather than a slower path.
    #[error(
        "no PRSS key family installed: run setup_prss_keys before generating daBits. There is \
         deliberately no dealt fallback."
    )]
    PrssKeysMissing,
    #[error(
        "threshold t must be at least 1: at t = 0 every unqualified set is empty, C(n,0) = 1, and \
         the single PRSS seed is known to everyone"
    )]
    DegenerateThreshold,
    #[error("threshold t={t} must be smaller than n={n}")]
    ThresholdOutOfRange { n: usize, t: usize },
    #[error("C({n},{t}) exceeds the {max} unqualified sets this implementation will enumerate")]
    TooManyUnqualifiedSets { n: usize, t: usize, max: u128 },
    /// The field is too narrow to carry a Mod2 mask at this party count. Hard error, never a
    /// `warn!`: a zero-width mask makes the opened `c` reveal `S` outright.
    #[error(
        "a {modulus_bits}-bit modulus cannot carry a Mod2 mask alongside {set_bits} bits of \
         C(n,t) multiplicity"
    )]
    MaskWidthUnavailable {
        modulus_bits: usize,
        set_bits: usize,
    },
    /// `k` and `lambda` are one budget: both follow from the single no-wrap inequality, so
    /// changing either without re-checking the other silently breaks correctness.
    #[error("RandBit top-up k={requested} exceeds the maximum of ceil(log2 C(n,t)) - 1 = {max}")]
    TopUpTooLarge { requested: usize, max: usize },
    /// The derived `(lambda, k)` lets `S + 2r'' + r'_0` wrap `p`. `p` is odd, so a wrap flips the
    /// extracted bit — this is a correctness break, not a tightness preference, and it is checked
    /// numerically against the actual modulus rather than assumed from the formula.
    #[error(
        "mask width lambda={mask_bits} with top-up k={topup_bits} at {set_bits} bits of C(n,t) \
         multiplicity does not satisfy the Mod2 no-wrap inequality"
    )]
    NoWrapViolated {
        mask_bits: usize,
        topup_bits: usize,
        set_bits: usize,
    },
    #[error(
        "per-daBit leak 2^-{leak_exponent} is not below the statistical budget \
         2^-{statistical_security}: no positive number of daBits fits"
    )]
    LeakBudgetUnreachable {
        leak_exponent: usize,
        statistical_security: usize,
    },
    /// The **lifetime** daBit budget `Q = 2^(lambda+k+1-kappa)` is spent. Never a silent wrap:
    /// past `Q` the union bound on the per-daBit statistical leak exceeds the configured `kappa`,
    /// and the fix is a re-keyed node or a larger `k`, not another batch.
    #[error(
        "daBit leak budget exhausted: {produced} produced, {requested} more requested, lifetime \
         budget {budget}"
    )]
    LeakBudgetExhausted {
        produced: u64,
        requested: usize,
        budget: u64,
    },
    #[error(
        "key stores disagree: {what} says {left}, but the other says {right}. A daBit assembled \
         from mismatched stores is a pair of two unrelated bits."
    )]
    KeyStoreMismatch {
        what: &'static str,
        left: usize,
        right: usize,
    },
    /// A [`PrssExecSlot`](crate::honeybadger::prss::PrssExecSlot) or
    /// [`PrssWindow`](crate::honeybadger::prss::PrssWindow) burned on the wrong keystream's
    /// cursor. The edaBit filter and the daBit generator must draw their parent exec ids from one
    /// cursor, or their `exec * 2^20 + wave` child blocks can overlap.
    #[error("PRSS claim names stream {got}, expected {expected}")]
    WrongPrssStream {
        expected: &'static str,
        got: &'static str,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::gf2k::field::Gf256;
    use crate::common::math::goldilocks::GoldilocksField;

    fn arith(value: u64, id: usize, degree: usize) -> RobustShare<GoldilocksField> {
        RobustShare::new(GoldilocksField::from(value), id, degree)
    }

    fn bin(value: u8, id: usize, degree: usize) -> GfShare<Gf256> {
        GfShare::new(Gf256(value), id, degree)
    }

    #[test]
    fn dabit_new_rejects_index_mismatch() {
        let err =
            DaBit::<GoldilocksField, Gf256>::new(arith(1, 2, 3), bin(1, 5, 3), 3).unwrap_err();
        assert!(matches!(err, DaBitError::IdMismatch));
    }

    #[test]
    fn dabit_new_rejects_degree_mismatch() {
        let err =
            DaBit::<GoldilocksField, Gf256>::new(arith(1, 2, 4), bin(1, 2, 3), 3).unwrap_err();
        assert!(matches!(err, DaBitError::DegreeMismatch));
        let err =
            DaBit::<GoldilocksField, Gf256>::new(arith(1, 2, 3), bin(1, 2, 4), 3).unwrap_err();
        assert!(matches!(err, DaBitError::DegreeMismatch));
    }

    #[test]
    fn dabit_new_accepts_matching_pair() {
        let dabit = DaBit::<GoldilocksField, Gf256>::new(arith(1, 2, 3), bin(1, 2, 3), 3).unwrap();
        assert_eq!(dabit.id(), 2);
    }

    #[test]
    fn edabit_compose_is_weighted_sum_of_arithmetic_halves() {
        // Shares are linear, so composing share-wise composes the secrets; with one party's
        // "shares" being the clear values themselves this checks the weighting directly.
        let bits = [true, false, true, true]; // 0b1101 = 13
        let dabits: Vec<_> = bits
            .iter()
            .map(|&b| {
                DaBit::<GoldilocksField, Gf256>::new(arith(b as u64, 0, 1), bin(b as u8, 0, 1), 1)
                    .unwrap()
            })
            .collect();
        let edabit = EdaBit::compose(&dabits, 4).unwrap();
        assert_eq!(edabit.value.share[0], GoldilocksField::from(13u64));
        assert_eq!(edabit.width, 4);
        assert_eq!(edabit.bits.len(), 4);
    }

    #[test]
    fn edabit_compose_rejects_full_width_and_zero_width() {
        let dabit = DaBit::<GoldilocksField, Gf256>::new(arith(0, 0, 1), bin(0, 0, 1), 1).unwrap();
        let capacity = crate::common::convert::field_bit_width::<GoldilocksField>();
        let full = vec![dabit.clone(); capacity];
        assert!(matches!(
            EdaBit::compose(&full, capacity),
            Err(DaBitError::WidthTooLarge { .. })
        ));
        assert!(matches!(
            EdaBit::<GoldilocksField, Gf256>::compose(&[], 0),
            Err(DaBitError::ZeroWidth)
        ));
    }

    #[test]
    fn edabit_compose_rejects_wrong_count() {
        let dabit = DaBit::<GoldilocksField, Gf256>::new(arith(0, 0, 1), bin(0, 0, 1), 1).unwrap();
        let err = EdaBit::compose(&vec![dabit; 3], 4).unwrap_err();
        assert!(matches!(
            err,
            DaBitError::MaterialLengthMismatch {
                what: "edabit dabits",
                expected: 4,
                got: 3
            }
        ));
    }

    #[test]
    fn edabit_full_width_requires_the_overflow_filter_to_have_passed() {
        let capacity = crate::common::convert::field_bit_width::<GoldilocksField>();
        let dabit = DaBit::<GoldilocksField, Gf256>::new(arith(1, 0, 1), bin(1, 0, 1), 1).unwrap();
        let dabits = vec![dabit; capacity];
        assert!(matches!(
            EdaBit::compose_full_width(&dabits, true),
            Err(DaBitError::ModulusOverflow)
        ));
        let ok = EdaBit::compose_full_width(&dabits, false).unwrap();
        assert_eq!(ok.width, capacity);
    }

    #[test]
    fn payload_byte_len_counts_both_blobs() {
        let payload = DaBitPayload::MaskShares {
            arith: vec![0u8; 7],
            bin: vec![0u8; 5],
        };
        assert_eq!(payload.byte_len(), 12);
    }

    /// Both conversion drivers size their pipelines against this, and both must get the same
    /// figure — which is why it lives here rather than in either of them.
    #[test]
    fn conv_pipeline_depth_never_collapses_to_zero() {
        use crate::honeybadger::batch_recon::batch_recon::MAX_BATCH_RECON_SESSIONS;
        assert_eq!(conv_pipeline_depth(10), MAX_BATCH_RECON_SESSIONS / 10);
        assert_eq!(conv_pipeline_depth(MAX_BATCH_RECON_SESSIONS + 1), 1);
        // The degenerate party counts, which would otherwise divide by zero or floor to zero.
        assert!(conv_pipeline_depth(0) >= 1);
        assert!(conv_pipeline_depth(usize::MAX) >= 1);
    }
}
