//! Doubly-shared bits (daBits) — the single cross-domain primitive behind A2B and B2A.
//!
//! A daBit is a pair `([b]_F, [b]_K)` of degree-`t` sharings of the *same* bit `b`, one in the
//! prime field `F` and one in `GF(2^k)`. It is the only object in this crate that ties the two
//! domains together, and it ties them **by value**: the two halves share nothing but the party
//! index. [`crate::common::convert`] carries the same invariant at the level of clear values.
//!
//! # Construction
//!
//! [`replicated::ReplicatedDaBitNode`] generates them **information-theoretically**, from
//! replicated one-time bits:
//!
//! 1. **Deal and echo.** For each of the `C(n,t)` maximal unqualified sets `T`, one party outside
//!    `T` samples a fresh uniform bit `β_T` and sends it to the other parties outside `T`, who
//!    echo it to each other and abort on any mismatch.
//! 2. **Two local conversions of the same bits.** `[b]_K = Σ_T β_T · f^K_T` is the XOR of the set
//!    bits, because in characteristic 2 addition *is* XOR. Over `F` each `β_T · f_T` is a
//!    degree-`t` sharing of one set bit.
//! 3. **An XOR fold over `F`.** `C(n,t) - 1` degree-reduction multiplications, masked by dealt
//!    `RanDouSha` double sharings, fold the per-set sharings into `[b]_F`.
//!
//! Nothing here is pseudorandom: there is no PRF, no hash and no commitment, and privacy of the
//! daBit is perfect. The two halves agree by arithmetic — they are functions of the same `β_T` —
//! so there is no cross-domain check, and bit-ness is structural because the wire carries bits.
//! See the [`replicated`] module docs for the security argument and the cost.
//!
//! edaBits are **composed from daBits locally** ([`EdaBit::compose`]); there is no native edaBit
//! generation, because `[r]_F = sum 2^i [b_i]_F` is free while a native candidate costs an
//! `(n-1)`-deep tree of binary adders. Full-range composition additionally needs the `r < p`
//! filter, which is [`edabit::EdaBitFilterNode`].
//!
//! # Phase
//!
//! **PREPROCESSING** throughout: synchronous, abort permitted. The XOR fold and the edaBit
//! filter both open at degree `2t`, which needs every honest share and detects any wrong one, so
//! a crashed or cheating party stalls or aborts a batch exactly as it already does for RanSha
//! and RanDouSha. Nothing in this module tree is reachable from the online phase.

pub mod edabit;
mod packing;
pub mod replicated;

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
    /// BLS12-381's scalar field is about 9% — far above any budget this crate tolerates.
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

/// Payload of a [`DaBitMessage`]: the two steps of replicated one-time-bit dealing.
///
/// `count` is the batch size the sender is running. It travels on the wire so that two parties
/// whose views of the batch differ fail loudly instead of comparing equal-length packings of
/// different batches.
///
/// Each entry is `(rank, bits)`: the rank of a maximal unqualified set in
/// lexicographic order over the `t`-subsets of the parties, and one bit per daBit in the
/// batch, packed LSB-first with the last byte's unused high bits zero.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum DaBitPayload {
    /// The dealer of each listed set sends that set's bits to another party outside the set.
    Deal {
        count: u32,
        sets: Vec<(u32, Vec<u8>)>,
    },
    /// A party outside each listed set repeats the bits it holds to another party outside the
    /// set. The two must agree exactly.
    Echo {
        count: u32,
        sets: Vec<(u32, Vec<u8>)>,
    },
}

impl DaBitPayload {
    /// Bytes of packed bits carried, for the per-message bound.
    pub fn byte_len(&self) -> usize {
        match self {
            DaBitPayload::Deal { sets, .. } | DaBitPayload::Echo { sets, .. } => sets
                .iter()
                .fold(0usize, |acc, (_, bits)| acc.saturating_add(bits.len() + 4)),
        }
    }
}

/// A daBit dealing message, point-to-point between two parties outside the same set.
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

    // ---- Replicated one-time-bit dealing ----------------------------------------------------
    #[error("threshold t must be at least 1: at t = 0 the single set bit is known to everyone")]
    DegenerateThreshold,
    #[error("n={n} parties cannot tolerate t={t}: need n >= 3t + 1")]
    ThresholdOutOfRange { n: usize, t: usize },
    #[error("C({n},{t}) exceeds the {max} unqualified sets this implementation will enumerate")]
    TooManyUnqualifiedSets { n: usize, t: usize, max: u128 },
    /// A peer sent a dealing message that no honest party would send. The batch aborts.
    #[error("invalid daBit dealing: {0}")]
    InvalidDealing(String),
    /// Two holders of the same set disagree on its bits, so the set's dealer (or the echoing
    /// party) cheated. The batch aborts; nothing is output.
    #[error("daBit dealing echo from party {with} does not match the bits held locally")]
    DealingMismatch { with: usize },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::gf2k::field::Gf256;
    use ark_bls12_381::Fr as CurveField;

    fn arith(value: u64, id: usize, degree: usize) -> RobustShare<CurveField> {
        RobustShare::new(CurveField::from(value), id, degree)
    }

    fn bin(value: u8, id: usize, degree: usize) -> GfShare<Gf256> {
        GfShare::new(Gf256(value), id, degree)
    }

    #[test]
    fn dabit_new_rejects_index_mismatch() {
        let err = DaBit::<CurveField, Gf256>::new(arith(1, 2, 3), bin(1, 5, 3), 3).unwrap_err();
        assert!(matches!(err, DaBitError::IdMismatch));
    }

    #[test]
    fn dabit_new_rejects_degree_mismatch() {
        let err = DaBit::<CurveField, Gf256>::new(arith(1, 2, 4), bin(1, 2, 3), 3).unwrap_err();
        assert!(matches!(err, DaBitError::DegreeMismatch));
        let err = DaBit::<CurveField, Gf256>::new(arith(1, 2, 3), bin(1, 2, 4), 3).unwrap_err();
        assert!(matches!(err, DaBitError::DegreeMismatch));
    }

    #[test]
    fn dabit_new_accepts_matching_pair() {
        let dabit = DaBit::<CurveField, Gf256>::new(arith(1, 2, 3), bin(1, 2, 3), 3).unwrap();
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
                DaBit::<CurveField, Gf256>::new(arith(b as u64, 0, 1), bin(b as u8, 0, 1), 1)
                    .unwrap()
            })
            .collect();
        let edabit = EdaBit::compose(&dabits, 4).unwrap();
        assert_eq!(edabit.value.share[0], CurveField::from(13u64));
        assert_eq!(edabit.width, 4);
        assert_eq!(edabit.bits.len(), 4);
    }

    #[test]
    fn edabit_compose_rejects_full_width_and_zero_width() {
        let dabit = DaBit::<CurveField, Gf256>::new(arith(0, 0, 1), bin(0, 0, 1), 1).unwrap();
        let capacity = crate::common::convert::field_bit_width::<CurveField>();
        let full = vec![dabit.clone(); capacity];
        assert!(matches!(
            EdaBit::compose(&full, capacity),
            Err(DaBitError::WidthTooLarge { .. })
        ));
        assert!(matches!(
            EdaBit::<CurveField, Gf256>::compose(&[], 0),
            Err(DaBitError::ZeroWidth)
        ));
    }

    #[test]
    fn edabit_compose_rejects_wrong_count() {
        let dabit = DaBit::<CurveField, Gf256>::new(arith(0, 0, 1), bin(0, 0, 1), 1).unwrap();
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
        let capacity = crate::common::convert::field_bit_width::<CurveField>();
        let dabit = DaBit::<CurveField, Gf256>::new(arith(1, 0, 1), bin(1, 0, 1), 1).unwrap();
        let dabits = vec![dabit; capacity];
        assert!(matches!(
            EdaBit::compose_full_width(&dabits, true),
            Err(DaBitError::ModulusOverflow)
        ));
        let ok = EdaBit::compose_full_width(&dabits, false).unwrap();
        assert_eq!(ok.width, capacity);
    }

    #[test]
    fn payload_byte_len_counts_every_set_entry() {
        let payload = DaBitPayload::Deal {
            count: 12,
            sets: vec![(0, vec![0u8; 7]), (3, vec![0u8; 5])],
        };
        assert_eq!(payload.byte_len(), 7 + 4 + 5 + 4);
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
