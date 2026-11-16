//! Arithmetic-to-binary share conversion: `[x]_F -> ([x_0]_K, ..., [x_{w-1}]_K)`.
//!
//! Given a degree-`t` sharing of `x` in the prime field `F`, A2B produces degree-`t` `GF(2^k)`
//! sharings of the `w = ceil(log2 p)` bits of the **canonical representative of `x` in `[0, p)`**,
//! LSB first. [`a2b::A2BNode`] drives it; the arithmetic of the conversion itself lives in
//! [`crate::honeybadger::binary_circuits`], which is pure data and does no I/O.
//!
//! # Exact, full range, no statistical parameter
//!
//! The construction is the edaBits/Rabbit one (eprint 2020/338 §4.2), in its **exact** form:
//!
//! ```text
//! 1. local        [y]_F = [x]_F - [r]_F          -- r is the edaBit's arithmetic half
//! 2. open (deg t) y     = Open([y])              -- exactly uniform on Z_p
//! 3. circuit      bits  = FieldA2BCircuit(y)([r_0], .., [r_{w-1}])
//!                       = MUX(carry_out(Y + r), y + r, Y + r),   Y = y + (2^w - p)
//! ```
//!
//! Step 3 is the **parallel offset adder**: the mod-`p` reduction is folded into the *public*
//! operand, so the two additions read only `r` and run concurrently instead of chaining. The
//! blueprint's serial `ADD_w(y, r) -> ADD_w(2^w - p, t1) -> MUX` computes the same bits in 13 AND
//! layers; this one takes 7. See [`FieldA2BCircuit`](crate::honeybadger::binary_circuits::FieldA2BCircuit)
//! for the case analysis.
//!
//! `r` is uniform on `[0, p)` and independent of `x`, so `y = (x - r) mod p` is *exactly* uniform
//! on `Z_p`: the masking is perfect rather than statistical, there is no `kappa` anywhere on this
//! path, and `HoneyBadgerMPCNodeOpts::max_masked_width` / `check_mask_security` are deliberately
//! not involved (C14). The bounded/statistical variant, which trades input
//! range for a statistical parameter, is deliberately not built.
//!
//! # Cost
//!
//! One degree-`t` arithmetic opening plus the adder's AND layers, independent of how many values
//! are converted together, and **zero** `F` multiplications. The counts depend on the field's bit
//! width `w`, because the prefix adder grows as `w log w`:
//!
//! | Field | `w` | GF(2^k) triples (bound / mean) | AND layers |
//! |---|---|---|---|
//! | BLS12-381 scalar | 255 | 3798 / ~3590 | 9 |
//! | BN254 scalar | 254 | 3771 / ~3560 | 9 |
//!
//! See [`binary_circuits`](crate::honeybadger::binary_circuits) for the gate-by-gate breakdown,
//! and `PrefixTopology::BrentKung` for the other end of the trade: at `w = 255` it needs 1722
//! triples instead of 3798, over 15 layers instead of 9.
//!
//! Preprocessing dominates the total: each conversion spends one edaBit (`w` daBits and one run
//! of the `r < p` filter, which rejects about 9% of candidates on BLS12-381 and 24% on BN254)
//! and the triples above, all made by the dealt, information-theoretic protocols.
//!
//! Measured by `tests/conv_cost_measurement.rs` for one conversion on the BLS12-381 scalar
//! field: bytes each party puts on the wire (a broadcast counted once per other party), and
//! online message rounds under a fixed one-way latency.
//!
//! | `n`, `t` | edaBit | GF(2^8) triples | online | online rounds |
//! |---|---|---|---|---|
//! | 4, 1 | 339,281 | 1,207,151 | 23,449 | 11 |
//! | 7, 2 | 2,386,204 | 1,967,655 | 43,656 | 18 |
//! | 10, 3 | 15,138,478 | 2,693,003 | 52,326 | 20 |
//! | 13, 4 | 98,454,773 | 3,406,269 | 59,550 | 20 |
//!
//! The edaBit column grows with `C(n,t)`: a daBit folds one dealt bit per `t`-set, so it spends
//! 3 / 20 / 119 / 714 double sharings at these sizes. The online figures are lower bounds, about
//! 5-10% short, because the harness reads its counters as soon as one party has its output; the
//! round count depends on the opened mask and is at most `A2BNode::message_rounds`.
//!
//!
//! Every opening here is degree-`t`, where this repo's robust reconstruction genuinely corrects
//! `t` errors; nothing on this path opens at degree `2t`, waits on a timeout, broadcasts outside
//! RBC, or can abort. Both halves of
//! [`OpeningPolicy`](crate::honeybadger::gf_mul::OpeningPolicy) preserve that: the batched path
//! and the direct path are the same degree-`t` Reed–Solomon decode, differing only in how the
//! evaluations are packed, and both re-attempt the decode on every arrival — which is what makes
//! the direct path robust rather than merely usually-correct, since with `e` corrupt shares among
//! the first `2t+1` received, OEC only succeeds once the later honest shares land.
//!
//! A2B is therefore robust and async-live *given* well-formed preprocessing. Its
//! guaranteed-output claim is still transitively capped by its **preprocessing**, which is a
//! different phase and is synchronous and abort-permitting: the degree-`2t` openings inside GF
//! triple generation, inside the daBit generator's XOR fold and inside the edaBit filter. Those
//! are detect-and-abort with soundness error 0; see [`dabit`](crate::honeybadger::dabit).
//! is no dealing left on this path at all.

pub mod a2b;

use std::marker::PhantomData;

use ark_ff::PrimeField;
use bincode::ErrorKind;
use stoffelnet::network_utils::{NetworkError, PartyId};
use thiserror::Error;
use tokio::sync::oneshot::{channel, Receiver, Sender};

use crate::{
    common::{
        convert::ConvertError,
        gf2k::{field::BinaryField, share::GfShare, Gf2kError},
        share::ShareError,
    },
    honeybadger::{
        batch_recon::BatchReconError, binary_circuits::CircuitError,
        gf_batch_recon::GfBatchReconError, gf_mul::GfMulError,
        robust_interpolate::InterpolateError, SessionId,
    },
};

/// Phase of one A2B session.
///
/// The ordering is load-bearing: the circuit plan is a function of the opened mask `y`, so no
/// AND layer can be built before [`A2BState::Masking`] has completed. Because `y` is *robustly*
/// opened, every honest party builds the same plan, spends the same triples and runs the same
/// number of layers, with no agreement sub-protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum A2BState {
    /// The store exists but [`a2b::A2BNode::init`] has not run here yet.
    NotInitialized,
    /// `[y] = [x] - [r]` is being opened at degree `t`.
    Masking,
    /// The mask is open and the AND layers of the adder are running.
    Circuit,
    /// Terminal. Reprocessing anything for a finished session is a silent no-op.
    Finished,
}

/// Per-session state.
///
/// Deliberately tiny: A2B owns no wire messages, so there is nothing for a peer to park here. The
/// batch's inputs, edaBits, triples and wire arenas all live on the driving [`a2b::A2BNode::init`]
/// call's own stack, and what is retained between calls is one result channel plus the list of
/// child session ids `clear_store` has to retire.
#[derive(Debug)]
pub struct A2BStore<F: PrimeField, K: BinaryField> {
    pub state: A2BState,
    /// Number of values this session converts. Zero until `init` sets it.
    pub conversions: usize,
    /// Bits per converted value, i.e. `field_bit_width::<F>()`. Zero until `init` sets it.
    pub width: usize,
    pub output_sender: Option<Sender<Vec<Vec<GfShare<K>>>>>,
    pub output_receiver: Option<Receiver<Vec<Vec<GfShare<K>>>>>,
    /// Every child session id this batch minted, so that `clear_store` retires exactly those
    /// rather than re-deriving them (C7). A re-derivation drifts the moment a chunk count
    /// changes, leaving orphaned child sessions squatting on their own caps.
    pub child_sessions: Vec<SessionId>,
    _f: PhantomData<fn() -> F>,
}

impl<F: PrimeField, K: BinaryField> A2BStore<F, K> {
    pub fn empty() -> Self {
        let (output_sender, output_receiver) = channel();
        Self {
            state: A2BState::NotInitialized,
            conversions: 0,
            width: 0,
            output_sender: Some(output_sender),
            output_receiver: Some(output_receiver),
            child_sessions: Vec::new(),
            _f: PhantomData,
        }
    }
}

impl<F: PrimeField, K: BinaryField> Default for A2BStore<F, K> {
    fn default() -> Self {
        Self::empty()
    }
}

/// Errors raised by arithmetic-to-binary conversion.
///
/// Every variant is returned rather than panicked. A2B has no message path of its own, but the
/// products it absorbs come back from a multiplication peers took part in and the opened mask
/// comes back from a reconstruction peers took part in, so both sit downstream of the network and
/// neither may be allowed to abort an honest party (C12).
#[derive(Debug, Error)]
pub enum A2BError {
    #[error("there was an error in the network: {0:?}")]
    NetworkError(#[from] NetworkError),
    #[error("error while serializing/deserializing bytes: {0:?}")]
    SerializationError(#[from] Box<ErrorKind>),
    #[error("error while serializing/deserializing field elements: {0:?}")]
    ArkSerialization(#[from] ark_serialize::SerializationError),
    #[error("Share error: {0:?}")]
    ShareError(#[from] ShareError),
    #[error("interpolation error: {0:?}")]
    InterpolateError(#[from] InterpolateError),
    #[error("GF(2^k) error: {0:?}")]
    Gf2kError(#[from] Gf2kError),
    #[error("conversion error: {0:?}")]
    ConvertError(#[from] ConvertError),
    #[error("binary circuit error: {0:?}")]
    CircuitError(#[from] CircuitError),
    #[error("GF(2^k) multiplication error: {0:?}")]
    GfMulError(#[from] GfMulError),
    #[error("batch reconstruction error: {0:?}")]
    BatchReconError(#[from] BatchReconError),
    #[error("GF(2^k) batch reconstruction error: {0:?}")]
    GfBatchReconError(#[from] GfBatchReconError),
    #[error("error sending the result: {0:?}")]
    SendError(SessionId),
    #[error("error receiving the result: {0:?}")]
    ReceiveError(SessionId),
    #[error("A2B session {0:?} did not complete in time")]
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
    /// A share carried a party index other than this node's.
    #[error("share index {got} does not match this party's index {expected}")]
    IdMismatch { expected: PartyId, got: PartyId },
    #[error("share degree {got} does not match the threshold {expected}")]
    DegreeMismatch { expected: usize, got: usize },
    /// C13: an empty batch would make every downstream length check pass vacuously.
    #[error("an empty A2B batch was requested")]
    EmptyBatch,
    #[error("batch of {requested} conversions exceeds the maximum of {max}")]
    BatchTooLarge { requested: usize, max: usize },
    #[error("input `{what}` has length {got}, expected {expected}")]
    MaterialLengthMismatch {
        what: &'static str,
        expected: usize,
        got: usize,
    },
    /// An edaBit was not full width. A2B converts the whole canonical range, so a short edaBit
    /// cannot mask it — and a short one also means the `r < p` filter was never applied.
    #[error("edabit {index} has width {got}, expected the full field width {expected}")]
    EdaBitWidthMismatch {
        index: usize,
        expected: usize,
        got: usize,
    },
    /// A circuit asked for more triples than the worst-case budget reserved for it. Unreachable
    /// while `FieldA2BCircuit::max_and_count` really is an upper bound over every admissible `y`;
    /// returned rather than asserted so that a future planner change degrades into an error
    /// instead of an out-of-bounds index (C12).
    #[error("conversion {index} needs {needed} triples, budget is {budget}")]
    TripleBudgetExceeded {
        index: usize,
        needed: usize,
        budget: usize,
    },
}
