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
//! not involved (C14). The bounded/statistical variant — which would cap the input at 22 bits at
//! `kappa = 40` on Goldilocks, below what the repo's own default `FixedPointPrecision(32, 16)`
//! already needs — is deliberately not built.
//!
//! # Cost
//!
//! One degree-`t` arithmetic opening plus `<= 7` AND layers, independent of how many values are
//! converted together. `<= 695` `GF(2^k)` Beaver triples (642 on average over a uniform mask) and
//! **zero** `F` multiplications per value at `w = 64`; see
//! [`binary_circuits`](crate::honeybadger::binary_circuits) for the gate-by-gate breakdown.
//!
//! ## Bytes — measured, and in the only unit that means anything
//!
//! One 64-bit A2B, **bytes actually put on the wire by one party**, preprocessing plus online,
//! excluding the one-off PRSS key setup, broadcast charged to all `n` recipients
//! (`conv_cost_measurement::measured_cost_n*`):
//!
//! ```text
//!                                    n=4      n=7     n=10     n=13
//!   conversion preprocessing      7 112   13 118   18 664   25 926   B/party
//!     of which the edaBit filter  2 888    4 942    7 000    9 022   (93-97% frame)
//!   GF triple pool (695)          2 240    2 618    2 960    3 276
//!   online (mask open + 7 layers) 6 352   11 390   16 758   22 642
//!   TOTAL                         15.34    26.49    37.48    50.63   KiB/party
//! ```
//!
//! Roughly half of that is per-message framing, not payload — a `GfBatchRecon` message costs
//! `48 + elements` bytes and a direct `GfMult` `52 + 2 * mults`, and an element-counting model
//! has no term for the constants. Any figure quoted in "field elements on the wire" (`O1`, `O2`,
//! `M1`, and every table in `scratchpad/a2b-b2a-protocol-performance.md`) is a **payload** figure
//! and is roughly half the truth here; see [`crate::honeybadger::dn07`] for the units rule and
//! the measured model.
//!
//! Message rounds are `2 + layers * rounds_per_layer`. The leading `2` is the mask opening's own
//! `BatchReconNode` round trip — evaluations out, reveals back — and it is two rounds whatever the
//! AND layers do, because [`OpeningPolicy`](crate::honeybadger::gf_mul::OpeningPolicy) governs the
//! multiplier alone and never the mask opening:
//!
//! | | AND layers | rounds/layer | message rounds |
//! |---|---|---|---|
//! | blueprint, serial adder + batched openings | 13 | 2 | 28 |
//! | parallel offset adder + batched openings | 7 | 2 | **16** |
//! | parallel offset adder + direct openings (what `Auto` picks below the crossover) | 7 | 1 | **9** |
//!
//! The blueprint's **8** for the last row drops the mask opening's second round; this node does
//! not route that opening directly, so one round of the saving is unclaimed. The same off-by-one
//! is why B2A is 2 rounds and not 1.
//! [`A2BNode::message_rounds`](a2b::A2BNode::message_rounds) computes the figure from the node's
//! own policy and circuit depth rather than restating it.
//!
//! **Measured, a real 64-bit conversion takes 9 rounds at every `n`** — 9.01 at `n = 4/7/10/13`
//! on turmoil's simulated clock at a fixed 100 ms one-way latency
//! (`conv_cost_measurement::measured_rounds_a2b_n*`). `message_rounds()` reports 16 at `n >= 7`
//! because it is deliberately an **upper bound**: it maximises over every wave width the node
//! could issue up to its cap, and the widest of those does cross
//! [`OpeningPolicy`](crate::honeybadger::gf_mul::OpeningPolicy)'s crossover, while the 89-118-wide
//! waves an actual 64-bit conversion issues do not. Quote 9 for a latency budget and 16 only as
//! the worst case.
//!
//! The triple count and the round count move in opposite directions and are both worth having:
//! the +11% on the sizing bound buys −46% depth, and on an asynchronous BFT network latency, not
//! bandwidth, is what a conversion waits on.
//!
//! # Preconditions
//!
//! * Every edaBit must be **full width** (`width == field_bit_width::<F>()`) and must have passed
//!   the `r < p` filter — that is what [`EdaBit::compose_full_width`](crate::honeybadger::dabit::EdaBit::compose_full_width)
//!   enforces by refusing to build without the opened overflow bit. With `r >= p` the adder's
//!   "at most one subtraction of `p`" argument fails and the output is simply wrong.
//! * Every edaBit is **single-use**. Reusing one turns two openings into `y XOR y' = x XOR x'`.
//!
//! # Output convention — canonical representative, not two's complement
//!
//! `mpc/src/common/types` encodes a negative fixed-point value `-|v|` as `p - |v|`, so `-1` comes
//! back from A2B as `0xFFFF_FFFF_0000_0000` and **not** as `0xFFFF_FFFF_FFFF_FFFF`. A caller that
//! wants a sign bit must shift by `2^(k-1)` first, exactly as `truncpr.rs` already does.
//!
//! # This node owns no wire messages (C4, C17)
//!
//! A2B sends nothing of its own. Its traffic is entirely its child protocols':
//! [`BatchReconNode`](crate::honeybadger::batch_recon::batch_recon::BatchReconNode) under
//! [`ProtocolType::A2B`](crate::honeybadger::ProtocolType::A2B) for the mask opening, and
//! [`GfMultiply`](crate::honeybadger::gf_mul::gf_multiplication::GfMultiply) under
//! [`ProtocolType::A2BGfMul`](crate::honeybadger::ProtocolType::A2BGfMul) for the AND layers —
//! demuxed by `calling_protocol()` alone, exactly as `FpMul` already is. The two tags are
//! distinct because `GfMultiply::init` mints its batch-reconstruction children with the *parent's*
//! tag: a node owning both a `GfMultiply<K>` and its own `GfBatchReconNode<K>` under one tag would
//! be unroutable.
//!
//! Consequently this node introduces **no local-only round**: every value it consumes is either a
//! robust reconstruction it performed itself or a product returned by a multiplication whose share
//! ids and degrees [`BinaryCircuit::absorb_layer`](crate::honeybadger::binary_circuits::BinaryCircuit::absorb_layer)
//! re-checks before it touches a wire.
//!
//! # Robustness
//!
//! **Phase: ONLINE — asynchronous, robust, guaranteed output delivery, no abort.**
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
//! triple generation and inside the `RandBit`s that
//! [`PrssDaBitNode`](crate::honeybadger::dabit::prss_dabit::PrssDaBitNode) consumes. Those are
//! detect-and-abort with soundness error 0 and are pre-existing; see
//! [`dabit`](crate::honeybadger::dabit). The daBit itself no longer waits on any dealer — there
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
