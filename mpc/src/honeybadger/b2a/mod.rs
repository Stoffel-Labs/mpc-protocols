//! Binary-to-arithmetic share conversion (B2A).
//!
//! Turns `ell` degree-`t` binary sharings `[x_0]_K, .., [x_{ell-1}]_K` of the bits of a value into
//! one degree-`t` arithmetic sharing `[sum_i 2^i x_i]_F`, using one daBit per bit.
//!
//! # The protocol, in full
//!
//! ```text
//! 1. local (FREE):   [c_i]_K = [x_i]_K + [r_i].bin          -- characteristic 2, so this is XOR
//! 2. open (1 opening): every c_i, at degree t, through GfBatchRecon
//! 3. local (FREE):   gamma_i = (c_i == 1)
//!                    [x_i]_F = [r_i].arith        if gamma_i = 0
//!                            = 1 - [r_i].arith    if gamma_i = 1
//! 4. local (FREE):   [x]_F   = sum_i 2^i [x_i]_F
//! ```
//!
//! **One GF opening, zero online multiplications, and nothing at all opened in `F`.** The
//! arithmetic half of every daBit is consumed entirely locally, which is why this is the cheapest
//! conversion in the crate and why it is the right thing to build and test before A2B.
//!
//! # Cost, stated exactly
//!
//! *One opening* is not *one round*. `GfBatchRecon` is a two-round protocol — evaluations to the
//! kings, reveals back — so B2A as built is **2 message rounds** for any `ell`, never 1. The
//! blueprint's "1 round" conflated an opening with a round, and it is the same off-by-one that
//! made A2B read 8 where it is 9.
//!
//! **Bytes, with the units named.** `2n/(t+1)` bytes per bit is the *payload*: `4.00 / 4.67 /
//! 5.00 / 5.20` B/bit at `n = 4/7/10/13`. The wire cost is that plus the 48-byte frame each of
//! the session's `2n` messages carries, and at `ell = 63` the frame is the larger half:
//!
//! ```text
//!   online bytes/party = 2n * (48 + ceil(ell/(t+1)))
//!   ell = 63, MEASURED (conv_cost_measurement::measured_cost_n*, `online` row):
//!                       n=4      n=7     n=10     n=13
//!     total              640      966     1280     1586      B/party
//!     of which frame     384      672      960     1248      = 2n * 48, i.e. 60-79%
//!     per bit          10.16    15.33    20.32    25.17      B, against the payload 4.00-5.20
//! ```
//!
//! Add the daBits it spends and one whole 63-bit B2A is **4.69 / 8.71 / 12.31 / 17.26 KiB/party**
//! measured, against a payload-only derivation of 3.53 / 6.72 / 9.80 / 14.25 — a gap that is
//! entirely framing (measured / (derived + `2n * 48`) = 0.98x at every `n`). See
//! [`crate::honeybadger::dn07`] for the units rule this crate now follows everywhere.
//!
//! A one-round B2A does exist: open every `c_i` directly all-to-all instead — the same trade
//! [`OpeningPolicy`](crate::honeybadger::gf_mul::OpeningPolicy) makes for A2B's AND layers, and
//! under the measured model there (a 52-byte direct frame against a 48-byte batched one, both at
//! one byte per value) it is *cheaper* here as well as shorter: `n * (52 + 63)` = 460 / 805 /
//! 1150 / 1495 B/party against the 640 / 966 / 1280 / 1586 measured above, in one wave of `n`
//! messages rather than two rounds of `2n`. It is
//! **not** built here, and deliberately: A2B's layers reach the direct path through `GfMultiply`,
//! which already owns a direct-open message type, whereas B2A opens through `GfBatchReconNode`
//! and a direct variant would need a new wire variant of its own. Since `WrappedMessage` is an
//! unversioned `bincode` enum whose variant *order* is the format, that is an append-only change
//! worth making on its own evidence rather than as a side effect of this one.
//!
//! **Phase: ONLINE.** Asynchronous and robust either way: the opening is degree-`t`, where OEC
//! corrects `t` errors, so a corrupt party can neither abort it nor forge it, and all honest
//! parties decode the same `c_i` because `t+1` honest points determine the polynomial uniquely.
//! Nothing here opens at degree `2t`, waits on a timeout, or aborts.
//!
//! # Privacy is perfect, and single use is what makes it so
//!
//! `c_i = x_i XOR r_i` with `r_i` the binary half of a **fresh, single-use** daBit: uniform on
//! `{0,1}` and independent of `x_i`, so `c_i` is exactly uniform on `{0,1}` and reveals nothing.
//! There is no statistical parameter anywhere on this path and no distance to bound — the
//! simulator samples `c_i` by a fair coin.
//!
//! That argument is *entirely* carried by the daBit being used once. Two conversions sharing a
//! daBit open `c` and `c'` with the same pad, and `c XOR c' = x XOR x'` is a plaintext relation in
//! the clear. The pools in [`conv_preprocessing`](crate::honeybadger::conv_preprocessing) are
//! drain-only for exactly this reason, and this node takes its daBits **by value** so a caller
//! cannot hand the same slice to two sessions and still compile.
//!
//! # `ell <= field_bit_width::<F>() - 1` is a correctness bound, not a heuristic
//!
//! Step 4 is an integer recomposition performed in `F`. It is faithful only while
//! `sum_i 2^i x_i < p`, which is guaranteed for every input exactly when `2^ell - 1 < p`. On
//! Goldilocks that is `ell <= 63`: at `ell = 64` the `2^32 - 1` payloads in `[p, 2^64)` would come
//! back silently reduced mod `p`, and the payload is the adversary's to choose. So width is a
//! hard [`B2AError::WidthTooLarge`], never an assertion and never a `warn!`.
//!
//! Fixing it with a conditional subtraction would reintroduce a comparison circuit and destroy the
//! one-round property, which is the whole point of this protocol. A caller who *knows*
//! `sum 2^i x_i < p` — because the bits came out of A2B, which emits the canonical representative
//! in `[0, p)` — gets the exact 64-bit round trip from
//! [`b2a::B2ANode::b2a_full_width_unchecked`](b2a::B2ANode::b2a_full_width_unchecked).
//!
//! # Owns no wire messages
//!
//! B2A defines no message type of its own. Everything it sends rides
//! [`WrappedMessage::GfBatchRecon`](crate::honeybadger::WrappedMessage::GfBatchRecon) under
//! [`ProtocolType::B2A`](crate::honeybadger::ProtocolType::B2A) and is demuxed by
//! `calling_protocol()` alone, exactly as `FpMul` already rides `Mult`/`BatchRecon`. Two
//! consequences worth stating, because they are what most of the usual checklist would otherwise
//! be about:
//!
//! * **No attacker-controlled length reaches this module.** Every vector length here comes from
//!   the local caller. The only network-facing deserialisation is inside `GfBatchReconNode`, which
//!   bounds each payload by its own byte length and refuses to adopt a single sender's claimed
//!   width (`agreeing_width`).
//! * **No local-only round (C4).** Every value this node consumes is either a share the local
//!   caller supplied — re-checked for index and degree — or a degree-`t` robust reconstruction it
//!   performed itself. There is nothing here for a forged `sender == self.id` message to reach.
//!
//! # What it opens, and at which degree
//!
//! Everything is opened at **degree `t`**, never `2t`. Degree-`2t` robust reconstruction in this
//! repo needs `degree + t + 1 = n` agreeing evaluations and so tolerates zero faults; degree-`t`
//! needs `2t + 1` of up to `3t + 1` and genuinely corrects `t` errors. B2A therefore inherits no
//! new robustness cap — although, like everything else here, its guaranteed-output claim is still
//! capped transitively by the daBits it consumes (see the [`dabit`](crate::honeybadger::dabit)
//! module header).

pub mod b2a;

use ark_ff::PrimeField;
use bincode::ErrorKind;
use stoffelnet::network_utils::NetworkError;
use thiserror::Error;
use tokio::sync::oneshot::{channel, Receiver, Sender};

use crate::{
    common::{gf2k::Gf2kError, share::ShareError},
    honeybadger::{
        dabit::DaBitError, gf_batch_recon::GfBatchReconError,
        robust_interpolate::robust_interpolate::RobustShare, SessionId,
    },
};

/// Phase of one B2A session.
///
/// `Finished` is terminal and finalisation takes the output sender out of the store, so a late
/// drain or a repeated call is a silent no-op rather than a second, contradictory result (C18).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum B2AState {
    /// The store has been admitted but no conversion has been started in it yet.
    NotInitialized,
    /// The masked bits `c_i = x_i XOR r_i` — and, in the checked variant, the Beaver masks
    /// `d_i`, `e_i` alongside them — are in flight.
    Opening,
    /// Checked variant only: the exact-zero products `x_i(x_i + 1)` are in flight.
    Certifying,
    /// Terminal.
    Finished,
}

/// Per-session state.
///
/// Deliberately tiny. The bits, the daBits and the opened values all live on the driving call's
/// own stack for the few round-trips they are needed, and no peer can cause an allocation here at
/// all: B2A owns no wire messages, so the only party that can create one of these is this node.
/// What the store carries is the result channel, the terminal state, and the child session ids
/// [`b2a::B2ANode::clear_store`] must retire.
///
/// Generic in `F` only: nothing `K`-typed survives a round here — the binary shares are consumed
/// into the opening and the output is arithmetic — so a second parameter would buy a
/// `PhantomData` and nothing else.
#[derive(Debug)]
pub struct B2AStore<F: PrimeField> {
    pub state: B2AState,
    /// Every child `GfBatchRecon` session id this conversion minted, so `clear_store` retires
    /// exactly those rather than re-deriving them (C7). Re-derivation drifts the moment a chunk
    /// count changes, leaving orphaned child sessions squatting on the batch-recon cap.
    pub child_sessions: Vec<SessionId>,
    pub output_sender: Option<Sender<Vec<RobustShare<F>>>>,
    pub output_receiver: Option<Receiver<Vec<RobustShare<F>>>>,
}

impl<F: PrimeField> B2AStore<F> {
    pub fn empty() -> Self {
        let (output_sender, output_receiver) = channel();
        Self {
            state: B2AState::NotInitialized,
            child_sessions: Vec::new(),
            output_sender: Some(output_sender),
            output_receiver: Some(output_receiver),
        }
    }
}

impl<F: PrimeField> Default for B2AStore<F> {
    fn default() -> Self {
        Self::empty()
    }
}

/// Errors raised by binary-to-arithmetic conversion.
///
/// Every variant is returned, never panicked. Most of them are caller bugs rather than attacks —
/// B2A has no inbound message path of its own — but a caller bug that aborts a party is still an
/// abort, and `NonBooleanInput` in particular is an *agreed* condition every honest party reaches
/// identically, so it must be a typed error rather than a panic or an attributable abort (C12).
#[derive(Debug, Error)]
pub enum B2AError {
    #[error("there was an error in the network: {0:?}")]
    NetworkError(#[from] NetworkError),
    #[error("error while serializing/deserializing bytes: {0:?}")]
    SerializationError(#[from] Box<ErrorKind>),
    #[error("GF(2^k) batch reconstruction error: {0:?}")]
    GfBatchReconError(#[from] GfBatchReconError),
    #[error("GF(2^k) error: {0:?}")]
    Gf2kError(#[from] Gf2kError),
    #[error("share error: {0:?}")]
    ShareError(#[from] ShareError),
    #[error("daBit error: {0:?}")]
    DaBitError(#[from] DaBitError),
    #[error("error sending the result: {0:?}")]
    SendError(SessionId),
    #[error("error receiving the result: {0:?}")]
    ReceiveError(SessionId),
    #[error("B2A conversion {0:?} did not complete in time")]
    Timeout(SessionId),
    #[error("channel closed")]
    Abort,
    #[error("party id is out of bounds")]
    InvalidPartyId,
    #[error("session ID {0:?} malformed")]
    SessionIdError(SessionId),
    #[error("limit reached")]
    LimitError,
    #[error("no such session ID exists: {0:?}")]
    NoSuchSessionId(SessionId),
    #[error("result already received: {0:?}")]
    ResultAlreadyReceived(SessionId),
    /// `2^width - 1` must be less than `p` or the recomposition `sum 2^i x_i` wraps and the
    /// conversion silently returns `x mod p`. On Goldilocks the bound is 63.
    #[error("value {value} has width {width}, which exceeds the maximum of {max}")]
    WidthTooLarge {
        value: usize,
        width: usize,
        max: usize,
    },
    /// A zero-width value would make every verification loop below it pass vacuously (C13).
    #[error("value {value} has zero width")]
    ZeroWidth { value: usize },
    #[error("no values to convert")]
    NoValues,
    #[error("preprocessing material `{what}` has length {got}, expected {expected}")]
    MaterialLengthMismatch {
        what: &'static str,
        expected: usize,
        got: usize,
    },
    /// The opened mask `c_i = x_i XOR r_i` is not in the `GF(2)` subfield. Since `c_i` was
    /// robustly opened, every honest party sees the same value, so this is an agreed condition and
    /// can only mean the caller supplied a non-bit share — `GfShare` carries no bit-ness
    /// guarantee of its own.
    #[error("input bit {index} of value {value} is not boolean")]
    NonBooleanInput { value: usize, index: usize },
    /// `b2a_checked` only: the exact-zero opening of `x_i (x_i + 1)` was non-zero, which is a
    /// *proof* that the input share is not a bit — unlike [`B2AError::NonBooleanInput`], this
    /// verdict does not rely on the daBit's binary half being well formed.
    #[error("input bit {index} of value {value} failed certification: x(x + 1) != 0")]
    CertificationFailed { value: usize, index: usize },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::math::goldilocks::GoldilocksField;

    #[test]
    fn store_starts_uninitialized_with_a_live_result_channel() {
        let mut store = B2AStore::<GoldilocksField>::empty();
        assert_eq!(store.state, B2AState::NotInitialized);
        assert!(store.child_sessions.is_empty());
        assert!(store.output_receiver.take().is_some());
        // Taking the receiver is what makes a second `wait_for_result` an error rather than a
        // silent hang, and taking the sender is what makes finalisation idempotent.
        assert!(store.output_receiver.take().is_none());
        assert!(store.output_sender.take().is_some());
        assert!(store.output_sender.take().is_none());
    }

    #[test]
    fn finished_is_distinguishable_from_every_other_phase() {
        // The bucket of states is small enough that a typo would otherwise go unnoticed.
        let all = [
            B2AState::NotInitialized,
            B2AState::Opening,
            B2AState::Certifying,
            B2AState::Finished,
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                assert_eq!(a == b, i == j);
            }
        }
    }
}
