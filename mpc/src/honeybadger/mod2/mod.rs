//! Catrina–Saxena `Mod2m` at `m = 1` — parity extraction by **one degree-`t` opening and zero
//! multiplications**.
//!
//! Given a degree-`t` sharing `[S]_F` of a small non-negative *integer* `S`, a statistical mask
//! `[r'']_F` and one `RandBit` `[r'_0]_F`:
//!
//! ```text
//!   local    [c]   = [S]_F + 2·[r'']_F + [r'_0]_F
//!   open     c     = Open_t([c])                      (ONE batched opening, t+1 per group)
//!   local    c_0   = c mod 2                          (a PUBLIC bit)
//!   local    [b]_F = c_0 + (1 − 2·c_0)·[r'_0]_F       (public-affine, i.e. c_0 XOR r'_0)
//! ```
//!
//! **Correctness.** While `S + r'_0 + 2r''` does not wrap `p` the opening is an integer identity,
//! so `c mod 2 = (S mod 2) ⊕ r'_0` and therefore `b = c_0 ⊕ r'_0 = S mod 2`. `c_0 + (1−2c_0)r'_0`
//! is `r'_0` at `c_0 = 0` and `1 − r'_0` at `c_0 = 1`, which is exactly that XOR. The no-wrap
//! side condition is **the caller's**, and for the PRSS daBit it is
//! [`DaBitLeakBudget`](crate::honeybadger::dabit::prss_dabit::DaBitLeakBudget), which both derives
//! it and re-checks it numerically at construction.
//!
//! Soundness error **0**, multiplications **0**, rounds **2** (one batch reconstruction).
//!
//! # Phase
//!
//! This node's single opening is at **degree `t`**, so it is robust and reconstructible on the
//! asynchronous path: at `n = 3t+1` the degree-`t` evaluation code is `[3t+1, t+1]` Reed–Solomon
//! with minimum distance `2t+1`, OEC corrects `t` errors and its guard `degree + t + 1 + r <= n`
//! is reachable for every `r <= t`. Nothing here opens above degree `t`, broadcasts, or aborts on
//! a peer's behaviour, and the node carries **no phase restriction of its own** — unlike
//! [`dn07`](crate::honeybadger::dn07), whose degree-`2t` opening makes it preprocessing-only.
//!
//! Its one consumer today, [PRSS daBit generation](crate::honeybadger::dabit::prss_dabit), is
//! **PREPROCESSING**, and the `duration` argument on [`mod2::Mod2Node::wait_for_bits`] is that
//! caller's synchronous liveness bound, not an online-path timeout.
//!
//! # The public branch needs no agreement round
//!
//! `c` was robustly opened at degree `t`, and `t+1` honest evaluations determine a degree-`t`
//! polynomial uniquely, so every honest party decodes the *same* `c` and therefore the same
//! `c_0`. Branching on a public bit is then local and unanimous — the same justification
//! `rand_bit`'s "this square opened to zero, drop the index" branch already relies on.
//!
//! # Share-type discipline
//!
//! `ShamirShare::degree` is caller-written `usize` metadata and proves nothing about the
//! polynomial a share lies on. Following `batch_recon.rs:250`, this node **discards** the supplied
//! degree on every input and substitutes its own `threshold`. The share `id` is the one label
//! checked rather than overwritten: it is the evaluation point and there is no local constant to
//! put in its place.

use ark_serialize::SerializationError;
use thiserror::Error;
use tokio::sync::oneshot::{channel, Receiver, Sender};

use crate::common::share::ShareError;
use crate::honeybadger::batch_recon::BatchReconError;
use crate::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use crate::honeybadger::SessionId;

pub mod mod2;

/// Concurrent Mod2 sessions admitted node-wide.
pub const MAX_MOD2_SESSIONS: usize = 256;

/// Largest number of `t+1`-wide batch-reconstruction groups one [`mod2::Mod2Node::init`] may open.
///
/// Every group contributes one field element to the same eval/reveal message pair, so this bounds
/// the payload of a single session. Callers chunk against
/// [`mod2::Mod2Node::max_batch_size`] rather than reimplementing the `t+1` arithmetic.
pub const MAX_MOD2_GROUPS: usize = 256;

#[derive(Debug, Error)]
pub enum Mod2Error {
    #[error("ark serialization: {0:?}")]
    ArkSerialization(#[from] SerializationError),
    #[error("batch recon: {0:?}")]
    BatchRecon(#[from] BatchReconError),
    #[error("error operating with the shares: {0:?}")]
    Share(#[from] ShareError),
    #[error(
        "threshold t must be at least 1: at t = 0 a degree-0 sharing is a constant and the \
         opening reveals every input"
    )]
    DegenerateThreshold,
    #[error(
        "n = {n} is below the Byzantine bound 3t+1 = {bound}; below it the degree-t opening's \
         online error correction is unreachable"
    )]
    PartyCountTooSmall { n: usize, bound: usize },
    #[error("{what}: expected {expected} items, got {got}")]
    LengthMismatch {
        what: &'static str,
        expected: usize,
        got: usize,
    },
    #[error("empty input")]
    EmptyInput,
    #[error("batch of {requested} exceeds the per-session maximum of {max}")]
    BatchTooLarge { requested: usize, max: usize },
    #[error(
        "share at index {index} carries id {got}, but this node is party {expected}: a share's \
         id is its evaluation point and there is no local constant to substitute for it"
    )]
    ShareIdMismatch {
        index: usize,
        expected: usize,
        got: usize,
    },
    #[error("session {0:?} carries no calling protocol")]
    MissingCallingProtocol(SessionId),
    #[error("session {0:?} must be a root session: sub_id and round_id must both be zero")]
    MalformedSessionId(SessionId),
    #[error("send error: {0:?}")]
    SendError(SessionId),
    #[error("receive error: {0:?}")]
    ReceiveError(SessionId),
    #[error("timeout: {0:?}")]
    Timeout(SessionId),
    #[error("no such session: {0:?}")]
    NoSuchSession(SessionId),
    #[error("result already received: {0:?}")]
    ResultAlreadyReceived(SessionId),
    #[error("session limit reached")]
    LimitError,
    #[error("channel closed")]
    Abort,
}

/// Lifecycle of one Mod2 session. Two-valued: there is exactly one network round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mod2State {
    Running,
    Finished,
}

/// Per-session state.
///
/// Deliberately small: the only thing parked here is the `RandBit` vector the public-affine step
/// needs, plus at most one batch-reconstruction payload that arrived before `init` ran locally.
#[derive(Debug)]
pub struct Mod2Store<F: ark_ff::FftField> {
    pub state: Mod2State,
    /// Secrets in this session. `0` is the "not initialised here yet" sentinel — it is never a
    /// legal batch size.
    pub k: usize,
    /// `[r'_0]`, one per secret, parked by `init` for the public-affine step. `None` until then,
    /// which is what tells [`mod2::Mod2Node::finish_from_payload`] to park instead of decode.
    pub rand_bits: Option<Vec<RobustShare<F>>>,
    /// A reconstruction that completed before this node reached `init`. Bounded at one payload
    /// because a session can only complete once.
    pub pending_batch_recon_payload: Option<Vec<u8>>,
    pub output_sender: Option<Sender<Vec<RobustShare<F>>>>,
    pub output_receiver: Option<Receiver<Vec<RobustShare<F>>>>,
}

impl<F: ark_ff::FftField> Mod2Store<F> {
    pub fn new(k: usize) -> Self {
        let (output_sender, output_receiver) = channel();
        Self {
            state: Mod2State::Running,
            k,
            rand_bits: None,
            pending_batch_recon_payload: None,
            output_sender: Some(output_sender),
            output_receiver: Some(output_receiver),
        }
    }
}
