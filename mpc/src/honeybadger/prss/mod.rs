//! Pseudorandom secret sharing (PRSS) — Cramer/Damgård/Ishai, TCC 2005, §4.
//!
//! Replicated shares double as PRF keys: instead of re-dealing one `r_T` per maximal unqualified
//! set on every invocation, each set's value is *derived* from a key distributed once. The
//! replicated-to-Shamir conversion is unchanged (`s_j = Σ_T ψ_{r_T}(a) · f_T(x_j)`); only the
//! origin of `r_T` moves from the network to a local PRF, which is what removes the per-session
//! `C(n,t)` communication.
//!
//! This module is the local half only: key storage, the PRF, and share assembly. Distributing the
//! keys in the first place is a separate one-time protocol.

use crate::common::share::ShareError;
use thiserror::Error;

pub mod prss;
pub mod window;

pub use window::{DaBitWindows, PrssAllocator, PrssExecSlot, PrssStream, PrssWindow};

/// Length of a PRSS key, in bytes. Also HMAC-SHA256's output width, so one key is exactly one
/// block of keying material.
pub const PRSS_KEY_LEN: usize = 32;

/// Upper bound on `C(n, t)`, the number of maximal unqualified sets any store over this key
/// family will enumerate. **The canonical definition** — `gf_prss::MAX_UNQUALIFIED_SETS` and
/// `dabit::prss_dabit::MAX_UNQUALIFIED_SETS` are re-derived from this one rather than restating
/// the number, so the four constructors that check it cannot drift apart.
///
/// Every store built over a PRSS key family — [`prss::PrssKeys`],
/// [`PrzsKeys`](crate::honeybadger::przs::przs::PrzsKeys),
/// [`GfPrssKeys`](crate::honeybadger::gf_prss::gf_prss::GfPrssKeys),
/// [`GfPrzsKeys`](crate::honeybadger::przs::gf_przs::GfPrzsKeys) — begins by calling
/// [`all_tsets`](prss::all_tsets), which allocates one `Vec<usize>` per set. An `(n, t)` chosen
/// far outside the useful range is therefore an unbounded allocation, and an unbounded allocation
/// reached through a *constructor* is an abort with no error to log. This is configure-your-own
/// OOM rather than an attacker path — `n` and `t` come from the deployment, never from the wire —
/// but the repo's discipline is that a bounded store says what its bound is, and three of the
/// four constructors enforcing it while one did not was the trap.
///
/// The bound is generous. It admits every party count PRSS is remotely practical at
/// (`C(16,5) = 4368`, `C(19,6) = 27 132`) and rejects only parameters already infeasible for the
/// separate `C(n-1, t)` PRF-stream reason: each party spends one stream per held key per call —
/// 3 / 15 / 84 / 495 / 3003 at `n = 4 / 7 / 10 / 13 / 16` with `n = 3t+1` — and PRZS spends `t`
/// times that. Whatever this constant says, the deployment ceiling is lower.
pub const MAX_UNQUALIFIED_SETS: usize = 65_536;

#[derive(Debug, Error)]
pub enum PrssError {
    #[error("expected keys for {expected} unqualified sets, got {got}")]
    KeyCountMismatch { expected: usize, got: usize },
    #[error("no key held for unqualified-set rank {0}")]
    MissingKey(usize),
    #[error("party {id} is out of range for n={n}")]
    PartyOutOfRange { id: usize, n: usize },
    #[error("requested {bits} bits, which does not fit the field")]
    WidthExceedsField { bits: usize },
    /// `C(n, t)` is above [`MAX_UNQUALIFIED_SETS`], or overflowed while being counted. Raised
    /// *before* the enumeration allocates, which is the only point at which raising it is any
    /// use.
    #[error("C({n},{t}) exceeds the {max} unqualified sets this implementation will enumerate")]
    TooManyUnqualifiedSets { n: usize, t: usize, max: usize },
    #[error("error operating with the shares: {0:?}")]
    ShareError(#[from] ShareError),
    /// A [`PrssAllocator`] claim of zero positions, or of zero width. Always a caller bug:
    /// admitting it would make "was this position issued?" ambiguous, which is the one question
    /// the allocator exists to answer.
    #[error("empty PRSS window claimed on stream {stream}")]
    EmptyClaim { stream: &'static str },
    /// Two claims on one stream at different widths. The P2 guard — see [`window`]. A PRSS
    /// position is addressed as byte `start * ceil(bits/8)`, so the same `start` at two widths
    /// reads *overlapping* bytes, and partitioning `start` does not save it.
    #[error(
        "stream {stream} was first claimed at {expected} bits and is now claimed at {got}: two \
         widths on one keystream address overlapping bytes"
    )]
    StreamWidthMismatch {
        stream: &'static str,
        expected: usize,
        got: usize,
    },
    /// The stream's monotone cursor saturated. Faults loudly rather than wrapping onto a
    /// position it has already issued, exactly as `SubProtocolCounter` does at `u64::MAX`.
    #[error("PRSS position cursor for stream {stream} is exhausted")]
    CursorExhausted { stream: &'static str },
    /// A direct [`PrssAllocator::claim`] on a stream whose `exec_id` is minted by another
    /// stream's cursor. Claiming it alone would give it an exec its leader has not burned — see
    /// [`PrssStream::exec_leader`].
    #[error("stream {stream} takes its exec id from {leader}; claim through the leader")]
    FollowerStream {
        stream: &'static str,
        leader: &'static str,
    },
    /// [`PrssAllocator::claim_exec`] on a cursor-scheme stream, which pins `exec_id = 0` and
    /// therefore has no exec to burn.
    #[error("stream {stream} pins exec_id = 0 and has no exec to burn")]
    CursorStreamHasNoExec { stream: &'static str },
    /// A [`PrssWindow`] presented to a key store that does not derive that stream — e.g. a
    /// PRZS-backed or uniform-label stream handed to the mask keystream.
    #[error("PRSS window names stream {got}, which is not drawn from this keystream")]
    WindowStreamMismatch { got: &'static str },
    /// A [`PrssWindow`] claimed by an allocator built over other key material. A position count
    /// is only meaningful against the keys it was counted for; see
    /// [`PrssAllocator::key_family_id`].
    #[error("PRSS window was claimed against a different key family")]
    WindowKeyFamilyMismatch,
}
