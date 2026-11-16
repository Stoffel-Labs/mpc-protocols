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

/// Length of a PRSS key, in bytes. Also HMAC-SHA256's output width, so one key is exactly one
/// block of keying material.
pub const PRSS_KEY_LEN: usize = 32;

/// Upper bound on `C(n, t)`, the number of maximal unqualified sets a key store over this key
/// family will enumerate.
///
/// [`prss::PrssKeys`] begins by calling [`all_tsets`](prss::all_tsets), which allocates one
/// `Vec<usize>` per set, so an `(n, t)` far outside the useful range is an unbounded allocation
/// reached through a constructor. `n` and `t` come from the deployment, never from the wire; the
/// bound makes that misconfiguration an error instead of an abort. It admits `C(16,5) = 4368`
/// and `C(19,6) = 27 132`.
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
}
