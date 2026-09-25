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
    #[error("error operating with the shares: {0:?}")]
    ShareError(#[from] ShareError),
}
