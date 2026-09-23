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
}
