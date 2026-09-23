//! Pseudorandom secret sharing over a binary field — Cramer/Damgård/Ishai, TCC 2005, §4.
//!
//! Structural port of [`crate::honeybadger::prss`] from `F: PrimeField` to `K: BinaryField`. The
//! replicated-to-Shamir conversion is unchanged in shape (`s_j = Σ_T β_{r_T}(a) · f^K_T(x^K_j)`);
//! only the field, the conversion polynomials and the embedding of a derived integer into a field
//! element differ. The PRF itself is *not* ported: this module calls the `F`-side
//! [`derive_ints_at`](crate::honeybadger::prss::prss::derive_ints_at) verbatim, because that
//! function is field-independent and both domains must consume the *same bytes* for the same
//! `(key, session, position)` — see "One derivation, two conversions" below.
//!
//! # Phase
//!
//! **PREPROCESSING**, and *purely local*. There is no message, no round, no timeout, no broadcast
//! and no abort anywhere in this module — a `GfPrssKeys` turns key material into shares with zero
//! communication. It therefore cannot smuggle a degree-`2t` opening, a timeout or an abort onto
//! the asynchronous robust online path; its *outputs* are preprocessing material (the `K`-half of
//! a daBit, the `Gf2k` double sharings behind DN07 GF triples) and it is the consumers of those
//! outputs that carry a phase.
//!
//! # One derivation, two conversions
//!
//! For a daBit, the same per-set value `β_T` is converted twice:
//!
//! ```text
//! F side:   [S]_F  =  Σ_{T ∌ i}  β_T · f_T(x_i)       secret S = Σ_T β_T  over the INTEGERS
//! K side:   [b]_K  =  Σ_{T ∌ i}  β_T · f^K_T(x^K_i)   secret   = ⊕_T β_T  = S mod 2
//! ```
//!
//! The two agree modulo 2 by arithmetic rather than by protocol, which is what makes the daBit's
//! cross-domain tie free. That only holds if both sides consume the *same* keystream, so
//! [`GfPrssKeys::bit_shares_at`](gf_prss::GfPrssKeys::bit_shares_at) and
//! [`PrssKeys::shares_at`](crate::honeybadger::prss::prss::PrssKeys::shares_at) must be called
//! with the identical `(session_id, start, count, bits = 1)`. Sharing one
//! `derive_ints_at` between the two domains makes a "derivation-label split" structurally
//! impossible rather than a discipline requirement.
//!
//! # Two hazards this module cannot fix on its own
//!
//! * **Domain separation of `β` from the Mod2 mask `ψ`.** `context_bytes` in the `F`-side PRSS
//!   hard-codes its domain-separator byte to `0x01`, so a `β` draw and a `ψ` draw with the same
//!   `SessionId` collide, `ψ_A`'s low bit equals `β_A`, and `V mod 4` then reveals the daBit with
//!   probability ~3/4. Until `derive_ints_at` grows a separator argument, **the two draws must use
//!   distinct `SessionId`s** (distinct `sub_id`/`round_id`/`exec_id`/`instance_id`). One byte to
//!   get wrong, catastrophic to miss, and invisible to an all-honest test suite.
//! * **Cursor monotonicity.** A position is *burned* once derived, including on an abort or a
//!   retry. Two daBits drawn from the same PRSS position share the same unknown `β_A`; it cancels
//!   in their difference and the adversary learns `x ⊕ x'`. This is the same cursor-rewind class
//!   as VERIA-222 on `prandint.rs`. This module is position-addressed and stateless, so the cursor
//!   lives in the caller and the caller owns that obligation.
//!
//! # Party-count limits
//!
//! Two independent ceilings, both hard-errored rather than panicked:
//!
//! * **Field domain.** `n` distinct nonzero evaluation points must exist, i.e.
//!   `n <= K::MAX_DOMAIN_SIZE` ([`max_parties`](gf_prss::max_parties)): 15 for `Gf2p4`, 255 for
//!   `Gf256`/`Gf2p8`, 65535 for `Gf2p16`. Exceeding it yields
//!   [`GfPrssError::PartyCountExceedsField`].
//! * **Key blow-up.** Every party holds `C(n-1, t)` keys and spends one PRF stream per key per
//!   call — 3 / 15 / 84 / 495 / 3003 at `n = 4 / 7 / 10 / 13 / 16` with `n = 3t+1`. That is the
//!   binding constraint in practice: PRSS is comfortable to `n = 13`, tolerable at `n = 16`, and
//!   unusable at `n = 19` (18 564 streams per party per call). [`MAX_UNQUALIFIED_SETS`] caps the
//!   allocation so a mis-parameterised caller gets [`GfPrssError::TooManyUnqualifiedSets`] instead
//!   of an out-of-memory abort.

use crate::common::gf2k::Gf2kError;
use crate::common::share::ShareError;
use thiserror::Error;

pub mod gf_prss;

/// Upper bound on `C(n, t)`, the number of maximal unqualified sets this module will enumerate.
///
/// Re-exported from [`prss::MAX_UNQUALIFIED_SETS`](crate::honeybadger::prss::MAX_UNQUALIFIED_SETS)
/// rather than restated, so this path stays valid while the number lives in exactly one place.
/// The `F`-side `PrssKeys::new` and both `PrzsKeys` now enforce the same bound — it used to be
/// this module's alone, which made a bounded store a property of which field you instantiated.
pub const MAX_UNQUALIFIED_SETS: usize = crate::honeybadger::prss::MAX_UNQUALIFIED_SETS;

#[derive(Debug, Error)]
pub enum GfPrssError {
    #[error("expected keys for {expected} unqualified sets, got {got}")]
    KeyCountMismatch { expected: usize, got: usize },
    #[error("no key held for unqualified-set rank {0}")]
    MissingKey(usize),
    #[error("party {id} is out of range for n={n}")]
    PartyOutOfRange { id: usize, n: usize },
    /// `n` exceeds the number of distinct nonzero evaluation points `K` has.
    #[error("n={n} exceeds the {max} evaluation points this binary field supports")]
    PartyCountExceedsField { n: usize, max: usize },
    /// `t >= n`: there is no maximal unqualified set of size `t` inside `n` parties.
    #[error("threshold t={t} must be smaller than n={n}")]
    ThresholdOutOfRange { n: usize, t: usize },
    /// `C(n, t)` is above [`MAX_UNQUALIFIED_SETS`], or overflowed while being counted.
    #[error("C({n},{t}) exceeds the {max} unqualified sets this implementation will enumerate")]
    TooManyUnqualifiedSets { n: usize, t: usize, max: usize },
    /// A derived value `bits` wide cannot be embedded injectively into `K`, whose elements carry
    /// exactly `extension_degree` bits.
    #[error("requested {bits} bits, but this binary field carries only {degree}")]
    WidthExceedsField { bits: usize, degree: usize },
    /// `K::MAX_DOMAIN_SIZE` is not of the form `2^k - 1` for a `k` this platform can represent, so
    /// the field's extension degree cannot be recovered from the trait and no uniform draw can be
    /// sized. Reachable only for a `Gf2k<K, ..>` with `K >= usize::BITS`, whose `MAX_DOMAIN_SIZE`
    /// saturates.
    #[error("cannot recover the extension degree from MAX_DOMAIN_SIZE={order}")]
    IndeterminateExtensionDegree { order: usize },
    #[error("error operating in the binary field: {0:?}")]
    Gf2kError(#[from] Gf2kError),
    #[error("error operating with the shares: {0:?}")]
    ShareError(#[from] ShareError),
    /// A [`PrssWindow`](crate::honeybadger::prss::PrssWindow) rejected by
    /// [`GfPrssKeys::bit_shares_at_in`](gf_prss::GfPrssKeys::bit_shares_at_in) — wrong stream,
    /// wrong key family, or a width other than 1. The position discipline lives in one module, so
    /// its errors are re-raised rather than restated here.
    #[error("PRSS window rejected: {0}")]
    Prss(#[from] crate::honeybadger::prss::PrssError),
}
