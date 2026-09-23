//! Pseudorandom **zero** sharing (PRZS) at degree `2t` — Cramer/Damgård/Ishai, TCC 2005, §4, in
//! the **`t`-coefficient form**.
//!
//! A PRZS is the zero-secret twin of [`prss`](crate::honeybadger::prss): every party derives its
//! share locally from replicated PRF keys, with **no communication at all**, and the `n` shares
//! are evaluations of a single polynomial `h` with `deg h <= 2t` and `h(0) = 0`. Adding one to a
//! degree-`2t` object before opening it re-randomises everything the opening would otherwise
//! reveal beyond the constant term.
//!
//! # Phase: PREPROCESSING ONLY (synchronous, abort permitted). Never online.
//!
//! PRZS itself is non-interactive and therefore phase-neutral — it sends nothing, waits for
//! nothing, and cannot abort. Its *output* is not phase-neutral: a degree-`2t` sharing can only
//! be consumed by a degree-`2t` opening, and a degree-`2t` opening is
//!
//! * **legal in preprocessing** — synchronous, abort permitted, and *cheaper* per secret than a
//!   degree-`t` one (`2n/(2t+1)` vs `2n/(t+1)`, 1.75–1.8x in **payload**; both sessions carry
//!   the same `2n` messages and the same 48-byte frames, so the wire ratio is smaller and
//!   approaches 1 as the batch narrows), with cheating detected with
//!   probability **1** at `n = 3t+1` (the `[3t+1, 2t+1]` evaluation code has minimum distance
//!   `n - 2t = t+1 > t`, so any weight-`<= t` deviation is a non-codeword); and
//! * **illegal on the online path** — the online phase is asynchronous and robust with guaranteed
//!   output delivery, and degree-`2t` unique decoding needs `n >= 4t+1` when a party may wait for
//!   only `2t+1` honest shares plus `e <= t` corrupt ones. `robust_interpolate`'s own guard
//!   (`required = degree + t + 1 + r > n`) makes OEC unreachable at degree `2t`, so such an
//!   opening can be *stalled* by one silent party and *diverged* by one equivocating one.
//!
//! Every consumer of this module must therefore live in preprocessing: the DN07 degree-reduction
//! multiplication, the degree-`2t` exact-zero checks, and `MulPub` (and through it `RandBit`).
//! Putting a PRZS-masked degree-`2t` opening on the online path is the single most likely way to
//! break the threat model, and no type in this module can stop you — only this sentence can.
//!
//! # Why `t` coefficients per set, and what a single coefficient would cost
//!
//! The naive port of [`PrssKeys`](crate::honeybadger::prss::prss::PrssKeys) derives **one**
//! pseudorandom scalar per maximal unqualified set `T` and multiplies it by a fixed conversion
//! polynomial. Ported to zero sharing that gives `h(X) = Σ_T a_T · g_T(X)` for fixed `g_T`, i.e.
//! **one** pseudorandom direction per set. That object is a perfectly valid degree-`2t` sharing of
//! zero. It passes every functional test — reconstruction, degree, zero-ness, cross-party
//! agreement — and it is a **privacy break**.
//!
//! The reason is that the adversary is not an outsider. A static adversary corrupting exactly `t`
//! parties *is itself* a maximal unqualified set `A`, and since `|A| = |T| = t`, the containment
//! `A ⊆ T` holds only for `T = A`. So the adversary holds the key `k_T` for **every set except
//! `A`** and can subtract every term of `h` except `h_A`. The whole mask, from its point of view,
//! is `h_A` and nothing else.
//!
//! Now count what a degree-`2t` opening exposes. The opened object is the full polynomial `φ`, of
//! which the adversary is entitled to know `2t + 1` coordinates' worth: the constant term (the
//! value being opened, which is public by definition) and its own `t` evaluations `φ(x_j)`,
//! `j ∈ A`. That leaves **exactly `t` dimensions** of `φ` that it must not learn. The mask must
//! therefore span all `t` of them.
//!
//! ```text
//!   { h : deg h <= 2t, h(0) = 0, h|_A = 0 }   has dimension exactly t
//!         (2t+1 coefficients, minus 1 constraint at 0, minus t constraints on A)
//!
//!   h_A(X) = f_A(X) · Σ_{l=1..t} a_{A,l} · X^l   spans exactly that space
//!         (f_A has degree t, f_A(0) = 1, f_A|_A = 0; the t products have distinct
//!          degrees t+1 .. 2t, hence are independent, hence span a t-dimensional
//!          subspace of a t-dimensional space)
//! ```
//!
//! **The concrete attack against the single-coefficient form.** Take the DN07 preprocessing
//! multiplication, which is the main consumer: parties holding `[x]_t` and `[y]_t` compute the
//! local product `[xy]_{2t}` (`share_mul`), add the PRZS mask, and open the result at degree `2t`
//! through batch reconstruction. The opened polynomial is `φ = φ_x·φ_y + h`. A corrupt party
//! strips `h_T` for every `T != A` — it holds those keys — and is left with `φ_x·φ_y + h_A`. It
//! already knows `φ_x(x_j)·φ_y(x_j)` for `j ∈ A` and the public constant term `xy`, so its
//! residual uncertainty in `φ_x·φ_y` is `t`-dimensional. With a `t`-dimensional `h_A` that
//! uncertainty is preserved exactly and nothing leaks. With a **1**-dimensional `h_A`, `t - 1`
//! dimensions of `φ_x·φ_y` are handed over in the clear on every multiplication. For `t >= 2`
//! that is enough linear information — and a corrupt batch-reconstruction king holds *all* `n`
//! evaluations of its Vandermonde combination, not just its own — to solve for `φ_x` and `φ_y`
//! and recover the honest multiplicands. The same mechanism applied to `MulPub` inside
//! `RandBit` exposes the sharing polynomial of `a`, and with it the correlation structure of a
//! whole batch of random bits.
//!
//! At `t = 1` the two forms coincide (`t` coefficients *is* one coefficient), which is precisely
//! why a test suite run at `n = 4` cannot see the difference either. The break begins at `t = 2`.
//!
//! **An all-honest test suite cannot catch this.** The targeted test is a *dimension* count, not
//! a value check: see `single_set_mask_spans_exactly_t_dimensions` in both submodules, and
//! [`PrzsKeys::mask_dimension`](przs::PrzsKeys::mask_dimension).
//!
//! # Key material and domain separation
//!
//! PRZS reuses the **same** per-set keys as PRSS — the `[u8; PRSS_KEY_LEN]` a party holds for
//! each rank it is outside of — because the two must agree on which sets exist and who is in
//! them, and a second key-distribution protocol would be pure cost. Reuse is sound only under
//! strict domain separation, so this module derives with its **own** KDF label
//! ([`PRZS_KDF_LABEL`], distinct from PRSS's `STOFFEL-PRSS-v2`) **and** its own value in the
//! context's domain-separator byte ([`PrzsDomain::context_tag`], `0x02`/`0x03`, distinct from
//! PRSS's `0x01`). Either alone would suffice; both are present so that a future refactor which
//! unifies one of them does not silently merge the two keystreams. The arithmetic and binary
//! sides are separated from *each other* the same way, for the reason given on [`PrzsDomain`].
//!
//! This matters beyond tidiness. Two PRF streams that collide at the same position are not a
//! degraded mask, they are a solved one: the PRSS-daBit's `β_T`/`ψ_T` collision (the same hazard
//! class, one byte apart) reveals the daBit with probability ~3/4 from `V mod 4`. Any future
//! consumer of these keys must take a value here that no other consumer uses.
//!
//! # Cost, and the `n` ceiling it implies
//!
//! Zero elements on the wire and zero rounds — that is the whole point. The price is local: one
//! PRF stream per `(held set, coefficient index)`, i.e. `t · C(n-1, t)` streams per party per
//! zero sharing (3 / 30 / 252 / 1980 at `n` = 4 / 7 / 10 / 13). That is `t` times PRSS's own
//! `C(n-1, t)`, so wherever PRSS's practical ceiling sits (roughly `n <= 13–16`), PRZS's sits
//! lower. This is a deployment bound, not a correctness one, and it is the reason the ranking in
//! the plan inverts above `n ~ 16`.
//!
//! # What this module deliberately does not have
//!
//! No `ProtocolType` tag, no `WrappedMessage` variant, no session store, no admission cap, no
//! network handle. PRZS exchanges no messages, so none of the session-admission or store-cleanup
//! discipline that applies to a protocol node applies here; the only resource it can consume is
//! local allocation, which [`MAX_PRZS_COEFFS_PER_CALL`] bounds.

use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use sha2::Sha256;
use thiserror::Error;

use crate::common::gf2k::field::Gf256;
use crate::common::gf2k::generic_field::Gf2k;
use crate::common::gf2k::Gf2kError;
use crate::common::share::ShareError;
use crate::common::ProtocolSessionId;
use crate::honeybadger::prss::PRSS_KEY_LEN;
use crate::honeybadger::SessionId;

pub mod gf_przs;
pub mod przs;

type HmacSha256 = Hmac<Sha256>;

/// Fixed label for the PRZS KDF, per NIST SP 800-108.
///
/// **Distinct from PRSS's `STOFFEL-PRSS-v2` on purpose** — the two derivations run over the *same*
/// keys, and a shared label would make a PRZS mask a deterministic function of a PRSS value drawn
/// at the same position. Bump the version suffix if the derivation changes in any way; every
/// key's entire output stream depends on it.
///
/// The suffix is also the key-family **epoch** marker, and the three labels move together:
/// `v1 -> v2` was the `PrssAllocator` migration, which brought `PRandIntMask`, `DaBitSeed` and
/// `DaBitPsi` under the one allocator and had to make every pre-migration byte unaddressable
/// rather than merely unlikely to be re-addressed. `RandBitZero` and both DN07 streams' PRZS
/// halves ride *this* label, so leaving it at `v1` would have made the epoch partial — worse than
/// not having one. See
/// [`KDF_LABEL`](crate::honeybadger::prss::prss) for the full argument.
pub const PRZS_KDF_LABEL: &[u8] = b"STOFFEL-PRZS-v2";

/// Which field a PRZS mask is being derived for.
///
/// **Not a formatting hint — a domain separator.** The arithmetic and binary stores hold the
/// *same* per-set keys, and the arithmetic side draws `MODULUS_BIT_SIZE + 128` bits per
/// coefficient where the binary side draws `k`. Reading one keystream at two widths makes the two
/// masks overlap byte-for-byte: `a_K(T, l)` would be the low byte of the window `a_F(T, l)` is
/// reduced from, so an opening that pinned one would partially pin the other. They mask different
/// objects opened at different times, and nothing in the security argument gives them permission
/// to be correlated, so they are separated at the PRF instead: the arithmetic side derives under
/// context tag `0x02` and the binary side under `0x03`.
///
/// Passed explicitly at every derivation site rather than defaulted, so that the choice is
/// visible in the code and a new consumer has to make it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrzsDomain {
    /// Masks for degree-`2t` openings over the arithmetic field `F`.
    Arithmetic,
    /// Masks for degree-`2t` openings over a binary field `K`.
    Binary,
}

impl PrzsDomain {
    /// This domain's value for the context's domain-separator byte (`ctx[15]`).
    ///
    /// PRSS reserves `0x01` for `PRandInt` masks and its own comment reserves the byte for
    /// exactly this purpose. `0x02` and `0x03` are now taken by PRZS; any future consumer of the
    /// PRSS key family must take a value used by no other consumer. See the module docs on
    /// domain separation for why a collision here is catastrophic rather than merely untidy.
    pub fn context_tag(self) -> u8 {
        match self {
            PrzsDomain::Arithmetic => 0x02,
            PrzsDomain::Binary => 0x03,
        }
    }
}

/// Fixed output-length parameter for the KDF, held constant so that the keystream for a given
/// `(key, context)` is one fixed sequence regardless of how many values a call asks for. Same
/// rationale, and same value, as PRSS's: it is what lets coefficients be addressed by absolute
/// position, so a party topping up a half-full pool derives exactly the suffix the others already
/// hold.
const KDF_L_BITS: u32 = u32::MAX;

/// Extra PRF bits drawn beyond the field's modulus width before reducing, on the arithmetic side.
///
/// Reducing a uniform `MODULUS_BIT_SIZE`-bit integer mod `p` is *not* uniform on `F`; reducing a
/// uniform `(MODULUS_BIT_SIZE + 128)`-bit one is within statistical distance `2^-128` of uniform,
/// which is below every other term in the analysis. Rejection sampling would be exactly uniform
/// but is the one step where two implementations can consume different numbers of bytes and
/// silently diverge — and PRZS, like PRSS, has no message exchange left to catch that.
pub const PRZS_REDUCTION_SLACK_BITS: usize = 128;

/// Upper bound on the number of PRF coefficients a single call may materialise, i.e. on
/// `count * t`.
///
/// Local-allocation guard only: `count` here is always derived from a locally-chosen batch size,
/// never from an attacker-supplied length, so this is a backstop against a caller-side arithmetic
/// mistake rather than a defence. Callers needing more should loop, which is free — the
/// derivation is position-addressed, so consecutive calls agree with one big one.
pub const MAX_PRZS_COEFFS_PER_CALL: usize = 1 << 16;

#[derive(Debug, Error)]
pub enum PrzsError {
    #[error("expected keys for {expected} unqualified sets, got {got}")]
    KeyCountMismatch { expected: usize, got: usize },
    #[error("no key held for unqualified-set rank {0}")]
    MissingKey(usize),
    #[error("no coefficients supplied for unqualified-set rank {0}")]
    MissingCoefficients(usize),
    #[error("party {id} is out of range for n={n}")]
    PartyOutOfRange { id: usize, n: usize },
    /// `C(n, t)` is above
    /// [`MAX_UNQUALIFIED_SETS`](crate::honeybadger::prss::MAX_UNQUALIFIED_SETS), or overflowed
    /// while being counted. PRZS reaches the enumeration through the same `all_tsets` call as
    /// PRSS and spends `t` PRF streams per set where PRSS spends one, so if the bound binds
    /// anywhere it binds here first.
    #[error("C({n},{t}) exceeds the {max} unqualified sets this implementation will enumerate")]
    TooManyUnqualifiedSets { n: usize, t: usize, max: usize },
    #[error(
        "threshold t must be at least 1: at t=0 the only degree-0 sharing of zero is the \
         constant 0, which masks nothing"
    )]
    DegenerateThreshold,
    #[error(
        "n={n} is below the Byzantine bound 3t+1={bound}; a degree-2t sharing is not \
         reconstructible there"
    )]
    PartyCountTooSmall { n: usize, bound: usize },
    #[error(
        "a PRZS mask at threshold {t} needs exactly {t} coefficients per unqualified set, got \
         {got} — the single-coefficient form is a privacy break, not an optimisation"
    )]
    CoefficientCountMismatch { t: usize, got: usize },
    #[error("requested {requested} coefficients, more than the per-call maximum {max}")]
    BatchTooLarge { requested: usize, max: usize },
    #[error("coefficient stream position overflowed usize")]
    PositionOverflow,
    #[error("unqualified set {tset:?} is not a valid size-{t} subset of {n} parties")]
    MalformedTset {
        tset: Vec<usize>,
        t: usize,
        n: usize,
    },
    #[error("error operating with the shares: {0:?}")]
    ShareError(#[from] ShareError),
    #[error("error operating in the binary field: {0:?}")]
    Gf2k(#[from] Gf2kError),
}

/// The `t` pseudorandom coefficients of **one** unqualified set's contribution to a PRZS mask.
///
/// `coefficients()[l - 1]` is `a_{T,l}`, the coefficient of `X^l` in
/// `h_T(X) = f_T(X) · Σ_{l=1..t} a_{T,l} X^l`. Index `l` starts at **1**, never 0: `l = 0` would
/// put a constant term inside the bracket, `h_T(0)` would become `f_T(0)·a_{T,0} = a_{T,0}`, and
/// the "sharing of zero" property would be gone.
///
/// # This type is the enforcement point for the `t`-coefficient form
///
/// The field is private and the only two ways to obtain one are
/// [`PrzsKeys::derived_coefficients`](przs::PrzsKeys::derived_coefficients) (which always emits
/// exactly `t`, read off the key store, never from the caller) and [`ZeroCoeffs::from_vec`]
/// (which rejects any other count). There is no public path that produces a one-coefficient set
/// when `t > 1`, so "use `t` coefficients" is an invariant of the type rather than a comment
/// somebody has to remember — see the module docs for what forgetting it costs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZeroCoeffs<V> {
    /// INVARIANT: `coeffs.len() == t` and `t >= 1`. Upheld by every constructor, re-checked at
    /// every assembly site.
    coeffs: Vec<V>,
}

impl<V: Copy> ZeroCoeffs<V> {
    /// Wraps an explicit coefficient vector, checking it against the threshold it is for.
    ///
    /// The `t` argument is not redundant with `coeffs.len()`: it is the *expected* count, and the
    /// point of the call is to reject a vector that does not match it. Supplied by the caller
    /// rather than inferred precisely so that a mistakenly-short vector is an error instead of a
    /// silently weaker mask.
    ///
    /// Exists for preprocessing paths that source their randomness somewhere other than the PRF
    /// (for example a perfect-privacy deployment that refuses the PRF assumption and takes the
    /// coefficients from a dealt `ZeroSha`). The PRSS-keyed path never calls it.
    pub fn from_vec(coeffs: Vec<V>, t: usize) -> Result<Self, PrzsError> {
        if t == 0 {
            return Err(PrzsError::DegenerateThreshold);
        }
        if coeffs.len() != t {
            return Err(PrzsError::CoefficientCountMismatch {
                t,
                got: coeffs.len(),
            });
        }
        Ok(Self { coeffs })
    }

    /// `a_{T,1} .. a_{T,t}`, in ascending order of the power of `X` they multiply.
    pub fn coefficients(&self) -> &[V] {
        &self.coeffs
    }

    /// Always `t`. Kept public because the dimension of the mask *is* the security property.
    pub fn len(&self) -> usize {
        self.coeffs.len()
    }

    /// Never true for a value built by either constructor — both reject `t == 0`. Present
    /// because `len` without it is a clippy error under `-D warnings`.
    pub fn is_empty(&self) -> bool {
        self.coeffs.is_empty()
    }
}

/// Canonical, hand-rolled encoding of the PRF input context, differing from PRSS's only in the
/// domain-separator byte.
///
/// Deliberately not `serde`/`bincode`, for the same reason PRSS is not: a serialization-format
/// change would silently repoint every derivation, and there is no message exchange left to
/// notice the divergence. Fixed-width big-endian only.
fn context_bytes(session_id: SessionId, domain: PrzsDomain) -> [u8; 16] {
    let mut ctx = [0u8; 16];
    ctx[0] = session_id
        .calling_protocol()
        .map(|p| p as u8)
        .unwrap_or(0xFF);
    ctx[1..5].copy_from_slice(&session_id.instance_id().to_be_bytes());
    ctx[5..13].copy_from_slice(&session_id.exec_id().to_be_bytes());
    ctx[13] = session_id.sub_id();
    ctx[14] = session_id.round_id();
    ctx[15] = domain.context_tag();
    ctx
}

/// NIST SP 800-108 counter-mode KDF over HMAC-SHA256, on the PRZS label:
///
/// ```text
/// block_i = HMAC(key, [i]_4 ‖ PRZS_KDF_LABEL ‖ 0x00 ‖ Context ‖ [L]_4)
/// ```
///
/// Returns the `count` integers at absolute positions `start .. start + count` of this
/// `(key, context)` stream, each uniform in `[0, 2^bits)`.
///
/// Structurally identical to `prss::derive_ints_at` and intentionally so — the two must behave
/// the same way under partial requests — but keyed to a different label, so the two streams are
/// independent for the same key and session. See the module docs on domain separation.
///
/// Position-addressed: the value at index `i` never depends on which range a caller asked for.
/// PRZS lays a zero sharing's `t` coefficients out contiguously, so sharing `ν`'s coefficient `l`
/// lives at absolute position `ν·t + (l-1)`; a partially-filled pool topped up later therefore
/// lands on exactly the values the other parties already hold.
///
/// **No rejection sampling.** Callers use a power-of-two bound, so masking the top byte is
/// already exact; the arithmetic side then reduces a deliberately over-wide draw (see
/// [`PRZS_REDUCTION_SLACK_BITS`]). Rejection is the one step where two implementations could
/// consume different numbers of bytes and silently produce different values.
pub fn derive_zero_coeff_ints_at(
    key: &[u8; PRSS_KEY_LEN],
    session_id: SessionId,
    domain: PrzsDomain,
    start: usize,
    count: usize,
    bits: usize,
) -> Vec<BigUint> {
    if count == 0 || bits == 0 {
        return Vec::new();
    }

    const BLOCK: usize = 32;
    let width = bits.div_ceil(8);
    let ctx = context_bytes(session_id, domain);

    // Seek to the first block covering byte `start * width`, then discard the partial prefix.
    let byte_offset = start * width;
    let first_block = byte_offset / BLOCK;
    let skip = byte_offset % BLOCK;
    let need = count * width;

    let mut stream = Vec::with_capacity((skip + need).next_multiple_of(BLOCK));
    let mut counter = first_block as u32;
    while stream.len() < skip + need {
        // `new_from_slice` only fails on a bad key length, and PRSS keys are fixed-width.
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(&counter.to_be_bytes());
        mac.update(PRZS_KDF_LABEL);
        mac.update(&[0x00]);
        mac.update(&ctx);
        mac.update(&KDF_L_BITS.to_be_bytes());
        stream.extend_from_slice(&mac.finalize().into_bytes());
        counter += 1;
    }

    // Mask the top byte down when `bits` is not byte-aligned, so the result is uniform on
    // [0, 2^bits) rather than [0, 2^(8*width)).
    let top_mask: u8 = match bits % 8 {
        0 => 0xFF,
        r => (1u8 << r) - 1,
    };

    stream[skip..skip + need]
        .chunks_exact(width)
        .map(|chunk| {
            let mut bytes = chunk.to_vec();
            // Little-endian, matching PRSS's convention.
            if let Some(last) = bytes.last_mut() {
                *last &= top_mask;
            }
            BigUint::from_bytes_le(&bytes)
        })
        .collect()
}

/// Shared position/size arithmetic for both sides: validates a `(start, count)` request against
/// the threshold and the per-call cap, returning `(coefficient_start, coefficient_count)`.
///
/// A zero sharing consumes `t` contiguous coefficient positions, so sharing `ν`'s coefficients
/// occupy `[ν·t, (ν+1)·t)`. Everything here is `checked_*` because `start` and `count` come from
/// a caller's batch bookkeeping, and a wrapped product would silently alias two batches onto the
/// same PRF positions — the cursor-reuse failure of §6.5 error 3, arrived at by arithmetic
/// instead of by a rewind.
pub(crate) fn coefficient_window(
    start: usize,
    count: usize,
    t: usize,
) -> Result<(usize, usize), PrzsError> {
    let total = count.checked_mul(t).ok_or(PrzsError::PositionOverflow)?;
    if total > MAX_PRZS_COEFFS_PER_CALL {
        return Err(PrzsError::BatchTooLarge {
            requested: total,
            max: MAX_PRZS_COEFFS_PER_CALL,
        });
    }
    let coeff_start = start.checked_mul(t).ok_or(PrzsError::PositionOverflow)?;
    coeff_start
        .checked_add(total)
        .ok_or(PrzsError::PositionOverflow)?;
    Ok((coeff_start, total))
}

/// How a PRF output becomes a mask coefficient in a binary field.
///
/// The arithmetic side does not need this — `F: PrimeField` already has `From<BigUint>` with the
/// right reduction semantics — but [`BinaryField`](crate::common::gf2k::BinaryField) has no
/// constructor at all on the trait, so the byte-to-element map has to be supplied per field.
/// Both of the crate's binary fields implement it below; a new `BinaryField` needs an impl here
/// before it can carry a PRZS.
///
/// The contract is that drawing [`Self::COEFF_BITS`] bits and passing them through
/// [`Self::from_prf_value`] is **exactly** uniform on the field — not statistically close,
/// exactly — which holds because a `GF(2^k)` element is `k` free bits with no modulus to reduce
/// against.
pub trait PrzsCoefficient: Copy + 'static {
    /// PRF bits to draw per coefficient. Must equal the field's extension degree `k`.
    const COEFF_BITS: usize;

    /// Interprets a `COEFF_BITS`-bit value as a field element. Little-endian, matching
    /// [`derive_zero_coeff_ints_at`]'s output convention.
    fn from_prf_value(value: &BigUint) -> Self;
}

impl PrzsCoefficient for Gf256 {
    const COEFF_BITS: usize = 8;

    fn from_prf_value(value: &BigUint) -> Self {
        // `From<BigUint> for Gf256` takes the low little-endian byte, which is exactly the 8 bits
        // drawn.
        Gf256::from(value.clone())
    }
}

impl<const K: usize, const MODULUS: u128, const GENERATOR: u128> PrzsCoefficient
    for Gf2k<K, MODULUS, GENERATOR>
{
    const COEFF_BITS: usize = K;

    fn from_prf_value(value: &BigUint) -> Self {
        // `Gf2k` is `u128`-backed and `K <= 127`, so the drawn `K` bits always fit in 16 bytes.
        // `Gf2k::new` masks to `K` bits, which is a no-op here and a backstop if `COEFF_BITS`
        // and `K` ever drift apart.
        let mut acc: u128 = 0;
        for (i, byte) in value.to_bytes_le().iter().take(16).enumerate() {
            acc |= (*byte as u128) << (8 * i);
        }
        Gf2k::new(acc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::honeybadger::prss::prss::derive_ints_at;
    use crate::honeybadger::ProtocolType;

    fn sid(exec: u64) -> SessionId {
        SessionId::new(
            ProtocolType::PRandInt,
            SessionId::pack_slot(exec, 0, 0),
            111,
        )
    }

    /// §6.5 error 2's hazard class, one layer down: PRZS and PRSS run over the *same* keys, so if
    /// their streams ever coincide the mask becomes a known function of a value the adversary
    /// already has. Two independent separators stand between them; this pins that at least one is
    /// actually doing something.
    #[test]
    fn przs_stream_is_independent_of_the_prss_stream() {
        let key = [0x42u8; PRSS_KEY_LEN];
        for exec in 0..4u64 {
            let przs =
                derive_zero_coeff_ints_at(&key, sid(exec), PrzsDomain::Arithmetic, 0, 16, 64);
            let prss = derive_ints_at(&key, sid(exec), 0, 16, 64);
            assert_eq!(przs.len(), prss.len());
            assert_ne!(
                przs, prss,
                "PRZS and PRSS keystreams collided at exec={exec}"
            );
            // Not merely different in aggregate: no individual position may coincide either,
            // since a single shared coefficient is already a leaked dimension.
            for (i, (a, b)) in przs.iter().zip(prss.iter()).enumerate() {
                assert_ne!(a, b, "position {i} collided at exec={exec}");
            }
        }
    }

    /// The arithmetic and binary stores hold the *same* keys and read them at different widths.
    /// Without the domain tag, `a_K(T, l)` would be the low byte of the very window
    /// `a_F(T, l)` is reduced from. Separated at the PRF; pinned here.
    #[test]
    fn arithmetic_and_binary_masks_use_independent_streams() {
        assert_ne!(
            PrzsDomain::Arithmetic.context_tag(),
            PrzsDomain::Binary.context_tag()
        );
        // PRSS's `PRandInt` masks own 0x01; neither PRZS domain may take it.
        assert_ne!(PrzsDomain::Arithmetic.context_tag(), 0x01);
        assert_ne!(PrzsDomain::Binary.context_tag(), 0x01);

        let key = [0x5du8; PRSS_KEY_LEN];
        for bits in [8usize, 64, 383] {
            let a = derive_zero_coeff_ints_at(&key, sid(1), PrzsDomain::Arithmetic, 0, 16, bits);
            let b = derive_zero_coeff_ints_at(&key, sid(1), PrzsDomain::Binary, 0, 16, bits);
            assert_eq!(a.len(), 16);
            assert_ne!(a, b, "bits={bits}");
            if bits >= 64 {
                // Narrow draws can coincide at a position by chance; wide ones cannot.
                for (i, (x, y)) in a.iter().zip(b.iter()).enumerate() {
                    assert_ne!(x, y, "position {i} collided at bits={bits}");
                }
            }
        }
    }

    #[test]
    fn derivation_is_position_addressed() {
        let key = [0x3cu8; PRSS_KEY_LEN];
        for bits in [8usize, 12, 64, 192] {
            let whole = derive_zero_coeff_ints_at(&key, sid(5), PrzsDomain::Arithmetic, 0, 8, bits);
            let head = derive_zero_coeff_ints_at(&key, sid(5), PrzsDomain::Arithmetic, 0, 4, bits);
            let tail = derive_zero_coeff_ints_at(&key, sid(5), PrzsDomain::Arithmetic, 4, 4, bits);
            assert_eq!([head, tail].concat(), whole, "bits={bits}");

            // From an offset that lands mid-block, which is where the skip arithmetic bites.
            let mid = derive_zero_coeff_ints_at(&key, sid(5), PrzsDomain::Arithmetic, 3, 2, bits);
            assert_eq!(mid, whole[3..5], "bits={bits} mid-block");
        }
    }

    #[test]
    fn derivation_respects_the_declared_width() {
        let key = [0x5au8; PRSS_KEY_LEN];
        for bits in [1usize, 7, 8, 63, 64, 192] {
            let bound = BigUint::from(1u8) << bits;
            for v in derive_zero_coeff_ints_at(&key, sid(1), PrzsDomain::Arithmetic, 0, 32, bits) {
                assert!(v < bound, "value {v} exceeded 2^{bits}");
            }
        }
    }

    #[test]
    fn distinct_sessions_and_keys_give_distinct_streams() {
        let key = [0x11u8; PRSS_KEY_LEN];
        assert_ne!(
            derive_zero_coeff_ints_at(&key, sid(1), PrzsDomain::Arithmetic, 0, 16, 64),
            derive_zero_coeff_ints_at(&key, sid(2), PrzsDomain::Arithmetic, 0, 16, 64)
        );
        assert_ne!(
            derive_zero_coeff_ints_at(
                &[1u8; PRSS_KEY_LEN],
                sid(1),
                PrzsDomain::Arithmetic,
                0,
                16,
                64
            ),
            derive_zero_coeff_ints_at(
                &[2u8; PRSS_KEY_LEN],
                sid(1),
                PrzsDomain::Arithmetic,
                0,
                16,
                64
            )
        );
        // A repeated session id repeats the stream, which is exactly why a cursor must never be
        // rewound after an abort (§6.5 error 3).
        assert_eq!(
            derive_zero_coeff_ints_at(&key, sid(1), PrzsDomain::Arithmetic, 0, 16, 64),
            derive_zero_coeff_ints_at(&key, sid(1), PrzsDomain::Arithmetic, 0, 16, 64)
        );
    }

    /// The type-level half of the `t`-coefficient enforcement: there is no public way to build a
    /// short coefficient set.
    #[test]
    fn zero_coeffs_rejects_every_count_but_t() {
        for t in 1usize..5 {
            for got in 0usize..7 {
                let v = vec![7u64; got];
                let built = ZeroCoeffs::from_vec(v, t);
                if got == t {
                    assert_eq!(built.expect("exact count accepted").len(), t);
                } else {
                    assert!(
                        matches!(built, Err(PrzsError::CoefficientCountMismatch { .. })),
                        "t={t} accepted {got} coefficients"
                    );
                }
            }
        }
        // The single-coefficient form, stated as the test it fails.
        assert!(matches!(
            ZeroCoeffs::from_vec(vec![1u64], 3),
            Err(PrzsError::CoefficientCountMismatch { t: 3, got: 1 })
        ));
    }

    #[test]
    fn zero_coeffs_rejects_a_degenerate_threshold() {
        assert!(matches!(
            ZeroCoeffs::<u64>::from_vec(Vec::new(), 0),
            Err(PrzsError::DegenerateThreshold)
        ));
    }

    #[test]
    fn coefficient_window_is_checked() {
        assert_eq!(coefficient_window(4, 5, 3).unwrap(), (12, 15));
        assert_eq!(coefficient_window(0, 0, 3).unwrap(), (0, 0));
        assert!(matches!(
            coefficient_window(0, MAX_PRZS_COEFFS_PER_CALL, 2),
            Err(PrzsError::BatchTooLarge { .. })
        ));
        assert!(matches!(
            coefficient_window(0, usize::MAX, 2),
            Err(PrzsError::PositionOverflow)
        ));
        assert!(matches!(
            coefficient_window(usize::MAX, 1, 2),
            Err(PrzsError::PositionOverflow)
        ));
    }

    #[test]
    fn binary_coefficients_cover_their_field_uniformly() {
        // Gf256: 8 bits in, every one of the 256 elements reachable, low byte taken.
        for v in 0u16..256 {
            let got = Gf256::from_prf_value(&BigUint::from(v));
            assert_eq!(got, Gf256::new(v as u8));
        }
        assert_eq!(<Gf256 as PrzsCoefficient>::COEFF_BITS, 8);

        // Gf2p16: 16 bits in, masked to the field width.
        use crate::common::gf2k::generic_field::Gf2p16;
        assert_eq!(<Gf2p16 as PrzsCoefficient>::COEFF_BITS, 16);
        for v in [0u32, 1, 0x1234, 0xFFFF] {
            assert_eq!(
                Gf2p16::from_prf_value(&BigUint::from(v)),
                Gf2p16::new(v as u128)
            );
        }
    }
}
