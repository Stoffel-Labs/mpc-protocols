//! PRZS over a [`BinaryField`] — degree-`2t` pseudorandom sharings of zero in `GF(2^k)`, in the
//! CDI05 §4 `t`-coefficient form. A structural port of [`super::przs`], the way `gf_share_gen` is
//! a structural port of `share_gen`.
//!
//! **Phase: PREPROCESSING only.** Same statement, same reason: derivation is local and
//! non-interactive, but a degree-`2t` sharing can only be spent by a degree-`2t` opening, and
//! those are legal in the synchronous abort-permitted preprocessing phase and illegal on the
//! asynchronous robust online path. The online AND gates of the A2B circuit are degree-`t` Beaver
//! multiplications and must stay that way. See the [module docs](super) for the full statement and
//! for the concrete attack the single-coefficient form enables.
//!
//! # What changes in characteristic 2, and what does not
//!
//! Nothing about the `t`-coefficient argument changes: the adversary is still a maximal
//! unqualified set `A`, still holds `k_T` for every `T != A`, and its residual uncertainty in an
//! opened degree-`2t` polynomial given the public constant term and its own `t` evaluations is
//! still exactly `t`-dimensional. Only the field changes.
//!
//! The conversion polynomial does change shape, harmlessly:
//!
//! ```text
//! f^K_T(X) = Π_{m∈T} (X + x_m) / x_m          -- since 0 − x_m = x_m in characteristic 2
//! f^K_T(0) = 1,   f^K_T|_T = 0,   deg f^K_T = t
//! ```
//!
//! so `h_T(X) = f^K_T(X) · Σ_{l=1..t} a_{T,l} X^l` has degree `<= 2t` and `h_T(0) = 0` exactly, as
//! before. This module builds `f^K_T` by interpolation, through the same `(0, 1) + (x_m, 0)`
//! points `build_all_f_polys` uses on the arithmetic side, rather than by the product form — and
//! then [`gf_set_basis_evals`] recomputes it by the product form, so the two cross-check.
//!
//! One genuine difference is worth stating because it is a trap elsewhere in this codebase:
//! squaring is a *bijection* on `GF(2^k)`, so anything that opens `W^2` opens `W`. That is why the
//! exact-zero check this mask serves is `W(W+1) = W^2 + W` and never `W^2`. It is not a property
//! of PRZS, but it is a property of the thing PRZS masks.

use std::collections::HashMap;

use crate::common::gf2k::{
    field::BinaryField, get_or_create_gf2k_domain, poly::lagrange_interpolate, share::GfShare,
    Gf2kError, Poly,
};
use crate::honeybadger::{
    prss::{
        prss::{all_tsets, bounded_set_count, held_ranks},
        MAX_UNQUALIFIED_SETS, PRSS_KEY_LEN,
    },
    przs::{
        coefficient_window, derive_zero_coeff_ints_at, PrzsCoefficient, PrzsDomain, PrzsError,
        ZeroCoeffs,
    },
    SessionId,
};

/// The `GF(2^k)` twin of `build_all_f_polys`: the degree-`t` conversion polynomial
/// `f^K_T` for each requested unqualified set, keyed by the set itself.
///
/// `f^K_T` is pinned by `f^K_T(0) = 1` and `f^K_T(x_m) = 0` for every `m ∈ T`, which is `t + 1`
/// points and therefore a unique polynomial of degree `<= t`. Interpolated rather than multiplied
/// out so that the code sits beside `build_all_f_polys` in shape; the closed form is in
/// [`gf_set_basis_evals`], and the two are checked against each other.
///
/// # Errors
/// - [`Gf2kError::NoSuitableDomain`] if `n` exceeds `K::MAX_DOMAIN_SIZE`.
/// - [`Gf2kError::PolynomialOperationError`] if a set names an out-of-range or duplicated party,
///   which collapses two interpolation points onto one x-value.
pub fn build_all_gf_f_polys<K: BinaryField>(
    n: usize,
    tsets: Vec<Vec<usize>>,
) -> Result<HashMap<Vec<usize>, Poly<K>>, Gf2kError> {
    let domain = get_or_create_gf2k_domain::<K>(n)?;
    tsets
        .into_iter()
        .map(|tset| {
            if tset.iter().any(|j| *j >= n) {
                return Err(Gf2kError::InvalidInput(format!(
                    "unqualified set {tset:?} names a party outside 0..{n}"
                )));
            }
            // x = 0 is never a domain point (they are powers of the generator), so prepending it
            // cannot duplicate an x-value; duplicates within `tset` still can, and
            // `lagrange_interpolate` rejects those.
            let xs = std::iter::once(K::zero())
                .chain(tset.iter().map(|j| domain.element(*j)))
                .collect::<Vec<_>>();
            let ys = std::iter::once(K::one())
                .chain(std::iter::repeat(K::zero()).take(tset.len()))
                .collect::<Vec<_>>();
            let poly = lagrange_interpolate(&xs, &ys)?;
            Ok((tset, poly))
        })
        .collect()
}

/// The `t` basis directions of unqualified set `T`'s mask space over `K`, evaluated at party
/// `j`'s point: `gf_set_basis_evals(n, t, T, j)[l - 1] = f^K_T(x_j) · x_j^l` for `l = 1..=t`.
///
/// The binary twin of [`set_basis_evals`](super::przs::set_basis_evals), and the same security
/// object: its **length** must be `t`. Computed from the closed product form
/// `f^K_T(x_j) = Π_{m∈T} (x_j − x_m)/(0 − x_m)` — written with the subtractions spelled out even
/// though both are XOR here, so that the expression is visibly the same one the arithmetic side
/// uses.
///
/// # Errors
/// - [`PrzsError::DegenerateThreshold`] for `t == 0`.
/// - [`PrzsError::MalformedTset`] if `tset` is not a set of `t` distinct indices below `n`.
/// - [`PrzsError::PartyOutOfRange`] if `j >= n`.
/// - [`PrzsError::Gf2k`] if no domain of size `n` exists over `K`.
pub fn gf_set_basis_evals<K: BinaryField>(
    n: usize,
    t: usize,
    tset: &[usize],
    j: usize,
) -> Result<Vec<K>, PrzsError> {
    if t == 0 {
        return Err(PrzsError::DegenerateThreshold);
    }
    if j >= n {
        return Err(PrzsError::PartyOutOfRange { id: j, n });
    }
    let malformed = tset.len() != t
        || tset.iter().any(|m| *m >= n)
        || (0..tset.len()).any(|a| tset[a + 1..].contains(&tset[a]));
    if malformed {
        return Err(PrzsError::MalformedTset {
            tset: tset.to_vec(),
            t,
            n,
        });
    }

    let domain = get_or_create_gf2k_domain::<K>(n)?;
    let x_j = domain.element(j);

    let mut f_t = K::one();
    for m in tset {
        let x_m = domain.element(*m);
        let inv = (K::zero() - x_m).inverse().ok_or_else(|| {
            Gf2kError::PolynomialOperationError(
                "domain point 0 has no inverse — the evaluation domain contains zero".to_string(),
            )
        })?;
        f_t = f_t * ((x_j - x_m) * inv);
    }

    let mut evals = Vec::with_capacity(t);
    let mut pow = K::one();
    for _ in 0..t {
        // `l` starts at 1: a constant term inside the bracket would break `h(0) = 0`.
        pow = pow * x_j;
        evals.push(f_t * pow);
    }
    Ok(evals)
}

/// One party's PRZS key material over a binary field.
///
/// **Phase: PREPROCESSING only** — see the [module docs](super).
#[derive(Clone)]
pub struct GfPrzsKeys<K: BinaryField> {
    id: usize,
    n: usize,
    t: usize,
    /// `(rank, key, f^K_T(x_id))` for each set this party is outside of, ordered by rank.
    entries: Vec<(usize, [u8; PRSS_KEY_LEN], K)>,
    /// `x_id^1 .. x_id^t`.
    ///
    /// INVARIANT: `basis_powers.len() == t`. Zipping a set's coefficients against this vector is
    /// what makes the `t`-coefficient form structural rather than conventional.
    basis_powers: Vec<K>,
}

/// Redacts the key bytes — the same secrets as the PRSS store, and a logged one retroactively
/// de-randomises every mask ever derived from it.
impl<K: BinaryField> std::fmt::Debug for GfPrzsKeys<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GfPrzsKeys")
            .field("id", &self.id)
            .field("n", &self.n)
            .field("t", &self.t)
            .field("degree", &(2 * self.t))
            .field("held_sets", &self.entries.len())
            .field("coefficients_per_set", &self.basis_powers.len())
            .field("keys", &"<redacted>")
            .finish()
    }
}

impl<K: BinaryField + PrzsCoefficient> GfPrzsKeys<K> {
    /// Builds from the keys this party holds, indexed by rank in
    /// [`all_tsets`](crate::honeybadger::prss::prss::all_tsets).
    ///
    /// These are the **same** keys, with the **same** ranks, as the arithmetic-side
    /// [`PrzsKeys`](super::przs::PrzsKeys) and as `PrssKeys` — one key family, three
    /// domain-separated derivations. That is not merely an economy: the daBit construction needs
    /// the arithmetic and binary halves to be functions of one seed family, and a second key set
    /// would reintroduce exactly the cross-domain tie the construction exists to avoid paying for.
    ///
    /// # Errors
    /// - [`PrzsError::DegenerateThreshold`] for `t == 0`.
    /// - [`PrzsError::PartyCountTooSmall`] for `n < 3t+1`.
    /// - [`PrzsError::TooManyUnqualifiedSets`] when `C(n, t)` is above
    ///   [`MAX_UNQUALIFIED_SETS`](crate::honeybadger::prss::MAX_UNQUALIFIED_SETS) or overflows,
    ///   raised before the enumeration allocates.
    /// - [`PrzsError::PartyOutOfRange`], [`PrzsError::KeyCountMismatch`],
    ///   [`PrzsError::MissingKey`].
    /// - [`PrzsError::Gf2k`] if `n > K::MAX_DOMAIN_SIZE` (255 for `Gf256`).
    pub fn new(
        id: usize,
        n: usize,
        t: usize,
        keys: &[(usize, [u8; PRSS_KEY_LEN])],
    ) -> Result<Self, PrzsError> {
        if t == 0 {
            return Err(PrzsError::DegenerateThreshold);
        }
        if id >= n {
            return Err(PrzsError::PartyOutOfRange { id, n });
        }
        if n < 3 * t + 1 {
            return Err(PrzsError::PartyCountTooSmall {
                n,
                bound: 3 * t + 1,
            });
        }
        // Before `all_tsets`, which is the allocation this rejects. `n <= K::MAX_DOMAIN_SIZE`
        // bounds `n` but not `C(n, t)`: at `n = 255` the binomial peaks above `2^250`.
        if bounded_set_count(n, t).is_none() {
            return Err(PrzsError::TooManyUnqualifiedSets {
                n,
                t,
                max: MAX_UNQUALIFIED_SETS,
            });
        }

        let tsets = all_tsets(n, t);
        let held = held_ranks(n, t, id);
        if keys.len() != held.len() {
            return Err(PrzsError::KeyCountMismatch {
                expected: held.len(),
                got: keys.len(),
            });
        }

        let my_tsets: Vec<Vec<usize>> = held.iter().map(|r| tsets[*r].clone()).collect();
        let polys = build_all_gf_f_polys::<K>(n, my_tsets)?;
        let domain = get_or_create_gf2k_domain::<K>(n)?;
        let x_id = domain.element(id);

        let mut entries = Vec::with_capacity(held.len());
        for rank in held {
            let key = keys
                .iter()
                .find_map(|(r, k)| (*r == rank).then_some(*k))
                .ok_or(PrzsError::MissingKey(rank))?;
            let poly = polys.get(&tsets[rank]).ok_or(PrzsError::MissingKey(rank))?;
            entries.push((rank, key, poly.evaluate(x_id)));
        }

        let mut basis_powers = Vec::with_capacity(t);
        let mut pow = K::one();
        for _ in 0..t {
            pow = pow * x_id;
            basis_powers.push(pow);
        }

        Ok(Self {
            id,
            n,
            t,
            entries,
            basis_powers,
        })
    }

    /// This party's index.
    pub fn id(&self) -> usize {
        self.id
    }

    /// Number of keys held — `C(n−1, t)`.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Never true for a store built by [`Self::new`]; present because `len` without it is a
    /// clippy error under `-D warnings`.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The degree of every sharing this store produces: **`2t`**, fixed and not a parameter.
    pub fn degree(&self) -> usize {
        2 * self.t
    }

    /// The dimension of the mask from the adversary's point of view: **`t`**. This is the number
    /// that must not be 1 — see the [module docs](super).
    pub fn mask_dimension(&self) -> usize {
        self.basis_powers.len()
    }

    /// `t` PRF coefficients are drawn per unqualified set per zero sharing, so one sharing costs
    /// `t · C(n−1, t)` PRF streams.
    pub fn coefficients_per_set(&self) -> usize {
        self.basis_powers.len()
    }

    /// The `t` coefficients this party derives for one unqualified set at one sharing index.
    ///
    /// `K::COEFF_BITS` bits are drawn per coefficient, which is **exactly** uniform on `GF(2^k)` —
    /// there is no modulus to reduce against, so the binary side has none of the arithmetic side's
    /// `2^-128` reduction slack.
    ///
    /// # Errors
    /// - [`PrzsError::MissingKey`] if this party is inside set `rank`. Its contribution would be
    ///   zero anyway (`f^K_T(x_id) = 0` for `id ∈ T`); the error reports the absence rather than
    ///   inventing a value.
    pub fn derived_coefficients(
        &self,
        rank: usize,
        session_id: SessionId,
        index: usize,
    ) -> Result<ZeroCoeffs<K>, PrzsError> {
        let key = self
            .entries
            .iter()
            .find_map(|(r, k, _)| (*r == rank).then_some(k))
            .ok_or(PrzsError::MissingKey(rank))?;
        let (start, count) = coefficient_window(index, 1, self.t)?;
        let raw = derive_zero_coeff_ints_at(
            key,
            session_id,
            PrzsDomain::Binary,
            start,
            count,
            K::COEFF_BITS,
        );
        let coeffs: Vec<K> = raw.iter().map(K::from_prf_value).collect();
        ZeroCoeffs::from_vec(coeffs, self.t)
    }

    /// This party's shares of the degree-`2t` zero sharings at absolute positions
    /// `start .. start + count`.
    ///
    /// Purely local, zero rounds, zero bytes:
    ///
    /// ```text
    /// share_i(ν) = Σ_{T ∌ i}  f^K_T(x_i) · Σ_{l=1..t} a_{T,l}(ν) · x_i^l
    /// ```
    ///
    /// The inner sum starts at `l = 1`, so the underlying polynomial vanishes at `X = 0`
    /// **exactly**, for every coefficient assignment. Zero-ness is structural, not statistical.
    ///
    /// Every party must pass the identical `session_id`, `start` and `count`; there is no message
    /// exchange left to catch a mismatch. A consumed range must be **burned, never rewound**, on
    /// an abort or retry — re-deriving an already-opened position hands the adversary the mask in
    /// advance (the VERIA-222 cursor-rewind class).
    ///
    /// # Errors
    /// - [`PrzsError::BatchTooLarge`] / [`PrzsError::PositionOverflow`].
    /// - [`PrzsError::CoefficientCountMismatch`] if the store's basis is not `t`-dimensional.
    pub fn zero_shares_at(
        &self,
        session_id: SessionId,
        start: usize,
        count: usize,
    ) -> Result<Vec<GfShare<K>>, PrzsError> {
        self.check_basis()?;
        let (coeff_start, coeff_count) = coefficient_window(start, count, self.t)?;
        let mut shares = vec![GfShare::new(K::zero(), self.id, self.degree()); count];
        if count == 0 {
            return Ok(shares);
        }

        for (_, key, f_t) in &self.entries {
            let raw = derive_zero_coeff_ints_at(
                key,
                session_id,
                PrzsDomain::Binary,
                coeff_start,
                coeff_count,
                K::COEFF_BITS,
            );
            if raw.len() != coeff_count {
                return Err(PrzsError::CoefficientCountMismatch {
                    t: coeff_count,
                    got: raw.len(),
                });
            }
            for (nu, chunk) in raw.chunks_exact(self.t).enumerate() {
                let mut inner = K::zero();
                for (a, x_pow) in chunk.iter().zip(self.basis_powers.iter()) {
                    inner = inner + K::from_prf_value(a) * *x_pow;
                }
                shares[nu].share = shares[nu].share + inner * *f_t;
            }
        }
        Ok(shares)
    }

    /// Assembles one share from **explicit** per-set coefficients instead of the PRF.
    ///
    /// `coeffs` is a `(rank, coefficients)` table; every rank this party holds must appear, and
    /// ranks it does not hold may appear and are ignored — soundly, since `f^K_T(x_id) = 0` for
    /// `id ∈ T`. See the arithmetic twin for why this entry point exists.
    ///
    /// # Errors
    /// - [`PrzsError::MissingCoefficients`] for a held rank absent from the table.
    /// - [`PrzsError::CoefficientCountMismatch`] if any entry does not carry exactly `t`
    ///   coefficients.
    pub fn zero_share_from_coefficients(
        &self,
        coeffs: &[(usize, ZeroCoeffs<K>)],
    ) -> Result<GfShare<K>, PrzsError> {
        self.check_basis()?;
        let mut acc = K::zero();
        for (rank, _, f_t) in &self.entries {
            let set = coeffs
                .iter()
                .find_map(|(r, c)| (r == rank).then_some(c))
                .ok_or(PrzsError::MissingCoefficients(*rank))?;
            if set.len() != self.t {
                return Err(PrzsError::CoefficientCountMismatch {
                    t: self.t,
                    got: set.len(),
                });
            }
            let mut inner = K::zero();
            for (a, x_pow) in set.coefficients().iter().zip(self.basis_powers.iter()) {
                inner = inner + *a * *x_pow;
            }
            acc = acc + inner * *f_t;
        }
        Ok(GfShare::new(acc, self.id, self.degree()))
    }

    /// Re-asserts the `t`-coefficient invariant at every assembly site. `new` establishes it, so
    /// this is unreachable — which is the point: the failure mode guarded against is a future
    /// edit that quietly shortens the basis, and that edit leaves every functional test passing.
    fn check_basis(&self) -> Result<(), PrzsError> {
        if self.basis_powers.len() != self.t || self.t == 0 {
            return Err(PrzsError::CoefficientCountMismatch {
                t: self.t,
                got: self.basis_powers.len(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::gf2k::field::Gf256;
    use crate::common::ProtocolSessionId;
    use crate::honeybadger::przs::MAX_PRZS_COEFFS_PER_CALL;
    use crate::honeybadger::ProtocolType;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    /// `n = 3t+1` at t = 1, 2, 3. `t = 1` is where the `t`-coefficient and single-coefficient
    /// forms coincide and where a test suite that stops there learns nothing.
    const CONFIGS: [(usize, usize); 3] = [(4, 1), (7, 2), (10, 3)];

    fn sid(exec: u64) -> SessionId {
        SessionId::new(
            ProtocolType::PRandInt,
            SessionId::pack_slot(exec, 0, 0),
            111,
        )
    }

    fn deal_keys(n: usize, t: usize) -> Vec<Vec<(usize, [u8; PRSS_KEY_LEN])>> {
        let mut rng = StdRng::seed_from_u64(19);
        let tsets = all_tsets(n, t);
        let all: Vec<[u8; PRSS_KEY_LEN]> = (0..tsets.len()).map(|_| rng.gen()).collect();
        (0..n)
            .map(|id| {
                held_ranks(n, t, id)
                    .into_iter()
                    .map(|rank| (rank, all[rank]))
                    .collect()
            })
            .collect()
    }

    fn build_all(n: usize, t: usize) -> Vec<GfPrzsKeys<Gf256>> {
        let dealt = deal_keys(n, t);
        (0..n)
            .map(|id| GfPrzsKeys::<Gf256>::new(id, n, t, &dealt[id]).unwrap())
            .collect()
    }

    /// The polynomial the `n` shares of one sharing lie on, by plain interpolation through all
    /// `n` points (all honest here, so no error correction is wanted).
    fn sharing_polynomial(n: usize, shares: &[GfShare<Gf256>]) -> Poly<Gf256> {
        let domain = get_or_create_gf2k_domain::<Gf256>(n).unwrap();
        let xs: Vec<Gf256> = shares.iter().map(|s| domain.element(s.id)).collect();
        let ys: Vec<Gf256> = shares.iter().map(|s| s.share).collect();
        lagrange_interpolate(&xs, &ys).unwrap()
    }

    /// Rank over `Gf256`, by Gaussian elimination. The dimension counts are the security
    /// property, so they are measured rather than asserted.
    fn rank(rows: &[Vec<Gf256>]) -> usize {
        let mut m: Vec<Vec<Gf256>> = rows.to_vec();
        let cols = m.first().map(|r| r.len()).unwrap_or(0);
        let mut r = 0usize;
        for c in 0..cols {
            let pivot = (r..m.len()).find(|&i| !m[i][c].is_zero());
            let Some(p) = pivot else { continue };
            m.swap(r, p);
            let inv = m[r][c].inverse().unwrap();
            for v in m[r].iter_mut() {
                *v = *v * inv;
            }
            for i in 0..m.len() {
                if i != r && !m[i][c].is_zero() {
                    let factor = m[i][c];
                    for k in 0..cols {
                        let sub = m[r][k] * factor;
                        m[i][k] = m[i][k] - sub;
                    }
                }
            }
            r += 1;
            if r == m.len() {
                break;
            }
        }
        r
    }

    fn share_vectors(
        keys: &[GfPrzsKeys<Gf256>],
        n: usize,
        exec: u64,
        count: usize,
    ) -> Vec<Vec<Gf256>> {
        let per_party: Vec<Vec<GfShare<Gf256>>> = keys
            .iter()
            .map(|k| k.zero_shares_at(sid(exec), 0, count).unwrap())
            .collect();
        (0..count)
            .map(|nu| (0..n).map(|id| per_party[id][nu].share).collect())
            .collect()
    }

    #[test]
    fn every_party_holds_c_n_minus_1_choose_t_keys() {
        for (n, t, expected) in [(4usize, 1usize, 3usize), (7, 2, 15), (10, 3, 84)] {
            for k in &build_all(n, t) {
                assert_eq!(k.len(), expected, "n={n} t={t}");
                assert!(!k.is_empty());
                assert_eq!(k.degree(), 2 * t);
                assert_eq!(k.mask_dimension(), t);
                assert_eq!(k.coefficients_per_set(), t);
            }
        }
    }

    /// `f^K_T(0) = 1`, `f^K_T` vanishes on `T`, degree exactly `t`. All three are what make
    /// `h_T(0) = 0` and `h_T|_T = 0` hold, and `f^K_T(0) = 1` is the characteristic-2 statement
    /// that `Π x_m / x_m = 1`.
    #[test]
    fn gf_conversion_polynomials_have_the_right_shape() {
        for (n, t) in CONFIGS {
            let domain = get_or_create_gf2k_domain::<Gf256>(n).unwrap();
            let tsets = all_tsets(n, t);
            let polys = build_all_gf_f_polys::<Gf256>(n, tsets.clone()).unwrap();
            for tset in &tsets {
                let p = &polys[tset];
                assert_eq!(p.evaluate(Gf256::zero()), Gf256::one(), "f_T(0) != 1");
                assert_eq!(p.degree(), t, "deg f_T != t for {tset:?}");
                for m in tset {
                    assert!(
                        p.evaluate(domain.element(*m)).is_zero(),
                        "f_T did not vanish at member {m} of {tset:?}"
                    );
                }
                for j in 0..n {
                    if !tset.contains(&j) {
                        assert!(
                            !p.evaluate(domain.element(j)).is_zero(),
                            "f_T vanished at non-member {j} of {tset:?}"
                        );
                    }
                }
            }
        }
    }

    /// The interpolated `f^K_T` used by [`GfPrzsKeys::new`] and the closed product form used by
    /// [`gf_set_basis_evals`] must agree. Two independent code paths for the same object, so a
    /// bug in one is visible.
    #[test]
    fn interpolated_and_closed_form_conversion_agree() {
        for (n, t) in CONFIGS {
            let domain = get_or_create_gf2k_domain::<Gf256>(n).unwrap();
            let tsets = all_tsets(n, t);
            let polys = build_all_gf_f_polys::<Gf256>(n, tsets.clone()).unwrap();
            for tset in &tsets {
                for j in 0..n {
                    let x_j = domain.element(j);
                    let from_poly = polys[tset].evaluate(x_j);
                    let evals = gf_set_basis_evals::<Gf256>(n, t, tset, j).unwrap();
                    assert_eq!(evals.len(), t);
                    // evals[0] = f_T(x_j) * x_j, so divide back out.
                    let recovered = evals[0] * x_j.inverse().unwrap();
                    assert_eq!(recovered, from_poly, "n={n} t={t} T={tset:?} j={j}");
                }
            }
        }
    }

    #[test]
    fn zero_sharing_reconstructs_to_zero_at_degree_2t() {
        for (n, t) in CONFIGS {
            let keys = build_all(n, t);
            let count = 4;
            let per_party: Vec<Vec<GfShare<Gf256>>> = keys
                .iter()
                .map(|k| k.zero_shares_at(sid(3), 0, count).unwrap())
                .collect();

            for nu in 0..count {
                let shares: Vec<GfShare<Gf256>> =
                    (0..n).map(|id| per_party[id][nu].clone()).collect();
                assert!(shares.iter().all(|s| s.degree == 2 * t));
                assert!(shares.iter().enumerate().all(|(i, s)| s.id == i));

                let (coeffs, secret) = GfShare::recover_secret(&shares, n, t)
                    .expect("degree-2t reconstruction from all n honest shares");
                assert!(
                    secret.is_zero(),
                    "n={n} t={t}: sharing {nu} was not of zero"
                );
                assert!(coeffs.len() <= 2 * t + 1);
                assert!(coeffs.first().map(|c| c.is_zero()).unwrap_or(true));
            }
        }
    }

    /// It must not be a degree-`t` sharing wearing a degree-`2t` label: a degree-`t` mask would
    /// leave the `t` extra coefficients a degree-`2t` opening exposes uncovered, which is the
    /// same leak the single-coefficient form causes by a different route.
    #[test]
    fn zero_sharing_is_not_a_degree_t_sharing() {
        for (n, t) in CONFIGS {
            let keys = build_all(n, t);
            let count = 8;
            let per_party: Vec<Vec<GfShare<Gf256>>> = keys
                .iter()
                .map(|k| k.zero_shares_at(sid(4), 0, count).unwrap())
                .collect();

            let mut saw_above_t = false;
            for nu in 0..count {
                let shares: Vec<GfShare<Gf256>> =
                    (0..n).map(|id| per_party[id][nu].clone()).collect();
                let poly = sharing_polynomial(n, &shares);
                assert!(
                    poly.degree() <= 2 * t,
                    "n={n} t={t}: sharing {nu} had degree {} > 2t",
                    poly.degree()
                );
                assert!(
                    poly.evaluate(Gf256::zero()).is_zero(),
                    "n={n} t={t}: sharing {nu} did not vanish at 0"
                );
                if poly.degree() > t {
                    saw_above_t = true;
                }
            }
            assert!(
                saw_above_t,
                "n={n} t={t}: every sampled sharing had degree <= t"
            );
        }
    }

    /// **The test the single-coefficient form fails.** Binary twin of the arithmetic one: freeze
    /// every set's coefficients to zero except the adversary's own set `A` — the one set whose
    /// key it does not hold — and measure the dimension reachable by varying `A` alone. It must
    /// be `t`. A one-scalar-per-set PRZS reaches 1, while passing every other test in this file.
    #[test]
    fn single_set_mask_spans_exactly_t_dimensions() {
        for (n, t) in CONFIGS {
            let keys = build_all(n, t);
            let tsets = all_tsets(n, t);
            let a_rank = 0usize;
            let a_set = &tsets[a_rank];

            let mut rows: Vec<Vec<Gf256>> = Vec::with_capacity(t);
            for l in 0..t {
                let mut unit = vec![Gf256::zero(); t];
                unit[l] = Gf256::one();
                let table: Vec<(usize, ZeroCoeffs<Gf256>)> = (0..tsets.len())
                    .map(|r| {
                        let c = if r == a_rank {
                            unit.clone()
                        } else {
                            vec![Gf256::zero(); t]
                        };
                        (r, ZeroCoeffs::from_vec(c, t).unwrap())
                    })
                    .collect();

                let shares: Vec<GfShare<Gf256>> = (0..n)
                    .map(|id| keys[id].zero_share_from_coefficients(&table).unwrap())
                    .collect();

                for j in a_set {
                    assert!(
                        shares[*j].share.is_zero(),
                        "n={n} t={t}: set A's mask was visible in A-member {j}'s own share"
                    );
                }

                let poly = sharing_polynomial(n, &shares);
                assert_eq!(
                    poly.degree(),
                    t + l + 1,
                    "n={n} t={t}: basis direction {l} had the wrong degree"
                );
                assert!(poly.evaluate(Gf256::zero()).is_zero());

                rows.push((0..n).map(|id| shares[id].share).collect());
            }

            assert_eq!(
                rank(&rows),
                t,
                "n={n} t={t}: the mask reachable by varying ONE unqualified set spans {} \
                 dimension(s), not t. Dimension 1 is the CDI05 single-coefficient form and is a \
                 privacy break for t >= 2 (see the module docs).",
                rank(&rows)
            );
            assert_eq!(keys[0].mask_dimension(), t);
        }
    }

    /// The whole producible space: `{ h : deg h <= 2t, h(0) = 0 }`, dimension `2t`.
    #[test]
    fn the_mask_space_has_dimension_2t() {
        for (n, t) in CONFIGS {
            let keys = build_all(n, t);
            let rows = share_vectors(&keys, n, 12, 4 * t + 8);
            assert_eq!(
                rank(&rows),
                2 * t,
                "n={n} t={t}: sampled masks spanned {} dimensions, expected 2t",
                rank(&rows)
            );
        }
    }

    /// Binds [`GfPrzsKeys::zero_shares_at`] to the published basis: the assembled share must be
    /// `Σ_T Σ_l a_{T,l} · f^K_T(x_i) · x_i^l`, recomputed through the independent closed form.
    #[test]
    fn zero_shares_match_the_independent_t_coefficient_expansion() {
        for (n, t) in CONFIGS {
            let keys = build_all(n, t);
            let tsets = all_tsets(n, t);
            let count = 6;
            for id in 0..n {
                let got = keys[id].zero_shares_at(sid(11), 0, count).unwrap();
                assert_eq!(got.len(), count);
                for (nu, share) in got.iter().enumerate() {
                    let mut expected = Gf256::zero();
                    for r in held_ranks(n, t, id) {
                        let coeffs = keys[id].derived_coefficients(r, sid(11), nu).unwrap();
                        assert_eq!(coeffs.len(), t);
                        let basis = gf_set_basis_evals::<Gf256>(n, t, &tsets[r], id).unwrap();
                        assert_eq!(basis.len(), t);
                        for (a, b) in coeffs.coefficients().iter().zip(basis.iter()) {
                            expected = expected + *a * *b;
                        }
                    }
                    assert_eq!(share.share, expected, "n={n} t={t} party={id} nu={nu}");
                    assert_eq!(share.id, id);
                    assert_eq!(share.degree, 2 * t);
                }
            }
        }
    }

    #[test]
    fn basis_evals_vanish_on_their_own_set() {
        for (n, t) in CONFIGS {
            for tset in all_tsets(n, t) {
                for j in 0..n {
                    let evals = gf_set_basis_evals::<Gf256>(n, t, &tset, j).unwrap();
                    assert_eq!(evals.len(), t);
                    if tset.contains(&j) {
                        assert!(evals.iter().all(|e| e.is_zero()));
                    } else {
                        assert!(evals.iter().all(|e| !e.is_zero()));
                    }
                }
            }
        }
    }

    #[test]
    fn position_addressing_is_range_independent() {
        for (n, t) in CONFIGS {
            for k in &build_all(n, t) {
                let whole = k.zero_shares_at(sid(6), 0, 6).unwrap();
                let head = k.zero_shares_at(sid(6), 0, 2).unwrap();
                let tail = k.zero_shares_at(sid(6), 2, 4).unwrap();
                assert_eq!([head, tail].concat(), whole, "n={n} t={t}");
            }
        }
    }

    #[test]
    fn distinct_sessions_give_distinct_masks() {
        let (n, t) = (7usize, 2usize);
        let keys = build_all(n, t);
        let a = share_vectors(&keys, n, 21, 4);
        let b = share_vectors(&keys, n, 22, 4);
        assert_ne!(a, b);
        assert_eq!(a, share_vectors(&keys, n, 21, 4));
    }

    /// The binary mask must not be a function of the arithmetic one: the two stores hold the
    /// *same* keys, and without the [`PrzsDomain`] tag the binary coefficient would be the low
    /// byte of the window the arithmetic coefficient is reduced from. Checked here at the level
    /// this module actually consumes — derived `Gf256` coefficients, not raw integers.
    #[test]
    fn binary_coefficients_are_not_a_function_of_the_arithmetic_stream() {
        let key = [0x5du8; PRSS_KEY_LEN];
        let binary: Vec<Gf256> =
            derive_zero_coeff_ints_at(&key, sid(1), PrzsDomain::Binary, 0, 16, 8)
                .iter()
                .map(Gf256::from_prf_value)
                .collect();
        let arithmetic_low: Vec<Gf256> =
            derive_zero_coeff_ints_at(&key, sid(1), PrzsDomain::Arithmetic, 0, 16, 383)
                .iter()
                .map(Gf256::from_prf_value)
                .collect();
        assert_eq!(binary.len(), 16);
        assert_ne!(binary, arithmetic_low);
    }

    #[test]
    fn empty_request_is_empty() {
        let keys = build_all(4, 1);
        assert!(keys[0].zero_shares_at(sid(1), 0, 0).unwrap().is_empty());
    }

    #[test]
    fn rejects_a_degenerate_or_undersized_configuration() {
        let dealt = deal_keys(4, 1);
        assert!(matches!(
            GfPrzsKeys::<Gf256>::new(0, 4, 0, &[]),
            Err(PrzsError::DegenerateThreshold)
        ));
        assert!(matches!(
            GfPrzsKeys::<Gf256>::new(0, 3, 1, &dealt[0]),
            Err(PrzsError::PartyCountTooSmall { n: 3, bound: 4 })
        ));
        assert!(matches!(
            GfPrzsKeys::<Gf256>::new(9, 4, 1, &dealt[0]),
            Err(PrzsError::PartyOutOfRange { id: 9, n: 4 })
        ));
    }

    /// `Gf256`'s domain tops out at 255 points, so a party count above that has no evaluation
    /// domain at all. Rejected, never silently wrapped onto a reused x-coordinate.
    #[test]
    fn rejects_a_party_count_past_the_domain() {
        let n = 256usize;
        let t = 1usize;
        let dealt: Vec<(usize, [u8; PRSS_KEY_LEN])> = held_ranks(n, t, 0)
            .into_iter()
            .map(|r| (r, [0u8; PRSS_KEY_LEN]))
            .collect();
        assert!(matches!(
            GfPrzsKeys::<Gf256>::new(0, n, t, &dealt),
            Err(PrzsError::Gf2k(Gf2kError::NoSuitableDomain(256)))
        ));
        assert!(matches!(
            gf_set_basis_evals::<Gf256>(n, t, &[1], 0),
            Err(PrzsError::Gf2k(Gf2kError::NoSuitableDomain(256)))
        ));
    }

    #[test]
    fn rejects_a_partial_key_store() {
        let (n, t) = (7usize, 2usize);
        let dealt = deal_keys(n, t);
        let mut short = dealt[0].clone();
        short.pop();
        assert!(matches!(
            GfPrzsKeys::<Gf256>::new(0, n, t, &short),
            Err(PrzsError::KeyCountMismatch { .. })
        ));

        let mut wrong = dealt[0].clone();
        wrong[0].0 = all_tsets(n, t).len() + 1;
        assert!(matches!(
            GfPrzsKeys::<Gf256>::new(0, n, t, &wrong),
            Err(PrzsError::MissingKey(_))
        ));
    }

    #[test]
    fn rejects_coefficients_of_the_wrong_dimension() {
        let (n, t) = (7usize, 2usize);
        let keys = build_all(n, t);
        let tsets = all_tsets(n, t);

        let one_each: Vec<(usize, ZeroCoeffs<Gf256>)> = (0..tsets.len())
            .map(|r| (r, ZeroCoeffs::from_vec(vec![Gf256::one()], 1).unwrap()))
            .collect();
        assert!(matches!(
            keys[0].zero_share_from_coefficients(&one_each),
            Err(PrzsError::CoefficientCountMismatch { t: 2, got: 1 })
        ));

        let partial: Vec<(usize, ZeroCoeffs<Gf256>)> = held_ranks(n, t, 0)
            .iter()
            .skip(1)
            .map(|r| (*r, ZeroCoeffs::from_vec(vec![Gf256::one(); t], t).unwrap()))
            .collect();
        assert!(matches!(
            keys[0].zero_share_from_coefficients(&partial),
            Err(PrzsError::MissingCoefficients(_))
        ));
    }

    #[test]
    fn rejects_an_oversized_batch() {
        let keys = build_all(7, 2);
        assert!(matches!(
            keys[0].zero_shares_at(sid(1), 0, MAX_PRZS_COEFFS_PER_CALL),
            Err(PrzsError::BatchTooLarge { .. })
        ));
        assert!(matches!(
            keys[0].zero_shares_at(sid(1), usize::MAX, 1),
            Err(PrzsError::PositionOverflow)
        ));
    }

    #[test]
    fn gf_set_basis_evals_validates_its_inputs() {
        assert!(matches!(
            gf_set_basis_evals::<Gf256>(7, 0, &[], 0),
            Err(PrzsError::DegenerateThreshold)
        ));
        assert!(matches!(
            gf_set_basis_evals::<Gf256>(7, 2, &[0, 1], 7),
            Err(PrzsError::PartyOutOfRange { id: 7, n: 7 })
        ));
        for bad in [vec![0usize, 0], vec![0, 9], vec![0]] {
            assert!(matches!(
                gf_set_basis_evals::<Gf256>(7, 2, &bad, 3),
                Err(PrzsError::MalformedTset { .. })
            ));
        }
    }

    #[test]
    fn all_parties_agree_on_one_polynomial() {
        for (n, t) in CONFIGS {
            let keys = build_all(n, t);
            let per_party: Vec<Vec<GfShare<Gf256>>> = keys
                .iter()
                .map(|k| k.zero_shares_at(sid(13), 0, 3).unwrap())
                .collect();
            let domain = get_or_create_gf2k_domain::<Gf256>(n).unwrap();
            for nu in 0..3 {
                let xs: Vec<Gf256> = (0..=2 * t).map(|id| domain.element(id)).collect();
                let ys: Vec<Gf256> = (0..=2 * t).map(|id| per_party[id][nu].share).collect();
                let poly = lagrange_interpolate(&xs, &ys).unwrap();
                for id in (2 * t + 1)..n {
                    assert_eq!(
                        poly.evaluate(domain.element(id)),
                        per_party[id][nu].share,
                        "n={n} t={t}: party {id} was off the shared polynomial"
                    );
                }
            }
        }
    }

    /// The `Gf2k` twin of `przs::tests::new_rejects_a_party_count_whose_enumeration_would_be_unbounded`.
    ///
    /// `n <= K::MAX_DOMAIN_SIZE` bounds `n` at 255 for `Gf256` but says nothing about `C(n, t)`,
    /// which peaks there above `2^250`.
    #[test]
    fn new_rejects_a_party_count_whose_enumeration_would_be_unbounded() {
        assert!(matches!(
            GfPrzsKeys::<Gf256>::new(0, 64, 21, &[]),
            Err(PrzsError::TooManyUnqualifiedSets {
                n: 64,
                t: 21,
                max: MAX_UNQUALIFIED_SETS
            })
        ));
    }
}
