//! PRZS over the arithmetic field `F` — degree-`2t` pseudorandom sharings of zero, in the CDI05
//! §4 `t`-coefficient form.
//!
//! **Phase: PREPROCESSING only.** Derivation is local and non-interactive, but its output is a
//! degree-`2t` object and a degree-`2t` opening is legal only in the synchronous, abort-permitted
//! preprocessing phase — never on the asynchronous robust online path. See the
//! [module docs](super) for the full statement and for the attack the single-coefficient form
//! enables.
//!
//! Structurally this is [`PrssKeys`](crate::honeybadger::prss::prss::PrssKeys) with three
//! differences, all of them load-bearing:
//!
//! | | `PrssKeys` | `PrzsKeys` |
//! |---|---|---|
//! | secret | `Σ_T r_T`, pseudorandom | `0`, always and exactly |
//! | degree | `t` | `2t` |
//! | pseudorandom scalars per set | 1 | **`t`** |
//!
//! The conversion coefficient `f_T(x_id)` is the same object in both, built by the same
//! [`build_all_f_polys`], because a PRZS mask has to live in the same conversion family as the
//! PRSS sharings it masks.

use ark_ff::{FftField, PrimeField};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain, Polynomial};

use crate::common::share::ShareError;
use crate::honeybadger::{
    fpmul::build_all_f_polys,
    prss::{
        prss::{all_tsets, bounded_set_count, held_ranks},
        MAX_UNQUALIFIED_SETS, PRSS_KEY_LEN,
    },
    przs::{
        coefficient_window, derive_zero_coeff_ints_at, PrzsDomain, PrzsError, ZeroCoeffs,
        PRZS_REDUCTION_SLACK_BITS,
    },
    robust_interpolate::robust_interpolate::RobustShare,
    SessionId,
};

/// The `t` basis directions of unqualified set `T`'s mask space, evaluated at party `j`'s point.
///
/// `set_basis_evals(n, t, T, j)[l - 1] = f_T(x_j) · x_j^l` for `l = 1..=t`, i.e. the evaluation at
/// `x_j` of the `l`-th basis polynomial of
///
/// ```text
/// { h : deg h <= 2t, h(0) = 0, h|_T = 0 }        dimension exactly t
/// ```
///
/// This is the security-critical object of the whole module, exposed rather than hidden because
/// the property that matters about it is its **length**: it must be `t`, and a `t` of 1 for
/// `t > 1` is the silent privacy break of §6.5. An auditor can check the invariant here, and the
/// module's tests check that [`PrzsKeys::zero_shares_at`] really is the `t`-term expansion over
/// exactly these values.
///
/// Computed from the closed product form `f_T(x_j) = Π_{m∈T} (x_j − x_m)/(0 − x_m)` rather than
/// by interpolation. That is deliberately a *different* code path from the `build_all_f_polys`
/// that [`PrzsKeys::new`] uses, so that the two cross-check each other in tests instead of
/// sharing a bug.
///
/// # Errors
/// - [`PrzsError::DegenerateThreshold`] for `t == 0`.
/// - [`PrzsError::MalformedTset`] if `tset` is not a set of `t` distinct indices below `n`.
/// - [`PrzsError::PartyOutOfRange`] if `j >= n`.
pub fn set_basis_evals<F: PrimeField>(
    n: usize,
    t: usize,
    tset: &[usize],
    j: usize,
) -> Result<Vec<F>, PrzsError> {
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

    let domain = GeneralEvaluationDomain::<F>::new(n).ok_or(ShareError::NoSuitableDomain(n))?;
    let x_j = domain.element(j);

    // f_T(x_j) = Π_{m ∈ T} (x_j − x_m) / (0 − x_m). Every FFT-domain point is a root of unity and
    // therefore nonzero, so `-x_m` is always invertible; the `ok_or` is a belt-and-braces guard
    // against a future domain whose element(0) is 0, never a reachable branch today.
    let mut f_t = F::one();
    for m in tset {
        let x_m = domain.element(*m);
        let inv = (-x_m).inverse().ok_or(ShareError::InvalidInput)?;
        f_t *= (x_j - x_m) * inv;
    }

    let mut evals = Vec::with_capacity(t);
    let mut pow = F::one();
    for _ in 0..t {
        // `l` starts at 1: a basis polynomial with a constant term would break `h(0) = 0`.
        pow *= x_j;
        evals.push(f_t * pow);
    }
    Ok(evals)
}

/// One party's PRZS key material: the PRSS keys it holds, plus the per-set conversion coefficient
/// and the `t` basis powers its share assembly needs.
///
/// **Phase: PREPROCESSING only** — see the [module docs](super).
#[derive(Clone)]
pub struct PrzsKeys<F: FftField> {
    id: usize,
    n: usize,
    t: usize,
    /// `(rank, key, f_T(x_id))` for each set this party is outside of, ordered by rank. Identical
    /// in shape and in value to `PrssKeys`'s, because a PRZS mask must live in the same
    /// conversion family as the sharings it masks.
    entries: Vec<(usize, [u8; PRSS_KEY_LEN], F)>,
    /// `x_id^1 .. x_id^t`.
    ///
    /// INVARIANT: `basis_powers.len() == t`. This vector *is* the `t`-coefficient form at the
    /// assembly site — a share is built by zipping a set's coefficients against it, so a mask of
    /// the wrong dimension cannot be assembled, only rejected.
    basis_powers: Vec<F>,
}

/// Redacts the key bytes. `PrssKeys` derives `Debug` and prints its keys; a PRZS key store holds
/// the same secrets, and a logged mask key retroactively de-randomises every preprocessing item
/// ever derived from it, so this one does not.
impl<F: FftField> std::fmt::Debug for PrzsKeys<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrzsKeys")
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

impl<F: PrimeField> PrzsKeys<F> {
    /// Builds from the keys this party holds, indexed by rank in
    /// [`all_tsets`](crate::honeybadger::prss::prss::all_tsets) — the *same* keys and the *same*
    /// ranks as [`PrssKeys::new`](crate::honeybadger::prss::prss::PrssKeys::new), since PRZS
    /// reuses the PRSS key family under its own KDF label.
    ///
    /// Requires a key for every set the party is outside of. A partial store would silently
    /// produce a mask of *lower dimension* than `t·C(n−1,t)`, which is the failure this whole
    /// module exists to prevent, so it is rejected rather than tolerated.
    ///
    /// # Errors
    /// - [`PrzsError::DegenerateThreshold`] for `t == 0`: the only degree-0 sharing of zero is the
    ///   constant 0, which masks nothing. A `warn!` here would be the `ℓ`/`κ` misconfiguration
    ///   class the repo has already shipped once; it is a hard error.
    /// - [`PrzsError::PartyCountTooSmall`] for `n < 3t+1`: a degree-`2t` sharing needs `2t+1`
    ///   points to reconstruct at all and `3t+1` for the repo's detect-with-probability-1
    ///   guarantee, so producing one below the bound would be producing an object nothing can
    ///   consume.
    /// - [`PrzsError::TooManyUnqualifiedSets`] when `C(n, t)` is above
    ///   [`MAX_UNQUALIFIED_SETS`](crate::honeybadger::prss::MAX_UNQUALIFIED_SETS) or overflows,
    ///   raised before the enumeration allocates.
    /// - [`PrzsError::PartyOutOfRange`], [`PrzsError::KeyCountMismatch`],
    ///   [`PrzsError::MissingKey`].
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
        // Before `all_tsets`, which is the allocation this rejects.
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
        let polys = build_all_f_polys::<F>(n, my_tsets)?;
        let domain = GeneralEvaluationDomain::<F>::new(n).ok_or(ShareError::NoSuitableDomain(n))?;
        let x_id = domain.element(id);

        let mut entries = Vec::with_capacity(held.len());
        for rank in held {
            let key = keys
                .iter()
                .find_map(|(r, k)| (*r == rank).then_some(*k))
                .ok_or(PrzsError::MissingKey(rank))?;
            let coeff = polys[&tsets[rank]].evaluate(&x_id);
            entries.push((rank, key, coeff));
        }

        // `t` powers, `x_id^1 .. x_id^t` — never `x_id^0`, which would break `h(0) = 0`.
        let mut basis_powers = Vec::with_capacity(t);
        let mut pow = F::one();
        for _ in 0..t {
            pow *= x_id;
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

    /// Never true for a `PrzsKeys` built by [`Self::new`]: `C(n−1, t) >= 1` for any valid `n > t`,
    /// and `new` rejects a key set that doesn't match the held ranks. Present because `len`
    /// without it is a clippy error under `-D warnings`.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The degree of every sharing this store produces: **`2t`**, fixed.
    ///
    /// Not a parameter. A degree-`t` zero sharing is a different object with a different security
    /// analysis and a different legal phase (it may be used online, where degree `2t` may not), so
    /// it gets its own type if it is ever wanted — it does not get a flag on this one.
    pub fn degree(&self) -> usize {
        2 * self.t
    }

    /// The dimension of the mask, from the adversary's point of view: **`t`**.
    ///
    /// This is the number that must not be 1. It is the residual freedom of a degree-`2t`
    /// polynomial once its constant term (public, it is the opened value) and the adversary's own
    /// `t` evaluations are fixed, and the mask must cover all of it. See the
    /// [module docs](super) for what covering only one dimension leaks, and
    /// `single_set_mask_spans_exactly_t_dimensions` for the test that measures it.
    pub fn mask_dimension(&self) -> usize {
        self.basis_powers.len()
    }

    /// Alias of [`Self::mask_dimension`] from the derivation side: `t` PRF coefficients are drawn
    /// per unqualified set per zero sharing, so one sharing costs `t · C(n−1, t)` PRF streams.
    pub fn coefficients_per_set(&self) -> usize {
        self.basis_powers.len()
    }

    /// The `t` coefficients this party derives for one unqualified set at one sharing index.
    ///
    /// Exposed for tests and audits: it returns values this party already holds, so it reveals
    /// nothing it does not know. The returned [`ZeroCoeffs`] carries the `t`-count invariant.
    ///
    /// # Errors
    /// - [`PrzsError::MissingKey`] if this party is inside set `rank` and therefore holds no key
    ///   for it. (Its contribution to this party's share would be zero anyway, since
    ///   `f_T(x_id) = 0` for `id ∈ T`; the error reports the absence rather than inventing a
    ///   value.)
    pub fn derived_coefficients(
        &self,
        rank: usize,
        session_id: SessionId,
        index: usize,
    ) -> Result<ZeroCoeffs<F>, PrzsError> {
        let key = self
            .entries
            .iter()
            .find_map(|(r, k, _)| (*r == rank).then_some(k))
            .ok_or(PrzsError::MissingKey(rank))?;
        let (start, count) = coefficient_window(index, 1, self.t)?;
        let bits = F::MODULUS_BIT_SIZE as usize + PRZS_REDUCTION_SLACK_BITS;
        let raw =
            derive_zero_coeff_ints_at(key, session_id, PrzsDomain::Arithmetic, start, count, bits);
        let coeffs: Vec<F> = raw.iter().map(|v| F::from(v.clone())).collect();
        ZeroCoeffs::from_vec(coeffs, self.t)
    }

    /// This party's shares of the degree-`2t` zero sharings at absolute positions
    /// `start .. start + count`.
    ///
    /// Purely local, zero rounds, zero bytes:
    ///
    /// ```text
    /// share_i(ν) = Σ_{T ∌ i}  f_T(x_i) · Σ_{l=1..t} a_{T,l}(ν) · x_i^l
    /// ```
    ///
    /// which is the evaluation at `x_i` of `h_ν(X) = Σ_T f_T(X)·Σ_l a_{T,l}(ν) X^l`. Every term
    /// vanishes at `X = 0` because the inner sum starts at `l = 1`, so `h_ν(0) = 0` **exactly**,
    /// for every coefficient assignment — the zero-ness is structural, not statistical, and there
    /// is nothing to check.
    ///
    /// Every party must pass the identical `session_id`, `start` and `count`. The derivation is
    /// deterministic and there is no message exchange left to catch a mismatch; parties that
    /// disagree produce shares of *different* polynomials, whose sum is a degree-`2t` sharing of a
    /// nonzero value, and the resulting opening is silently wrong rather than detectably so.
    ///
    /// **The `session_id` must never be reused, and a consumed range must be burned rather than
    /// rewound on an abort or retry.** Re-deriving an already-opened position hands the adversary
    /// the mask in advance; this is the VERIA-222 cursor-rewind class, and PRZS has exactly the
    /// same exposure to it as `PRandInt`.
    ///
    /// # Errors
    /// - [`PrzsError::BatchTooLarge`] / [`PrzsError::PositionOverflow`] from
    ///   [`coefficient_window`].
    /// - [`PrzsError::CoefficientCountMismatch`] if the store's basis is not `t`-dimensional,
    ///   which [`Self::new`] makes unreachable and which is re-checked here anyway, because this
    ///   is the one invariant whose violation is invisible downstream.
    pub fn zero_shares_at(
        &self,
        session_id: SessionId,
        start: usize,
        count: usize,
    ) -> Result<Vec<RobustShare<F>>, PrzsError> {
        self.check_basis()?;
        let (coeff_start, coeff_count) = coefficient_window(start, count, self.t)?;
        let mut shares = vec![RobustShare::new(F::zero(), self.id, self.degree()); count];
        if count == 0 {
            return Ok(shares);
        }

        let bits = F::MODULUS_BIT_SIZE as usize + PRZS_REDUCTION_SLACK_BITS;
        for (_, key, f_t) in &self.entries {
            let raw = derive_zero_coeff_ints_at(
                key,
                session_id,
                PrzsDomain::Arithmetic,
                coeff_start,
                coeff_count,
                bits,
            );
            if raw.len() != coeff_count {
                return Err(PrzsError::CoefficientCountMismatch {
                    t: coeff_count,
                    got: raw.len(),
                });
            }
            for (nu, chunk) in raw.chunks_exact(self.t).enumerate() {
                let mut inner = F::zero();
                for (a, x_pow) in chunk.iter().zip(self.basis_powers.iter()) {
                    inner += F::from(a.clone()) * x_pow;
                }
                shares[nu].share[0] += inner * f_t;
            }
        }
        Ok(shares)
    }

    /// Assembles one share from **explicit** per-set coefficients instead of the PRF.
    ///
    /// `coeffs` is a `(rank, coefficients)` table; every rank this party holds must appear.
    /// Ranks it does not hold may appear and are ignored — soundly, because `f_T(x_id) = 0` for
    /// `id ∈ T` makes their contribution identically zero — so the natural usage is to build one
    /// table over all `C(n,t)` ranks and hand the same table to every party.
    ///
    /// Exists for two reasons: a perfect-privacy deployment that refuses the PRF assumption can
    /// drive PRZS from dealt randomness through this entry point, and it is what lets the tests
    /// measure the dimension of the producible mask space directly rather than inferring it.
    ///
    /// # Errors
    /// - [`PrzsError::MissingCoefficients`] for a held rank absent from the table.
    /// - [`PrzsError::CoefficientCountMismatch`] if any entry does not carry exactly `t`
    ///   coefficients. [`ZeroCoeffs`] already enforces this at construction; the second check is
    ///   here because a `ZeroCoeffs` built for a *different* `t` would otherwise pass.
    pub fn zero_share_from_coefficients(
        &self,
        coeffs: &[(usize, ZeroCoeffs<F>)],
    ) -> Result<RobustShare<F>, PrzsError> {
        self.check_basis()?;
        let mut acc = F::zero();
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
            let mut inner = F::zero();
            for (a, x_pow) in set.coefficients().iter().zip(self.basis_powers.iter()) {
                inner += *a * x_pow;
            }
            acc += inner * f_t;
        }
        Ok(RobustShare::new(acc, self.id, self.degree()))
    }

    /// Re-asserts the `t`-coefficient invariant at every assembly site.
    ///
    /// `new` establishes it, so this is unreachable — which is the point. The failure mode this
    /// module guards against is a future edit that quietly shortens the basis, and that edit
    /// would leave every functional test passing. A cheap check on the one line where the mask is
    /// actually built is the cheapest place to notice.
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
    use crate::common::lagrange_interpolate;
    use crate::common::{ProtocolSessionId, SecretSharingScheme};
    use crate::honeybadger::ProtocolType;
    use ark_bls12_381::Fr;
    use ark_ff::{Field, One, Zero};
    use ark_poly::univariate::DensePolynomial;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    /// `n = 3t+1` at t = 1, 2, 3. `t = 1` is included deliberately even though the two PRZS forms
    /// coincide there — it is the configuration a careless test suite would stop at, and the one
    /// that proves nothing.
    const CONFIGS: [(usize, usize); 3] = [(4, 1), (7, 2), (10, 3)];

    fn sid(exec: u64) -> SessionId {
        SessionId::new(
            ProtocolType::PRandInt,
            SessionId::pack_slot(exec, 0, 0),
            111,
        )
    }

    /// Deal one key per maximal unqualified set, then hand each party the keys for the sets it is
    /// outside of — i.e. what the one-time PRSS setup produces, reused verbatim by PRZS.
    fn deal_keys(n: usize, t: usize) -> Vec<Vec<(usize, [u8; PRSS_KEY_LEN])>> {
        let mut rng = StdRng::seed_from_u64(7);
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

    fn build_all(n: usize, t: usize) -> Vec<PrzsKeys<Fr>> {
        let dealt = deal_keys(n, t);
        (0..n)
            .map(|id| PrzsKeys::<Fr>::new(id, n, t, &dealt[id]).unwrap())
            .collect()
    }

    /// The polynomial the `n` shares of one sharing lie on, recovered by plain interpolation
    /// through all `n` points (all honest here, so no error correction is wanted).
    fn sharing_polynomial(n: usize, shares: &[RobustShare<Fr>]) -> DensePolynomial<Fr> {
        let domain = GeneralEvaluationDomain::<Fr>::new(n).unwrap();
        let xs: Vec<Fr> = shares.iter().map(|s| domain.element(s.id)).collect();
        let ys: Vec<Fr> = shares.iter().map(|s| s.share[0]).collect();
        lagrange_interpolate(&xs, &ys).unwrap()
    }

    /// Degree read straight off the coefficient vector.
    ///
    /// Not `Polynomial::degree`: ark's `DensePolynomial::degree` asserts that the leading
    /// coefficient is nonzero, which makes it a panic rather than an answer on any interpolant
    /// that happens to carry trailing zeros — and a mask whose top coefficients vanish is exactly
    /// the case these tests are trying to detect.
    fn poly_degree(p: &DensePolynomial<Fr>) -> usize {
        if p.coeffs.is_empty() {
            return 0;
        }
        let mut d = p.coeffs.len() - 1;
        while d > 0 && p.coeffs[d].is_zero() {
            d -= 1;
        }
        d
    }

    /// Rank of a set of vectors over `Fr`, by Gaussian elimination. The dimension counts in this
    /// module are the security property, so they are measured, not asserted.
    fn rank(rows: &[Vec<Fr>]) -> usize {
        let mut m: Vec<Vec<Fr>> = rows.to_vec();
        let cols = m.first().map(|r| r.len()).unwrap_or(0);
        let mut r = 0usize;
        for c in 0..cols {
            let pivot = (r..m.len()).find(|&i| !m[i][c].is_zero());
            let Some(p) = pivot else { continue };
            m.swap(r, p);
            let inv = m[r][c].inverse().unwrap();
            for v in m[r].iter_mut() {
                *v *= inv;
            }
            for i in 0..m.len() {
                if i != r && !m[i][c].is_zero() {
                    let factor = m[i][c];
                    for k in 0..cols {
                        let sub = m[r][k] * factor;
                        m[i][k] -= sub;
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

    fn share_vectors(keys: &[PrzsKeys<Fr>], n: usize, exec: u64, count: usize) -> Vec<Vec<Fr>> {
        let per_party: Vec<Vec<RobustShare<Fr>>> = keys
            .iter()
            .map(|k| k.zero_shares_at(sid(exec), 0, count).unwrap())
            .collect();
        (0..count)
            .map(|nu| (0..n).map(|id| per_party[id][nu].share[0]).collect())
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

    /// The defining property: `n` locally-derived shares of a *degree-`2t`* polynomial whose
    /// constant term is exactly zero, with no communication anywhere.
    #[test]
    fn zero_sharing_reconstructs_to_zero_at_degree_2t() {
        for (n, t) in CONFIGS {
            let keys = build_all(n, t);
            let count = 4;
            let per_party: Vec<Vec<RobustShare<Fr>>> = keys
                .iter()
                .map(|k| k.zero_shares_at(sid(3), 0, count).unwrap())
                .collect();

            for nu in 0..count {
                let shares: Vec<RobustShare<Fr>> =
                    (0..n).map(|id| per_party[id][nu].clone()).collect();
                assert!(shares.iter().all(|s| s.degree == 2 * t));
                assert!(shares.iter().enumerate().all(|(i, s)| s.id == i));

                let (coeffs, secret) = RobustShare::recover_secret(&shares, n, t)
                    .expect("degree-2t reconstruction from all n honest shares");
                assert!(
                    secret.is_zero(),
                    "n={n} t={t}: sharing {nu} was not of zero"
                );
                assert!(
                    coeffs.len() <= 2 * t + 1,
                    "n={n} t={t}: {} coefficients, expected at most {}",
                    coeffs.len(),
                    2 * t + 1
                );
                assert!(
                    coeffs.first().map(|c| c.is_zero()).unwrap_or(true),
                    "n={n} t={t}: constant term was not zero"
                );
            }
        }
    }

    /// The other half of "degree `2t`": it must not be a degree-`t` sharing in disguise. A
    /// degree-`t` zero sharing would be a *legal* object but the wrong one — it would fail to
    /// mask the `t` extra coefficients a degree-`2t` opening exposes, which is the same leak the
    /// single-coefficient form causes by a different route.
    #[test]
    fn zero_sharing_is_not_a_degree_t_sharing() {
        for (n, t) in CONFIGS {
            let keys = build_all(n, t);
            let count = 8;
            let per_party: Vec<Vec<RobustShare<Fr>>> = keys
                .iter()
                .map(|k| k.zero_shares_at(sid(4), 0, count).unwrap())
                .collect();

            let mut saw_above_t = false;
            for nu in 0..count {
                let shares: Vec<RobustShare<Fr>> =
                    (0..n).map(|id| per_party[id][nu].clone()).collect();
                let poly = sharing_polynomial(n, &shares);
                assert!(
                    poly_degree(&poly) <= 2 * t,
                    "n={n} t={t}: sharing {nu} had degree {} > 2t",
                    poly_degree(&poly)
                );
                assert!(
                    poly.evaluate(&Fr::zero()).is_zero(),
                    "n={n} t={t}: sharing {nu} did not vanish at 0"
                );
                if poly_degree(&poly) > t {
                    saw_above_t = true;
                }
            }
            assert!(
                saw_above_t,
                "n={n} t={t}: every sampled sharing had degree <= t — this is a degree-t zero \
                 sharing wearing a degree-2t label"
            );
        }
    }

    /// **The test the single-coefficient form fails.**
    ///
    /// Freeze every unqualified set's coefficients to zero except one set `A` — the adversary's
    /// own set, the only one whose key it does not hold — and measure the dimension of the space
    /// of share vectors reachable by varying `A`'s coefficients alone. That dimension is the
    /// adversary's residual uncertainty in a masked degree-`2t` opening, and it must be `t`.
    ///
    /// A PRZS built on one pseudorandom scalar per set reaches dimension **1** here for every
    /// `t`, while passing `zero_sharing_reconstructs_to_zero_at_degree_2t` and every other
    /// functional test in this file. At `t = 1` the two forms coincide and this test cannot
    /// distinguish them, which is exactly why it is run at `t = 2` and `t = 3` as well.
    #[test]
    fn single_set_mask_spans_exactly_t_dimensions() {
        for (n, t) in CONFIGS {
            let keys = build_all(n, t);
            let tsets = all_tsets(n, t);
            let a_rank = 0usize;
            let a_set = &tsets[a_rank];

            let mut rows: Vec<Vec<Fr>> = Vec::with_capacity(t);
            for l in 0..t {
                let mut unit = vec![Fr::zero(); t];
                unit[l] = Fr::one();
                let table: Vec<(usize, ZeroCoeffs<Fr>)> = (0..tsets.len())
                    .map(|r| {
                        let c = if r == a_rank {
                            unit.clone()
                        } else {
                            vec![Fr::zero(); t]
                        };
                        (r, ZeroCoeffs::from_vec(c, t).unwrap())
                    })
                    .collect();

                let shares: Vec<RobustShare<Fr>> = (0..n)
                    .map(|id| keys[id].zero_share_from_coefficients(&table).unwrap())
                    .collect();

                // The adversary's own shares carry none of its own unknown coefficient:
                // `f_A(x_j) = 0` for `j ∈ A`. This is why it cannot strip `h_A` from its view.
                for j in a_set {
                    assert!(
                        shares[*j].share[0].is_zero(),
                        "n={n} t={t}: set A's mask was visible in A-member {j}'s own share"
                    );
                }

                // Basis polynomial `l` is `f_A(X)·X^{l+1}`, of degree exactly `t + l + 1`. The
                // `t` of them therefore have distinct degrees `t+1 .. 2t` and are independent.
                let poly = sharing_polynomial(n, &shares);
                assert_eq!(
                    poly_degree(&poly),
                    t + l + 1,
                    "n={n} t={t}: basis direction {l} had the wrong degree"
                );
                assert!(poly.evaluate(&Fr::zero()).is_zero());

                rows.push((0..n).map(|id| shares[id].share[0]).collect());
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

    /// The whole producible space, over all sets: `{ h : deg h <= 2t, h(0) = 0 }`, dimension `2t`.
    /// Upper bound is structural; the lower bound is what says the PRF really is filling it.
    #[test]
    fn the_mask_space_has_dimension_2t() {
        for (n, t) in CONFIGS {
            let keys = build_all(n, t);
            let samples = 4 * t + 8;
            let rows = share_vectors(&keys, n, 12, samples);
            assert_eq!(
                rank(&rows),
                2 * t,
                "n={n} t={t}: sampled masks spanned {} dimensions, expected 2t",
                rank(&rows)
            );
        }
    }

    /// Binds [`PrzsKeys::zero_shares_at`] to the published basis: the assembled share must equal
    /// `Σ_T Σ_l a_{T,l} · f_T(x_i) · x_i^l`, recomputed through [`set_basis_evals`]'s independent
    /// closed-form code path. If the two ever disagree, one of the `f_T` families is wrong, and a
    /// wrong `f_T` family is a mask that does not vanish where it must.
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
                    let mut expected = Fr::zero();
                    for r in held_ranks(n, t, id) {
                        let coeffs = keys[id].derived_coefficients(r, sid(11), nu).unwrap();
                        assert_eq!(
                            coeffs.len(),
                            t,
                            "derived {} coefficients, expected t",
                            coeffs.len()
                        );
                        let basis = set_basis_evals::<Fr>(n, t, &tsets[r], id).unwrap();
                        assert_eq!(basis.len(), t);
                        for (a, b) in coeffs.coefficients().iter().zip(basis.iter()) {
                            expected += *a * *b;
                        }
                    }
                    assert_eq!(share.share[0], expected, "n={n} t={t} party={id} nu={nu}");
                    assert_eq!(share.id, id);
                    assert_eq!(share.degree, 2 * t);
                }
            }
        }
    }

    /// `set_basis_evals`'s closed product form must agree with the interpolated `f_T` that
    /// `PrzsKeys::new` uses, and must vanish on `T`.
    #[test]
    fn basis_evals_vanish_on_their_own_set() {
        for (n, t) in CONFIGS {
            for tset in all_tsets(n, t) {
                for j in 0..n {
                    let evals = set_basis_evals::<Fr>(n, t, &tset, j).unwrap();
                    assert_eq!(evals.len(), t);
                    if tset.contains(&j) {
                        assert!(
                            evals.iter().all(|e| e.is_zero()),
                            "n={n} t={t}: basis for {tset:?} did not vanish at member {j}"
                        );
                    } else {
                        assert!(
                            evals.iter().any(|e| !e.is_zero()),
                            "n={n} t={t}: basis for {tset:?} vanished at non-member {j}"
                        );
                    }
                }
            }
        }
    }

    /// Pool top-ups: the sharing at an absolute index never depends on which range was asked for.
    /// A rewound or misaligned cursor is a security failure, not a performance one (§6.5).
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
        let a = share_vectors(&keys, n, 21, 3);
        let b = share_vectors(&keys, n, 22, 3);
        assert_ne!(a, b);
        assert_eq!(a, share_vectors(&keys, n, 21, 3));
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
            PrzsKeys::<Fr>::new(0, 4, 0, &[]),
            Err(PrzsError::DegenerateThreshold)
        ));
        assert!(matches!(
            PrzsKeys::<Fr>::new(0, 3, 1, &dealt[0]),
            Err(PrzsError::PartyCountTooSmall { n: 3, bound: 4 })
        ));
        assert!(matches!(
            PrzsKeys::<Fr>::new(9, 4, 1, &dealt[0]),
            Err(PrzsError::PartyOutOfRange { id: 9, n: 4 })
        ));
    }

    #[test]
    fn rejects_a_partial_key_store() {
        let (n, t) = (7usize, 2usize);
        let dealt = deal_keys(n, t);
        let mut short = dealt[0].clone();
        short.pop();
        assert!(matches!(
            PrzsKeys::<Fr>::new(0, n, t, &short),
            Err(PrzsError::KeyCountMismatch { .. })
        ));

        let mut wrong = dealt[0].clone();
        let bad_rank = all_tsets(n, t).len() + 1;
        wrong[0].0 = bad_rank;
        assert!(matches!(
            PrzsKeys::<Fr>::new(0, n, t, &wrong),
            Err(PrzsError::MissingKey(_))
        ));
    }

    /// The assembly-site half of the `t`-coefficient enforcement: a `ZeroCoeffs` built for a
    /// different threshold is rejected rather than zero-padded or truncated.
    #[test]
    fn rejects_coefficients_of_the_wrong_dimension() {
        let (n, t) = (7usize, 2usize);
        let keys = build_all(n, t);
        let tsets = all_tsets(n, t);

        // One coefficient per set — the form the module exists to forbid.
        let one_each: Vec<(usize, ZeroCoeffs<Fr>)> = (0..tsets.len())
            .map(|r| (r, ZeroCoeffs::from_vec(vec![Fr::one()], 1).unwrap()))
            .collect();
        assert!(matches!(
            keys[0].zero_share_from_coefficients(&one_each),
            Err(PrzsError::CoefficientCountMismatch { t: 2, got: 1 })
        ));

        // A table missing a held rank.
        let held = held_ranks(n, t, 0);
        let partial: Vec<(usize, ZeroCoeffs<Fr>)> = held
            .iter()
            .skip(1)
            .map(|r| (*r, ZeroCoeffs::from_vec(vec![Fr::one(); t], t).unwrap()))
            .collect();
        assert!(matches!(
            keys[0].zero_share_from_coefficients(&partial),
            Err(PrzsError::MissingCoefficients(_))
        ));
    }

    /// Ranks this party is *inside* may appear in the table and contribute nothing, because
    /// `f_T(x_id) = 0` there. Relied on so that one table can be shared by all `n` parties.
    #[test]
    fn unheld_ranks_in_the_table_are_ignored() {
        let (n, t) = (7usize, 2usize);
        let keys = build_all(n, t);
        let tsets = all_tsets(n, t);

        let full: Vec<(usize, ZeroCoeffs<Fr>)> = (0..tsets.len())
            .map(|r| {
                let v: Vec<Fr> = (0..t).map(|l| Fr::from((r * 31 + l + 1) as u64)).collect();
                (r, ZeroCoeffs::from_vec(v, t).unwrap())
            })
            .collect();

        for id in 0..n {
            let held_only: Vec<(usize, ZeroCoeffs<Fr>)> = full
                .iter()
                .filter(|(r, _)| held_ranks(n, t, id).contains(r))
                .cloned()
                .collect();
            assert_eq!(
                keys[id].zero_share_from_coefficients(&full).unwrap(),
                keys[id].zero_share_from_coefficients(&held_only).unwrap()
            );
        }
    }

    #[test]
    fn rejects_an_oversized_batch() {
        use crate::honeybadger::przs::MAX_PRZS_COEFFS_PER_CALL;
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
    fn set_basis_evals_validates_its_inputs() {
        assert!(matches!(
            set_basis_evals::<Fr>(7, 0, &[], 0),
            Err(PrzsError::DegenerateThreshold)
        ));
        assert!(matches!(
            set_basis_evals::<Fr>(7, 2, &[0, 1], 7),
            Err(PrzsError::PartyOutOfRange { id: 7, n: 7 })
        ));
        assert!(matches!(
            set_basis_evals::<Fr>(7, 2, &[0, 0], 3),
            Err(PrzsError::MalformedTset { .. })
        ));
        assert!(matches!(
            set_basis_evals::<Fr>(7, 2, &[0, 9], 3),
            Err(PrzsError::MalformedTset { .. })
        ));
        assert!(matches!(
            set_basis_evals::<Fr>(7, 2, &[0], 3),
            Err(PrzsError::MalformedTset { .. })
        ));
    }

    /// Masks from different parties at the same position must be shares of *one* polynomial —
    /// the property that makes the sum a sharing at all. Checked by asserting the interpolant
    /// through the first `2t+1` points reproduces the remaining `t` points exactly.
    #[test]
    fn all_parties_agree_on_one_polynomial() {
        for (n, t) in CONFIGS {
            let keys = build_all(n, t);
            let per_party: Vec<Vec<RobustShare<Fr>>> = keys
                .iter()
                .map(|k| k.zero_shares_at(sid(13), 0, 3).unwrap())
                .collect();
            let domain = GeneralEvaluationDomain::<Fr>::new(n).unwrap();
            for nu in 0..3 {
                let xs: Vec<Fr> = (0..=2 * t).map(|id| domain.element(id)).collect();
                let ys: Vec<Fr> = (0..=2 * t).map(|id| per_party[id][nu].share[0]).collect();
                let poly = lagrange_interpolate(&xs, &ys).unwrap();
                for id in (2 * t + 1)..n {
                    assert_eq!(
                        poly.evaluate(&domain.element(id)),
                        per_party[id][nu].share[0],
                        "n={n} t={t}: party {id} was off the shared polynomial"
                    );
                }
            }
        }
    }

    /// The `C(n, t)` cap, fired before `all_tsets` allocates.
    ///
    /// `n = 64, t = 21` clears the Byzantine bound (`3t+1 = 64`) and has `C(64,21) ~ 1.2e17`
    /// unqualified sets. PRZS would then want `t` PRF streams for each of them. A hang or an
    /// OOM here instead of a failure means the check has drifted below the enumeration.
    #[test]
    fn new_rejects_a_party_count_whose_enumeration_would_be_unbounded() {
        assert!(matches!(
            PrzsKeys::<Fr>::new(0, 64, 21, &[]),
            Err(PrzsError::TooManyUnqualifiedSets {
                n: 64,
                t: 21,
                max: MAX_UNQUALIFIED_SETS
            })
        ));
        // The Byzantine-bound check still comes first: it is the more specific diagnosis.
        assert!(matches!(
            PrzsKeys::<Fr>::new(0, 63, 21, &[]),
            Err(PrzsError::PartyCountTooSmall { .. })
        ));
    }
}
