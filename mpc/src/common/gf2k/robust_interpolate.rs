//! Robust reconstruction over a [`BinaryField`] domain — a mechanical port of
//! `honeybadger::robust_interpolate::robust_interpolate`, with `ark_poly::DensePolynomial<F>`
//! replaced by [`Poly<K>`] and `ark_ff::FftField` replaced by [`BinaryField`].

use ark_std::rand::Rng;
use std::collections::HashSet;

use crate::common::share::ShareError;
use crate::common::SecretSharingScheme;

use super::field::{BinaryField, Gf2kDomain};
use super::poly::{lagrange_interpolate, Poly};
use super::share::GfShare;
use super::Gf2kError;

impl<K: BinaryField> GfShare<K> {
    /// Full robust interpolation combining optimistic decoding and error correction.
    ///
    /// # Errors
    /// - `Gf2kError::InvalidInput` if `n < 3t + 1` (the Byzantine fault-tolerance bound), if
    ///   `shares` is empty, has mismatched degrees, duplicate/out-of-range ids, or too few
    ///   entries to attempt decoding.
    /// - `Gf2kError::DecodingError` if no valid degree-consistent polynomial can be recovered.
    pub fn recover_secret(
        shares: &[GfShare<K>],
        n: usize,
        t: usize,
    ) -> Result<(Vec<K>, K), Gf2kError> {
        // n >= 3t + 1 is required for Byzantine fault tolerance.
        if n < 3 * t + 1 {
            return Err(Gf2kError::InvalidInput(format!(
                "n ({n}) must be >= 3t + 1 ({}) for Byzantine fault tolerance",
                3 * t + 1
            )));
        }

        if shares.is_empty() {
            return Err(Gf2kError::InvalidInput("Share slice is empty".to_string()));
        }
        let degree = shares[0].degree;
        if !shares.iter().all(|share| share.degree == degree) {
            return Err(Gf2kError::ShareError(ShareError::DegreeMismatch));
        }

        let mut seen = HashSet::new();
        if !shares.iter().all(|s| seen.insert(s.id)) {
            return Err(Gf2kError::InvalidInput("Duplicate share Ids".to_string()));
        }

        for s in shares {
            if s.id >= n {
                return Err(Gf2kError::InvalidInput(format!(
                    "Share id {} is out of range: expected 0 <= id < n (n = {n})",
                    s.id
                )));
            }
        }

        let share_len = shares.len();
        if share_len < degree + t + 1 {
            return Err(Gf2kError::InvalidInput(format!(
                "Not enough shares provided ({share_len}) to attempt decoding for t={t}. At \
                 least {} shares are required.",
                degree + t + 1
            )));
        }

        let mut sorted_shares = shares.to_vec();
        sorted_shares.sort_by_key(|s| s.id);

        // === Step 1: Optimistic decoding attempt ===
        if let Ok(poly) = robust_interpolate_fnt(t, n, &sorted_shares[..degree + t + 1]) {
            let value_at_zero = poly.evaluate(K::zero());
            return Ok((poly.coeffs.clone(), value_at_zero));
        }
        // === Step 2: Fall back to online error correction ===
        let (poly, value_at_zero) = oec_decode(n, t, sorted_shares)?;
        Ok((poly.coeffs.clone(), value_at_zero))
    }
}

/// Conformance to the crate's established share-type contract (see `SecretSharingScheme`'s own
/// doc comment: implementing it is how a custom share type plugs into the rest of the crate's
/// public interface). This only asserts *signature* conformance — the same method names/shapes
/// as `RobustShare<F>` — not any additional behavioral guarantee: the real correctness
/// properties (the `n >= 3t + 1` bound, robust reconstruction under `<= t` active faults) live in
/// `recover_secret`'s own checks above and are validated by this module's test suite, not by the
/// trait bound itself.
impl<K: BinaryField> SecretSharingScheme<K> for GfShare<K> {
    type SecretType = K;
    type Error = Gf2kError;

    fn compute_shares(
        secret: Self::SecretType,
        n: usize,
        degree: usize,
        _ids: Option<&[usize]>,
        rng: &mut impl Rng,
    ) -> Result<Vec<Self>, Self::Error> {
        GfShare::compute_shares(secret, n, degree, rng)
    }

    fn recover_secret(
        shares: &[Self],
        n: usize,
        t: usize,
    ) -> Result<(Vec<Self::SecretType>, Self::SecretType), Self::Error> {
        GfShare::recover_secret(shares, n, t)
    }
}

impl<K: BinaryField> GfShare<K> {
    /// Naive Lagrange reconstruction — trusts every given share as-is, with **no** error
    /// correction. Mirrors `common::share::shamir::NonRobustShare::recover_secret` (including
    /// its unused `_t` parameter, kept only so call sites mirror `recover_secret`'s signature).
    ///
    /// This is a genuinely different reconstruction primitive from [`GfShare::recover_secret`],
    /// not a weaker version of it: it exists for protocols (like the eventual `GfRanDouSha`) that
    /// establish trust in the shares some other way — e.g. a cross-degree consistency check —
    /// rather than relying on Reed-Solomon fault tolerance inside reconstruction itself. Using
    /// this where the robust path is actually needed would silently drop the `t`-fault guarantee.
    ///
    /// # Errors
    /// - `Gf2kError::InvalidInput` if `shares` is empty, has duplicate or out-of-range ids,
    ///   mismatched degrees, or fewer than `degree + 1` entries.
    /// - `Gf2kError::ShareError` if the interpolated polynomial's true degree exceeds the shares'
    ///   claimed degree.
    pub fn recover_secret_naive(
        shares: &[GfShare<K>],
        n: usize,
        _t: usize,
    ) -> Result<(Vec<K>, K), Gf2kError> {
        if shares.is_empty() {
            return Err(Gf2kError::InvalidInput("Share slice is empty".to_string()));
        }
        let mut seen = HashSet::new();
        if !shares.iter().all(|s| seen.insert(s.id)) {
            return Err(Gf2kError::InvalidInput("Duplicate share Ids".to_string()));
        }
        let degree = shares[0].degree;
        if !shares.iter().all(|s| s.degree == degree) {
            return Err(Gf2kError::ShareError(ShareError::DegreeMismatch));
        }
        if shares.len() < degree + 1 {
            return Err(Gf2kError::InvalidInput(format!(
                "Not enough shares ({}) to reconstruct degree {degree} (need {})",
                shares.len(),
                degree + 1
            )));
        }

        let domain = Gf2kDomain::<K>::new(n)?;
        let (x_vals, y_vals): (Vec<K>, Vec<K>) = shares
            .iter()
            .map(|s| {
                if s.id >= n {
                    Err(Gf2kError::InvalidInput(format!(
                        "share id {} out of range (n = {n})",
                        s.id
                    )))
                } else {
                    Ok((domain.element(s.id), s.share))
                }
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .unzip();

        let result_poly = lagrange_interpolate(&x_vals, &y_vals)?;
        if result_poly.degree() > degree {
            return Err(Gf2kError::ShareError(ShareError::DegreeMismatch));
        }
        let constant_term = result_poly.evaluate(K::zero());
        Ok((result_poly.coeffs, constant_term))
    }
}

/// Optimistically interpolates a polynomial from an arbitrary subset of `degree + 1` shares and
/// checks it against all `degree + t + 1` shares given.
/// Based on https://pagespro.isae-supaero.fr/IMG/pdf/FNT_submitted.pdf
fn robust_interpolate_fnt<K: BinaryField>(
    t: usize,
    n: usize,
    shares: &[GfShare<K>],
) -> Result<Poly<K>, Gf2kError> {
    let degree = shares[0].degree;
    let domain = Gf2kDomain::<K>::new(n)?;
    let subset = &shares[..=degree];
    let xs: Vec<K> = subset.iter().map(|s| domain.element(s.id)).collect();
    let ys: Vec<K> = subset.iter().map(|s| s.share).collect();

    // Step 1: Compute A(x) = ∏ (x - x_i)
    let mut a_poly = Poly::one();
    for &x in &xs {
        a_poly = &a_poly * &Poly::monomial(x);
    }

    // Step 2: Compute A'(x)
    let a_derivative = a_poly.derivative();

    // Step 3: Build P(x) = sum_i y_i * A(x) / (A'(x_i) * (x - x_i))
    let mut interpolated = Poly::zero();
    for (i, &x_i) in xs.iter().enumerate() {
        let denom = a_derivative.evaluate(x_i);
        let denom_inv = denom.inverse().ok_or_else(|| {
            Gf2kError::PolynomialOperationError(
                "Denominator evaluated to zero during interpolation basis calculation".into(),
            )
        })?;
        let scalar = ys[i] * denom_inv;

        // A(x) / (x - x_i)
        let term_divisor = Poly::monomial(x_i);
        let (basis_poly, rem) = a_poly.div_with_remainder(&term_divisor)?;
        if !rem.is_zero() {
            return Err(Gf2kError::PolynomialOperationError(
                "A(x) not perfectly divisible by (x - x_i)".into(),
            ));
        }

        interpolated = &interpolated + &(&basis_poly * scalar);
    }

    // Step 4: Verify agreement
    let valid_count = shares
        .iter()
        .map(|s| (domain.element(s.id), s.share))
        .filter(|&(x, y)| interpolated.evaluate(x) == y)
        .count();

    if valid_count >= degree + t + 1 {
        Ok(interpolated)
    } else {
        Err(Gf2kError::DecodingError(
            "Not enough shares matched the interpolated polynomial".into(),
        ))
    }
}

/// Batched analogue of [`GfShare::recover_secret`] for the `(sender_id, values)` representation
/// used by batch reconstruction (`honeybadger::gf_batch_recon`). Mechanical port of
/// `honeybadger::robust_interpolate::robust_interpolate::batch_recover_secret`, with
/// `DensePolynomial<F>` replaced by [`Poly<K>`].
///
/// `evals_by_sender[i]` is `(sender_id, values)` where `values[c]` is that sender's evaluation of
/// the `c`-th independent degree-`degree` polynomial. All inner vectors must have the same length
/// (`batch_len` = number of chunks). Returns one coefficient vector (length `degree + 1`) per
/// chunk.
///
/// The Lagrange interpolation basis depends only on the evaluation points (the sender ids), which
/// are identical across chunks, so it is built once and applied to every chunk as a linear
/// combination, instead of rebuilding `A(x)` and the per-point polynomial divisions for each
/// chunk. Each chunk is still verified against all `degree + t + 1` evaluations; any chunk
/// failing the optimistic check falls back to the full robust `recover_secret` (OEC/Gao) path for
/// that chunk alone, so `t`-fault tolerance is unchanged — only the redundant per-chunk fixed
/// cost is removed.
pub fn batch_recover_secret<K: BinaryField>(
    evals_by_sender: &[(usize, Vec<K>)],
    n: usize,
    degree: usize,
    t: usize,
) -> Result<Vec<Vec<K>>, Gf2kError> {
    if n < 3 * t + 1 {
        return Err(Gf2kError::InvalidInput(format!(
            "n ({n}) must be >= 3t + 1 ({}) for Byzantine fault tolerance",
            3 * t + 1
        )));
    }
    if evals_by_sender.is_empty() {
        return Err(Gf2kError::InvalidInput("No evaluations provided".to_string()));
    }
    let batch_len = evals_by_sender[0].1.len();
    if batch_len == 0 {
        return Err(Gf2kError::InvalidInput("Empty batch".to_string()));
    }
    if !evals_by_sender.iter().all(|(_, v)| v.len() == batch_len) {
        return Err(Gf2kError::InvalidInput(
            "Inconsistent batch widths".to_string(),
        ));
    }

    let mut sorted: Vec<(usize, &Vec<K>)> =
        evals_by_sender.iter().map(|(id, v)| (*id, v)).collect();
    sorted.sort_by_key(|(id, _)| *id);

    let mut seen = HashSet::new();
    for (id, _) in &sorted {
        if !seen.insert(*id) {
            return Err(Gf2kError::InvalidInput("Duplicate sender id".to_string()));
        }
        if *id >= n {
            return Err(Gf2kError::InvalidInput(format!(
                "Sender id {id} out of range (n = {n})"
            )));
        }
    }

    let needed = degree + t + 1;
    if sorted.len() < needed {
        return Err(Gf2kError::InvalidInput(format!(
            "Not enough evaluations ({}) for degree {degree} and t {t} (need {needed})",
            sorted.len()
        )));
    }

    let domain = Gf2kDomain::<K>::new(n)?;

    // The lowest (degree + 1) senders define the optimistic interpolation subset — matches
    // `robust_interpolate_fnt`, which interpolates from `shares[..=degree]` on the id-sorted
    // slice.
    let m = degree + 1;
    let subset_xs: Vec<K> = (0..m).map(|i| domain.element(sorted[i].0)).collect();

    // Build the Lagrange basis {L_i(x)} for the subset ONCE:
    //   A(x) = prod_i (x - x_i),  L_i(x) = A(x) / ((x - x_i) * A'(x_i)).
    let mut a_poly = Poly::one();
    for &x in &subset_xs {
        a_poly = &a_poly * &Poly::monomial(x);
    }
    let a_derivative = a_poly.derivative();

    let mut basis: Vec<Poly<K>> = Vec::with_capacity(m);
    for &x_i in &subset_xs {
        let denom = a_derivative.evaluate(x_i);
        let inv = denom.inverse().ok_or_else(|| {
            Gf2kError::PolynomialOperationError(
                "Denominator evaluated to zero during interpolation basis calculation".into(),
            )
        })?;
        let divisor = Poly::monomial(x_i);
        let (basis_poly, rem) = a_poly.div_with_remainder(&divisor)?;
        if !rem.is_zero() {
            return Err(Gf2kError::PolynomialOperationError(
                "A(x) not perfectly divisible by (x - x_i)".into(),
            ));
        }
        basis.push(&basis_poly * inv);
    }

    // Points used for verification: the lowest `needed` sender evaluations.
    let verify_xs: Vec<K> = (0..needed).map(|s| domain.element(sorted[s].0)).collect();

    // Flatten the Lagrange basis into pure field arithmetic so the per-chunk apply is a pair of
    // matrix-vector products with zero polynomial allocation.
    let basis_coeffs: Vec<&[K]> = basis.iter().map(|p| p.coeffs.as_slice()).collect();
    let mut verify_matrix = vec![K::zero(); needed * m]; // row-major [needed][m]
    for s in 0..needed {
        let xs = verify_xs[s];
        let row = &mut verify_matrix[s * m..(s + 1) * m];
        for (i, slot) in row.iter_mut().enumerate() {
            *slot = basis[i].evaluate(xs);
        }
    }

    let mut results: Vec<Vec<K>> = Vec::with_capacity(batch_len);
    for c in 0..batch_len {
        let mut ok = true;
        for s in 0..needed {
            let row = &verify_matrix[s * m..(s + 1) * m];
            let mut acc = K::zero();
            for i in 0..m {
                acc = acc + row[i] * sorted[i].1[c];
            }
            if acc != sorted[s].1[c] {
                ok = false;
                break;
            }
        }

        if ok {
            let mut coeffs = vec![K::zero(); degree + 1];
            for (k, coeff) in coeffs.iter_mut().enumerate() {
                let mut acc = K::zero();
                for i in 0..m {
                    let bik = basis_coeffs[i].get(k).copied().unwrap_or(K::zero());
                    acc = acc + bik * sorted[i].1[c];
                }
                *coeff = acc;
            }
            results.push(coeffs);
        } else {
            // Fall back to the full robust path for this chunk alone.
            let shares: Vec<GfShare<K>> = sorted
                .iter()
                .map(|(id, vals)| GfShare::new(vals[c], *id, degree))
                .collect();
            let (coeffs, _) = GfShare::recover_secret(&shares, n, t)?;
            results.push(coeffs);
        }
    }

    Ok(results)
}

/// `g0(x) = ∏_{i<n} (x - domain.element(i))`.
///
/// Unlike the `F`-domain equivalent (`honeybadger::robust_interpolate::compute_g0_from_domain`),
/// this is not memoized — that cache was a measured perf optimization on the hot preprocessing
/// path, not a correctness requirement.
pub fn compute_g0_from_domain<K: BinaryField>(n: usize) -> Result<Poly<K>, Gf2kError> {
    let domain = Gf2kDomain::<K>::new(n)?;
    let mut g0 = Poly::one();
    for i in 0..n {
        g0 = &g0 * &Poly::monomial(domain.element(i));
    }
    Ok(g0)
}

/// Decodes a Reed-Solomon codeword with known erasure positions using Gao's algorithm.
/// https://www.math.clemson.edu/~sgao/papers/RS.pdf
fn gao_rs_decode<K: BinaryField>(
    received: &[K],
    k: usize,
    n: usize,
    erasure_positions: &[usize],
) -> Result<Vec<K>, Gf2kError> {
    if k > n {
        return Err(Gf2kError::InvalidInput(format!(
            "k ({k}) must be less than or equal to n ({n})"
        )));
    }
    let domain = Gf2kDomain::<K>::new(n)?;

    let s_set: HashSet<usize> = erasure_positions.iter().copied().collect();
    let s = s_set.len();

    // Erasure locator polynomial: s(x) = ∏ (x - a_i)
    let s_poly = s_set
        .iter()
        .fold(Poly::one(), |acc, &i| &acc * &Poly::monomial(domain.element(i)));

    // Step 1: Interpolate g1(x) directly from known (x, y) pairs using Lagrange
    let known_points: Vec<(K, K)> = (0..n)
        .filter(|i| !s_set.contains(i))
        .map(|i| (domain.element(i), received[i]))
        .collect();
    let (x_vals, y_vals): (Vec<K>, Vec<K>) = known_points.into_iter().unzip();
    let g1 = lagrange_interpolate(&x_vals, &y_vals)?;

    // Step 2: Define g0(x) = ∏ (x - a_i), then divide out the erasure locator.
    let x_a_prod = compute_g0_from_domain::<K>(n)?;
    let (g0, rem) = x_a_prod.div_with_remainder(&s_poly)?;
    if !rem.is_zero() {
        return Err(Gf2kError::PolynomialOperationError(
            "g0(x) not evenly divisible by the erasure locator polynomial".into(),
        ));
    }

    // Step 3: Extended Euclidean algorithm: find g(x) and v(x) such that g = f * v
    let threshold = (n - s + k) / 2;

    let (mut r0, mut r1) = (g0, g1);
    let (mut s0, mut s1) = (Poly::one(), Poly::zero());
    let (mut t0, mut t1) = (Poly::zero(), Poly::one());

    while r1.degree() >= threshold {
        let (q, _) = r0.div_with_remainder(&r1)?;
        let r = &r0 - &(&q * &r1);
        let s = &s0 - &(&q * &s1);
        let t = &t0 - &(&q * &t1);

        r0 = r1;
        r1 = r;
        s0 = s1;
        s1 = s;
        t0 = t1;
        t1 = t;
    }

    let g = r1;
    let v = t1;

    // Recover message polynomial f(x) = g(x) / v(x)
    let (quotient, remainder) = g.div_with_remainder(&v)?;

    if remainder.is_zero() && quotient.degree() < k {
        Ok(quotient.coeffs.clone())
    } else {
        Err(Gf2kError::DecodingError(
            "Failed to recover message polynomial from g(x)/v(x)".into(),
        ))
    }
}

/// Implements OEC decoding by incrementally increasing the number of shares considered until
/// decoding succeeds. https://eprint.iacr.org/2012/517.pdf
fn oec_decode<K: BinaryField>(
    n: usize,
    t: usize,
    shares: Vec<GfShare<K>>,
) -> Result<(Poly<K>, K), Gf2kError> {
    let domain = Gf2kDomain::<K>::new(n)?;
    let degree = shares[0].degree;

    for r in 1..=t {
        let required = degree + t + 1 + r;
        if shares.len() < required {
            break;
        }

        let subset = &shares[..required];
        let mut received = vec![K::zero(); n];
        let mut erasures = vec![];

        for i in 0..n {
            if let Some(val) = subset.iter().find(|s| s.id == i) {
                received[i] = val.share;
            } else {
                erasures.push(i);
            }
        }

        if let Ok(coeffs) = gao_rs_decode(&received, degree + 1, n, &erasures) {
            let poly = Poly::from_coeffs(coeffs);

            let matched = subset
                .iter()
                .filter(|s| poly.evaluate(domain.element(s.id)) == s.share)
                .count();

            if matched >= degree + t + 1 {
                let value_at_zero = poly.evaluate(K::zero());
                return Ok((poly, value_at_zero));
            }
        }
    }
    Err(Gf2kError::DecodingError(
        "Online Error Correction failed to find a valid polynomial".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::super::field::Gf256;
    use super::*;
    use ark_std::test_rng;
    use itertools::Itertools;

    #[test]
    fn test_robust_interpolate_fnt_optimistic_case() {
        let n = 16;
        let t = 2; // max error and degree tolerated

        let domain = Gf2kDomain::<Gf256>::new(n).unwrap();

        // Polynomial degree <= t (2), e.g. f(x) = 7 + 3x + 5x^2
        let poly = Poly::from_coeffs(vec![Gf256(7), Gf256(3), Gf256(5)]);

        let shares: Vec<GfShare<Gf256>> = (0..n)
            .map(|i| {
                let x = domain.element(i);
                GfShare::new(poly.evaluate(x), i, t)
            })
            .collect();

        // Use 2t + 1 shares for interpolation.
        let used_shares = shares[..(2 * t + 1)].to_vec();

        let result = robust_interpolate_fnt(t, n, &used_shares);
        assert!(result.is_ok(), "Optimistic interpolation failed");

        let recovered = result.unwrap().trimmed();
        assert_eq!(recovered.coeffs, poly.trimmed().coeffs);
    }

    #[test]
    fn test_reed_solomon_erasure() {
        let mut rng = test_rng();
        let t = 2;
        let n = 8;

        let secret = Gf256(42);
        let shares = GfShare::compute_shares(secret, n, t, &mut rng).unwrap();

        let mut erased: Vec<Gf256> = shares.iter().map(|s| s.share).collect();
        let erasures = vec![1, 2];
        for &i in &erasures {
            erased[i] = Gf256::zero();
        }
        let decoded = gao_rs_decode(&erased, t + 1, n, &erasures).unwrap();
        assert_eq!(decoded[0], secret, "Failed to decode with known erasures");
    }

    #[test]
    fn test_reed_solomon_error() {
        let mut rng = test_rng();
        let t = 2;
        let n = 10;
        let secret = Gf256(42);
        let shares = GfShare::compute_shares(secret, n, t, &mut rng).unwrap();

        let mut corrupted: Vec<Gf256> = shares.iter().map(|s| s.share).collect();
        corrupted[2] = corrupted[2] + Gf256(5);
        corrupted[4] = corrupted[4] + Gf256(3);

        let decoded = gao_rs_decode(&corrupted, t + 1, n, &[]).unwrap();
        assert_eq!(decoded[0], secret, "Failed to decode with errors");
    }

    #[test]
    fn test_reed_solomon_error_all_triples() {
        let mut rng = test_rng();
        let t = 3;
        let n = 10;
        let secret = Gf256(42);
        let shares = GfShare::compute_shares(secret, n, t, &mut rng).unwrap();

        for triple in (0..n).combinations(3) {
            let mut corrupted: Vec<Gf256> = shares.iter().map(|s| s.share).collect();
            corrupted[triple[0]] = corrupted[triple[0]] + Gf256(5);
            corrupted[triple[1]] = corrupted[triple[1]] + Gf256(3);
            corrupted[triple[2]] = corrupted[triple[2]] + Gf256(9);

            let decoded = gao_rs_decode(&corrupted, t + 1, n, &[]).unwrap();
            assert_eq!(
                decoded[0], secret,
                "Failed to decode when corrupting indices {triple:?}"
            );
        }
    }

    #[test]
    fn test_oec_protocol() {
        let mut rng = test_rng();
        let t = 2;
        let n = 10;

        let secret = Gf256(42);
        let mut shares = GfShare::compute_shares(secret, n, t, &mut rng).unwrap();

        shares[0].share = shares[0].share + Gf256(99);
        shares[5].share = shares[5].share + Gf256(99);

        let result = oec_decode(n, t, shares.clone());
        assert!(result.is_ok(), "Decoding failed despite sufficient honest shares");

        let (_, recovered) = result.unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_robust_interpolate_full() {
        let mut rng = test_rng();
        let t = 3;
        let n = 10;

        let secret = Gf256(42);
        let mut shares = GfShare::compute_shares(secret, n, t, &mut rng).unwrap();

        let corruption_indices = [1, 4];
        for &i in &corruption_indices {
            shares[i] = (shares[i].clone() + GfShare::new(Gf256(7), i, t)).unwrap();
        }

        let result = GfShare::recover_secret(&shares, n, t);
        assert!(result.is_ok(), "robust_interpolate failed despite valid parameters");

        let (_, val_at_zero) = result.unwrap();
        assert_eq!(val_at_zero, secret);
    }

    #[test]
    fn test_robust_interpolate_all_corruption_combinations() {
        let mut rng = test_rng();
        let t = 2;
        let n = 7;

        let secret = Gf256(42);
        let base_shares = GfShare::compute_shares(secret, n, t, &mut rng).unwrap();

        for k in 1..=t {
            for corruption_indices in (0..n).combinations(k) {
                let mut shares = base_shares.clone();
                for &i in &corruption_indices {
                    shares[i].share = shares[i].share + Gf256(99);
                }

                let result = GfShare::recover_secret(&shares, n, t);
                assert!(
                    result.is_ok(),
                    "Decoding failed for corrupted indices: {corruption_indices:?}"
                );

                let (_, val_at_zero) = result.unwrap();
                assert_eq!(
                    val_at_zero, secret,
                    "Incorrect recovery for {corruption_indices:?}"
                );
            }
        }
    }

    /// `recover_secret` must fail closed when `n < 3t + 1` — the BFT guard is an input-validation
    /// check independent of which/how many shares are actually corrupted, so this is a
    /// deterministic property (unlike "beyond t corruptions", where Reed-Solomon decoding beyond
    /// its unique-decoding radius is merely *unguaranteed* to be correct, not guaranteed to
    /// fail — asserting the latter would be testing behavior the algorithm never promised).
    #[test]
    fn test_robust_interpolate_rejects_n_below_bft_bound() {
        let mut rng = test_rng();
        let t = 2;
        let n = 6; // one short of the required 3t + 1 = 7

        let secret = Gf256(42);
        let shares = GfShare::compute_shares(secret, n, t, &mut rng).unwrap();

        let result = GfShare::recover_secret(&shares, n, t);
        assert!(
            matches!(result, Err(Gf2kError::InvalidInput(_))),
            "recover_secret must reject n < 3t + 1, got {result:?}"
        );
    }

    #[test]
    fn test_recover_secret_naive_roundtrip() {
        let mut rng = test_rng();
        let n = 6;
        let degree = 2;
        let secret = Gf256(77);
        let shares = GfShare::compute_shares(secret, n, degree, &mut rng).unwrap();

        let (_, recovered) = GfShare::recover_secret_naive(&shares, n, 0).unwrap();
        assert_eq!(recovered, secret);
    }

    /// Unlike `recover_secret`, the naive path has no error correction: a single corrupted
    /// share, given no additional redundancy beyond `degree + 1`, silently changes the recovered
    /// value rather than being detected and corrected. This is the property that makes
    /// `recover_secret_naive` unsuitable anywhere `t`-fault tolerance is actually required — it's
    /// only safe to use when the caller establishes trust some other way.
    #[test]
    fn test_recover_secret_naive_does_not_correct_corruption() {
        let mut rng = test_rng();
        let n = 6;
        let degree = 2;
        let secret = Gf256(77);
        let shares = GfShare::compute_shares(secret, n, degree, &mut rng).unwrap();
        // Exactly degree+1 shares, one corrupted — no redundancy to detect this with.
        let mut subset = shares[..=degree].to_vec();
        subset[0].share = subset[0].share + Gf256(1);

        let (_, recovered) = GfShare::recover_secret_naive(&subset, n, 0).unwrap();
        assert_ne!(
            recovered, secret,
            "naive reconstruction should NOT recover the true secret from a corrupted minimal set"
        );
    }

    /// `batch_recover_secret` must reproduce per-chunk `recover_secret` exactly on the honest
    /// path, for any arrival order of the sender evaluations.
    #[test]
    fn test_batch_recover_secret_matches_per_chunk() {
        let mut rng = test_rng();
        let n = 10;
        let t = 3;
        let degree = t;
        let batch_len = 16;

        let polys: Vec<Poly<Gf256>> = (0..batch_len)
            .map(|_| {
                let coeffs: Vec<Gf256> = (0..=degree).map(|_| Gf256::random(&mut rng)).collect();
                Poly::from_coeffs(coeffs)
            })
            .collect();
        let domain = Gf2kDomain::<Gf256>::new(n).unwrap();

        // Build per-sender evaluation vectors (one value per chunk). Reverse the order so the
        // function must sort internally, mirroring real arrival order.
        let mut evals_by_sender: Vec<(usize, Vec<Gf256>)> = (0..n)
            .map(|id| {
                let x = domain.element(id);
                (id, polys.iter().map(|p| p.evaluate(x)).collect())
            })
            .collect();
        evals_by_sender.reverse();

        let batched = batch_recover_secret(&evals_by_sender, n, degree, t).unwrap();
        assert_eq!(batched.len(), batch_len);

        for c in 0..batch_len {
            let shares: Vec<GfShare<Gf256>> = evals_by_sender
                .iter()
                .map(|(id, vals)| GfShare::new(vals[c], *id, degree))
                .collect();
            let (mut per_chunk, _) = GfShare::recover_secret(&shares, n, t).unwrap();
            per_chunk.resize(degree + 1, Gf256::zero());
            assert_eq!(batched[c], per_chunk, "chunk {c} differs from recover_secret");
            assert_eq!(
                batched[c][0], polys[c].coeffs[0],
                "chunk {c} secret mismatch"
            );
        }
    }

    /// With up to `t` corrupted senders (across all chunks), the optimistic verify fails and the
    /// per-chunk OEC fallback must still recover the correct secrets.
    #[test]
    fn test_batch_recover_secret_with_corruption() {
        let mut rng = test_rng();
        let n = 10;
        let t = 3;
        let degree = t;
        let batch_len = 8;

        let polys: Vec<Poly<Gf256>> = (0..batch_len)
            .map(|_| {
                let coeffs: Vec<Gf256> = (0..=degree).map(|_| Gf256::random(&mut rng)).collect();
                Poly::from_coeffs(coeffs)
            })
            .collect();
        let domain = Gf2kDomain::<Gf256>::new(n).unwrap();
        let mut evals_by_sender: Vec<(usize, Vec<Gf256>)> = (0..n)
            .map(|id| {
                let x = domain.element(id);
                (id, polys.iter().map(|p| p.evaluate(x)).collect())
            })
            .collect();

        // Corrupt the first `t` senders, with a distinct error per chunk.
        for bad in 0..t {
            for c in 0..batch_len {
                evals_by_sender[bad].1[c] =
                    evals_by_sender[bad].1[c] + Gf256(((c as u8 + 1) * 7).wrapping_add(bad as u8));
            }
        }

        let batched = batch_recover_secret(&evals_by_sender, n, degree, t).unwrap();
        for c in 0..batch_len {
            assert_eq!(
                batched[c][0], polys[c].coeffs[0],
                "corrupted chunk {c} secret mismatch"
            );
        }
    }
}
