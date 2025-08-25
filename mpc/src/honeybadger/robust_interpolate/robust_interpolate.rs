use crate::common::{
    lagrange_interpolate,
    share::{shamir::NonRobustShare, ShareError},
    SecretSharingScheme, ShamirShare,
};
use ark_ff::{FftField, Zero};
use ark_poly::{
    univariate::{DenseOrSparsePolynomial, DensePolynomial},
    DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain, Polynomial,
};
use ark_std::rand::Rng;
use std::collections::HashSet;
use std::marker::PhantomData;

use super::*;
#[derive(Clone, Debug)]
pub struct Robust;
pub type RobustShare<T> = ShamirShare<T, 1, Robust>;

impl<F: FftField> RobustShare<F> {
    pub fn new(share: F, id: usize, degree: usize) -> Self {
        ShamirShare {
            share: [share],
            id,
            degree,
            _sharetype: PhantomData,
        }
    }
}
impl<F: FftField> From<NonRobustShare<F>> for RobustShare<F> {
    fn from(non_robust: NonRobustShare<F>) -> Self {
        RobustShare {
            share: non_robust.share,
            id: non_robust.id,
            degree: non_robust.degree,
            _sharetype: PhantomData,
        }
    }
}

impl<F: FftField> SecretSharingScheme<F> for RobustShare<F> {
    type SecretType = F;
    type Error = InterpolateError;
    /// Generates `n` secret shares for a `value` using a degree `t` polynomial,
    /// such that `f(0) = value`. Any `t + 1` shares can reconstruct the secret.
    ///
    /// Shares are evaluations of `f(x)` on an FFT domain.
    ///
    /// # Errors
    /// - `InterpolateError::InvalidInput` if `n` is not greater than `t`.
    /// - `InterpolateError::NoSuitableDomain` if a suitable FFT evaluation domain of size `n` isn't found.
    fn compute_shares(
        secret: Self::SecretType,
        n: usize,
        degree: usize,
        _ids: Option<&[usize]>,
        rng: &mut impl Rng,
    ) -> Result<Vec<RobustShare<F>>, InterpolateError> {
        if n <= degree {
            return Err(InterpolateError::InvalidInput(format!(
                "Number of shares ({}) must be greater than threshold ({})",
                n, degree
            )));
        }
        let domain = GeneralEvaluationDomain::<F>::new(n)
            .ok_or_else(|| InterpolateError::NoSuitableDomain(n))?;

        let mut poly = DensePolynomial::<F>::rand(degree, rng);
        poly.coeffs[0] = secret;
        // Evaluate the polynomial over the domain
        let evals = domain.fft(&poly);

        // Create shares from evaluations
        let shares: Vec<RobustShare<F>> = evals
            .iter()
            .take(n)
            .enumerate()
            .map(|(i, &eval)| RobustShare::new(eval, i, degree))
            .collect();

        Ok(shares)
    }

    /// Full robust interpolation combining optimistic decoding and error correction
    ///
    /// # Arguments
    /// * `n` - total number of shares
    /// * `t` - maximum number of errors
    /// * `d` - degree of the original polynomial
    /// * `shares` - (index, value) pairs, unordered
    ///
    /// # Returns
    /// * `Ok((poly, poly(0)))` if decoding succeeds, or `Err(InterpolateError)` otherwise
    fn recover_secret(
        shares: &[Self],
        n: usize,
    ) -> Result<(Vec<Self::SecretType>, Self::SecretType), InterpolateError> {
        let t = shares[0].degree;
        if !shares.iter().all(|share| share.degree == t) {
            return Err(InterpolateError::ShareError(ShareError::DegreeMismatch));
        };

        let share_len = shares.len();
        if share_len < 2 * t + 1 {
            return Err(InterpolateError::InvalidInput(format!(
            "Not enough shares provided ({}) to attempt decoding for t={}. At least {} shares are required.",
            share_len,
            t,
            2 * t + 1
        )));
        }

        let mut sorted_shares = shares.to_vec();
        sorted_shares.sort_by_key(|i| i.id);

        // === Step 1: Optimistic decoding attempt ===
        if let Ok(poly) = robust_interpolate_fnt(t, n, &sorted_shares[..2 * t + 1]) {
            return Ok((poly.coeffs.clone(), poly.evaluate(&F::zero())));
        }
        // === Step 2: Fall back to online error correction ===
        let poly = oec_decode(n, t, sorted_shares.to_vec());
        match poly {
            Ok(p) => Ok((p.0.coeffs.clone(), p.1)),
            Err(e) => Err(e),
        }
    }
}

/// Computes the formal derivative of a polynomial.
///
/// # Returns
/// - an empty polynomial if the input polynomial has degree 0 or is empty.
fn poly_derivative<F: FftField>(poly: &DensePolynomial<F>) -> DensePolynomial<F> {
    if poly.coeffs.len() <= 1 {
        return DensePolynomial::from_coefficients_vec(vec![]);
    }

    let derived_coeffs: Vec<F> = poly
        .coeffs
        .iter()
        .enumerate()
        .skip(1)
        .map(|(i, coeff)| F::from(i as u64) * coeff)
        .collect();

    DensePolynomial::from_coefficients_vec(derived_coeffs)
}

/// Divides a `numerator` polynomial by a `denominator` polynomial, returning the quotient and remainder.
/// # Errors
/// - `InterpolateError::PolynomialOperationError` if the polynomial division fails (e.g., if the denominator is a zero polynomial).
fn div_with_remainder<F: FftField>(
    numerator: &DensePolynomial<F>,
    denominator: &DensePolynomial<F>,
) -> Result<(DensePolynomial<F>, DensePolynomial<F>), InterpolateError> {
    let a = DenseOrSparsePolynomial::from(numerator.clone());
    let b = DenseOrSparsePolynomial::from(denominator.clone());
    let (q, r) = a
        .divide_with_q_and_r(&b)
        .ok_or_else(|| InterpolateError::PolynomialOperationError("Division failed".to_string()))?;
    Ok((DensePolynomial::from(q), DensePolynomial::from(r)))
}

///Optimistically interpolates a polynomial from an arbitrary subset of t + 1 shares and checks on all
/// 2t+1 shares given
/// Based on https://core.ac.uk/download/pdf/12041389.pdf
/// # Arguments
/// * n - total number of shares
/// * t - number of malicious parties
/// * shares - List of (index, value) pairs representing received shares vi = v(αi)
///
/// # Returns
/// * `Ok(polynomial)` if successful
/// * `Err(InterpolateError)` if decoding fails
fn robust_interpolate_fnt<F: FftField>(
    t: usize,
    n: usize,
    shares: &[RobustShare<F>],
) -> Result<DensePolynomial<F>, InterpolateError> {
    let domain =
        GeneralEvaluationDomain::<F>::new(n).ok_or(InterpolateError::NoSuitableDomain(n))?;
    let subset = &shares[..=t];
    let xs: Vec<F> = subset.iter().map(|s| domain.element(s.id)).collect();
    let ys: Vec<F> = subset.iter().map(|s| s.share[0]).collect();

    // Step 1: Compute A(x) = ∏ (x - x_i)
    let mut a_poly = DensePolynomial::from_coefficients_slice(&[F::one()]);
    for &x in &xs {
        let xi_poly = DensePolynomial::from_coefficients_slice(&[-x, F::one()]);
        a_poly = &a_poly * &xi_poly;
    }

    // Step 2: Compute A'(x)
    let a_derivative = poly_derivative(&a_poly);

    // Step 3: Build P(x) = sum_i y_i * A(x) / (A'(x_i) * (x - x_i))
    let mut interpolated = DensePolynomial::from_coefficients_slice(&[F::zero()]);
    for (i, &x_i) in xs.iter().enumerate() {
        let denom = a_derivative.evaluate(&x_i);
        if denom.is_zero() {
            return Err(InterpolateError::PolynomialOperationError(
                "Denominator evaluated to zero during interpolation basis calculation".into(),
            ));
        }

        let scalar = ys[i] / denom;

        // A(x) / (x - x_i)
        let term_divisor = DensePolynomial::from_coefficients_slice(&[-x_i, F::one()]);
        let (basis_poly, rem) = div_with_remainder(&a_poly, &term_divisor)?;
        if !rem.is_zero() {
            return Err(InterpolateError::PolynomialOperationError(
                "A(x) not perfectly divisible by (x - x_i)".into(),
            ));
        }

        interpolated = &interpolated + &(&basis_poly * scalar);
    }

    // Step 4: Verify agreement
    let valid_count = shares
        .iter()
        .map(|s| (domain.element(s.id), s.share))
        .filter(|(x, y)| interpolated.evaluate(x) == y[0])
        .count();

    if valid_count >= 2 * t + 1 {
        Ok(interpolated)
    } else {
        Err(InterpolateError::DecodingError(
            "Not enough shares matched the interpolated polynomial".into(),
        ))
    }
}

/// Decodes a Reed-Solomon codeword with known erasure positions using Gao's algorithm.
///
/// https://www.math.clemson.edu/~sgao/papers/RS.pdf
/// # Arguments
/// * `received` - Shares
/// * `k` - Original message length in paper but for our usecase (t+1) i.e number of coefficients
/// * `n` - Codeword length or number of parties
/// * `erasure_positions` - Indices of erasures in the received vector
///
/// # Returns
/// * `Ok(Vec<F>)` if decoding succeeds, or `Err(InterpolateError)` if it fails
fn gao_rs_decode<F: FftField>(
    received: &[F],
    k: usize,
    n: usize,
    erasure_positions: &[usize],
) -> Result<Vec<F>, InterpolateError> {
    if k > n {
        return Err(InterpolateError::InvalidInput(format!(
            "k ({}) must be less than or equal to n ({})",
            k, n
        )));
    }
    let domain =
        GeneralEvaluationDomain::<F>::new(n).ok_or(InterpolateError::NoSuitableDomain(n))?;

    let s_set: HashSet<usize> = erasure_positions.iter().copied().collect();
    let s = s_set.len();

    // Construct the erasure locator polynomial: s(x) = ∏ (x - a_i)
    let s_poly = s_set.iter().fold(
        DensePolynomial::from_coefficients_slice(&[F::one()]),
        |acc, &i| {
            let xi = domain.element(i);
            &acc * &DensePolynomial::from_coefficients_slice(&[-xi, F::one()])
        },
    );

    // Step 1: Interpolate g₁(x) directly from known (x, y) pairs using Lagrange
    let known_points: Vec<_> = (0..n)
        .filter(|i| !s_set.contains(i))
        .map(|i| (domain.element(i), received[i]))
        .collect();

    let (x_vals, y_vals): (Vec<F>, Vec<F>) = known_points.iter().cloned().unzip();
    //To do: need to make this efficient
    let g1 = lagrange_interpolate(&x_vals, &y_vals)?;

    // Step 2 : Define g₀(x) = ∏ (x - aᵢ)
    let x_a_prod = compute_g0_from_domain(n);
    let g0 = &x_a_prod / &s_poly;

    // Step 3: Extended Euclidean algorithm: find g(x) and v(x) such that g = f * v
    let threshold = (n - s + k) / 2;

    let (mut r0, mut r1) = (g0.clone(), g1.clone());
    let (mut s0, mut s1) = (
        DensePolynomial::from_coefficients_slice(&[F::one()]),
        DensePolynomial::zero(),
    );
    let (mut t0, mut t1) = (
        DensePolynomial::zero(),
        DensePolynomial::from_coefficients_slice(&[F::one()]),
    );

    while r1.degree() >= threshold {
        let q = &r0 / &r1;
        let r = &r0 - &q * &r1;
        let s = &s0 - &q * &s1;
        let t = &t0 - &q * &t1;

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
    let quotient = &g / &v;
    let remainder = &g - &quotient * &v;

    if remainder.is_zero() && quotient.degree() < k {
        Ok(quotient.coeffs.clone())
    } else {
        Err(InterpolateError::DecodingError(
            "Failed to recover message polynomial from g(x)/v(x)".into(),
        ))
    }
}

pub fn compute_g0_from_domain<F: FftField>(n: usize) -> DensePolynomial<F> {
    // Create an FFT-compatible evaluation domain of size n
    let domain =
        GeneralEvaluationDomain::<F>::new(n).expect("Domain of size n must exist over the field");

    // Extract evaluation points: ω^0, ω^1, ..., ω^{n-1}
    let evaluation_points: Vec<F> = domain.elements().collect();

    // Compute g₀(x) = ∏ (x - aᵢ) for aᵢ in evaluation_points
    let mut g0 = DensePolynomial::from_coefficients_slice(&[F::one()]); // g0 = 1

    for ai in evaluation_points.iter().take(n) {
        let factor = DensePolynomial::from_coefficients_slice(&[-*ai, F::one()]); // (x - ai)
        g0 = &g0 * &factor;
    }

    g0
}
/// Implements OEC decoding by incrementally increasing the number of shares until decoding succeeds.
/// https://eprint.iacr.org/2012/517.pdf
///
/// To do : Replace this with a store that is constantly updating or else make sure to call the func again
/// with an updated list
/// # Arguments
/// * n - total number of shares
/// * t - Maximum number of corrupted shares
/// * mut shares - List of (index, value) pairs representing received shares vi = v(αi)
///
/// # Returns
/// * `Ok((polynomial, value_at_0))` if successful
/// * `Err(InterpolateError)` if decoding fails
fn oec_decode<F: FftField>(
    n: usize,
    t: usize,
    shares: Vec<RobustShare<F>>,
) -> Result<(DensePolynomial<F>, F), InterpolateError> {
    let domain =
        GeneralEvaluationDomain::<F>::new(n).ok_or(InterpolateError::NoSuitableDomain(n))?;

    // Iterate, increasing the number of shares considered (r) to handle more erasures/errors
    for r in 1..=t {
        let required = 2 * t + 1 + r;
        if shares.len() < required {
            break;
        }

        let subset = &shares[..required];
        let mut received = vec![F::zero(); n];
        let mut erasures = vec![];

        // Populate `received` and `erasures` based on the current subset of shares
        for i in 0..n {
            if let Some(val) = subset.iter().find(|s| s.id == i) {
                received[i] = val.share[0];
            } else {
                erasures.push(i);
            }
        }

        // Attempt Reed-Solomon decoding (Gao's algorithm is used for this)
        // t+1 is the expected number of coefficients (degree t polynomial)
        if let Ok(coeffs) = gao_rs_decode(&received, t + 1, n, &erasures) {
            let poly = DensePolynomial::from_coefficients_vec(coeffs);

            // Verify if the interpolated polynomial matches a sufficient number of original shares
            let matched = subset
                .iter()
                .filter(|s| poly.evaluate(&domain.element(s.id)) == s.share[0])
                .count();

            // If enough shares match, the decoding is considered successful
            if matched >= 2 * t + 1 {
                return Ok((poly.clone(), poly.evaluate(&F::zero())));
            }
        }
    }
    Err(InterpolateError::DecodingError(
        "Online Error Correction failed to find a valid polynomial".into(),
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_std::test_rng;

    #[test]
    fn test_poly_derivative() {
        let coeffs = vec![Fr::from(3), Fr::from(2), Fr::from(1)]; // 3 + 2x + x^2
        let poly = DensePolynomial::from_coefficients_vec(coeffs);
        let deriv = poly_derivative(&poly);

        let expected = DensePolynomial::from_coefficients_vec(vec![Fr::from(2), Fr::from(2)]); // 2 + 2x
        assert_eq!(deriv, expected);
    }
    #[test]
    fn test_robust_interpolate_fnt_optimistic_case() {
        use ark_bls12_381::Fr;
        use ark_poly::univariate::DensePolynomial;

        let n = 16;
        let t = 2; // max error and degree tolerated

        let domain = GeneralEvaluationDomain::<Fr>::new(n).unwrap();

        // Polynomial degree ≤ t (2), e.g., f(x) = 7 + 3x + 5x^2
        let coeffs = vec![Fr::from(7u32), Fr::from(3u32), Fr::from(5u32)];
        let poly = DensePolynomial::from_coefficients_vec(coeffs);

        // Evaluate over domain
        let shares: Vec<RobustShare<Fr>> = (0..n)
            .map(|i| {
                let x = domain.element(i);
                let y = poly.evaluate(&x);
                RobustShare::new(y, i, t)
            })
            .collect();

        // Use 2t + 1 shares for interpolation, here 5 shares
        let used_shares = shares[..(2 * t + 1)].to_vec();

        let result = robust_interpolate_fnt(t, n, &used_shares);
        assert!(result.is_ok(), "Optimistic interpolation failed");

        let recovered = result.unwrap();

        assert_eq!(recovered.coeffs.len(), poly.coeffs.len());
        for (a, b) in recovered.coeffs.iter().zip(poly.coeffs.iter()) {
            assert_eq!(a, b, "Mismatch in optimistic recovery");
        }
    }

    #[test]
    fn test_reed_solomon_erasure() {
        let mut rng = test_rng();
        let t = 2;
        let n = 8;

        let secret = Fr::from(42u32);
        let ids: Vec<usize> = (0..n).collect();
        let shares = RobustShare::compute_shares(secret, n, t, Some(&ids), &mut rng).unwrap();

        // === Case 1: Erasure-only decoding ===
        let mut erased: Vec<Fr> = shares.iter().map(|a| a.share[0]).collect();
        let erasures = vec![1, 2];
        for &i in &erasures {
            erased[i] = Fr::zero();
        }
        let decoded_erasure = gao_rs_decode(&erased, t + 1, n, &erasures);
        let recovered_secret = decoded_erasure.unwrap()[0];
        assert_eq!(
            recovered_secret, secret,
            "Failed to decode with known erasures"
        );
    }
    #[test]
    fn test_reed_solomon_error() {
        let mut rng = test_rng();
        let t = 2;
        let n = 10;
        let secret = Fr::from(42u32);
        let shares = RobustShare::compute_shares(secret, n, t, None, &mut rng).unwrap();

        // === Case 2: Error-only decoding ===
        let mut corrupted: Vec<Fr> = shares.iter().map(|a| a.share[0]).collect();
        corrupted[2] += Fr::from(5u64);
        corrupted[4] += Fr::from(3u64);

        // No erasure information provided
        let decoded = gao_rs_decode(&corrupted, t + 1, n, &[]);

        let recovered_secret = decoded.unwrap()[0];
        assert_eq!(
            recovered_secret, secret,
            "Failed to decode with known erasures"
        );
    }
    #[test]
    fn test_reed_solomon_error_all_triples() {
        use itertools::Itertools;

        let mut rng = test_rng();
        let t = 3;
        let n = 10;
        let secret = Fr::from(42u32);
        let shares = RobustShare::compute_shares(secret, n, t, None, &mut rng).unwrap();

        // Go through all possible combinations of 2 distinct indices
        for triple in (0..n).combinations(3) {
            let mut corrupted: Vec<Fr> = shares.iter().map(|a| a.share[0]).collect();

            // Apply different corruptions to the two indices
            corrupted[triple[0]] += Fr::from(5u64);
            corrupted[triple[1]] += Fr::from(3u64);
            corrupted[triple[2]] += Fr::from(3u64);

            // No erasure information provided
            let decoded = gao_rs_decode(&corrupted, t + 1, n, &[]).unwrap();

            let recovered_secret = decoded[0];
            assert_eq!(
                recovered_secret, secret,
                "Failed to decode when corrupting indices {:?}",
                triple
            );
        }
    }
    #[test]
    fn test_oec_protocol() {
        use ark_bls12_381::Fr;
        use ark_std::test_rng;

        let mut rng = test_rng();
        let t = 2;
        let n = 10;

        // Step 1: Create random message and encode it
        let secret = Fr::from(42u32);
        let ids: Vec<usize> = (0..n).collect();
        let mut shares = RobustShare::compute_shares(secret, n, t, Some(&ids), &mut rng).unwrap();

        // Step 3: Corrupt up to t shares
        shares[0].share[0] += Fr::from(999u64);
        shares[5].share[0] += Fr::from(999u64);

        // Step 4: Attempt OEC decode
        let result = oec_decode(n, t, shares.clone());

        assert!(
            result.is_ok(),
            "Decoding failed despite sufficient honest shares"
        );

        let (_, recovered_zero) = result.unwrap();

        assert_eq!(
            recovered_zero, secret,
            "Recovered polynomial does not match the original"
        );
    }
    #[test]
    fn test_robust_interpolate_full() {
        use ark_bls12_381::Fr;
        use ark_std::test_rng;

        let mut rng = test_rng();
        let t = 3;
        let n = 10;

        // Generate random message and encode it
        let secret = Fr::from(42u32);
        let ids: Vec<usize> = (0..n).collect();
        let mut shares = RobustShare::compute_shares(secret, n, t, Some(&ids), &mut rng).unwrap();

        // Corrupt up to t shares
        let corruption_indices = [1, 4];
        for &i in &corruption_indices {
            shares[i] = (shares[i].clone()
                + RobustShare {
                    share: [Fr::from(7u64)],
                    id: i,
                    degree: t,
                    _sharetype: PhantomData,
                })
            .unwrap();
        }
        // Attempt robust interpolation
        let result = RobustShare::recover_secret(&shares, n);
        assert!(
            result.is_ok(),
            "robust_interpolate failed despite valid parameters"
        );

        let (_, val_at_zero) = result.unwrap();

        assert_eq!(val_at_zero, secret, "Evaluation at zero incorrect");
    }
    #[test]
    fn test_robust_interpolate_all_corruption_combinations() {
        use ark_bls12_381::Fr;
        use ark_std::test_rng;
        use itertools::Itertools;

        let mut rng = test_rng();
        let t = 2;
        let n = 7;

        let secret = Fr::from(42u32);

        let base_shares = RobustShare::compute_shares(secret, n, t, None, &mut rng).unwrap();

        // Generate all corruption combinations of size 1..=t
        for k in 1..=t {
            for corruption_indices in (0..n).combinations(k) {
                // Clone base shares to avoid compounding corruption
                let mut shares = base_shares.clone();

                // Apply corruption
                for &i in &corruption_indices {
                    shares[i].share[0] += Fr::from(999u64); // Ensure significant corruption
                }

                // Run recovery
                let result = RobustShare::recover_secret(&shares, n);

                // Debug: show the corrupted indices
                if result.is_err() {
                    eprintln!("Failed for corrupted indices: {:?}", corruption_indices);
                }

                // Assert: should always succeed up to t corruptions
                assert!(
                    result.is_ok(),
                    "Decoding failed for corrupted indices: {:?}",
                    corruption_indices
                );

                // Check recovered secret
                let (_, val_at_zero) = result.unwrap();
                assert_eq!(
                    val_at_zero, secret,
                    "Incorrect recovery at zero for {:?}",
                    corruption_indices
                );
            }
        }
    }
}
