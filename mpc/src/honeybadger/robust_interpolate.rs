use ark_ff::{FftField, Zero};
use ark_poly::{
    univariate::{DenseOrSparsePolynomial, DensePolynomial},
    DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain, Polynomial,
};
use ark_std::rand::Rng;
use std::collections::HashSet;
use stoffelmpc_common::share::shamir::{lagrange_interpolate, ShamirSecretSharing};
use thiserror::Error;

/// Custom Error type for polynomial operations.
#[derive(Error, Debug)]
pub enum InterpolateError {
    /// Errors related to polynomial operations, potentially with an underlying cause.
    #[error("Polynomial operation failed: {0}")]
    PolynomialOperationError(String),

    /// Errors specific to invalid input parameters or conditions.
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Errors that occur during the decoding process.
    #[error("Decoding failed: {0}")]
    DecodingError(String),

    /// No suitable FFT evaluation domain could be found.
    #[error("No suitable FFT evaluation domain found for n={0}")]
    NoSuitableDomain(usize),
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
    shares: &[(usize, ShamirSecretSharing<F>)],
) -> Result<DensePolynomial<F>, InterpolateError> {
    let domain =
        GeneralEvaluationDomain::<F>::new(n).ok_or(InterpolateError::NoSuitableDomain(n))?;
    let subset = &shares[..=t];
    let xs: Vec<F> = subset.iter().map(|(i, _)| domain.element(*i)).collect();
    let ys: Vec<F> = subset.iter().map(|(_, y)| y.share).collect();

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
        .map(|(i, y)| (domain.element(*i), *y))
        .filter(|(x, y)| interpolated.evaluate(x) == y.share)
        .count();

    if valid_count >= 2 * t + 1 {
        Ok(interpolated)
    } else {
        Err(InterpolateError::DecodingError(
            "Not enough shares matched the interpolated polynomial".into(),
        ))
    }
}

/// Generates `n` secret shares for a `value` using a degree `t` polynomial,
/// such that `f(0) = value`. Any `t + 1` shares can reconstruct the secret.
///
/// Shares are evaluations of `f(x)` on an FFT domain.
///
/// # Errors
/// - `InterpolateError::InvalidInput` if `n` is not greater than `t`.
/// - `InterpolateError::NoSuitableDomain` if a suitable FFT evaluation domain of size `n` isn't found.
pub fn gen_shares<F: FftField, R: Rng>(
    value: F,
    n: usize,
    t: usize,
    rng: &mut R,
) -> Result<Vec<ShamirSecretSharing<F>>, InterpolateError> {
    if n <= t {
        return Err(InterpolateError::InvalidInput(format!(
            "Number of shares ({}) must be greater than threshold ({})",
            n, t
        )));
    }
    let domain = GeneralEvaluationDomain::<F>::new(n).ok_or_else(|| {
        InterpolateError::InvalidInput("No suitable evaluation domain found".to_string())
    })?;

    let mut poly = DensePolynomial::<F>::rand(t, rng);
    poly[0] = value;
    // Evaluate the polynomial over the domain
    let evals = domain.fft(&poly);

    // Create shares from evaluations
    let shares = evals
        .iter()
        .enumerate()
        .map(|(i, eval)| ShamirSecretSharing::new(*eval, i, t))
        .collect();

    Ok(shares)
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
    let g1 = lagrange_interpolate(&x_vals, &y_vals)
        .map_err(|_| InterpolateError::InvalidInput("No. of x and y values don't match".to_string()))?;

    // Step 2 : Define g0(x) = (x^n - 1) / s(x)
    let mut xn_minus_1_coeffs = vec![F::zero(); n + 1];
    xn_minus_1_coeffs[0] = -F::one();
    xn_minus_1_coeffs[n] = F::one();
    let xn_minus_1 = DensePolynomial::from_coefficients_vec(xn_minus_1_coeffs);
    let g0 = &xn_minus_1 / &s_poly;

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
    shares: Vec<(usize, ShamirSecretSharing<F>)>,
) -> Result<(DensePolynomial<F>, F), InterpolateError> {
    let domain =
        GeneralEvaluationDomain::<F>::new(n).ok_or(InterpolateError::NoSuitableDomain(n))?;

    // Iterate, increasing the number of shares considered (r) to handle more erasures/errors
    for r in 0..=t {
        let required = 2 * t + 1 + r;
        if shares.len() < required {
            continue;
        }

        let subset = &shares[..required];
        let mut received = vec![F::zero(); n];
        let mut erasures = vec![];

        // Populate `received` and `erasures` based on the current subset of shares
        for i in 0..n {
            if let Some((_, val)) = subset.iter().find(|(j, _)| *j == i) {
                received[i] = val.share;
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
                .filter(|(i, v)| poly.evaluate(&domain.element(*i)) == v.share)
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
pub fn robust_interpolate<F: FftField>(
    n: usize,
    t: usize,
    mut shares: Vec<(usize, ShamirSecretSharing<F>)>,
) -> Result<(DensePolynomial<F>, F), InterpolateError> {
    shares.sort_by_key(|(i, _)| *i); // ensure deterministic ordering

    if shares.len() < 2 * t + 1 {
        return Err(InterpolateError::InvalidInput(format!(
            "Not enough shares provided ({}) to attempt decoding for t={}. At least {} shares are required.",
            shares.len(),
            t,
            2 * t + 1
        )));
    }
    // === Step 1: Optimistic decoding attempt ===
    if let Ok(poly) = robust_interpolate_fnt(t, n, &shares[..2 * t + 1]) {
        return Ok((poly.clone(), poly.evaluate(&F::zero())));
    }
    // === Step 2: Fall back to online error correction ===
    oec_decode(n, t, shares)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_std::test_rng;
    use stoffelmpc_common::share::Share;

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
        let shares: Vec<(usize, ShamirSecretSharing<Fr>)> = (0..n)
            .map(|i| {
                let x = domain.element(i);
                let y = poly.evaluate(&x);
                (i, ShamirSecretSharing::new(y, i, t))
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
        let shares = gen_shares(secret, n, t, &mut rng).unwrap();

        // === Case 1: Erasure-only decoding ===
        let mut erased: Vec<Fr> = shares.iter().map(|a| a.share).collect();
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
        let n = 8;
        let secret = Fr::from(42u32);
        let shares = gen_shares(secret, n, t, &mut rng).unwrap();

        // === Case 2: Error-only decoding ===
        let mut corrupted: Vec<Fr> = shares.iter().map(|a| a.share).collect();
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
    fn test_oec_protocol() {
        use ark_bls12_381::Fr;
        use ark_std::test_rng;

        let mut rng = test_rng();
        let t = 2;
        let n = 8;

        // Step 1: Create random message and encode it
        let secret = Fr::from(42u32);
        let shares = gen_shares(secret, n, t, &mut rng).unwrap();

        // Step 2: Create shares as (index, value)
        let shares_list: Vec<(usize, ShamirSecretSharing<Fr>)> =
            shares.iter().enumerate().map(|(i, &v)| (i, v)).collect();

        // Step 3: Corrupt up to t shares
        let _ = shares_list[2].1.add(&ShamirSecretSharing {
            share: Fr::from(3u64),
            id: 2,
            degree: t,
        });
        let _ = shares_list[5].1.add(&ShamirSecretSharing {
            share: Fr::from(1u64),
            id: 5,
            degree: t,
        });

        // Step 4: Attempt OEC decode
        let result = oec_decode(n, t, shares_list.clone());

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
        let t = 2;
        let n = 8;

        // Generate random message and encode it
        let secret = Fr::from(42u32);
        let shares = gen_shares(secret, n, t, &mut rng).unwrap();

        // Create shares as (index, value)
        let shares_list: Vec<(usize, ShamirSecretSharing<Fr>)> =
            shares.iter().enumerate().map(|(i, &v)| (i, v)).collect();

        // Corrupt up to t shares
        let corruption_indices = [1, 4];
        for &i in &corruption_indices {
            let _ = shares_list[i].1.add(&ShamirSecretSharing {
                share: Fr::from(7u64),
                id: i,
                degree: t,
            });
        }
        // Attempt robust interpolation
        let result = robust_interpolate(n, t, shares_list.clone());
        assert!(
            result.is_ok(),
            "robust_interpolate failed despite valid parameters"
        );

        let (_, val_at_zero) = result.unwrap();

        assert_eq!(val_at_zero, secret, "Evaluation at zero incorrect");
    }
}
