use ark_ff::{FftField, Zero};
use ark_poly::{
    univariate::{DenseOrSparsePolynomial, DensePolynomial},
    DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain, Polynomial,
};
use std::collections::HashSet;

/// Computes the formal derivative of a polynomial.
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
pub fn robust_interpolate_fnt<F: FftField>(
    t: usize,
    n: usize,
    shares: &[(usize, F)],
) -> Option<DensePolynomial<F>> {
    if shares.len() < 2 * t + 1 {
        return None;
    }

    let domain = GeneralEvaluationDomain::<F>::new(n)?;
    let subset = &shares[..=t];
    let xs: Vec<F> = subset.iter().map(|(i, _)| domain.element(*i)).collect();
    let ys: Vec<F> = subset.iter().map(|(_, y)| *y).collect();

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
            return None;
        }

        let scalar = ys[i] / denom;

        // A(x) / (x - x_i)
        let term_divisor = DensePolynomial::from_coefficients_slice(&[-x_i, F::one()]);
        let (basis_poly, rem) = div_with_remainder(&a_poly, &term_divisor);
        assert!(rem.is_zero(), "A(x) not divisible by (x - x_i)");

        interpolated = &interpolated + &(&basis_poly * scalar);
    }

    // Step 4: Verify agreement
    let valid_count = shares
        .iter()
        .map(|(i, y)| (domain.element(*i), *y))
        .filter(|(x, y)| interpolated.evaluate(x) == *y)
        .count();

    if valid_count >= 2 * t + 1 {
        Some(interpolated)
    } else {
        None
    }
}
fn div_with_remainder<F: FftField>(
    numerator: &DensePolynomial<F>,
    denominator: &DensePolynomial<F>,
) -> (DensePolynomial<F>, DensePolynomial<F>) {
    let a = DenseOrSparsePolynomial::from(numerator.clone());
    let b = DenseOrSparsePolynomial::from(denominator.clone());
    let (q, r) = a
        .divide_with_q_and_r(&b)
        .expect("Polynomial division failed");
    (DensePolynomial::from(q), DensePolynomial::from(r))
}

/// Encodes a message into a Reed-Solomon codeword.
///
/// https://www.math.clemson.edu/~sgao/papers/RS.pdf
/// # Arguments
/// * message - Slice of message field elements (length k)
/// * n - Codeword length (must satisfy n ≥ k and n is power of 2 for FFT)
pub fn gao_rs_encode<F: FftField>(message: &[F], n: usize) -> Vec<F> {
    assert!(n >= message.len(), "n must be ≥ message length");
    let domain = GeneralEvaluationDomain::<F>::new(n).expect("No suitable evaluation domain found");

    let f = DensePolynomial::from_coefficients_slice(message);
    domain.fft(&f)
}

/// Decodes a Reed-Solomon codeword with known erasure positions using Gao's algorithm.
///
/// # Arguments
/// * `received` - Slice of received field elements (length n)
/// * `k` - Original message length
/// * `n` - Codeword length
/// * `erasure_positions` - Indices of erasures in the received vector
///
/// # Returns
/// * Some(Vec<F>) if decoding succeeds, or None if it fails
pub fn gao_rs_decode<F: FftField>(
    received: &[F],
    k: usize,
    n: usize,
    t: usize,
    erasure_positions: &[usize],
) -> Option<Vec<F>> {
    assert!(k <= n, "k must be <= n");
    let domain = GeneralEvaluationDomain::<F>::new(n).expect("No suitable evaluation domain found");

    let s_set: HashSet<usize> = erasure_positions.iter().copied().collect();
    let s = s_set.len();
    let d = n - k + 1;

    if 2 * t + s >= d {
        // Error-erasure decoding bound violated
        return None;
    }
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
    let g1 = lagrange_interpolate(&x_vals, &y_vals);

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
        Some(quotient.coeffs.clone())
    } else {
        None
    }
}

/// Interpolates a polynomial from (x, y) pairs using Lagrange interpolation.
fn lagrange_interpolate<F: FftField>(x_vals: &[F], y_vals: &[F]) -> DensePolynomial<F> {
    assert_eq!(x_vals.len(), y_vals.len(), "Mismatched input lengths");

    let n = x_vals.len();
    let mut result = DensePolynomial::zero();

    for j in 0..n {
        let mut numerator = DensePolynomial::from_coefficients_slice(&[F::one()]);
        let mut denominator = F::one();

        for m in 0..n {
            if m != j {
                numerator =
                    &numerator * &DensePolynomial::from_coefficients_slice(&[-x_vals[m], F::one()]);
                denominator *= x_vals[j] - x_vals[m];
            }
        }

        let term = numerator * DensePolynomial::from_coefficients_slice(&[y_vals[j] / denominator]);
        result = &result + &term;
    }

    result
}

/// Implements OEC decoding by incrementally increasing the number of shares until decoding succeeds.
/// https://eprint.iacr.org/2012/517.pdf
/// # Arguments
/// * n - total number of shares
/// * d - Degree of the original polynomial
/// * t - Maximum number of corrupted shares
/// * mut shares - List of (index, value) pairs representing received shares vi = v(αi)
///
/// # Returns
/// * Some((polynomial, value_at_0)) if successful
/// * None if decoding fails
pub fn oec_decode<F: FftField>(
    n: usize,
    d: usize,
    t: usize,
    mut shares: Vec<(usize, F)>, //to do : Replace this with a store that is constantly updating
) -> Option<(DensePolynomial<F>, F)> {
    shares.sort_by_key(|(i, _)| *i);
    let domain = GeneralEvaluationDomain::<F>::new(n).expect("invalid domain");

    for r in 0..=t {
        let required = d + t + 1 + r;
        if shares.len() < required {
            continue;
        }

        let subset = &shares[..required];
        let mut received = vec![F::zero(); n];
        let mut erasures = vec![];

        for i in 0..n {
            if let Some((_, val)) = subset.iter().find(|(j, _)| *j == i) {
                received[i] = *val;
            } else {
                erasures.push(i);
            }
        }

        if let Some(coeffs) = gao_rs_decode(&received, d + 1, n, t, &erasures) {
            let poly = DensePolynomial::from_coefficients_vec(coeffs);

            let matched = subset
                .iter()
                .filter(|(i, v)| poly.evaluate(&domain.element(*i)) == *v)
                .count();

            if matched >= d + t + 1 {
                return Some((poly.clone(), poly.evaluate(&F::zero())));
            }
        }
    }

    None
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
/// * Some((poly, poly(0))) if decoding succeeds, or None otherwise
pub fn robust_interpolate<F: FftField>(
    n: usize,
    t: usize,
    d: usize,
    mut shares: Vec<(usize, F)>,
) -> Option<(DensePolynomial<F>, F)> {
    shares.sort_by_key(|(i, _)| *i); // ensure deterministic ordering

    // === Step 1: Optimistic decoding attempt ===
    if let Some(poly) = robust_interpolate_fnt(t, n, &shares[..2 * t + 1]) {
        return Some((poly.clone(), poly.evaluate(&F::zero())));
    }

    // === Step 2: Fall back to online error correction ===
    oec_decode(n, d, t, shares)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::UniformRand;
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
        let shares: Vec<(usize, Fr)> = (0..n)
            .map(|i| {
                let x = domain.element(i);
                let y = poly.evaluate(&x);
                (i, y)
            })
            .collect();

        // Use 2t + 1 shares for interpolation, here 5 shares
        let used_shares = shares[..(2 * t + 1)].to_vec();

        let result = robust_interpolate_fnt(t, n, &used_shares);
        assert!(result.is_some(), "Optimistic interpolation failed");

        let recovered = result.unwrap();

        assert_eq!(recovered.coeffs.len(), poly.coeffs.len());
        for (a, b) in recovered.coeffs.iter().zip(poly.coeffs.iter()) {
            assert_eq!(a, b, "Mismatch in optimistic recovery");
        }
    }

    #[test]
    fn test_reed_solomon_erasure() {
        let mut rng = test_rng();
        let k = 4;
        let n = 8;

        let message: Vec<Fr> = (0..k).map(|_| Fr::rand(&mut rng)).collect();
        let codeword = gao_rs_encode(&message, n);

        // === Case 1: Erasure-only decoding ===
        let mut erased = codeword.clone();
        let erasures = vec![1, 2];
        for &i in &erasures {
            erased[i] = Fr::zero();
        }
        let decoded_erasure = gao_rs_decode(&erased, k, n, 0, &erasures);
        assert_eq!(
            decoded_erasure,
            Some(message.clone()),
            "Failed to decode with known erasures"
        );
    }
    #[test]
    fn test_reed_solomon_error() {
        let mut rng = test_rng();
        let k = 4;
        let n = 8;

        let message: Vec<Fr> = (0..k).map(|_| Fr::rand(&mut rng)).collect();
        let codeword = gao_rs_encode(&message, n);

        // === Case 2: Error-only decoding ===
        let mut corrupted = codeword.clone();
        corrupted[2] += Fr::from(5u64);
        corrupted[4] += Fr::from(3u64);

        // No erasure information provided
        let decoded = gao_rs_decode(&corrupted, k, n, 2, &[]);
        assert_eq!(decoded, Some(message.clone()));
    }
    #[test]
    fn test_oec_protocol() {
        use ark_bls12_381::Fr;
        use ark_ff::UniformRand;
        use ark_std::test_rng;

        let mut rng = test_rng();
        let k = 4;
        let d = k - 1;
        let t = 2;
        let n = 8;

        assert!(n >= k + 2 * t, "n must be ≥ k + 2t for OEC to succeed");

        // Step 1: Create random message and encode it
        let message: Vec<Fr> = (0..k).map(|_| Fr::rand(&mut rng)).collect();
        let codeword = gao_rs_encode(&message, n);

        // Step 2: Create shares as (index, value)
        let mut shares: Vec<(usize, Fr)> =
            codeword.iter().enumerate().map(|(i, &v)| (i, v)).collect();

        // Step 3: Corrupt up to t shares
        shares[2].1 += Fr::from(3u64);
        shares[5].1 += Fr::from(1u64);

        // Step 4: Attempt OEC decode
        let result = oec_decode(n, d, t, shares.clone());

        assert!(
            result.is_some(),
            "Decoding failed despite sufficient honest shares"
        );

        let (recovered_poly, recovered_zero) = result.unwrap();
        let expected_poly = DensePolynomial::from_coefficients_vec(message.clone());

        assert_eq!(
            recovered_poly, expected_poly,
            "Recovered polynomial does not match the original"
        );
        assert_eq!(
            recovered_zero, message[0],
            "Recovered polynomial does not evaluate to the original message at 0"
        );
    }
    #[test]
    fn test_robust_interpolate_full() {
        use ark_bls12_381::Fr;
        use ark_ff::UniformRand;
        use ark_std::test_rng;

        let mut rng = test_rng();
        let k = 4;
        let d = k - 1;
        let t = 2;
        let n = 8;

        // Generate random message and encode it
        let message: Vec<Fr> = (0..k).map(|_| Fr::rand(&mut rng)).collect();
        let codeword = gao_rs_encode(&message, n);

        // Create shares as (index, value)
        let mut shares: Vec<(usize, Fr)> =
            codeword.iter().enumerate().map(|(i, &v)| (i, v)).collect();

        // Corrupt up to t shares
        let corruption_indices = [1, 4];
        for &i in &corruption_indices {
            shares[i].1 += Fr::from(7u64);
        }

        // Attempt robust interpolation
        let result = robust_interpolate(n, t, d, shares.clone());
        assert!(
            result.is_some(),
            "robust_interpolate failed despite valid parameters"
        );

        let (recovered_poly, val_at_zero) = result.unwrap();
        let expected_poly = DensePolynomial::from_coefficients_slice(&message.clone());
        assert_eq!(
            recovered_poly, expected_poly,
            "Recovered polynomial does not match original"
        );
        assert_eq!(val_at_zero, message[0], "Evaluation at zero incorrect");
    }
}
