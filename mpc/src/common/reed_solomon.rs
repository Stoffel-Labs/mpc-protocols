use std::collections::HashSet;

use ark_ff::{FftField, Zero};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, Evaluations,
    GeneralEvaluationDomain, Polynomial,
};

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

/// Decodes a possibly corrupted Reed-Solomon codeword and recovers the original message.
///
/// # Arguments
/// * received - Slice of received values (length n)
/// * k - Original message length
///
/// # Returns
/// * Some(Vec<F>) if decoding succeeds, or None if it fails
pub fn gao_rs_decode<F: FftField>(received: &[F], k: usize, n: usize) -> Option<Vec<F>> {
    assert!(k <= n, "Message length must be ≤ codeword length");

    let domain = GeneralEvaluationDomain::<F>::new(n).expect("No suitable evaluation domain found");

    // Step 1: Interpolate g1(x) from received values
    let g1_evals = Evaluations::from_vec_and_domain(received.to_vec(), domain);
    let g1 = g1_evals.interpolate();

    //Step 2: define x^n - 1
    let mut coeffs = vec![F::zero(); n + 1];
    coeffs[0] = -F::one();
    coeffs[n] = F::one();
    let g0 = DensePolynomial::from_coefficients_vec(coeffs);

    // Step 3: Extended Euclidean Algorithm
    let threshold = (n + k) / 2;
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

    // Step 4: g(x) = f(x) * v(x)
    let quotient = &g / &v;
    let remainder = &g - &quotient * &v;

    if remainder.is_zero() && quotient.degree() < k {
        Some(quotient.coeffs.clone())
    } else {
        None
    }
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
pub fn gao_rs_decode_with_erasures<F: FftField>(
    received: &[F],
    k: usize,
    n: usize,
    erasure_positions: &[usize],
) -> Option<Vec<F>> {
    assert!(k <= n, "k must be <= n");
    let domain = GeneralEvaluationDomain::<F>::new(n).expect("No suitable evaluation domain found");

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

    // Step 1 : Interpolate g1(x) from received values with erasures zeroed out
    let values: Vec<F> = (0..n)
        .map(|i| {
            if s_set.contains(&i) {
                F::zero()
            } else {
                received[i]
            }
        })
        .collect();
    let mask: Vec<F> = (0..n)
        .map(|i| {
            if s_set.contains(&i) {
                F::zero()
            } else {
                F::one()
            }
        })
        .collect();

    let y_poly = Evaluations::from_vec_and_domain(values, domain).interpolate();
    let m_poly = Evaluations::from_vec_and_domain(mask, domain).interpolate();

    // f(x) * m(x) = y(x) => g1(x) = y(x), m(x) = known mask => f(x) = y(x) / m(x)
    let g1 = &y_poly / &m_poly;

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

    // Domain must be large enough for maximum expected size
    let domain = GeneralEvaluationDomain::<F>::new(n).expect("invalid domain");

    for r in 0..=t {
        let required = d + t + 1 + r;
        if shares.len() < required {
            continue; // wait for more shares
        }

        let subset = &shares[..required];
        let mut received = vec![F::zero(); n];
        for (i, val) in subset.iter() {
            received[*i] = *val;
        }

        if let Some(coeffs) = gao_rs_decode(&received, d + 1, n) {
            let poly = DensePolynomial::from_coefficients_vec(coeffs);

            // Count agreement
            let matched = subset
                .iter()
                .filter(|(i, v)| poly.evaluate(&domain.element(*i)) == *v)
                .count();

            if matched >= d + t + 1 {
                return Some((poly.clone(), poly.evaluate(&F::zero())));
            }
        }
    }

    None // No polynomial matched at any round
}

pub fn oec_decodee<F: FftField>(
    n: usize,
    d: usize,
    t: usize,
    mut shares: Vec<(usize, F)>,
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

        if let Some(coeffs) = gao_rs_decode_with_erasures(&received, d + 1, n, &erasures) {
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
#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::UniformRand;
    use ark_std::test_rng;

    #[test]
    fn test_reed_solomon() {
        let mut rng = test_rng();
        let k = 4;
        let n = 8;

        let message: Vec<Fr> = (0..k).map(|_| Fr::rand(&mut rng)).collect();
        let codeword = gao_rs_encode(&message, n);

        // Simulate errors
        let mut received = codeword.clone();
        received[2] += Fr::from(5u64);
        received[4] += Fr::from(3u64);

        let decoded = gao_rs_decode(&received, k, n);
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
        let result = oec_decodee(n, d, t, shares.clone());

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
}
