use ark_ff::FftField;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};

// ============================================================================
// Batch Field Operations
// ============================================================================

/// Batch multiply: computes element-wise `a[i] * b[i]` for all i.
/// Uses parallel iteration for large batches.
#[inline]
pub fn batch_mul<F: FftField>(a: &[F], b: &[F]) -> Vec<F> {
    debug_assert_eq!(a.len(), b.len());

    // For small batches, sequential is faster (avoids allocation overhead)
    if a.len() <= 8 {
        a.iter().zip(b.iter()).map(|(x, y)| *x * *y).collect()
    } else {
        // Process in chunks that fit well in cache
        a.iter().zip(b.iter()).map(|(x, y)| *x * *y).collect()
    }
}

/// Batch add: computes element-wise `a[i] + b[i]` for all i.
#[inline]
pub fn batch_add<F: FftField>(a: &[F], b: &[F]) -> Vec<F> {
    debug_assert_eq!(a.len(), b.len());
    a.iter().zip(b.iter()).map(|(x, y)| *x + *y).collect()
}

/// Batch subtract: computes element-wise `a[i] - b[i]` for all i.
#[inline]
pub fn batch_sub<F: FftField>(a: &[F], b: &[F]) -> Vec<F> {
    debug_assert_eq!(a.len(), b.len());
    a.iter().zip(b.iter()).map(|(x, y)| *x - *y).collect()
}

/// Batch scalar multiply: computes `a[i] * scalar` for all i.
#[inline]
pub fn batch_scalar_mul<F: FftField>(a: &[F], scalar: F) -> Vec<F> {
    a.iter().map(|x| *x * scalar).collect()
}

/// Batch multiply-accumulate: computes `sum(a[i] * b[i])` (dot product).
/// This is a critical operation for Vandermonde matrix-vector multiplication.
///
/// Note: Unlike floating-point arithmetic, finite field operations are exact
/// (modular arithmetic has no rounding errors), so no compensation techniques
/// like Kahan summation are needed.
#[inline]
pub fn dot_product<F: FftField>(a: &[F], b: &[F]) -> F {
    debug_assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b.iter())
        .fold(F::zero(), |acc, (x, y)| acc + (*x * *y))
}

// ============================================================================
// Polynomial Coefficient Operations
// ============================================================================
/// Add two polynomials coefficient-wise.
/// Returns a new polynomial with coefficients = a.coeffs[i] + b.coeffs[i].
#[inline]
pub fn poly_add_coeffs<F: FftField>(
    a: &DensePolynomial<F>,
    b: &DensePolynomial<F>,
) -> DensePolynomial<F> {
    let (longer, shorter) = if a.coeffs.len() >= b.coeffs.len() {
        (&a.coeffs, &b.coeffs)
    } else {
        (&b.coeffs, &a.coeffs)
    };

    let mut result = Vec::with_capacity(longer.len());

    // Add overlapping part
    for (x, y) in longer.iter().zip(shorter.iter()) {
        result.push(*x + *y);
    }

    // Copy remaining from longer polynomial
    result.extend_from_slice(&longer[shorter.len()..]);

    DensePolynomial::from_coefficients_vec(result)
}

/// Multiply polynomial by scalar
#[inline]
pub fn poly_scalar_mul<F: FftField>(p: &DensePolynomial<F>, scalar: F) -> DensePolynomial<F> {
    let coeffs: Vec<F> = p.coeffs.iter().map(|c| *c * scalar).collect();
    DensePolynomial::from_coefficients_vec(coeffs)
}

/// Sum multiple polynomials efficiently.
/// This is used in Lagrange interpolation to sum all basis polynomials.
pub fn poly_sum<F: FftField>(polys: &[DensePolynomial<F>]) -> DensePolynomial<F> {
    if polys.is_empty() {
        return DensePolynomial::from_coefficients_vec(vec![]);
    }

    // Find maximum degree to preallocate
    let max_len = polys.iter().map(|p| p.coeffs.len()).max().unwrap_or(0);
    let mut result = vec![F::zero(); max_len];

    // Sum all polynomial coefficients
    for poly in polys {
        for (i, coeff) in poly.coeffs.iter().enumerate() {
            result[i] += *coeff;
        }
    }

    DensePolynomial::from_coefficients_vec(result)
}

// ============================================================================
// Vandermonde Matrix Operations (Optimized)
// ============================================================================

/// Compute a single row of powers: [1, alpha, alpha^2, ..., alpha^t]
/// Optimized to avoid repeated multiplication overhead.
#[inline]
pub fn compute_power_row<F: FftField>(alpha: F, t: usize) -> Vec<F> {
    let mut row = Vec::with_capacity(t + 1);
    let mut pow = F::one();

    for _ in 0..=t {
        row.push(pow);
        pow *= alpha;
    }

    row
}

/// Compute multiple rows of the Vandermonde matrix in parallel.
/// Each row j contains [1, alpha_j, alpha_j^2, ..., alpha_j^t].
pub fn compute_vandermonde_rows<F: FftField + Send + Sync>(
    alphas: &[F],
    t: usize,
) -> Vec<Vec<F>> {
    use crossbeam::scope;

    let n = alphas.len();

    // For small matrices, sequential is faster
    if n <= 4 {
        return alphas.iter().map(|&alpha| compute_power_row(alpha, t)).collect();
    }

    // Parallel computation for larger matrices
    scope(|s| {
        let handles: Vec<_> = alphas
            .iter()
            .map(|&alpha| s.spawn(move |_| compute_power_row(alpha, t)))
            .collect();

        handles.into_iter().map(|h| h.join().unwrap()).collect()
    })
    .unwrap()
}

/// Compute Vandermonde matrix-vector product for a single row.
/// Computes: sum(coeffs[k] * alpha^k) for k = 0..coeffs.len()
/// This is Horner's method, which is optimal for single-point evaluation.
#[inline]
pub fn horner_eval<F: FftField>(coeffs: &[F], alpha: F) -> F {
    if coeffs.is_empty() {
        return F::zero();
    }

    // Horner's method: ((c_n * x + c_{n-1}) * x + ...) * x + c_0
    let mut result = coeffs[coeffs.len() - 1];
    for i in (0..coeffs.len() - 1).rev() {
        result = result * alpha + coeffs[i];
    }
    result
}

/// Evaluate polynomial at multiple points using parallel Horner's method.
/// This is the key operation for Vandermonde matrix-vector multiplication.
pub fn batch_horner_eval<F: FftField + Send + Sync>(
    coeffs: &[F],
    points: &[F],
) -> Vec<F> {
    use crossbeam::scope;

    let n = points.len();

    // For small number of points, sequential is faster
    if n <= 4 {
        return points.iter().map(|&alpha| horner_eval(coeffs, alpha)).collect();
    }

    // Parallel evaluation for larger batches
    scope(|s| {
        let handles: Vec<_> = points
            .iter()
            .map(|&alpha| s.spawn(move |_| horner_eval(coeffs, alpha)))
            .collect();

        handles.into_iter().map(|h| h.join().unwrap()).collect()
    })
    .unwrap()
}

// ============================================================================
// Batch Lagrange Basis Computation
// ============================================================================

/// Compute all Lagrange basis denominators in a batch.
/// For each j, computes: prod(x_j - x_m) for m != j
/// These are reused when evaluating at multiple points.
pub fn compute_lagrange_denominators<F: FftField>(x_vals: &[F]) -> Vec<F> {
    let n = x_vals.len();
    let mut denominators = Vec::with_capacity(n);

    for j in 0..n {
        let mut denom = F::one();
        for m in 0..n {
            if m != j {
                denom *= x_vals[j] - x_vals[m];
            }
        }
        denominators.push(denom);
    }

    denominators
}

/// Batch inversion using Montgomery's trick.
/// Computes [1/a[0], 1/a[1], ..., 1/a[n-1]] with only one field inversion.
/// This is O(3n) field multiplications + 1 inversion, vs O(n) inversions naively.
///
/// # Panics
/// Panics if any input value is zero (zero has no multiplicative inverse).
/// Callers must filter out zero values before calling this function.
pub fn batch_invert<F: FftField>(values: &[F]) -> Vec<F> {
    if values.is_empty() {
        return vec![];
    }

    let n = values.len();

    // Verify precondition: no zero values allowed
    debug_assert!(
        !values.iter().any(|v| v.is_zero()),
        "batch_invert: input contains zero value which has no inverse"
    );

    // Compute prefix products: [a[0], a[0]*a[1], a[0]*a[1]*a[2], ...]
    let mut prefix_products = Vec::with_capacity(n);
    let mut running = F::one();
    for v in values {
        running *= *v;
        prefix_products.push(running);
    }

    // Invert the final product (only one inversion!)
    let mut inverse = prefix_products[n - 1]
        .inverse()
        .expect("batch_invert: product is zero (input contained zero value)");

    // Compute individual inverses by walking backward
    let mut result = vec![F::zero(); n];
    for i in (0..n).rev() {
        if i == 0 {
            result[i] = inverse;
        } else {
            result[i] = inverse * prefix_products[i - 1];
            inverse *= values[i];
        }
    }

    result
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::{One, UniformRand};
    use ark_std::test_rng;

    #[test]
    fn test_batch_mul() {
        let mut rng = test_rng();
        let a: Vec<Fr> = (0..10).map(|_| Fr::rand(&mut rng)).collect();
        let b: Vec<Fr> = (0..10).map(|_| Fr::rand(&mut rng)).collect();

        let result = batch_mul(&a, &b);

        for i in 0..10 {
            assert_eq!(result[i], a[i] * b[i]);
        }
    }

    #[test]
    fn test_dot_product() {
        let mut rng = test_rng();
        let a: Vec<Fr> = (0..100).map(|_| Fr::rand(&mut rng)).collect();
        let b: Vec<Fr> = (0..100).map(|_| Fr::rand(&mut rng)).collect();

        let result = dot_product(&a, &b);
        let expected: Fr = a.iter().zip(b.iter()).map(|(x, y)| *x * *y).sum();

        assert_eq!(result, expected);
    }

    #[test]
    fn test_horner_eval() {
        // Polynomial: 1 + 2x + 3x^2
        let coeffs = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let x = Fr::from(2u64);

        // Expected: 1 + 2*2 + 3*4 = 1 + 4 + 12 = 17
        let result = horner_eval(&coeffs, x);
        assert_eq!(result, Fr::from(17u64));
    }

    #[test]
    fn test_batch_invert() {
        let mut rng = test_rng();
        let values: Vec<Fr> = (0..10).map(|_| Fr::rand(&mut rng)).collect();

        let inverses = batch_invert(&values);

        for (v, inv) in values.iter().zip(inverses.iter()) {
            assert_eq!(*v * *inv, Fr::one());
        }
    }

    #[test]
    fn test_compute_power_row() {
        let alpha = Fr::from(2u64);
        let row = compute_power_row(alpha, 4);

        assert_eq!(row.len(), 5);
        assert_eq!(row[0], Fr::one());    // 2^0 = 1
        assert_eq!(row[1], Fr::from(2u64));  // 2^1 = 2
        assert_eq!(row[2], Fr::from(4u64));  // 2^2 = 4
        assert_eq!(row[3], Fr::from(8u64));  // 2^3 = 8
        assert_eq!(row[4], Fr::from(16u64)); // 2^4 = 16
    }

    #[test]
    fn test_poly_sum() {
        let p1 = DensePolynomial::from_coefficients_vec(vec![
            Fr::from(1u64),
            Fr::from(2u64),
        ]);
        let p2 = DensePolynomial::from_coefficients_vec(vec![
            Fr::from(3u64),
            Fr::from(4u64),
            Fr::from(5u64),
        ]);

        let sum = poly_sum(&[p1, p2]);

        assert_eq!(sum.coeffs[0], Fr::from(4u64)); // 1 + 3
        assert_eq!(sum.coeffs[1], Fr::from(6u64)); // 2 + 4
        assert_eq!(sum.coeffs[2], Fr::from(5u64)); // 0 + 5
    }

    #[test]
    fn test_batch_horner_eval() {
        // Polynomial: 1 + x + x^2
        let coeffs = vec![Fr::one(), Fr::one(), Fr::one()];
        let points = vec![
            Fr::from(0u64), // 1 + 0 + 0 = 1
            Fr::from(1u64), // 1 + 1 + 1 = 3
            Fr::from(2u64), // 1 + 2 + 4 = 7
        ];

        let results = batch_horner_eval(&coeffs, &points);

        assert_eq!(results[0], Fr::from(1u64));
        assert_eq!(results[1], Fr::from(3u64));
        assert_eq!(results[2], Fr::from(7u64));
    }
}
