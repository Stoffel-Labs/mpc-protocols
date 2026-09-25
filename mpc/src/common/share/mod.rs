pub mod avss;
pub mod feldman;
pub mod shamir;
use std::ops::{Add, Mul};

use ark_ff::{batch_inversion, FftField};
use ark_poly::EvaluationDomain;
use thiserror::Error;

use super::ShamirShare;

#[derive(Debug, Error)]
pub enum ShareError {
    #[error("insufficient shares to reconstruct the secret")]
    InsufficientShares,
    #[error("mismatch degree between shares")]
    DegreeMismatch,
    #[error("mismatch index between shares")]
    IdMismatch,
    #[error("invalid input")]
    InvalidInput,
    #[error("types are different")]
    TypeMismatch,
    /// No suitable FFT evaluation domain could be found.
    #[error("No suitable FFT evaluation domain found for n={0}")]
    NoSuitableDomain(usize),
}

/// Creates a Vandermonde matrix `V` of size `n x (t+1)`.
/// Each row `j` contains powers of `domain.element(j)`: `[1, alpha_j, alpha_j^2, ..., alpha_j^t]`.
///
/// This is a plain power-basis matrix, not a hyperinvertible one: it is only sound for
/// uses that don't rely on "check a fixed subset of rows, trust the rest" (e.g. batch
/// reconstruction, which relies on Reed-Solomon minimum-distance decoding on the
/// receiving end instead). For that "check some rows, release the rest as trusted
/// preprocessing" pattern, use [`make_hyperinvertible_matrix`] instead — see its doc
/// comment for why this matrix is unsound there.
pub fn make_vandermonde<F: FftField>(n: usize, t: usize) -> Result<Vec<Vec<F>>, ShareError> {
    let domain = crate::common::get_or_create_evaluation_domain::<F>(n)
        .ok_or(ShareError::NoSuitableDomain(n))?;
    let mut matrix = vec![vec![F::zero(); t + 1]; n];
    for j in 0..n {
        let alpha_j = domain.element(j);
        let mut pow = F::one();
        for k in 0..=t {
            matrix[j][k] = pow;
            pow *= alpha_j;
        }
    }

    Ok(matrix)
}

/// Builds an `n x n` hyperinvertible matrix `M`: every square submatrix (any subset of
/// rows crossed with any equal-size subset of columns) is invertible.
///
/// # Background: why this function exists
///
/// RanSha, ZeroSha and RanDouSha all follow the same pattern: `n` parties each deal one
/// input sharing, a fixed public matrix `M` combines the `n` inputs into `n` output
/// sharings, and *only some* of the outputs are ever reconstructed and checked — the rest
/// are trusted and released straight into the preprocessing pool. That pattern is only
/// sound if `M` is hyperinvertible: checking a subset of outputs implies the rest are
/// valid *only* because every square submatrix of `M` is invertible (see
/// Beerliová-Trubíniová & Hirt, "Perfectly-Secure MPC with Linear Communication
/// Complexity", TCC 2008, Definition 2).
///
/// The matrix this codebase used before (`make_vandermonde(n, n-1)`, i.e.
/// `M[j][d] = alpha_j^d` for a single FFT domain `alpha`) is *not* hyperinvertible: on a
/// power-of-two domain, `alpha^(n/2) = -1`, so columns at distance `n/2` cancel
/// identically across an entire parity class of rows. A pair of colluding dealers could
/// pick that column pair and pass every checked row while corrupting the unchecked rows
/// released into the pool. Confirmed both algebraically and against the real crate (see
/// `test_hyperinvertible_matrix_closes_n16_t5_attack` below).
///
/// # The construction actually used
///
/// This is Construction 1 from Beerliová-Trubíniová & Hirt (TCC 2008, Section 3.2):
/// interpolate a degree-<n polynomial through one set of `n` points (`delta`) and
/// evaluate it at a second, *disjoint* set of `n` points (`gamma`). Lemma 1 of that paper
/// proves this is hyperinvertible for *any* choice of `2n` pairwise-distinct field
/// elements — the proof only uses that no `delta` ever equals any `gamma`, nothing about
/// how either set is otherwise structured. That's the whole reason this is safe where the
/// single-domain Vandermonde wasn't: reusing one FFT domain for both roles is what let
/// the two roles' shared algebraic structure (`alpha^(n/2) = -1`) leak into an
/// exploitable relation between columns and rows.
///
/// Concretely: `delta_d` is the *existing* per-party evaluation domain (the same points
/// shares are already evaluated at elsewhere in this crate) — kept as-is so nothing about
/// share evaluation/reconstruction changes. `gamma_j` is a disjoint coset of that same
/// domain, shifted by `F::GENERATOR` (see the comment at its use below for why that's
/// guaranteed disjoint). `M[j][d]` is then the Lagrange coefficient for "evaluate at
/// `gamma_j` the unique degree-<n polynomial through `(delta_0, y_0), ..., (delta_{n-1},
/// y_{n-1})`" — computed via the barycentric form of that formula (Berrut & Trefethen,
/// "Barycentric Lagrange Interpolation", SIAM Review 46(3), 2004) so the whole matrix
/// costs `O(n)` field inversions (batched) instead of `O(n^2)`.
pub fn make_hyperinvertible_matrix<F: FftField>(n: usize) -> Result<Vec<Vec<F>>, ShareError> {
    let domain = crate::common::get_or_create_evaluation_domain::<F>(n)
        .ok_or(ShareError::NoSuitableDomain(n))?;
    // A coset is "the domain, uniformly shifted": every element multiplied by a fixed
    // offset. get_coset(offset) returns the domain {offset * delta : delta in domain}.
    // F::GENERATOR has multiplicative order F::MODULUS - 1, which is astronomically
    // larger than (and so never divides) the domain's own subgroup order — so
    // GENERATOR is never itself a domain element, which is exactly what guarantees
    // offset*delta_j never lands back on some other domain element delta_k. That's the
    // whole disjointness property Construction 1 needs; nothing about *which* nonzero
    // non-domain offset is chosen matters beyond that.
    let coset = domain
        .get_coset(F::GENERATOR)
        .ok_or(ShareError::NoSuitableDomain(n))?;

    let deltas: Vec<F> = (0..n).map(|d| domain.element(d)).collect();
    let gammas: Vec<F> = (0..n).map(|j| coset.element(j)).collect();

    // Barycentric weights: w_d = 1 / prod_{k != d} (delta_d - delta_k). Depends only on
    // the deltas, so computed once and reused for every row below.
    let mut weights: Vec<F> = (0..n)
        .map(|d| {
            deltas
                .iter()
                .enumerate()
                .filter(|&(k, _)| k != d)
                .fold(F::one(), |acc, (_, &delta_k)| acc * (deltas[d] - delta_k))
        })
        .collect();
    batch_inversion(&mut weights);

    let mut matrix = vec![vec![F::zero(); n]; n];
    for j in 0..n {
        let gamma_j = gammas[j];
        // Node polynomial value at gamma_j: prod_k (gamma_j - delta_k).
        let ell_j: F = deltas
            .iter()
            .fold(F::one(), |acc, &delta_k| acc * (gamma_j - delta_k));

        // M[j][d] = w_d * ell_j / (gamma_j - delta_d), batched over one row at a time.
        let mut denoms: Vec<F> = deltas.iter().map(|&delta_d| gamma_j - delta_d).collect();
        batch_inversion(&mut denoms);
        for d in 0..n {
            matrix[j][d] = weights[d] * ell_j * denoms[d];
        }
    }

    Ok(matrix)
}

/// Computes the matrix-vector product: `M * shares`.
pub fn apply_vandermonde<F: FftField, P>(
    vandermonde: &[Vec<F>],
    shares: &[ShamirShare<F, 1, P>],
) -> Result<Vec<ShamirShare<F, 1, P>>, ShareError>
where
    ShamirShare<F, 1, P>: Clone
        + Mul<F, Output = Result<ShamirShare<F, 1, P>, ShareError>>
        + Add<ShamirShare<F, 1, P>, Output = Result<ShamirShare<F, 1, P>, ShareError>>,
{
    let share_len = shares.len();
    for (_, row) in vandermonde.iter().enumerate() {
        if row.len() != share_len {
            return Err(ShareError::InvalidInput);
        }
    }
    vandermonde
        .iter()
        .map(|row| {
            let mut acc = (shares[0].clone() * row[0])?;
            for (a, b) in row.iter().zip(shares.iter()).skip(1) {
                let term = (b.clone() * *a)?;
                acc = (acc + term)?
            }
            Ok(acc)
        })
        .collect()
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
    use ark_bls12_381::Fr;
    use ark_ff::{Field, One, UniformRand, Zero};
    use ark_poly::{DenseUVPolynomial, GeneralEvaluationDomain, Polynomial};
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    /// Gaussian elimination over a field: true iff `rows` (a square matrix, given as a
    /// list of equal-length rows) is invertible. Test-only; not meant to be efficient.
    fn is_invertible<F: Field>(mut rows: Vec<Vec<F>>) -> bool {
        let k = rows.len();
        for col in 0..k {
            let Some(pivot) = (col..k).find(|&r| !rows[r][col].is_zero()) else {
                return false;
            };
            rows.swap(col, pivot);
            let inv = rows[col][col].inverse().unwrap();
            for r in (col + 1)..k {
                let factor = rows[r][col] * inv;
                for c in col..k {
                    let term = rows[col][c] * factor;
                    rows[r][c] -= term;
                }
            }
        }
        true
    }

    #[test]
    fn test_hyperinvertible_matrix_dimensions() {
        let n = 11;
        let matrix = make_hyperinvertible_matrix::<Fr>(n).expect("matrix construction failed");
        assert_eq!(matrix.len(), n);
        for row in &matrix {
            assert_eq!(row.len(), n);
        }
    }

    #[test]
    fn test_hyperinvertible_matrix_lagrange_correctness() {
        // M[j][d] should be the Lagrange coefficient mapping evaluations at the party
        // domain to evaluations at the disjoint coset: for any degree-<n polynomial P,
        // sum_d M[j][d] * P(delta_d) == P(gamma_j) for every output row j.
        let n = 9;
        let mut rng = StdRng::seed_from_u64(42);
        let domain = GeneralEvaluationDomain::<Fr>::new(n).unwrap();
        let coset = domain.get_coset(Fr::GENERATOR).unwrap();
        let matrix = make_hyperinvertible_matrix::<Fr>(n).expect("matrix construction failed");

        for _ in 0..5 {
            let poly = ark_poly::univariate::DensePolynomial::<Fr>::rand(n - 1, &mut rng);
            let evals_at_deltas: Vec<Fr> =
                (0..n).map(|d| poly.evaluate(&domain.element(d))).collect();
            for j in 0..n {
                let expected = poly.evaluate(&coset.element(j));
                let actual: Fr = (0..n).map(|d| matrix[j][d] * evals_at_deltas[d]).sum();
                assert_eq!(actual, expected, "row {j} mismatch");
            }
        }
    }

    #[test]
    fn test_hyperinvertible_matrix_random_submatrices_invertible() {
        let n = 16;
        let matrix = make_hyperinvertible_matrix::<Fr>(n).expect("matrix construction failed");
        let mut rng = StdRng::seed_from_u64(7);

        for k in 1..=n {
            for _ in 0..5 {
                let mut rows: Vec<usize> = (0..n).collect();
                let mut cols: Vec<usize> = (0..n).collect();
                // Fisher-Yates-ish partial shuffle via random swaps, then take first k.
                for i in 0..n {
                    let j = (u64::rand(&mut rng) as usize) % n;
                    rows.swap(i, j);
                    let j2 = (u64::rand(&mut rng) as usize) % n;
                    cols.swap(i, j2);
                }
                rows.truncate(k);
                cols.truncate(k);
                let submatrix: Vec<Vec<Fr>> = rows
                    .iter()
                    .map(|&r| cols.iter().map(|&c| matrix[r][c]).collect())
                    .collect();
                assert!(
                    is_invertible(submatrix),
                    "submatrix rows={rows:?} cols={cols:?} (k={k}) should be invertible"
                );
            }
        }
    }

    #[test]
    fn test_hyperinvertible_matrix_closes_n16_t5_attack() {
        // Regression test for the FFT-Vandermonde verification bypass: with the old
        // plain power-basis Vandermonde matrix (M[j][d] = alpha_j^d over a single order-16
        // FFT domain), columns 0 and 8 satisfy alpha_j^0 + alpha_j^8 = 1 + (-1)^j, which is
        // exactly 0 on all 8 odd rows and 2 on all 8 even rows - including the unchecked
        // rows 10, 12, 14 that a "check first 2t=10 rows, trust the rest" protocol releases
        // straight into the preprocessing pool. Two colluding dealers at columns 0 and 8
        // could deal a matching nonzero secret that cancels on every odd checked row while
        // silently surviving in the unchecked, released output.
        //
        // With a genuinely hyperinvertible matrix, that pair can zero out at most
        // k-1 = 1 of the n rows (a 2-column corruption can't force more than 1 row to
        // vanish without contradicting invertibility of some 2x2 submatrix) - nowhere near
        // the 8-row parity-class wipeout the broken matrix allowed.
        let n = 16;

        let old_matrix = make_vandermonde::<Fr>(n, n - 1).expect("old matrix construction failed");
        let old_zero_rows = (0..n)
            .filter(|&j| (old_matrix[j][0] + old_matrix[j][8]).is_zero())
            .count();
        assert_eq!(
            old_zero_rows, 8,
            "sanity check: the old matrix should reproduce the known 8-row cancellation"
        );

        let new_matrix =
            make_hyperinvertible_matrix::<Fr>(n).expect("new matrix construction failed");
        let new_zero_rows = (0..n)
            .filter(|&j| (new_matrix[j][0] + new_matrix[j][8]).is_zero())
            .count();
        assert!(
            new_zero_rows <= 1,
            "hyperinvertible matrix should allow at most 1 coincidental zero row for a \
             2-column corruption, got {new_zero_rows}"
        );
    }

    #[test]
    fn test_make_vandermonde_basic() {
        let n = 4;
        let t = 2; // Matrix will have t+1 columns
        let vandermonde = make_vandermonde::<Fr>(n, t).expect("apply_vandermonde failed");

        // Verify dimensions
        assert_eq!(
            vandermonde.len(),
            n,
            "Vandermonde matrix should have 'n' rows"
        );
        for row in &vandermonde {
            assert_eq!(row.len(), t + 1, "Each row should have 't+1' columns");
        }

        let domain =
            GeneralEvaluationDomain::<Fr>::new(n).expect("Failed to create evaluation domain");

        // Verify specific elements based on the domain elements
        // Row 0: [1, 1, 1] since domain.element(0) is always 1
        assert_eq!(vandermonde[0][0], Fr::one());
        assert_eq!(vandermonde[0][1], Fr::one());
        assert_eq!(vandermonde[0][2], Fr::one());

        // Row 1: [1, alpha_1, alpha_1^2]
        let alpha_1 = domain.element(1);
        assert_eq!(vandermonde[1][0], Fr::one());
        assert_eq!(vandermonde[1][1], alpha_1);
        assert_eq!(vandermonde[1][2], alpha_1 * alpha_1);

        // Verify a general element: matrix[j][k] should be (domain.element(j))^k
        let j_test = 2;
        let k_test = 1;
        let alpha_j_test = domain.element(j_test);
        assert_eq!(
            vandermonde[j_test][k_test],
            alpha_j_test.pow([k_test as u64]),
            "Mismatch at matrix[{j_test}][{k_test}]"
        );

        let j_test_2 = 3;
        let k_test_2 = 2;
        let alpha_j_test_2 = domain.element(j_test_2);
        assert_eq!(
            vandermonde[j_test_2][k_test_2],
            alpha_j_test_2.pow([k_test_2 as u64]),
            "Mismatch at matrix[{j_test_2}][{k_test_2}]"
        );
    }

    #[test]
    fn test_apply_vandermonde_basic() {
        let n = 4;
        let t = 2;
        let vandermonde = make_vandermonde::<Fr>(n, t).expect("make_vandermonde failed");
        // Shares represent coefficients [c0, c1, c2] for a polynomial c0 + c1*x + c2*x^2
        let shares = vec![
            RobustShare::new(Fr::from(1u64), 0, 2),
            RobustShare::new(Fr::from(2u64), 0, 2),
            RobustShare::new(Fr::from(3u64), 0, 2),
        ];
        let y_values = apply_vandermonde(&vandermonde, &shares).expect("apply_vandermonde failed");
        assert_eq!(
            y_values.len(),
            n,
            "Output y_values should have 'n' elements"
        );

        let domain =
            GeneralEvaluationDomain::<Fr>::new(n).expect("Failed to create evaluation domain");

        // Expected y_values[j] = sum(shares[k] * alpha_j^k)
        // This is equivalent to evaluating the polynomial represented by 'shares' at alpha_j
        for j in 0..n {
            let alpha_j = domain.element(j);
            let expected_y_j = shares[0].share[0] * alpha_j.pow([0]) // shares[0] * 1
                             + shares[1].share[0] * alpha_j.pow([1]) // shares[1] * alpha_j
                             + shares[2].share[0] * alpha_j.pow([2]); // shares[2] * alpha_j^2
            assert_eq!(
                y_values[j].share[0], expected_y_j,
                "Mismatch for y_values at index {}",
                j
            );
        }
    }
}
