pub mod shamir;

use std::ops::{Add, Mul};

use ark_ff::FftField;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use thiserror::Error;

use crate::honeybadger::robust_interpolate::InterpolateError;

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
}

/// Creates a Vandermonde matrix `V` of size `n x (t+1)`.
/// Each row `j` contains powers of `domain.element(j)`: `[1, alpha_j, alpha_j^2, ..., alpha_j^t]`.
pub fn make_vandermonde<F: FftField>(n: usize, t: usize) -> Result<Vec<Vec<F>>, InterpolateError> {
    let domain =
        GeneralEvaluationDomain::<F>::new(n).ok_or(InterpolateError::NoSuitableDomain(n))?;
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

/// Computes the matrix-vector product: `V * shares`.
/// This effectively evaluates a polynomial (defined by `shares` as coefficients)
/// at the domain elements corresponding to the Vandermonde matrix rows.
pub fn apply_vandermonde<F: FftField, P>(
    vandermonde: &[Vec<F>],
    shares: &[ShamirShare<F, 1, P>],
) -> Result<Vec<ShamirShare<F, 1, P>>, InterpolateError>
where
    ShamirShare<F, 1, P>: Clone
        + Mul<F, Output = Result<ShamirShare<F, 1, P>, ShareError>>
        + Add<ShamirShare<F, 1, P>, Output = Result<ShamirShare<F, 1, P>, ShareError>>,
{
    let share_len = shares.len();
    for (_, row) in vandermonde.iter().enumerate() {
        if row.len() != share_len {
            return Err(InterpolateError::InvalidInput(
                "Incorrect matrix length".to_string(),
            ));
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

    use crate::honeybadger::robust_interpolate::robust_interpolate::RobustShamirShare;
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::{Field, One};
    use ark_poly::GeneralEvaluationDomain;

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
            RobustShamirShare::new(Fr::from(1u64), 0, 2),
            RobustShamirShare::new(Fr::from(2u64), 0, 2),
            RobustShamirShare::new(Fr::from(3u64), 0, 2),
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
