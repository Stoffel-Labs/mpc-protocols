//! Hyperinvertible-matrix helpers for GF(2^k), mirroring `common/share/mod.rs`'s
//! `make_vandermonde`/`apply_vandermonde` (`F: FftField`-bound) with `Gf2kDomain<K>` in place of
//! `get_or_create_evaluation_domain::<F>` and `GfShare<K>` in place of `ShamirShare<F, 1, P>`.

use super::field::{BinaryField, Gf2kDomain};
use super::share::GfShare;
use super::Gf2kError;

/// Creates a Vandermonde matrix `V` of size `n x (t+1)`. Each row `j` contains powers of
/// `domain.element(j)`: `[1, alpha_j, alpha_j^2, ..., alpha_j^t]`.
pub fn make_vandermonde<K: BinaryField>(n: usize, t: usize) -> Result<Vec<Vec<K>>, Gf2kError> {
    let domain = Gf2kDomain::<K>::new(n)?;
    let mut matrix = vec![vec![K::zero(); t + 1]; n];
    for j in 0..n {
        let alpha_j = domain.element(j);
        let mut pow = K::one();
        for k in 0..=t {
            matrix[j][k] = pow;
            pow = pow * alpha_j;
        }
    }
    Ok(matrix)
}

/// Computes the matrix-vector product `V * shares`: evaluates the polynomial defined by `shares`
/// (as coefficients) at each domain point corresponding to a Vandermonde matrix row.
pub fn apply_vandermonde<K: BinaryField>(
    vandermonde: &[Vec<K>],
    shares: &[GfShare<K>],
) -> Result<Vec<GfShare<K>>, Gf2kError> {
    let share_len = shares.len();
    for row in vandermonde {
        if row.len() != share_len {
            return Err(Gf2kError::InvalidInput(
                "vandermonde row length does not match share count".to_string(),
            ));
        }
    }
    vandermonde
        .iter()
        .map(|row| {
            let mut acc = (shares[0].clone() * row[0])?;
            for (a, b) in row.iter().zip(shares.iter()).skip(1) {
                let term = (b.clone() * *a)?;
                acc = (acc + term)?;
            }
            Ok(acc)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::super::field::Gf256;
    use super::*;

    #[test]
    fn test_make_vandermonde_basic() {
        let n = 4;
        let t = 2;
        let vandermonde = make_vandermonde::<Gf256>(n, t).unwrap();

        assert_eq!(vandermonde.len(), n);
        for row in &vandermonde {
            assert_eq!(row.len(), t + 1);
        }

        let domain = Gf2kDomain::<Gf256>::new(n).unwrap();
        assert_eq!(vandermonde[0][0], Gf256::one());
        assert_eq!(vandermonde[0][1], Gf256::one());
        assert_eq!(vandermonde[0][2], Gf256::one());

        let alpha_1 = domain.element(1);
        assert_eq!(vandermonde[1][0], Gf256::one());
        assert_eq!(vandermonde[1][1], alpha_1);
        assert_eq!(vandermonde[1][2], alpha_1 * alpha_1);

        let alpha_2 = domain.element(2);
        assert_eq!(vandermonde[2][1], alpha_2);
    }

    #[test]
    fn test_apply_vandermonde_basic() {
        let n = 4;
        let t = 2;
        let vandermonde = make_vandermonde::<Gf256>(n, t).unwrap();
        // Shares represent coefficients [c0, c1, c2] for a polynomial c0 + c1*x + c2*x^2.
        let shares = vec![
            GfShare::new(Gf256(1), 0, 2),
            GfShare::new(Gf256(2), 0, 2),
            GfShare::new(Gf256(3), 0, 2),
        ];
        let y_values = apply_vandermonde(&vandermonde, &shares).unwrap();
        assert_eq!(y_values.len(), n);

        let domain = Gf2kDomain::<Gf256>::new(n).unwrap();
        for j in 0..n {
            let alpha_j = domain.element(j);
            let expected = shares[0].share
                + shares[1].share * alpha_j
                + shares[2].share * (alpha_j * alpha_j);
            assert_eq!(y_values[j].share, expected, "mismatch at index {j}");
        }
    }

    #[test]
    fn test_apply_vandermonde_row_length_mismatch_errors() {
        let vandermonde = vec![vec![Gf256::one(), Gf256::one()]];
        let shares = vec![GfShare::new(Gf256(1), 0, 0)]; // length 1, row expects 2
        assert!(apply_vandermonde(&vandermonde, &shares).is_err());
    }
}
