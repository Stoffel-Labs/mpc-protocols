use crate::share::{Share, ShareError};
use ark_ff::{FftField, Zero};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;

#[derive(Debug, Clone, Copy, CanonicalSerialize, CanonicalDeserialize, PartialEq)]
pub struct ShamirSecretSharing<F: FftField> {
    pub share: F,
    pub id: F,
    pub degree: usize,
}

impl<F: FftField> ShamirSecretSharing<F> {
    pub fn new(share: F, id: F, degree: usize) -> Self {
        Self { share, id, degree }
    }

    pub fn compute_shares(
        secret: F,
        degree: usize,
        ids: &[F],
        rng: &mut impl Rng,
    ) -> (Vec<Self>, DensePolynomial<F>) {
        let mut poly = DensePolynomial::<F>::rand(degree, rng);
        poly[0] = secret;

        let shares = ids
            .iter()
            .map(|id| Self::new(poly.evaluate(id), *id, degree))
            .collect();
        (shares, poly)
    }

    pub fn recover_secret(shares: &[Self]) -> Result<F, ShareError> {
        let deg = shares[0].degree;
        if !shares.iter().all(|share| share.degree == deg) {
            return Err(ShareError::DegreeMismatch);
        };
        if shares.len() < deg + 1 {
            return Err(ShareError::InsufficientShares);
        }
        let (x_vals, y_vals): (Vec<F>, Vec<F>) =
            shares.iter().map(|share| (share.id, share.share)).unzip();

        let result_poly = lagrange_interpolate(&x_vals, &y_vals);
        if result_poly.len() == 0 {
            println!("incorrect shares: {:?}", shares)
        }
        Ok(result_poly[0])
    }
}

impl<F: FftField> Share for ShamirSecretSharing<F> {
    type UnderlyingSecret = F;
    fn add(&self, other: &Self) -> Result<Self, ShareError> {
        if self.degree != other.degree {
            return Err(ShareError::DegreeMismatch);
        }
        if self.id != other.id {
            return Err(ShareError::IdMismatch);
        }
        let new_share = self.share + other.share;
        Ok(Self {
            share: new_share,
            id: self.id,
            degree: self.degree,
        })
    }

    fn scalar_mul(&self, scalar: &Self::UnderlyingSecret) -> Self {
        Self {
            share: self.share * scalar,
            id: self.id,
            degree: self.degree,
        }
    }

    fn mul() {
        todo!()
    }

    fn reveal() {
        todo!()
    }
}

// todo - duplicated code
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

#[cfg(test)]
mod test {

    use super::*;
    use ark_bls12_381::Fr;
    use ark_std::test_rng;
    use std::iter::zip;

    #[test]
    fn should_recover_secret() {
        let secret = Fr::from(918520);
        let ids = &[
            Fr::from(1),
            Fr::from(2),
            Fr::from(3),
            Fr::from(4),
            Fr::from(5),
            Fr::from(6),
        ];
        let mut rng = test_rng();
        let (shares, _) = ShamirSecretSharing::compute_shares(secret, 5, ids, &mut rng);
        let recovered_secret = ShamirSecretSharing::recover_secret(&shares).unwrap();
        assert!(recovered_secret == secret);
    }

    #[test]
    fn should_add_shares() {
        let secret1 = Fr::from(10);
        let secret2 = Fr::from(20);
        let ids = &[
            Fr::from(1),
            Fr::from(2),
            Fr::from(3),
            Fr::from(4),
            Fr::from(5),
            Fr::from(6),
        ];
        let mut rng = test_rng();
        let (shares_1, _) = ShamirSecretSharing::compute_shares(secret1, 5, ids, &mut rng);
        let (shares_2, _) = ShamirSecretSharing::compute_shares(secret2, 5, ids, &mut rng);

        let added_shares = zip(shares_1, shares_2)
            .map(|(a, b)| a.add(&b).unwrap())
            .collect::<Vec<_>>();
        let recovered_secret = ShamirSecretSharing::recover_secret(&added_shares).unwrap();
        assert!(recovered_secret == secret1 + secret2);
    }

    #[test]
    fn should_multiply_scalar() {
        let secret = Fr::from(55);
        let ids = &[
            Fr::from(1),
            Fr::from(2),
            Fr::from(3),
            Fr::from(4),
            Fr::from(5),
            Fr::from(6),
            Fr::from(7),
            Fr::from(20),
        ];
        let mut rng = test_rng();
        let (shares, _) = ShamirSecretSharing::compute_shares(secret, 5, ids, &mut rng);
        let tripled_shares = shares
            .iter()
            .map(|share| share.scalar_mul(&Fr::from(3)))
            .collect::<Vec<_>>();
        let recovered_secret = ShamirSecretSharing::recover_secret(&tripled_shares).unwrap();
        assert!(recovered_secret == secret * Fr::from(3));
    }

    #[test]
    fn test_degree_mismatch() {
        let secret = Fr::from(918520);
        let ids = &[
            Fr::from(1),
            Fr::from(2),
            Fr::from(3),
            Fr::from(4),
            Fr::from(5),
            Fr::from(6),
        ];
        let mut rng = test_rng();
        let (mut shares, _) = ShamirSecretSharing::compute_shares(secret, 5, ids, &mut rng);

        shares[2].degree = 4;
        let recovered_secret = ShamirSecretSharing::recover_secret(&shares).unwrap_err();
        match recovered_secret {
            ShareError::InsufficientShares => panic!("incorrect error type"),
            ShareError::DegreeMismatch => (),
            ShareError::IdMismatch => panic!("incorrect error type"),
        }
    }

    #[test]
    fn test_insufficient_shares() {
        let secret = Fr::from(918520);
        let ids = &[Fr::from(1), Fr::from(2), Fr::from(3)];
        let mut rng = test_rng();
        let (shares, _) = ShamirSecretSharing::compute_shares(secret, 5, ids, &mut rng);
        let recovered_secret = ShamirSecretSharing::recover_secret(&shares).unwrap_err();
        match recovered_secret {
            ShareError::InsufficientShares => (),
            ShareError::DegreeMismatch => panic!("incorrect error type"),
            ShareError::IdMismatch => panic!("incorrect error type"),
        }
    }

    #[test]
    fn test_id_mis_match() {
        let secret1 = Fr::from(10);
        let secret2 = Fr::from(20);
        let ids1 = &[
            Fr::from(1),
            Fr::from(2),
            Fr::from(3),
            Fr::from(4),
            Fr::from(5),
            Fr::from(6),
        ];
        let ids2 = &[
            Fr::from(7),
            Fr::from(8),
            Fr::from(9),
            Fr::from(4),
            Fr::from(5),
            Fr::from(6),
        ];
        let mut rng = test_rng();
        let (shares_1, _) = ShamirSecretSharing::compute_shares(secret1, 5, ids1, &mut rng);
        let (shares_2, _) = ShamirSecretSharing::compute_shares(secret2, 5, ids2, &mut rng);

        let err = shares_1[0].add(&shares_2[0]).unwrap_err();
        match err {
            ShareError::InsufficientShares => panic!("incorrect error type"),
            ShareError::DegreeMismatch => panic!("incorrect error type"),
            ShareError::IdMismatch => (),
        }
    }
}
