/// This file contains the more common secret sharing protocols used in MPC.
/// You can reuse them for the MPC protocols that you aim to implement.
///
use crate::{SecretSharing, Share, ShareError};
use ark_ff::{FftField, Zero};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_std::rand::Rng;

// struct represents a single shamir share
#[derive(Debug, Clone, Copy)]
pub struct ShamirSecretSharing<F: FftField> {
    pub share: F,      // shamir share
    pub id: usize,     // id of the share
    pub degree: usize, // degree of the underlying polynomial
}

impl<F: FftField> ShamirSecretSharing<F> {
    pub fn new(share: F, id: usize, degree: usize) -> Self {
        Self { share, id, degree }
    }
}

impl<F: FftField> SecretSharing for ShamirSecretSharing<F> {
    type Secret = <ShamirSecretSharing<F> as Share>::UnderlyingSecret;
    type Share = Self;

    // compute the shamir shares of all ids for a secret
    fn compute_shares(
        secret: Self::Secret,
        degree: usize,
        ids: &[usize],
        rng: &mut impl Rng,
    ) -> Vec<Self> {
        let mut poly = DensePolynomial::rand(degree, rng);
        poly[0] = secret;

        let shares = ids
            .iter()
            .map(|id| ShamirSecretSharing::new(poly.evaluate(&F::from(*id as u64)), *id, degree))
            .collect();
        shares
    }

    // recover the secret of the input shares
    fn recover_secret(shares: &[Self]) -> Result<Self::Secret, ShareError> {
        let deg = shares[0].degree;
        if !shares.iter().all(|share| share.degree == deg) {
            return Err(ShareError::DegreeMismatch);
        };
        if shares.len() < deg + 1 {
            return Err(ShareError::InsufficientShares);
        }
        let (x_vals, y_vals): (Vec<F>, Vec<F>) = shares
            .iter()
            .map(|share| (F::from(share.id as u64), share.share))
            .unzip();

        let result_poly = lagrange_interpolate(&x_vals, &y_vals);
        if result_poly.degree() != deg {
            return Err(ShareError::DegreeMismatch);
        }
        Ok(result_poly[0])
    }
}

impl<F: FftField> Share for ShamirSecretSharing<F> {
    type UnderlyingSecret = F;

    // adds two shares with the same id
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

    // multiplies the share with a scalar
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

/// Interpolates a polynomial from (x, y) pairs using Lagrange interpolation.
pub fn lagrange_interpolate<F: FftField>(x_vals: &[F], y_vals: &[F]) -> DensePolynomial<F> {
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
        let ids = &[1, 2, 3, 4, 5, 6];
        let mut rng = test_rng();
        let shares = ShamirSecretSharing::compute_shares(secret, 5, ids, &mut rng);
        let recovered_secret = ShamirSecretSharing::recover_secret(&shares).unwrap();
        assert!(recovered_secret == secret);
    }

    #[test]
    fn should_add_shares() {
        let secret1 = Fr::from(10);
        let secret2 = Fr::from(20);
        let ids = &[1, 2, 3, 4, 5, 6];
        let mut rng = test_rng();
        let shares_1 = ShamirSecretSharing::compute_shares(secret1, 5, ids, &mut rng);
        let shares_2 = ShamirSecretSharing::compute_shares(secret2, 5, ids, &mut rng);

        let added_shares = zip(shares_1, shares_2)
            .map(|(a, b)| a.add(&b).unwrap())
            .collect::<Vec<_>>();
        let recovered_secret = ShamirSecretSharing::recover_secret(&added_shares).unwrap();
        assert!(recovered_secret == secret1 + secret2);
    }

    #[test]
    fn should_multiply_scalar() {
        let secret = Fr::from(55);
        let ids = &[1, 2, 3, 4, 5, 6, 7, 20];
        let mut rng = test_rng();
        let shares = ShamirSecretSharing::compute_shares(secret, 5, ids, &mut rng);
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
        let ids = &[1, 2, 3, 4, 5, 6];
        let mut rng = test_rng();
        let mut shares = ShamirSecretSharing::compute_shares(secret, 5, ids, &mut rng);

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
        let ids = &[1, 2, 3];
        let mut rng = test_rng();
        let shares = ShamirSecretSharing::compute_shares(secret, 5, ids, &mut rng);
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
        let ids1 = &[1, 2, 3, 4, 5, 6];
        let ids2 = &[7, 8, 9, 4, 5, 6];
        let mut rng = test_rng();
        let shares_1 = ShamirSecretSharing::compute_shares(secret1, 5, ids1, &mut rng);
        let shares_2 = ShamirSecretSharing::compute_shares(secret2, 5, ids2, &mut rng);

        let err = shares_1[0].add(&shares_2[0]).unwrap_err();
        match err {
            ShareError::InsufficientShares => panic!("incorrect error type"),
            ShareError::DegreeMismatch => panic!("incorrect error type"),
            ShareError::IdMismatch => (),
        }
    }
}
