use std::ops::{Add, Mul};

/// This file contains the more common secret sharing protocols used in MPC.
/// You can reuse them for the MPC protocols that you aim to implement.
///
use crate::{Share, SecretSharingScheme, ShareError};
use ark_ff::{FftField, Zero};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;

pub type ShamirShare<T> = Share<T, 1>;  


impl<F: FftField> ShamirShare<F> {
    fn new(share: F, degree: usize, id: usize) -> Self {
        Share { share: [share], id: id, degree: degree }
    }
}

impl<F: FftField> SecretSharingScheme<F, 1> for ShamirShare<F> {
    type SecretType = F;

    // compute the shamir shares of all ids for a secret
    fn compute_shares(
        secret: Self::SecretType,
        degree: usize,
        ids: &[usize],
        rng: &mut impl Rng,
    ) -> Vec<Self> {
        let mut poly = DensePolynomial::rand(degree, rng);
        poly[0] = secret;

        let shares = ids
            .iter()
            .map(|id| {
                ShamirShare::new(
                    poly.evaluate(&F::from(*id as u64)),
                    *id,
                    degree
                )
            })
            .collect();
        shares
    }

    // recover the secret of the input shares
    fn recover_secret(shares: &[Self]) -> Result<Self::SecretType, ShareError> {
        let deg = shares[0].degree;
        if !shares.iter().all(|share| share.degree == deg) {
            return Err(ShareError::DegreeMismatch);
        };
        if shares.len() < deg + 1 {
            return Err(ShareError::InsufficientShares);
        }
        let (x_vals, y_vals): (Vec<F>, Vec<F>) = shares
            .iter()
            .map(|share| (F::from(share.id as u64), share.share[0]))
            .unzip();

        let result_poly = Self::lagrange_interpolate(&x_vals, &y_vals)?;
        Ok(result_poly[0])
    }
    
    fn lagrange_interpolate(
    x_vals: &[F],
    y_vals: &[F],
        ) -> Result<DensePolynomial<F>, ShareError> {
    if x_vals.len() != y_vals.len() {
        return Err(ShareError::InvalidInput);
    }
    let n = x_vals.len();
    let mut result = DensePolynomial::zero();
    
    for j in 0..n {
        let mut numerator = DensePolynomial::from_coefficients_slice(&[<F>::one()]);
        let mut denominator = <F>::one();
    
        for m in 0..n {
            if m != j {
                numerator =
                    &numerator * &DensePolynomial::from_coefficients_slice(&[-x_vals[m], <F>::one()]);
                denominator *= x_vals[j] - x_vals[m];
            }
        }
    
        let term = numerator * DensePolynomial::from_coefficients_slice(&[y_vals[j] / denominator]);
        result = &result + &term;
    }
    
    Ok(result)
        }
}



impl<F> Add<Rhs = &Self> for S<F>
where
    F: FftField,
{
    type Output = Result<Self, ShareError>;

    fn add(self, other: Self) -> Self::Output {
        if self.degree != other.degree {
            return Err(ShareError::DegreeMismatch);
        }
        if self.id != other.id {
            return Err(ShareError::IdMismatch);
        }
        if self.shamir_type != other.shamir_type {
            return Err(ShareError::TypeMismatch);
        }
        let new_share = self.share + other.share;
        Ok(Self {
            share: new_share,
            id: self.id,
            degree: self.degree,
            shamir_type: self.shamir_type,
        })
    }
}

impl<F> Mul<Rhs = &F> for ShamirShare<F>
where
    F: FftField,
{
    type Output = Self;
    fn mul(self, rhs: F) -> Self::Output {
        Self {
            share: self.share * rhs,
            id: self.id,
            degree: self.degree,
            shamir_type: self.shamir_type,
        }
    }
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
            ShareError::InvalidInput => panic!("incorrect error type"),
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
            ShareError::InvalidInput => panic!("incorrect error type"),
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
            ShareError::InvalidInput => panic!("incorrect error type"),
        }
    }
}
