use std::marker::PhantomData;

/// This file contains the more common secret sharing protocols used in MPC.
/// You can reuse them for the MPC protocols that you aim to implement.
///
use crate::common::{lagrange_interpolate, share::ShareError, SecretSharingScheme, ShamirShare};
use ark_ff::FftField;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_std::rand::Rng;

#[derive(Clone, Debug)]
pub struct NonRobust;
pub type NonRobustShamirShare<T> = ShamirShare<T, 1, NonRobust>;

impl<F: FftField> NonRobustShamirShare<F> {
    pub fn new(share: F, id: usize, degree: usize) -> Self {
        ShamirShare {
            share: [share],
            id,
            degree,
            _sharetype: PhantomData,
        }
    }
}

impl<F: FftField> Default for NonRobustShamirShare<F> {
    fn default() -> Self {
        Self {
            share: [F::ZERO],
            id: 0,
            degree: 0,
            _sharetype: PhantomData,
        }
    }
}

impl<F: FftField> SecretSharingScheme<F> for NonRobustShamirShare<F> {
    type SecretType = F;
    type Error = ShareError;

    // compute the shamir shares of all ids for a secret
    fn compute_shares(
        secret: Self::SecretType,

        // TODO: Remove this.
        _n: usize,

        degree: usize,
        ids: Option<&[usize]>,
        rng: &mut impl Rng,
    ) -> Result<Vec<Self>, ShareError> {
        let mut poly = DensePolynomial::rand(degree, rng);
        poly[0] = secret;

        // TODO: Why is ids an Option type?
        match ids {
            Some(id_list) => {
                let shares = id_list
                    .iter()
                    .map(|id| {
                        let x = F::from(*id as u64);
                        let y = poly.evaluate(&x);
                        NonRobustShamirShare::new(y, *id, degree)
                    })
                    .collect();
                Ok(shares)
            }
            None => {
                return Err(ShareError::InvalidInput);
            }
        }
    }

    // recover the secret of the input shares
    fn recover_secret(
        shares: &[Self],
    ) -> Result<(Vec<Self::SecretType>, Self::SecretType), ShareError> {
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

        let result_poly = lagrange_interpolate(&x_vals, &y_vals)?;
        Ok((result_poly.coeffs.clone(), result_poly[0]))
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
        let shares =
            NonRobustShamirShare::compute_shares(secret, 6, 5, Some(ids), &mut rng).unwrap();
        let (_, recovered_secret) = NonRobustShamirShare::recover_secret(&shares).unwrap();
        assert!(recovered_secret == secret);
    }

    #[test]
    fn should_add_shares() {
        let secret1 = Fr::from(10);
        let secret2 = Fr::from(20);
        let ids = &[1, 2, 3, 4, 5, 6];
        let mut rng = test_rng();
        let shares_1 =
            NonRobustShamirShare::compute_shares(secret1, 6, 5, Some(ids), &mut rng).unwrap();
        let shares_2 =
            NonRobustShamirShare::compute_shares(secret2, 6, 5, Some(ids), &mut rng).unwrap();

        let added_shares: Vec<_> = zip(shares_1, shares_2)
            .map(|(a, b)| a + b)
            .collect::<Result<_, _>>() // Handles errors cleanly
            .unwrap();
        let (_, recovered_secret) = NonRobustShamirShare::recover_secret(&added_shares).unwrap();
        assert!(recovered_secret == secret1 + secret2);
    }

    #[test]
    fn should_multiply_scalar() {
        let secret = Fr::from(55);
        let ids = &[1, 2, 3, 4, 5, 6, 7, 20];
        let mut rng = test_rng();
        let shares =
            NonRobustShamirShare::compute_shares(secret, 8, 5, Some(ids), &mut rng).unwrap();
        let tripled_shares = shares
            .iter()
            .map(|share| share.clone() * Fr::from(3))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let (_, recovered_secret) = NonRobustShamirShare::recover_secret(&tripled_shares).unwrap();
        assert!(recovered_secret == secret * Fr::from(3));
    }

    #[test]
    fn test_degree_mismatch() {
        let secret = Fr::from(918520);
        let ids = &[1, 2, 3, 4, 5, 6];
        let mut rng = test_rng();
        let mut shares =
            NonRobustShamirShare::compute_shares(secret, 6, 5, Some(ids), &mut rng).unwrap();

        shares[2].degree = 4;
        let recovered_secret = NonRobustShamirShare::recover_secret(&shares).unwrap_err();
        match recovered_secret {
            ShareError::InsufficientShares => panic!("incorrect error type"),
            ShareError::DegreeMismatch => (),
            ShareError::IdMismatch => panic!("incorrect error type"),
            ShareError::InvalidInput => panic!("incorrect error type"),
            ShareError::TypeMismatch => panic!("incorrect error type"),
        }
    }

    #[test]
    fn test_insufficient_shares() {
        let secret = Fr::from(918520);
        let ids = &[1, 2, 3];
        let mut rng = test_rng();
        let shares =
            NonRobustShamirShare::compute_shares(secret, 3, 5, Some(ids), &mut rng).unwrap();
        let recovered_secret = NonRobustShamirShare::recover_secret(&shares).unwrap_err();
        match recovered_secret {
            ShareError::InsufficientShares => (),
            ShareError::DegreeMismatch => panic!("incorrect error type"),
            ShareError::IdMismatch => panic!("incorrect error type"),
            ShareError::InvalidInput => panic!("incorrect error type"),
            ShareError::TypeMismatch => panic!("incorrect error type"),
        }
    }

    #[test]
    fn test_id_mis_match() {
        let secret1 = Fr::from(10);
        let secret2 = Fr::from(20);
        let ids1 = &[1, 2, 3, 4, 5, 6];
        let ids2 = &[7, 8, 9, 4, 5, 6];
        let mut rng = test_rng();
        let shares_1 =
            NonRobustShamirShare::compute_shares(secret1, 6, 5, Some(ids1), &mut rng).unwrap();
        let shares_2 =
            NonRobustShamirShare::compute_shares(secret2, 6, 5, Some(ids2), &mut rng).unwrap();

        let err = (shares_1[0].clone() + shares_2[0].clone()).unwrap_err();
        match err {
            ShareError::InsufficientShares => panic!("incorrect error type"),
            ShareError::DegreeMismatch => panic!("incorrect error type"),
            ShareError::IdMismatch => (),
            ShareError::InvalidInput => panic!("incorrect error type"),
            ShareError::TypeMismatch => panic!("incorrect error type"),
        }
    }
}
