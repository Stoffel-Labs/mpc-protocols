/// This file contains the more common secret sharing protocols used in MPC.
/// You can reuse them for the MPC protocols that you aim to implement.
///
use crate::common::{lagrange_interpolate, share::ShareError, SecretSharingScheme, ShamirShare};
use ark_ff::FftField;
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain,
    Polynomial,
};
use ark_std::rand::Rng;
use std::{collections::HashSet, marker::PhantomData};


#[derive(Clone, Debug)]
pub struct Shamir;
pub type Shamirshare<T> = ShamirShare<T, 1, Shamir>;

impl<F: FftField> Shamirshare<F> {
    pub fn new(share: F, id: usize, degree: usize) -> Self {
        ShamirShare {
            share: [share],
            id,
            degree,
            _sharetype: PhantomData,
        }
    }
}

impl<F: FftField> Default for Shamirshare<F> {
    fn default() -> Self {
        Self {
            share: [F::ZERO],
            id: 0,
            degree: 0,
            _sharetype: PhantomData,
        }
    }
}

impl<F: FftField> SecretSharingScheme<F> for Shamirshare<F> {
    type SecretType = F;
    type Error = ShareError;

    // compute the shamir shares of all ids for a secret
    fn compute_shares(
        secret: Self::SecretType,
        _n: usize,
        degree: usize,
        ids: Option<&[usize]>,
        rng: &mut impl Rng,
    ) -> Result<Vec<Self>, ShareError> {
        let id_list = match ids {
            Some(ids) => ids,
            None => return Err(ShareError::InvalidInput),
        };

        // Enough IDs to construct a degree-d polynomial
        if id_list.len() < degree + 1 {
            return Err(ShareError::InsufficientShares);
        }

        // All IDs are non-zero (optional, depending on your protocol)
        if id_list.iter().any(|&id| id == 0) {
            return Err(ShareError::InvalidInput);
        }

        // All IDs are unique
        let mut seen = HashSet::new();
        if !id_list.iter().all(|id| seen.insert(id)) {
            return Err(ShareError::InvalidInput);
        }

        // Generate the random polynomial of degree `degree` with `secret` as constant term
        let mut poly = DensePolynomial::rand(degree, rng);
        poly[0] = secret;

        // Evaluate the polynomial at each `id`
        let shares = id_list
            .iter()
            .map(|id| {
                let x = F::from(*id as u64);
                let y = poly.evaluate(&x);
                Shamirshare::new(y, *id, degree)
            })
            .collect();

        Ok(shares)
    }

    // recover the secret of the input shares
    fn recover_secret(
        shares: &[Self],
        _n: usize,
    ) -> Result<(Vec<Self::SecretType>, Self::SecretType), ShareError> {
        if shares.is_empty() {
            return Err(ShareError::InvalidInput);
        }
        let mut seen = HashSet::new();
        if !shares.iter().all(|s| seen.insert(s.id)) {
            return Err(ShareError::InvalidInput);
        }
        let deg = shares[0].degree;
        if !shares.iter().all(|share| share.degree == deg) {
            return Err(ShareError::DegreeMismatch);
        };
        if shares.len() < deg + 1 {
            return Err(ShareError::InsufficientShares);
        }
        if shares.iter().any(|share| share.id == 0) {
            return Err(ShareError::InvalidInput);
        }
        let (x_vals, y_vals): (Vec<F>, Vec<F>) = shares
            .iter()
            .map(|share| (F::from(share.id as u64), share.share[0]))
            .unzip();

        let result_poly = lagrange_interpolate(&x_vals, &y_vals)?;
        Ok((result_poly.coeffs.clone(), result_poly[0]))
    }
}
#[derive(Clone, Debug)]
pub struct NonRobust;
pub type NonRobustShare<T> = ShamirShare<T, 1, NonRobust>;

impl<F: FftField> NonRobustShare<F> {
    pub fn new(share: F, id: usize, degree: usize) -> Self {
        ShamirShare {
            share: [share],
            id,
            degree,
            _sharetype: PhantomData,
        }
    }
}

impl<F: FftField> Default for NonRobustShare<F> {
    fn default() -> Self {
        Self {
            share: [F::ZERO],
            id: 0,
            degree: 0,
            _sharetype: PhantomData,
        }
    }
}

impl<F: FftField> SecretSharingScheme<F> for NonRobustShare<F> {
    type SecretType = F;
    type Error = ShareError;

    // compute the shamir shares of all ids for a secret
    fn compute_shares(
        secret: Self::SecretType,
        n: usize,
        degree: usize,
        _ids: Option<&[usize]>,
        rng: &mut impl Rng,
    ) -> Result<Vec<Self>, ShareError> {
        if n <= degree {
            return Err(ShareError::InvalidInput);
        }
        let domain =
            GeneralEvaluationDomain::<F>::new(n).ok_or_else(|| ShareError::NoSuitableDomain(n))?;

        let mut poly = DensePolynomial::<F>::rand(degree, rng);
        poly[0] = secret;
        // Evaluate the polynomial over the domain
        let evals = domain.fft(&poly);

        // Create shares from evaluations
        let shares: Vec<NonRobustShare<F>> = evals
            .iter()
            .take(n)
            .enumerate()
            .map(|(i, &eval)| NonRobustShare::new(eval, i, degree))
            .collect();

        Ok(shares)
    }

    // recover the secret of the input shares
    fn recover_secret(
        shares: &[Self],
        n: usize,
    ) -> Result<(Vec<Self::SecretType>, Self::SecretType), ShareError> {
        if shares.is_empty() {
            return Err(ShareError::InvalidInput);
        }
        let mut seen = HashSet::new();
        if !shares.iter().all(|s| seen.insert(s.id)) {
            return Err(ShareError::InvalidInput);
        }
        let deg = shares[0].degree;
        if !shares.iter().all(|share| share.degree == deg) {
            return Err(ShareError::DegreeMismatch);
        };
        if shares.len() < deg + 1 {
            return Err(ShareError::InsufficientShares);
        }

        let domain =
            GeneralEvaluationDomain::<F>::new(n).ok_or_else(|| ShareError::NoSuitableDomain(n))?;
        let (x_vals, y_vals): (Vec<F>, Vec<F>) = shares
            .iter()
            .map(|share| (domain.element(share.id), share.share[0]))
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
        let shares = NonRobustShare::compute_shares(secret, 6, 5, Some(ids), &mut rng).unwrap();
        let (_, recovered_secret) = NonRobustShare::recover_secret(&shares, 6).unwrap();
        assert!(recovered_secret == secret);
    }

    #[test]
    fn should_add_shares() {
        let secret1 = Fr::from(10);
        let secret2 = Fr::from(20);
        let ids = &[1, 2, 3, 4, 5, 6];
        let mut rng = test_rng();
        let shares_1 = NonRobustShare::compute_shares(secret1, 6, 5, Some(ids), &mut rng).unwrap();
        let shares_2 = NonRobustShare::compute_shares(secret2, 6, 5, Some(ids), &mut rng).unwrap();

        let added_shares: Vec<_> = zip(shares_1, shares_2)
            .map(|(a, b)| a + b)
            .collect::<Result<_, _>>() // Handles errors cleanly
            .unwrap();
        let (_, recovered_secret) = NonRobustShare::recover_secret(&added_shares, 6).unwrap();
        assert!(recovered_secret == secret1 + secret2);
    }

    #[test]
    fn should_multiply_scalar() {
        let secret = Fr::from(55);
        let ids = &[1, 2, 3, 4, 5, 6, 7, 20];
        let mut rng = test_rng();
        let shares = NonRobustShare::compute_shares(secret, 8, 5, Some(ids), &mut rng).unwrap();
        let tripled_shares = shares
            .iter()
            .map(|share| share.clone() * Fr::from(3))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let (_, recovered_secret) = NonRobustShare::recover_secret(&tripled_shares, 8).unwrap();
        assert!(recovered_secret == secret * Fr::from(3));
    }

    #[test]
    fn test_degree_mismatch() {
        let secret = Fr::from(918520);
        let ids = &[1, 2, 3, 4, 5, 6];
        let mut rng = test_rng();
        let mut shares = NonRobustShare::compute_shares(secret, 6, 5, Some(ids), &mut rng).unwrap();

        shares[2].degree = 4;
        let recovered_secret = NonRobustShare::recover_secret(&shares, 6).unwrap_err();
        match recovered_secret {
            ShareError::InsufficientShares => panic!("incorrect error type"),
            ShareError::DegreeMismatch => (),
            ShareError::IdMismatch => panic!("incorrect error type"),
            ShareError::InvalidInput => panic!("incorrect error type"),
            ShareError::TypeMismatch => panic!("incorrect error type"),
            ShareError::NoSuitableDomain(_) => panic!("incorrect error type"),
        }
    }

    #[test]
    fn test_insufficient_shares() {
        let secret = Fr::from(918520);
        let ids = &[1, 2, 3];
        let mut rng = test_rng();
        let shares = NonRobustShare::compute_shares(secret, 3, 2, Some(ids), &mut rng).unwrap();
        let recovered_secret = NonRobustShare::recover_secret(&shares[1..], 3).unwrap_err();
        match recovered_secret {
            ShareError::InsufficientShares => (),
            ShareError::DegreeMismatch => panic!("incorrect error type"),
            ShareError::IdMismatch => panic!("incorrect error type"),
            ShareError::InvalidInput => panic!("incorrect error type"),
            ShareError::TypeMismatch => panic!("incorrect error type"),
            ShareError::NoSuitableDomain(_) => panic!("incorrect error type"),
        }
    }

    #[test]
    fn test_id_mis_match() {
        let secret1 = Fr::from(10);
        let secret2 = Fr::from(20);
        let mut ids2 = vec![7, 8, 9, 4, 5, 6];
        let mut rng = test_rng();
        let shares_1 = NonRobustShare::compute_shares(secret1, 6, 5, None, &mut rng).unwrap();
        let mut shares_2 = NonRobustShare::compute_shares(secret2, 6, 5, None, &mut rng).unwrap();
        shares_2
            .iter_mut()
            .for_each(|share| share.id = ids2.pop().unwrap());
        let err = (shares_1[0].clone() + shares_2[0].clone()).unwrap_err();
        match err {
            ShareError::InsufficientShares => panic!("incorrect error type"),
            ShareError::DegreeMismatch => panic!("incorrect error type"),
            ShareError::IdMismatch => (),
            ShareError::InvalidInput => panic!("incorrect error type"),
            ShareError::TypeMismatch => panic!("incorrect error type"),
            ShareError::NoSuitableDomain(_) => panic!("incorrect error type"),
        }
    }
    #[test]
    fn shamir_should_recover_secret() {
        let secret = Fr::from(918520);
        let ids = &[1, 2, 3, 4, 5, 6];
        let mut rng = test_rng();
        let shares = Shamirshare::compute_shares(secret, 6, 5, Some(ids), &mut rng).unwrap();
        let (_, recovered_secret) = Shamirshare::recover_secret(&shares, 6).unwrap();
        assert!(recovered_secret == secret);
    }

    #[test]
    fn shamir_should_add_shares() {
        let secret1 = Fr::from(10);
        let secret2 = Fr::from(20);
        let ids = &[1, 2, 3, 4, 5, 6];
        let mut rng = test_rng();
        let shares_1 = Shamirshare::compute_shares(secret1, 6, 5, Some(ids), &mut rng).unwrap();
        let shares_2 = Shamirshare::compute_shares(secret2, 6, 5, Some(ids), &mut rng).unwrap();

        let added_shares: Vec<_> = zip(shares_1, shares_2)
            .map(|(a, b)| a + b)
            .collect::<Result<_, _>>() // Handles errors cleanly
            .unwrap();
        let (_, recovered_secret) = Shamirshare::recover_secret(&added_shares, 6).unwrap();
        assert!(recovered_secret == secret1 + secret2);
    }

    #[test]
    fn shamir_should_multiply_scalar() {
        let secret = Fr::from(55);
        let ids = &[1, 2, 3, 4, 5, 6, 7, 20];
        let mut rng = test_rng();
        let shares = Shamirshare::compute_shares(secret, 8, 5, Some(ids), &mut rng).unwrap();
        let tripled_shares = shares
            .iter()
            .map(|share| share.clone() * Fr::from(3))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let (_, recovered_secret) = Shamirshare::recover_secret(&tripled_shares, 8).unwrap();
        assert!(recovered_secret == secret * Fr::from(3));
    }

    #[test]
    fn shamir_test_degree_mismatch() {
        let secret = Fr::from(918520);
        let ids = &[1, 2, 3, 4, 5, 6];
        let mut rng = test_rng();
        let mut shares = Shamirshare::compute_shares(secret, 6, 5, Some(ids), &mut rng).unwrap();

        shares[2].degree = 4;
        let recovered_secret = Shamirshare::recover_secret(&shares, 6).unwrap_err();
        match recovered_secret {
            ShareError::InsufficientShares => panic!("incorrect error type"),
            ShareError::DegreeMismatch => (),
            ShareError::IdMismatch => panic!("incorrect error type"),
            ShareError::InvalidInput => panic!("incorrect error type"),
            ShareError::TypeMismatch => panic!("incorrect error type"),
            ShareError::NoSuitableDomain(_) => panic!("incorrect error type"),
        }
    }

    #[test]
    fn shamir_test_insufficient_shares() {
        let secret = Fr::from(918520);
        let ids = &[1, 2, 3];
        let mut rng = test_rng();
        let shares = Shamirshare::compute_shares(secret, 3, 2, Some(ids), &mut rng).unwrap();
        let recovered_secret = Shamirshare::recover_secret(&shares[1..], 3).unwrap_err();
        match recovered_secret {
            ShareError::InsufficientShares => (),
            ShareError::DegreeMismatch => panic!("incorrect error type"),
            ShareError::IdMismatch => panic!("incorrect error type"),
            ShareError::InvalidInput => panic!("incorrect error type"),
            ShareError::TypeMismatch => panic!("incorrect error type"),
            ShareError::NoSuitableDomain(_) => panic!("incorrect error type"),
        }
    }

    #[test]
    fn shamir_test_id_mis_match() {
        let secret1 = Fr::from(10);
        let secret2 = Fr::from(20);
        let mut ids2 = vec![7, 8, 9, 4, 5, 6];
        let mut rng = test_rng();
        let shares_1 = Shamirshare::compute_shares(secret1, 6, 5, Some(&[1, 2, 3, 4, 5, 6]), &mut rng).unwrap();
        let mut shares_2 = Shamirshare::compute_shares(secret2, 6, 5, Some(&[1, 2, 3, 4, 5, 6]), &mut rng).unwrap();
        shares_2
            .iter_mut()
            .for_each(|share| share.id = ids2.pop().unwrap());
        let err = (shares_1[0].clone() + shares_2[0].clone()).unwrap_err();
        match err {
            ShareError::InsufficientShares => panic!("incorrect error type"),
            ShareError::DegreeMismatch => panic!("incorrect error type"),
            ShareError::IdMismatch => (),
            ShareError::InvalidInput => panic!("incorrect error type"),
            ShareError::TypeMismatch => panic!("incorrect error type"),
            ShareError::NoSuitableDomain(_) => panic!("incorrect error type"),
        }
    }
}
