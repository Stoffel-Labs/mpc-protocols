use std::marker::PhantomData;

/// This file contains the more common secret sharing protocols used in MPC.
/// You can reuse them for the MPC protocols that you aim to implement.
///
use crate::common::{lagrange_interpolate, share::ShareError, SecretSharingScheme, ShamirShare};
use ark_ff::FftField;
use ark_poly::{
    domain,
    univariate::{DenseOrSparsePolynomial, DensePolynomial},
    DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain, Polynomial,
};
use ark_std::rand::Rng;

#[derive(Clone, Debug)]
pub struct NonRobust;
pub type NonRobustShamirShare<T> = ShamirShare<T, 1, NonRobust>;

impl<F: FftField> NonRobustShamirShare<F> {
    pub fn new(share: F, id: usize, n: usize, degree: usize) -> Self {
        ShamirShare {
            share: [share],
            id,
            n,
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
            n: 0,
            degree: 0,
            _sharetype: PhantomData,
        }
    }
}

impl<F: FftField> SecretSharingScheme<F> for NonRobustShamirShare<F> {
    type SecretType = F;
    type Error = ShareError;

    /// Generates `n` secret shares for a `value` using a degree `t` polynomial,
    /// such that `f(0) = value`. Any `t + 1` shares can reconstruct the secret.
    ///
    /// Shares are evaluations of `f(x)` on an FFT domain.
    ///
    /// # Errors
    /// - `InterpolateError::InvalidInput` if `n` is not greater than `t`.
    /// - `InterpolateError::NoSuitableDomain` if a suitable FFT evaluation domain of size `n` isn't found.
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
            GeneralEvaluationDomain::<F>::new(n).ok_or_else(|| ShareError::NoSuitableDomain)?;

        let mut poly = DensePolynomial::<F>::rand(degree, rng);
        poly[0] = secret;
        // Evaluate the polynomial over the domain
        let evals = domain.fft(&poly);

        // Create shares from evaluations
        let shares = evals[..n]
            .iter()
            .enumerate()
            .map(|(i, eval)| NonRobustShamirShare::new(*eval, i, n, degree))
            .collect();

        Ok(shares)
    }

    // recover the secret of the input shares
    fn recover_secret(
        shares: &[Self],
    ) -> Result<(Vec<Self::SecretType>, Self::SecretType), ShareError> {
        let deg = shares[0].degree;
        let n = shares[0].n;
        if !shares.iter().all(|share| share.degree == deg) {
            return Err(ShareError::DegreeMismatch);
        };
        if !shares.iter().all(|share| share.n == n) {
            return Err(ShareError::NMismatch);
        };
        if shares.len() < deg + 1 {
            return Err(ShareError::InsufficientShares);
        }
        let domain =
            GeneralEvaluationDomain::<F>::new(n).ok_or_else(|| ShareError::NoSuitableDomain)?;
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
            ShareError::NoSuitableDomain => panic!("incorrect error type"),
            ShareError::NMismatch => panic!("incorrect number of shares"),
        }
    }

    #[test]
    fn test_insufficient_shares() {
        let secret = Fr::from(918520);
        let ids = &[1, 2, 3];
        let mut rng = test_rng();
        let shares_error =
            NonRobustShamirShare::compute_shares(secret, 3, 5, Some(ids), &mut rng).unwrap_err();
        match shares_error {
            ShareError::InsufficientShares => (),
            ShareError::DegreeMismatch => panic!("incorrect error type"),
            ShareError::IdMismatch => panic!("incorrect error type"),
            ShareError::InvalidInput => (),
            ShareError::TypeMismatch => panic!("incorrect error type"),
            ShareError::NoSuitableDomain => panic!("incorrect error type"),
            ShareError::NMismatch => panic!("incorrect number of shares"),
        }
    }

    #[test]
    fn test_id_mis_match() {
        let secret1 = Fr::from(10);
        let secret2 = Fr::from(20);
        let mut ids2 = vec![7, 8, 9, 4, 5, 6];
        let mut rng = test_rng();
        let shares_1 = NonRobustShamirShare::compute_shares(secret1, 6, 5, None, &mut rng).unwrap();
        let mut shares_2 =
            NonRobustShamirShare::compute_shares(secret2, 6, 5, None, &mut rng).unwrap();
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
            ShareError::NoSuitableDomain => panic!("incorrect error type"),
            ShareError::NMismatch => panic!("incorrect number of shares"),
        }
    }
}
