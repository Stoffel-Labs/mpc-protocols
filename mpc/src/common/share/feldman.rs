use crate::common::{
    lagrange_interpolate,
    share::{shamir::Shamirshare, ShareError},
    SecretSharingScheme,
};
use ark_ec::CurveGroup;
use ark_ff::FftField;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use std::ops::{Mul, Sub};
use std::{collections::HashSet, ops::Add};

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct FeldmanShamirShare<F: FftField, G: CurveGroup<ScalarField = F>> {
    pub feldmanshare: Shamirshare<F>,
    pub commitments: Vec<G>,
}

impl<F: FftField, G: CurveGroup<ScalarField = F>> FeldmanShamirShare<F, G> {
    pub fn new(
        share: F,
        id: usize,
        degree: usize,
        commitments: Vec<G>,
    ) -> Result<Self, ShareError> {
        let shamirshare = Shamirshare::new(share, id, degree);
        if commitments.len() != degree + 1 {
            return Err(ShareError::InvalidInput);
        }
        Ok(FeldmanShamirShare {
            feldmanshare: shamirshare,
            commitments,
        })
    }

    /// Shares independent secrets and computes all commitments using one
    /// fixed-base batch multiplication. Output is secret-major.
    pub fn compute_shares_batch<R: Rng>(
        secrets: &[F],
        n: usize,
        degree: usize,
        ids: Option<&[usize]>,
        rng: &mut R,
    ) -> Result<Vec<Vec<Self>>, ShareError> {
        let id_list = ids.ok_or(ShareError::InvalidInput)?;
        if id_list.len() != n || id_list.len() < degree + 1 {
            return Err(ShareError::InsufficientShares);
        }
        if id_list.iter().any(|&id| F::from(id as u64) == F::ZERO) {
            return Err(ShareError::InvalidInput);
        }
        let mut seen = HashSet::new();
        if !id_list.iter().all(|id| seen.insert(id)) {
            return Err(ShareError::InvalidInput);
        }
        if secrets.is_empty() {
            return Ok(Vec::new());
        }

        let mut polynomials = Vec::with_capacity(secrets.len());
        let mut coefficients = Vec::with_capacity(secrets.len() * (degree + 1));
        for secret in secrets {
            let mut polynomial = DensePolynomial::rand(degree, rng);
            polynomial[0] = *secret;
            coefficients.extend_from_slice(&polynomial.coeffs);
            polynomials.push(polynomial);
        }

        let commitment_bases = G::generator().batch_mul(&coefficients);
        let commitments: Vec<Vec<G>> = commitment_bases
            .chunks(degree + 1)
            .map(|chunk| chunk.iter().copied().map(Into::into).collect())
            .collect();

        polynomials
            .iter()
            .zip(commitments)
            .map(|(polynomial, commitments)| {
                id_list
                    .iter()
                    .map(|id| {
                        let value = polynomial.evaluate(&F::from(*id as u64));
                        Self::new(value, *id, degree, commitments.clone())
                    })
                    .collect()
            })
            .collect()
    }
}

impl<F, G> Add for FeldmanShamirShare<F, G>
where
    F: FftField,
    G: CurveGroup<ScalarField = F>,
{
    type Output = Result<Self, ShareError>;

    fn add(self, rhs: Self) -> Self::Output {
        if self.feldmanshare.degree != rhs.feldmanshare.degree {
            return Err(ShareError::DegreeMismatch);
        }

        let share = (self.feldmanshare + rhs.feldmanshare)?;

        let commitments = self
            .commitments
            .iter()
            .zip(rhs.commitments.iter())
            .map(|(a, b)| *a + *b)
            .collect();

        Ok(FeldmanShamirShare {
            feldmanshare: share,
            commitments,
        })
    }
}

impl<F, G> Sub for FeldmanShamirShare<F, G>
where
    F: FftField,
    G: CurveGroup<ScalarField = F>,
{
    type Output = Result<Self, ShareError>;

    fn sub(self, rhs: Self) -> Self::Output {
        if self.feldmanshare.degree != rhs.feldmanshare.degree {
            return Err(ShareError::DegreeMismatch);
        }

        let share = (self.feldmanshare - rhs.feldmanshare)?;

        let commitments = self
            .commitments
            .iter()
            .zip(rhs.commitments.iter())
            .map(|(a, b)| *a - *b)
            .collect();

        Ok(FeldmanShamirShare {
            feldmanshare: share,
            commitments,
        })
    }
}

impl<F, G> Add<F> for FeldmanShamirShare<F, G>
where
    F: FftField,
    G: CurveGroup<ScalarField = F>,
{
    type Output = Result<Self, ShareError>;

    fn add(mut self, scalar: F) -> Self::Output {
        let share = (self.feldmanshare + scalar)?;

        // Only constant-term commitment changes
        if let Some(c0) = self.commitments.get_mut(0) {
            *c0 += G::generator() * scalar;
        }

        Ok(FeldmanShamirShare {
            feldmanshare: share,
            commitments: self.commitments,
        })
    }
}

impl<F, G> Sub<F> for FeldmanShamirShare<F, G>
where
    F: FftField,
    G: CurveGroup<ScalarField = F>,
{
    type Output = Result<Self, ShareError>;

    fn sub(mut self, scalar: F) -> Self::Output {
        let share = (self.feldmanshare - scalar)?;

        if let Some(c0) = self.commitments.get_mut(0) {
            *c0 -= G::generator() * scalar;
        }

        Ok(FeldmanShamirShare {
            feldmanshare: share,
            commitments: self.commitments,
        })
    }
}

impl<F, G> Mul<F> for FeldmanShamirShare<F, G>
where
    F: FftField,
    G: CurveGroup<ScalarField = F>,
{
    type Output = Result<Self, ShareError>;

    fn mul(self, scalar: F) -> Self::Output {
        let share = (self.feldmanshare * scalar)?;

        let commitments = self.commitments.iter().map(|c| c.mul(scalar)).collect();

        Ok(FeldmanShamirShare {
            feldmanshare: share,
            commitments,
        })
    }
}
impl<F, G> SecretSharingScheme<F> for FeldmanShamirShare<F, G>
where
    F: FftField,
    G: CurveGroup<ScalarField = F>,
{
    type SecretType = F;

    type Error = ShareError;

    fn compute_shares(
        secret: Self::SecretType,
        n: usize,
        degree: usize,
        ids: Option<&[usize]>,
        rng: &mut impl Rng,
    ) -> Result<Vec<Self>, Self::Error> {
        Self::compute_shares_batch(&[secret], n, degree, ids, rng)?
            .pop()
            .ok_or(ShareError::InvalidInput)
    }

    fn recover_secret(
        shares: &[Self],
        _n: usize,
        _t: usize,
    ) -> Result<(Vec<Self::SecretType>, Self::SecretType), Self::Error> {
        if shares.is_empty() {
            return Err(ShareError::InvalidInput);
        }
        let mut seen = HashSet::new();
        if !shares.iter().all(|s| seen.insert(s.feldmanshare.id)) {
            return Err(ShareError::InvalidInput);
        }
        let deg = shares[0].feldmanshare.degree;
        if !shares.iter().all(|share| share.feldmanshare.degree == deg) {
            return Err(ShareError::DegreeMismatch);
        };
        if shares.len() < deg + 1 {
            return Err(ShareError::InsufficientShares);
        }
        if shares
            .iter()
            .any(|share| F::from(share.feldmanshare.id as u64) == F::ZERO)
        {
            return Err(ShareError::InvalidInput);
        }
        let (x_vals, y_vals): (Vec<F>, Vec<F>) = shares
            .iter()
            .map(|share| {
                (
                    F::from(share.feldmanshare.id as u64),
                    share.feldmanshare.share[0],
                )
            })
            .unzip();

        let result_poly = lagrange_interpolate(&x_vals, &y_vals)?;
        if result_poly.degree() > deg {
            return Err(ShareError::DegreeMismatch);
        }
        Ok((result_poly.coeffs.clone(), result_poly[0]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Fr, G1Projective};
    use ark_ec::PrimeGroup;
    use ark_ff::{One, UniformRand, Zero};
    use ark_std::test_rng;

    type F = Fr;
    type G = G1Projective;

    fn verify_feldman_share(share: &FeldmanShamirShare<F, G>) -> bool {
        // Check: f(id) * G == sum_j commitments[j] * id^j
        let x = F::from(share.feldmanshare.id as u64);

        let lhs = G::generator().mul(share.feldmanshare.share[0]);

        let mut rhs = G::zero();
        let mut pow = F::one();
        for c in &share.commitments {
            rhs += c.mul(pow);
            pow *= x;
        }

        lhs == rhs
    }

    fn sample_ids(n: usize) -> Vec<usize> {
        (1..=n).collect()
    }

    #[test]
    fn test_feldman_share_generation_and_verification() {
        let mut rng = test_rng();
        let secret = F::rand(&mut rng);
        let degree = 3;
        let ids = sample_ids(6);

        let shares = FeldmanShamirShare::<F, G>::compute_shares(
            secret,
            ids.len(),
            degree,
            Some(&ids),
            &mut rng,
        )
        .unwrap();

        for s in &shares {
            assert!(verify_feldman_share(s));
        }
    }

    #[test]
    fn test_batched_generation_verifies_each_share() {
        let mut rng = test_rng();
        let ids = sample_ids(4);
        let secrets: Vec<F> = (0..129).map(|_| F::rand(&mut rng)).collect();

        let shares = FeldmanShamirShare::<F, G>::compute_shares_batch(
            &secrets,
            ids.len(),
            1,
            Some(&ids),
            &mut rng,
        )
        .unwrap();

        assert_eq!(shares.len(), secrets.len());
        for party_index in 0..ids.len() {
            let recipient_batch: Vec<_> = shares
                .iter()
                .map(|secret_shares| secret_shares[party_index].clone())
                .collect();
            assert!(recipient_batch.iter().all(verify_feldman_share));
        }
    }

    #[test]
    fn test_batched_verification_rejects_corruption() {
        let mut rng = test_rng();
        let ids = sample_ids(4);
        let secrets: Vec<F> = (0..16).map(|_| F::rand(&mut rng)).collect();
        let shares = FeldmanShamirShare::<F, G>::compute_shares_batch(
            &secrets,
            ids.len(),
            1,
            Some(&ids),
            &mut rng,
        )
        .unwrap();
        let mut recipient_batch: Vec<_> = shares
            .iter()
            .map(|secret_shares| secret_shares[0].clone())
            .collect();

        recipient_batch[7].feldmanshare.share[0] += F::one();
        assert!(!recipient_batch.iter().all(verify_feldman_share));

        recipient_batch = shares
            .iter()
            .map(|secret_shares| secret_shares[0].clone())
            .collect();
        recipient_batch[5].commitments[0] += G::generator();
        assert!(!recipient_batch.iter().all(verify_feldman_share));
    }

    #[test]
    fn test_feldman_recover_secret() {
        let mut rng = test_rng();
        let secret = F::rand(&mut rng);
        let degree = 2;
        let ids = sample_ids(5);

        let shares = FeldmanShamirShare::<F, G>::compute_shares(
            secret,
            ids.len(),
            degree,
            Some(&ids),
            &mut rng,
        )
        .unwrap();

        let (coeffs, recovered) =
            FeldmanShamirShare::<F, G>::recover_secret(&shares[..degree + 1], ids.len(), 2)
                .unwrap();

        assert_eq!(recovered, secret);
        assert_eq!(coeffs[0], secret);
    }

    #[test]
    fn test_feldman_addition() {
        let mut rng = test_rng();
        let ids = sample_ids(6);
        let degree = 2;

        let s1 = F::rand(&mut rng);
        let s2 = F::rand(&mut rng);

        let a =
            FeldmanShamirShare::<F, G>::compute_shares(s1, ids.len(), degree, Some(&ids), &mut rng)
                .unwrap();
        let b =
            FeldmanShamirShare::<F, G>::compute_shares(s2, ids.len(), degree, Some(&ids), &mut rng)
                .unwrap();

        let sum: Vec<_> = a
            .into_iter()
            .zip(b.into_iter())
            .map(|(x, y)| (x + y).unwrap())
            .collect();

        for s in &sum {
            assert!(verify_feldman_share(s));
        }

        let (_, recovered) =
            FeldmanShamirShare::<F, G>::recover_secret(&sum[..degree + 1], ids.len(), 2).unwrap();
        assert_eq!(recovered, s1 + s2);
    }

    #[test]
    fn test_feldman_subtraction() {
        let mut rng = test_rng();
        let ids = sample_ids(6);
        let degree = 2;

        let s1 = F::rand(&mut rng);
        let s2 = F::rand(&mut rng);

        let a =
            FeldmanShamirShare::<F, G>::compute_shares(s1, ids.len(), degree, Some(&ids), &mut rng)
                .unwrap();
        let b =
            FeldmanShamirShare::<F, G>::compute_shares(s2, ids.len(), degree, Some(&ids), &mut rng)
                .unwrap();

        let diff: Vec<_> = a
            .into_iter()
            .zip(b.into_iter())
            .map(|(x, y)| (x - y).unwrap())
            .collect();

        for s in &diff {
            assert!(verify_feldman_share(s));
        }

        let (_, recovered) =
            FeldmanShamirShare::<F, G>::recover_secret(&diff[..degree + 1], ids.len(), 2).unwrap();
        assert_eq!(recovered, s1 - s2);
    }

    #[test]
    fn test_feldman_scalar_multiplication() {
        let mut rng = test_rng();
        let ids = sample_ids(6);
        let degree = 2;

        let secret = F::rand(&mut rng);
        let scalar = F::rand(&mut rng);

        let shares = FeldmanShamirShare::<F, G>::compute_shares(
            secret,
            ids.len(),
            degree,
            Some(&ids),
            &mut rng,
        )
        .unwrap();

        let scaled: Vec<_> = shares.into_iter().map(|s| (s * scalar).unwrap()).collect();

        for s in &scaled {
            assert!(verify_feldman_share(s));
        }

        let (_, recovered) =
            FeldmanShamirShare::<F, G>::recover_secret(&scaled[..degree + 1], ids.len(), 2)
                .unwrap();
        assert_eq!(recovered, secret * scalar);
    }

    #[test]
    fn test_add_constant() {
        let mut rng = test_rng();
        let ids = sample_ids(6);
        let degree = 2;

        let secret = F::rand(&mut rng);
        let constant = F::rand(&mut rng);

        let shares = FeldmanShamirShare::<F, G>::compute_shares(
            secret,
            ids.len(),
            degree,
            Some(&ids),
            &mut rng,
        )
        .unwrap();

        let shifted: Vec<_> = shares
            .into_iter()
            .map(|s| (s + constant).unwrap())
            .collect();

        for s in &shifted {
            assert!(verify_feldman_share(s));
        }

        let (_, recovered) =
            FeldmanShamirShare::<F, G>::recover_secret(&shifted[..degree + 1], ids.len(), 2)
                .unwrap();
        assert_eq!(recovered, secret + constant);
    }
}
