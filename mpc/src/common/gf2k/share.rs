use ark_std::rand::Rng;
use serde::{Deserialize, Serialize};
use std::ops::{Add, Mul, Sub};

use crate::common::share::ShareError;

use super::field::{BinaryField, Gf2kDomain};
use super::poly::Poly;
use super::Gf2kError;

/// A Shamir share over a `BinaryField`: `share = f(id-th domain point)` for a degree-`degree`
/// polynomial `f` with `f(0)` equal to the shared secret.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
// The default derive would add a fresh `K: Deserialize<'de>` where-clause on the generated
// impl; since `BinaryField` already implies that (via its `DeserializeOwned` supertrait), rustc
// finds two structurally different (though equivalent) proof paths and reports an ambiguous
// E0283. Pinning the bound to `K: BinaryField` gives it a single path.
#[serde(bound = "K: BinaryField")]
pub struct GfShare<K: BinaryField> {
    pub share: K,
    /// Index of the share (x-value index into the canonical domain); can differ from the
    /// receiving party's id.
    pub id: usize,
    pub degree: usize,
}

impl<K: BinaryField> GfShare<K> {
    pub fn new(share: K, id: usize, degree: usize) -> Self {
        GfShare { share, id, degree }
    }

    /// Multiplies two shares held by the same party, producing a share of the product on a
    /// polynomial of the summed degree (the standard local-multiplication step behind Beaver
    /// triple generation).
    pub fn share_mul(&self, other: &Self) -> Result<Self, ShareError> {
        if self.id != other.id {
            return Err(ShareError::IdMismatch);
        }
        Ok(GfShare {
            share: self.share * other.share,
            id: self.id,
            degree: self.degree + other.degree,
        })
    }

    /// Generates `n` secret shares of `secret` using a random degree-`degree` polynomial with
    /// `f(0) = secret`, evaluated at the first `n` points of the canonical [`Gf2kDomain`].
    ///
    /// Evaluated via direct Horner evaluation at each point : `BinaryField` is
    /// deliberately not bound by `FftField`, and at `n <= K::MAX_DOMAIN_SIZE` (255 for GF(2^8))
    /// this is cheap.
    ///
    /// # Errors
    /// - `Gf2kError::InvalidInput` if `n` is not greater than `degree`.
    /// - `Gf2kError::NoSuitableDomain` if `n` exceeds `K::MAX_DOMAIN_SIZE`.
    pub fn compute_shares(
        secret: K,
        n: usize,
        degree: usize,
        rng: &mut impl Rng,
    ) -> Result<Vec<GfShare<K>>, Gf2kError> {
        if n <= degree {
            return Err(Gf2kError::InvalidInput(format!(
                "Number of shares ({n}) must be greater than threshold ({degree})"
            )));
        }
        let domain = Gf2kDomain::<K>::new(n)?;

        let mut coeffs = vec![K::zero(); degree + 1];
        coeffs[0] = secret;
        for c in coeffs.iter_mut().skip(1) {
            *c = K::random(rng);
        }
        let poly = Poly::from_coeffs(coeffs);

        Ok((0..n)
            .map(|i| GfShare::new(poly.evaluate(domain.element(i)), i, degree))
            .collect())
    }
}

impl<K: BinaryField> Add for GfShare<K> {
    type Output = Result<Self, ShareError>;
    fn add(self, other: Self) -> Self::Output {
        if self.degree != other.degree {
            return Err(ShareError::DegreeMismatch);
        }
        if self.id != other.id {
            return Err(ShareError::IdMismatch);
        }
        Ok(GfShare {
            share: self.share + other.share,
            id: self.id,
            degree: self.degree,
        })
    }
}

impl<K: BinaryField> Add<K> for GfShare<K> {
    type Output = Result<Self, ShareError>;
    fn add(self, other: K) -> Self::Output {
        Ok(GfShare {
            share: self.share + other,
            id: self.id,
            degree: self.degree,
        })
    }
}

impl<K: BinaryField> Sub for GfShare<K> {
    type Output = Result<Self, ShareError>;
    fn sub(self, other: Self) -> Self::Output {
        if self.degree != other.degree {
            return Err(ShareError::DegreeMismatch);
        }
        if self.id != other.id {
            return Err(ShareError::IdMismatch);
        }
        Ok(GfShare {
            share: self.share - other.share,
            id: self.id,
            degree: self.degree,
        })
    }
}

impl<K: BinaryField> Sub<K> for GfShare<K> {
    type Output = Result<Self, ShareError>;
    fn sub(self, other: K) -> Self::Output {
        Ok(GfShare {
            share: self.share - other,
            id: self.id,
            degree: self.degree,
        })
    }
}

impl<K: BinaryField> Mul<K> for GfShare<K> {
    type Output = Result<Self, ShareError>;
    fn mul(self, other: K) -> Self::Output {
        Ok(GfShare {
            share: self.share * other,
            id: self.id,
            degree: self.degree,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::field::Gf256;
    use super::*;
    use ark_std::test_rng;

    #[test]
    fn test_compute_shares_recover_secret_roundtrip() {
        let mut rng = test_rng();
        let n = 10;
        let t = 3;

        for trial in 0u8..20 {
            let secret = Gf256(trial.wrapping_mul(37).wrapping_add(1));
            let shares = GfShare::compute_shares(secret, n, t, &mut rng).unwrap();
            let (_, recovered) = GfShare::recover_secret(&shares, n, t).unwrap();
            assert_eq!(recovered, secret, "round-trip failed for secret {secret:?}");
        }
    }

    #[test]
    fn test_compute_shares_rejects_n_leq_degree() {
        let mut rng = test_rng();
        let result = GfShare::<Gf256>::compute_shares(Gf256(1), 3, 3, &mut rng);
        assert!(result.is_err());
    }

    #[test]
    fn test_share_arithmetic_id_and_degree_checks() {
        let a = GfShare::new(Gf256(3), 0, 2);
        let b = GfShare::new(Gf256(5), 0, 2);
        let sum = (a.clone() + b.clone()).unwrap();
        assert_eq!(sum.share, Gf256(3) + Gf256(5));

        let mismatched_id = GfShare::new(Gf256(5), 1, 2);
        assert!(matches!(
            a.clone() + mismatched_id,
            Err(ShareError::IdMismatch)
        ));

        let mismatched_degree = GfShare::new(Gf256(5), 0, 3);
        assert!(matches!(
            a + mismatched_degree,
            Err(ShareError::DegreeMismatch)
        ));

        let product = b.share_mul(&GfShare::new(Gf256(2), 0, 2)).unwrap();
        assert_eq!(product.degree, 4);
    }
}
