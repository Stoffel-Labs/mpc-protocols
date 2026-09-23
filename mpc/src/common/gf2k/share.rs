use ark_std::rand::Rng;
use serde::{Deserialize, Serialize};
use std::ops::{Add, Mul, Sub};

use crate::common::share::ShareError;

use super::field::BinaryField;
use super::get_or_create_gf2k_domain;
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
    /// `f(0) = secret`, evaluated at the first `n` points of the canonical
    /// [`Gf2kDomain`](super::field::Gf2kDomain).
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
        let domain = get_or_create_gf2k_domain::<K>(n)?;

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

/// The **wire** encoding of a run of [`GfShare<K>`] that all carry the same evaluation index and
/// the same degree: the field elements, and nothing else.
///
/// # Why this type exists
///
/// `GfShare<K>` serialises under `bincode`'s fixint encoding to `1 + 8 + 8 = 17` bytes to carry
/// **one** byte of secret. The 16 redundant bytes are:
///
/// - **`id`** — the sender's own evaluation index. It restates the authenticated transport
///   sender, which every receiving handler already has and already checks the envelope's
///   `sender` field against. A receiver must *reject* a mismatching `id` rather than believe it,
///   so the field can never legitimately tell the receiver anything it did not already know.
/// - **`degree`** — a session-wide constant fixed by the protocol (the node's own `threshold`,
///   or `2 * threshold` for the degree-`2t` half of a double sharing). It cannot legitimately
///   vary within a message, let alone within a session.
///
/// Both fields are attacker-controlled on the wire and neither is a proof of anything: a dealer
/// writes them, nothing binds them to the share. Deleting them from the wire therefore removes
/// two forgeable inputs as well as 16 bytes per share.
///
/// # Unrepresentable, not merely smaller
///
/// This struct has no `id` and no `degree` field, so a peer has no way to state either one.
/// [`GfShareWire::encode`] refuses to build one from a batch that is not homogeneous at the
/// *sender's own* `(id, degree)`, and [`GfShareWire::decode`] stamps the **receiver-derived**
/// pair onto every element it returns. There is no code path by which a peer-supplied index or
/// degree can reach a `GfShare`.
///
/// # Wire size
///
/// `8 + m` bytes for `m` shares under `bincode` fixint (`Vec`'s `u64` length prefix plus one
/// `Gf256` byte each), against `8 + 17m` for a `Vec<GfShare<K>>`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(bound = "K: BinaryField", transparent)]
pub struct GfShareWire<K: BinaryField> {
    elements: Vec<K>,
}

impl<K: BinaryField> GfShareWire<K> {
    /// Encodes `shares` for the wire, dropping `id`/`degree`.
    ///
    /// `id` and `degree` are the **sender's own**, passed explicitly rather than read off
    /// `shares[0]`: the caller states what it believes it is sending and this rejects the batch
    /// if the shares disagree, so a bug that mixes two dealers' or two degrees' shares into one
    /// message fails here instead of being silently flattened onto the receiver's derivation.
    ///
    /// # Errors
    /// - [`ShareError::IdMismatch`] if any share's `id` differs from `id`.
    /// - [`ShareError::DegreeMismatch`] if any share's `degree` differs from `degree`.
    pub fn encode(shares: &[GfShare<K>], id: usize, degree: usize) -> Result<Self, ShareError> {
        for share in shares {
            if share.id != id {
                return Err(ShareError::IdMismatch);
            }
            if share.degree != degree {
                return Err(ShareError::DegreeMismatch);
            }
        }
        Ok(Self {
            elements: shares.iter().map(|s| s.share).collect(),
        })
    }

    /// Rebuilds `GfShare<K>`s from the wire, stamping the **receiver-derived** `id` and `degree`.
    ///
    /// `id` must be the authenticated transport sender's party id and `degree` the degree the
    /// session fixes for this opening; neither may be taken from anything the peer sent. This is
    /// infallible by construction — the values the old encoding could have disagreed with are no
    /// longer on the wire to disagree.
    pub fn decode(&self, id: usize, degree: usize) -> Vec<GfShare<K>> {
        self.elements
            .iter()
            .map(|&share| GfShare::new(share, id, degree))
            .collect()
    }

    /// Number of shares carried. Callers check this against a **locally derived** expectation.
    pub fn len(&self) -> usize {
        self.elements.len()
    }

    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    /// The raw field elements, for callers that need no `GfShare` wrapper.
    pub fn elements(&self) -> &[K] {
        &self.elements
    }

    /// Builds a body straight from field elements, for callers that never held `GfShare`s.
    ///
    /// There is nothing to validate: elements are all this encoding carries.
    pub fn from_elements(elements: Vec<K>) -> Self {
        Self { elements }
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
