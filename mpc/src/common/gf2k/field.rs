use ark_std::rand::Rng;
use num_bigint::BigUint;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt::Debug;
use std::ops::{Add, Mul, Sub};

use super::Gf2kError;

/// A finite field of characteristic 2, GF(2^k)
pub trait BinaryField:
    Copy
    + Clone
    + Debug
    + PartialEq
    + Eq
    + Send
    + Sync
    + 'static
    + Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + Serialize
    + DeserializeOwned
{
    /// `|F*|`, the size of the multiplicative group — the maximum number of distinct nonzero
    /// evaluation points, and therefore the maximum number of parties a domain over this field
    /// can support.
    const MAX_DOMAIN_SIZE: usize;

    fn zero() -> Self;
    fn one() -> Self;
    fn is_zero(&self) -> bool;

    /// A generator of the field's multiplicative group, used to build canonical domains.
    fn generator() -> Self;

    fn inverse(&self) -> Option<Self>;
    fn pow(&self, exp: u64) -> Self;
    fn random(rng: &mut impl Rng) -> Self;

    /// `x² = x` — true exactly for the two elements of the canonical GF(2) subfield embedded in
    /// this field. Used to check that a field element represents a valid single bit.
    fn is_bit(&self) -> bool {
        (*self * *self) == *self
    }
}

/// Finite field GF(2^8) with AES modulus x^8 + x^4 + x^3 + x + 1 (0x11B).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Gf256(pub u8);

impl Gf256 {
    pub const MODULUS: u16 = 0x11B;
    pub const GENERATOR: Gf256 = Gf256(0x03);

    pub fn new(value: u8) -> Self {
        Gf256(value)
    }

    pub fn is_one(&self) -> bool {
        self.0 == 1
    }

    pub fn div(self, other: Self) -> Self {
        self * other.inverse().expect("division by zero in GF(2^8)")
    }

    /// Fallible division, for use in polynomial arithmetic where a zero denominator is a data
    /// error rather than a programming error.
    pub fn checked_div(self, other: Self) -> Result<Self, Gf2kError> {
        match other.inverse() {
            Some(inv) => Ok(self * inv),
            None => Err(Gf2kError::PolynomialOperationError(
                "division by zero in GF(2^8)".to_string(),
            )),
        }
    }
}

impl BinaryField for Gf256 {
    const MAX_DOMAIN_SIZE: usize = 255;

    fn zero() -> Self {
        Gf256(0)
    }

    fn one() -> Self {
        Gf256(1)
    }

    fn is_zero(&self) -> bool {
        self.0 == 0
    }

    fn generator() -> Self {
        Self::GENERATOR
    }

    /// Multiplicative inverse using Fermat's little theorem: a^-1 = a^(2^8 - 2) = a^254.
    fn inverse(&self) -> Option<Self> {
        if self.0 == 0 {
            None
        } else {
            Some(self.pow(254))
        }
    }

    /// Exponentiation by square-and-multiply.
    fn pow(&self, mut exp: u64) -> Self {
        let mut result = Gf256::one();
        let mut base = *self;

        while exp > 0 {
            if exp & 1 == 1 {
                result = result * base;
            }
            base = base * base;
            exp >>= 1;
        }

        result
    }

    fn random(rng: &mut impl Rng) -> Self {
        Gf256(rng.gen::<u8>())
    }
}

impl From<u8> for Gf256 {
    fn from(value: u8) -> Self {
        Gf256(value)
    }
}

impl From<u16> for Gf256 {
    fn from(value: u16) -> Self {
        // Reduce to 8 bits in case input > 255
        Gf256((value & 0xFF) as u8)
    }
}

impl From<BigUint> for Gf256 {
    fn from(value: BigUint) -> Self {
        Gf256(value.to_bytes_le().first().copied().unwrap_or(0))
    }
}

impl Add for Gf256 {
    type Output = Gf256;
    /// Addition in GF(2^8) is XOR — not a typo for `|`/`&`, hence the lint suppression below.
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, other: Gf256) -> Self::Output {
        Gf256(self.0 ^ other.0)
    }
}

impl Sub for Gf256 {
    type Output = Gf256;
    /// Subtraction == addition in characteristic 2 — not a typo for a real subtraction.
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, other: Gf256) -> Gf256 {
        self + other
    }
}

impl Mul for Gf256 {
    type Output = Gf256;
    /// Multiplication in GF(2^8): carry-less polynomial multiply, reduced mod [`Gf256::MODULUS`].
    fn mul(self, other: Gf256) -> Gf256 {
        let mut result = 0u16;
        let mut a = self.0 as u16;
        let mut b = other.0 as u16;

        while b != 0 {
            if (b & 1) != 0 {
                result ^= a;
            }
            a <<= 1;
            if (a & 0x100) != 0 {
                a ^= Self::MODULUS;
            }
            b >>= 1;
        }

        Gf256(result as u8)
    }
}

/// A canonical evaluation-point domain over `K`: the first `size` powers of `K::generator()`,
/// i.e. `size` distinct nonzero field elements usable as Shamir share x-coordinates.
pub struct Gf2kDomain<K: BinaryField> {
    elements: Vec<K>,
}

impl<K: BinaryField> Gf2kDomain<K> {
    pub fn new(size: usize) -> Result<Self, Gf2kError> {
        if size > K::MAX_DOMAIN_SIZE {
            return Err(Gf2kError::NoSuitableDomain(size));
        }

        let mut elements = Vec::with_capacity(size);
        let mut x = K::one();
        for _ in 0..size {
            elements.push(x);
            x = x * K::generator();
        }
        Ok(Self { elements })
    }

    pub fn element(&self, i: usize) -> K {
        self.elements[i]
    }

    pub fn elements(&self) -> &[K] {
        &self.elements
    }

    pub fn len(&self) -> usize {
        self.elements.len()
    }

    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf256_field_axioms_exhaustive() {
        // Exhaustive over all 256 elements: additive/multiplicative identities, and that every
        // nonzero element has a correct multiplicative inverse.
        for a in 0u8..=255 {
            let a = Gf256(a);
            assert_eq!(a + Gf256::zero(), a, "additive identity failed for {a:?}");
            assert_eq!(a * Gf256::one(), a, "multiplicative identity failed for {a:?}");
            assert_eq!(a - a, Gf256::zero(), "self-subtraction failed for {a:?}");

            if a.is_zero() {
                assert!(a.inverse().is_none());
            } else {
                let inv = a.inverse().expect("nonzero element must have an inverse");
                assert_eq!(a * inv, Gf256::one(), "a * a^-1 != 1 for {a:?}");
                assert_eq!(inv * a, Gf256::one(), "a^-1 * a != 1 for {a:?}");
            }
        }
    }

    #[test]
    fn test_gf256_commutativity_associativity_distributivity_spot_check() {
        use ark_std::test_rng;
        let mut rng = test_rng();

        for _ in 0..1000 {
            let a = Gf256::random(&mut rng);
            let b = Gf256::random(&mut rng);
            let c = Gf256::random(&mut rng);

            assert_eq!(a + b, b + a, "addition not commutative");
            assert_eq!(a * b, b * a, "multiplication not commutative");
            assert_eq!((a + b) + c, a + (b + c), "addition not associative");
            assert_eq!((a * b) * c, a * (b * c), "multiplication not associative");
            assert_eq!(a * (b + c), a * b + a * c, "distributivity failed");
        }
    }

    #[test]
    fn test_gf256_is_bit() {
        // x^2 = x holds exactly for the GF(2) subfield {0, 1}.
        for a in 0u8..=255 {
            let a = Gf256(a);
            let expected = a == Gf256::zero() || a == Gf256::one();
            assert_eq!(a.is_bit(), expected, "is_bit mismatch for {a:?}");
        }
    }

    #[test]
    fn test_gf2kdomain_uniqueness_and_generator_order() {
        let domain = Gf2kDomain::<Gf256>::new(255).expect("domain of size 255 must exist");
        assert_eq!(domain.len(), 255);

        let mut seen = std::collections::HashSet::new();
        for i in 0..255 {
            let e = domain.element(i);
            assert!(!e.is_zero(), "domain element {i} was zero");
            assert!(seen.insert(e), "domain element {i} repeated: {e:?}");
        }

        // The generator must have multiplicative order exactly 255 (i.e. no earlier power == 1,
        // other than the trivial element(0) == 1).
        for i in 1..255 {
            assert_ne!(
                domain.element(i),
                Gf256::one(),
                "generator order divides {i}, expected exactly 255"
            );
        }
        assert_eq!(
            domain.element(0).pow(255),
            Gf256::one(),
            "generator^255 must be 1"
        );
    }

    #[test]
    fn test_gf2kdomain_rejects_oversized() {
        let result = Gf2kDomain::<Gf256>::new(256);
        assert!(result.is_err(), "domain of size 256 must be rejected");
    }
}
