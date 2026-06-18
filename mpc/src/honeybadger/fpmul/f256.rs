use num_bigint::BigUint;
use std::{
    collections::HashMap,
    ops::{Add, Mul, Sub},
};
use thiserror::Error;

/// Error type for GF(2^8) field and domain operations.
#[derive(Error, Debug)]
pub enum Gf256Error {
    /// Division or inversion by zero.
    #[error("Division by zero in GF(2^8)")]
    DivisionByZero,

    /// Element has no multiplicative inverse (should only occur for 0).
    #[error("Element {0:?} has no multiplicative inverse")]
    NotInvertible(Gf256),

    /// Invalid domain size (must be ≤ 255).
    #[error("Invalid domain size for GF(2^8): n = {0}")]
    InvalidDomainSize(usize),

    /// Internal polynomial operation error or custom failure.
    #[error("Polynomial operation failed: {0}")]
    PolynomialOperationError(String),
}

/// Finite field GF(2^8) with AES modulus x^8 + x^4 + x^3 + x + 1 (0x11B)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gf256(pub u8);

impl Gf256 {
    pub const MODULUS: u16 = 0x11B;
    pub const GENERATOR: Gf256 = Gf256(0x03);

    pub fn generator() -> Self {
        Self::GENERATOR
    }

    pub fn new(value: u8) -> Self {
        Gf256(value)
    }

    pub fn zero() -> Self {
        Gf256(0)
    }

    pub fn one() -> Self {
        Gf256(1)
    }

    /// Addition in GF(2^8) is XOR
    pub fn add(self, other: Gf256) -> Gf256 {
        Gf256(self.0 ^ other.0)
    }

    /// Multiplication in GF(2^8) with reduction by MODULUS
    pub fn mul(self, other: Gf256) -> Gf256 {
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

    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }

    pub fn is_one(&self) -> bool {
        self.0 == 1
    }

    /// Multiplicative inverse using Fermat’s little theorem:
    /// a^-1 = a^(2^8 - 2) = a^254
    pub fn inverse(self) -> Option<Gf256> {
        if self.0 == 0 {
            None
        } else {
            Some(self.pow(254))
        }
    }

    /// Exponentiation by square-and-multiply
    pub fn pow(self, mut exp: u64) -> Gf256 {
        let mut result = Gf256::one();
        let mut base = self;

        while exp > 0 {
            if exp & 1 == 1 {
                result = result.mul(base);
            }
            base = base.mul(base);
            exp >>= 1;
        }

        result
    }

    pub fn div(self, other: Self) -> Self {
        self.mul(other.inverse().expect("division by zero in GF(2^8)"))
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
    fn add(self, other: Gf256) -> Self::Output {
        self.add(other)
    }
}

impl Mul for Gf256 {
    type Output = Gf256;
    fn mul(self, other: Gf256) -> Gf256 {
        self.mul(other)
    }
}

impl Sub for Gf256 {
    type Output = Gf256;
    fn sub(self, other: Gf256) -> Gf256 {
        self.add(other) // subtraction = addition in characteristic 2
    }
}

//---------------------------------POLYNOMIAL---------------------------------

#[derive(Clone, Debug)]
pub struct Poly {
    pub coeffs: Vec<Gf256>, // coeffs[0] + coeffs[1] x + coeffs[2] x^2 + ...
}

impl Poly {
    pub fn zero() -> Self {
        Poly {
            coeffs: vec![Gf256::zero()],
        }
    }

    pub fn from_coeffs(c: Vec<Gf256>) -> Self {
        Poly { coeffs: c }
    }

    pub fn evaluate(&self, x: Gf256) -> Gf256 {
        let mut acc = Gf256::zero();
        let mut pow = Gf256::one();
        for &c in &self.coeffs {
            acc = acc.add(c.mul(pow));
            pow = pow.mul(x);
        }
        acc
    }
}

fn poly_add(a: &Poly, b: &Poly) -> Poly {
    let n = a.coeffs.len().max(b.coeffs.len());
    let mut coeffs = vec![Gf256::zero(); n];
    for i in 0..a.coeffs.len() {
        coeffs[i] = coeffs[i].add(a.coeffs[i]);
    }
    for i in 0..b.coeffs.len() {
        coeffs[i] = coeffs[i].add(b.coeffs[i]);
    }
    Poly::from_coeffs(coeffs)
}

fn poly_mul(a: &Poly, b: &Poly) -> Poly {
    let mut coeffs = vec![Gf256::zero(); a.coeffs.len() + b.coeffs.len() - 1];
    for i in 0..a.coeffs.len() {
        for j in 0..b.coeffs.len() {
            coeffs[i + j] = coeffs[i + j].add(a.coeffs[i].mul(b.coeffs[j]));
        }
    }
    Poly::from_coeffs(coeffs)
}

fn poly_scale(a: &Poly, k: Gf256) -> Poly {
    Poly::from_coeffs(a.coeffs.iter().map(|&c| c.mul(k)).collect())
}

pub fn lagrange_interpolate_f2_8(x_vals: &[Gf256], y_vals: &[Gf256]) -> Poly {
    assert_eq!(x_vals.len(), y_vals.len());
    let n = x_vals.len();
    let mut result = Poly::zero();

    for j in 0..n {
        // numerator polynomial
        let mut num = Poly::from_coeffs(vec![Gf256::one()]);
        let mut denom = Gf256::one();

        for m in 0..n {
            if m != j {
                // (x - x_m)
                num = poly_mul(&num, &Poly::from_coeffs(vec![x_vals[m], Gf256::one()]));
                denom = denom.mul(x_vals[j].sub(x_vals[m]));
            }
        }

        let scale = y_vals[j].div(denom);
        num = poly_scale(&num, scale);
        result = poly_add(&result, &num);
    }

    result
}
pub fn build_all_f_polys_2_8(
    n: usize,
    tsets: Vec<Vec<usize>>,
) -> Result<HashMap<Vec<usize>, Poly>, Gf256Error> {
    let domain_2 = Gf256Domain::new(n)?;
    Ok(tsets
        .into_iter()
        .map(|tset| {
            // Construct interpolation points
            let xs = std::iter::once(Gf256::zero())
                .chain(tset.iter().map(|&j| domain_2.element(j)))
                .collect::<Vec<_>>();
            let ys = std::iter::once(Gf256::one())
                .chain(std::iter::repeat(Gf256::zero()).take(tset.len()))
                .collect::<Vec<_>>();
            // Interpolate polynomial
            let poly = lagrange_interpolate_f2_8(&xs, &ys);
            (tset, poly)
        })
        .collect())
}

//---------------------------------SHARE---------------------------------

#[derive(Clone, Debug)]
pub struct Gf256ShamirShare {
    pub share: Gf256,
    ///index of the share(x-values),can be different from the reciever ID
    pub id: usize,
    pub degree: usize,
}

//---------------------------------DOMAIN---------------------------------

pub struct Gf256Domain {
    pub elements: Vec<Gf256>,
}

impl Gf256Domain {
    pub fn new(size: usize) -> Result<Self, Gf256Error> {
        if size > 255 {
            return Err(Gf256Error::InvalidDomainSize(size));
        }

        let mut elements = Vec::with_capacity(size);
        let mut x = Gf256::one();
        for _ in 0..size {
            elements.push(x);
            x = x.mul(Gf256::GENERATOR);
        }
        Ok(Self { elements })
    }

    pub fn element(&self, i: usize) -> Gf256 {
        self.elements[i]
    }
}
