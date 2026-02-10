use std::{
    collections::HashMap,
    ops::{Add, Mul, Sub},
};
use thiserror::Error;

/// Error type for GF(2^8) field and domain operations.
#[derive(Error, Debug)]
pub enum GF256Error {
    /// Division or inversion by zero.
    #[error("Division by zero in GF(2^8)")]
    DivisionByZero,

    /// Element has no multiplicative inverse (should only occur for 0).
    #[error("Element {0:?} has no multiplicative inverse")]
    NotInvertible(GF256),

    /// Invalid domain size (must be ≤ 255).
    #[error("Invalid domain size for GF(2^8): n = {0}")]
    InvalidDomainSize(usize),

    /// Internal polynomial operation error or custom failure.
    #[error("Polynomial operation failed: {0}")]
    PolynomialOperationError(String),
}

/// Finite field GF(2^8) with AES modulus x^8 + x^4 + x^3 + x + 1 (0x11B)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GF256(pub u8);

impl GF256 {
    pub const MODULUS: u16 = 0x11B;
    pub const GENERATOR: GF256 = GF256(0x03);

    pub fn generator() -> Self {
        Self::GENERATOR
    }

    pub fn new(value: u8) -> Self {
        GF256(value)
    }

    pub fn zero() -> Self {
        GF256(0)
    }

    pub fn is_zero(&self) -> bool {
        *self == Self::zero()
    }

    pub fn is_one(&self) -> bool {
        *self == Self::one()
    }

    pub fn one() -> Self {
        GF256(1)
    }

    /// Addition in GF(2^8) is XOR
    pub fn add(self, other: GF256) -> GF256 {
        GF256(self.0 ^ other.0)
    }

    /// Multiplication in GF(2^8) with reduction by MODULUS
    pub fn mul(self, other: GF256) -> GF256 {
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

        GF256(result as u8)
    }

    /// Multiplicative inverse using Fermat’s little theorem:
    /// a^-1 = a^(2^8 - 2) = a^254
    pub fn inverse(self) -> Option<GF256> {
        if self.0 == 0 {
            None
        } else {
            Some(self.pow(254))
        }
    }

    /// Exponentiation by square-and-multiply
    pub fn pow(self, mut exp: u64) -> GF256 {
        let mut result = GF256::one();
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

impl From<u8> for GF256 {
    fn from(value: u8) -> Self {
        GF256(value)
    }
}

impl From<u16> for GF256 {
    fn from(value: u16) -> Self {
        // Reduce to 8 bits in case input > 255
        GF256((value & 0xFF) as u8)
    }
}

impl Add for GF256 {
    type Output = GF256;
    fn add(self, other: GF256) -> Self::Output {
        self.add(other)
    }
}

impl Mul for GF256 {
    type Output = GF256;
    fn mul(self, other: GF256) -> GF256 {
        self.mul(other)
    }
}

impl Sub for GF256 {
    type Output = GF256;
    fn sub(self, other: GF256) -> GF256 {
        self.add(other) // subtraction = addition in characteristic 2
    }
}

//---------------------------------POLYNOMIAL---------------------------------

/// Polynomial in GF(2^8).
#[derive(Clone, Debug)]
pub struct GF256Poly {
    /// Coefficients of the polynomial in decreasing powers of x, i.e.,
    /// coeffs[0] + coeffs[1] x + coeffs[2] x^2 + ...
    pub coeffs: Vec<GF256>,
}

impl GF256Poly {
    pub fn zero() -> Self {
        GF256Poly {
            coeffs: vec![GF256::zero()],
        }
    }

    pub fn from_coeffs(c: Vec<GF256>) -> Self {
        GF256Poly { coeffs: c }
    }

    pub fn evaluate(&self, x: GF256) -> GF256 {
        let mut acc = GF256::zero();
        let mut pow = GF256::one();
        for &c in &self.coeffs {
            acc = acc.add(c.mul(pow));
            pow = pow.mul(x);
        }
        acc
    }
}

impl Add<Self> for GF256Poly {
    type Output = Self;
    fn add(self, other: Self) -> Self::Output {
        poly_add(&self, &other)
    }
}

impl Mul<Self> for GF256Poly {
    type Output = Self;
    fn mul(self, other: Self) -> Self::Output {
        poly_mul(&self, &other)
    }
}

impl Mul<GF256> for GF256Poly {
    type Output = Self;
    fn mul(self, other: GF256) -> Self::Output {
        poly_scale(&self, other)
    }
}

impl Add<&Self> for GF256Poly {
    type Output = Self;
    fn add(self, other: &Self) -> Self::Output {
        poly_add(&self, other)
    }
}

impl Mul<&Self> for GF256Poly {
    type Output = Self;
    fn mul(self, other: &Self) -> Self::Output {
        poly_mul(&self, other)
    }
}

impl Mul<&GF256> for GF256Poly {
    type Output = Self;
    fn mul(self, other: &GF256) -> Self::Output {
        poly_scale(&self, *other)
    }
}

/// Addition of two polynomials in GF(2^8).
fn poly_add(a: &GF256Poly, b: &GF256Poly) -> GF256Poly {
    let n = a.coeffs.len().max(b.coeffs.len());
    let mut coeffs = vec![GF256::zero(); n];
    for i in 0..a.coeffs.len() {
        coeffs[i] = coeffs[i].add(a.coeffs[i]);
    }
    for i in 0..b.coeffs.len() {
        coeffs[i] = coeffs[i].add(b.coeffs[i]);
    }
    GF256Poly::from_coeffs(coeffs)
}

/// Multiplication of two polynomials in GF(2^8).
fn poly_mul(a: &GF256Poly, b: &GF256Poly) -> GF256Poly {
    let mut coeffs = vec![GF256::zero(); a.coeffs.len() + b.coeffs.len() - 1];
    for i in 0..a.coeffs.len() {
        for j in 0..b.coeffs.len() {
            coeffs[i + j] = coeffs[i + j].add(a.coeffs[i].mul(b.coeffs[j]));
        }
    }
    GF256Poly::from_coeffs(coeffs)
}

/// Multiplication by a scalar for GF(2^8) polynomials.
fn poly_scale(a: &GF256Poly, k: GF256) -> GF256Poly {
    GF256Poly::from_coeffs(a.coeffs.iter().map(|&c| c.mul(k)).collect())
}

/// Lagrange interpolation in GF(2^8).
pub fn lagrange_interpolate_f2_8(x_vals: &[GF256], y_vals: &[GF256]) -> GF256Poly {
    assert_eq!(x_vals.len(), y_vals.len());
    let n = x_vals.len();
    let mut result = GF256Poly::zero();

    for j in 0..n {
        // numerator polynomial
        let mut num = GF256Poly::from_coeffs(vec![GF256::one()]);
        let mut denom = GF256::one();

        for m in 0..n {
            if m != j {
                // (x - x_m)
                num = poly_mul(&num, &GF256Poly::from_coeffs(vec![x_vals[m], GF256::one()]));
                denom = denom.mul(x_vals[j].sub(x_vals[m]));
            }
        }

        let scale = y_vals[j].div(denom);
        num = poly_scale(&num, scale);
        result = poly_add(&result, &num);
    }

    result
}

/// For each T set in the adversarial structure, interpolates a polynomial f_T such that
/// f_T(0) = 1, and f_T(x_i) = 0 for all i in T.
pub fn build_all_f_polys_2_8(
    n: usize,
    tsets: Vec<Vec<usize>>,
) -> Result<HashMap<Vec<usize>, GF256Poly>, GF256Error> {
    let domain_2 = GF256Domain::new(n)?;
    Ok(tsets
        .into_iter()
        .map(|tset| {
            // Construct interpolation points
            let xs = std::iter::once(GF256::zero())
                .chain(tset.iter().map(|&j| domain_2.element(j)))
                .collect::<Vec<_>>();
            let ys = std::iter::once(GF256::one())
                .chain(std::iter::repeat(GF256::zero()).take(tset.len()))
                .collect::<Vec<_>>();
            // Interpolate polynomial
            let poly = lagrange_interpolate_f2_8(&xs, &ys);
            (tset, poly)
        })
        .collect())
}

//---------------------------------SHARE---------------------------------

/// A share of an element in GF(2^8).
#[derive(Clone, Debug)]
pub struct GF256ShamirShare {
    /// Share value, i.e., y_i = f(x_i).
    pub share: GF256,
    /// Index of the share(x-values), it can be different from the reciever ID.
    pub id: usize,
    /// Degree of the polynomial that generated the share.
    pub degree: usize,
}

//---------------------------------DOMAIN---------------------------------

pub struct GF256Domain {
    pub elements: Vec<GF256>,
}

impl GF256Domain {
    pub fn new(size: usize) -> Result<Self, GF256Error> {
        if size > 255 {
            return Err(GF256Error::InvalidDomainSize(size));
        }

        let mut elements = Vec::with_capacity(size);
        let mut x = GF256::one();
        for _ in 0..size {
            elements.push(x);
            x = x.mul(GF256::GENERATOR);
        }
        Ok(Self { elements })
    }

    pub fn element(&self, i: usize) -> GF256 {
        self.elements[i]
    }
}
