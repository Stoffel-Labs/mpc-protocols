use std::{
    collections::HashMap,
    ops::{Add, Mul, Sub},
};
/// Finite field GF(2^8) with AES modulus x^8 + x^4 + x^3 + x + 1 (0x11B)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct F2_8(pub u8);

impl F2_8 {
    pub const MODULUS: u16 = 0x11B;

    pub fn new(value: u8) -> Self {
        F2_8(value)
    }

    pub fn zero() -> Self {
        F2_8(0)
    }

    pub fn one() -> Self {
        F2_8(1)
    }

    /// Addition in GF(2^8) is XOR
    pub fn add(self, other: F2_8) -> F2_8 {
        F2_8(self.0 ^ other.0)
    }

    /// Multiplication in GF(2^8) with reduction by MODULUS
    pub fn mul(self, other: F2_8) -> F2_8 {
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

        F2_8(result as u8)
    }

    /// Multiplicative inverse using Fermat’s little theorem:
    /// a^-1 = a^(2^8 - 2) = a^254
    pub fn inverse(self) -> Option<F2_8> {
        if self.0 == 0 {
            None
        } else {
            Some(self.pow(254))
        }
    }

    /// Exponentiation by square-and-multiply
    pub fn pow(self, mut exp: u64) -> F2_8 {
        let mut result = F2_8::one();
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

impl From<u8> for F2_8 {
    fn from(value: u8) -> Self {
        F2_8(value)
    }
}

impl From<u16> for F2_8 {
    fn from(value: u16) -> Self {
        // Reduce to 8 bits in case input > 255
        F2_8((value & 0xFF) as u8)
    }
}

impl Add for F2_8 {
    type Output = F2_8;
    fn add(self, other: F2_8) -> Self::Output {
        self.add(other)
    }
}

impl Mul for F2_8 {
    type Output = F2_8;
    fn mul(self, other: F2_8) -> F2_8 {
        self.mul(other)
    }
}

impl Sub for F2_8 {
    type Output = F2_8;
    fn sub(self, other: F2_8) -> F2_8 {
        self.add(other) // subtraction = addition in characteristic 2
    }
}

//---------------------------------POLYNOMIAL---------------------------------

#[derive(Clone, Debug)]
pub struct Poly {
    pub coeffs: Vec<F2_8>, // coeffs[0] + coeffs[1] x + coeffs[2] x^2 + ...
}

impl Poly {
    pub fn zero() -> Self {
        Poly {
            coeffs: vec![F2_8::zero()],
        }
    }

    pub fn from_coeffs(c: Vec<F2_8>) -> Self {
        Poly { coeffs: c }
    }

    pub fn evaluate(&self, x: F2_8) -> F2_8 {
        let mut acc = F2_8::zero();
        let mut pow = F2_8::one();
        for &c in &self.coeffs {
            acc = acc.add(c.mul(pow));
            pow = pow.mul(x);
        }
        acc
    }
}

fn poly_add(a: &Poly, b: &Poly) -> Poly {
    let n = a.coeffs.len().max(b.coeffs.len());
    let mut coeffs = vec![F2_8::zero(); n];
    for i in 0..a.coeffs.len() {
        coeffs[i] = coeffs[i].add(a.coeffs[i]);
    }
    for i in 0..b.coeffs.len() {
        coeffs[i] = coeffs[i].add(b.coeffs[i]);
    }
    Poly::from_coeffs(coeffs)
}

fn poly_mul(a: &Poly, b: &Poly) -> Poly {
    let mut coeffs = vec![F2_8::zero(); a.coeffs.len() + b.coeffs.len() - 1];
    for i in 0..a.coeffs.len() {
        for j in 0..b.coeffs.len() {
            coeffs[i + j] = coeffs[i + j].add(a.coeffs[i].mul(b.coeffs[j]));
        }
    }
    Poly::from_coeffs(coeffs)
}

fn poly_scale(a: &Poly, k: F2_8) -> Poly {
    Poly::from_coeffs(a.coeffs.iter().map(|&c| c.mul(k)).collect())
}

pub fn lagrange_interpolate_f2_8(x_vals: &[F2_8], y_vals: &[F2_8]) -> Poly {
    assert_eq!(x_vals.len(), y_vals.len());
    let n = x_vals.len();
    let mut result = Poly::zero();

    for j in 0..n {
        // numerator polynomial
        let mut num = Poly::from_coeffs(vec![F2_8::one()]);
        let mut denom = F2_8::one();

        for m in 0..n {
            if m != j {
                // (x - x_m)
                num = poly_mul(&num, &Poly::from_coeffs(vec![x_vals[m], F2_8::one()]));
                denom = denom.mul(x_vals[j].sub(x_vals[m]));
            }
        }

        let scale = y_vals[j].div(denom);
        num = poly_scale(&num, scale);
        result = poly_add(&result, &num);
    }

    result
}
pub fn build_all_f_polys_2_8(tsets: HashMap<Vec<usize>, i64>) -> HashMap<Vec<usize>, Poly> {
    tsets
        .into_iter()
        .map(|(tset, _)| {
            // Construct interpolation points
            let xs = std::iter::once(F2_8::zero())
                .chain(tset.iter().map(|&j| F2_8::from((j + 1) as u16)))
                .collect::<Vec<_>>();
            let ys = std::iter::once(F2_8::one())
                .chain(std::iter::repeat(F2_8::zero()).take(tset.len()))
                .collect::<Vec<_>>();
            // Interpolate polynomial
            let poly = lagrange_interpolate_f2_8(&xs, &ys);
            (tset, poly)
        })
        .collect()
}
