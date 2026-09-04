use std::ops::{Add, Mul, Sub};

use super::field::BinaryField;
use super::Gf2kError;

/// A univariate polynomial over `K`, `coeffs[0] + coeffs[1] x + coeffs[2] x^2 + ...`.
#[derive(Clone, Debug, PartialEq)]
pub struct Poly<K: BinaryField> {
    pub coeffs: Vec<K>,
}

impl<K: BinaryField> Poly<K> {
    pub fn zero() -> Self {
        Poly {
            coeffs: vec![K::zero()],
        }
    }

    pub fn one() -> Self {
        Poly {
            coeffs: vec![K::one()],
        }
    }

    pub fn from_coeffs(c: Vec<K>) -> Self {
        if c.is_empty() {
            return Self::zero();
        }
        Poly { coeffs: c }
    }

    /// The degree-1 polynomial `x - root` (== `x + root` in characteristic 2).
    pub fn monomial(root: K) -> Self {
        Poly::from_coeffs(vec![root, K::one()])
    }

    pub fn is_zero(&self) -> bool {
        self.coeffs.iter().all(|c| c.is_zero())
    }

    /// Drops trailing zero coefficients, leaving `[K::zero()]` for the zero polynomial.
    pub fn trim(&mut self) {
        while self.coeffs.len() > 1 && self.coeffs.last().is_some_and(|c| c.is_zero()) {
            self.coeffs.pop();
        }
        if self.coeffs.is_empty() {
            self.coeffs.push(K::zero());
        }
    }

    pub fn trimmed(mut self) -> Self {
        self.trim();
        self
    }

    /// Degree of the polynomial; the zero polynomial has degree 0.
    pub fn degree(&self) -> usize {
        let mut d = self.coeffs.len().saturating_sub(1);
        while d > 0 && self.coeffs[d].is_zero() {
            d -= 1;
        }
        d
    }

    pub fn leading_coeff(&self) -> K {
        self.coeffs[self.degree()]
    }

    /// Evaluates the polynomial at `x` via Horner's method.
    pub fn evaluate(&self, x: K) -> K {
        let mut acc = K::zero();
        for &c in self.coeffs.iter().rev() {
            acc = acc * x + c;
        }
        acc
    }

    /// Characteristic-2-aware formal derivative: the coefficient of `x^{i-1}` in the derivative
    /// is `i * coeffs[i]`, and in characteristic 2, `i * c` is `c` when `i` is odd and `0` when
    /// `i` is even (repeated XOR of `c` with itself cancels in pairs).
    pub fn derivative(&self) -> Poly<K> {
        if self.coeffs.len() <= 1 {
            return Poly::zero();
        }
        let d_coeffs: Vec<K> = self
            .coeffs
            .iter()
            .enumerate()
            .skip(1)
            .map(|(i, &c)| if i % 2 == 1 { c } else { K::zero() })
            .collect();
        Poly::from_coeffs(d_coeffs).trimmed()
    }

    /// Schoolbook polynomial long division: returns `(quotient, remainder)` such that
    /// `self = quotient * denom + remainder` and `remainder.degree() < denom.degree()`.
    ///
    /// # Errors
    /// - `Gf2kError::PolynomialOperationError` if `denom` is the zero polynomial.
    pub fn div_with_remainder(&self, denom: &Poly<K>) -> Result<(Poly<K>, Poly<K>), Gf2kError> {
        let denom = denom.clone().trimmed();
        if denom.is_zero() {
            return Err(Gf2kError::PolynomialOperationError(
                "division by the zero polynomial".to_string(),
            ));
        }
        let denom_deg = denom.degree();
        let denom_lead_inv = denom.leading_coeff().inverse().ok_or_else(|| {
            Gf2kError::PolynomialOperationError(
                "divisor leading coefficient is not invertible".to_string(),
            )
        })?;

        let mut remainder = self.clone().trimmed();
        if remainder.is_zero() || remainder.degree() < denom_deg {
            return Ok((Poly::zero(), remainder));
        }

        let quotient_deg = remainder.degree() - denom_deg;
        let mut quotient_coeffs = vec![K::zero(); quotient_deg + 1];

        loop {
            remainder.trim();
            if remainder.is_zero() || remainder.degree() < denom_deg {
                break;
            }
            let cur_deg = remainder.degree();
            let shift = cur_deg - denom_deg;
            let coeff = remainder.leading_coeff() * denom_lead_inv;
            quotient_coeffs[shift] = coeff;

            // remainder -= coeff * x^shift * denom (subtraction == addition in characteristic 2)
            for (i, &dc) in denom.coeffs.iter().enumerate() {
                let idx = i + shift;
                remainder.coeffs[idx] = remainder.coeffs[idx] + coeff * dc;
            }
        }
        remainder.trim();

        Ok((Poly::from_coeffs(quotient_coeffs).trimmed(), remainder))
    }
}

/// Interpolates the unique lowest-degree polynomial through `(x_vals[i], y_vals[i])`.
///
/// # Errors
/// - `Gf2kError::InvalidInput` if the slices have mismatched lengths.
/// - `Gf2kError::PolynomialOperationError` if `x_vals` contains a duplicate.
pub fn lagrange_interpolate<K: BinaryField>(
    x_vals: &[K],
    y_vals: &[K],
) -> Result<Poly<K>, Gf2kError> {
    if x_vals.len() != y_vals.len() {
        return Err(Gf2kError::InvalidInput(
            "mismatched x/y value lengths".to_string(),
        ));
    }
    let n = x_vals.len();
    let mut result = Poly::zero();

    for j in 0..n {
        let mut num = Poly::one();
        let mut denom = K::one();
        for m in 0..n {
            if m != j {
                num = &num * &Poly::monomial(x_vals[m]);
                denom = denom * (x_vals[j] - x_vals[m]);
            }
        }
        let inv_denom = denom.inverse().ok_or_else(|| {
            Gf2kError::PolynomialOperationError(
                "duplicate x value in lagrange_interpolate".to_string(),
            )
        })?;
        let scale = y_vals[j] * inv_denom;
        result = &result + &(&num * scale);
    }

    Ok(result)
}

impl<K: BinaryField> Add for &Poly<K> {
    type Output = Poly<K>;
    fn add(self, other: &Poly<K>) -> Poly<K> {
        let n = self.coeffs.len().max(other.coeffs.len());
        let mut coeffs = vec![K::zero(); n];
        for (i, &c) in self.coeffs.iter().enumerate() {
            coeffs[i] = coeffs[i] + c;
        }
        for (i, &c) in other.coeffs.iter().enumerate() {
            coeffs[i] = coeffs[i] + c;
        }
        Poly::from_coeffs(coeffs)
    }
}

impl<K: BinaryField> Sub for &Poly<K> {
    type Output = Poly<K>;
    /// Subtraction == addition in characteristic 2 — not a typo for a real subtraction.
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, other: &Poly<K>) -> Poly<K> {
        self + other
    }
}

impl<K: BinaryField> Mul for &Poly<K> {
    type Output = Poly<K>;
    fn mul(self, other: &Poly<K>) -> Poly<K> {
        let mut coeffs = vec![K::zero(); self.coeffs.len() + other.coeffs.len() - 1];
        for (i, &a) in self.coeffs.iter().enumerate() {
            for (j, &b) in other.coeffs.iter().enumerate() {
                coeffs[i + j] = coeffs[i + j] + a * b;
            }
        }
        Poly::from_coeffs(coeffs)
    }
}

impl<K: BinaryField> Mul<K> for &Poly<K> {
    type Output = Poly<K>;
    fn mul(self, scalar: K) -> Poly<K> {
        Poly::from_coeffs(self.coeffs.iter().map(|&c| c * scalar).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::super::field::Gf256;
    use super::*;
    use ark_std::test_rng;

    fn random_poly(degree: usize, rng: &mut impl ark_std::rand::Rng) -> Poly<Gf256> {
        Poly::from_coeffs((0..=degree).map(|_| Gf256::random(rng)).collect())
    }

    #[test]
    fn test_evaluate_matches_naive_sum() {
        // f(x) = 7 + 3x + 5x^2
        let poly = Poly::from_coeffs(vec![Gf256(7), Gf256(3), Gf256(5)]);
        let x = Gf256(2);
        let expected = Gf256(7) + Gf256(3) * x + Gf256(5) * x * x;
        assert_eq!(poly.evaluate(x), expected);
    }

    #[test]
    fn test_derivative_hand_computed() {
        // f(x) = 3 + 2x + x^2 + 4x^3  ->  f'(x) = 2 + 2x + 12x^2, coefficient of x^{i-1} is
        // coeffs[i] if i odd else 0: i=1 (odd) -> coeffs[1]=2, i=2 (even) -> 0, i=3 (odd) ->
        // coeffs[3]=4. So f'(x) = 2 + 0*x + 4x^2, trimmed leaves the middle zero in place since
        // it's not trailing.
        let poly = Poly::from_coeffs(vec![Gf256(3), Gf256(2), Gf256(1), Gf256(4)]);
        let deriv = poly.derivative();
        assert_eq!(deriv.coeffs, vec![Gf256(2), Gf256::zero(), Gf256(4)]);
    }

    #[test]
    fn test_derivative_constant_is_zero() {
        let poly = Poly::from_coeffs(vec![Gf256(9)]);
        assert!(poly.derivative().is_zero());
    }

    #[test]
    fn test_div_with_remainder_exact_division() {
        let mut rng = test_rng();
        for _ in 0..50 {
            let q = random_poly(4, &mut rng);
            let d = random_poly(2, &mut rng);
            let product = &q * &d;

            let (quotient, remainder) = product.div_with_remainder(&d).unwrap();
            assert!(
                remainder.is_zero(),
                "expected exact division, got remainder {remainder:?}"
            );
            assert_eq!(quotient.trimmed(), q.trimmed());
        }
    }

    #[test]
    fn test_div_with_remainder_nontrivial_remainder() {
        let mut rng = test_rng();
        for _ in 0..50 {
            let d = random_poly(3, &mut rng);
            let r = random_poly(1, &mut rng); // degree < d's degree
            let q = random_poly(2, &mut rng);
            let numerator = &(&q * &d) + &r;

            let (got_q, got_r) = numerator.div_with_remainder(&d).unwrap();
            assert_eq!(got_q.clone().trimmed(), q.trimmed());
            assert_eq!(got_r.clone().trimmed(), r.trimmed());
            assert!(got_r.degree() < d.degree() || got_r.is_zero());

            // Reconstruct: q*d + r must equal the numerator.
            let reconstructed = &(&got_q * &d) + &got_r;
            assert_eq!(reconstructed.trimmed(), numerator.trimmed());
        }
    }

    #[test]
    fn test_div_with_remainder_by_zero_fails() {
        let numerator = Poly::from_coeffs(vec![Gf256(1), Gf256(2)]);
        let zero = Poly::<Gf256>::zero();
        assert!(numerator.div_with_remainder(&zero).is_err());
    }

    #[test]
    fn test_lagrange_interpolate_roundtrip() {
        let mut rng = test_rng();
        let degree = 5;
        let poly = random_poly(degree, &mut rng);

        let xs: Vec<Gf256> = (1..=(degree as u8 + 1)).map(Gf256).collect();
        let ys: Vec<Gf256> = xs.iter().map(|&x| poly.evaluate(x)).collect();

        let recovered = lagrange_interpolate(&xs, &ys).unwrap();
        assert_eq!(recovered.trimmed(), poly.trimmed());
    }

    #[test]
    fn test_lagrange_interpolate_mismatched_lengths_errors() {
        let xs = vec![Gf256(1), Gf256(2)];
        let ys = vec![Gf256(1)];
        assert!(lagrange_interpolate(&xs, &ys).is_err());
    }
}
