use crate::common::types::TypeError;
use crate::common::SecretSharingScheme;
use ark_ff::{FftField, PrimeField};
use std::marker::PhantomData;
use std::ops::{Add, Mul, Sub};

/// Represents a secret signed integer shared among the parties.
///
/// The fields of this struct are private to prevent erroneous mutation of the precision and the
/// share. The share and the bit size must be consistent in that the integer representation must
/// fit into the field to guarantee correctness.
#[derive(Clone)]
pub struct SecretInt<F, S>
where
    F: FftField,
    S: SecretSharingScheme<F>,
{
    share: S,
    bit_length: usize,
    _field: PhantomData<F>,
}

impl<F, S> SecretInt<F, S>
where
    F: FftField,
    S: SecretSharingScheme<F>,
{
    pub fn new(share: S, bit_length: usize) -> Self {
        assert!(
            ((bit_length) as u32) < F::BasePrimeField::MODULUS_BIT_SIZE,
            "the bit length of the resulting multiplication does not fit into the field"
        );

        Self {
            share,
            bit_length,
            _field: PhantomData,
        }
    }

    pub fn share(&self) -> &S {
        &self.share
    }

    pub fn bit_length(&self) -> usize {
        self.bit_length
    }

    pub fn set_bit_length(&mut self, bit_length: usize) {
        assert!(
            ((bit_length) as u32) < F::BasePrimeField::MODULUS_BIT_SIZE,
            "the bit length of the resulting multiplication does not fit into the field"
        );
        self.bit_length = bit_length;
    }

    pub fn set_bit_length_unchecked(&mut self, bit_length: usize) {
        self.bit_length = bit_length;
    }
}

impl<F, S> Mul<ClearInt<F>> for SecretInt<F, S>
where
    F: FftField,
    S: SecretSharingScheme<F>,
{
    type Output = Result<Self, TypeError>;

    fn mul(self, rhs: ClearInt<F>) -> Self::Output {
        if self.bit_length != rhs.bit_length {
            return Err(TypeError::IncompatibleIntegerPrecision {
                current: self.bit_length,
                other: rhs.bit_length,
            });
        }
        // Multiplying two signed integers with bit length k can result in an integer of 2k bits,
        // hence, we need to check that the multiplication fits into the current bit length.
        assert!(
            ((2 * self.bit_length) as u32) < F::BasePrimeField::MODULUS_BIT_SIZE,
            "the bit length of the resulting multiplication does not fit into the field"
        );
        Ok(Self {
            share: (self.share * rhs.value)?,
            bit_length: self.bit_length,
            _field: PhantomData,
        })
    }
}

impl<F, S> Sub<ClearInt<F>> for SecretInt<F, S>
where
    F: FftField,
    S: SecretSharingScheme<F>,
{
    type Output = Result<Self, TypeError>;

    fn sub(self, rhs: ClearInt<F>) -> Self::Output {
        if self.bit_length != rhs.bit_length {
            return Err(TypeError::IncompatibleIntegerPrecision {
                current: self.bit_length,
                other: rhs.bit_length,
            });
        }
        Ok(Self {
            share: (self.share - rhs.value)?,
            bit_length: self.bit_length,
            _field: PhantomData,
        })
    }
}

impl<F, S> Sub for SecretInt<F, S>
where
    F: FftField,
    S: SecretSharingScheme<F>,
{
    type Output = Result<Self, TypeError>;

    fn sub(self, rhs: Self) -> Self::Output {
        if self.bit_length != rhs.bit_length {
            return Err(TypeError::IncompatibleIntegerPrecision {
                current: self.bit_length,
                other: rhs.bit_length,
            });
        }
        Ok(Self {
            share: (self.share - rhs.share)?,
            bit_length: self.bit_length,
            _field: PhantomData,
        })
    }
}

impl<F, S> SecretInt<F, S>
where
    F: FftField + PrimeField,
    S: SecretSharingScheme<F>,
{
    /// Divide a secret integer by a clear (public) integer constant.
    ///
    /// Performs exact field division `[z] = [x] * c^{-1}`.
    /// Returns an error if the bit lengths are incompatible or if the constant is zero.
    pub fn div_by_const(self, c: i128) -> Result<Self, TypeError> {
        // Constant must be non-zero
        if c == 0 {
            return Err(TypeError::DivisionByZero);
        }

        // Bit length check (logical)
        assert!(
            (self.bit_length as u32) < F::BasePrimeField::MODULUS_BIT_SIZE,
            "bit length exceeds field capacity"
        );

        // Encode constant into field
        let c_field = if c < 0 {
            -F::from((-c) as u128)
        } else {
            F::from(c as u128)
        };

        // Invert constant
        let inv_c = c_field.inverse().ok_or(TypeError::DivisionByZero)?; // should never fail if c != 0

        // Multiply each share locally
        Ok(Self {
            share: (self.share * inv_c)?,
            bit_length: self.bit_length,
            _field: PhantomData,
        })
    }
}

impl<F, S> Add<ClearInt<F>> for SecretInt<F, S>
where
    F: FftField,
    S: SecretSharingScheme<F>,
{
    type Output = Result<Self, TypeError>;

    fn add(self, rhs: ClearInt<F>) -> Self::Output {
        if self.bit_length != rhs.bit_length {
            return Err(TypeError::IncompatibleIntegerPrecision {
                current: self.bit_length,
                other: rhs.bit_length,
            });
        }
        Ok(Self {
            share: (self.share + rhs.value)?,
            bit_length: self.bit_length,
            _field: PhantomData,
        })
    }
}

impl<F, S> Add for SecretInt<F, S>
where
    F: FftField,
    S: SecretSharingScheme<F>,
{
    type Output = Result<Self, TypeError>;

    fn add(self, rhs: Self) -> Self::Output {
        if self.bit_length != rhs.bit_length {
            return Err(TypeError::IncompatibleIntegerPrecision {
                current: self.bit_length,
                other: rhs.bit_length,
            });
        }
        Ok(Self {
            share: (self.share + rhs.share)?,
            bit_length: self.bit_length,
            _field: PhantomData,
        })
    }
}

/// Represents a public signed integer shared among the parties.
///
/// The fields of this struct are private to prevent erroneous mutation of the precision and the
/// share. The share and the bit size must be consistent in that the integer representation must
/// fit into the field to guarantee correctness.
pub struct ClearInt<F: FftField> {
    /// Clear value encoding the clear integer.
    value: F,
    /// Number of bits of the integer representation.
    bit_length: usize,
}

impl<F> ClearInt<F>
where
    F: FftField,
{
    /// Creates a new clear integer, encoding the integer in the field.
    ///
    /// The `bit_length` must satisfy that `2 ^ bit_length < q` to avoid overflow.
    pub fn new(value: F, bit_length: usize) -> Self {
        assert!(
            (bit_length as u32) < F::BasePrimeField::MODULUS_BIT_SIZE,
            "the bit length in the representation does not fit into the field"
        );
        Self { value, bit_length }
    }
}

#[cfg(test)]
mod tests {
    use crate::honeybadger::robust_interpolate::robust_interpolate::RobustShare;

    use super::*;
    use ark_bn254::Fr;
    use ark_std::test_rng;

    #[test]
    fn test_secret_int_new_from_shares() {
        let mut rng = test_rng();
        let n = 5;
        let t = 1;
        let bitlen = 8;

        // Example: 10 as int8
        let shares = RobustShare::compute_shares(Fr::from(10u64), n, t, None, &mut rng).unwrap();
        let sint = SecretInt::<Fr, RobustShare<Fr>>::new(shares[0].clone(), bitlen);

        assert_eq!(sint.bit_length(), bitlen);
        assert_eq!(sint.share(), &shares[0]);
    }

    #[test]
    fn test_clear_int_new() {
        let cint = ClearInt::<Fr>::new(Fr::from(42u64), 8);
        assert_eq!(cint.bit_length, 8);
    }

    #[test]
    fn test_secret_int_addition_same_bitlen() {
        let mut rng = test_rng();
        let n = 5;
        let t = 1;
        let bitlen = 8;

        // x = 5, y = 7
        let x_shares = RobustShare::compute_shares(Fr::from(5u64), n, t, None, &mut rng).unwrap();
        let y_shares = RobustShare::compute_shares(Fr::from(7u64), n, t, None, &mut rng).unwrap();

        let sx = SecretInt::<Fr, RobustShare<Fr>>::new(x_shares[0].clone(), bitlen);
        let sy = SecretInt::<Fr, RobustShare<Fr>>::new(y_shares[0].clone(), bitlen);
        let sum = (sx + sy).unwrap();

        let expected = (x_shares[0].clone() + y_shares[0].clone()).unwrap();
        assert_eq!(sum.share(), &expected);
        assert_eq!(sum.bit_length(), bitlen);
    }

    #[test]
    fn test_secret_int_subtraction_same_bitlen() {
        let mut rng = test_rng();
        let n = 5;
        let t = 1;
        let bitlen = 8;

        // x = 20, y = 8
        let x_shares = RobustShare::compute_shares(Fr::from(20u64), n, t, None, &mut rng).unwrap();
        let y_shares = RobustShare::compute_shares(Fr::from(8u64), n, t, None, &mut rng).unwrap();

        let sx = SecretInt::<Fr, RobustShare<Fr>>::new(x_shares[0].clone(), bitlen);
        let sy = SecretInt::<Fr, RobustShare<Fr>>::new(y_shares[0].clone(), bitlen);
        let diff = (sx - sy).unwrap();

        let expected = (x_shares[0].clone() - y_shares[0].clone()).unwrap();
        assert_eq!(diff.share(), &expected);
    }

    #[test]
    fn test_secret_int_addition_with_clear_int() {
        let mut rng = test_rng();
        let n = 5;
        let t = 1;
        let bitlen = 16;

        // secret = 15, clear = 5
        let shares = RobustShare::compute_shares(Fr::from(15u64), n, t, None, &mut rng).unwrap();
        let secret = SecretInt::<Fr, RobustShare<Fr>>::new(shares[0].clone(), bitlen);
        let clear = ClearInt::<Fr>::new(Fr::from(5u64), bitlen);

        let res = (secret + clear).unwrap();
        let expected = (shares[0].clone() + Fr::from(5u64)).unwrap();
        assert_eq!(res.share(), &expected);
        assert_eq!(res.bit_length(), bitlen);
    }

    #[test]
    fn test_secret_int_subtraction_with_clear_int() {
        let mut rng = test_rng();
        let n = 5;
        let t = 1;
        let bitlen = 8;

        // secret = 12, clear = 7
        let shares = RobustShare::compute_shares(Fr::from(12u64), n, t, None, &mut rng).unwrap();
        let secret = SecretInt::<Fr, RobustShare<Fr>>::new(shares[0].clone(), bitlen);
        let clear = ClearInt::<Fr>::new(Fr::from(7u64), bitlen);

        let res = (secret - clear).unwrap();
        let expected = (shares[0].clone() - Fr::from(7u64)).unwrap();
        assert_eq!(res.share(), &expected);
    }

    #[test]
    fn test_secret_int_multiplication_with_clear_int() {
        let mut rng = test_rng();
        let n = 5;
        let t = 1;
        let bitlen = 8;

        // secret = 6, clear = 3 → expected = 18
        let shares = RobustShare::compute_shares(Fr::from(6u64), n, t, None, &mut rng).unwrap();
        let secret = SecretInt::<Fr, RobustShare<Fr>>::new(shares[0].clone(), bitlen);
        let clear = ClearInt::<Fr>::new(Fr::from(3u64), bitlen);

        let res = (secret * clear).unwrap();
        let expected = (shares[0].clone() * Fr::from(3u64)).unwrap();
        assert_eq!(res.share(), &expected);
        assert_eq!(res.bit_length(), bitlen);
    }

    #[test]
    fn test_bit_length_mismatch_error() {
        let mut rng = test_rng();
        let n = 5;
        let t = 1;

        let x_shares = RobustShare::compute_shares(Fr::from(9u64), n, t, None, &mut rng).unwrap();
        let y_shares = RobustShare::compute_shares(Fr::from(5u64), n, t, None, &mut rng).unwrap();

        let sx = SecretInt::<Fr, RobustShare<Fr>>::new(x_shares[0].clone(), 8);
        let sy = SecretInt::<Fr, RobustShare<Fr>>::new(y_shares[0].clone(), 16);

        // Secret + Secret
        let res1 = sx.clone() + sy.clone();
        assert!(res1.is_err());

        // Secret + Clear
        let c = ClearInt::<Fr>::new(Fr::from(2u64), 16);
        let res2 = sx.clone() + c;
        assert!(res2.is_err());

        // Secret * Clear
        let c2 = ClearInt::<Fr>::new(Fr::from(2u64), 16);
        let res3 = sx.clone() * c2;
        assert!(res3.is_err());

        // Secret - Clear
        let c3 = ClearInt::<Fr>::new(Fr::from(2u64), 16);
        let res4 = sx.clone() - c3;
        assert!(res4.is_err());
    }

    #[test]
    #[should_panic]
    fn test_invalid_bit_length_panics_on_creation() {
        // bit length exceeds modulus size for the field (should panic)
        let _ = ClearInt::<Fr>::new(Fr::from(5u64), (Fr::MODULUS_BIT_SIZE + 10) as usize);
    }

    #[test]
    fn test_secret_int_div_by_const() {
        use crate::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
        use ark_bn254::Fr;
        use ark_std::test_rng;

        let mut rng = test_rng();
        let n = 5;
        let t = 1;
        let bitlen = 8;

        // secret = 20, divide by 4 → expected = 5
        let shares = RobustShare::compute_shares(Fr::from(20u64), n, t, None, &mut rng).unwrap();
        let mut s = Vec::new();
        for i in shares {
            s.push(
                SecretInt::<Fr, RobustShare<Fr>>::new(i.clone(), bitlen)
                    .div_by_const(4)
                    .unwrap(),
            );
        }
        let new_shares: Vec<_> = s.iter().map(|s| s.share.clone()).collect();
        let expected = RobustShare::recover_secret(&new_shares, n).unwrap();

        assert_eq!(Fr::from(5), expected.1);
        s.iter().for_each(|i| assert_eq!(i.bit_length(), bitlen));
    }
}
