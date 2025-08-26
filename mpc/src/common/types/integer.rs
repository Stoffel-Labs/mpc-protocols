use crate::common::types::Error;
use crate::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use ark_ff::{FftField, PrimeField};
use std::ops::{Add, Mul, Sub};

// TODO: Include an arbitrary Share type.
// TODO: Make it an API-friendly code.

/// Represents a secret signed integer shared among the parties.
pub struct SecretInt<F>
where
    F: FftField,
{
    share: RobustShare<F>,
    bit_length: usize,
}

impl<F> Mul<ClearInt<F>> for SecretInt<F>
where
    F: FftField,
{
    type Output = Result<Self, Error>;

    fn mul(self, rhs: ClearInt<F>) -> Self::Output {
        if self.bit_length != rhs.bit_length {
            return Err(Error::IncompatibleIntegerPrecision {
                current: self.bit_length,
                other: rhs.bit_length,
            });
        }
        Ok(Self {
            share: (self.share * rhs.value)?,
            bit_length: self.bit_length,
        })
    }
}

impl<F> Sub<ClearInt<F>> for SecretInt<F>
where
    F: FftField,
{
    type Output = Result<Self, Error>;

    fn sub(self, rhs: ClearInt<F>) -> Self::Output {
        if self.bit_length != rhs.bit_length {
            return Err(Error::IncompatibleIntegerPrecision {
                current: self.bit_length,
                other: rhs.bit_length,
            });
        }
        Ok(Self {
            share: (self.share - &rhs.value)?,
            bit_length: self.bit_length,
        })
    }
}

impl<F> Sub for SecretInt<F>
where
    F: FftField,
{
    type Output = Result<Self, Error>;

    fn sub(self, rhs: SecretInt<F>) -> Self::Output {
        if self.bit_length != rhs.bit_length {
            return Err(Error::IncompatibleIntegerPrecision {
                current: self.bit_length,
                other: rhs.bit_length,
            });
        }
        Ok(Self {
            share: (self.share - rhs.share)?,
            bit_length: self.bit_length,
        })
    }
}

impl<F> Add<ClearInt<F>> for SecretInt<F>
where
    F: FftField,
{
    type Output = Result<Self, Error>;

    fn add(self, rhs: ClearInt<F>) -> Self::Output {
        if self.bit_length != rhs.bit_length {
            return Err(Error::IncompatibleIntegerPrecision {
                current: self.bit_length,
                other: rhs.bit_length,
            });
        }
        Ok(Self {
            share: (self.share + &rhs.value)?,
            bit_length: self.bit_length,
        })
    }
}

impl<F> Add for SecretInt<F>
where
    F: FftField,
{
    type Output = Result<Self, Error>;

    fn add(self, rhs: SecretInt<F>) -> Self::Output {
        if self.bit_length != rhs.bit_length {
            return Err(Error::IncompatibleIntegerPrecision {
                current: self.bit_length,
                other: rhs.bit_length,
            });
        }
        Ok(Self {
            share: (self.share + rhs.share)?,
            bit_length: self.bit_length,
        })
    }
}

/// Represents a public signed integer shared among the parties.
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
    fn new(value: F, bit_length: usize) -> Self {
        assert!((1 << bit_length) < F::BasePrimeField::MODULUS_BIT_SIZE);
        Self { value, bit_length }
    }
}
