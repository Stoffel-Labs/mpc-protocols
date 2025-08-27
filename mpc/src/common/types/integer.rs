use crate::common::types::Error;
use crate::common::ShamirShare;
use ark_ff::{FftField, PrimeField};
use std::ops::{Add, Mul, Sub};
// TODO: Include an arbitrary Share type.
// TODO: Make it an API-friendly code.

/// Represents a secret signed integer shared among the parties.
pub struct SecretInt<F, const N: usize, P>
where
    F: FftField,
{
    pub share: ShamirShare<F, N, P>,
    pub bit_length: usize,
}

impl<F, const N: usize, P> Mul<ClearInt<F>> for SecretInt<F, N, P>
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

impl<F, const N: usize, P> Sub<ClearInt<F>> for SecretInt<F, N, P>
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

impl<F, const N: usize, P> Sub for SecretInt<F, N, P>
where
    F: FftField,
{
    type Output = Result<Self, Error>;

    fn sub(self, rhs: Self) -> Self::Output {
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

impl<F, const N: usize, P> Add<ClearInt<F>> for SecretInt<F, N, P>
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

impl<F, const N: usize, P> Add for SecretInt<F, N, P>
where
    F: FftField,
{
    type Output = Result<Self, Error>;

    fn add(self, rhs: Self) -> Self::Output {
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
