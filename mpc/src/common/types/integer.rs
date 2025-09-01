use crate::common::types::Error;
use crate::common::SecretSharingScheme;
use ark_ff::{FftField, PrimeField};
use std::marker::PhantomData;
use std::ops::{Add, Mul, Sub};

/// Represents a secret signed integer shared among the parties.
///
/// The fields of this struct are private to prevent erroneous mutation of the precision and the
/// share. The share and the bit size must be consistent in that the integer representation must
/// fit into the field to guarantee correctness.
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
    type Output = Result<Self, Error>;

    fn mul(self, rhs: ClearInt<F>) -> Self::Output {
        if self.bit_length != rhs.bit_length {
            return Err(Error::IncompatibleIntegerPrecision {
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
    type Output = Result<Self, Error>;

    fn sub(self, rhs: ClearInt<F>) -> Self::Output {
        if self.bit_length != rhs.bit_length {
            return Err(Error::IncompatibleIntegerPrecision {
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
            _field: PhantomData,
        })
    }
}

impl<F, S> Add<ClearInt<F>> for SecretInt<F, S>
where
    F: FftField,
    S: SecretSharingScheme<F>,
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
    fn new(value: F, bit_length: usize) -> Self {
        assert!(
            (bit_length as u32) < F::BasePrimeField::MODULUS_BIT_SIZE,
            "the bit length in the representation does not fit into the field"
        );
        Self { value, bit_length }
    }
}
