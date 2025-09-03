use crate::common::types::Error;
use crate::common::SecretSharingScheme;
use ark_ff::{FftField, PrimeField};
use std::marker::PhantomData;
use std::ops::{Add, Mul, Sub};

/// Parameters that decribe the precision of the fixed point representation.
#[derive(Copy, Debug, Clone, PartialEq)]
pub struct FixedPointPrecision {
    /// Total number of bits in the fixed point representation.
    k: usize,
    /// Number of bits spent in the fractional fragment.
    f: usize,
}

impl FixedPointPrecision {
    pub fn new(k: usize, f: usize) -> Self {
        assert!(f < k, "the number of bits in the fractional fragment must be less than the total number of bits for the representation");
        Self { k, f }
    }

    pub fn k(&self) -> usize {
        self.k
    }

    pub fn f(&self) -> usize {
        self.f
    }

    pub fn set_k(&mut self, k: usize) {
        assert!(self.f < k, "the number of bits in the fractional fragment must be less than the total number of bits for the representation");
        self.k = k;
    }

    pub fn set_f(&mut self, f: usize) {
        assert!(f < self.k, "the number of bits in the fractional fragment must be less than the total number of bits for the representation");
        self.f = f;
    }

    pub fn set_k_unchecked(&mut self, k: usize) {
        self.k = k;
    }

    pub fn set_f_unchecked(&mut self, f: usize) {
        self.f = f;
    }
}

/// Represents a fixed-point number shared among the parties.
///
/// The fields of this struct are private to prevent erroneous mutation of the precision and the
/// share. The share and the bit size must be consistent in that the integer representation must
/// fit into the field to guarantee correctness.
pub struct SecretFixedPoint<F, S>
where
    F: FftField,
    S: SecretSharingScheme<F>,
{
    /// The secret share used to represent the fixed point number.
    value: S,
    /// Precision of this fixed point number.
    precision: FixedPointPrecision,
    _field_type: PhantomData<F>,
}

impl<F, S> SecretFixedPoint<F, S>
where
    F: FftField,
    S: SecretSharingScheme<F>,
{
    /// Creates a new secret fixed point number.
    ///
    /// When we crate a new fixed point value, we must check that the created element fits into the
    /// field.
    pub fn new(value: S, precision: FixedPointPrecision) -> Self {
        assert!(
            (precision.k as u32) < F::BasePrimeField::MODULUS_BIT_SIZE,
            "the precision does not fit into the field"
        );
        Self {
            value,
            precision,
            _field_type: PhantomData,
        }
    }

    pub fn value(&self) -> &S {
        &self.value
    }

    pub fn precision(&self) -> &FixedPointPrecision {
        &self.precision
    }
}

impl<F, S> Mul<ClearFixedPoint<F>> for SecretFixedPoint<F, S>
where
    F: FftField,
    S: SecretSharingScheme<F>,
{
    type Output = Result<Self, Error>;

    fn mul(self, rhs: ClearFixedPoint<F>) -> Self::Output {
        if self.precision != rhs.precision {
            return Err(Error::IncompatibleFixedPointPrecision {
                current: self.precision,
                other: rhs.precision,
            });
        }
        // Multiplying two fixed point with bit length k can result in an integer of 2k bits,
        // hence, we need to check that the multiplication fits into the current field.
        assert!(
            ((self.precision.k * 2) as u32) < F::BasePrimeField::MODULUS_BIT_SIZE,
            "the resulting precision of the operation does not fit into the field"
        );
        Ok(Self {
            value: (self.value * rhs.value)?,
            precision: self.precision,
            _field_type: PhantomData,
        })
    }
}

impl<F, S> Add<ClearFixedPoint<F>> for SecretFixedPoint<F, S>
where
    F: FftField,
    S: SecretSharingScheme<F>,
{
    type Output = Result<Self, Error>;

    fn add(self, rhs: ClearFixedPoint<F>) -> Self::Output {
        if self.precision != rhs.precision {
            return Err(Error::IncompatibleFixedPointPrecision {
                current: self.precision,
                other: rhs.precision,
            });
        }
        Ok(Self {
            value: (self.value + rhs.value)?,
            precision: self.precision,
            _field_type: PhantomData,
        })
    }
}

impl<F, S> Sub<ClearFixedPoint<F>> for SecretFixedPoint<F, S>
where
    F: FftField,
    S: SecretSharingScheme<F>,
{
    type Output = Result<Self, Error>;

    fn sub(self, rhs: ClearFixedPoint<F>) -> Self::Output {
        if self.precision != rhs.precision {
            return Err(Error::IncompatibleFixedPointPrecision {
                current: self.precision,
                other: rhs.precision,
            });
        }
        Ok(Self {
            value: (self.value - rhs.value)?,
            precision: self.precision,
            _field_type: PhantomData,
        })
    }
}

impl<F, S> Add for SecretFixedPoint<F, S>
where
    F: FftField,
    S: SecretSharingScheme<F>,
{
    type Output = Result<Self, Error>;

    fn add(self, rhs: Self) -> Self::Output {
        if self.precision != rhs.precision {
            return Err(Error::IncompatibleFixedPointPrecision {
                current: self.precision,
                other: rhs.precision,
            });
        }
        Ok(Self {
            value: (self.value + rhs.value)?,
            precision: self.precision,
            _field_type: PhantomData,
        })
    }
}

impl<F, S> Sub for SecretFixedPoint<F, S>
where
    F: FftField,
    S: SecretSharingScheme<F>,
{
    type Output = Result<Self, Error>;

    fn sub(self, rhs: Self) -> Self::Output {
        if self.precision != rhs.precision {
            return Err(Error::IncompatibleFixedPointPrecision {
                current: self.precision,
                other: rhs.precision,
            });
        }
        Ok(Self {
            value: (self.value - rhs.value)?,
            precision: self.precision,
            _field_type: PhantomData,
        })
    }
}

/// Represents a public fixed-point number.
///
/// The fields of this struct are private to prevent erroneous mutation of the precision and the
/// share. The share and the bit size must be consistent in that the integer representation must
/// fit into the field to guarantee correctness.
pub struct ClearFixedPoint<F: FftField> {
    value: F,
    precision: FixedPointPrecision,
}

impl<F> ClearFixedPoint<F>
where
    F: FftField,
{
    /// Creates a new secret fixed point number.
    ///
    /// When we crate a new fixed point value, we must check that the created element fits into the
    /// field.
    pub fn new(value: F, precision: FixedPointPrecision) -> Self {
        assert!(
            (precision.k as u32) < F::BasePrimeField::MODULUS_BIT_SIZE,
            "the precision does not fit into the field"
        );
        Self { value, precision }
    }

    pub fn value(&self) -> &F {
        &self.value
    }

    pub fn precision(&self) -> &FixedPointPrecision {
        &self.precision
    }
}

impl<F> Add for ClearFixedPoint<F>
where
    F: FftField,
{
    type Output = Result<Self, Error>;
    fn add(self, rhs: Self) -> Self::Output {
        if self.precision != rhs.precision {
            Err(Error::IncompatibleFixedPointPrecision {
                current: self.precision,
                other: rhs.precision,
            })
        } else {
            Ok(Self {
                value: self.value + rhs.value,
                precision: self.precision,
            })
        }
    }
}

impl<F> Sub for ClearFixedPoint<F>
where
    F: FftField,
{
    type Output = Result<Self, Error>;
    fn sub(self, rhs: Self) -> Self::Output {
        if self.precision != rhs.precision {
            Err(Error::IncompatibleFixedPointPrecision {
                current: self.precision,
                other: rhs.precision,
            })
        } else {
            Ok(Self {
                value: self.value - rhs.value,
                precision: self.precision,
            })
        }
    }
}
