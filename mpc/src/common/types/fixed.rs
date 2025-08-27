use crate::common::types::Error;
use crate::common::ShamirShare;
use ark_ff::FftField;
use std::marker::PhantomData;
use std::ops::{Add, Mul, Sub};

/// Parameters that decribe the precision of the fixed point representation.
#[derive(Copy, Debug, Clone, PartialEq)]
pub struct FixedPointPrecision {
    /// Total number of bits in the fixed point representation.
    pub k: usize,
    /// Number of bits spent in the fractional fragment.
    pub f: usize,
}

/// Represents a fixed-point number shared among the parties.
pub struct SecretFixedPoint<F, const N: usize, P>
where
    F: FftField,
{
    /// The secret share used to represent the fixed point number.
    pub value: ShamirShare<F, N, P>,
    /// Precision of this fixed point number.
    pub precision: FixedPointPrecision,
    _field_type: PhantomData<F>,
}

impl<F, const N: usize, P> SecretFixedPoint<F, N, P>
where
    F: FftField,
{
    /// Creates a new secret fixed point number.
    pub fn new(value: ShamirShare<F, N, P>, precision: FixedPointPrecision) -> Self {
        Self {
            value,
            precision,
            _field_type: PhantomData,
        }
    }
}

impl<F, const N: usize, P> Mul<ClearFixedPoint<F>> for SecretFixedPoint<F, N, P>
where
    F: FftField,
{
    type Output = Result<Self, Error>;

    fn mul(self, rhs: ClearFixedPoint<F>) -> Self::Output {
        if self.precision != rhs.precision {
            return Err(Error::IncompatibleFixedPointPrecision {
                current: self.precision,
                other: rhs.precision,
            });
        }
        Ok(Self {
            value: (self.value * rhs.value)?,
            precision: self.precision,
            _field_type: PhantomData,
        })
    }
}

impl<F, const N: usize, P> Add<ClearFixedPoint<F>> for SecretFixedPoint<F, N, P>
where
    F: FftField,
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
            value: (self.value + &rhs.value)?,
            precision: self.precision,
            _field_type: PhantomData,
        })
    }
}

impl<F, const N: usize, P> Sub<ClearFixedPoint<F>> for SecretFixedPoint<F, N, P>
where
    F: FftField,
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
            value: (self.value - &rhs.value)?,
            precision: self.precision,
            _field_type: PhantomData,
        })
    }
}

impl<F, const N: usize, P> Add for SecretFixedPoint<F, N, P>
where
    F: FftField,
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

impl<F, const N: usize, P> Sub for SecretFixedPoint<F, N, P>
where
    F: FftField,
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
pub struct ClearFixedPoint<F: FftField> {
    value: F,
    precision: FixedPointPrecision,
}

impl<F> ClearFixedPoint<F>
where
    F: FftField,
{
    pub fn new(value: F, precision: FixedPointPrecision) -> Self {
        Self { value, precision }
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
