use crate::common::share::ShareError;
use crate::common::types::fixed::FixedPointPrecision;
use thiserror::Error;

/// Implements the secure fixed-point arithmetic.
///
/// The implementation of secure fixed-point arithmetic follows the paper "Secure Computation With
/// Fixed-Point Numbers" by Catrina and Saxena.
pub mod fixed;

/// Implements the secure fixed-point arithmetic between shared values.
pub mod integer;

#[derive(Error, Debug)]
pub enum Error {
    #[error("error operating incompatible types - self precision: {current:?}, other precision: {other:?}")]
    IncompatibleIntegerPrecision { current: usize, other: usize },
    #[error("error operating incompatible types - self precision: {current:?}, other precision: {other:?}")]
    IncompatibleFixedPointPrecision {
        current: FixedPointPrecision,
        other: FixedPointPrecision,
    },
    #[error("error operating with shares: {0:?}")]
    ShareError(#[from] ShareError),
}
