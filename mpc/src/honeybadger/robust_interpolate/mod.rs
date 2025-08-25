pub mod robust_interpolate;

use crate::common::share::ShareError;
use thiserror::Error;

/// Custom Error type for polynomial operations.
#[derive(Error, Debug)]
pub enum InterpolateError {
    /// Errors related to polynomial operations, potentially with an underlying cause.
    #[error("Polynomial operation failed: {0}")]
    PolynomialOperationError(String),

    /// Errors specific to invalid input parameters or conditions.
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Errors that occur during the decoding process.
    #[error("Decoding failed: {0}")]
    DecodingError(String),

    /// No suitable FFT evaluation domain could be found.
    #[error("No suitable FFT evaluation domain found for n={0}")]
    NoSuitableDomain(usize),

    #[error("inner error: {0}")]
    ShareError(#[from] ShareError),
}