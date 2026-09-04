//! A GF(2^k) Shamir-sharing domain, parallel to the existing `F: FftField` prime-field domain
//! (`common::share`, `honeybadger::robust_interpolate`), intended for arithmetic circuits (e.g.
//! AES) that are naturally expressed over a binary field rather than a large prime field.
//!

pub mod field;
pub mod generic_field;
pub mod poly;
pub mod robust_interpolate;
pub mod share;
pub mod vandermonde;

pub use field::{BinaryField, Gf256, Gf2kDomain};
pub use generic_field::{verify_field_and_generator, Gf2k, Gf2p16, Gf2p4, Gf2p8};
pub use poly::Poly;
pub use share::GfShare;
pub use vandermonde::{apply_vandermonde, make_vandermonde};

use crate::common::share::ShareError;
use thiserror::Error;

/// Error type for GF(2^k) field, polynomial, and share operations.
#[derive(Error, Debug)]
pub enum Gf2kError {
    #[error("Polynomial operation failed: {0}")]
    PolynomialOperationError(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Decoding error: {0}")]
    DecodingError(String),

    /// No suitable domain of the requested size exists (i.e. it exceeds
    /// `K::MAX_DOMAIN_SIZE`).
    #[error("No suitable domain found for n={0}")]
    NoSuitableDomain(usize),

    #[error(transparent)]
    ShareError(#[from] ShareError),
}
