pub mod shamir;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ShareError {
    #[error("insufficient shares to reconstruct the secret")]
    InsufficientShares,
    #[error("mismatch degree between shares")]
    DegreeMismatch,
    #[error("mismatch index between shares")]
    IdMismatch,
    #[error("invalid input")]
    InvalidInput,
    #[error("types are different")]
    TypeMismatch,
    #[error("no suitalble fft domain")]
    NoSuitableDomain,
}
