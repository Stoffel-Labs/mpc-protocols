pub mod shamir;

use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use thiserror::Error;

pub trait Share: Sized + CanonicalSerialize + CanonicalDeserialize {
    /// The underlying secret that this share represents.
    type UnderlyingSecret: Field;

    /// You can add shares together locally
    fn add(&self, other: &Self) -> Result<Self, ShareError>;

    /// You can multiply a scalar to a share locally
    fn scalar_mul(&self, scalar: &Self::UnderlyingSecret) -> Self;

    /// You can multiply shares together with other parties
    fn mul();

    /// You can reveal shares together with other parties
    /// Reveal a share means that you are revealing the underlying secret
    fn reveal();
}

#[derive(Debug, Error)]
pub enum ShareError {
    #[error("insufficient shares to reconstruct the secret")]
    InsufficientShares,
    #[error("mismatch degree between shares")]
    DegreeMismatch,
    #[error("mismatch index between shares")]
    IdMismatch,
    #[error("Invalid input")]
    InvalidInput
}
