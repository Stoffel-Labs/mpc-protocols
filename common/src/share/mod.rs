pub mod shamir;

use thiserror::Error;

trait Share: Sized {
    /// The underlying secret that this share represents.
    type UnderlyingSecret;
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
}
