use crate::{
    common::share::ShareError,
    honeybadger::{batch_recon::BatchReconError, mul_pub::MulPubError, SessionId},
};
use ark_serialize::SerializationError;
use thiserror::Error;

pub mod rand_inv_pair;

#[derive(Debug, Error)]
pub enum RandInvPairError {
    #[error("mul pub error: {0}")]
    MulPubError(#[from] MulPubError),
    #[error("batch recon error: {0}")]
    BatchReconError(#[from] BatchReconError),
    #[error("share error: {0}")]
    ShareError(#[from] ShareError),
    #[error("serialization: {0}")]
    SerializationError(#[from] SerializationError),
    #[error("no session: {0:?}")]
    NoSuchSessionId(SessionId),
    #[error("already received: {0:?}")]
    ResultAlreadyReceived(SessionId),
    #[error("send error: {0:?}")]
    SendError(SessionId),
    #[error("receive error: {0:?}")]
    ReceiveError(SessionId),
    #[error("timeout: {0:?}")]
    Timeout(SessionId),
    #[error("bad session id: {0:?}")]
    SessionIdError(SessionId),
    #[error("session limit")]
    LimitError,
    #[error("wrong input length")]
    LengthError,
    #[error("abort")]
    Abort,
}
