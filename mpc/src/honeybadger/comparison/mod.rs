use crate::{
    common::{rbc::RbcError, share::ShareError},
    honeybadger::{
        batch_recon::BatchReconError, mul::MulError, robust_interpolate::InterpolateError,
        SessionId,
    },
};
use ark_serialize::SerializationError;
use bincode::ErrorKind;
use stoffelnet::network_utils::NetworkError;
use thiserror::Error;

pub mod bit_ltc1;
pub mod ltz;
pub mod mod2;
pub mod mod2m;
pub mod pre_mulc;
pub mod trunc;

#[derive(Debug, Error)]
pub enum PreMulCError {
    #[error("mul error: {0}")]
    MulError(#[from] MulError),
    #[error("rbc error: {0}")]
    RbcError(#[from] RbcError),
    #[error("share error: {0}")]
    ShareError(#[from] ShareError),
    #[error("serialization: {0}")]
    SerializationError(#[from] SerializationError),
    #[error("bincode: {0}")]
    BincodeError(#[from] Box<ErrorKind>),
    #[error("network: {0}")]
    NetworkError(#[from] NetworkError),
    #[error("interpolate: {0}")]
    InterpolateError(#[from] InterpolateError),
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
    #[error("duplicate from {0}")]
    Duplicate(usize),
    #[error("session limit")]
    LimitError,
    #[error("clear store: {0:?}")]
    ClearStoreError(SessionId),
    #[error("bad session id: {0:?}")]
    SessionIdError(SessionId),
    #[error("abort")]
    Abort,
    #[error("empty input")]
    EmptyInput,
    #[error("error in batch reconstruction: {0:?}")]
    BatchRecError(#[from] BatchReconError),
}

#[derive(Debug, Error)]
pub enum BitLTC1Error {
    #[error("pre_mulc error: {0}")]
    PreMulCError(#[from] PreMulCError),
    #[error("share error: {0}")]
    ShareError(#[from] ShareError),
    #[error("bad session id: {0:?}")]
    SessionIdError(SessionId),
    #[error("wrong input length")]
    LengthError,
    #[error("mod2 error: {0}")]
    Mod2Error(#[from] Mod2Error),
}
#[derive(Debug, Error)]
pub enum Mod2Error {
    #[error("rbc error: {0}")]
    RbcError(#[from] RbcError),
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
    #[error("clear store: {0:?}")]
    ClearStoreError(SessionId),
    #[error("abort")]
    Abort,
}

#[derive(Debug, Error)]
pub enum Mod2mError {
    #[error("batch recon error: {0:?}")]
    BatchRecError(#[from] BatchReconError),
    #[error("bit_ltc1 error: {0}")]
    BitLTC1Error(#[from] BitLTC1Error),
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

#[derive(Debug, Error)]
pub enum TruncError {
    #[error("mod2m error: {0}")]
    Mod2mError(#[from] Mod2mError),
    #[error("share error: {0}")]
    ShareError(#[from] ShareError),
}
#[derive(Debug, Error)]
pub enum LTZError {
    #[error("trunc error: {0}")]
    TruncError(#[from] TruncError),
    #[error("share error: {0}")]
    ShareError(#[from] ShareError),
}
