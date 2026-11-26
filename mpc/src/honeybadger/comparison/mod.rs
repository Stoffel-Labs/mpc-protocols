use crate::honeybadger::bitwise::{KOrCLError, PreMod2mError};
use crate::{
    common::{rbc::RbcError, share::ShareError},
    honeybadger::SessionId,
};
use ark_serialize::SerializationError;
use serde::{Deserialize, Serialize};
use stoffelnet::network_utils::{NetworkError, PartyId};
use thiserror::Error;

pub mod eqz;
pub mod ltz;

/// Direct point-to-point opening of EQZ's own share of `c`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EqzMessage {
    pub sender: PartyId,
    pub session_id: SessionId,
    pub payload: Vec<u8>,
}

impl EqzMessage {
    pub fn new(sender: PartyId, session_id: SessionId, payload: Vec<u8>) -> Self {
        Self {
            sender,
            session_id,
            payload,
        }
    }
}

/// Raw pool draws one `LTZ(k)` consumes: `(triples, prandbit, prandint)`.
/// LTZ runs PreMod2m(k, m = k-1), whose PRandM(k, m) mask costs 1 PRandInt +
/// m PRandBits, and whose inner PreBitLT (on m bits) costs m-1 triples plus m
/// degenerate Mod2 PRandM bundles (1 PRandInt + 1 PRandBit each).
/// The PreMulC bundle it also needs is counted separately (`len.premulc`).
pub fn ltz_prep_counts(k: usize) -> (usize, usize, usize) {
    let m = k - 1;
    (m - 1, 2 * m, 1 + m)
}

/// Raw pool draws one `EQZ(k)` consumes: `(triples, prandbit, prandint,
/// rand_inv_pairs)`, where `m = floor(log2(k)) + 1` is KOrCL's reduced width.
/// The two PRandM masks (k-bit for EQZ, m-bit for KOrCL) cost 1 PRandInt each;
/// KOrCS needs m pairs plus (m-1) + m triples across its two Multiply rounds.
pub fn eqz_prep_counts(k: usize) -> (usize, usize, usize, usize) {
    let m = (k as u32).ilog2() as usize + 1;
    ((2 * m).saturating_sub(1), k + m, 2, m)
}

#[derive(Debug, Error)]
pub enum LTZError {
    #[error("PreMod2m error: {0}")]
    PreMod2mError(#[from] PreMod2mError),
    #[error("share error: {0}")]
    ShareError(#[from] ShareError),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("session ID error: {0:?}")]
    SessionIdError(SessionId),
}

#[derive(Debug, Error)]
pub enum EQZError {
    #[error("rbc error: {0}")]
    RbcError(#[from] RbcError),
    #[error("there was an error in the network: {0:?}")]
    NetworkError(#[from] NetworkError),
    #[error("share error: {0}")]
    ShareError(#[from] ShareError),
    #[error("kor_cl error: {0}")]
    KOrCLError(#[from] KOrCLError),
    #[error("serialization: {0}")]
    SerializationError(#[from] SerializationError),
    #[error("error during the serialization using bincode: {0:?}")]
    BincodeSerializationError(#[from] Box<bincode::ErrorKind>),
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
    #[error("wrong input length")]
    LengthError,
}
