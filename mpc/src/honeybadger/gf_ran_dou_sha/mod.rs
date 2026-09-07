use bincode::ErrorKind;
use serde::{Deserialize, Serialize};
use stoffelnet::network_utils::{NetworkError, PartyId};
use thiserror::Error;

use crate::common::{gf2k::field::BinaryField, gf2k::share::GfShare, gf2k::Gf2kError, rbc::RbcError, share::ShareError};
use crate::honeybadger::SessionId;

pub mod gf_ran_dou_sha;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum GfRanDouShaPayload {
    Reconstruct(Vec<u8>),
    ReconstructBatch(Vec<Vec<u8>>),
    Output(bool),
}

/// Message sent in the GF(2^k) Random Double Sharing protocol.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct GfRanDouShaMessage {
    pub sender_id: PartyId,
    pub session_id: SessionId,
    pub payload: GfRanDouShaPayload,
}

impl GfRanDouShaMessage {
    pub fn new(sender_id: PartyId, session_id: SessionId, payload: GfRanDouShaPayload) -> Self {
        Self {
            sender_id,
            session_id,
            payload,
        }
    }
}

/// Payload of a reconstruction message: bundles a party's degree-`t` and degree-`2t` share of the
/// same `r_i`, bincode-serialized as a unit (mirrors `ReconstructionMessage<F>`'s ark_serialize
/// bundling — same reason as elsewhere in this track: `GfRanDouShaMessage` needs to stay
/// non-generic to slot into `WrappedMessage`, so the typed `K` payload travels as opaque bytes).
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(bound = "K: BinaryField")]
pub struct GfReconstructionMessage<K: BinaryField> {
    pub r_share_deg_t: GfShare<K>,
    pub r_share_deg_2t: GfShare<K>,
}

impl<K: BinaryField> GfReconstructionMessage<K> {
    pub fn new(r_deg_t: GfShare<K>, r_deg_2t: GfShare<K>) -> Self {
        Self {
            r_share_deg_t: r_deg_t,
            r_share_deg_2t: r_deg_2t,
        }
    }
}

/// Error for the GF(2^k) Random Double Share protocol. Mirrors `RanDouShaError`'s shape, minus
/// the ark_serialize-specific variants.
#[derive(Debug, Error)]
pub enum GfRanDouShaError {
    #[error("there was an error in the network: {0:?}")]
    NetworkError(#[from] NetworkError),
    #[error("error while serializing the object into bytes: {0:?}")]
    SerializationError(#[from] Box<ErrorKind>),
    #[error("Rbc error: {0}")]
    RbcError(#[from] RbcError),
    #[error("inner error: {0:?}")]
    Gf2kError(#[from] Gf2kError),
    #[error("received abort signal")]
    Abort,
    #[error("error sending the result: {0:?}")]
    SendError(SessionId),
    #[error("error receiving the result: {0:?}")]
    ReceiveError(SessionId),
    #[error("Share ID and Sender ID doesn't match")]
    IncorrectID,
    #[error("ShareError: {0}")]
    ShareError(#[from] ShareError),
    #[error("session ID {0:?} malformed")]
    SessionIdError(SessionId),
    #[error("limit reached")]
    LimitError,
    #[error("no such session ID exists: {0:?}")]
    NoSuchSessionId(SessionId),
    #[error("result already received: {0:?}")]
    ResultAlreadyReceived(SessionId),
    #[error("gf random double share {0:?} did not complete in time")]
    Timeout(SessionId),
}
