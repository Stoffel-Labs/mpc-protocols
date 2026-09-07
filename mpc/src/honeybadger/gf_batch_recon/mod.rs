use bincode::ErrorKind;
use serde::{Deserialize, Serialize};
use stoffelnet::network_utils::NetworkError;
use thiserror::Error;

use crate::{
    common::{gf2k::field::BinaryField, gf2k::share::GfShare, gf2k::Gf2kError},
    honeybadger::SessionId,
};

pub mod gf_batch_recon;

/// Represents message types exchanged during the GF(2^k) batch reconstruction protocol.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum GfBatchReconMsgType {
    Eval,   // sent in the first round
    Reveal, // sent in the second round
    EvalBatch,
    RevealBatch,
}

/// Message exchanged between network nodes during the GF(2^k) batch reconstruction protocol.
/// `payload` holds bincode-serialized `GfShare<K>`/`Vec<K>` bytes rather than a typed value
/// directly — same rationale as `gf_share_gen::GfRanShaMessage`: this needs to slot into the
/// crate-wide, non-generic `WrappedMessage` envelope, which can't have a generic variant.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct GfBatchReconMsg {
    pub session_id: SessionId,
    pub sender_id: usize,
    pub msg_type: GfBatchReconMsgType,
    pub payload: Vec<u8>,
}

impl GfBatchReconMsg {
    pub fn new(
        sender_id: usize,
        session_id: SessionId,
        msg_type: GfBatchReconMsgType,
        payload: Vec<u8>,
    ) -> Self {
        GfBatchReconMsg {
            sender_id,
            session_id,
            msg_type,
            payload,
        }
    }
}

#[derive(Debug)]
pub struct GfBatchReconStore<K: BinaryField> {
    pub evals_received: Vec<GfShare<K>>,
    pub reveals_received: Vec<GfShare<K>>,
    pub batch_evals_received: Vec<(usize, Vec<K>)>,
    pub batch_reveals_received: Vec<(usize, Vec<K>)>,
    pub y_j: Option<GfShare<K>>,
    pub y_j_batch: Option<Vec<K>>,
    /// The finally reconstructed original secrets (polynomial coefficients), bincode-serialized.
    pub secrets: Option<Vec<u8>>,
}

impl<K: BinaryField> GfBatchReconStore<K> {
    pub fn empty() -> Self {
        Self {
            evals_received: vec![],
            reveals_received: vec![],
            batch_evals_received: vec![],
            batch_reveals_received: vec![],
            y_j: None,
            y_j_batch: None,
            secrets: None,
        }
    }
}

/// Error type for the GF(2^k) batch reconstruction protocol. Mirrors `BatchReconError`'s shape,
/// minus the ark_serialize-specific variants — this track uses `bincode`/`serde` throughout.
#[derive(Debug, Error)]
pub enum GfBatchReconError {
    #[error("there was an error in the network: {0:?}")]
    NetworkError(#[from] NetworkError),
    #[error("inner error: {0:?}")]
    Gf2kError(#[from] Gf2kError),
    #[error("error while serializing/deserializing bytes: {0:?}")]
    SerializationError(#[from] Box<ErrorKind>),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("error sending the output of the batch reconstruction")]
    SendError,
}
