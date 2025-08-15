use crate::{
    common::share::ShareError,
    honeybadger::{
        batch_recon::BatchReconError, robust_interpolate::robust_interpolate::RobustShare,
        SessionId,
    },
};
use ark_ff::FftField;
use ark_serialize::SerializationError;
use serde::{Deserialize, Serialize};
use stoffelmpc_network::{NetworkError, PartyId};
use thiserror::Error;
use tokio::sync::mpsc::error::SendError;

pub mod multiplication;

#[derive(Clone, Debug)]
pub enum MultProtocolState {
    NotInitialized,
    Finished,
    NotFinished,
}

#[derive(Clone, Debug)]
pub struct MultStorage<F>
where
    F: FftField,
{
    pub output_open_mult: (Option<Vec<F>>, Option<Vec<F>>),
    pub inputs: (Vec<RobustShare<F>>, Vec<RobustShare<F>>),
    pub protocol_state: MultProtocolState,
    pub protocol_output: Vec<RobustShare<F>>,
    pub share_mult_from_triple: Vec<RobustShare<F>>,
}

impl<F> MultStorage<F>
where
    F: FftField,
{
    pub fn empty() -> Self {
        Self {
            output_open_mult: (None, None),
            inputs: (Vec::new(), Vec::new()),
            protocol_state: MultProtocolState::NotInitialized,
            protocol_output: Vec::new(),
            share_mult_from_triple: Vec::new(),
        }
    }
}

/// Error that occurs during the execution of the Batch reconstruction.
#[derive(Debug, Error)]
pub enum MulError {
    /// The error occurs when communicating using the network.
    #[error("there was an error in the network: {0:?}")]
    NetworkError(#[from] NetworkError),
    #[error("Shard Error: {0:?}")]
    ShareError(#[from] ShareError),
    #[error("error while serializing an arkworks object: {0:?}")]
    ArkSerialization(#[from] SerializationError),
    #[error("error while serializing an arkworks object: {0:?}")]
    ArkDeserialization(SerializationError),
    #[error("error sending the thread asynchronously")]
    SendError(#[from] SendError<SessionId>),
    #[error("Batch reconstruction error : {0:?}")]
    BatchReconError(#[from] BatchReconError),
}

/// Generic message for the multiplication protocol.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultMessage {
    /// ID of the sender of the message.
    pub sender: PartyId,
    /// Session ID of the current instance of the protocol.
    pub session_id: SessionId,
    /// Payload contained in the message.
    ///
    /// This payload is a serialized field element containing either `triple.a - x` or
    /// `triple.b - y`.
    pub payload: Vec<u8>,
}

impl MultMessage {
    /// Creates a new generic multiplication message [`MultMessage`].
    pub fn new(sender: PartyId, session_id: SessionId, payload: Vec<u8>) -> Self {
        Self {
            sender,
            session_id,
            payload,
        }
    }
}
