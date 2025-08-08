pub mod batch_recon;
pub use batch_recon::{apply_vandermonde, make_vandermonde};

use crate::honeybadger::robust_interpolate::InterpolateError;
use ark_serialize::SerializationError;
use bincode::ErrorKind;
use serde::{Deserialize, Serialize};
use stoffelmpc_network::{NetworkError, PartyId, SessionId};
use thiserror::Error;

/// Content type of the batch reconstruction message.
#[derive(Copy, Clone, Serialize, Deserialize, Debug)]
pub enum BatchReconContentType {
    /// The message is for the triple generation protocol.
    TripleGenMessage,
    /// The message is for the multiplication protocol.
    MultMessageFirstOpen,
    MultMessageSecondOpen,
}

/// Represents message type exchanged between network nodes during the batch reconstruction protocol.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum BatchReconMsgType {
    Eval,   // sent in the first round
    Reveal, // sent in the second round
}

///Message exchanged between network nodes during the batch reconstruction protocol.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct BatchReconMsg {
    pub session_id: SessionId,
    pub sender_id: PartyId,                  // Sender id
    pub msg_type: BatchReconMsgType,         // Message type
    pub content_type: BatchReconContentType, // Content type
    pub payload: Vec<u8>,                    // Field element
}

impl BatchReconMsg {
    pub fn new(
        sender_id: PartyId,
        session_id: SessionId,
        msg_type: BatchReconMsgType,
        content_type: BatchReconContentType,
        payload: Vec<u8>,
    ) -> Self {
        BatchReconMsg {
            sender_id,
            session_id,
            msg_type,
            payload,
            content_type,
        }
    }
}

/// Error that occurs during the execution of the Batch reconstruction.
#[derive(Debug, Error)]
pub enum BatchReconError {
    /// The error occurs when communicating using the network.
    #[error("there was an error in the network: {0:?}")]
    NetworkError(#[from] NetworkError),
    #[error("error while serializing an arkworks object: {0:?}")]
    ArkSerialization(#[from] SerializationError),
    #[error("error while serializing an arkworks object: {0:?}")]
    ArkDeserialization(SerializationError),
    #[error("error while serializing the object into bytes: {0:?}")]
    SerializationError(#[from] Box<ErrorKind>),
    /// Errors specific to invalid input parameters or conditions.
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("inner error: {0}")]
    Inner(#[from] InterpolateError),
}
