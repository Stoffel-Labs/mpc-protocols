pub mod batch_recon;

use crate::honeybadger::robust_interpolate::InterpolateError;
use ark_serialize::SerializationError;
use bincode::ErrorKind;
use serde::{Deserialize, Serialize};
use stoffelmpc_network::NetworkError;
use thiserror::Error;

/// Represents message type exchanged between network nodes during the batch reconstruction protocol.
#[derive(Clone, Serialize, Deserialize)]
pub enum BatchReconMsgType {
    Eval,   // sent in the first round
    Reveal, // sent in the second round
}
///Message exchanged between network nodes during the batch reconstruction protocol.
#[derive(Clone, Serialize, Deserialize)]
pub struct BatchReconMsg {
    pub sender_id: usize,            //Sender id
    pub msg_type: BatchReconMsgType, //Message type
    pub payload: Vec<u8>,            //field element
}

impl BatchReconMsg {
    pub fn new(sender_id: usize, msg_type: BatchReconMsgType, payload: Vec<u8>) -> Self {
        BatchReconMsg {
            sender_id,
            msg_type,
            payload,
        }
    }
}

/// Error that occurs during the execution of the Batch reconstruction.
#[derive(Debug, Error)]
pub enum BatchReconError {
    /// The error occurs when communicating using the network.
    #[error("there was an error in the network: {0:?}")]
    NetworkError(NetworkError),
    #[error("error while serializing an arkworks object: {0:?}")]
    ArkSerialization(SerializationError),
    #[error("error while serializing an arkworks object: {0:?}")]
    ArkDeserialization(SerializationError),
    #[error("error while serializing the object into bytes: {0:?}")]
    SerializationError(Box<ErrorKind>),
    /// Errors specific to invalid input parameters or conditions.
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("inner error: {0}")]
    Inner(#[from] InterpolateError),
}
