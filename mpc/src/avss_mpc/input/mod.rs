pub mod input;

use crate::common::{rbc::RbcError, share::ShareError};
use ark_serialize::SerializationError;
use bincode::ErrorKind;
use serde::{Deserialize, Serialize};
use stoffelnet::network_utils::NetworkError;
use thiserror::Error;
use tokio::{sync::watch::error::RecvError, time::error::Elapsed};

#[derive(Debug, Error)]
pub enum AvssInputError {
    #[error("inner error: {0}")]
    RbcError(#[from] RbcError),
    #[error("there was an error in the network: {0:?}")]
    NetworkError(#[from] NetworkError),
    #[error("error while serializing an arkworks object: {0:?}")]
    ArkSerialization(#[from] SerializationError),
    #[error("error while serializing the object into bytes: {0:?}")]
    SerializationError(#[from] Box<ErrorKind>),
    #[error("Incorrect input: {0}")]
    InvalidInput(String),
    #[error("Duplicate input: {0}")]
    Duplicate(String),
    #[error("Share error: {0:?}")]
    ShareError(#[from] ShareError),
    #[error("Feldman verification failed: {0}")]
    VerificationFailed(String),
    #[error("error while waiting for all inputs")]
    WaitingError(#[from] RecvError),
    #[error("client {0:?} did not send input in time")]
    Timeout(#[from] Elapsed),
    #[error("Channel closed")]
    Abort,
}

/// Message sent in the AVSS Input protocol.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AvssInputMessage {
    /// ID of the sender of the message or the client
    pub sender_id: usize,
    /// Serialized payload
    pub payload: Vec<u8>,
}

impl AvssInputMessage {
    pub fn new(sender_id: usize, payload: Vec<u8>) -> AvssInputMessage {
        Self { sender_id, payload }
    }
}
