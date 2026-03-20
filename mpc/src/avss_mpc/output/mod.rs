pub mod output;

use crate::common::{rbc::RbcError, share::ShareError};
use ark_serialize::SerializationError;
use bincode::ErrorKind;
use serde::{Deserialize, Serialize};
use stoffelnet::network_utils::NetworkError;
use thiserror::Error;
use tokio::{sync::watch::error::RecvError, time::error::Elapsed};

#[derive(Debug, Error)]
pub enum AvssOutputError {
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
    #[error("error while waiting for output")]
    WaitingError(#[from] RecvError),
    #[error("client {0:?} did not receive output in time")]
    Timeout(#[from] Elapsed),
}

/// Message sent in the AVSS Output protocol.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct AvssOutputMessage {
    /// ID of the sender of the message
    pub sender_id: usize,
    /// Serialized payload
    pub payload: Vec<u8>,
}

impl AvssOutputMessage {
    pub fn new(sender_id: usize, payload: Vec<u8>) -> AvssOutputMessage {
        Self { sender_id, payload }
    }
}
