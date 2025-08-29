pub mod output;

use ark_serialize::SerializationError;
use bincode::ErrorKind;
use serde::{Deserialize, Serialize};
use stoffelnet::network_utils::NetworkError;
use thiserror::Error;

use crate::{common::rbc::RbcError, honeybadger::robust_interpolate::InterpolateError};


#[derive(Debug, Error)]
pub enum OutputError {
    #[error("inner error: {0}")]
    RbcError(#[from] RbcError),
    #[error("there was an error in the network: {0:?}")]
    NetworkError(#[from] NetworkError),
    #[error("error while serializing an arkworks object: {0:?}")]
    ArkSerialization(#[from] SerializationError),
    #[error("error while serializing an arkworks object: {0:?}")]
    ArkDeserialization(SerializationError),
    #[error("error while serializing the object into bytes: {0:?}")]
    SerializationError(#[from] Box<ErrorKind>),
    #[error("Incorrect input: {0}")]
    InvalidInput(String),
    #[error("Duplicate input: {0}")]
    Duplicate(String),
    #[error("Interpolate error: {0:?}")]
    InterpolateError(#[from] InterpolateError),
}

/// Message sent in the Random Double Sharing protocol.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OutputMessage {
    /// ID of the sender of the message or the client
    pub sender_id: usize,
    pub payload: Vec<u8>,
}

impl OutputMessage {
    pub fn new(sender_id: usize,  payload: Vec<u8>) -> OutputMessage {
        Self {
            sender_id,
            payload,
        }
    }
}
