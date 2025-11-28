use crate::{common::rbc::RbcError, honeybadger::robust_interpolate::InterpolateError};
use ark_serialize::SerializationError;
use bincode::ErrorKind;
use serde::{Deserialize, Serialize};
use stoffelnet::network_utils::{ClientId, NetworkError};
use tokio::{time::error::Elapsed, sync::watch::error::RecvError};
use thiserror::Error;

pub mod input;

#[derive(Debug, Error)]
pub enum InputError {
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
    #[error("error while waiting for all inputs")]
    WaitingError(#[from] RecvError),
    #[error("client {0:?} did not sent input in time")]
    Timeout(#[from] Elapsed)
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub enum InputMessageType {
    MaskShare,
    MaskedInput,
}

/// Message sent in the Random Double Sharing protocol.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct InputMessage {
    /// ID of the sender of the message or the client
    pub sender_id: usize,
    /// Type of the message according to the handler.
    pub msg_type: InputMessageType,

    pub payload: Vec<u8>,
}

impl InputMessage {
    pub fn new(sender_id: usize, msg_type: InputMessageType, payload: Vec<u8>) -> InputMessage {
        Self {
            sender_id,
            msg_type,
            payload,
        }
    }
}
