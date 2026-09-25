use crate::{common::rbc::RbcError, honeybadger::robust_interpolate::InterpolateError};
use ark_serialize::SerializationError;
use bincode::ErrorKind;
use serde::{Deserialize, Serialize};
use stoffelnet::network_utils::{ClientId, NetworkError};
use thiserror::Error;
use tokio::{sync::watch::error::RecvError, time::error::Elapsed};

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
    Timeout(#[from] Elapsed),
    #[error("Channel closed")]
    Abort,
    #[error(
        "client id {0} is invalid: it must satisfy {1} <= id <= 255 (ids below {1} collide with \
         consensus node ids; ids above 255 cannot fit the session id's 8-bit sub-id field)"
    )]
    InvalidClientId(ClientId, usize),
}

/// Message sent in the Random Double Sharing protocol.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct InputMessage {
    /// ID of the sender of the message or the client
    pub sender_id: usize,
    /// Execution this direct packet belongs to — checked against the receiving handler's own
    /// `instance_id` before the packet is allowed to touch protocol state, so a share replayed
    /// or delayed from a prior execution can't be mistaken for one from the current run.
    pub instance_id: u32,
    /// Type of the message according to the handler.
    pub payload: Vec<u8>,
}

impl InputMessage {
    pub fn new(sender_id: usize, instance_id: u32, payload: Vec<u8>) -> InputMessage {
        Self {
            sender_id,
            instance_id,
            payload,
        }
    }
}
