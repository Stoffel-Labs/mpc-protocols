use std::collections::HashMap;

use ark_ff::FftField;
use ark_serialize::SerializationError;
use bincode::ErrorKind;
use serde::{Deserialize, Serialize};
use stoffelmpc_network::NetworkError;
use thiserror::Error;

use crate::{
    common::{
        rbc::RbcError,
        share::ShareError,
    },
    honeybadger::{robust_interpolate::{robust_interpolate::RobustShamirShare, InterpolateError}, SessionId},
};

pub mod share_gen;

/// Error type for the Random Single Share (RanSha) protocol.
#[derive(Debug, Error)]
pub enum RanShaError {
    #[error("there was an error in the network: {0:?}")]
    NetworkError(NetworkError),
    #[error("error while serializing an arkworks object: {0:?}")]
    ArkSerialization(SerializationError),
    #[error("error while serializing an arkworks object: {0:?}")]
    ArkDeserialization(SerializationError),
    #[error("error while serializing the object into bytes: {0:?}")]
    SerializationError(Box<ErrorKind>),
    #[error("inner error: {0:?}")]
    Inner(#[from] InterpolateError),
    #[error("Rbc error: {0:?}")]
    RbcError(RbcError),
    #[error("Share error: {0:?}")]
    ShareError(ShareError),
    #[error("received abort signal")]
    Abort,
    #[error("waiting for more confirmations")]
    WaitForOk,
}

#[derive(Clone,Debug)]
pub struct RanShaStore<F: FftField> {
    pub received_r_shares: HashMap<usize, RobustShamirShare<F>>,
    pub computed_r_shares: Vec<RobustShamirShare<F>>,
    pub received_ok_msg: Vec<usize>,
    pub state: RanShaState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RanShaState {
    Initialized,
    Reconstruction,
    Output,
    Finished,
}

impl<F: FftField> RanShaStore<F> {
    pub fn empty() -> Self {
        Self {
            received_r_shares: HashMap::new(),
            computed_r_shares: Vec::new(),
            received_ok_msg: Vec::new(),
            state: RanShaState::Initialized,
        }
    }
}

/// Types for all the possible messages sent during the Random Single Sharing protocol.
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub enum RanShaMessageType {
    /// Tag for the message received by the reconstruction handler.
    ReconstructMessage,
    /// Tag for the message received by the output handler.
    OutputMessage,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum RanShaPayload {
    /// Contains the share of r sent during reconstruction.
    Reconstruct(Vec<u8>),
    /// Output message confirming reconstruction success or failure.
    Output(bool),
}

/// Message sent in the Random Single Sharing protocol.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RanShaMessage {
    /// ID of the sender of the message.
    pub sender_id: usize,
    /// Type of the message according to the handler.
    pub msg_type: RanShaMessageType,
    /// Session ID of the execution.
    pub session_id: SessionId,
    /// Contents of the message.
    pub payload: RanShaPayload,
}

impl RanShaMessage {
    pub fn new(
        sender_id: usize,
        msg_type: RanShaMessageType,
        session_id: SessionId,
        payload: RanShaPayload,
    ) -> Self {
        Self {
            sender_id,
            msg_type,
            session_id,
            payload,
        }
    }
}