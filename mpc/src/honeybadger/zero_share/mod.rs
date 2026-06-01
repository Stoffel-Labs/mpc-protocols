use crate::{
    common::{rbc::RbcError, share::ShareError},
    honeybadger::{
        robust_interpolate::{robust_interpolate::RobustShare, InterpolateError},
        SessionId,
    },
};
use ark_ff::FftField;
use ark_serialize::SerializationError;
use bincode::ErrorKind;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use stoffelnet::network_utils::NetworkError;
use thiserror::Error;
use tokio::sync::oneshot::{channel, Receiver, Sender};

pub mod zero_share;

#[derive(Debug, Error)]
pub enum ZeroShaError {
    #[error("there was an error in the network: {0:?}")]
    NetworkError(#[from] NetworkError),
    #[error("error while serializing an arkworks object: {0:?}")]
    ArkSerialization(#[from] SerializationError),
    #[error("error while serializing an arkworks object: {0:?}")]
    ArkDeserialization(SerializationError),
    #[error("error while serializing the object into bytes: {0:?}")]
    SerializationError(#[from] Box<ErrorKind>),
    #[error("inner error: {0:?}")]
    InterpolateError(#[from] InterpolateError),
    #[error("Rbc error: {0:?}")]
    RbcError(#[from] RbcError),
    #[error("Share error: {0:?}")]
    ShareError(#[from] ShareError),
    #[error("error sending the result: {0:?}")]
    SendError(SessionId),
    #[error("error receiving the result: {0:?}")]
    ReceiveError(SessionId),
    #[error("received abort signal")]
    Abort,
    #[error("Party Id is out of bounds")]
    InvalidPartyId,
    #[error("session ID {0:?} malformed")]
    SessionIdError(SessionId),
    #[error("limit reached")]
    LimitError,
    #[error("no such session ID exists: {0:?}")]
    NoSuchSessionId(SessionId),
    #[error("result already received: {0:?}")]
    ResultAlreadyReceived(SessionId),
    #[error("multiplication {0:?} did not complete in time")]
    Timeout(SessionId),
    #[error("reconstructed secret is not zero — malicious sharing detected")]
    NotZero,
}

#[derive(Debug)]
pub struct ZeroShaStore<F: FftField> {
    pub initial_shares: HashMap<usize, RobustShare<F>>,
    pub reception_tracker: Vec<bool>,
    pub received_r_shares: HashMap<usize, RobustShare<F>>,
    pub computed_r_shares: Vec<RobustShare<F>>,
    pub received_ok_msg: Vec<usize>,
    pub state: ZeroShaState,
    pub protocol_output: Vec<RobustShare<F>>,
    pub output_sender: Option<Sender<Vec<RobustShare<F>>>>,
    pub output_receiver: Option<Receiver<Vec<RobustShare<F>>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZeroShaState {
    Initialized,
    FinishedInitialSharing,
    Reconstruction,
    Finished,
}

impl<F: FftField> ZeroShaStore<F> {
    pub fn empty(n_parties: usize) -> Self {
        let (output_sender, output_receiver) = channel();
        Self {
            initial_shares: HashMap::new(),
            reception_tracker: vec![false; n_parties],
            received_r_shares: HashMap::new(),
            computed_r_shares: Vec::new(),
            received_ok_msg: Vec::new(),
            state: ZeroShaState::Initialized,
            protocol_output: Vec::new(),
            output_sender: Some(output_sender),
            output_receiver: Some(output_receiver),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub enum ZeroShaMessageType {
    ShareMessage,
    ReconstructMessage,
    OutputMessage,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum ZeroShaPayload {
    Share(Vec<u8>),
    Reconstruct(Vec<u8>),
    Output(bool),
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ZeroShaMessage {
    pub sender_id: usize,
    pub msg_type: ZeroShaMessageType,
    pub session_id: SessionId,
    pub payload: ZeroShaPayload,
}

impl ZeroShaMessage {
    pub fn new(
        sender_id: usize,
        msg_type: ZeroShaMessageType,
        session_id: SessionId,
        payload: ZeroShaPayload,
    ) -> Self {
        Self {
            sender_id,
            msg_type,
            session_id,
            payload,
        }
    }
}
