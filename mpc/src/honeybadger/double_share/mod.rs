use crate::{
    common::share::{shamir::NonRobustShare, ShareError},
    honeybadger::{
        double_share::double_share_generation::ProtocolState, robust_interpolate::InterpolateError,
        SessionId,
    },
};
use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bincode::ErrorKind;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use stoffelnet::network_utils::{NetworkError, PartyId};
use thiserror::Error;
use tokio::sync::oneshot::{channel, Receiver, Sender};

pub mod double_share_generation;

/// Error for the faulty double share distribution protocol.
#[derive(Debug, Error)]
pub enum DouShaError {
    /// The sender ID does not match with the expected ID.
    #[error(
        "sender mismatch: expected sender: {expected_sender:?}, actual_sender: {actual_sender:?}"
    )]
    SenderMismatch {
        expected_sender: PartyId,
        actual_sender: PartyId,
    },
    /// There was an error when manipulating shares.
    #[error("error in share: {0:?}")]
    InterpolateError(#[from] InterpolateError),
    /// Error in the serialization using `arkworks`.
    #[error("ark serialization error: {0:?}")]
    ArkSerializationError(#[from] ark_serialize::SerializationError),
    /// Error in the serialization using `bincode`.
    #[error("bincode serialization error: {0:?}")]
    BincodeSerializationError(#[from] Box<ErrorKind>),
    /// Error during a network operation.
    #[error("error in the network: {0:?}")]
    NetworkError(#[from] NetworkError),
    #[error("error sending the result: {0:?}")]
    SendError(SessionId),
    #[error("error receiving the result: {0:?}")]
    ReceiveError(SessionId),
    #[error("ShareError: {0}")]
    ShareError(#[from] ShareError),
    #[error("Party Id is out of bounds")]
    InvalidPartyId,
    #[error("no such session ID exists: {0:?}")]
    NoSuchSessionId(SessionId),
    #[error("result already received: {0:?}")]
    ResultAlreadyReceived(SessionId),
    #[error("multiplication {0:?} did not complete in time")]
    Timeout(SessionId),
    #[error("Store Limit")]
    LimitError,
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct DoubleShamirShare<F: FftField> {
    /// Share of degree 2t.
    pub degree_2t: NonRobustShare<F>,
    // Share of degree t.
    pub degree_t: NonRobustShare<F>,
}

impl<F: FftField> DoubleShamirShare<F> {
    pub fn new(degree_t: NonRobustShare<F>, degree_2t: NonRobustShare<F>) -> Self {
        assert!(degree_t.id == degree_2t.id);
        Self {
            degree_2t,
            degree_t,
        }
    }
}

/// Payload for one or more faulty double shares.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DouShaPayload {
    Share(Vec<u8>),
    Shares(Vec<u8>),
}

/// Generic message for the faulty double share distribution protocol.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DouShaMessage {
    /// ID of the sender.
    pub sender_id: PartyId,
    /// ID of the session.
    pub session_id: SessionId,
    /// Payload of the message.
    pub payload: DouShaPayload,
}

impl DouShaMessage {
    /// Creates a new generic message for the faulty double share protocol.
    pub fn new(sender: PartyId, session_id: SessionId, payload: DouShaPayload) -> Self {
        Self {
            sender_id: sender,
            session_id,
            payload,
        }
    }
}

/// Storage for the faulty double share protocol.
#[derive(Debug)]

pub struct DouShaStorage<F>
where
    F: FftField,
{
    /// Double shares resulting from the execution of the protocol.
    pub protocol_output: Vec<DoubleShamirShare<F>>,
    pub share: BTreeMap<usize, Vec<DoubleShamirShare<F>>>,
    pub batch_size: usize,

    /// Current state of the protocol.
    pub state: ProtocolState,

    /// Tracker for the received shares.
    ///
    /// Each time tha a party receives a share, the boolean vector in its position is set to
    /// `true`. The protocol is finished once all the flags of the vector are `true`.
    reception_tracker: Vec<bool>,
    pub output_sender: Option<Sender<Vec<DoubleShamirShare<F>>>>,
    pub output_receiver: Option<Receiver<Vec<DoubleShamirShare<F>>>>,
}

impl<F> DouShaStorage<F>
where
    F: FftField,
{
    /// Creates an empty storage. The
    pub fn empty(n_parties: usize) -> Self {
        let (output_sender, output_receiver) = channel();
        Self {
            protocol_output: Vec::new(),
            share: BTreeMap::new(),
            batch_size: 1,
            reception_tracker: vec![false; n_parties],
            state: ProtocolState::NotInitialized,
            output_sender: Some(output_sender),
            output_receiver: Some(output_receiver),
        }
    }
}
