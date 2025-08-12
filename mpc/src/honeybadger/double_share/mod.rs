use crate::honeybadger::{
    double_share::double_share_generation::ProtocolState,
    robust_interpolate::{robust_interpolate::RobustShamirShare, InterpolateError},
    SessionId,
};
use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bincode::ErrorKind;
use serde::{Deserialize, Serialize};
use stoffelmpc_network::{NetworkError, PartyId};
use thiserror::Error;
use tokio::sync::mpsc::error::SendError;

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
    #[error("error sending the output of the protocol execution: {0:?}")]
    SendError(#[from] SendError<SessionId>),
}

#[derive(Clone,Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct DoubleShamirShare<F: FftField> {
    /// Share of degree 2t.
    pub degree_2t: RobustShamirShare<F>,
    // Share of degree t.
    pub degree_t: RobustShamirShare<F>,
}

impl<F: FftField> DoubleShamirShare<F> {
    pub fn new(degree_t: RobustShamirShare<F>, degree_2t: RobustShamirShare<F>) -> Self {
        assert!(degree_t.id == degree_2t.id);
        Self {
            degree_2t,
            degree_t,
        }
    }
}

/// Generic message for the faulty double share distribution protocol.
#[derive(Clone, Serialize, Deserialize)]
pub struct DouShaMessage {
    /// ID of the sender.
    sender_id: PartyId,
    /// ID of the session.
    pub session_id: SessionId,
    /// Payload of the message.
    payload: Vec<u8>,
}

impl DouShaMessage {
    /// Creates a new generic message for the faulty double share protocol.
    pub fn new(sender: PartyId, session_id: SessionId, payload: Vec<u8>) -> Self {
        Self {
            sender_id: sender,
            session_id,
            payload,
        }
    }
}

/// Storage for the faulty double share protocol.
#[derive(Clone,Debug)]

pub struct DouShaStorage<F>
where
    F: FftField,
{
    /// Double shares resulting from the execution of the protocol.
    pub protocol_output: Vec<DoubleShamirShare<F>>,

    /// Current state of the protocol.
    pub state: ProtocolState,

    /// Tracker for the received shares.
    ///
    /// Each time tha a party receives a share, the boolean vector in its position is set to
    /// `true`. The protocol is finished once all the flags of the vector are `true`.
    reception_tracker: Vec<bool>,
}

impl<F> DouShaStorage<F>
where
    F: FftField,
{
    /// Creates an empty storage. The
    pub fn empty(n_parties: usize) -> Self {
        Self {
            protocol_output: Vec::new(),
            reception_tracker: vec![false; n_parties],
            state: ProtocolState::NotInitialized,
        }
    }
}
