pub mod multiplication;

use crate::{
    common::{
        rbc::RbcError,
        share::{feldman::FeldmanShamirShare, ShareError},
    },
    honeybadger::SessionId,
};
use ark_ec::CurveGroup;
use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use bincode::ErrorKind;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use stoffelnet::network_utils::{NetworkError, PartyId};
use thiserror::Error;
use tokio::sync::oneshot::{channel, Receiver, Sender};

#[derive(Debug, Error)]
pub enum MulError {
    #[error("there was an error in the network: {0:?}")]
    NetworkError(#[from] NetworkError),
    #[error("Shard Error: {0:?}")]
    ShareError(#[from] ShareError),
    #[error("error in the RBC: {0:?}")]
    RbcError(#[from] RbcError),
    #[error("error while serializing an arkworks object: {0:?}")]
    ArkSerialization(#[from] SerializationError),
    #[error("error while serializing an arkworks object: {0:?}")]
    ArkDeserialization(SerializationError),
    #[error("error sending the result: {0:?}")]
    SendError(SessionId),
    #[error("error receiving the result: {0:?}")]
    ReceiveError(SessionId),
    #[error("Duplicate input: {0}")]
    Duplicate(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("error during the serialization using bincode: {0:?}")]
    BincodeSerializationError(#[from] Box<ErrorKind>),
    #[error("no such session ID exists: {0:?}")]
    NoSuchSessionId(SessionId),
    #[error("result already received: {0:?}")]
    ResultAlreadyReceived(SessionId),
    #[error("waiting for more openings")]
    WaitForOk,
    #[error("multiplication {0:?} did not complete in time")]
    Timeout(SessionId),
}

#[derive(Clone, Debug, PartialEq)]
pub enum MultProtocolState {
    NotInitialized,
    Finished,
    NotFinished,
}

#[derive(Debug)]
pub struct MultStorage<F, G>
where
    F: FftField,
    G: CurveGroup<ScalarField = F>,
{
    pub no_of_mul: Option<usize>,
    pub inputs: (Vec<FeldmanShamirShare<F, G>>, Vec<FeldmanShamirShare<F, G>>),
    pub share_mult_from_triple: Vec<FeldmanShamirShare<F, G>>,
    /// shares for reconstruction using RBC
    pub received_shares:
        HashMap<PartyId, (Vec<FeldmanShamirShare<F, G>>, Vec<FeldmanShamirShare<F, G>>)>,
    /// opened a-x and b-y values reconstructed using RBC
    pub openings: Option<(Vec<F>, Vec<F>)>,
    pub output_sender: Option<Sender<Vec<FeldmanShamirShare<F, G>>>>,
    pub output_receiver: Option<Receiver<Vec<FeldmanShamirShare<F, G>>>>,
    pub protocol_state: MultProtocolState,
}

impl<F, G> MultStorage<F, G>
where
    F: FftField,
    G: CurveGroup<ScalarField = F>,
{
    pub fn empty() -> Self {
        let (output_sender, output_receiver) = channel();

        Self {
            no_of_mul: None,
            inputs: (Vec::new(), Vec::new()),
            share_mult_from_triple: Vec::new(),
            received_shares: HashMap::new(),
            openings: None,
            output_sender: Some(output_sender),
            output_receiver: Some(output_receiver),
            protocol_state: MultProtocolState::NotInitialized,
        }
    }
}

// Generic message for the multiplication protocol.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultMessage {
    /// ID of the sender of the message.
    pub sender: PartyId,
    /// Session ID of the current instance of the protocol.
    pub session_id: SessionId,
    /// Payload contained in the message.
    ///
    /// This payload is a serialized field element containing either `triple.a - x` or
    /// `triple.b - y`.
    pub payload: Vec<u8>,
}

impl MultMessage {
    /// Creates a new generic multiplication message [`MultMessage`].
    pub fn new(sender: PartyId, session_id: SessionId, payload: Vec<u8>) -> Self {
        Self {
            sender,
            session_id,
            payload,
        }
    }
}

#[derive(CanonicalDeserialize, CanonicalSerialize)]
pub struct ReconstructionMessage<F: FftField, G: CurveGroup<ScalarField = F>> {
    pub a_sub_x: Vec<FeldmanShamirShare<F, G>>,
    pub b_sub_y: Vec<FeldmanShamirShare<F, G>>,
}

impl<F, G> ReconstructionMessage<F, G>
where
    F: FftField,
    G: CurveGroup<ScalarField = F>,
{
    /// Creates a message for the reconstruction phase.
    pub fn new(
        a_sub_x: Vec<FeldmanShamirShare<F, G>>,
        b_sub_y: Vec<FeldmanShamirShare<F, G>>,
    ) -> Self {
        Self { a_sub_x, b_sub_y }
    }
}
