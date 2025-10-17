use crate::{
    common::{rbc::RbcError, share::ShareError},
    honeybadger::{
        batch_recon::BatchReconError,
        robust_interpolate::{robust_interpolate::RobustShare, InterpolateError},
        SessionId,
    },
};
use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use bincode::ErrorKind;
use serde::{Deserialize, Serialize};
use std::{sync::Arc, collections::HashMap};
use stoffelnet::network_utils::{NetworkError, PartyId};
use thiserror::Error;
use tokio::sync::{oneshot::{error::RecvError, channel, Sender, Receiver}};

pub mod multiplication;

#[derive(Clone, Debug, PartialEq)]
pub enum MultProtocolState {
    NotInitialized,
    Finished,
    NotFinished,
}

#[derive(Debug)]
pub struct MultStorage<F>
where
    F: FftField,
{
    pub no_of_mul: Option<usize>,
    /// opened a-x values reconstructed using batch reconstruction
    pub output_open_mult1: HashMap<u8, Vec<F>>,
    /// opened b-y values reconstructed using batch reconstruction
    pub output_open_mult2: HashMap<u8, Vec<F>>,
    pub inputs: (Vec<RobustShare<F>>, Vec<RobustShare<F>>),
    pub protocol_state: MultProtocolState,
    pub share_mult_from_triple: Vec<RobustShare<F>>,
    /// shares for reconstruction using RBC
    pub received_shares: HashMap<PartyId, (Vec<RobustShare<F>>, Vec<RobustShare<F>>)>,
    /// opened a-x and b-y values reconstructed using RBC
    pub openings: Option<(Vec<F>, Vec<F>)>,
    pub output_sender: Option<Sender<Vec<RobustShare<F>>>>,
    pub output_receiver: Option<Receiver<Vec<RobustShare<F>>>>
}

impl<F> MultStorage<F>
where
    F: FftField,
{
    pub fn empty() -> Self {
        let (output_sender, output_receiver) = channel();

        Self {
            no_of_mul: None,
            output_open_mult1: HashMap::new(),
            output_open_mult2: HashMap::new(),
            inputs: (Vec::new(), Vec::new()),
            protocol_state: MultProtocolState::NotInitialized,
            share_mult_from_triple: Vec::new(),
            received_shares: HashMap::new(),
            openings: None,
            output_sender: Some(output_sender),
            output_receiver: Some(output_receiver)
        }
    }
}

/// Error that occurs during the execution of the Batch reconstruction.
#[derive(Debug, Error)]
pub enum MulError {
    /// The error occurs when communicating using the network.
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
    #[error("Batch reconstruction error : {0:?}")]
    BatchReconError(#[from] BatchReconError),
    #[error("Duplicate input: {0}")]
    Duplicate(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("error during the serialization using bincode: {0:?}")]
    BincodeSerializationError(#[from] Box<ErrorKind>),
    #[error("Interpolate error: {0:?}")]
    InterpolateError(#[from] InterpolateError),
    #[error("no such session ID exists: {0:?}")]
    NoSuchSessionId(SessionId),
    #[error("result already received: {0:?}")]
    ResultAlreadyReceived(SessionId),
    #[error("waiting for more openings")]
    WaitForOk,
    #[error("multiplication {0:?} did not complete in time")]
    Timeout(SessionId)
}

/// Generic message for the multiplication protocol.
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
pub struct ReconstructionMessage<F: FftField> {
    pub a_sub_x: Vec<RobustShare<F>>,
    pub b_sub_y: Vec<RobustShare<F>>,
}

impl<F> ReconstructionMessage<F>
where
    F: FftField,
{
    /// Creates a message for the reconstruction phase.
    pub fn new(a_sub_x: Vec<RobustShare<F>>, b_sub_y: Vec<RobustShare<F>>) -> Self {
        Self { a_sub_x, b_sub_y }
    }
}

pub fn concat_sorted<F: FftField>(map: &HashMap<u8, Vec<F>>) -> Vec<F> {
    // collect and sort keys
    let mut keys: Vec<_> = map.keys().cloned().collect();
    keys.sort_unstable();

    // pre-compute total size to reserve capacity
    let total_len: usize = keys.iter().map(|k| map[k].len()).sum();

    // build result with exact capacity
    let mut out = Vec::with_capacity(total_len);
    for k in keys {
        out.extend_from_slice(&map[&k]);
    }
    out
}
