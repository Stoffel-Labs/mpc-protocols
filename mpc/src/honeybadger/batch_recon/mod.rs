pub mod batch_recon;

use crate::honeybadger::{
    robust_interpolate::{robust_interpolate::RobustShare, InterpolateError},
    SessionId,
};
use ark_ff::FftField;
use ark_serialize::SerializationError;
use bincode::ErrorKind;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use stoffelnet::network_utils::NetworkError;
use thiserror::Error;

/// Represents message type exchanged between network nodes during the batch reconstruction protocol.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum BatchReconMsgType {
    Eval,   // sent in the first round
    Reveal, // sent in the second round
}

///Message exchanged between network nodes during the batch reconstruction protocol.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct BatchReconMsg {
    pub session_id: SessionId,
    pub sender_id: usize,            //Sender id
    pub msg_type: BatchReconMsgType, //Message type
    pub payload: Vec<u8>,            //field element
}
impl BatchReconMsg {
    pub fn new(
        sender_id: usize,
        session_id: SessionId,
        msg_type: BatchReconMsgType,
        payload: Vec<u8>,
    ) -> Self {
        BatchReconMsg {
            sender_id,
            session_id,
            msg_type,
            payload,
        }
    }
}

pub struct BatchReconStore<F: FftField> {
    pub evals_received: Vec<RobustShare<F>>,   // Stores (sender_id, eval_share) messages
    pub reveals_received: Vec<RobustShare<F>>, // Stores (sender_id, y_j_value) messages
    pub evals_seen: HashSet<usize>,            // O(1) deduplication for eval senders
    pub reveals_seen: HashSet<usize>,          // O(1) deduplication for reveal senders
    pub y_j: Option<RobustShare<F>>,           // The interpolated y_j value for this node's index
    pub secrets: Option<Vec<F>>, // The finally reconstructed original secrets (polynomial coefficients)
    pub eval_interpolation_claimed: AtomicBool,   // Prevents race on eval interpolation
    pub reveal_interpolation_claimed: AtomicBool, // Prevents race on reveal interpolation
}

impl<F: FftField> BatchReconStore<F> {
    pub fn empty() -> Self {
        Self {
            evals_received: vec![],
            reveals_received: vec![],
            evals_seen: HashSet::new(),
            reveals_seen: HashSet::new(),
            y_j: None,
            secrets: None,
            eval_interpolation_claimed: AtomicBool::new(false),
            reveal_interpolation_claimed: AtomicBool::new(false),
        }
    }

    /// Creates a new store with pre-allocated capacity for expected number of shares.
    pub fn with_capacity(n: usize) -> Self {
        Self {
            evals_received: Vec::with_capacity(n),
            reveals_received: Vec::with_capacity(n),
            evals_seen: HashSet::with_capacity(n),
            reveals_seen: HashSet::with_capacity(n),
            y_j: None,
            secrets: None,
            eval_interpolation_claimed: AtomicBool::new(false),
            reveal_interpolation_claimed: AtomicBool::new(false),
        }
    }

    /// Atomically claim eval interpolation rights. Returns true if this caller won.
    pub fn try_claim_eval_interpolation(&self) -> bool {
        self.eval_interpolation_claimed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    /// Atomically claim reveal interpolation rights. Returns true if this caller won.
    pub fn try_claim_reveal_interpolation(&self) -> bool {
        self.reveal_interpolation_claimed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }
}

/// Error that occurs during the execution of the Batch reconstruction.
#[derive(Debug, Error)]
pub enum BatchReconError {
    /// The error occurs when communicating using the network.
    #[error("there was an error in the network: {0:?}")]
    NetworkError(#[from] NetworkError),
    #[error("error while serializing an arkworks object: {0:?}")]
    ArkSerialization(#[from] SerializationError),
    #[error("error while serializing an arkworks object: {0:?}")]
    ArkDeserialization(SerializationError),
    #[error("error while serializing the object into bytes: {0:?}")]
    SerializationError(#[from] Box<ErrorKind>),
    /// Errors specific to invalid input parameters or conditions.
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("inner error: {0}")]
    InterpolateError(#[from] InterpolateError),
}
