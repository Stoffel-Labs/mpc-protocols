use ark_ff::FftField;
use ark_serialize::SerializationError;
use bincode::ErrorKind;
use serde::{Deserialize, Serialize};
use stoffelmpc_network::{NetworkError, PartyId};
use thiserror::Error;
use tokio::{sync::mpsc::error::SendError, task::JoinError};

use crate::{
    common::share::ShareError,
    honeybadger::{
        batch_recon::BatchReconError, double_share::DoubleShamirShare,
        robust_interpolate::robust_interpolate::RobustShare,
        triple_gen::triple_generation::ProtocolState, SessionId,
    },
};

pub mod triple_generation;

/// Error type for the triple generation protocol.
#[derive(Debug, Error)]
pub enum TripleGenError {
    /// Error that describes an failure in the network processes.
    #[error("network error: {0:?}")]
    NetworkError(#[from] NetworkError),
    /// Error that arises when there is a failure manipulating shares.
    #[error("share error: {0:?}")]
    ShareError(#[from] ShareError),
    /// This error arises when there is not enough random double shares in the
    /// preprocessing to complete the triple generation protocol.
    #[error("not enough preprocessing")]
    NotEnoughPreprocessing,
    /// Error during the serialization using [`bincode`].
    #[error("error during the serialization using bincode: {0:?}")]
    BincodeSerializationError(#[from] Box<ErrorKind>),
    /// Error during the serialization using [`ark_serialize`].
    #[error("error during the serialization using bincode: {0:?}")]
    ArkSerializationError(#[from] SerializationError),
    /// The error arises when there are not enough random shares in the input to the triple
    /// generation protocol.
    #[error("wrong ammount of shares")]
    NotEnoughShares,
    /// Error during the batch reconstruction protocol.
    #[error("batch reconstruction error: {0:?}")]
    BatchReconError(#[from] BatchReconError),
    /// Error during the execution of async operations.
    #[error("async error: {0:?}")]
    AsyncError(#[from] JoinError),
    /// The session ID of the parameters and the received message does not match.
    #[error("the session IDs do not match")]
    SessionIdMismatch,
    #[error("error sending the thread asynchronously")]
    SendError(#[from] SendError<SessionId>),
}

/// Represents a Beaver triple of non-robust Shamir shares.
#[derive(Clone,Debug)]
pub struct ShamirBeaverTriple<F: FftField> {
    /// First random value of the triple.
    pub a: RobustShare<F>,
    /// Second random value of the triple.
    pub b: RobustShare<F>,
    /// Multiplication of both random values.
    pub mult: RobustShare<F>,
}

impl<F> ShamirBeaverTriple<F>
where
    F: FftField,
{
    /// Creates a new Shamir Beaver triple with `a` and `b` being the random values of the triple
    /// and `mult` is the multiplication of `a` and `b`.
    pub fn new(
        a: RobustShare<F>,
        b: RobustShare<F>,
        mult: RobustShare<F>,
    ) -> Self {
        Self { a, b, mult }
    }
}

/// Storage necessary for the triple generation protocol.
#[derive(Clone,Debug)]
pub struct TripleGenStorage<F>
where
    F: FftField,
{
    /// Current state of the protocol execution.
    pub protocol_state: ProtocolState,
    pub randousha_pairs: Vec<DoubleShamirShare<F>>,
    pub random_shares_a_input: Vec<RobustShare<F>>,
    pub random_shares_b_input: Vec<RobustShare<F>>,
    pub protocol_output: Vec<ShamirBeaverTriple<F>>,
}

impl<F> TripleGenStorage<F>
where
    F: FftField,
{
    /// Creates an empty state for the protocol.
    pub fn empty() -> Self {
        Self {
            protocol_state: ProtocolState::NotInitialized,
            randousha_pairs: Vec::new(),
            random_shares_a_input: Vec::new(),
            random_shares_b_input: Vec::new(),
            protocol_output: Vec::new(),
        }
    }
}

/// Generic message for the triple generation protocol.
///
/// This generic message contains the payload in bytes of any message sent during the protocol
/// execution. Any message that is sent in the protocol is converted into bytes that are placed in
/// the `payload`. Once a party receives a message, it takes the payload and deserialize it to the
/// specific message sent during the protocol execution.
#[derive(Clone,Debug, Serialize, Deserialize)]
pub struct TripleGenMessage {
    /// The ID of the party.
    pub sender_id: PartyId,
    /// The session ID of the instance.
    pub session_id: SessionId,
    /// The payload of the message.
    pub payload: Vec<u8>,
}

impl TripleGenMessage {
    /// Creates a new generic message for the triple generation protocol.
    pub fn new(sender_id: PartyId, session_id: SessionId, payload: Vec<u8>) -> Self {
        Self {
            sender_id,
            session_id,
            payload,
        }
    }
}
