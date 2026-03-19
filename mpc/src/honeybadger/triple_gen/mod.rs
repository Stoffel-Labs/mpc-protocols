use ark_ff::FftField;
use ark_serialize::SerializationError;
use bincode::ErrorKind;
use stoffelnet::network_utils::NetworkError;
use thiserror::Error;
use tokio::{
    sync::oneshot::{channel, Receiver, Sender},
    task::JoinError,
};

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
    #[error("error sending the result: {0:?}")]
    SendError(SessionId),
    #[error("error receiving the result: {0:?}")]
    ReceiveError(SessionId),
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
    #[error("received abort signal")]
    Abort,
}

/// Represents a Beaver triple of non-robust Shamir shares.
#[derive(Clone, Debug)]
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
    pub fn new(a: RobustShare<F>, b: RobustShare<F>, mult: RobustShare<F>) -> Self {
        Self { a, b, mult }
    }
}

/// Storage necessary for the triple generation protocol.
#[derive(Debug)]
pub struct TripleGenStorage<F>
where
    F: FftField,
{
    /// Current state of the protocol execution.
    pub protocol_state: ProtocolState,
    pub batch_recon_result: Option<Vec<F>>,
    pub randousha_pairs: Vec<DoubleShamirShare<F>>,
    pub random_shares_a_input: Vec<RobustShare<F>>,
    pub random_shares_b_input: Vec<RobustShare<F>>,
    pub protocol_output: Vec<ShamirBeaverTriple<F>>,
    pub output_sender: Option<Sender<Vec<ShamirBeaverTriple<F>>>>,
    pub output_receiver: Option<Receiver<Vec<ShamirBeaverTriple<F>>>>,
}

impl<F> TripleGenStorage<F>
where
    F: FftField,
{
    /// Creates an empty state for the protocol.
    pub fn empty() -> Self {
        let (output_sender, output_receiver) = channel();

        Self {
            protocol_state: ProtocolState::NotInitialized,
            batch_recon_result: None,
            randousha_pairs: Vec::new(),
            random_shares_a_input: Vec::new(),
            random_shares_b_input: Vec::new(),
            protocol_output: Vec::new(),
            output_sender: Some(output_sender),
            output_receiver: Some(output_receiver),
        }
    }
}
