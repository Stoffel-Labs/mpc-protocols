use bincode::ErrorKind;
use stoffelnet::network_utils::NetworkError;
use thiserror::Error;
use tokio::sync::oneshot::{channel, Receiver, Sender};

use crate::{
    common::{gf2k::field::BinaryField, gf2k::share::GfShare, share::ShareError},
    honeybadger::{
        gf_batch_recon::GfBatchReconError, gf_double_share::GfDoubleShamirShare,
        triple_gen::triple_generation::ProtocolState, SessionId,
    },
};

pub mod gf_triple_generation;

/// Error type for the GF(2^k) triple generation protocol. Mirrors `TripleGenError`'s shape,
/// minus the ark_serialize-specific variant — this track uses `bincode`/`serde` throughout.
#[derive(Debug, Error)]
pub enum GfTripleGenError {
    #[error("network error: {0:?}")]
    NetworkError(#[from] NetworkError),
    #[error("share error: {0:?}")]
    ShareError(#[from] ShareError),
    /// This error arises when there is not enough random double shares in the preprocessing to
    /// complete the triple generation protocol.
    #[error("not enough preprocessing")]
    NotEnoughPreprocessing,
    #[error("error during the serialization using bincode: {0:?}")]
    BincodeSerializationError(#[from] Box<ErrorKind>),
    /// The error arises when there are not enough random shares in the input to the triple
    /// generation protocol.
    #[error("wrong amount of shares")]
    NotEnoughShares,
    #[error("batch reconstruction error: {0:?}")]
    GfBatchReconError(#[from] GfBatchReconError),
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

/// Represents a Beaver triple of GF(2^k) shares.
#[derive(Clone, Debug)]
pub struct GfBeaverTriple<K: BinaryField> {
    /// First random value of the triple.
    pub a: GfShare<K>,
    /// Second random value of the triple.
    pub b: GfShare<K>,
    /// Multiplication of both random values.
    pub mult: GfShare<K>,
}

impl<K: BinaryField> GfBeaverTriple<K> {
    /// Creates a new GF(2^k) Beaver triple with `a` and `b` being the random values of the
    /// triple and `mult` is the multiplication of `a` and `b`.
    pub fn new(a: GfShare<K>, b: GfShare<K>, mult: GfShare<K>) -> Self {
        Self { a, b, mult }
    }
}

/// Storage necessary for the GF(2^k) triple generation protocol.
#[derive(Debug)]
pub struct GfTripleGenStorage<K: BinaryField> {
    /// Current state of the protocol execution.
    pub protocol_state: ProtocolState,
    /// A batch-reconstruction result can arrive before this party initializes the corresponding
    /// triple-generation session. Keep the serialized result until the local inputs establish
    /// its expected width.
    pub pending_batch_recon_payload: Option<Vec<u8>>,
    pub batch_recon_result: Option<Vec<K>>,
    pub randousha_pairs: Vec<GfDoubleShamirShare<K>>,
    pub random_shares_a_input: Vec<GfShare<K>>,
    pub random_shares_b_input: Vec<GfShare<K>>,
    pub protocol_output: Vec<GfBeaverTriple<K>>,
    pub output_sender: Option<Sender<Vec<GfBeaverTriple<K>>>>,
    pub output_receiver: Option<Receiver<Vec<GfBeaverTriple<K>>>>,
}

impl<K: BinaryField> GfTripleGenStorage<K> {
    /// Creates an empty state for the protocol.
    pub fn empty() -> Self {
        let (output_sender, output_receiver) = channel();

        Self {
            protocol_state: ProtocolState::NotInitialized,
            pending_batch_recon_payload: None,
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
