use crate::honeybadger::{batch_recon::BatchReconError, dn07::Dn07Error, SessionId};
use ark_ff::FftField;
use ark_serialize::SerializationError;
use bincode::ErrorKind;
use thiserror::Error;
use tokio::sync::oneshot::{channel, Receiver, Sender};

pub mod mul_pub;

#[derive(Debug, Error)]
pub enum MulPubError {
    /// The session offered to [`MulPubNode::init`](mul_pub::MulPubNode::init) was not a
    /// preprocessing session, or was not root-shaped.
    ///
    /// `init` takes a [`PreprocessingSessionId`](crate::honeybadger::dn07::PreprocessingSessionId)
    /// rather than a bare [`SessionId`], so in practice this variant is how a *caller* reports the
    /// refusal it got when it tried to name the session at all — see
    /// [`RandBit::init`](crate::honeybadger::fpmul::rand_bit::RandBit::init), which is where the
    /// conversion happens for the one production MulPub caller. The wrapped
    /// [`Dn07Error::OnlinePhaseForbidden`] is the case that matters: MulPub opens
    /// `a*b + [0]_{2t}` at degree `2t`, which the asynchronous robust path cannot reconstruct at
    /// `n = 3t+1`.
    #[error("MulPub session rejected: {0}")]
    SessionPhase(#[from] Dn07Error),
    #[error("ark serialization: {0:?}")]
    ArkSerialization(#[from] SerializationError),
    #[error("bincode: {0:?}")]
    Serialization(#[from] Box<ErrorKind>),
    #[error("batch recon: {0:?}")]
    BatchRecon(#[from] BatchReconError),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("batch of {requested} exceeds the per-session maximum of {max}")]
    BatchTooLarge { requested: usize, max: usize },
    #[error("send error")]
    SendError,
    #[error("receive error: {0:?}")]
    ReceiveError(SessionId),
    #[error("timeout: {0:?}")]
    Timeout(SessionId),
    #[error("no such session: {0:?}")]
    NoSuchSession(SessionId),
    #[error("result already received: {0:?}")]
    ResultAlreadyReceived(SessionId),
    #[error("session limit reached")]
    LimitError,
    #[error("channel closed")]
    Abort,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MulPubState {
    Running,
    Finished,
}

#[derive(Debug)]
pub struct MulPubStore<F: FftField> {
    pub k: usize,
    pub state: MulPubState,
    pub output_sender: Option<Sender<Vec<F>>>,
    pub output_receiver: Option<Receiver<Vec<F>>>,
    /// A batch-reconstruction result can arrive before `init` sets `k` (a faster
    /// quorum can finish this node's reconstruction before it calls `init`).
    /// Keep the raw bytes until `k` is known.
    pub pending_batch_recon_payload: Option<Vec<u8>>,
}

impl<F: FftField> MulPubStore<F> {
    pub fn new(k: usize) -> Self {
        let (output_sender, output_receiver) = channel();
        Self {
            k,
            state: MulPubState::Running,
            output_sender: Some(output_sender),
            output_receiver: Some(output_receiver),
            pending_batch_recon_payload: None,
        }
    }
}
