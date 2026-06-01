use crate::honeybadger::{batch_recon::BatchReconError, SessionId};
use ark_ff::FftField;
use ark_serialize::SerializationError;
use bincode::ErrorKind;
use std::collections::HashMap;
use thiserror::Error;
use tokio::sync::oneshot::{channel, Receiver, Sender};

pub mod mul_pub;

#[derive(Debug, Error)]
pub enum MulPubError {
    #[error("ark serialization: {0:?}")]
    ArkSerialization(#[from] SerializationError),
    #[error("bincode: {0:?}")]
    Serialization(#[from] Box<ErrorKind>),
    #[error("batch recon: {0:?}")]
    BatchRecon(#[from] BatchReconError),
    #[error("invalid input: {0}")]
    InvalidInput(String),
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
    pub results: HashMap<usize, F>,
    pub state: MulPubState,
    pub output_sender: Option<Sender<Vec<F>>>,
    pub output_receiver: Option<Receiver<Vec<F>>>,
}

impl<F: FftField> MulPubStore<F> {
    pub fn new(k: usize) -> Self {
        let (output_sender, output_receiver) = channel();
        Self {
            k,
            results: HashMap::new(),
            state: MulPubState::Running,
            output_sender: Some(output_sender),
            output_receiver: Some(output_receiver),
        }
    }
}
