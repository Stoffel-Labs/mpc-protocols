use std::collections::HashMap;

use bincode::ErrorKind;
use serde::{Deserialize, Serialize};
use stoffelnet::network_utils::NetworkError;
use thiserror::Error;
use tokio::sync::oneshot::{channel, Receiver, Sender};

use crate::{
    common::{
        gf2k::field::BinaryField, gf2k::share::GfShare, gf2k::Gf2kError, rbc::RbcError,
        share::ShareError,
    },
    honeybadger::SessionId,
};

pub mod gf_share_gen;

/// Error type for the GF(2^k) Random Single Share (RanSha-equivalent) protocol. Mirrors
/// `share_gen::RanShaError`'s shape, minus the ark_serialize-specific variants (not needed —
/// this track uses plain `bincode`/`serde` throughout, since `GfShare<K>` has native serde
/// support unlike `RobustShare<F>`).
#[derive(Debug, Error)]
pub enum GfRanShaError {
    #[error("there was an error in the network: {0:?}")]
    NetworkError(#[from] NetworkError),
    #[error("error while serializing/deserializing bytes: {0:?}")]
    SerializationError(#[from] Box<ErrorKind>),
    #[error("inner error: {0:?}")]
    Gf2kError(#[from] Gf2kError),
    #[error("Rbc error: {0:?}")]
    RbcError(#[from] RbcError),
    #[error("Share error: {0:?}")]
    ShareError(#[from] ShareError),
    #[error("error sending the result: {0:?}")]
    SendError(SessionId),
    #[error("error receiving the result: {0:?}")]
    ReceiveError(SessionId),
    #[error("received abort signal")]
    Abort,
    #[error("Party Id is out of bounds")]
    InvalidPartyId,
    #[error("session ID {0:?} malformed")]
    SessionIdError(SessionId),
    #[error("limit reached")]
    LimitError,
    #[error("no such session ID exists: {0:?}")]
    NoSuchSessionId(SessionId),
    #[error("result already received: {0:?}")]
    ResultAlreadyReceived(SessionId),
    #[error("GfRanSha {0:?} did not complete in time")]
    Timeout(SessionId),
    #[error("no calling protocol in the session ID")]
    NoCallingProtocol,
}

#[derive(Debug)]
pub struct GfRanShaStore<K: BinaryField> {
    pub initial_shares: HashMap<usize, Vec<GfShare<K>>>,
    pub reception_tracker: Vec<bool>,
    pub received_r_shares: HashMap<usize, Vec<GfShare<K>>>,
    pub computed_r_shares: Vec<GfShare<K>>,
    pub received_ok_msg: Vec<usize>,
    pub batch_size: usize,
    pub state: GfRanShaState,
    pub protocol_output: Vec<GfShare<K>>,
    pub output_sender: Option<Sender<Vec<GfShare<K>>>>,
    pub output_receiver: Option<Receiver<Vec<GfShare<K>>>>,
    /// Share messages that arrived before local `init_batch` set `batch_size`.
    /// Drained and replayed by `init_batch` once the trusted `batch_size` is set.
    pub pending_share_messages: Vec<GfRanShaMessage>,
    /// Reconstruction messages that arrived before `init_ransha_batch` set `computed_r_shares`.
    /// Drained and replayed by `init_ransha_batch` once the trusted state is set.
    pub pending_recon_messages: Vec<GfRanShaMessage>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GfRanShaState {
    NotInitialized,
    Initialized,
    FinishedInitialSharing,
    Reconstruction,
    Finished,
}

impl<K: BinaryField> GfRanShaStore<K> {
    pub fn empty(n_parties: usize) -> Self {
        let (output_sender, output_receiver) = channel();
        Self {
            initial_shares: HashMap::new(),
            reception_tracker: vec![false; n_parties],
            received_r_shares: HashMap::new(),
            computed_r_shares: Vec::new(),
            received_ok_msg: Vec::new(),
            batch_size: 1,
            state: GfRanShaState::NotInitialized,
            protocol_output: Vec::new(),
            output_sender: Some(output_sender),
            output_receiver: Some(output_receiver),
            pending_share_messages: Vec::new(),
            pending_recon_messages: Vec::new(),
        }
    }
}

/// Types for all possible messages sent during the GF(2^k) Random Single Sharing protocol.
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub enum GfRanShaMessageType {
    ShareMessage,
    ReconstructMessage,
    OutputMessage,
}

/// Payloads carry opaque, `bincode`-serialized `GfShare<K>`/`Vec<GfShare<K>>` bytes rather than a
/// typed `GfShare<K>` directly
#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum GfRanShaPayload {
    Share(Vec<u8>),
    SharesBatch(Vec<u8>),
    /// Contains the bincode-serialized share of `r` sent during reconstruction.
    Reconstruct(Vec<u8>),
    ReconstructSharesBatch(Vec<u8>),
    /// Output message confirming reconstruction success or failure.
    Output(bool),
}

/// Message sent in the GF(2^k) Random Single Sharing protocol.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct GfRanShaMessage {
    /// ID of the sender of the message. Trusted as given by every handler in this module —
    /// authenticating it against the actual network-layer party identity is the caller's job
    pub sender_id: usize,
    pub msg_type: GfRanShaMessageType,
    pub session_id: SessionId,
    pub payload: GfRanShaPayload,
}

impl GfRanShaMessage {
    pub fn new(
        sender_id: usize,
        msg_type: GfRanShaMessageType,
        session_id: SessionId,
        payload: GfRanShaPayload,
    ) -> Self {
        Self {
            sender_id,
            msg_type,
            session_id,
            payload,
        }
    }
}
