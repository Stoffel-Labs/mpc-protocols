use bincode::ErrorKind;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use stoffelnet::network_utils::{NetworkError, PartyId};
use thiserror::Error;
use tokio::sync::oneshot::{channel, Receiver, Sender};

use crate::common::{gf2k::field::BinaryField, gf2k::share::GfShare, gf2k::Gf2kError, share::ShareError};
use crate::honeybadger::{double_share::double_share_generation::ProtocolState, SessionId};

pub mod gf_double_share_generation;

/// Error for the GF(2^k) double-share dealing protocol. Mirrors `DouShaError`'s shape, minus the
/// ark_serialize-specific variants — this track uses `bincode`/`serde` throughout.
#[derive(Debug, Error)]
pub enum GfDouShaError {
    #[error("sender mismatch: expected sender: {expected_sender:?}, actual_sender: {actual_sender:?}")]
    SenderMismatch {
        expected_sender: PartyId,
        actual_sender: PartyId,
    },
    #[error("error in share: {0:?}")]
    Gf2kError(#[from] Gf2kError),
    #[error("bincode serialization error: {0:?}")]
    SerializationError(#[from] Box<ErrorKind>),
    #[error("error in the network: {0:?}")]
    NetworkError(#[from] NetworkError),
    #[error("error sending the result: {0:?}")]
    SendError(SessionId),
    #[error("error receiving the result: {0:?}")]
    ReceiveError(SessionId),
    #[error("ShareError: {0}")]
    ShareError(#[from] ShareError),
    #[error("Party Id is out of bounds")]
    InvalidPartyId,
    #[error("no such session ID exists: {0:?}")]
    NoSuchSessionId(SessionId),
    #[error("result already received: {0:?}")]
    ResultAlreadyReceived(SessionId),
    #[error("multiplication {0:?} did not complete in time")]
    Timeout(SessionId),
    #[error("Store Limit")]
    LimitError,
}

/// A dealt (but not yet verified) pair of degree-`t`/degree-`2t` GF(2^k) shares of the same
/// secret. Verification (RanDouSha's hyperinvertible-matrix extraction + checksum) happens one
/// layer up — this type is purely the dealing protocol's raw output.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "K: BinaryField")]
pub struct GfDoubleShamirShare<K: BinaryField> {
    pub degree_2t: GfShare<K>,
    pub degree_t: GfShare<K>,
}

impl<K: BinaryField> GfDoubleShamirShare<K> {
    pub fn new(degree_t: GfShare<K>, degree_2t: GfShare<K>) -> Self {
        assert!(degree_t.id == degree_2t.id);
        Self {
            degree_2t,
            degree_t,
        }
    }
}

/// Payload for one or more dealt GF(2^k) double shares. `Vec<u8>` (not `GfDoubleShamirShare<K>`
/// directly) for the same reason as `gf_share_gen`/`gf_batch_recon`: this needs to slot into the
/// crate-wide, non-generic `WrappedMessage` envelope.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GfDouShaPayload {
    Share(Vec<u8>),
    Shares(Vec<u8>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GfDouShaMessage {
    pub sender_id: PartyId,
    pub session_id: SessionId,
    pub payload: GfDouShaPayload,
}

impl GfDouShaMessage {
    pub fn new(sender: PartyId, session_id: SessionId, payload: GfDouShaPayload) -> Self {
        Self {
            sender_id: sender,
            session_id,
            payload,
        }
    }
}

#[derive(Debug)]
pub struct GfDouShaStorage<K: BinaryField> {
    pub protocol_output: Vec<GfDoubleShamirShare<K>>,
    pub share: BTreeMap<usize, Vec<GfDoubleShamirShare<K>>>,
    pub batch_size: usize,
    pub state: ProtocolState,
    reception_tracker: Vec<bool>,
    pub output_sender: Option<Sender<Vec<GfDoubleShamirShare<K>>>>,
    pub output_receiver: Option<Receiver<Vec<GfDoubleShamirShare<K>>>>,
    /// Messages that arrived before local initialization (batch_size unknown). Drained and
    /// replayed by `init_batch` once the trusted batch_size is set.
    pub pending_messages: Vec<GfDouShaMessage>,
}

impl<K: BinaryField> GfDouShaStorage<K> {
    pub fn empty(n_parties: usize) -> Self {
        let (output_sender, output_receiver) = channel();
        Self {
            protocol_output: Vec::new(),
            share: BTreeMap::new(),
            batch_size: 1,
            reception_tracker: vec![false; n_parties],
            state: ProtocolState::NotInitialized,
            output_sender: Some(output_sender),
            output_receiver: Some(output_receiver),
            pending_messages: Vec::new(),
        }
    }
}
