use bincode::ErrorKind;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use stoffelnet::network_utils::NetworkError;
use thiserror::Error;
use tokio::sync::oneshot::{channel, Receiver, Sender};

use crate::{
    common::{
        gf2k::field::BinaryField,
        gf2k::share::{GfShare, GfShareWire},
        gf2k::Gf2kError,
        share::ShareError,
    },
    honeybadger::{gf_batch_recon::GfBatchReconError, mul::MultProtocolState, SessionId},
};

pub mod gf_multiplication;

/// Error that occurs during the execution of GF(2^k) secure multiplication.
#[derive(Debug, Error)]
pub enum GfMulError {
    #[error("there was an error in the network: {0:?}")]
    NetworkError(#[from] NetworkError),
    #[error("share error: {0:?}")]
    ShareError(#[from] ShareError),
    #[error("inner error: {0:?}")]
    Gf2kError(#[from] Gf2kError),
    #[error("batch reconstruction error: {0:?}")]
    GfBatchReconError(#[from] GfBatchReconError),
    #[error("error while serializing/deserializing bytes: {0:?}")]
    BincodeSerializationError(#[from] Box<ErrorKind>),
    #[error("Duplicate input: {0}")]
    Duplicate(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("no such session ID exists: {0:?}")]
    NoSuchSessionId(SessionId),
    #[error("result already received: {0:?}")]
    ResultAlreadyReceived(SessionId),
    #[error("multiplication {0:?} did not complete in time")]
    Timeout(SessionId),
    #[error("error sending the result: {0:?}")]
    SendError(SessionId),
    #[error("error receiving the result: {0:?}")]
    ReceiveError(SessionId),
    #[error("Channel closed")]
    Abort,
    #[error("Store Limit")]
    LimitError,
}

/// Storage for one GF(2^k) multiplication session. Mirrors `MultStorage<F>` field-for-field.
#[derive(Debug)]
pub struct GfMultStorage<K: BinaryField> {
    pub no_of_mul: Option<usize>,
    /// opened `a-x` values reconstructed using batch reconstruction
    pub output_open_mult1: HashMap<u8, Vec<K>>,
    /// opened `b-y` values reconstructed using batch reconstruction
    pub output_open_mult2: HashMap<u8, Vec<K>>,
    pub inputs: (Vec<GfShare<K>>, Vec<GfShare<K>>),
    pub protocol_state: MultProtocolState,
    pub share_mult_from_triple: Vec<GfShare<K>>,
    /// shares for reconstruction using direct point-to-point broadcast (the sub-`t+1` remainder)
    pub received_shares: HashMap<usize, (Vec<GfShare<K>>, Vec<GfShare<K>>)>,
    /// opened `a-x` and `b-y` values reconstructed from the remainder shares above
    pub openings: Option<(Vec<K>, Vec<K>)>,
    pub output_sender: Option<Sender<Vec<GfShare<K>>>>,
    pub output_receiver: Option<Receiver<Vec<GfShare<K>>>>,
}

impl<K: BinaryField> GfMultStorage<K> {
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
            output_receiver: Some(output_receiver),
        }
    }
}

/// Direct point-to-point opening of a GF(2^k) multiplication's `(a-x)`/`(b-y)` remainder shares
/// (used when the batch size isn't a multiple of `t+1`). Robust interpolation tolerates up to `t`
/// bad shares, so this doesn't need RBC's reliable-broadcast agreement — same trust model as
/// `GfBatchRecon`'s own point-to-point `Eval`/`Reveal` messages.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GfMultMessage {
    pub sender: usize,
    pub session_id: SessionId,
    pub payload: Vec<u8>,
}

impl GfMultMessage {
    pub fn new(sender: usize, session_id: SessionId, payload: Vec<u8>) -> Self {
        Self {
            sender,
            session_id,
            payload,
        }
    }
}

/// Payload of a [`GfMultMessage`] carrying the remainder `(a-x)`/`(b-y)` shares directly.
///
/// The two runs ride as [`GfShareWire`]: bare field elements, with the sender's evaluation index
/// and the opening degree **absent from the wire** rather than shipped and then checked. Both are
/// re-derived by the receiver — the index from the authenticated envelope `sender` that
/// `HoneyBadgerMPCNode` has already matched against the transport party id, the degree from the
/// node's own `threshold`. This is what makes the direct opening path cost `1` byte per share
/// instead of `17`; see [`GfShareWire`] for why the dropped fields were never trustworthy.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "K: BinaryField")]
pub struct GfMultReconstructionMessage<K: BinaryField> {
    pub a_sub_x: GfShareWire<K>,
    pub b_sub_y: GfShareWire<K>,
}

impl<K: BinaryField> GfMultReconstructionMessage<K> {
    /// Builds the message from the sender's own remainder shares.
    ///
    /// `id` is the sender's party id and `degree` the opening degree (the node's `threshold`);
    /// both are asserted against every share and then dropped.
    ///
    /// # Errors
    /// [`ShareError`] if either run is not homogeneous at `(id, degree)`.
    pub fn new(
        a_sub_x: &[GfShare<K>],
        b_sub_y: &[GfShare<K>],
        id: usize,
        degree: usize,
    ) -> Result<Self, ShareError> {
        Ok(Self {
            a_sub_x: GfShareWire::encode(a_sub_x, id, degree)?,
            b_sub_y: GfShareWire::encode(b_sub_y, id, degree)?,
        })
    }

    /// Rebuilds the two runs of shares, stamping the **receiver-derived** `(id, degree)`.
    ///
    /// `id` must be the authenticated sender's party id, `degree` the receiver's own threshold.
    pub fn into_shares(&self, id: usize, degree: usize) -> (Vec<GfShare<K>>, Vec<GfShare<K>>) {
        (
            self.a_sub_x.decode(id, degree),
            self.b_sub_y.decode(id, degree),
        )
    }
}
