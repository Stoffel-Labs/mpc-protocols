//! The protocol RandBit generates random bits of a shared value.
//!
//! # Output
//!
//! If `t + 1` random elements are provided, then the protocol will return `t + 1` random bits. The
//! number of random elements is limited by the number of shared elements that the batch
//! reconstruction protocol can reconstruct. (Updated to generate multiples of `t + 1`)
//!
//! # Assumptions
//!
//! This protocol is based on the secure multiplication protocol and the generation of random shared
//! values. Hence, the protocol assumes that you provide one multiplication triple to execute the
//! secure multiplication protocol and the share of a random value.
//!
//! If the underlying sharing scheme implements the ideal arithmetic black box functionality, then
//! this protocol is secure.

use crate::common::share::ShareError;
use crate::common::RBC;
use crate::honeybadger::batch_recon::batch_recon::BatchReconNode;
use crate::honeybadger::batch_recon::BatchReconError;
use crate::honeybadger::fpmul::ProtocolState;
use crate::honeybadger::mul::multiplication::Multiply;
use crate::honeybadger::mul::{concat_sorted, MulError};
use crate::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use crate::honeybadger::triple_gen::ShamirBeaverTriple;
use crate::honeybadger::{ProtocolType, SessionId};
use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, SerializationError};
use itertools::izip;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ops::{Add, Mul};
use std::sync::Arc;
use stoffelnet::network_utils::{Network, PartyId};
use thiserror::Error;
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;
use tokio::time::Duration;
use tracing::{error, info, warn};

#[derive(Error, Debug)]
pub enum RandBitError {
    #[error("incompatible treshold ({0:}) and number of parties {1:}")]
    IncompatibleNumberOfParties(usize, usize),
    #[error("the square multiplication was not completed successfuly")]
    SquareMult(#[from] MulError),
    #[error("the square is zero")]
    ZeroSquare,
    #[error("the square root does not exist")]
    SquareRootDoesNotExist,
    #[error("the inverse does not exist")]
    Inverse,
    #[error("not initialized error")]
    NotInitialized,
    #[error("number of random shares is not a multiple of (t+1)")]
    Incompatible,
    #[error("Duplicate input: {0}")]
    Duplicate(String),
    #[error("waiting for more openings")]
    WaitForAllBatches,
    #[error("error in batch reconstruction: {0:?}")]
    BatchRecError(#[from] BatchReconError),
    #[error("error during deserialization: {0:?}")]
    SerializationError(#[from] SerializationError),
    #[error("error operating with the shares: {0:?}")]
    ShareError(#[from] ShareError),
    #[error("error sending the finished session ID to the caller: {0:?}")]
    SenderError(#[from] SendError<SessionId>),
    #[error("the session ID has not been set")]
    SessionIdNotSet,
}

/// A message sent in the RandBit protocol.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RandBitMessage {
    /// Sender of the message.
    pub sender: PartyId,
    /// Session ID of the protocol to which this message belongs.
    pub session_id: SessionId,
    /// Payload of the message.
    pub payload: Vec<u8>,
}

impl RandBitMessage {
    /// Creates a new message for the RandBit protocol
    pub fn new(sender: PartyId, session_id: SessionId, payload: Vec<u8>) -> Self {
        Self {
            sender,
            session_id,
            payload,
        }
    }
}

/// Storage of the node for the RandBit protocol.
#[derive(Clone, Debug)]
pub struct RandBitStorage<F>
where
    F: FftField,
{
    /// State of the protocol.
    pub protocol_state: ProtocolState,
    /// Output of the protocol. If the protocol is not finished yet, `protocol_output` will be
    /// [`None`].
    pub protocol_output: Option<Vec<RobustShare<F>>>,
    /// Share of `a`
    pub a_share: Option<Vec<RobustShare<F>>>,
    pub output_open: HashMap<u8, Vec<F>>,
}

impl<F> RandBitStorage<F>
where
    F: FftField,
{
    /// Creates a new empty storage.
    pub fn empty() -> Self {
        Self {
            protocol_state: ProtocolState::NotInitialized,
            protocol_output: None,
            a_share: None,
            output_open: HashMap::new(),
        }
    }
}

/// Represents the random bit generation protocol.
#[derive(Clone, Debug)]
pub struct RandBit<F, R>
where
    F: FftField,
    R: RBC,
{
    /// The ID of the node.
    pub id: PartyId,
    /// The number of parties participating in the protocol.
    pub n_parties: usize,
    /// The threshold of corrupted parties.
    pub threshold: usize,
    /// Storage for the protocol.
    pub storage: Arc<Mutex<HashMap<SessionId, Arc<Mutex<RandBitStorage<F>>>>>>,
    /// Channel to send session ID of the current session once the protocol finishes its execution.
    pub output_channel: Sender<SessionId>,
    /// Node to execute a secure multiplication.
    pub mult_node: Multiply<F, R>,
    /// Batch reconstruction node to reconstruct `a^2 mod p`.
    pub batch_recon: BatchReconNode<F>,
    /// Original session ID for the execution of RandBit.
    ///
    /// The field is [`Option`] because at the beginning of the execution, the session ID is not
    /// known yet.
    pub original_session_id: Option<SessionId>,
}

impl<F, R> RandBit<F, R>
where
    F: FftField,
    R: RBC,
{
    /// Creates a new node for the RandBit protocol.
    ///
    /// # Arguments
    ///
    /// - `id`: The ID of the party.
    /// - `n_parties`: The number of parties participating in the protocol.
    /// - `protocol_output`: A [`Sender`] that returns the session ID of protocols that already
    ///    finished.
    pub fn new(
        id: PartyId,
        n_parties: usize,
        threshold: usize,
        protocol_output: Sender<SessionId>,
    ) -> Result<Self, RandBitError> {
        let batch_recon_node = BatchReconNode::new(id, n_parties, threshold)?;
        let mult_node = Multiply::new(id, n_parties, threshold)?;
        Ok(Self {
            id,
            n_parties,
            threshold,
            storage: Arc::new(Mutex::new(HashMap::new())),
            output_channel: protocol_output,
            mult_node,
            batch_recon: batch_recon_node,
            original_session_id: None,
        })
    }

    /// Clears the storage of the node.
    pub async fn clear_store(&self) {
        let mut store = self.storage.lock().await;
        store.clear();
        self.mult_node.clear_store().await;
        self.batch_recon.clear_entire_store().await;
    }

    /// Gets the storage of the node for the given session ID. If the storage does not exist,
    /// then it is created.
    pub async fn get_or_create_storage(
        &self,
        session_id: SessionId,
    ) -> Arc<Mutex<RandBitStorage<F>>> {
        let mut storage = self.storage.lock().await;
        storage
            .entry(session_id)
            .or_insert(Arc::new(Mutex::new(RandBitStorage::empty())))
            .clone()
    }

    /// Initialization of the RandBit protocol.
    pub async fn init<N>(
        &mut self,
        a_shares: Vec<RobustShare<F>>,
        mult_triples: Vec<ShamirBeaverTriple<F>>,
        session_id: SessionId,
        network: Arc<N>,
    ) -> Result<(), RandBitError>
    where
        N: Network + Send + Sync + 'static,
    {
        if a_shares.len() % (self.threshold + 1) != 0 {
            error!("The length of the array a is not a multiple of t + 1");
            return Err(RandBitError::Incompatible);
        }

        if a_shares.len() != mult_triples.len() {
            error!("The length of the array a is nont the same as the number of multiplication triples");
            return Err(RandBitError::Incompatible);
        }

        self.original_session_id = Some(session_id);

        // Mark the protocol as initialized.
        {
            let storage_bind = self.get_or_create_storage(session_id).await;
            let mut storage = storage_bind.lock().await;
            storage.protocol_state = ProtocolState::Initialized;
            storage.a_share = Some(a_shares.clone());
        }

        // Step 2: Execute the multiplication to get a^2 mod p.
        let mult_session_id = SessionId::new(
            session_id.calling_protocol().unwrap(),
            session_id.exec_id(),
            0,
            session_id.round_id(),
            session_id.instance_id(),
        );
        info!(
            mult_session_id = ?mult_session_id,
            "Initializing multiplication from within RandBit",
        );
        let a_shares_copy = a_shares.clone();
        self.mult_node
            .init(
                mult_session_id,
                a_shares,
                a_shares_copy,
                mult_triples,
                network.clone(),
            )
            .await?;

        info!(id = self.id, "Multiplication at RandBit initialized");

        let a_square_share = self
            .mult_node
            .wait_for_result(mult_session_id, Duration::from_millis(10000))
            .await?;

        tracing::info!("Multiplication at RandBit done: {0:?}", self.id);

        for (i, chunk) in a_square_share.chunks(self.threshold + 1).enumerate() {
            let session_id_batch_recon = SessionId::new(
                session_id.calling_protocol().unwrap(),
                session_id.exec_id(),
                session_id.sub_id(),
                i as u8,
                session_id.instance_id(),
            );
            info!("Initializing batch reconstruction from within RandBit, session ID for batch reconstruction: {:?}", session_id_batch_recon);
            self.batch_recon
                .init_batch_reconstruct(chunk, session_id_batch_recon, network.clone())
                .await?;
        }

        Ok(())
    }

    async fn square_reconstruction_handler(
        &self,
        message: RandBitMessage,
    ) -> Result<Vec<RobustShare<F>>, RandBitError> {
        info!(
            "RandBit reconstruction msg received from node: {0:?}",
            message.sender
        );
        let session_id = match self.original_session_id {
            Some(original_session_id) => original_session_id,
            None => {
                error!("The session ID is not set. This should not happen.");
                return Err(RandBitError::SessionIdNotSet);
            }
        };
        let storage_bind = self.get_or_create_storage(session_id).await;
        let mut storage = storage_bind.lock().await;
        let a = storage
            .a_share
            .clone()
            .ok_or(RandBitError::NotInitialized)?;

        // This is safe as we tested in the init step that a % (t + 1) = 0.
        let batch_size = a.len() / (self.threshold + 1);

        let open: Vec<F> =
            CanonicalDeserialize::deserialize_compressed(message.payload.as_slice())?;
        let round_id = message.session_id.round_id();
        if storage.output_open.contains_key(&round_id) {
            return Err(RandBitError::Duplicate(format!(
                "Already received from {}",
                message.sender
            )));
        }
        storage.output_open.insert(round_id, open);
        if storage.output_open.len() != batch_size {
            warn!("Batches are not ready, Waiting for the rest of the batches");
            return Err(RandBitError::WaitForAllBatches);
        }

        let a_square_array = concat_sorted(&storage.output_open);
        drop(storage);

        // Step 4.
        for a_square in &a_square_array {
            if *a_square == F::zero() {
                return Err(RandBitError::ZeroSquare);
            }
        }

        // Step 5.
        let mut b_array = Vec::new();
        for a_square in &a_square_array {
            let b = a_square
                .sqrt()
                .ok_or(RandBitError::SquareRootDoesNotExist)?;
            b_array.push(b);
        }

        // Step 6.
        let mut b_inv_array = Vec::new();
        for b in &b_array {
            let b_inv = b.inverse().ok_or(RandBitError::Inverse)?;
            b_inv_array.push(b_inv);
        }

        let a_share_array = {
            let storage_for_sid = self.get_or_create_storage(session_id).await;
            let storage_guard = storage_for_sid.lock().await;
            storage_guard
                .a_share
                .clone()
                .ok_or(RandBitError::NotInitialized)?
        };

        let mut c_share_array = Vec::new();
        for (a_share, b_inv) in izip!(&a_share_array, &b_inv_array) {
            let c_share = a_share.clone().mul(b_inv.clone())?;
            c_share_array.push(c_share);
        }

        // Step 7.
        // SAFETY: we can unwrap as the field cannot have characteristic 2.
        let two_inv = (F::one() + F::one()).inverse().unwrap();
        let mut d_share_array = Vec::new();
        for c_share in &c_share_array {
            let d = c_share.clone().add(F::one())?.mul(two_inv)?;
            d_share_array.push(d);
        }

        // Mark the protocol as finished.
        {
            let storage_bind = self.get_or_create_storage(session_id).await;
            let mut storage = storage_bind.lock().await;
            storage.protocol_state = ProtocolState::Finished;
            storage.protocol_output = Some(d_share_array.clone());
        }

        // You send the current session ID as finished to the sender channel.
        self.output_channel.send(session_id).await?;

        Ok(d_share_array)
    }

    pub async fn process(&mut self, message: RandBitMessage) -> Result<(), RandBitError> {
        self.square_reconstruction_handler(message).await?;
        Ok(())
    }
}
