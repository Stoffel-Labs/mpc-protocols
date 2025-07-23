use std::{collections::HashMap, ops::Sub, sync::Arc};

use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::rand::Rng;
use bincode::ErrorKind;
use itertools::izip;
use serde::{Deserialize, Serialize};
use stoffelmpc_network::{Message, Network, NetworkError, Node, PartyId, SessionId};
use thiserror::Error;
use tokio::{sync::Mutex, task::JoinError};

use crate::common::share::{shamir::NonRobustShamirShare, ShareError};

use super::{
    batch_recon::{
        self, batch_recon::BatchReconNode, BatchReconContentType, BatchReconError, BatchReconMsg,
    },
    robust_interpolate::RobustShamirShare,
    DoubleShamirShare,
};

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
}

/// Represents a Beaver triple of non-robus Shamir shares.
pub struct ShamirBeaverTriple<F: FftField> {
    /// First random value of the triple.
    pub a: NonRobustShamirShare<F>,
    /// Second random value of the triple.
    pub b: NonRobustShamirShare<F>,
    /// Multiplication of both random values.
    pub mult: NonRobustShamirShare<F>,
}

impl<F> ShamirBeaverTriple<F>
where
    F: FftField,
{
    /// Creates a new Shamir Beaver triple with `a` and `b` being the random values of the triple
    /// and `mult` is the multiplication of `a` and `b`.
    pub fn new(
        a: NonRobustShamirShare<F>,
        b: NonRobustShamirShare<F>,
        mult: NonRobustShamirShare<F>,
    ) -> Self {
        Self { a, b, mult }
    }
}

/// Parameters for the Beaver triple generation protocol.
pub struct TripleGenParams {
    /// The ID of the session.
    pub session_id: SessionId,
    /// The number of parties participating in the triple generation protocol.
    pub n_parties: usize,
    /// The upper bound of corrupt parties participating in the triple generation protocol.
    pub threshold: usize,
    /// The number of triples that will be generated.
    pub n_triples: usize,
}

impl TripleGenParams {
    /// Creates a new set of parameters for the triple generation protocol.
    pub fn new(
        session_id: SessionId,
        n_parties: usize,
        threshold: usize,
        n_triples: usize,
    ) -> Self {
        Self {
            session_id,
            n_parties,
            threshold,
            n_triples,
        }
    }
}

/// Current state of the Shamir Beaver triple generation protocol.
pub enum ProtocolState {
    /// The protocol has not been initialized.
    NotInitialized,
    /// The protocol has been initialized and under execution.
    Initialized,
    /// The protocol has finished.
    Finished,
}

/// Storage necessary for the triple generation protocol.
pub struct TripleGenStorage<F>
where
    F: FftField,
{
    /// Current state of the protocol execution.
    pub protocol_state: ProtocolState,
    pub randousha_pairs: Vec<DoubleShamirShare<F>>,
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
        }
    }
}

/// Generic message for the triple generation protocol.
///
/// This generic message contains the payload in bytes of any message sent during the protocol
/// execution. Any message that is sent in the protocol is converted into bytes that are placed in
/// the `payload`. Once a party receives a message, it takes the payload and deserialize it to the
/// specific message sent during the protocol execution.
#[derive(Clone, Serialize, Deserialize)]
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

#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct BatchReconFinishMessage<F: FftField> {
    pub content: Vec<F>,
    pub sender_id: PartyId,
    pub session_id: SessionId,
}

impl<F: FftField> BatchReconFinishMessage<F> {
    pub fn new(content: Vec<F>, sender_id: PartyId, session_id: SessionId) -> Self {
        Self {
            content,
            sender_id,
            session_id,
        }
    }
}

impl Message for TripleGenMessage {
    fn sender_id(&self) -> PartyId {
        self.sender_id
    }

    fn bytes(&self) -> &[u8] {
        &self.payload
    }
}

/// Represents a node in the Triple generation protocol.
pub struct TripleGenNode<F>
where
    F: FftField,
{
    /// ID of the node.
    pub id: PartyId,
    /// Parameters of the protocol.
    pub params: TripleGenParams,
    /// Internal storage of the node.
    pub storage: Arc<Mutex<HashMap<SessionId, Arc<Mutex<TripleGenStorage<F>>>>>>,
}

impl<F> TripleGenNode<F>
where
    F: FftField,
{
    /// Accesses the storage of the node, and in case that the storage does not exists yet for the
    /// given `session_id`, it is created in place and returned.
    pub async fn get_or_create_store(
        &mut self,
        session_id: SessionId,
    ) -> Arc<Mutex<TripleGenStorage<F>>> {
        let mut storage = self.storage.lock().await;
        storage
            .entry(session_id)
            .or_insert(Arc::new(Mutex::new(TripleGenStorage::empty())))
            .clone()
    }

    /// Initializes the protocol to generate random triples based on previously generated shares
    /// and random double shares.
    pub async fn init<R: Rng, N: Network>(
        &mut self,
        random_shares_a: Vec<RobustShamirShare<F>>,
        random_shares_b: Vec<RobustShamirShare<F>>,
        randousha_pairs: Vec<DoubleShamirShare<F>>,
        network: Arc<N>,
    ) -> Result<(), TripleGenError> {
        // Validates that there are enough random double shares and random shares to perform the
        // operation.
        if randousha_pairs.len() != self.params.n_triples
            || random_shares_a.len() != self.params.n_triples
            || random_shares_b.len() != self.params.n_triples
        {
            return Err(TripleGenError::NotEnoughPreprocessing);
        }

        // First, we mark the protocol as initialized.
        {
            let storage_bind = self.get_or_create_store(self.params.session_id).await;
            let mut storage = storage_bind.lock().await;
            storage.protocol_state = ProtocolState::Initialized;
            storage.randousha_pairs = randousha_pairs.clone();
        }

        let mut sub_shares_deg_2t = Vec::new();
        for (share_a, share_b, ran_dou_sha) in
            izip!(&random_shares_a, &random_shares_b, &randousha_pairs)
        {
            let mult_share_deg_2t = share_a.share_mul(share_b)?;
            let sub_share_deg_2t =
                (mult_share_deg_2t - &RobustShamirShare::from(ran_dou_sha.degree_2t.clone()))?;
            sub_shares_deg_2t.push(sub_share_deg_2t);
        }

        // Call to Batch Reconstruction.
        let batch_recon_node =
            BatchReconNode::<F>::new(self.id, self.params.n_parties, self.params.threshold)?;
        batch_recon_node
            .init_batch_reconstruct(
                &sub_shares_deg_2t,
                self.params.session_id,
                BatchReconContentType::TripleGenMessage,
                Arc::clone(&network),
            )
            .await?;
        Ok(())
    }

    pub async fn batch_recon_finish_handler(
        &mut self,
        batch_recon_message: BatchReconFinishMessage<F>,
    ) -> Result<Vec<NonRobustShamirShare<F>>, TripleGenError> {
        if batch_recon_message.session_id != self.params.session_id {
            return Err(TripleGenError::SessionIdMismatch);
        }
        let storage_bind = self.get_or_create_store(self.params.session_id).await;
        let storage = storage_bind.lock().await;

        let mut result_shares = Vec::new();
        for (sub_value, pair) in batch_recon_message
            .content
            .into_iter()
            .zip(&storage.randousha_pairs)
        {
            let result_share = (pair.degree_t.clone() + &sub_value)?;
            result_shares.push(result_share);
        }

        // First, we mark the protocol as initialized.
        let storage_bind = self.get_or_create_store(self.params.session_id).await;
        let mut storage = storage_bind.lock().await;
        storage.protocol_state = ProtocolState::Finished;

        Ok(result_shares)
    }

    pub async fn process<N: Network>(
        &mut self,
        message: &TripleGenMessage,
    ) -> Result<(), TripleGenError> {
        let batch_recon_finished_msg =
            BatchReconFinishMessage::deserialize_compressed(message.payload.as_slice())?;
        self.batch_recon_finish_handler(batch_recon_finished_msg)
            .await?;
        Ok(())
    }
}
