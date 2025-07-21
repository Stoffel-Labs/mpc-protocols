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
    batch_recon::{batch_recon::BatchReconNode, BatchReconError},
    robust_interpolate::RobustShamirShare,
    DoubleShamirShare,
};

#[derive(Debug, Error)]
pub enum TripleGenError {
    #[error("network error: {0:?}")]
    NetworkError(#[from] NetworkError),
    #[error("share error: {0:?}")]
    ShareError(#[from] ShareError),
    #[error("not enough preprocessing")]
    NotEnoughPreprocessing,
    #[error("error during the serialization using bincode: {0:?}")]
    BincodeSerializationError(#[from] Box<ErrorKind>),
    #[error("error during the serialization using bincode: {0:?}")]
    ArkSerializationError(#[from] SerializationError),
    #[error("wrong ammount of shares")]
    NotEnoughShares,
    #[error("batch reconstruction error: {0:?}")]
    BatchReconError(#[from] BatchReconError),
    #[error("async error: {0:?}")]
    AsyncError(#[from] JoinError),
}

pub struct ShamirBeaverTriple<F: FftField> {
    pub a: NonRobustShamirShare<F>,
    pub b: NonRobustShamirShare<F>,
    pub mult: NonRobustShamirShare<F>,
}

impl<F> ShamirBeaverTriple<F>
where
    F: FftField,
{
    pub fn new(
        a: NonRobustShamirShare<F>,
        b: NonRobustShamirShare<F>,
        mult: NonRobustShamirShare<F>,
    ) -> Self {
        Self { a, b, mult }
    }
}

pub struct TripleGenParams {
    pub session_id: SessionId,
    pub n_parties: usize,
    pub threshold: usize,
    pub n_triples: usize,
}

impl TripleGenParams {
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

pub enum ProtocolState {
    NotInitialized,
    Initialized,
    Finished,
}

pub struct TripleGenStorage<F>
where
    F: FftField,
{
    pub ran_dou_sha: Vec<DoubleShamirShare<F>>,
    pub shares_a: Vec<RobustShamirShare<F>>,
    pub shares_b: Vec<RobustShamirShare<F>>,
}

impl<F> TripleGenStorage<F>
where
    F: FftField,
{
    pub fn empty(n_triples: usize) -> Self {
        Self {
            ran_dou_sha: Vec::with_capacity(n_triples),
            shares_a: Vec::with_capacity(n_triples),
            shares_b: Vec::with_capacity(n_triples),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TripleGenMessage {
    pub sender_id: PartyId,
    pub session_id: SessionId,
    pub payload: Vec<u8>,
}

impl TripleGenMessage {
    pub fn new(sender_id: PartyId, session_id: SessionId, payload: Vec<u8>) -> Self {
        Self {
            sender_id,
            session_id,
            payload,
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

#[derive(Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ShareMessage<F: FftField> {
    pub sender_id: PartyId,
    pub session_id: SessionId,
    pub shares: Vec<RobustShamirShare<F>>,
}

impl<F> ShareMessage<F>
where
    F: FftField,
{
    pub fn new(
        sender_id: PartyId,
        session_id: SessionId,
        shares: Vec<RobustShamirShare<F>>,
    ) -> Self {
        Self {
            sender_id,
            session_id,
            shares,
        }
    }
}

pub struct TripleGenNode<F>
where
    F: FftField,
{
    pub id: PartyId,
    pub params: TripleGenParams,
    pub storage: Arc<Mutex<HashMap<SessionId, Arc<Mutex<TripleGenStorage<F>>>>>>,
}

impl<F: FftField> TripleGenNode<F> {
    pub async fn get_or_create_store(
        &mut self,
        session_id: SessionId,
    ) -> Arc<Mutex<TripleGenStorage<F>>> {
        let mut storage = self.storage.lock().await;
        storage
            .entry(session_id)
            .or_insert(Arc::new(Mutex::new(TripleGenStorage::empty(
                self.params.n_triples,
            ))))
            .clone()
    }

    pub async fn init<R: Rng, N: Network>(
        &mut self,
        random_shares_a: Vec<RobustShamirShare<F>>,
        random_shares_b: Vec<RobustShamirShare<F>>,
        randousha_pairs: Vec<DoubleShamirShare<F>>,
        network: Arc<N>,
    ) -> Result<Vec<NonRobustShamirShare<F>>, TripleGenError> {
        // Validates that there are enough random double shares and random shares to perform the
        // operation.
        if randousha_pairs.len() != self.params.n_triples
            || random_shares_a.len() != self.params.n_triples
            || random_shares_b.len() != self.params.n_triples
        {
            return Err(TripleGenError::NotEnoughPreprocessing);
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
            .init_batch_reconstruct(&sub_shares_deg_2t, Arc::clone(&network))
            .await?;

        let sub_values_clean = tokio::spawn(async move {
            loop {
                match batch_recon_node.secrets {
                    None => continue,
                    Some(rbc_result) => return rbc_result,
                };
            }
        })
        .await?;

        let mut result_shares = Vec::new();
        for (sub_value, pair) in sub_values_clean.into_iter().zip(randousha_pairs) {
            let result_share = (pair.degree_t + &sub_value)?;
            result_shares.push(result_share);
        }
        Ok(result_shares)
    }
}
