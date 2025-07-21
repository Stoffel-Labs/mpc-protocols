use std::{collections::HashMap, sync::Arc};

use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::rand::Rng;
use bincode::ErrorKind;
use itertools::izip;
use serde::{Deserialize, Serialize};
use stoffelmpc_network::{Message, Network, NetworkError, Node, PartyId, SessionId};
use thiserror::Error;
use tokio::sync::Mutex;

use crate::common::share::{shamir::NonRobustShamirShare, ShareError};

use super::DoubleShamirShare;

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
    pub shares_a: Vec<NonRobustShamirShare<F>>,
    pub shares_b: Vec<NonRobustShamirShare<F>>,
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
    pub shares: Vec<NonRobustShamirShare<F>>,
}

impl<F> ShareMessage<F>
where
    F: FftField,
{
    pub fn new(
        sender_id: PartyId,
        session_id: SessionId,
        shares: Vec<NonRobustShamirShare<F>>,
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
        random_shares_a: Vec<NonRobustShamirShare<F>>,
        random_shares_b: Vec<NonRobustShamirShare<F>>,
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

        let mut sub_shares_deg_2t = Vec::new();
        for ((share_a, share_b), ran_dou_sha) in random_shares_a
            .iter()
            .zip(&random_shares_b)
            .zip(&randousha_pairs)
        {
            let mult_share_deg_2t = share_a.share_mul(share_b)?;
            let sub_share_deg_2t = (mult_share_deg_2t - &ran_dou_sha.degree_2t)?;
            sub_shares_deg_2t.push(sub_share_deg_2t);
        }

        // Store the provided random shares to be used in the second step of the protocol.
        let storage_binder = self.get_or_create_store(self.params.session_id).await;
        let mut storage = storage_binder.lock().await;
        storage.ran_dou_sha = randousha_pairs;
        storage.shares_a = random_shares_a;
        storage.shares_b = random_shares_b;

        let share_message = ShareMessage::new(self.id, self.params.session_id, sub_shares_deg_2t);
        let mut bytes_share_msg = Vec::new();
        share_message.serialize_compressed(&mut bytes_share_msg)?;

        let generic_share_message =
            TripleGenMessage::new(self.id, self.params.session_id, bytes_share_msg);
        let bytes_generic_msg = bincode::serialize(&generic_share_message)?;

        network.broadcast(&bytes_generic_msg).await?;

        Ok(())
    }

    pub async fn share_handler(
        &mut self,
        share_message: ShareMessage<F>,
    ) -> Result<Vec<ShamirBeaverTriple<F>>, TripleGenError> {
        let storage_binder = self.get_or_create_store(self.params.session_id).await;
        let storage = storage_binder.lock().await;

        let mut result_triples = Vec::with_capacity(self.params.n_triples);
        for (share_a, share_b, mult_plus_r, randousha_pair) in izip!(
            &storage.shares_a,
            &storage.shares_b,
            &share_message.shares,
            &storage.ran_dou_sha
        ) {
            let mult_result = (mult_plus_r.clone() - &randousha_pair.degree_t)?;
            let triple = ShamirBeaverTriple::new(share_a.clone(), share_b.clone(), mult_result);
            result_triples.push(triple);
        }

        Ok(result_triples)
    }
}
