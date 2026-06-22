use std::{collections::HashMap, sync::Arc};

use ark_ff::FftField;
use itertools::izip;
use stoffelnet::network_utils::{Network, PartyId};
use tokio::sync::mpsc::Receiver;
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};
use tracing::info;

use crate::common::utils::deser_bounded_vec;
use crate::honeybadger::triple_gen::{TripleGenError, TripleGenStorage};
use crate::honeybadger::{
    double_share::DoubleShamirShare, triple_gen::ShamirBeaverTriple, SessionId,
};

use crate::honeybadger::{
    batch_recon::batch_recon::BatchReconNode, robust_interpolate::robust_interpolate::RobustShare,
};

/// Current state of the Shamir Beaver triple generation protocol.
#[derive(Clone, PartialEq, Debug)]
pub enum ProtocolState {
    /// The protocol has not been initialized.
    NotInitialized,
    /// The protocol has been initialized and under execution.
    Initialized,
    /// The protocol has finished.
    Finished,
}

/// Represents a node in the Triple generation protocol.
#[derive(Clone, Debug)]
pub struct TripleGenNode<F>
where
    F: FftField,
{
    /// ID of the node.
    pub id: PartyId,
    /// The number of parties participating in the triple generation protocol.
    pub n_parties: usize,
    /// The upper bound of corrupt parties participating in the triple generation protocol.
    pub threshold: usize,
    /// Internal storage of the node.
    pub storage: Arc<Mutex<HashMap<SessionId, (usize, Arc<Mutex<TripleGenStorage<F>>>)>>>,
    /// Batch reconstruction node used in the triple generation
    pub batch_recon_node: BatchReconNode<F>,
    pub batch_output: Arc<Mutex<Receiver<SessionId>>>,
}

// pub static MAX_TRIPLE_GEN_SESSIONS: usize = 1024;

impl<F> TripleGenNode<F>
where
    F: FftField,
{
    pub fn new(id: PartyId, n_parties: usize, threshold: usize) -> Result<Self, TripleGenError> {
        let (batch_sender, batch_receiver) = tokio::sync::mpsc::channel(200);
        // batch_recon_node is for opening degree 2t shares
        let batch_recon_node =
            BatchReconNode::<F>::new(id, n_parties, threshold, threshold * 2, batch_sender)?;
        Ok(Self {
            id,
            n_parties,
            threshold,
            storage: Arc::new(Mutex::new(HashMap::new())),
            batch_recon_node,
            batch_output: Arc::new(Mutex::new(batch_receiver)),
        })
    }

    /// Accesses the storage of the node, and in case that the storage does not exists yet for the
    /// given `session_id`, it is created in place and returned.
    pub async fn get_or_create_store(
        &mut self,
        session_id: SessionId,
        initiator_id: usize,
    ) -> Result<Arc<Mutex<TripleGenStorage<F>>>, TripleGenError> {
        let mut storage = self.storage.lock().await;

        // TODO: restore session limits
        // if !storage.contains_key(&session_id) {
        //     if storage.len() >= MAX_TRIPLE_GEN_SESSIONS {
        //         return Err(TripleGenError::LimitError);
        //     }
        //     let per_peer_limit = MAX_TRIPLE_GEN_SESSIONS / self.n_parties;
        //     let peer_count = storage
        //         .values()
        //         .filter(|(id, _)| *id == initiator_id)
        //         .count();
        //     if peer_count >= per_peer_limit {
        //         return Err(TripleGenError::LimitError);
        //     }
        // }

        Ok(storage
            .entry(session_id)
            .or_insert((
                initiator_id,
                Arc::new(Mutex::new(TripleGenStorage::empty())),
            ))
            .1
            .clone())
    }
    pub async fn clear_store(&self, session_id: SessionId) -> bool {
        self.batch_recon_node.clear_store(session_id).await;
        let mut store = self.storage.lock().await;
        store.remove(&session_id).is_some()
    }

    pub async fn store_len(&self) -> usize {
        self.storage.lock().await.len()
    }

    pub async fn drain_batch_recon_output(&mut self) -> Result<(), TripleGenError> {
        loop {
            let id = {
                let mut rx = self.batch_output.lock().await;
                match rx.try_recv() {
                    Ok(id) => id,
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        return Err(TripleGenError::Abort);
                    }
                }
            };

            let output = self.batch_recon_node.get_store(id).await?;
            match self.batch_recon_finish_handler(id, output).await {
                Ok(()) => {}
                Err(e) => {
                    return Err(e);
                }
            }
        }
        Ok(())
    }
    pub async fn wait_for_result(
        &self,
        session_id: SessionId,
        duration: Duration,
    ) -> Result<Vec<ShamirBeaverTriple<F>>, TripleGenError> {
        let output_receiver = {
            let storage = self.storage.lock().await;
            let storage_bind = match storage.get(&session_id) {
                Some((_, arc)) => arc,
                None => return Err(TripleGenError::NoSuchSessionId(session_id)),
            };
            let mut storage = storage_bind.lock().await;

            storage
                .output_receiver
                .take()
                .ok_or(TripleGenError::ResultAlreadyReceived(session_id))?
        };

        match timeout(duration, output_receiver).await {
            Err(_) => Err(TripleGenError::Timeout(session_id)),
            Ok(Err(_)) => Err(TripleGenError::ReceiveError(session_id)),
            Ok(Ok(shares)) => Ok(shares),
        }
    }

    async fn try_finalize_triple_gen(
        &self,
        session_id: SessionId,
        storage_bind: Arc<Mutex<TripleGenStorage<F>>>,
    ) -> Result<bool, TripleGenError> {
        // ---------- Phase 1: Check readiness ----------
        let (batch_recon_result, randousha_pairs, random_a, random_b) = {
            let storage = storage_bind.lock().await;

            if storage.protocol_state == ProtocolState::Finished {
                return Ok(true);
            }

            if storage.protocol_state != ProtocolState::Initialized {
                return Ok(false);
            }

            let Some(result) = storage.batch_recon_result.clone() else {
                return Ok(false);
            };

            (
                result,
                storage.randousha_pairs.clone(),
                storage.random_shares_a_input.clone(),
                storage.random_shares_b_input.clone(),
            )
        };

        // ---------- Phase 2: Compute outside lock ----------
        let mut result_triples = Vec::new();

        for (sub_value, pair, share_a, share_b) in izip!(
            batch_recon_result.into_iter(),
            &randousha_pairs,
            &random_a,
            &random_b,
        ) {
            let result_share = (pair.degree_t.clone() + &sub_value)?;
            result_triples.push(ShamirBeaverTriple::new(
                share_a.clone(),
                share_b.clone(),
                result_share.into(),
            ));
        }

        // ---------- Phase 3: Commit + send ----------
        let sender = {
            let mut storage = storage_bind.lock().await;

            if storage.protocol_state == ProtocolState::Finished {
                return Ok(true);
            }

            storage.protocol_state = ProtocolState::Finished;
            storage.protocol_output = result_triples.clone();

            storage
                .output_sender
                .take()
                .ok_or(TripleGenError::SendError(session_id))?
        };

        sender
            .send(result_triples)
            .map_err(|_| TripleGenError::SendError(session_id))?;

        Ok(true)
    }
    /// Initializes the protocol to generate random triples based on previously generated shares
    /// and random double shares.
    pub async fn init<N: Network>(
        &mut self,
        random_shares_a: Vec<RobustShare<F>>,
        random_shares_b: Vec<RobustShare<F>>,
        randousha_pairs: Vec<DoubleShamirShare<F>>,
        session_id: SessionId,
        network: Arc<N>,
    ) -> Result<(), TripleGenError> {
        // Validates that there are enough random double shares and random shares to perform the
        // operation.

        info!(
            num_randousha = randousha_pairs.len(),
            num_random_a = random_shares_a.len(),
            num_random_b = random_shares_b.len(),
            "Initializing TripleGen protocol"
        );

        assert_eq!(session_id.sub_id(), 0);

        if randousha_pairs.len() != 2 * self.threshold + 1
            || random_shares_a.len() != 2 * self.threshold + 1
            || random_shares_b.len() != 2 * self.threshold + 1
        {
            return Err(TripleGenError::NotEnoughPreprocessing);
        }

        let mut sub_shares_deg_2t = Vec::new();
        for (share_a, share_b, ran_dou_sha) in
            izip!(&random_shares_a, &random_shares_b, &randousha_pairs)
        {
            let mult_share_deg_2t = share_a.share_mul(share_b)?;
            let sub_share_deg_2t =
                (mult_share_deg_2t - RobustShare::from(ran_dou_sha.degree_2t.clone()))?;
            sub_shares_deg_2t.push(sub_share_deg_2t);
        }

        // We mark the protocol as initialized and store the input shares.
        {
            let storage_bind = self.get_or_create_store(session_id, self.id).await?;
            let mut storage = storage_bind.lock().await;
            storage.protocol_state = ProtocolState::Initialized;
            storage.randousha_pairs = randousha_pairs;
            storage.random_shares_a_input = random_shares_a;
            storage.random_shares_b_input = random_shares_b;
        }

        let storage_bind = self.get_or_create_store(session_id, self.id).await?;

        if self
            .try_finalize_triple_gen(session_id, storage_bind.clone())
            .await?
        {
            return Ok(());
        }
        info!(
            ?session_id,
            "Starting batch reconstruction for degree-2t shares"
        );
        // Call to Batch Reconstruction.
        self.batch_recon_node
            .init_batch_reconstruct(&sub_shares_deg_2t, session_id, Arc::clone(&network))
            .await?;
        Ok(())
    }

    /// Initializes triple generation for multiple consecutive triple groups in one network
    /// session. Inputs are flattened as chunks of `2t + 1`; each chunk produces that many Beaver
    /// triples using the same algebra as `init`.
    pub async fn init_batch<N: Network>(
        &mut self,
        random_shares_a: Vec<RobustShare<F>>,
        random_shares_b: Vec<RobustShare<F>>,
        randousha_pairs: Vec<DoubleShamirShare<F>>,
        session_id: SessionId,
        network: Arc<N>,
    ) -> Result<(), TripleGenError> {
        let group_size = 2 * self.threshold + 1;

        info!(
            num_randousha = randousha_pairs.len(),
            num_random_a = random_shares_a.len(),
            num_random_b = random_shares_b.len(),
            groups = randousha_pairs.len() / group_size,
            "Initializing batched TripleGen protocol"
        );

        assert_eq!(session_id.sub_id(), 0);

        if randousha_pairs.is_empty()
            || randousha_pairs.len() % group_size != 0
            || random_shares_a.len() != randousha_pairs.len()
            || random_shares_b.len() != randousha_pairs.len()
        {
            return Err(TripleGenError::NotEnoughPreprocessing);
        }

        let mut sub_shares_deg_2t = Vec::with_capacity(randousha_pairs.len());
        for (share_a, share_b, ran_dou_sha) in
            izip!(&random_shares_a, &random_shares_b, &randousha_pairs)
        {
            let mult_share_deg_2t = share_a.share_mul(share_b)?;
            let sub_share_deg_2t =
                (mult_share_deg_2t - RobustShare::from(ran_dou_sha.degree_2t.clone()))?;
            sub_shares_deg_2t.push(sub_share_deg_2t);
        }

        {
            let storage_bind = self.get_or_create_store(session_id, self.id).await?;
            let mut storage = storage_bind.lock().await;
            storage.protocol_state = ProtocolState::Initialized;
            storage.randousha_pairs = randousha_pairs;
            storage.random_shares_a_input = random_shares_a;
            storage.random_shares_b_input = random_shares_b;
        }

        let storage_bind = self.get_or_create_store(session_id, self.id).await?;

        if self
            .try_finalize_triple_gen(session_id, storage_bind.clone())
            .await?
        {
            return Ok(());
        }

        self.batch_recon_node
            .init_batch_reconstruct_many(&sub_shares_deg_2t, session_id, Arc::clone(&network))
            .await?;
        Ok(())
    }

    pub async fn batch_recon_finish_handler(
        &mut self,
        session_id: SessionId,
        payload: Vec<u8>,
    ) -> Result<(), TripleGenError> {
        info!("Handling Batch reconstruction results");
        // SHOULD NEVER HAPPEN, since comes from batch reconstruction
        if session_id.sub_id() != 0 {
            return Err(TripleGenError::SessionIdError(session_id));
        }

        // SHOULD ALSO NEVER FAIL, since comes from batch reconstruction
        let storage_bind = self.get_or_create_store(session_id, self.id).await?;
        let expected_len = {
            let storage = storage_bind.lock().await;
            storage.randousha_pairs.len()
        };
        let batch_recon_result: Vec<F> = deser_bounded_vec(&mut payload.as_slice(), expected_len)?;
        {
            let mut storage = storage_bind.lock().await;

            if storage.protocol_state == ProtocolState::Finished {
                return Ok(());
            }

            // STORE result instead of immediately computing
            storage.batch_recon_result = Some(batch_recon_result);
        }

        self.try_finalize_triple_gen(session_id, storage_bind)
            .await?;

        Ok(())
    }
}
