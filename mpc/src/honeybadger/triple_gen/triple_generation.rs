use std::{collections::HashMap, sync::Arc};

use ark_ff::FftField;
use ark_serialize::CanonicalDeserialize;
use itertools::izip;
use stoffelnet::network_utils::{Network, PartyId};
use tokio::sync::{mpsc::Sender, Mutex};
use tracing::info;

use crate::honeybadger::triple_gen::{TripleGenError, TripleGenMessage, TripleGenStorage};
use crate::honeybadger::{
    double_share::DoubleShamirShare, triple_gen::ShamirBeaverTriple, SessionId,
};

use crate::honeybadger::{
    batch_recon::batch_recon::BatchReconNode,
    robust_interpolate::robust_interpolate::RobustShare,
};

/// Current state of the Shamir Beaver triple generation protocol.
#[derive(Clone, Debug)]
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
    pub storage: Arc<Mutex<HashMap<SessionId, Arc<Mutex<TripleGenStorage<F>>>>>>,
    pub output_sender: Sender<SessionId>,
    /// Batch reconstruction node used in the triple generation
    // TODO - should we put batch_recon_node here or in honeybadger node
    pub batch_recon_node: BatchReconNode<F>,
}

impl<F> TripleGenNode<F>
where
    F: FftField,
{
    pub fn new(
        id: PartyId,
        n_parties: usize,
        threshold: usize,
        output_sender: Sender<SessionId>,
    ) -> Result<Self, TripleGenError> {
        // batch_recon_node is for opening degree 2t shares
        let batch_recon_node = BatchReconNode::<F>::new(id, n_parties, threshold * 2)?;
        Ok(Self {
            id,
            n_parties,
            threshold,
            storage: Arc::new(Mutex::new(HashMap::new())),
            output_sender,
            batch_recon_node,
        })
    }

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

        if randousha_pairs.len() != 2*self.threshold + 1
            || random_shares_a.len() != 2*self.threshold + 1
            || random_shares_b.len() != 2*self.threshold + 1
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
            let storage_bind = self.get_or_create_store(session_id).await;
            let mut storage = storage_bind.lock().await;
            storage.protocol_state = ProtocolState::Initialized;
            storage.randousha_pairs = randousha_pairs;
            storage.random_shares_a_input = random_shares_a;
            storage.random_shares_b_input = random_shares_b;
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

    pub async fn batch_recon_finish_handler(
        &mut self,
        message: TripleGenMessage,
    ) -> Result<(), TripleGenError> {
        info!("Handling Batch reconstruction results");
        let batch_recon_result: Vec<F> =
            CanonicalDeserialize::deserialize_compressed(message.payload.as_slice())?;

        let storage_bind = self.get_or_create_store(message.session_id).await;
        let mut storage = storage_bind.lock().await;

        let mut result_triples = Vec::new();
        for (sub_value, pair, share_a, share_b) in izip!(
            batch_recon_result.into_iter(),
            &storage.randousha_pairs,
            &storage.random_shares_a_input,
            &storage.random_shares_b_input,
        ) {
            let result_share = (pair.degree_t.clone() + &sub_value)?;
            result_triples.push(ShamirBeaverTriple::new(
                share_a.clone(),
                share_b.clone(),
                result_share.into(),
            ));
        }

        // First, we mark the protocol as initialized.
        storage.protocol_state = ProtocolState::Finished;
        self.output_sender.send(message.session_id).await?;
        info!(?message.session_id, id = message.sender_id, "TripleGen protocol finished");

        // Store the result in the inner memory of the node.
        storage.protocol_output = result_triples;
        Ok(())
    }

    pub async fn process(&mut self, message: TripleGenMessage) -> Result<(), TripleGenError> {
        self.batch_recon_finish_handler(message).await?;
        Ok(())
    }
}
