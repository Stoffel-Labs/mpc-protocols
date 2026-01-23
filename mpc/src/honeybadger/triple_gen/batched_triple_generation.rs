//! Batched Triple Generation
//!
//! This module provides an optimized triple generation that combines multiple
//! batch reconstructions into a SINGLE network round.
//!
//! ## Performance Improvement
//!
//! Traditional approach (for 20000 triples with t=1):
//! - group_size = 2t+1 = 3
//! - num_batches = 6,667 separate batch reconstruction protocols
//! - Each protocol requires network round trips
//!
//! Batched approach:
//! - 1 network round containing ALL batch data
//! - Local interpolation for each batch
//! - ~6667x fewer network round trips

use std::{collections::HashMap, sync::Arc};

use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use dashmap::DashMap;
use itertools::izip;
use stoffelnet::network_utils::{Network, PartyId};
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::{
    common::{
        lagrange_interpolate,
        share::{apply_vandermonde, make_vandermonde, shamir::NonRobustShare},
    },
    honeybadger::{
        double_share::DoubleShamirShare,
        robust_interpolate::robust_interpolate::RobustShare,
        triple_gen::{ShamirBeaverTriple, TripleGenError, TripleGenMessage},
        SessionId, WrappedMessage,
    },
};

use super::triple_generation::ProtocolState;

/// Message types for batched triple generation protocol
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BatchedTripleMessageType {
    /// Reveal message containing Vandermonde-encoded shares for all batches
    Reveal,
    /// OK message confirming successful reconstruction
    Ok,
}

/// Storage for batched triple generation.
#[derive(Clone, Debug)]
pub struct BatchedTripleGenStorage<F: FftField> {
    pub protocol_state: ProtocolState,
    /// All RanDouSha pairs (for final triple computation)
    pub randousha_pairs: Vec<DoubleShamirShare<F>>,
    /// All random shares for 'a' values
    pub random_shares_a: Vec<RobustShare<F>>,
    /// All random shares for 'b' values
    pub random_shares_b: Vec<RobustShare<F>>,
    /// Number of secrets per batch (2t+1 for degree 2t reconstruction)
    pub secrets_per_batch: usize,
    /// Number of batches
    pub num_batches: usize,
    /// Total number of triples being generated
    pub total_triples: usize,
    /// Our computed Vandermonde-encoded shares for all batches
    /// Layout: [batch0_share, batch1_share, ..., batchM_share]
    pub our_vandermonde_shares: Vec<F>,
    /// Received Vandermonde shares from other parties
    /// Key: party_id, Value: [batch0_share, batch1_share, ..., batchM_share]
    pub received_shares: HashMap<PartyId, Vec<F>>,
    /// Parties that sent OK messages
    pub ok_received: Vec<PartyId>,
    /// Output triples
    pub protocol_output: Vec<ShamirBeaverTriple<F>>,
}

impl<F: FftField> BatchedTripleGenStorage<F> {
    pub fn new(secrets_per_batch: usize, num_batches: usize, total_triples: usize) -> Self {
        Self {
            protocol_state: ProtocolState::NotInitialized,
            randousha_pairs: Vec::new(),
            random_shares_a: Vec::new(),
            random_shares_b: Vec::new(),
            secrets_per_batch,
            num_batches,
            total_triples,
            our_vandermonde_shares: Vec::new(),
            received_shares: HashMap::new(),
            ok_received: Vec::new(),
            protocol_output: Vec::new(),
        }
    }
}

/// Batched Triple Generation Node
///
/// Generates multiple Beaver triples using a SINGLE network round,
/// dramatically reducing network round trips.
#[derive(Clone, Debug)]
pub struct BatchedTripleGenNode<F: FftField> {
    pub id: PartyId,
    pub n_parties: usize,
    pub threshold: usize,
    pub store: Arc<DashMap<SessionId, Arc<Mutex<BatchedTripleGenStorage<F>>>>>,
    pub output_sender: Sender<SessionId>,
}

impl<F: FftField> BatchedTripleGenNode<F> {
    pub fn new(
        id: PartyId,
        n_parties: usize,
        threshold: usize,
        output_sender: Sender<SessionId>,
    ) -> Result<Self, TripleGenError> {
        Ok(Self {
            id,
            n_parties,
            threshold,
            store: Arc::new(DashMap::new()),
            output_sender,
        })
    }

    pub async fn get_or_create_store(
        &self,
        session_id: SessionId,
        secrets_per_batch: usize,
        num_batches: usize,
        total_triples: usize,
    ) -> Arc<Mutex<BatchedTripleGenStorage<F>>> {
        self.store
            .entry(session_id)
            .or_insert_with(|| {
                Arc::new(Mutex::new(BatchedTripleGenStorage::new(
                    secrets_per_batch,
                    num_batches,
                    total_triples,
                )))
            })
            .clone()
    }

    /// Initialize batched triple generation with ALL triples at once.
    ///
    /// This computes all sub_shares, groups them into batches, applies Vandermonde
    /// encoding, and sends ONE message containing all batch data.
    pub async fn init<N: Network + Send + Sync + 'static>(
        &self,
        random_shares_a: Vec<RobustShare<F>>,
        random_shares_b: Vec<RobustShare<F>>,
        randousha_pairs: Vec<DoubleShamirShare<F>>,
        session_id: SessionId,
        network: Arc<N>,
    ) -> Result<(), TripleGenError> {
        let total_triples = random_shares_a.len();

        // For degree 2t shares, we need 2t+1 reveals to interpolate
        // Batch reconstruction produces 2t+1 secrets per batch
        let secrets_per_batch = 2 * self.threshold + 1;
        let num_batches = (total_triples + secrets_per_batch - 1) / secrets_per_batch;

        if random_shares_b.len() != total_triples || randousha_pairs.len() != total_triples {
            return Err(TripleGenError::NotEnoughShares);
        }

        info!(
            total_triples,
            secrets_per_batch,
            num_batches,
            "BatchedTripleGen: Initializing with {} triples in {} batches (1 network round)",
            total_triples,
            num_batches
        );

        // Step 1: Compute ALL sub_shares_deg_2t
        let mut all_sub_shares: Vec<RobustShare<F>> = Vec::with_capacity(total_triples);
        for (share_a, share_b, ran_dou_sha) in
            izip!(&random_shares_a, &random_shares_b, &randousha_pairs)
        {
            let mult_share_deg_2t = share_a.share_mul(share_b)?;
            let sub_share_deg_2t =
                (mult_share_deg_2t - RobustShare::from(ran_dou_sha.degree_2t.clone()))?;
            all_sub_shares.push(sub_share_deg_2t);
        }

        // Pad to full batches if needed
        let padded_size = num_batches * secrets_per_batch;
        while all_sub_shares.len() < padded_size {
            // Pad with zero shares (won't affect real outputs)
            all_sub_shares.push(RobustShare::new(F::zero(), self.id, 2 * self.threshold));
        }

        // Step 2: For each batch, apply Vandermonde encoding
        // Vandermonde takes secrets_per_batch shares and produces n evaluation points
        // We only need our evaluation point (at position self.id)
        let vandermonde_matrix = make_vandermonde(self.n_parties, secrets_per_batch - 1)?;

        let mut our_vandermonde_shares: Vec<F> = Vec::with_capacity(num_batches);

        for batch_idx in 0..num_batches {
            let batch_start = batch_idx * secrets_per_batch;
            let batch_shares: Vec<NonRobustShare<F>> = all_sub_shares[batch_start..batch_start + secrets_per_batch]
                .iter()
                .map(|rs| NonRobustShare::new(rs.share[0], rs.id, rs.degree))
                .collect();

            // Apply Vandermonde to get n evaluation points
            let evaluations = apply_vandermonde(&vandermonde_matrix, &batch_shares)?;

            // Keep only our evaluation point (evaluations is Vec<NonRobustShare<F>>)
            // NonRobustShare.share is [F; 1], so we access share[0]
            our_vandermonde_shares.push(evaluations[self.id].share[0]);

            // Yield periodically
            if batch_idx % 32 == 31 {
                tokio::task::yield_now().await;
            }
        }

        // Store inputs for later use
        {
            let storage_arc = self
                .get_or_create_store(session_id, secrets_per_batch, num_batches, total_triples)
                .await;
            let mut storage = storage_arc.lock().await;
            storage.protocol_state = ProtocolState::Initialized;
            storage.randousha_pairs = randousha_pairs;
            storage.random_shares_a = random_shares_a;
            storage.random_shares_b = random_shares_b;
            storage.our_vandermonde_shares = our_vandermonde_shares.clone();
            // Add our own shares to received
            storage.received_shares.insert(self.id, our_vandermonde_shares.clone());
        }

        info!(
            session_id = ?session_id,
            num_batches,
            "BatchedTripleGen: Sending {} Vandermonde shares in SINGLE message",
            num_batches
        );

        // Step 3: Send our Vandermonde shares to all parties in ONE message
        let mut payload = Vec::new();
        // Encode message type (0 = Reveal)
        0u8.serialize_compressed(&mut payload)?;
        our_vandermonde_shares.serialize_compressed(&mut payload)?;

        let triple_msg = TripleGenMessage::new(self.id, session_id, payload);
        let wrapped = WrappedMessage::BatchedTriple(triple_msg);
        let bytes = bincode::serialize(&wrapped)?;

        // Broadcast to all parties
        for pid in 0..self.n_parties {
            network.send(pid, &bytes).await?;
        }

        Ok(())
    }

    /// Process incoming batched triple generation message.
    pub async fn process<N: Network + Send + Sync + 'static>(
        &self,
        session_id: SessionId,
        sender_id: PartyId,
        payload: &[u8],
        network: Arc<N>,
    ) -> Result<(), TripleGenError> {
        // Decode message type
        let msg_type: u8 = CanonicalDeserialize::deserialize_compressed(&payload[..1])?;
        let data = &payload[1..];

        match msg_type {
            0 => self.handle_reveal(session_id, sender_id, data, network).await,
            1 => self.handle_ok(session_id, sender_id).await,
            _ => {
                warn!("BatchedTripleGen: Unknown message type {}", msg_type);
                Ok(())
            }
        }
    }

    /// Handle Reveal message containing Vandermonde shares for all batches
    async fn handle_reveal<N: Network + Send + Sync + 'static>(
        &self,
        session_id: SessionId,
        sender_id: PartyId,
        data: &[u8],
        network: Arc<N>,
    ) -> Result<(), TripleGenError> {
        let shares: Vec<F> = CanonicalDeserialize::deserialize_compressed(data)?;

        // Get or create storage (we might receive before our own init completes)
        let num_batches = shares.len();
        let secrets_per_batch = 2 * self.threshold + 1;
        let total_triples = num_batches * secrets_per_batch; // Upper bound estimate

        let storage_arc = self
            .get_or_create_store(session_id, secrets_per_batch, num_batches, total_triples)
            .await;
        let mut storage = storage_arc.lock().await;

        // Store received shares
        storage.received_shares.insert(sender_id, shares);

        info!(
            session_id = ?session_id,
            sender_id,
            received_count = storage.received_shares.len(),
            needed = self.n_parties,
            "BatchedTripleGen: Received reveal from party {}",
            sender_id
        );

        // For robust interpolation of a degree-2t polynomial, we need 2*(2t)+1 = 4t+1 shares
        // to have enough redundancy for error correction. This means we need all n parties.
        // Note: secrets_per_batch = 2t+1, so the polynomial degree is 2t
        let needed_reveals = self.n_parties; // Need all parties for robust interpolation
        if storage.received_shares.len() >= needed_reveals
            && storage.protocol_state != ProtocolState::Finished
            && !storage.our_vandermonde_shares.is_empty()
        {
            // Perform reconstruction for all batches
            let reconstructed = self.reconstruct_all_batches(&storage)?;

            // Create triples from reconstructed values
            let mut result_triples = Vec::with_capacity(storage.total_triples);
            for (i, (sub_value, pair, share_a, share_b)) in izip!(
                reconstructed.into_iter(),
                &storage.randousha_pairs,
                &storage.random_shares_a,
                &storage.random_shares_b,
            ).enumerate() {
                if i >= storage.total_triples {
                    break; // Don't include padding
                }
                let result_share = (pair.degree_t.clone() + &sub_value)?;
                result_triples.push(ShamirBeaverTriple::new(
                    share_a.clone(),
                    share_b.clone(),
                    result_share.into(),
                ));
            }

            storage.protocol_output = result_triples;
            storage.protocol_state = ProtocolState::Finished;

            info!(
                session_id = ?session_id,
                id = self.id,
                num_triples = storage.protocol_output.len(),
                "BatchedTripleGen: Protocol finished with {} triples",
                storage.protocol_output.len()
            );

            drop(storage);

            // Send OK to all parties
            let mut ok_payload = Vec::new();
            1u8.serialize_compressed(&mut ok_payload)?;

            let triple_msg = TripleGenMessage::new(self.id, session_id, ok_payload);
            let wrapped = WrappedMessage::BatchedTriple(triple_msg);
            let bytes = bincode::serialize(&wrapped)?;

            for pid in 0..self.n_parties {
                network.send(pid, &bytes).await?;
            }

            // Signal completion
            self.output_sender.send(session_id).await?;
        }

        Ok(())
    }

    /// Reconstruct all batches from received Vandermonde shares using Lagrange interpolation.
    ///
    /// Each batch consists of evaluation points (y_i) at x = 1, 2, ..., n.
    /// We interpolate to recover the polynomial coefficients, which are the secrets.
    fn reconstruct_all_batches(
        &self,
        storage: &BatchedTripleGenStorage<F>,
    ) -> Result<Vec<F>, TripleGenError> {
        let num_batches = storage.num_batches;
        let secrets_per_batch = storage.secrets_per_batch;

        // Pre-compute x values (evaluation points): 1, 2, ..., n
        // These match the Vandermonde matrix construction: make_vandermonde uses (i+1)^j
        let x_vals: Vec<F> = (1..=self.n_parties)
            .map(|i| F::from(i as u64))
            .collect();

        // For each batch, we need to interpolate from the received evaluation points
        // to recover the secrets_per_batch coefficients (secrets)
        let mut all_secrets: Vec<F> = Vec::with_capacity(num_batches * secrets_per_batch);

        for batch_idx in 0..num_batches {
            // Collect this batch's y values from all parties in order
            // We need exactly n_parties values at points 1, 2, ..., n
            let mut y_vals: Vec<F> = vec![F::zero(); self.n_parties];

            for (&party_id, shares) in &storage.received_shares {
                if batch_idx < shares.len() && party_id < self.n_parties {
                    y_vals[party_id] = shares[batch_idx];
                }
            }

            // Use simple Lagrange interpolation to recover the polynomial
            // The polynomial has degree secrets_per_batch - 1 = 2t
            let poly = lagrange_interpolate(&x_vals, &y_vals)?;

            // The polynomial coefficients are the secrets
            for i in 0..secrets_per_batch {
                if i < poly.coeffs.len() {
                    all_secrets.push(poly.coeffs[i]);
                } else {
                    all_secrets.push(F::zero());
                }
            }
        }

        Ok(all_secrets)
    }

    /// Handle OK message
    async fn handle_ok(
        &self,
        session_id: SessionId,
        sender_id: PartyId,
    ) -> Result<(), TripleGenError> {
        if let Some(storage_ref) = self.store.get(&session_id) {
            let mut storage = storage_ref.lock().await;
            if !storage.ok_received.contains(&sender_id) {
                storage.ok_received.push(sender_id);
            }
        }
        Ok(())
    }

    /// Clear storage for a session
    pub async fn clear_store(&self, session_id: SessionId) {
        self.store.remove(&session_id);
    }
}
