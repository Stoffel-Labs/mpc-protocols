//! Batched Random Double Share Generation Protocol
//!
//! This module implements a batched version of the RanDouSha protocol where each party
//! contributes K secrets (each with degree-t and degree-2t shares) instead of 1,
//! producing K*(t+1) random double shares per protocol run.
//!
//! For n=5, t=1, K=512:
//! - Original protocol: n secrets → (t+1) = 2 output double shares per run
//! - Batched protocol: K*n secrets → K*(t+1) = 1024 output double shares per run
//!
//! This reduces the number of protocol runs dramatically for large preprocessing needs.

use ark_ff::FftField;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use dashmap::DashMap;
use futures::future::try_join_all;
use std::{collections::HashMap, sync::Arc};
use stoffelnet::network_utils::{Network, PartyId};
use tokio::sync::{mpsc::Sender, Mutex};
use tracing::info;

use crate::{
    common::{
        share::{apply_vandermonde, make_vandermonde, shamir::NonRobustShare, ShareError},
        SecretSharingScheme, RBC,
    },
    honeybadger::{
        double_share::DoubleShamirShare,
        ran_dou_sha::{
            messages::{RanDouShaMessage, RanDouShaMessageType, RanDouShaPayload},
            RanDouShaError, RanDouShaState,
        },
        ProtocolType, SessionId, WrappedMessage,
    },
};

/// Storage for batched random double share generation.
/// Stores K double shares per party instead of 1.
#[derive(Clone, Debug)]
pub struct BatchedRanDouShaStore<F: FftField> {
    /// K double shares received from each party during init phase (party_id -> Vec of K NonRobustShare pairs)
    pub initial_shares_t: HashMap<PartyId, Vec<NonRobustShare<F>>>,
    pub initial_shares_2t: HashMap<PartyId, Vec<NonRobustShare<F>>>,
    /// Tracks which parties have sent their batched shares
    pub reception_tracker: Vec<bool>,
    /// K*n computed r shares of degree t after Vandermonde transformation
    pub computed_r_shares_degree_t: Vec<NonRobustShare<F>>,
    /// K*n computed r shares of degree 2t after Vandermonde transformation
    pub computed_r_shares_degree_2t: Vec<NonRobustShare<F>>,
    /// Received reconstruction shares (for verification)
    /// Each entry contains K pairs of (degree_t, degree_2t) shares
    pub received_r_shares_t: HashMap<PartyId, Vec<NonRobustShare<F>>>,
    pub received_r_shares_2t: HashMap<PartyId, Vec<NonRobustShare<F>>>,
    /// Parties who have confirmed successful reconstruction
    pub received_ok_msg: Vec<PartyId>,
    /// Current protocol state
    pub state: RanDouShaState,
    /// Final output: K*(t+1) random double shares
    pub protocol_output: Vec<DoubleShamirShare<F>>,
    /// Batch size K (number of secrets per party)
    pub batch_size: usize,
}

impl<F: FftField> BatchedRanDouShaStore<F> {
    pub fn new(n_parties: usize, batch_size: usize) -> Self {
        Self {
            initial_shares_t: HashMap::with_capacity(n_parties),
            initial_shares_2t: HashMap::with_capacity(n_parties),
            reception_tracker: vec![false; n_parties],
            computed_r_shares_degree_t: Vec::with_capacity(batch_size * n_parties),
            computed_r_shares_degree_2t: Vec::with_capacity(batch_size * n_parties),
            received_r_shares_t: HashMap::new(),
            received_r_shares_2t: HashMap::new(),
            received_ok_msg: Vec::new(),
            state: RanDouShaState::Initialized,
            protocol_output: Vec::new(),
            batch_size,
        }
    }
}

/// Batched Random Double Share Generation Node.
///
/// Each protocol run generates K*(t+1) random double shares instead of just (t+1).
/// This dramatically reduces the number of protocol invocations needed for
/// large-scale preprocessing (e.g., triple generation).
#[derive(Clone, Debug)]
pub struct BatchedRanDouShaNode<F: FftField, R: RBC> {
    pub id: PartyId,
    pub n_parties: usize,
    pub threshold: usize,
    pub store: Arc<DashMap<SessionId, Arc<Mutex<BatchedRanDouShaStore<F>>>>>,
    pub rbc: R,
    pub output_sender: Sender<SessionId>,
}

impl<F, R> BatchedRanDouShaNode<F, R>
where
    F: FftField,
    R: RBC,
{
    pub fn new(
        id: PartyId,
        output_sender: Sender<SessionId>,
        n_parties: usize,
        threshold: usize,
        k: usize,
    ) -> Result<Self, RanDouShaError> {
        let rbc = R::new(id, n_parties, threshold, k)?;
        Ok(Self {
            id,
            n_parties,
            threshold,
            store: Arc::new(DashMap::new()),
            rbc,
            output_sender,
        })
    }

    pub async fn get_or_create_store(
        &self,
        session_id: SessionId,
        batch_size: usize,
    ) -> Arc<Mutex<BatchedRanDouShaStore<F>>> {
        self.store
            .entry(session_id)
            .or_insert_with(|| {
                Arc::new(Mutex::new(BatchedRanDouShaStore::new(
                    self.n_parties,
                    batch_size,
                )))
            })
            .clone()
    }

    pub async fn pop_finished_protocol_result(&self) -> Option<Vec<DoubleShamirShare<F>>> {
        let mut finished_sid = None;
        let mut output = Vec::new();
        for entry in self.store.iter() {
            let storage_bind = entry.value().lock().await;
            if storage_bind.state == RanDouShaState::Finished {
                finished_sid = Some(*entry.key());
                output = storage_bind.protocol_output.clone();
                break;
            }
        }
        match finished_sid {
            Some(sid) => {
                self.store.remove(&sid);
                Some(output)
            }
            None => None,
        }
    }

    /// Initialize batched random double share generation.
    ///
    /// Each party generates K random secrets, creates degree-t and degree-2t shares
    /// for each, and sends K double share pairs to each other party.
    ///
    /// # Arguments
    /// * `session_id` - Unique session identifier
    /// * `batch_size` - K, the number of secrets to generate
    /// * `rng` - Random number generator
    /// * `network` - Network for sending messages
    pub async fn init<N, G>(
        &self,
        session_id: SessionId,
        batch_size: usize,
        rng: &mut G,
        network: Arc<N>,
    ) -> Result<(), RanDouShaError>
    where
        N: Network,
        G: Rng,
    {
        info!(
            "Batched RanDouSha init: party {} generating {} secrets",
            self.id, batch_size
        );

        // Generate K secrets, each with degree-t and degree-2t shares
        // For each secret, we get n pairs of shares (one pair for each party)
        // We need to reorganize: for each recipient, collect their K share pairs
        let mut shares_t_per_recipient: Vec<Vec<NonRobustShare<F>>> =
            vec![Vec::with_capacity(batch_size); self.n_parties];
        let mut shares_2t_per_recipient: Vec<Vec<NonRobustShare<F>>> =
            vec![Vec::with_capacity(batch_size); self.n_parties];

        for _ in 0..batch_size {
            let secret = F::rand(rng);

            // Generate degree-t shares
            let shares_t =
                NonRobustShare::compute_shares(secret, self.n_parties, self.threshold, None, rng)?;
            // Generate degree-2t shares (same secret!)
            let shares_2t = NonRobustShare::compute_shares(
                secret,
                self.n_parties,
                2 * self.threshold,
                None,
                rng,
            )?;

            for (recipient_id, (share_t, share_2t)) in
                shares_t.into_iter().zip(shares_2t).enumerate()
            {
                shares_t_per_recipient[recipient_id].push(share_t);
                shares_2t_per_recipient[recipient_id].push(share_2t);
            }
        }

        // Send K double share pairs to each recipient concurrently
        let send_futures: Vec<_> = shares_t_per_recipient
            .into_iter()
            .zip(shares_2t_per_recipient)
            .enumerate()
            .map(|(recipient_id, (shares_t, shares_2t))| {
                let network = network.clone();
                let sender_id = self.id;

                async move {
                    // Serialize all K shares of degree t, then all K shares of degree 2t
                    let mut payload = Vec::new();
                    for share in &shares_t {
                        share
                            .serialize_compressed(&mut payload)
                            .map_err(RanDouShaError::ArkSerialization)?;
                    }
                    for share in &shares_2t {
                        share
                            .serialize_compressed(&mut payload)
                            .map_err(RanDouShaError::ArkSerialization)?;
                    }

                    let message = WrappedMessage::RanDouSha(RanDouShaMessage::new(
                        sender_id,
                        RanDouShaMessageType::BatchedShareMessage,
                        session_id,
                        RanDouShaPayload::BatchedShare(payload),
                    ));
                    let bytes = bincode::serialize(&message)?;

                    network
                        .send(recipient_id, &bytes)
                        .await
                        .map_err(RanDouShaError::NetworkError)?;
                    Ok::<(), RanDouShaError>(())
                }
            })
            .collect();

        try_join_all(send_futures).await?;

        // Update state
        let storage_access = self.get_or_create_store(session_id, batch_size).await;
        let mut storage = storage_access.lock().await;
        storage.state = RanDouShaState::Initialized;

        info!(
            "Batched RanDouSha: party {} sent {} double shares to each of {} parties",
            self.id, batch_size, self.n_parties
        );

        Ok(())
    }

    /// Handle received batched shares from another party.
    pub async fn receive_shares_handler<N>(
        &self,
        msg: RanDouShaMessage,
        network: Arc<N>,
    ) -> Result<(), RanDouShaError>
    where
        N: Network,
    {
        let payload = match &msg.payload {
            RanDouShaPayload::BatchedShare(s) => s,
            _ => return Err(RanDouShaError::Abort),
        };

        // Deserialize K shares of degree t, then K shares of degree 2t
        let mut cursor = payload.as_slice();
        let mut shares_t: Vec<NonRobustShare<F>> = Vec::new();
        let mut shares_2t: Vec<NonRobustShare<F>> = Vec::new();

        // First half: degree t shares
        while !cursor.is_empty() {
            let share: NonRobustShare<F> =
                CanonicalDeserialize::deserialize_compressed(&mut cursor)?;
            if share.degree == self.threshold {
                shares_t.push(share);
            } else if share.degree == 2 * self.threshold {
                shares_2t.push(share);
            } else {
                return Err(RanDouShaError::ShareError(ShareError::DegreeMismatch));
            }
        }

        if shares_t.len() != shares_2t.len() {
            return Err(RanDouShaError::ShareError(ShareError::InvalidInput));
        }

        let batch_size = shares_t.len();
        let binding = self.get_or_create_store(msg.session_id, batch_size).await;
        let mut store = binding.lock().await;

        store.initial_shares_t.insert(msg.sender_id, shares_t);
        store.initial_shares_2t.insert(msg.sender_id, shares_2t);
        store.reception_tracker[msg.sender_id] = true;

        info!(
            session_id = msg.session_id.as_u64(),
            "Batched RanDouSha: party {} received {} double shares from party {}",
            self.id,
            batch_size,
            msg.sender_id
        );

        // Check if we've received from all parties
        if store.reception_tracker.iter().all(|&received| received) {
            store.state = RanDouShaState::Reconstruction;

            // Collect and sort shares by sender_id
            let mut all_shares_t: Vec<(PartyId, Vec<NonRobustShare<F>>)> = store
                .initial_shares_t
                .iter()
                .map(|(sid, s)| (*sid, s.clone()))
                .collect();
            all_shares_t.sort_by_key(|(sid, _)| *sid);

            let mut all_shares_2t: Vec<(PartyId, Vec<NonRobustShare<F>>)> = store
                .initial_shares_2t
                .iter()
                .map(|(sid, s)| (*sid, s.clone()))
                .collect();
            all_shares_2t.sort_by_key(|(sid, _)| *sid);

            let batch_size = store.batch_size;
            drop(store);

            // Apply Vandermonde transformation
            self.apply_vandermonde_and_send_reconstruction(
                all_shares_t,
                all_shares_2t,
                batch_size,
                msg.session_id,
                network,
            )
            .await?;
        }

        Ok(())
    }

    /// Apply Vandermonde transformation to batched shares and send for reconstruction.
    ///
    /// For each secret index k (0..batch_size), we have n shares of degree t and n shares of degree 2t.
    /// We apply Vandermonde to each column independently.
    async fn apply_vandermonde_and_send_reconstruction<N>(
        &self,
        all_shares_t: Vec<(PartyId, Vec<NonRobustShare<F>>)>,
        all_shares_2t: Vec<(PartyId, Vec<NonRobustShare<F>>)>,
        batch_size: usize,
        session_id: SessionId,
        network: Arc<N>,
    ) -> Result<(), RanDouShaError>
    where
        N: Network,
    {
        info!(
            "Batched RanDouSha: party {} applying Vandermonde to {} batches",
            self.id, batch_size
        );

        let vandermonde_matrix = make_vandermonde(self.n_parties, self.n_parties - 1)?;

        // For each secret index k, collect the k-th share from each party and apply Vandermonde
        let mut all_r_shares_t: Vec<NonRobustShare<F>> =
            Vec::with_capacity(batch_size * self.n_parties);
        let mut all_r_shares_2t: Vec<NonRobustShare<F>> =
            Vec::with_capacity(batch_size * self.n_parties);

        for k in 0..batch_size {
            // Collect share k from each party (sorted by party id) for degree t
            let column_t: Vec<NonRobustShare<F>> = all_shares_t
                .iter()
                .map(|(_, shares)| shares[k].clone())
                .collect();

            // Collect share k from each party (sorted by party id) for degree 2t
            let column_2t: Vec<NonRobustShare<F>> = all_shares_2t
                .iter()
                .map(|(_, shares)| shares[k].clone())
                .collect();

            // Apply Vandermonde to both columns
            let r_shares_t_k = apply_vandermonde(&vandermonde_matrix, &column_t)?;
            let r_shares_2t_k = apply_vandermonde(&vandermonde_matrix, &column_2t)?;

            all_r_shares_t.extend(r_shares_t_k);
            all_r_shares_2t.extend(r_shares_2t_k);

            // Yield periodically to allow other tasks (especially message receivers) to run.
            // This prevents CPU-bound computation from starving the async executor.
            if k % 32 == 31 {
                tokio::task::yield_now().await;
            }
        }

        let bind_store = self.get_or_create_store(session_id, batch_size).await;
        let mut store = bind_store.lock().await;
        store.computed_r_shares_degree_t = all_r_shares_t.clone();
        store.computed_r_shares_degree_2t = all_r_shares_2t.clone();

        // Check if we can complete the output phase now
        // Output messages may have arrived before computed shares were ready
        let can_complete = store.received_ok_msg.len() >= self.n_parties - (self.threshold + 1)
            && !store.computed_r_shares_degree_t.is_empty()
            && !store.computed_r_shares_degree_2t.is_empty()
            && store.state != RanDouShaState::Finished;

        if can_complete {
            // Output: for each batch k, take the first (t+1) double shares
            let output_per_batch = self.threshold + 1;
            let mut output: Vec<DoubleShamirShare<F>> =
                Vec::with_capacity(batch_size * output_per_batch);

            for k in 0..batch_size {
                let batch_start = k * self.n_parties;
                for i in 0..output_per_batch {
                    let share_t = store.computed_r_shares_degree_t[batch_start + i].clone();
                    let share_2t = store.computed_r_shares_degree_2t[batch_start + i].clone();
                    output.push(DoubleShamirShare::new(share_t, share_2t));
                }
            }

            store.state = RanDouShaState::Finished;
            store.protocol_output = output;
            drop(store);
            self.output_sender.send(session_id).await?;
        } else {
            drop(store);
        }

        // For reconstruction verification, send to parties t+1..n
        // Each party i receives shares at position i from each batch
        let send_futures: Vec<_> = (self.threshold + 1..self.n_parties)
            .map(|target_party| {
                let network = network.clone();
                let sender_id = self.id;

                // Collect the target_party-th share from each batch
                let shares_t_for_party: Vec<NonRobustShare<F>> = (0..batch_size)
                    .map(|k| all_r_shares_t[k * self.n_parties + target_party].clone())
                    .collect();
                let shares_2t_for_party: Vec<NonRobustShare<F>> = (0..batch_size)
                    .map(|k| all_r_shares_2t[k * self.n_parties + target_party].clone())
                    .collect();

                async move {
                    let mut payload = Vec::new();
                    // Serialize degree t shares first
                    for share in &shares_t_for_party {
                        share
                            .serialize_compressed(&mut payload)
                            .map_err(RanDouShaError::ArkSerialization)?;
                    }
                    // Then degree 2t shares
                    for share in &shares_2t_for_party {
                        share
                            .serialize_compressed(&mut payload)
                            .map_err(RanDouShaError::ArkSerialization)?;
                    }

                    let message = WrappedMessage::RanDouSha(RanDouShaMessage::new(
                        sender_id,
                        RanDouShaMessageType::BatchedReconstructMessage,
                        session_id,
                        RanDouShaPayload::BatchedReconstruct(payload),
                    ));
                    let bytes = bincode::serialize(&message)?;
                    network
                        .send(target_party, &bytes)
                        .await
                        .map_err(RanDouShaError::NetworkError)?;
                    Ok::<(), RanDouShaError>(())
                }
            })
            .collect();

        try_join_all(send_futures).await?;

        info!(
            "Batched RanDouSha: party {} sent reconstruction data for {} batches",
            self.id, batch_size
        );

        Ok(())
    }

    /// Handle batched reconstruction messages.
    pub async fn reconstruction_handler<N>(
        &self,
        msg: RanDouShaMessage,
        network: Arc<N>,
    ) -> Result<(), RanDouShaError>
    where
        N: Network + Send + Sync,
    {
        let payload = match &msg.payload {
            RanDouShaPayload::BatchedReconstruct(s) => s,
            _ => return Err(RanDouShaError::Abort),
        };

        // Deserialize K shares of degree t, then K shares of degree 2t
        let mut cursor = payload.as_slice();
        let mut shares_t: Vec<NonRobustShare<F>> = Vec::new();
        let mut shares_2t: Vec<NonRobustShare<F>> = Vec::new();

        while !cursor.is_empty() {
            let share: NonRobustShare<F> =
                CanonicalDeserialize::deserialize_compressed(&mut cursor)?;
            if share.degree == self.threshold {
                shares_t.push(share);
            } else if share.degree == 2 * self.threshold {
                shares_2t.push(share);
            } else {
                return Err(RanDouShaError::ShareError(ShareError::DegreeMismatch));
            }
        }

        if shares_t.len() != shares_2t.len() {
            return Err(RanDouShaError::ShareError(ShareError::InvalidInput));
        }

        let batch_size = shares_t.len();
        let binding = self.get_or_create_store(msg.session_id, batch_size).await;
        let mut store = binding.lock().await;
        store.state = RanDouShaState::Reconstruction;
        store.received_r_shares_t.insert(msg.sender_id, shares_t);
        store.received_r_shares_2t.insert(msg.sender_id, shares_2t);

        // If we're one of the checking parties (t+1 <= id < n) and have enough shares, verify
        if self.id >= self.threshold + 1
            && self.id < self.n_parties
            && store.received_r_shares_t.len() >= 2 * self.threshold + 1
        {
            // Verify each batch's reconstruction
            let mut all_ok = true;

            for k in 0..batch_size {
                // Collect the k-th share from each party for verification
                let shares_t_for_batch: Vec<NonRobustShare<F>> = store
                    .received_r_shares_t
                    .values()
                    .map(|party_shares| party_shares[k].clone())
                    .collect();

                let shares_2t_for_batch: Vec<NonRobustShare<F>> = store
                    .received_r_shares_2t
                    .values()
                    .map(|party_shares| party_shares[k].clone())
                    .collect();

                // Reconstruct and verify degree t polynomial
                let reconstructed_t = match NonRobustShare::recover_secret(
                    &shares_t_for_batch,
                    self.n_parties,
                ) {
                    Ok(r) => r,
                    Err(_) => {
                        all_ok = false;
                        break;
                    }
                };

                // Reconstruct and verify degree 2t polynomial
                let reconstructed_2t = match NonRobustShare::recover_secret(
                    &shares_2t_for_batch,
                    self.n_parties,
                ) {
                    Ok(r) => r,
                    Err(_) => {
                        all_ok = false;
                        break;
                    }
                };

                let poly_t = DensePolynomial::from_coefficients_slice(&reconstructed_t.0);
                let poly_2t = DensePolynomial::from_coefficients_slice(&reconstructed_2t.0);

                // Verify:
                // 1. Degree t polynomial has degree exactly t
                // 2. Degree 2t polynomial has degree exactly 2t
                // 3. Both polynomials evaluate to the same value at 0 (same secret)
                let ok = (self.threshold == poly_t.degree())
                    && (2 * self.threshold == poly_2t.degree())
                    && (reconstructed_t.1 == reconstructed_2t.1);

                if !ok {
                    all_ok = false;
                    break;
                }
            }

            drop(store);

            // Broadcast verification result via RBC
            let result = WrappedMessage::RanDouSha(RanDouShaMessage::new(
                self.id,
                RanDouShaMessageType::OutputMessage,
                msg.session_id,
                RanDouShaPayload::Output(all_ok),
            ));
            let bytes = bincode::serialize(&result)?;
            let rbc_session_id = SessionId::new(
                ProtocolType::BatchedRandousha,
                msg.session_id.exec_id(),
                self.id as u8,
                msg.session_id.round_id(),
                msg.session_id.instance_id(),
            );
            self.rbc
                .init(bytes, rbc_session_id, Arc::clone(&network))
                .await?;
        }

        Ok(())
    }

    /// Handle output confirmation messages.
    pub async fn output_handler(&self, msg: RanDouShaMessage) -> Result<(), RanDouShaError> {
        let ok = match msg.payload {
            RanDouShaPayload::Output(o) => o,
            _ => return Err(RanDouShaError::Abort),
        };

        if !ok {
            return Err(RanDouShaError::Abort);
        }

        // Get store - it should already exist from earlier phases
        let store_arc = match self.store.get(&msg.session_id) {
            Some(s) => s.clone(),
            None => return Err(RanDouShaError::Abort),
        };

        let mut store = store_arc.lock().await;

        // If already finished (e.g., completed early in apply_vandermonde), just return Ok
        if store.state == RanDouShaState::Finished {
            return Ok(());
        }

        store.state = RanDouShaState::Output;

        if !store.received_ok_msg.contains(&msg.sender_id) {
            store.received_ok_msg.push(msg.sender_id);
        }

        // Wait for (n - (t+1)) OK messages
        if store.received_ok_msg.len() < self.n_parties - (self.threshold + 1) {
            return Err(RanDouShaError::WaitForOk);
        }

        if store.computed_r_shares_degree_t.is_empty()
            || store.computed_r_shares_degree_2t.is_empty()
        {
            return Err(RanDouShaError::WaitForOk);
        }

        // Output: for each batch k, take the first (t+1) double shares
        // Total output: K * (t+1) double shares
        let batch_size = store.batch_size;
        let output_per_batch = self.threshold + 1;
        let mut output: Vec<DoubleShamirShare<F>> =
            Vec::with_capacity(batch_size * output_per_batch);

        for k in 0..batch_size {
            let batch_start = k * self.n_parties;
            for i in 0..output_per_batch {
                let share_t = store.computed_r_shares_degree_t[batch_start + i].clone();
                let share_2t = store.computed_r_shares_degree_2t[batch_start + i].clone();
                output.push(DoubleShamirShare::new(share_t, share_2t));
            }
        }

        store.state = RanDouShaState::Finished;
        store.protocol_output = output;

        info!(
            "Batched RanDouSha: party {} finished with {} output double shares (batch_size={}, per_batch={})",
            self.id,
            store.protocol_output.len(),
            batch_size,
            output_per_batch
        );

        drop(store);
        self.output_sender.send(msg.session_id).await?;
        Ok(())
    }

    /// Process incoming messages.
    pub async fn process<N>(
        &self,
        msg: RanDouShaMessage,
        network: Arc<N>,
    ) -> Result<(), RanDouShaError>
    where
        N: Network + Send + Sync,
    {
        match (&msg.msg_type, &msg.payload) {
            (RanDouShaMessageType::BatchedShareMessage, RanDouShaPayload::BatchedShare(_)) => {
                self.receive_shares_handler(msg, network).await
            }
            (
                RanDouShaMessageType::BatchedReconstructMessage,
                RanDouShaPayload::BatchedReconstruct(_),
            ) => self.reconstruction_handler(msg, network).await,
            (RanDouShaMessageType::OutputMessage, RanDouShaPayload::Output(_)) => {
                self.output_handler(msg).await
            }
            _ => Err(RanDouShaError::Abort),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batched_store_creation() {
        use ark_bls12_381::Fr;
        let store = BatchedRanDouShaStore::<Fr>::new(5, 512);
        assert_eq!(store.batch_size, 512);
        assert_eq!(store.reception_tracker.len(), 5);
    }
}
