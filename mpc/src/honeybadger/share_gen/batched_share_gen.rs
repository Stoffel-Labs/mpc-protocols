//! Batched Random Share Generation Protocol
//!
//! This module implements a batched version of the RanSha protocol where each party
//! contributes K secrets instead of 1, producing K*(n-2t) random shares per protocol run.
//!
//! For n=5, t=1, K=512:
//! - Original protocol: 1 secret per party → 3 output shares per run
//! - Batched protocol: 512 secrets per party → 1536 output shares per run
//!
//! This reduces the number of protocol runs by ~500x for large preprocessing needs.

use ark_ff::FftField;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use futures::future::try_join_all;
use std::{collections::HashMap, sync::Arc};
use stoffelnet::network_utils::{Network, PartyId};
use tokio::sync::{mpsc::Sender, Mutex};
use tracing::info;

use crate::{
    common::{
        share::{apply_vandermonde, make_vandermonde, ShareError},
        SecretSharingScheme, ShamirShare, RBC,
    },
    honeybadger::{
        robust_interpolate::robust_interpolate::{Robust, RobustShare},
        share_gen::{
            BatchedRanShaStore, RanShaError, RanShaMessage, RanShaMessageType, RanShaPayload,
            RanShaState,
        },
        ProtocolType, SessionId, WrappedMessage,
    },
};

/// Batched Random Share Generation Node.
///
/// Each protocol run generates K*(n-2t) random shares instead of just (n-2t).
/// This dramatically reduces the number of protocol invocations needed for
/// large-scale preprocessing.
#[derive(Clone, Debug)]
pub struct BatchedRanShaNode<F: FftField, R: RBC> {
    pub id: usize,
    pub n_parties: usize,
    pub threshold: usize,
    pub store: Arc<Mutex<HashMap<SessionId, Arc<Mutex<BatchedRanShaStore<F>>>>>>,
    pub rbc: R,
    pub output_sender: Sender<SessionId>,
}

impl<F, R> BatchedRanShaNode<F, R>
where
    F: FftField,
    R: RBC,
{
    pub fn new(
        id: PartyId,
        n_parties: usize,
        threshold: usize,
        k: usize,
        output_sender: Sender<SessionId>,
    ) -> Result<Self, RanShaError> {
        let rbc = R::new(id, n_parties, threshold, k)?;
        Ok(Self {
            id,
            n_parties,
            threshold,
            store: Arc::new(Mutex::new(HashMap::new())),
            rbc,
            output_sender,
        })
    }

    pub async fn get_or_create_store(
        &self,
        session_id: SessionId,
        batch_size: usize,
    ) -> Arc<Mutex<BatchedRanShaStore<F>>> {
        let mut storage = self.store.lock().await;
        storage
            .entry(session_id)
            .or_insert(Arc::new(Mutex::new(BatchedRanShaStore::new(
                self.n_parties,
                batch_size,
            ))))
            .clone()
    }

    /// Initialize batched random share generation.
    ///
    /// Each party generates K random secrets, creates shares for each,
    /// and sends K shares to each other party.
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
    ) -> Result<(), RanShaError>
    where
        N: Network,
        G: Rng,
    {
        info!(
            "Batched ShareGen init: party {} generating {} secrets",
            self.id, batch_size
        );

        // Generate K secrets and their shares
        // For each secret, we get n shares (one for each party)
        // We need to reorganize: for each recipient, collect their K shares
        let mut shares_per_recipient: Vec<Vec<RobustShare<F>>> =
            vec![Vec::with_capacity(batch_size); self.n_parties];

        for _ in 0..batch_size {
            let secret = F::rand(rng);
            let shares =
                RobustShare::compute_shares(secret, self.n_parties, self.threshold, None, rng)?;

            for (recipient_id, share) in shares.into_iter().enumerate() {
                shares_per_recipient[recipient_id].push(share);
            }
        }

        // Send K shares to each recipient concurrently
        let send_futures: Vec<_> = shares_per_recipient
            .into_iter()
            .enumerate()
            .map(|(recipient_id, shares)| {
                let network = network.clone();
                let sender_id = self.id;

                async move {
                    // Serialize all K shares together
                    let mut payload = Vec::new();
                    for share in &shares {
                        share
                            .serialize_compressed(&mut payload)
                            .map_err(RanShaError::ArkSerialization)?;
                    }

                    let generic_message = WrappedMessage::RanSha(RanShaMessage::new(
                        sender_id,
                        RanShaMessageType::ShareMessage,
                        session_id,
                        RanShaPayload::BatchedShare(payload),
                    ));
                    let bytes_generic_msg = bincode::serialize(&generic_message)?;

                    network
                        .send(recipient_id, &bytes_generic_msg)
                        .await
                        .map_err(RanShaError::NetworkError)?;
                    Ok::<(), RanShaError>(())
                }
            })
            .collect();

        try_join_all(send_futures).await?;

        // Update state
        let storage_access = self.get_or_create_store(session_id, batch_size).await;
        let mut storage = storage_access.lock().await;
        storage.state = RanShaState::Initialized;

        info!(
            "Batched ShareGen: party {} sent {} shares to each of {} parties",
            self.id, batch_size, self.n_parties
        );

        Ok(())
    }

    /// Handle received batched shares from another party.
    pub async fn receive_shares_handler<N>(
        &self,
        msg: RanShaMessage,
        network: Arc<N>,
    ) -> Result<(), RanShaError>
    where
        N: Network,
    {
        let payload = match &msg.payload {
            RanShaPayload::BatchedShare(s) => s,
            _ => return Err(RanShaError::Abort),
        };

        // Deserialize K shares from the payload
        let mut cursor = payload.as_slice();
        let mut shares: Vec<RobustShare<F>> = Vec::new();

        while !cursor.is_empty() {
            let share: ShamirShare<F, 1, Robust> =
                CanonicalDeserialize::deserialize_compressed(&mut cursor)?;
            shares.push(share);
        }

        let batch_size = shares.len();
        let binding = self.get_or_create_store(msg.session_id, batch_size).await;
        let mut store = binding.lock().await;

        store.initial_shares.insert(msg.sender_id, shares);
        store.reception_tracker[msg.sender_id] = true;

        info!(
            session_id = msg.session_id.as_u64(),
            "Batched ShareGen: party {} received {} shares from party {}",
            self.id,
            batch_size,
            msg.sender_id
        );

        // Check if we've received from all parties
        if store.reception_tracker.iter().all(|&received| received) {
            store.state = RanShaState::FinishedInitialSharing;

            // Collect and sort shares by sender_id
            let mut all_shares: Vec<(usize, Vec<RobustShare<F>>)> = store
                .initial_shares
                .iter()
                .map(|(sid, s)| (*sid, s.clone()))
                .collect();
            all_shares.sort_by_key(|(sid, _)| *sid);

            let batch_size = store.batch_size;
            drop(store);

            // Process each "column" - for secret index k, collect share k from each party
            self.init_ransha(all_shares, batch_size, msg.session_id, network)
                .await?;
        }

        Ok(())
    }

    /// Apply Vandermonde transformation to batched shares.
    ///
    /// For each secret index k (0..batch_size), we have n shares (one from each party).
    /// We apply Vandermonde to each column of n shares, producing n random shares.
    /// Total: K columns × n shares = K*n random shares.
    async fn init_ransha<N>(
        &self,
        all_shares: Vec<(usize, Vec<RobustShare<F>>)>,
        batch_size: usize,
        session_id: SessionId,
        network: Arc<N>,
    ) -> Result<(), RanShaError>
    where
        N: Network,
    {
        info!(
            "Batched ShareGen: party {} applying Vandermonde to {} batches",
            self.id, batch_size
        );

        let vandermonde_matrix = make_vandermonde(self.n_parties, self.n_parties - 1)?;

        // For each secret index k, collect the k-th share from each party and apply Vandermonde
        let mut all_r_shares: Vec<RobustShare<F>> = Vec::with_capacity(batch_size * self.n_parties);

        for k in 0..batch_size {
            // Collect share k from each party (sorted by party id)
            let column: Vec<RobustShare<F>> = all_shares
                .iter()
                .map(|(_, shares)| shares[k].clone())
                .collect();

            // Apply Vandermonde to this column
            let r_shares_k = apply_vandermonde(&vandermonde_matrix, &column)?;
            all_r_shares.extend(r_shares_k);
        }

        let bind_store = self.get_or_create_store(session_id, batch_size).await;
        let mut store = bind_store.lock().await;
        store.computed_r_shares = all_r_shares.clone();

        // Check if we can complete the output phase now
        // Output messages may have arrived before computed_r_shares was ready
        let can_complete = store.received_ok_msg.len() >= 2 * self.threshold
            && !store.computed_r_shares.is_empty()
            && store.state != RanShaState::Finished;

        if can_complete {
            // Output: for each batch k, take shares [2t..n], giving (n-2t) shares per batch
            let output_per_batch = self.n_parties - 2 * self.threshold;
            let mut output: Vec<RobustShare<F>> = Vec::with_capacity(batch_size * output_per_batch);

            for k in 0..batch_size {
                let batch_start = k * self.n_parties;
                let output_start = batch_start + 2 * self.threshold;
                let output_end = batch_start + self.n_parties;
                output.extend(store.computed_r_shares[output_start..output_end].iter().cloned());
            }

            store.state = RanShaState::Finished;
            store.protocol_output = output;
            drop(store);
            self.output_sender.send(session_id).await?;
        } else {
            drop(store);
        }

        // For reconstruction verification, we need to check the first 2t shares
        // from each batch. Send batched reconstruction messages to parties 0..2t.
        //
        // Each party i (for i < 2t) receives the i-th share from each of the K batches.
        let send_futures: Vec<_> = (0..2 * self.threshold)
            .map(|target_party| {
                let network = network.clone();
                let sender_id = self.id;

                // Collect the target_party-th share from each batch
                let shares_for_party: Vec<RobustShare<F>> = (0..batch_size)
                    .map(|k| all_r_shares[k * self.n_parties + target_party].clone())
                    .collect();

                async move {
                    let mut payload = Vec::new();
                    for share in &shares_for_party {
                        share
                            .serialize_compressed(&mut payload)
                            .map_err(RanShaError::ArkSerialization)?;
                    }

                    let message = WrappedMessage::RanSha(RanShaMessage::new(
                        sender_id,
                        RanShaMessageType::ReconstructMessage,
                        session_id,
                        RanShaPayload::BatchedReconstruct(payload),
                    ));
                    let bytes = bincode::serialize(&message)?;
                    network
                        .send(target_party, &bytes)
                        .await
                        .map_err(RanShaError::NetworkError)?;
                    Ok::<(), RanShaError>(())
                }
            })
            .collect();

        try_join_all(send_futures).await?;

        info!(
            "Batched ShareGen: party {} sent reconstruction data for {} batches",
            self.id, batch_size
        );

        Ok(())
    }

    /// Handle batched reconstruction messages.
    pub async fn reconstruction_handler<N>(
        &self,
        msg: RanShaMessage,
        network: Arc<N>,
    ) -> Result<(), RanShaError>
    where
        N: Network + Send + Sync,
    {
        let payload = match &msg.payload {
            RanShaPayload::BatchedReconstruct(s) => s,
            _ => return Err(RanShaError::Abort),
        };

        // Deserialize K shares
        let mut cursor = payload.as_slice();
        let mut shares: Vec<RobustShare<F>> = Vec::new();

        while !cursor.is_empty() {
            let share: ShamirShare<F, 1, Robust> =
                CanonicalDeserialize::deserialize_compressed(&mut cursor)?;
            if share.degree != self.threshold {
                return Err(RanShaError::ShareError(ShareError::DegreeMismatch));
            }
            shares.push(share);
        }

        let batch_size = shares.len();
        let binding = self.get_or_create_store(msg.session_id, batch_size).await;
        let mut store = binding.lock().await;
        store.state = RanShaState::Reconstruction;
        store.received_r_shares.insert(msg.sender_id, shares);

        // If we're one of the first 2t parties and have enough shares, verify
        if self.id < 2 * self.threshold
            && store.received_r_shares.len() >= 2 * self.threshold + 1
        {
            // Verify each batch's reconstruction
            let mut all_ok = true;

            for k in 0..batch_size {
                // Collect the k-th share from each party for this verification
                let shares_for_batch: Vec<RobustShare<F>> = store
                    .received_r_shares
                    .values()
                    .map(|party_shares| party_shares[k].clone())
                    .collect();

                match RobustShare::recover_secret(&shares_for_batch, self.n_parties) {
                    Ok(r) => {
                        let poly = DensePolynomial::from_coefficients_slice(&r.0);
                        if poly.degree() != self.threshold {
                            all_ok = false;
                            break;
                        }
                    }
                    Err(_) => {
                        all_ok = false;
                        break;
                    }
                }
            }

            drop(store);

            // Broadcast verification result via RBC
            let result = WrappedMessage::RanSha(RanShaMessage::new(
                self.id,
                RanShaMessageType::OutputMessage,
                msg.session_id,
                RanShaPayload::Output(all_ok),
            ));
            let bytes = bincode::serialize(&result)?;
            let rbc_session_id = SessionId::new(
                ProtocolType::BatchedRansha,
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
    pub async fn output_handler(&self, msg: RanShaMessage) -> Result<(), RanShaError> {
        let ok = match msg.payload {
            RanShaPayload::Output(o) => o,
            _ => return Err(RanShaError::Abort),
        };

        if !ok {
            return Err(RanShaError::Abort);
        }

        // We need to know the batch_size. Get it from store or use a default.
        // The store should already exist from earlier phases.
        let storage_guard = self.store.lock().await;
        let store_arc = match storage_guard.get(&msg.session_id) {
            Some(s) => s.clone(),
            None => return Err(RanShaError::Abort),
        };
        drop(storage_guard);

        let mut store = store_arc.lock().await;

        // If already finished (e.g., completed early in init_ransha), just return Ok
        if store.state == RanShaState::Finished {
            return Ok(());
        }

        store.state = RanShaState::Output;

        if !store.received_ok_msg.contains(&msg.sender_id) {
            store.received_ok_msg.push(msg.sender_id);
        }

        if store.received_ok_msg.len() < 2 * self.threshold {
            return Err(RanShaError::WaitForOk);
        }

        if store.computed_r_shares.is_empty() {
            return Err(RanShaError::WaitForOk);
        }

        // Output: for each batch k, take shares [2t..n], giving (n-2t) shares per batch
        // Total output: K * (n - 2t) random shares
        let batch_size = store.batch_size;
        let output_per_batch = self.n_parties - 2 * self.threshold;
        let mut output: Vec<RobustShare<F>> = Vec::with_capacity(batch_size * output_per_batch);

        for k in 0..batch_size {
            let batch_start = k * self.n_parties;
            let output_start = batch_start + 2 * self.threshold;
            let output_end = batch_start + self.n_parties;
            output.extend(store.computed_r_shares[output_start..output_end].iter().cloned());
        }

        store.state = RanShaState::Finished;
        store.protocol_output = output;

        info!(
            "Batched ShareGen: party {} finished with {} output shares (batch_size={}, per_batch={})",
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
        msg: RanShaMessage,
        network: Arc<N>,
    ) -> Result<(), RanShaError>
    where
        N: Network + Send + Sync,
    {
        match (&msg.msg_type, &msg.payload) {
            (RanShaMessageType::ShareMessage, RanShaPayload::BatchedShare(_)) => {
                self.receive_shares_handler(msg, network).await
            }
            (RanShaMessageType::ReconstructMessage, RanShaPayload::BatchedReconstruct(_)) => {
                self.reconstruction_handler(msg, network).await
            }
            (RanShaMessageType::OutputMessage, RanShaPayload::Output(_)) => {
                self.output_handler(msg).await
            }
            _ => Err(RanShaError::Abort),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Basic compile test - full tests would require network setup
    #[test]
    fn test_batched_store_creation() {
        use ark_bls12_381::Fr;
        let store = BatchedRanShaStore::<Fr>::new(5, 512);
        assert_eq!(store.batch_size, 512);
        assert_eq!(store.reception_tracker.len(), 5);
    }
}
