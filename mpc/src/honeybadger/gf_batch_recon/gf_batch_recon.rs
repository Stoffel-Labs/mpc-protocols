//! GF(2^k) equivalent of `BatchReconNode` (`honeybadger::batch_recon`), a direct structural
//! port 

use bincode::Options;
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use stoffelnet::network_utils::Network;
use tokio::sync::{mpsc::Sender, Mutex};
use tracing::{debug, error, info, warn};

use crate::common::session_store::{Admission, SessionStore};
use crate::{
    common::gf2k::{
        field::BinaryField,
        robust_interpolate::batch_recover_secret,
        share::GfShare,
        vandermonde::{apply_vandermonde, make_vandermonde},
    },
    honeybadger::{
        gf_batch_recon::{GfBatchReconError, GfBatchReconMsg, GfBatchReconMsgType, GfBatchReconStore},
        SessionId, WrappedMessage,
    },
};

fn ser<T: Serialize>(value: &T) -> Result<Vec<u8>, GfBatchReconError> {
    Ok(bincode::serialize(value)?)
}

/// Bounded by the payload's own byte length, matching `bincode::serialize`'s fixint encoding
/// (see `gf_share_gen::gf_share_gen::deser_bounded` for why `with_fixint_encoding` is required,
/// not optional, here).
fn deser_bounded<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, GfBatchReconError> {
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(bytes.len() as u64)
        .deserialize(bytes)?)
}

/// Returns the payload width shared by at least `threshold` distinct senders, if any. See the
/// module docs and `honeybadger::batch_recon::batch_recon::agreeing_width` for the rationale —
/// identical logic, ported unchanged (it's field-agnostic, generic over the value type already).
fn agreeing_width<K>(entries: &[(usize, Vec<K>)], threshold: usize) -> Option<usize> {
    let mut counts: HashMap<usize, usize> = HashMap::new();
    for (_, values) in entries {
        let count = counts.entry(values.len()).or_insert(0);
        *count += 1;
        if *count >= threshold {
            return Some(values.len());
        }
    }
    None
}

const MAX_GF_BATCH_RECON_SESSIONS: usize = 256;

#[derive(Clone, Debug)]
pub struct GfBatchReconNode<K: BinaryField> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    pub degree: usize,
    pub store: Arc<
        Mutex<SessionStore<SessionId, (usize, Instant, Arc<Mutex<GfBatchReconStore<K>>>)>>,
    >,
    pub output_sender: Sender<SessionId>,
}

impl<K: BinaryField> GfBatchReconNode<K> {
    pub fn new(
        id: usize,
        n: usize,
        t: usize,
        degree: usize,
        output_sender: Sender<SessionId>,
    ) -> Result<Self, GfBatchReconError> {
        let store = Arc::new(Mutex::new(SessionStore::with_default_cap()));
        Ok(Self {
            id,
            n,
            t,
            degree,
            store,
            output_sender,
        })
    }

    pub async fn clear_entire_store(&self) {
        let mut store = self.store.lock().await;
        store.clear_all();
    }

    pub async fn clear_store(&self, session_id: SessionId) -> bool {
        let mut store = self.store.lock().await;
        store.retire(session_id)
    }

    pub async fn store_len(&self) -> usize {
        self.store.lock().await.len()
    }

    pub async fn get_store(&self, session_id: SessionId) -> Result<Vec<u8>, GfBatchReconError> {
        let store = self.store.lock().await;

        let (_, _, output_arc) = store.get(&session_id).ok_or_else(|| {
            GfBatchReconError::InvalidInput("Session ID does not exist".to_string())
        })?;

        let store_lock = output_arc.lock().await;

        if store_lock.secrets.is_none() {
            return Err(GfBatchReconError::InvalidInput(
                "Batch reconstruction has not terminated".to_string(),
            ));
        }

        Ok(store_lock.secrets.clone().unwrap())
    }

    /// Initiates the batch reconstruction protocol. Each party computes its `y_j_share` for all
    /// `j` and sends it to party `P_j`.
    pub async fn init_batch_reconstruct<N: Network>(
        &self,
        shares: &[GfShare<K>], // this party's shares of x_0 to x_degree
        session_id: SessionId,
        net: Arc<N>,
    ) -> Result<(), GfBatchReconError> {
        if shares.len() < self.degree + 1 {
            return Err(GfBatchReconError::InvalidInput(
                "too little shares to start batch reconstruct".to_string(),
            ));
        }
        let vandermonde = make_vandermonde::<K>(self.n, self.degree)?;
        let y_shares = apply_vandermonde(&vandermonde, &shares[..(self.degree + 1)])?;

        info!(
            id = self.id,
            "initialized gf batch reconstruction with Vandermonde transform"
        );

        for (j, y_j_share) in y_shares.into_iter().enumerate() {
            let payload = ser(&y_j_share.share)?;
            let msg = GfBatchReconMsg::new(self.id, session_id, GfBatchReconMsgType::Eval, payload);
            let wrapped = WrappedMessage::GfBatchRecon(msg);
            let encoded_msg = bincode::serialize(&wrapped)?;
            let _ = net.send(j, &encoded_msg).await?;
        }
        Ok(())
    }

    /// Initiates multiple independent batch reconstructions under one protocol session. `shares`
    /// is interpreted as consecutive chunks of `degree + 1` secrets.
    pub async fn init_batch_reconstruct_many<N: Network>(
        &self,
        shares: &[GfShare<K>],
        session_id: SessionId,
        net: Arc<N>,
    ) -> Result<(), GfBatchReconError> {
        let batch_width = self.degree + 1;
        if shares.is_empty() || shares.len() % batch_width != 0 {
            return Err(GfBatchReconError::InvalidInput(
                "batched shares must be a non-empty multiple of degree + 1".to_string(),
            ));
        }

        let vandermonde = make_vandermonde::<K>(self.n, self.degree)?;
        let mut y_shares_by_recipient = vec![Vec::new(); self.n];

        for chunk in shares.chunks_exact(batch_width) {
            let y_shares = apply_vandermonde(&vandermonde, chunk)?;
            for (recipient, y_j_share) in y_shares.into_iter().enumerate() {
                y_shares_by_recipient[recipient].push(y_j_share.share);
            }
        }

        info!(
            id = self.id,
            groups = shares.len() / batch_width,
            "initialized batched gf batch reconstruction with Vandermonde transform"
        );

        for (j, values) in y_shares_by_recipient.into_iter().enumerate() {
            let payload = ser(&values)?;
            let msg = GfBatchReconMsg::new(
                self.id,
                session_id,
                GfBatchReconMsgType::EvalBatch,
                payload,
            );
            let wrapped = WrappedMessage::GfBatchRecon(msg);
            let encoded_msg = bincode::serialize(&wrapped)?;
            let _ = net.send(j, &encoded_msg).await?;
        }
        Ok(())
    }

    pub async fn batch_recon_handler<N: Network>(
        &mut self,
        msg: GfBatchReconMsg,
        net: Arc<N>,
    ) -> Result<(), GfBatchReconError> {
        if msg.sender_id >= self.n {
            return Err(GfBatchReconError::InvalidInput(format!(
                "sender id {} is out of range: expected 0 <= id < n (n = {})",
                msg.sender_id, self.n
            )));
        }

        match msg.msg_type {
            GfBatchReconMsgType::Eval => {
                debug!(self_id = self.id, from = msg.sender_id, "Received Eval message");
                let sender_id = msg.sender_id;
                let val: K = deser_bounded(&msg.payload)?;

                let Some(session_store) = self.get_or_create_store(msg.session_id, sender_id).await
                else {
                    return Ok(()); // late message for an already-terminated session — dropped
                };
                let mut store = session_store.lock().await;

                if !store.evals_received.iter().any(|s| s.id == sender_id) {
                    store
                        .evals_received
                        .push(GfShare::new(val, sender_id, self.degree));
                }
                if store.evals_received.len() >= self.degree + self.t + 1 && store.y_j.is_none() {
                    info!(self_id = self.id, "Enough Evals collected, interpolating y_j");

                    match GfShare::recover_secret(&store.evals_received, self.n, self.t) {
                        Ok((_, value)) => {
                            store.y_j = Some(GfShare::new(value, self.id, self.degree));
                            drop(store);
                            info!(node = self.id, "Broadcasting y_j value");

                            let payload = ser(&value)?;
                            let new_msg = GfBatchReconMsg::new(
                                self.id,
                                msg.session_id,
                                GfBatchReconMsgType::Reveal,
                                payload,
                            );
                            let wrapped = WrappedMessage::GfBatchRecon(new_msg);
                            let encoded = bincode::serialize(&wrapped)?;
                            let _ = net.broadcast(&encoded).await?;
                        }
                        Err(e) => {
                            warn!(self_id = self.id, "Interpolation of y_j failed: {:?}", e);
                            return Err(GfBatchReconError::Gf2kError(e));
                        }
                    }
                }
                Ok(())
            }
            GfBatchReconMsgType::Reveal => {
                debug!(self_id = self.id, from = msg.sender_id, "Received Reveal message");
                let sender_id = msg.sender_id;
                let y_j: K = deser_bounded(&msg.payload)?;

                let Some(session_store) = self.get_or_create_store(msg.session_id, sender_id).await
                else {
                    return Ok(());
                };
                let mut store = session_store.lock().await;

                if !store.reveals_received.iter().any(|s| s.id == sender_id) {
                    store
                        .reveals_received
                        .push(GfShare::new(y_j, sender_id, self.degree));
                }
                if store.reveals_received.len() >= self.degree + self.t + 1 && store.secrets.is_none()
                {
                    info!(self_id = self.id, "Enough Reveals collected, interpolating secrets");
                    match GfShare::recover_secret(&store.reveals_received, self.n, self.t) {
                        Ok((mut result, _)) => {
                            result.resize(self.degree + 1, K::zero());
                            let bytes_message = ser(&result)?;

                            store.secrets = Some(bytes_message);
                            drop(store);
                            info!(self_id = self.id, "Secrets successfully reconstructed");

                            self.output_sender
                                .send(msg.session_id)
                                .await
                                .map_err(|_| GfBatchReconError::SendError)?;
                        }
                        Err(e) => {
                            error!(self_id = self.id, error = ?e, "Final secrets interpolation failed");
                            return Err(GfBatchReconError::Gf2kError(e));
                        }
                    }
                }
                Ok(())
            }
            GfBatchReconMsgType::EvalBatch => {
                debug!(self_id = self.id, from = msg.sender_id, "Received EvalBatch message");
                let sender_id = msg.sender_id;
                let values: Vec<K> = deser_bounded(&msg.payload)?;

                if values.is_empty() {
                    return Err(GfBatchReconError::InvalidInput(
                        "empty EvalBatch payload".to_string(),
                    ));
                }

                let Some(session_store) = self.get_or_create_store(msg.session_id, sender_id).await
                else {
                    return Ok(());
                };
                let mut store = session_store.lock().await;

                // See `agreeing_width`'s docs: never let a single (possibly Byzantine) sender's
                // claimed length define the session's width.
                if !store
                    .batch_evals_received
                    .iter()
                    .any(|(id, _)| *id == sender_id)
                {
                    store.batch_evals_received.push((sender_id, values));
                }

                if store.y_j_batch.is_none() {
                    let threshold = self.degree + self.t + 1;
                    if let Some(width) = agreeing_width(&store.batch_evals_received, threshold) {
                        let agreeing: Vec<(usize, Vec<K>)> = store
                            .batch_evals_received
                            .iter()
                            .filter(|(_, v)| v.len() == width)
                            .cloned()
                            .collect();
                        let decoded = batch_recover_secret(&agreeing, self.n, self.degree, self.t)?;
                        let y_j_values: Vec<K> =
                            decoded.into_iter().map(|coeffs| coeffs[0]).collect();

                        store.y_j_batch = Some(y_j_values.clone());
                        drop(store);

                        let payload = ser(&y_j_values)?;
                        let new_msg = GfBatchReconMsg::new(
                            self.id,
                            msg.session_id,
                            GfBatchReconMsgType::RevealBatch,
                            payload,
                        );
                        let wrapped = WrappedMessage::GfBatchRecon(new_msg);
                        let encoded = bincode::serialize(&wrapped)?;
                        let _ = net.broadcast(&encoded).await?;
                    }
                }
                Ok(())
            }
            GfBatchReconMsgType::RevealBatch => {
                debug!(self_id = self.id, from = msg.sender_id, "Received RevealBatch message");
                let sender_id = msg.sender_id;
                let values: Vec<K> = deser_bounded(&msg.payload)?;

                if values.is_empty() {
                    return Err(GfBatchReconError::InvalidInput(
                        "empty RevealBatch payload".to_string(),
                    ));
                }

                let Some(session_store) = self.get_or_create_store(msg.session_id, sender_id).await
                else {
                    return Ok(());
                };
                let mut store = session_store.lock().await;

                if !store
                    .batch_reveals_received
                    .iter()
                    .any(|(id, _)| *id == sender_id)
                {
                    store.batch_reveals_received.push((sender_id, values));
                }

                if store.secrets.is_none() {
                    let threshold = self.degree + self.t + 1;
                    if let Some(width) = agreeing_width(&store.batch_reveals_received, threshold) {
                        let agreeing: Vec<(usize, Vec<K>)> = store
                            .batch_reveals_received
                            .iter()
                            .filter(|(_, v)| v.len() == width)
                            .cloned()
                            .collect();
                        let decoded = batch_recover_secret(&agreeing, self.n, self.degree, self.t)?;
                        let mut result = Vec::with_capacity(decoded.len() * (self.degree + 1));
                        for coeffs in decoded {
                            result.extend(coeffs);
                        }

                        let bytes_message = ser(&result)?;
                        store.secrets = Some(bytes_message);
                        drop(store);

                        self.output_sender
                            .send(msg.session_id)
                            .await
                            .map_err(|_| GfBatchReconError::SendError)?;
                    }
                }
                Ok(())
            }
        }
    }

    pub async fn process<N: Network>(
        &mut self,
        msg: GfBatchReconMsg,
        net: Arc<N>,
    ) -> Result<(), GfBatchReconError> {
        self.batch_recon_handler(msg, net).await
    }

    pub async fn get_or_create_store(
        &self,
        session_id: SessionId,
        sender_id: usize,
    ) -> Option<Arc<Mutex<GfBatchReconStore<K>>>> {
        let store_lock = {
            let mut storage = self.store.lock().await;
            let admitted = storage.get_or_admit(
                session_id,
                sender_id,
                MAX_GF_BATCH_RECON_SESSIONS,
                MAX_GF_BATCH_RECON_SESSIONS / self.n,
                || Arc::new(Mutex::new(GfBatchReconStore::empty())),
            );
            match admitted {
                Admission::Got(arc) => arc,
                Admission::Retired => return None,
                Admission::Rejected => {
                    warn!(
                        self_id = self.id,
                        ?session_id,
                        "gf batch-recon session limit reached, dropping message"
                    );
                    return None;
                }
            }
        };

        {
            let store_guard = store_lock.lock().await;
            if store_guard.secrets.is_some() {
                debug!(
                    self_id = self.id,
                    ?session_id,
                    "dropping late message for already-terminated gf batch-recon session"
                );
                return None;
            }
        }

        Some(store_lock)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignores_a_minority_bogus_width_arriving_first() {
        let entries: Vec<(usize, Vec<u32>)> = vec![
            (3, vec![999]),
            (0, vec![1, 2]),
            (1, vec![3, 4]),
            (2, vec![5, 6]),
        ];
        assert_eq!(agreeing_width(&entries, 3), Some(2));
    }

    #[test]
    fn returns_none_below_threshold() {
        let entries: Vec<(usize, Vec<u32>)> = vec![(0, vec![1, 2]), (1, vec![3, 4])];
        assert_eq!(agreeing_width(&entries, 3), None);
    }

    #[test]
    fn a_lone_byzantine_width_can_never_reach_threshold_on_its_own() {
        let entries: Vec<(usize, Vec<u32>)> = vec![(0, vec![999])];
        assert_eq!(agreeing_width(&entries, 3), None);
    }
}
