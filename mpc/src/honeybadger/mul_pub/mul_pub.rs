use crate::common::ProtocolSessionId;
use crate::{
    common::utils::deser_bounded_vec,
    honeybadger::{
        batch_recon::batch_recon::BatchReconNode,
        mul_pub::{MulPubError, MulPubState, MulPubStore},
        robust_interpolate::robust_interpolate::RobustShare,
        SessionId,
    },
};
use ark_ff::FftField;
use std::{collections::HashMap, sync::Arc};
use stoffelnet::network_utils::{Network, PartyId};
use tokio::sync::{mpsc::Receiver, Mutex};
use tokio::time::{timeout, Duration};
use tracing::warn;

pub static MAX_MUL_PUB_SESSIONS: usize = 256;

#[derive(Clone, Debug)]
pub struct MulPubNode<F: FftField> {
    pub id: usize,
    pub n_parties: usize,
    pub threshold: usize,
    pub store: Arc<Mutex<HashMap<SessionId, Arc<Mutex<MulPubStore<F>>>>>>,
    pub batch_recon: BatchReconNode<F>,
    pub batch_output: Arc<Mutex<Receiver<SessionId>>>,
}

impl<F: FftField> MulPubNode<F> {
    pub fn new(id: PartyId, n_parties: usize, threshold: usize) -> Result<Self, MulPubError> {
        let (batch_sender, batch_receiver) = tokio::sync::mpsc::channel(200);
        let batch_recon =
            BatchReconNode::new(id, n_parties, threshold, 2 * threshold, batch_sender)?;
        Ok(Self {
            id,
            n_parties,
            threshold,
            store: Arc::new(Mutex::new(HashMap::new())),
            batch_recon,
            batch_output: Arc::new(Mutex::new(batch_receiver)),
        })
    }

    async fn get_or_create_store(
        &self,
        session_id: SessionId,
        k: usize,
    ) -> Result<Arc<Mutex<MulPubStore<F>>>, MulPubError> {
        let mut storage = self.store.lock().await;
        if storage.len() >= MAX_MUL_PUB_SESSIONS && !storage.contains_key(&session_id) {
            return Err(MulPubError::LimitError);
        }
        Ok(storage
            .entry(session_id)
            .or_insert_with(|| Arc::new(Mutex::new(MulPubStore::new(k))))
            .clone())
    }

    pub async fn clear_store(&self, session_id: SessionId) -> bool {
        self.batch_recon.clear_entire_store().await;
        self.store.lock().await.remove(&session_id).is_some()
    }

    pub async fn init<N: Network + Send + Sync + 'static>(
        &mut self,
        session_id: SessionId,
        a: Vec<RobustShare<F>>,
        b: Vec<RobustShare<F>>,
        zero_shares: Vec<RobustShare<F>>,
        network: Arc<N>,
    ) -> Result<(), MulPubError> {
        if a.len() != b.len() {
            return Err(MulPubError::InvalidInput(
                "a and b must have equal length".into(),
            ));
        }
        let k = a.len();
        if k != zero_shares.len() {
            return Err(MulPubError::InvalidInput(format!(
                "{k} multiplications but {} zero shares provided",
                zero_shares.len()
            )));
        }
        if k == 0 {
            return Err(MulPubError::InvalidInput("empty input".into()));
        }
        if zero_shares.iter().any(|s| s.degree != 2 * self.threshold) {
            return Err(MulPubError::InvalidInput(
                "zero shares must have degree 2t".into(),
            ));
        }
        if session_id.calling_protocol().is_none() {
            return Err(MulPubError::InvalidInput(
                "session_id must have a calling protocol".into(),
            ));
        }
        if session_id.sub_id() != 0 {
            return Err(MulPubError::InvalidInput(
                "session_id sub_id must be 0".into(),
            ));
        }
        if session_id.round_id() != 0 {
            return Err(MulPubError::InvalidInput(
                "session_id round_id must be 0".into(),
            ));
        }

        self.get_or_create_store(session_id, k).await?;

        let batch_size = 2 * self.threshold + 1;
        let num_batches = (k + batch_size - 1) / batch_size;

        let mut all_shares: Vec<RobustShare<F>> = (0..k)
            .map(|j| {
                let product = a[j].share_mul(&b[j])?;
                product + zero_shares[j].clone()
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| MulPubError::InvalidInput(e.to_string()))?;

        // Pad the last batch with 1s to reach an exact multiple of batch_size = 2t+1
        while all_shares.len() < num_batches * batch_size {
            all_shares.push(RobustShare::new(F::one(), self.id, 2 * self.threshold));
        }

        // One combined batch-recon round for every chunk, instead of one round
        // per chunk — round count is now independent of k.
        self.batch_recon
            .init_batch_reconstruct_many(&all_shares, session_id, Arc::clone(&network))
            .await?;
        Ok(())
    }

    pub async fn drain_batch_recon_output(&mut self) -> Result<(), MulPubError> {
        loop {
            let sid = {
                let mut rx = self.batch_output.lock().await;
                match rx.try_recv() {
                    Ok(id) => id,
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        return Err(MulPubError::Abort);
                    }
                }
            };

            let storage = self
                .store
                .lock()
                .await
                .get(&sid)
                .cloned()
                .ok_or(MulPubError::NoSuchSession(sid));
            let bind = match storage {
                Ok(b) => b,
                Err(_) => {
                    warn!("MulPub: no session for {sid:?}; init not yet called");
                    continue;
                }
            };
            let mut store = bind.lock().await;
            if store.state == MulPubState::Finished {
                continue;
            }

            let batch_size = 2 * self.threshold + 1;
            let num_batches = (store.k + batch_size - 1) / batch_size;
            let poly_bytes = self.batch_recon.get_store(sid).await?;
            let coeffs: Vec<F> =
                deser_bounded_vec(&mut poly_bytes.as_slice(), num_batches * batch_size)
                    .map_err(MulPubError::ArkSerialization)?;

            if coeffs.len() < store.k {
                warn!("MulPub: short coefficient vector for session {sid:?}");
                continue;
            }

            // Only the first store.k values are real; the rest is padding from
            // completing the last chunk.
            let output: Vec<F> = coeffs.into_iter().take(store.k).collect();
            store.state = MulPubState::Finished;
            if let Some(tx) = store.output_sender.take() {
                tx.send(output).map_err(|_| MulPubError::SendError)?;
            }
        }
        Ok(())
    }

    pub async fn wait_for_result(
        &self,
        session_id: SessionId,
        duration: Duration,
    ) -> Result<Vec<F>, MulPubError> {
        let rx = {
            let storage = self.store.lock().await;
            let bind = storage
                .get(&session_id)
                .ok_or(MulPubError::NoSuchSession(session_id))?;
            let mut store = bind.lock().await;
            store
                .output_receiver
                .take()
                .ok_or(MulPubError::ResultAlreadyReceived(session_id))?
        };
        match timeout(duration, rx).await {
            Err(_) => Err(MulPubError::Timeout(session_id)),
            Ok(Err(_)) => Err(MulPubError::ReceiveError(session_id)),
            Ok(Ok(result)) => Ok(result),
        }
    }
}