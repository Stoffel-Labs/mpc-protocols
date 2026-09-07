//! GF(2^k) equivalent of `TripleGenNode` (`honeybadger::triple_gen::triple_generation`), a
//! direct structural port. Like its `F`-domain counterpart, this protocol has no wire messages
//! of its own — it is driven entirely by its embedded [`GfBatchReconNode`]'s completions, which
//! open the masked degree-`2t` product `a*b - r_2t` so that adding back the matching degree-`t`
//! share `r_t` yields a degree-`t` share of `a*b`.

use std::sync::Arc;
use std::time::Instant;

use bincode::Options;
use itertools::izip;
use serde::de::DeserializeOwned;
use stoffelnet::network_utils::Network;
use tokio::sync::mpsc::Receiver;
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};
use tracing::info;

use crate::common::gf2k::field::BinaryField;
use crate::common::gf2k::share::GfShare;
use crate::common::session_store::SessionStore;
use crate::common::ProtocolSessionId;
use crate::honeybadger::gf_batch_recon::gf_batch_recon::GfBatchReconNode;
use crate::honeybadger::gf_double_share::GfDoubleShamirShare;
use crate::honeybadger::gf_triple_gen::{GfBeaverTriple, GfTripleGenError, GfTripleGenStorage};
use crate::honeybadger::triple_gen::triple_generation::ProtocolState;
use crate::honeybadger::SessionId;

/// Bounded by the payload's own byte length, matching `bincode::serialize`'s fixint encoding —
/// see `gf_share_gen::gf_share_gen::deser_bounded` for why `with_fixint_encoding` is required,
/// not optional, here.
fn deser_bounded<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, GfTripleGenError> {
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(bytes.len() as u64)
        .deserialize(bytes)?)
}

/// Represents a node in the GF(2^k) triple generation protocol.
#[derive(Clone, Debug)]
pub struct GfTripleGenNode<K: BinaryField> {
    /// ID of the node.
    pub id: usize,
    /// The number of parties participating in the triple generation protocol.
    pub n_parties: usize,
    /// The upper bound of corrupt parties participating in the triple generation protocol.
    pub threshold: usize,
    /// Internal storage of the node.
    pub storage:
        Arc<Mutex<SessionStore<SessionId, (usize, Instant, Arc<Mutex<GfTripleGenStorage<K>>>)>>>,
    /// Batch reconstruction node used in the triple generation, for opening degree-`2t` shares.
    pub batch_recon_node: GfBatchReconNode<K>,
    pub batch_output: Arc<Mutex<Receiver<SessionId>>>,
}

const MAX_GF_TRIPLE_GEN_SESSIONS: usize = 2048;

impl<K: BinaryField> GfTripleGenNode<K> {
    pub fn new(id: usize, n_parties: usize, threshold: usize) -> Result<Self, GfTripleGenError> {
        let (batch_sender, batch_receiver) = tokio::sync::mpsc::channel(200);
        // batch_recon_node is for opening degree 2t shares
        let batch_recon_node =
            GfBatchReconNode::<K>::new(id, n_parties, threshold, threshold * 2, batch_sender)?;
        Ok(Self {
            id,
            n_parties,
            threshold,
            storage: Arc::new(Mutex::new(SessionStore::with_default_cap())),
            batch_recon_node,
            batch_output: Arc::new(Mutex::new(batch_receiver)),
        })
    }

    /// Accesses the storage of the node, and in case that the storage does not exists yet for
    /// the given `session_id`, it is created in place and returned.
    pub async fn get_or_create_store(
        &mut self,
        session_id: SessionId,
        initiator_id: usize,
    ) -> Option<Arc<Mutex<GfTripleGenStorage<K>>>> {
        self.storage
            .lock()
            .await
            .get_or_admit(
                session_id,
                initiator_id,
                MAX_GF_TRIPLE_GEN_SESSIONS,
                MAX_GF_TRIPLE_GEN_SESSIONS / self.n_parties,
                || Arc::new(Mutex::new(GfTripleGenStorage::empty())),
            )
            .ok()
    }

    pub async fn clear_store(&self, session_id: SessionId) -> bool {
        self.batch_recon_node.clear_store(session_id).await;
        let mut store = self.storage.lock().await;
        store.retire(session_id)
    }

    pub async fn store_len(&self) -> usize {
        self.storage.lock().await.len()
    }

    pub async fn drain_batch_recon_output(&mut self) -> Result<(), GfTripleGenError> {
        loop {
            let id = {
                let mut rx = self.batch_output.lock().await;
                match rx.try_recv() {
                    Ok(id) => id,
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        return Err(GfTripleGenError::Abort);
                    }
                }
            };

            let output = self.batch_recon_node.get_store(id).await?;
            self.batch_recon_finish_handler(id, output).await?;
        }
        Ok(())
    }

    pub async fn wait_for_result(
        &self,
        session_id: SessionId,
        duration: Duration,
    ) -> Result<Vec<GfBeaverTriple<K>>, GfTripleGenError> {
        let output_receiver = {
            let storage = self.storage.lock().await;
            let storage_bind = match storage.get(&session_id) {
                Some((_, _, arc)) => arc,
                None => return Err(GfTripleGenError::NoSuchSessionId(session_id)),
            };
            let mut storage = storage_bind.lock().await;

            storage
                .output_receiver
                .take()
                .ok_or(GfTripleGenError::ResultAlreadyReceived(session_id))?
        };

        match timeout(duration, output_receiver).await {
            Err(_) => Err(GfTripleGenError::Timeout(session_id)),
            Ok(Err(_)) => Err(GfTripleGenError::ReceiveError(session_id)),
            Ok(Ok(shares)) => Ok(shares),
        }
    }

    async fn try_finalize_triple_gen(
        &self,
        session_id: SessionId,
        storage_bind: Arc<Mutex<GfTripleGenStorage<K>>>,
    ) -> Result<bool, GfTripleGenError> {
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
            let result_share = (pair.degree_t.clone() + sub_value)?;
            result_triples.push(GfBeaverTriple::new(
                share_a.clone(),
                share_b.clone(),
                result_share,
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
                .ok_or(GfTripleGenError::SendError(session_id))?
        };

        sender
            .send(result_triples)
            .map_err(|_| GfTripleGenError::SendError(session_id))?;

        Ok(true)
    }

    /// Accept a completed batch reconstruction without assuming that the local
    /// triple-generation inputs have already been installed. A fast quorum of remote parties
    /// can finish reconstruction before a slower party reaches `init`/`init_batch`; in that case
    /// the input width is not known yet and the serialized payload must be retained rather than
    /// decoded against width zero.
    async fn accept_batch_recon_payload(
        &self,
        session_id: SessionId,
        storage_bind: Arc<Mutex<GfTripleGenStorage<K>>>,
        payload: Vec<u8>,
    ) -> Result<bool, GfTripleGenError> {
        let expected_len = {
            let mut storage = storage_bind.lock().await;

            match storage.protocol_state {
                ProtocolState::Finished => return Ok(true),
                ProtocolState::NotInitialized => {
                    // Batch reconstruction emits one completion per session. Keep the first
                    // completion if a duplicate is ever delivered.
                    if storage.pending_batch_recon_payload.is_none() {
                        storage.pending_batch_recon_payload = Some(payload);
                    }
                    return Ok(false);
                }
                ProtocolState::Initialized => storage.randousha_pairs.len(),
            }
        };

        let batch_recon_result: Vec<K> = deser_bounded(&payload)?;
        if batch_recon_result.len() != expected_len {
            return Err(GfTripleGenError::NotEnoughShares);
        }

        {
            let mut storage = storage_bind.lock().await;

            if storage.protocol_state == ProtocolState::Finished {
                return Ok(true);
            }

            storage.batch_recon_result = Some(batch_recon_result);
        }

        self.try_finalize_triple_gen(session_id, storage_bind).await
    }

    /// Initializes the protocol to generate random triples based on previously generated shares
    /// and random double shares.
    pub async fn init<N: Network>(
        &mut self,
        random_shares_a: Vec<GfShare<K>>,
        random_shares_b: Vec<GfShare<K>>,
        randousha_pairs: Vec<GfDoubleShamirShare<K>>,
        session_id: SessionId,
        network: Arc<N>,
    ) -> Result<(), GfTripleGenError> {
        // Validates that there are enough random double shares and random shares to perform the
        // operation.

        info!(
            num_randousha = randousha_pairs.len(),
            num_random_a = random_shares_a.len(),
            num_random_b = random_shares_b.len(),
            "Initializing GfTripleGen protocol"
        );

        assert!(session_id.calling_protocol().is_some());
        assert_eq!(session_id.sub_id(), 0);
        assert_eq!(session_id.round_id(), 0);

        if randousha_pairs.len() != 2 * self.threshold + 1
            || random_shares_a.len() != 2 * self.threshold + 1
            || random_shares_b.len() != 2 * self.threshold + 1
        {
            return Err(GfTripleGenError::NotEnoughPreprocessing);
        }

        let mut sub_shares_deg_2t = Vec::new();
        for (share_a, share_b, ran_dou_sha) in
            izip!(&random_shares_a, &random_shares_b, &randousha_pairs)
        {
            let mult_share_deg_2t = share_a.share_mul(share_b)?;
            let sub_share_deg_2t = (mult_share_deg_2t - ran_dou_sha.degree_2t.clone())?;
            sub_shares_deg_2t.push(sub_share_deg_2t);
        }

        // Mark the protocol initialized and atomically claim any reconstruction result that
        // arrived before the local inputs.
        let storage_bind = match self.get_or_create_store(session_id, self.id).await {
            Some(s) => s,
            None => return Ok(()),
        };
        let pending_batch_recon_payload = {
            let mut storage = storage_bind.lock().await;
            storage.protocol_state = ProtocolState::Initialized;
            storage.randousha_pairs = randousha_pairs;
            storage.random_shares_a_input = random_shares_a;
            storage.random_shares_b_input = random_shares_b;
            storage.pending_batch_recon_payload.take()
        };

        if let Some(payload) = pending_batch_recon_payload {
            self.accept_batch_recon_payload(session_id, storage_bind.clone(), payload)
                .await?;
        }

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
        random_shares_a: Vec<GfShare<K>>,
        random_shares_b: Vec<GfShare<K>>,
        randousha_pairs: Vec<GfDoubleShamirShare<K>>,
        session_id: SessionId,
        network: Arc<N>,
    ) -> Result<(), GfTripleGenError> {
        let group_size = 2 * self.threshold + 1;

        info!(
            num_randousha = randousha_pairs.len(),
            num_random_a = random_shares_a.len(),
            num_random_b = random_shares_b.len(),
            groups = randousha_pairs.len() / group_size,
            "Initializing batched GfTripleGen protocol"
        );

        assert_eq!(session_id.sub_id(), 0);

        if randousha_pairs.is_empty()
            || randousha_pairs.len() % group_size != 0
            || random_shares_a.len() != randousha_pairs.len()
            || random_shares_b.len() != randousha_pairs.len()
        {
            return Err(GfTripleGenError::NotEnoughPreprocessing);
        }

        let mut sub_shares_deg_2t = Vec::with_capacity(randousha_pairs.len());
        for (share_a, share_b, ran_dou_sha) in
            izip!(&random_shares_a, &random_shares_b, &randousha_pairs)
        {
            let mult_share_deg_2t = share_a.share_mul(share_b)?;
            let sub_share_deg_2t = (mult_share_deg_2t - ran_dou_sha.degree_2t.clone())?;
            sub_shares_deg_2t.push(sub_share_deg_2t);
        }

        let storage_bind = match self.get_or_create_store(session_id, self.id).await {
            Some(s) => s,
            None => return Ok(()),
        };
        let pending_batch_recon_payload = {
            let mut storage = storage_bind.lock().await;
            storage.protocol_state = ProtocolState::Initialized;
            storage.randousha_pairs = randousha_pairs;
            storage.random_shares_a_input = random_shares_a;
            storage.random_shares_b_input = random_shares_b;
            storage.pending_batch_recon_payload.take()
        };

        if let Some(payload) = pending_batch_recon_payload {
            self.accept_batch_recon_payload(session_id, storage_bind.clone(), payload)
                .await?;
        }

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
    ) -> Result<(), GfTripleGenError> {
        info!("Handling Batch reconstruction results");
        // SHOULD NEVER HAPPEN, since comes from batch reconstruction
        if session_id.sub_id() != 0 {
            return Err(GfTripleGenError::SessionIdError(session_id));
        }

        // SHOULD ALSO NEVER FAIL, since comes from batch reconstruction
        let storage_bind = match self.get_or_create_store(session_id, self.id).await {
            Some(s) => s,
            None => return Ok(()),
        };
        self.accept_batch_recon_payload(session_id, storage_bind, payload)
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::gf2k::field::Gf256;
    use crate::common::ProtocolSessionId;
    use crate::honeybadger::ProtocolType;
    use stoffelmpc_network::fake_network::{FakeInnerNetwork, FakeNetwork, FakeNetworkConfig};

    #[tokio::test]
    async fn buffers_batch_reconstruction_that_finishes_before_local_init() {
        let mut node = GfTripleGenNode::<Gf256>::new(0, 5, 1).unwrap();
        let session_id = SessionId::new(ProtocolType::GfTriple, SessionId::pack_slot(7, 0, 0), 42);
        let values = vec![Gf256(1), Gf256(2), Gf256(3)];
        let payload = bincode::serialize(&values).unwrap();

        // Before this fix (mirrored from the F-domain test), the handler decoded this vector
        // with an expected width of zero and returned an error.
        node.batch_recon_finish_handler(session_id, payload.clone())
            .await
            .unwrap();

        {
            let storage_bind = node.get_or_create_store(session_id, node.id).await.unwrap();
            let storage = storage_bind.lock().await;
            assert_eq!(storage.protocol_state, ProtocolState::NotInitialized);
            assert_eq!(
                storage.pending_batch_recon_payload.as_deref(),
                Some(payload.as_slice())
            );
            assert!(storage.batch_recon_result.is_none());
        }

        let random_shares_a = values
            .iter()
            .map(|value| GfShare::new(*value, node.id, 1))
            .collect();
        let random_shares_b = values
            .iter()
            .map(|value| GfShare::new(*value, node.id, 1))
            .collect();
        let randousha_pairs = values
            .iter()
            .map(|value| {
                GfDoubleShamirShare::new(
                    GfShare::new(*value, node.id, 1),
                    GfShare::new(*value, node.id, 2),
                )
            })
            .collect();
        let (inner, _inboxes, _) = FakeInnerNetwork::new(5, None, FakeNetworkConfig::new(10));

        node.init(
            random_shares_a,
            random_shares_b,
            randousha_pairs,
            session_id,
            Arc::new(FakeNetwork::new(node.id, inner)),
        )
        .await
        .unwrap();

        let triples = node
            .wait_for_result(session_id, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(triples.len(), values.len());

        let storage_bind = node.get_or_create_store(session_id, node.id).await.unwrap();
        let storage = storage_bind.lock().await;
        assert_eq!(storage.protocol_state, ProtocolState::Finished);
        assert!(storage.pending_batch_recon_payload.is_none());
    }
}
