//! GF(2^k) equivalent of `RanDouShaNode` (`honeybadger::ran_dou_sha`), a direct structural port
//! — `honeybadger/ran_dou_sha/mod.rs` was read in full before writing this.
use bincode::Options;
use std::{collections::HashMap, sync::Arc, time::Instant};
use tokio::sync::{
    oneshot::{channel, Receiver, Sender},
    Mutex,
};
use tokio::time::{timeout, Duration};

use stoffelnet::network_utils::{Network, PartyId};
use tracing::{info, warn};

use crate::common::session_store::{Admission, SessionStore};
use crate::{
    common::{
        gf2k::{
            field::BinaryField,
            share::GfShare,
            vandermonde::{apply_vandermonde, make_vandermonde},
            Poly,
        },
        share::ShareError,
        ProtocolSessionId,
    },
    honeybadger::{
        gf_double_share::GfDoubleShamirShare,
        gf_ran_dou_sha::{
            GfRanDouShaError, GfRanDouShaMessage, GfRanDouShaPayload, GfReconstructionMessage,
        },
        ProtocolType, SessionId, WrappedMessage, MAX_MESSAGE_SIZE, RBC,
    },
};

fn ser<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, GfRanDouShaError> {
    Ok(bincode::serialize(value)?)
}

fn deser_bounded<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, GfRanDouShaError> {
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(bytes.len() as u64)
        .deserialize(bytes)?)
}

/// Storage for the GF(2^k) Random Double Sharing protocol.
#[derive(Debug)]
pub struct GfRanDouShaStore<K: BinaryField> {
    pub received_r_shares_degree_t: HashMap<PartyId, Vec<GfShare<K>>>,
    pub received_r_shares_degree_2t: HashMap<PartyId, Vec<GfShare<K>>>,
    pub computed_r_shares_degree_t: Vec<GfShare<K>>,
    pub computed_r_shares_degree_2t: Vec<GfShare<K>>,
    pub received_ok_msg: Vec<usize>,
    pub batch_size: usize,
    pub state: GfRanDouShaState,
    pub protocol_output: Vec<GfDoubleShamirShare<K>>,
    pub output_sender: Option<Sender<Vec<GfDoubleShamirShare<K>>>>,
    pub output_receiver: Option<Receiver<Vec<GfDoubleShamirShare<K>>>>,
    pub pending_messages: Vec<GfRanDouShaMessage>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GfRanDouShaState {
    Initialized,
    Finished,
}

impl<K: BinaryField> GfRanDouShaStore<K> {
    pub fn empty() -> Self {
        let (output_sender, output_receiver) = channel();
        Self {
            received_r_shares_degree_t: HashMap::new(),
            received_r_shares_degree_2t: HashMap::new(),
            computed_r_shares_degree_t: Vec::new(),
            computed_r_shares_degree_2t: Vec::new(),
            received_ok_msg: Vec::new(),
            batch_size: 1,
            state: GfRanDouShaState::Initialized,
            protocol_output: Vec::new(),
            output_sender: Some(output_sender),
            output_receiver: Some(output_receiver),
            pending_messages: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct GfRanDouShaNode<K: BinaryField, R: RBC> {
    pub id: PartyId,
    pub n_parties: usize,
    pub threshold: usize,
    pub store:
        Arc<Mutex<SessionStore<SessionId, (usize, Instant, Arc<Mutex<GfRanDouShaStore<K>>>)>>>,
    pub rbc: R,
    pub rbc_output: Arc<Mutex<tokio::sync::mpsc::Receiver<SessionId>>>,
}

const MAX_GF_RAN_DOU_SHA_SESSIONS: usize = 1024;

impl<K, R> GfRanDouShaNode<K, R>
where
    K: BinaryField,
    R: RBC<Id = SessionId>,
{
    pub fn new(
        id: PartyId,
        n_parties: usize,
        threshold: usize,
        k: usize,
    ) -> Result<Self, GfRanDouShaError> {
        let (rbc_sender, rbc_receiver) = tokio::sync::mpsc::channel(200);
        let rbc = R::new(
            id,
            n_parties,
            threshold,
            k,
            rbc_sender,
            Arc::new(WrappedMessage::rbc_wrap),
        )?;
        Ok(Self {
            id,
            n_parties,
            threshold,
            store: Arc::new(Mutex::new(SessionStore::with_default_cap())),
            rbc,
            rbc_output: Arc::new(Mutex::new(rbc_receiver)),
        })
    }

    pub async fn clear_store(&self, session_id: SessionId) -> bool {
        let caller = session_id
            .calling_protocol()
            .unwrap_or(ProtocolType::GfRandousha);
        for party_id in (self.threshold + 1)..self.n_parties {
            let rbc_session_id = SessionId::new(
                caller,
                SessionId::pack_slot(session_id.exec_id(), party_id as u8, session_id.round_id()),
                session_id.instance_id(),
            );
            self.rbc.clear_session(rbc_session_id).await;
        }

        let mut store = self.store.lock().await;
        store.retire(session_id)
    }

    pub async fn store_len(&self) -> usize {
        self.store.lock().await.len()
    }

    pub async fn get_or_create_store(
        &mut self,
        session_id: SessionId,
        initiator_id: usize,
    ) -> Option<Arc<Mutex<GfRanDouShaStore<K>>>> {
        match self.store.lock().await.get_or_admit(
            session_id,
            initiator_id,
            MAX_GF_RAN_DOU_SHA_SESSIONS,
            MAX_GF_RAN_DOU_SHA_SESSIONS / self.n_parties,
            || Arc::new(Mutex::new(GfRanDouShaStore::empty())),
        ) {
            Admission::Got(arc) => Some(arc),
            Admission::Retired => None,
            Admission::Rejected => {
                warn!("GfRanDouSha session limit reached");
                None
            }
        }
    }

    pub async fn drain_rbc_output(&mut self) -> Result<(), GfRanDouShaError> {
        loop {
            let id = {
                let mut rx = self.rbc_output.lock().await;
                match rx.try_recv() {
                    Ok(id) => id,
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        return Err(GfRanDouShaError::Abort);
                    }
                }
            };

            let output = self.rbc.get_store(id).await?;
            let mut msg: GfRanDouShaMessage = bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .allow_trailing_bytes()
                .with_limit(MAX_MESSAGE_SIZE)
                .deserialize(&output)?;
            let authenticated_sender = id.sub_id() as usize;
            if msg.sender_id != authenticated_sender {
                warn!(
                    "Dropping RBC output: inner sender_id {} does not match session sub_id {}",
                    msg.sender_id, authenticated_sender
                );
                continue;
            }
            if msg.session_id.exec_id() != id.exec_id()
                || msg.session_id.instance_id() != id.instance_id()
            {
                warn!("Dropping RBC output: inner session_id does not match RBC session metadata");
                continue;
            }
            if msg.session_id.round_id() != id.round_id() || msg.session_id.sub_id() != 0 {
                warn!("Dropping RBC output: inner session metadata does not match RBC session metadata");
                continue;
            }

            msg.sender_id = authenticated_sender;

            self.output_handler(msg).await?;
        }
        Ok(())
    }

    pub async fn wait_for_result(
        &self,
        session_id: SessionId,
        duration: Duration,
    ) -> Result<Vec<GfDoubleShamirShare<K>>, GfRanDouShaError> {
        let output_receiver = {
            let storage = self.store.lock().await;
            let storage_bind = match storage.get(&session_id) {
                Some((_, _, arc)) => arc,
                None => return Err(GfRanDouShaError::NoSuchSessionId(session_id)),
            };
            let mut storage = storage_bind.lock().await;

            storage
                .output_receiver
                .take()
                .ok_or(GfRanDouShaError::ResultAlreadyReceived(session_id))?
        };

        match timeout(duration, output_receiver).await {
            Err(_) => Err(GfRanDouShaError::Timeout(session_id)),
            Ok(Err(_)) => Err(GfRanDouShaError::ReceiveError(session_id)),
            Ok(Ok(shares)) => Ok(shares),
        }
    }

    async fn try_finalize(
        &self,
        session_id: SessionId,
        store_mutex: Arc<Mutex<GfRanDouShaStore<K>>>,
    ) -> Result<bool, GfRanDouShaError> {
        let mut store = store_mutex.lock().await;

        if store.state == GfRanDouShaState::Finished {
            return Ok(true);
        }

        if store.computed_r_shares_degree_t.len() < store.batch_size * self.n_parties
            || store.computed_r_shares_degree_2t.len() < store.batch_size * self.n_parties
        {
            return Ok(false);
        }

        if store.received_ok_msg.len() < self.n_parties - (self.threshold + 1) {
            return Ok(false);
        }

        let mut output_double_share = Vec::with_capacity(store.batch_size * (self.threshold + 1));
        for (shares_t, shares_2t) in store
            .computed_r_shares_degree_t
            .chunks_exact(self.n_parties)
            .zip(
                store
                    .computed_r_shares_degree_2t
                    .chunks_exact(self.n_parties),
            )
        {
            output_double_share.extend(
                shares_t[..self.threshold + 1]
                    .iter()
                    .cloned()
                    .zip(shares_2t[..self.threshold + 1].iter().cloned())
                    .map(|(a, b)| GfDoubleShamirShare::new(a, b)),
            );
        }

        store.state = GfRanDouShaState::Finished;
        store.protocol_output = output_double_share.clone();

        let sender = store.output_sender.take().unwrap();
        sender
            .send(output_double_share)
            .map_err(|_| GfRanDouShaError::SendError(session_id))?;

        Ok(true)
    }

    pub async fn init<N>(
        &mut self,
        shares_deg_t: Vec<GfShare<K>>,
        shares_deg_2t: Vec<GfShare<K>>,
        session_id: SessionId,
        network: Arc<N>,
    ) -> Result<(), GfRanDouShaError>
    where
        N: Network + Send + Sync,
    {
        self.init_batch(vec![shares_deg_t], vec![shares_deg_2t], session_id, network)
            .await
    }

    pub async fn init_batch<N>(
        &mut self,
        shares_deg_t_by_batch: Vec<Vec<GfShare<K>>>,
        shares_deg_2t_by_batch: Vec<Vec<GfShare<K>>>,
        session_id: SessionId,
        network: Arc<N>,
    ) -> Result<(), GfRanDouShaError>
    where
        N: Network + Send + Sync,
    {
        info!(
            "Node {} (session {}) - Starting gf init_batch.",
            self.id,
            session_id.as_u128()
        );

        assert_eq!(session_id.sub_id(), 0);
        if shares_deg_t_by_batch.len() != shares_deg_2t_by_batch.len() {
            return Err(GfRanDouShaError::ShareError(ShareError::DegreeMismatch));
        }

        let vandermonde_matrix = make_vandermonde::<K>(self.n_parties, self.n_parties - 1)?;
        let mut r_deg_t = Vec::with_capacity(shares_deg_t_by_batch.len() * self.n_parties);
        for shares_deg_t in shares_deg_t_by_batch {
            r_deg_t.extend(apply_vandermonde(&vandermonde_matrix, &shares_deg_t)?);
        }

        let mut r_deg_2t = Vec::with_capacity(shares_deg_2t_by_batch.len() * self.n_parties);
        for shares_deg_2t in shares_deg_2t_by_batch {
            r_deg_2t.extend(apply_vandermonde(&vandermonde_matrix, &shares_deg_2t)?);
        }

        let bind_store = match self.get_or_create_store(session_id, self.id).await {
            Some(s) => s,
            None => return Ok(()),
        };
        let pending = {
            let mut store = bind_store.lock().await;
            store.batch_size = r_deg_t.len() / self.n_parties;
            store.computed_r_shares_degree_t = r_deg_t.clone();
            store.computed_r_shares_degree_2t = r_deg_2t.clone();
            std::mem::take(&mut store.pending_messages)
        };

        for pending_msg in pending {
            let sender_id = pending_msg.sender_id;
            if let Err(e) = self
                .reconstruction_handler(pending_msg, Arc::clone(&network))
                .await
            {
                warn!(
                    session_id = session_id.as_u128(),
                    "dropping invalid pre-init gf reconstruction message from party {sender_id}: {e:?}"
                );
            }
        }

        if self.try_finalize(session_id, bind_store.clone()).await? {
            return Ok(());
        }

        for i in (self.threshold + 1)..self.n_parties {
            let recon_messages: Vec<_> = r_deg_t
                .chunks_exact(self.n_parties)
                .zip(r_deg_2t.chunks_exact(self.n_parties))
                .map(|(shares_t, shares_2t)| {
                    GfReconstructionMessage::new(shares_t[i].clone(), shares_2t[i].clone())
                })
                .collect();
            let payload = if recon_messages.len() == 1 {
                GfRanDouShaPayload::Reconstruct(ser(&recon_messages[0])?)
            } else {
                let mut payloads = Vec::with_capacity(recon_messages.len());
                for message in recon_messages {
                    payloads.push(ser(&message)?);
                }
                GfRanDouShaPayload::ReconstructBatch(payloads)
            };
            let rds_message = GfRanDouShaMessage::new(self.id, session_id, payload);
            let wrapped = WrappedMessage::GfRanDouSha(rds_message);

            let bytes_wrapped = bincode::serialize(&wrapped)?;
            network.send(i, &bytes_wrapped).await?;
        }
        Ok(())
    }

    pub async fn reconstruction_handler<N>(
        &mut self,
        msg: GfRanDouShaMessage,
        network: Arc<N>,
    ) -> Result<(), GfRanDouShaError>
    where
        N: Network + Send + Sync,
    {
        info!(
            "Node {} (session {}) - gf reconstruction_handler from sender {}.",
            self.id,
            msg.session_id.as_u128(),
            msg.sender_id
        );

        if msg.session_id.sub_id() != 0 {
            return Err(GfRanDouShaError::SessionIdError(msg.session_id));
        }

        let sender_id = msg.sender_id;
        let binding = match self.get_or_create_store(msg.session_id, sender_id).await {
            Some(s) => s,
            None => return Ok(()),
        };
        let expected_batch = {
            let mut store = binding.lock().await;
            if store.computed_r_shares_degree_t.is_empty() {
                if store.pending_messages.len() >= self.n_parties
                    || store
                        .pending_messages
                        .iter()
                        .any(|m| m.sender_id == sender_id)
                {
                    warn!(
                        session_id = msg.session_id.as_u128(),
                        "pending GfRanDouSha queue full or already holds a message from party {sender_id}; dropping"
                    );
                    return Ok(());
                }
                store.pending_messages.push(msg);
                return Ok(());
            }
            store.batch_size
        };

        let payloads = match msg.payload {
            GfRanDouShaPayload::Reconstruct(p) => vec![p],
            GfRanDouShaPayload::ReconstructBatch(p) => p,
            GfRanDouShaPayload::Output(_) => return Err(GfRanDouShaError::Abort),
        };
        // Validate the declared element count against the locally-known batch size *before*
        // deserializing any of them.
        if payloads.len() != expected_batch {
            return Err(GfRanDouShaError::ShareError(ShareError::DegreeMismatch));
        }
        let mut rec_messages: Vec<GfReconstructionMessage<K>> = Vec::with_capacity(payloads.len());
        for payload in payloads {
            rec_messages.push(deser_bounded(&payload)?);
        }

        for rec_msg in &rec_messages {
            if rec_msg.r_share_deg_t.id != sender_id || rec_msg.r_share_deg_2t.id != sender_id {
                return Err(GfRanDouShaError::IncorrectID);
            }
            if rec_msg.r_share_deg_t.degree != self.threshold
                || rec_msg.r_share_deg_2t.degree != 2 * self.threshold
            {
                return Err(GfRanDouShaError::ShareError(ShareError::DegreeMismatch));
            }
        }
        let mut store = binding.lock().await;
        if store.batch_size != rec_messages.len() {
            return Err(GfRanDouShaError::ShareError(ShareError::DegreeMismatch));
        }

        if store.state == GfRanDouShaState::Finished {
            return Ok(());
        }
        if store.received_r_shares_degree_t.contains_key(&sender_id) {
            warn!(
                session_id = msg.session_id.as_u128(),
                "Duplicate gf reconstruction share received from party {:?}, ignoring.", sender_id
            );
            return Ok(());
        }

        store.received_r_shares_degree_t.insert(
            sender_id,
            rec_messages
                .iter()
                .map(|m| m.r_share_deg_t.clone())
                .collect(),
        );
        store.received_r_shares_degree_2t.insert(
            sender_id,
            rec_messages
                .iter()
                .map(|m| m.r_share_deg_2t.clone())
                .collect(),
        );

        // Only designated checking parties (id in [t+1, n)) attempt reconstruction.
        if self.id >= self.threshold + 1 && self.id < self.n_parties {
            if store.received_r_shares_degree_t.len() >= 2 * self.threshold + 1
                && store.received_r_shares_degree_2t.len() >= self.n_parties
            {
                let batch_size = store.batch_size;
                let mut shares_t_by_batch = vec![Vec::new(); batch_size];
                let mut shares_2t_by_batch = vec![Vec::new(); batch_size];

                for shares in store.received_r_shares_degree_t.values() {
                    for (batch_index, share) in shares.iter().cloned().enumerate() {
                        shares_t_by_batch[batch_index].push(share);
                    }
                }
                for shares in store.received_r_shares_degree_2t.values() {
                    for (batch_index, share) in shares.iter().cloned().enumerate() {
                        shares_2t_by_batch[batch_index].push(share);
                    }
                }
                drop(store);

                let mut ok = true;
                for (shares_t_for_recon, shares_2t_for_recon) in
                    shares_t_by_batch.iter().zip(&shares_2t_by_batch)
                {
                    match (
                        GfShare::recover_secret_naive(
                            shares_t_for_recon,
                            self.n_parties,
                            self.threshold,
                        ),
                        GfShare::recover_secret_naive(
                            shares_2t_for_recon,
                            self.n_parties,
                            self.threshold,
                        ),
                    ) {
                        (Ok(reconstructed_r_t), Ok(reconstructed_r_2t)) => {
                            let poly1 = Poly::from_coeffs(reconstructed_r_t.0);
                            let poly2 = Poly::from_coeffs(reconstructed_r_2t.0);
                            if self.threshold != poly1.degree()
                                || 2 * self.threshold != poly2.degree()
                                || reconstructed_r_t.1 != reconstructed_r_2t.1
                            {
                                ok = false;
                                break;
                            }
                        }
                        _ => {
                            ok = false;
                            break;
                        }
                    }
                }

                let out_msg = GfRanDouShaMessage::new(
                    self.id,
                    msg.session_id,
                    GfRanDouShaPayload::Output(ok),
                );
                let bytes_msg = bincode::serialize(&out_msg)?;

                let caller = msg
                    .session_id
                    .calling_protocol()
                    .unwrap_or(ProtocolType::GfRandousha);
                let sessionid = SessionId::new(
                    caller,
                    SessionId::pack_slot(
                        msg.session_id.exec_id(),
                        self.id as u8,
                        msg.session_id.round_id(),
                    ),
                    msg.session_id.instance_id(),
                );
                self.rbc
                    .init(bytes_msg, sessionid, Arc::clone(&network))
                    .await?;
            }
        }

        Ok(())
    }

    pub async fn output_handler(
        &mut self,
        msg: GfRanDouShaMessage,
    ) -> Result<(), GfRanDouShaError> {
        let output = match msg.payload {
            GfRanDouShaPayload::Reconstruct(_) | GfRanDouShaPayload::ReconstructBatch(_) => {
                return Err(GfRanDouShaError::Abort)
            }
            GfRanDouShaPayload::Output(ok) => ok,
        };
        if msg.sender_id < self.threshold + 1 || msg.sender_id >= self.n_parties {
            return Err(GfRanDouShaError::IncorrectID);
        }

        info!(
            "Node {} (session {}) - gf output_handler from sender {}. Status: {}.",
            self.id,
            msg.session_id.as_u128(),
            msg.sender_id,
            output
        );
        if !output {
            return Err(GfRanDouShaError::Abort);
        }
        let binding = match self
            .get_or_create_store(msg.session_id, msg.sender_id)
            .await
        {
            Some(s) => s,
            None => return Ok(()),
        };
        let mut store = binding.lock().await;

        if !store.received_ok_msg.contains(&msg.sender_id) {
            store.received_ok_msg.push(msg.sender_id);
        }

        drop(store);
        self.try_finalize(msg.session_id, binding.clone()).await?;
        Ok(())
    }

    pub async fn process<N>(
        &mut self,
        msg: GfRanDouShaMessage,
        network: Arc<N>,
    ) -> Result<(), GfRanDouShaError>
    where
        N: Network + Send + Sync,
    {
        self.reconstruction_handler(msg, network).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::gf2k::field::Gf256;
    use crate::common::rbc::rbc::Avid;
    use crate::honeybadger::SessionId;
    use stoffelmpc_network::fake_network::{FakeInnerNetwork, FakeNetwork, FakeNetworkConfig};

    fn dummy_share(id: usize, degree: usize) -> GfShare<Gf256> {
        GfShare::new(Gf256(0), id, degree)
    }

    #[tokio::test]
    async fn test_gf_randousha_storage_limit_in_reconstruction_handler() {
        let mut node = GfRanDouShaNode::<Gf256, Avid<SessionId>>::new(0, 5, 1, 2).unwrap();
        let inner = FakeInnerNetwork::new(5, None, FakeNetworkConfig::new(10)).0;
        let net = Arc::new(FakeNetwork::new(0, inner));

        let per_peer_limit = MAX_GF_RAN_DOU_SHA_SESSIONS / 5;
        for exec in 0..per_peer_limit as u64 {
            let sid = SessionId::new(
                ProtocolType::GfRandousha,
                SessionId::pack_slot(exec, 0, 0),
                111,
            );
            let rec_msg = GfReconstructionMessage::new(dummy_share(0, 1), dummy_share(0, 2));
            let payload = ser(&rec_msg).unwrap();
            let msg = GfRanDouShaMessage::new(0, sid, GfRanDouShaPayload::Reconstruct(payload));
            let _ = node.reconstruction_handler(msg, net.clone()).await;
        }
        assert_eq!(node.store_len().await, per_peer_limit);

        let over_sid = SessionId::new(
            ProtocolType::GfRandousha,
            SessionId::pack_slot(per_peer_limit as u64, 0, 0),
            111,
        );
        let rec_msg = GfReconstructionMessage::new(dummy_share(0, 1), dummy_share(0, 2));
        let payload = ser(&rec_msg).unwrap();
        let msg = GfRanDouShaMessage::new(0, over_sid, GfRanDouShaPayload::Reconstruct(payload));

        let result = node.reconstruction_handler(msg, net).await;
        assert!(
            result.is_ok(),
            "handler should silently drop over-limit sessions, not error"
        );
        assert_eq!(
            node.store_len().await,
            per_peer_limit,
            "store must not grow past the per-peer limit"
        );
    }

    #[tokio::test]
    async fn test_gf_randousha_handle_invalid_sub_id() {
        let mut node = GfRanDouShaNode::<Gf256, Avid<SessionId>>::new(0, 5, 1, 2).unwrap();
        let inner = FakeInnerNetwork::new(5, None, FakeNetworkConfig::new(10)).0;
        let net = Arc::new(FakeNetwork::new(0, inner));

        let session_id =
            SessionId::new(ProtocolType::GfRandousha, SessionId::pack_slot(0, 1, 0), 0);

        let rec_msg = GfReconstructionMessage::new(dummy_share(0, 0), dummy_share(0, 0));
        let payload = ser(&rec_msg).unwrap();
        let msg = GfRanDouShaMessage::new(0, session_id, GfRanDouShaPayload::Reconstruct(payload));

        let result = node.reconstruction_handler(msg, net).await;
        match result {
            Err(GfRanDouShaError::SessionIdError(sid)) => assert_eq!(sid, session_id),
            _ => panic!("Expected SessionIdError for invalid sub_id"),
        }
    }

    /// Regression test mirroring RanDouSha's own: a Byzantine peer sending an oversized
    /// `ReconstructBatch` before this node's own `init_batch` runs must not let the attacker's
    /// message length leak into aggregation and panic once enough parties have reported.
    #[tokio::test]
    async fn test_gf_randousha_early_oversized_batch_does_not_panic() {
        let mut node = GfRanDouShaNode::<Gf256, Avid<SessionId>>::new(0, 5, 1, 2).unwrap();
        let (inner, _inboxes, _) = FakeInnerNetwork::new(5, None, FakeNetworkConfig::new(10));
        let net = Arc::new(FakeNetwork::new(0, inner));
        let session_id =
            SessionId::new(ProtocolType::GfRandousha, SessionId::pack_slot(0, 0, 0), 0);

        let oversized_payloads: Vec<Vec<u8>> = (0..10)
            .map(|_| {
                let rec_msg = GfReconstructionMessage::new(dummy_share(4, 1), dummy_share(4, 2));
                ser(&rec_msg).unwrap()
            })
            .collect();
        let attacker_msg = GfRanDouShaMessage::new(
            4,
            session_id,
            GfRanDouShaPayload::ReconstructBatch(oversized_payloads),
        );
        node.reconstruction_handler(attacker_msg, net.clone())
            .await
            .unwrap();

        let batch_size = 2;
        let shares_deg_t_by_batch: Vec<Vec<GfShare<Gf256>>> = (0..batch_size)
            .map(|_| (0..5).map(|_| dummy_share(0, 1)).collect())
            .collect();
        let shares_deg_2t_by_batch: Vec<Vec<GfShare<Gf256>>> = (0..batch_size)
            .map(|_| (0..5).map(|_| dummy_share(0, 2)).collect())
            .collect();
        node.init_batch(
            shares_deg_t_by_batch,
            shares_deg_2t_by_batch,
            session_id,
            net.clone(),
        )
        .await
        .unwrap();

        for sender in 0..4usize {
            let payloads: Vec<Vec<u8>> = (0..batch_size)
                .map(|_| {
                    let rec_msg = GfReconstructionMessage::new(
                        dummy_share(sender, 1),
                        dummy_share(sender, 2),
                    );
                    ser(&rec_msg).unwrap()
                })
                .collect();
            let msg = GfRanDouShaMessage::new(
                sender,
                session_id,
                GfRanDouShaPayload::ReconstructBatch(payloads),
            );
            node.reconstruction_handler(msg, net.clone()).await.unwrap();
        }
    }
}
