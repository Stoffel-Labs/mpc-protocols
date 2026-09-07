//! GF(2^k) equivalent of `DoubleShareNode` (`honeybadger::double_share`), a direct structural
//! port — dealer-based, non-robust, no verification (that's `GfRanDouSha`'s job, built on top of
//! this protocol's raw output). `honeybadger/double_share/` itself is untouched by this file.

use ark_std::rand::Rng;
use itertools::izip;
use std::sync::Arc;
use std::time::Instant;
use stoffelnet::network_utils::{Network, PartyId};
use tokio::{
    sync::Mutex,
    time::{timeout, Duration},
};
use tracing::{info, warn};

use crate::common::session_store::{Admission, SessionStore};
use crate::{
    common::{gf2k::field::BinaryField, gf2k::share::GfShare, share::ShareError, ProtocolSessionId},
    honeybadger::{
        double_share::double_share_generation::ProtocolState,
        gf_double_share::{GfDouShaError, GfDouShaMessage, GfDouShaPayload, GfDouShaStorage},
        gf_double_share::GfDoubleShamirShare,
        SessionId, WrappedMessage,
    },
};

fn ser<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, GfDouShaError> {
    Ok(bincode::serialize(value)?)
}

fn deser_bounded<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, GfDouShaError> {
    use bincode::Options;
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(bytes.len() as u64)
        .deserialize(bytes)?)
}

/// Node participating in a non-robust GF(2^k) double share protocol.
#[derive(Clone, Debug)]
pub struct GfDoubleShareNode<K: BinaryField> {
    pub id: PartyId,
    pub n_parties: usize,
    pub threshold: usize,
    pub storage:
        Arc<Mutex<SessionStore<SessionId, (usize, Instant, Arc<Mutex<GfDouShaStorage<K>>>)>>>,
}

const MAX_GF_DOUSHA_SESSIONS: usize = 256;

impl<K: BinaryField> GfDoubleShareNode<K> {
    pub async fn process(&mut self, message: GfDouShaMessage) -> Result<(), GfDouShaError> {
        self.receive_double_shares_handler(message).await
    }

    pub fn new(id: PartyId, n_parties: usize, threshold: usize) -> Self {
        Self {
            id,
            n_parties,
            threshold,
            storage: Arc::new(Mutex::new(SessionStore::with_default_cap())),
        }
    }

    pub async fn get_or_create_store(
        &mut self,
        session_id: SessionId,
        initiator_id: usize,
    ) -> Option<Arc<Mutex<GfDouShaStorage<K>>>> {
        match self.storage.lock().await.get_or_admit(
            session_id,
            initiator_id,
            MAX_GF_DOUSHA_SESSIONS,
            MAX_GF_DOUSHA_SESSIONS / self.n_parties,
            || Arc::new(Mutex::new(GfDouShaStorage::empty(self.n_parties))),
        ) {
            Admission::Got(arc) => Some(arc),
            Admission::Retired => None,
            Admission::Rejected => {
                warn!("GfDouSha session limit reached");
                None
            }
        }
    }

    pub async fn clear_store(&self, session_id: SessionId) -> bool {
        let mut store = self.storage.lock().await;
        store.retire(session_id)
    }

    pub async fn store_len(&self) -> usize {
        self.storage.lock().await.len()
    }

    pub async fn wait_for_result(
        &self,
        session_id: SessionId,
        duration: Duration,
    ) -> Result<Vec<GfDoubleShamirShare<K>>, GfDouShaError> {
        let output_receiver = {
            let storage = self.storage.lock().await;
            let storage_bind = match storage.get(&session_id) {
                Some((_, _, arc)) => arc,
                None => return Err(GfDouShaError::NoSuchSessionId(session_id)),
            };
            let mut storage = storage_bind.lock().await;

            storage
                .output_receiver
                .take()
                .ok_or(GfDouShaError::ResultAlreadyReceived(session_id))?
        };

        match timeout(duration, output_receiver).await {
            Err(_) => Err(GfDouShaError::Timeout(session_id)),
            Ok(Err(_)) => Err(GfDouShaError::ReceiveError(session_id)),
            Ok(Ok(shares)) => Ok(shares),
        }
    }

    pub async fn init<N, R>(
        &mut self,
        session_id: SessionId,
        rng: &mut R,
        network: Arc<N>,
    ) -> Result<(), GfDouShaError>
    where
        N: Network,
        R: Rng,
    {
        self.init_batch(session_id, 1, rng, network).await
    }

    pub async fn init_batch<N, R>(
        &mut self,
        session_id: SessionId,
        batch_size: usize,
        rng: &mut R,
        network: Arc<N>,
    ) -> Result<(), GfDouShaError>
    where
        N: Network,
        R: Rng,
    {
        info!("Receiving init for gf double share from {0:?}", self.id);
        let batch_size = batch_size.max(1);

        let mut shares_by_recipient = vec![Vec::with_capacity(batch_size); self.n_parties];
        for _ in 0..batch_size {
            let secret = K::random(rng);

            let shares_deg_t = GfShare::compute_shares(secret, self.n_parties, self.threshold, rng)?;
            let shares_deg_2t =
                GfShare::compute_shares(secret, self.n_parties, 2 * self.threshold, rng)?;

            for (recipient_id, (share_t, share_2t)) in
                izip!(shares_deg_t, shares_deg_2t).enumerate()
            {
                shares_by_recipient[recipient_id].push(GfDoubleShamirShare::new(share_t, share_2t));
            }
        }

        for (recipient_id, double_shares) in shares_by_recipient.into_iter().enumerate() {
            let payload = if batch_size == 1 {
                GfDouShaPayload::Share(ser(&double_shares[0])?)
            } else {
                GfDouShaPayload::Shares(ser(&double_shares)?)
            };

            let generic_message =
                WrappedMessage::GfDousha(GfDouShaMessage::new(self.id, session_id, payload));
            let bytes_generic_msg = bincode::serialize(&generic_message)?;

            info!(
                "sending gf double shares from {:?} to {:?}",
                self.id, recipient_id
            );
            network.send(recipient_id, &bytes_generic_msg).await?;
        }

        let storage_access = match self.get_or_create_store(session_id, self.id).await {
            Some(s) => s,
            None => return Ok(()),
        };
        let pending = {
            let mut storage = storage_access.lock().await;
            storage.batch_size = batch_size;
            storage.state = ProtocolState::Initialized;
            std::mem::take(&mut storage.pending_messages)
        };

        for msg in pending {
            let sender_id = msg.sender_id;
            if let Err(e) = self.receive_double_shares_handler(msg).await {
                warn!(
                    session_id = session_id.as_u128(),
                    "dropping invalid pre-init gf double share from party {sender_id}: {e:?}"
                );
            }
        }
        Ok(())
    }

    pub async fn receive_double_shares_handler(
        &mut self,
        recv_message: GfDouShaMessage,
    ) -> Result<(), GfDouShaError> {
        let binding = match self
            .get_or_create_store(recv_message.session_id, recv_message.sender_id)
            .await
        {
            Some(s) => s,
            None => return Ok(()),
        };

        {
            let mut dousha_storage = binding.lock().await;
            if dousha_storage.state == ProtocolState::NotInitialized {
                if dousha_storage.pending_messages.len() >= self.n_parties
                    || dousha_storage
                        .pending_messages
                        .iter()
                        .any(|m| m.sender_id == recv_message.sender_id)
                {
                    warn!(
                        session_id = recv_message.session_id.as_u128(),
                        "pending gf double-share queue full or already holds a message from party {}; dropping",
                        recv_message.sender_id
                    );
                    return Ok(());
                }
                dousha_storage.pending_messages.push(recv_message);
                return Ok(());
            }
        }

        let double_shares: Vec<GfDoubleShamirShare<K>> = match recv_message.payload {
            GfDouShaPayload::Share(payload) => vec![deser_bounded(&payload)?],
            GfDouShaPayload::Shares(payload) => deser_bounded(&payload)?,
        };
        for double_share in &double_shares {
            if double_share.degree_t.id != self.id || double_share.degree_2t.id != self.id {
                return Err(ShareError::IdMismatch.into());
            }
            if double_share.degree_t.degree != self.threshold {
                return Err(ShareError::DegreeMismatch.into());
            }
            if double_share.degree_2t.degree != 2 * self.threshold {
                return Err(ShareError::DegreeMismatch.into());
            }
        }

        let mut dousha_storage = binding.lock().await;
        if dousha_storage.batch_size != double_shares.len() {
            return Err(GfDouShaError::ShareError(ShareError::DegreeMismatch));
        }

        if dousha_storage.state == ProtocolState::Finished {
            return Ok(());
        }
        if dousha_storage.share.contains_key(&recv_message.sender_id) {
            warn!(
                session_id = recv_message.session_id.as_u128(),
                "Duplicate gf double share received from party {:?}, ignoring.",
                recv_message.sender_id
            );
            return Ok(());
        }

        if recv_message.sender_id >= self.n_parties {
            return Err(GfDouShaError::InvalidPartyId);
        }

        dousha_storage
            .share
            .insert(recv_message.sender_id, double_shares);
        info!(
            session_id = recv_message.session_id.as_u128(),
            "party {:?} received gf double shares from {:?}", self.id, recv_message.sender_id,
        );

        dousha_storage.reception_tracker[recv_message.sender_id] = true;

        if dousha_storage
            .reception_tracker
            .iter()
            .all(|&received| received)
        {
            let mut output =
                Vec::with_capacity(dousha_storage.batch_size * dousha_storage.share.len());
            for batch_index in 0..dousha_storage.batch_size {
                for shares in dousha_storage.share.values() {
                    output.push(shares[batch_index].clone());
                }
            }
            dousha_storage.protocol_output = output.clone();
            dousha_storage.state = ProtocolState::Finished;

            let taken_output_sender = dousha_storage.output_sender.take().unwrap();
            taken_output_sender
                .send(output)
                .map_err(|_| GfDouShaError::SendError(recv_message.session_id))?;
        }

        Ok(())
    }
}
