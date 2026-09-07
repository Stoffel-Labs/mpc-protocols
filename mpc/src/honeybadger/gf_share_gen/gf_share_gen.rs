//! GF(2^k) equivalent of RanSha (`honeybadger::share_gen`), a direct structural port]

use ark_std::rand::Rng;
use bincode::Options;
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;
use std::time::Instant;
use stoffelnet::network_utils::{Network, PartyId};
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};
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
        ProtocolSessionId, RBC,
    },
    honeybadger::{
        gf_share_gen::{
            GfRanShaError, GfRanShaMessage, GfRanShaMessageType, GfRanShaPayload, GfRanShaState,
            GfRanShaStore,
        },
        ProtocolType, SessionId, WrappedMessage, MAX_MESSAGE_SIZE,
    },
};

/// Serializes `value` with plain `bincode` defaults (matches the encoding `bincode::serialize`
/// uses crate-wide, so the bytes are readable back via [`deser_bounded`]).
fn ser<T: Serialize>(value: &T) -> Result<Vec<u8>, GfRanShaError> {
    Ok(bincode::serialize(value)?)
}

/// Deserializes `bytes` bounded by their own length, rather than trusting any length prefix
/// embedded in the data — the `bincode` equivalent of `common::utils::deser_bounded_vec`'s
/// guarantee, using `bincode`'s native `with_limit` instead of a hand-rolled prefix check (which
/// only existed because `deser_bounded_vec` is `ark_serialize`-specific and doesn't apply here).
///
/// `with_fixint_encoding` is required, not optional: the top-level `bincode::serialize` function
/// used by [`ser`] encodes integers (including this `Vec`'s length prefix) in fixint format,
/// while `bincode::DefaultOptions` defaults to varint — the two are not wire-compatible, and
/// without this the length prefix is misread, surfacing as spurious "bytes remaining" errors.
fn deser_bounded<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, GfRanShaError> {
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(bytes.len() as u64)
        .deserialize(bytes)?)
}

#[derive(Clone, Debug)]
pub struct GfRanShaNode<K: BinaryField, R: RBC> {
    pub id: usize,
    pub n_parties: usize,
    pub threshold: usize,
    pub store: Arc<Mutex<SessionStore<SessionId, (usize, Instant, Arc<Mutex<GfRanShaStore<K>>>)>>>,
    pub rbc: R,
    pub rbc_output: Arc<Mutex<tokio::sync::mpsc::Receiver<SessionId>>>,
}

const MAX_GF_SHARE_GEN_SESSIONS: usize = 1024;

#[cfg(test)]
pub const MAX_GF_SHARE_GEN_SESSIONS_FOR_TESTS: usize = MAX_GF_SHARE_GEN_SESSIONS;

impl<K, R> GfRanShaNode<K, R>
where
    K: BinaryField,
    R: RBC<Id = SessionId>,
{
    pub fn new(
        id: PartyId,
        n_parties: usize,
        threshold: usize,
        k: usize,
    ) -> Result<Self, GfRanShaError> {
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

    pub async fn drain_rbc_output(&mut self) -> Result<(), GfRanShaError> {
        loop {
            let id = {
                let mut rx = self.rbc_output.lock().await;
                match rx.try_recv() {
                    Ok(id) => id,
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        return Err(GfRanShaError::Abort);
                    }
                }
            };

            let output = self.rbc.get_store(id).await?;
            let mut msg: GfRanShaMessage = bincode::DefaultOptions::new()
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

    pub async fn get_or_create_store(
        &mut self,
        session_id: SessionId,
        initiator_id: usize,
    ) -> Option<Arc<Mutex<GfRanShaStore<K>>>> {
        match self.store.lock().await.get_or_admit(
            session_id,
            initiator_id,
            MAX_GF_SHARE_GEN_SESSIONS,
            MAX_GF_SHARE_GEN_SESSIONS / self.n_parties,
            || Arc::new(Mutex::new(GfRanShaStore::empty(self.n_parties))),
        ) {
            Admission::Got(arc) => Some(arc),
            Admission::Retired => None,
            Admission::Rejected => {
                warn!("GfRanSha session limit reached");
                None
            }
        }
    }

    pub async fn clear_store(&self, session_id: SessionId) -> bool {
        let caller = session_id
            .calling_protocol()
            .unwrap_or(ProtocolType::GfRansha);
        // Only parties with id < 2t broadcast the reconstruction-verification message
        // (see the `self.id < 2 * self.threshold` guard in reconstruction_handler).
        for party_id in 0..(2 * self.threshold) {
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

    pub async fn wait_for_result(
        &self,
        session_id: SessionId,
        duration: Duration,
    ) -> Result<Vec<GfShare<K>>, GfRanShaError> {
        let output_receiver = {
            let storage = self.store.lock().await;
            let storage_bind = match storage.get(&session_id) {
                Some((_, _, arc)) => arc,
                None => return Err(GfRanShaError::NoSuchSessionId(session_id)),
            };
            let mut storage = storage_bind.lock().await;

            storage
                .output_receiver
                .take()
                .ok_or(GfRanShaError::ResultAlreadyReceived(session_id))?
        };

        match timeout(duration, output_receiver).await {
            Err(_) => Err(GfRanShaError::Timeout(session_id)),
            Ok(Err(_)) => Err(GfRanShaError::ReceiveError(session_id)),
            Ok(Ok(shares)) => Ok(shares),
        }
    }

    async fn try_finalize(&mut self, session_id: SessionId) -> Result<bool, GfRanShaError> {
        let output = {
            let store_bind = match self.get_or_create_store(session_id, self.id).await {
                Some(s) => s,
                None => return Ok(false),
            };
            let mut store = store_bind.lock().await;

            if store.state == GfRanShaState::Finished {
                return Ok(true);
            }

            if store.received_ok_msg.len() < 2 * self.threshold {
                return Ok(false);
            }
            if store.computed_r_shares.len() < store.batch_size * self.n_parties {
                return Ok(false);
            }

            let mut output =
                Vec::with_capacity(store.batch_size * (self.n_parties - 2 * self.threshold));
            for shares in store.computed_r_shares.chunks_exact(self.n_parties) {
                output.extend_from_slice(&shares[2 * self.threshold..]);
            }
            store.state = GfRanShaState::Finished;
            store.protocol_output = output.clone();

            let sender = store.output_sender.take().unwrap();
            (sender, output)
        };

        let (sender, output) = output;
        sender
            .send(output)
            .map_err(|_| GfRanShaError::SendError(session_id))?;
        Ok(true)
    }

    pub async fn init<N, G>(
        &mut self,
        session_id: SessionId,
        rng: &mut G,
        network: Arc<N>,
    ) -> Result<(), GfRanShaError>
    where
        N: Network + Send + Sync,
        G: Rng,
    {
        self.init_batch(session_id, 1, rng, network).await
    }

    pub async fn init_batch<N, G>(
        &mut self,
        session_id: SessionId,
        batch_size: usize,
        rng: &mut G,
        network: Arc<N>,
    ) -> Result<(), GfRanShaError>
    where
        N: Network + Send + Sync,
        G: Rng,
    {
        info!("Receiving init for gf share from {0:?}", self.id);

        assert_eq!(session_id.sub_id(), 0);
        let batch_size = batch_size.max(1);

        let mut shares_by_recipient = vec![Vec::with_capacity(batch_size); self.n_parties];
        for _ in 0..batch_size {
            let secret = K::random(rng);
            let shares_deg_t =
                GfShare::compute_shares(secret, self.n_parties, self.threshold, rng)?;
            for (recipient_id, share_t) in shares_deg_t.into_iter().enumerate() {
                shares_by_recipient[recipient_id].push(share_t);
            }
        }

        for (recipient_id, shares_t) in shares_by_recipient.into_iter().enumerate() {
            let payload = if batch_size == 1 {
                GfRanShaPayload::Share(ser(&shares_t[0])?)
            } else {
                GfRanShaPayload::SharesBatch(ser(&shares_t)?)
            };

            let generic_message = WrappedMessage::GfRansha(GfRanShaMessage::new(
                self.id,
                GfRanShaMessageType::ShareMessage,
                session_id,
                payload,
            ));
            let bytes_generic_msg = bincode::serialize(&generic_message)?;

            info!("sending gf shares from {:?} to {:?}", self.id, recipient_id);
            network.send(recipient_id, &bytes_generic_msg).await?;
        }

        let storage_access = match self.get_or_create_store(session_id, self.id).await {
            Some(s) => s,
            None => return Ok(()),
        };
        let pending = {
            let mut storage = storage_access.lock().await;
            storage.batch_size = batch_size;
            storage.state = GfRanShaState::Initialized;
            std::mem::take(&mut storage.pending_share_messages)
        };

        // Replay messages that arrived before local initialization. A parked message that fails
        // validation on replay is the sender's fault, not ours — log and drop it. A blanket `?`
        // here would let a single Byzantine peer abort our own initialization by parking one
        // oversized batch before we started.
        for msg in pending {
            let sender_id = msg.sender_id;
            if let Err(e) = self.receive_shares_handler(msg, Arc::clone(&network)).await {
                warn!(
                    session_id = session_id.as_u128(),
                    "dropping invalid pre-init gf share from party {sender_id}: {e:?}"
                );
            }
        }
        Ok(())
    }

    pub async fn receive_shares_handler<N>(
        &mut self,
        msg: GfRanShaMessage,
        network: Arc<N>,
    ) -> Result<(), GfRanShaError>
    where
        N: Network + Send + Sync,
    {
        if msg.session_id.sub_id() != 0 {
            return Err(GfRanShaError::SessionIdError(msg.session_id));
        }

        if msg.sender_id >= self.n_parties {
            return Err(GfRanShaError::InvalidPartyId);
        }

        // Look up store BEFORE deserialization so we can queue the raw message when local
        // initialization hasn't run yet.
        let binding = match self
            .get_or_create_store(msg.session_id, msg.sender_id)
            .await
        {
            Some(s) => s,
            None => return Ok(()),
        };
        {
            let mut storage = binding.lock().await;
            if storage.state == GfRanShaState::NotInitialized {
                // batch_size not yet locally known; park and return. init_batch will drain and
                // replay these once the trusted value is set.
                //
                // Bound the queue at one parked message per peer. The length check is not
                // redundant with the per-sender check: `sender_id` is only validated against
                // `n_parties` further down, after this point, so a peer forging distinct ids
                // could otherwise grow this vector without limit before ever being rejected.
                if storage.pending_share_messages.len() >= self.n_parties
                    || storage
                        .pending_share_messages
                        .iter()
                        .any(|m| m.sender_id == msg.sender_id)
                {
                    warn!(
                        session_id = msg.session_id.as_u128(),
                        "pending GfRanSha share queue full or already holds a message from party {}; dropping",
                        msg.sender_id
                    );
                    return Ok(());
                }
                storage.pending_share_messages.push(msg);
                return Ok(());
            }
        }

        // msg.payload not yet consumed — proceed with deserialization.
        let shares: Vec<GfShare<K>> = match msg.payload {
            GfRanShaPayload::Share(payload) => vec![deser_bounded(&payload)?],
            GfRanShaPayload::SharesBatch(payload) => deser_bounded(&payload)?,
            _ => return Err(GfRanShaError::Abort),
        };
        for share in &shares {
            if share.id != self.id {
                return Err(ShareError::IdMismatch.into());
            }
            if share.degree != self.threshold {
                return Err(ShareError::DegreeMismatch.into());
            }
        }
        let mut storage = binding.lock().await;
        // Always validate against the locally-set batch_size; never adopt peer-controlled length.
        if storage.batch_size != shares.len() {
            return Err(GfRanShaError::Abort);
        }

        if storage.state == GfRanShaState::FinishedInitialSharing
            || storage.state == GfRanShaState::Finished
        {
            return Ok(());
        }

        if storage.initial_shares.contains_key(&msg.sender_id) {
            warn!(
                session_id = msg.session_id.as_u128(),
                "Duplicate gf share received from party {:?}, ignoring.", msg.sender_id
            );
            return Ok(());
        }

        storage.initial_shares.insert(msg.sender_id, shares);
        info!(
            session_id = msg.session_id.as_u128(),
            "party {:?} received gf shares from {:?}", self.id, msg.sender_id,
        );

        storage.reception_tracker[msg.sender_id] = true;

        if storage.reception_tracker.iter().all(|&received| received) {
            storage.state = GfRanShaState::FinishedInitialSharing;
            let batch_size = storage.batch_size;
            let mut shares_deg_t: Vec<(usize, Vec<GfShare<K>>)> = storage
                .initial_shares
                .iter()
                .map(|(sid, s)| (*sid, s.clone()))
                .collect();
            drop(storage);
            shares_deg_t.sort_by_key(|(sid, _)| *sid);

            let mut shares_by_batch = vec![Vec::with_capacity(self.n_parties); batch_size];
            for (_, sender_shares) in shares_deg_t {
                for (batch_index, share) in sender_shares.into_iter().enumerate() {
                    shares_by_batch[batch_index].push(share);
                }
            }
            self.init_ransha_batch(shares_by_batch, msg.session_id, network)
                .await?
        }

        Ok(())
    }

    pub async fn init_ransha<N>(
        &mut self,
        shares_deg_t: Vec<GfShare<K>>,
        session_id: SessionId,
        network: Arc<N>,
    ) -> Result<(), GfRanShaError>
    where
        N: Network + Send + Sync,
    {
        self.init_ransha_batch(vec![shares_deg_t], session_id, network)
            .await
    }

    async fn init_ransha_batch<N>(
        &mut self,
        shares_by_batch: Vec<Vec<GfShare<K>>>,
        session_id: SessionId,
        network: Arc<N>,
    ) -> Result<(), GfRanShaError>
    where
        N: Network + Send + Sync,
    {
        info!(
            "party {:?} received gf shares for Random sharing generation",
            self.id
        );

        let vandermonde_matrix = make_vandermonde::<K>(self.n_parties, self.n_parties - 1)?;
        let mut r_deg_t = Vec::with_capacity(shares_by_batch.len() * self.n_parties);
        for shares_deg_t in shares_by_batch {
            r_deg_t.extend(apply_vandermonde(&vandermonde_matrix, &shares_deg_t)?);
        }

        let bind_store = match self.get_or_create_store(session_id, self.id).await {
            Some(s) => s,
            None => return Ok(()),
        };
        let pending = {
            let mut store = bind_store.lock().await;
            store.batch_size = r_deg_t.len() / self.n_parties;
            store.computed_r_shares = r_deg_t.clone();
            std::mem::take(&mut store.pending_recon_messages)
        };
        if self.try_finalize(session_id).await? {
            return Ok(());
        }

        for i in 0..2 * self.threshold {
            let shares: Vec<_> = r_deg_t
                .chunks_exact(self.n_parties)
                .map(|batch_shares| batch_shares[i].clone())
                .collect();
            let payload = if shares.len() == 1 {
                GfRanShaPayload::Reconstruct(ser(&shares[0])?)
            } else {
                GfRanShaPayload::ReconstructSharesBatch(ser(&shares)?)
            };
            let message = WrappedMessage::GfRansha(GfRanShaMessage::new(
                self.id,
                GfRanShaMessageType::ReconstructMessage,
                session_id,
                payload,
            ));
            let bytes = bincode::serialize(&message)?;
            network.send(i, &bytes).await?;
        }

        // Replay reconstruction messages that arrived before init_ransha_batch completed. A
        // parked message that fails validation on replay is the sender's fault, not ours — log
        // and drop it rather than aborting our own initialization.
        for msg in pending {
            let sender_id = msg.sender_id;
            if let Err(e) = self.reconstruction_handler(msg, Arc::clone(&network)).await {
                warn!(
                    session_id = session_id.as_u128(),
                    "dropping invalid pre-init gf reconstruction message from party {sender_id}: {e:?}"
                );
            }
        }
        Ok(())
    }

    pub async fn reconstruction_handler<N>(
        &mut self,
        msg: GfRanShaMessage,
        network: Arc<N>,
    ) -> Result<(), GfRanShaError>
    where
        N: Network + Send + Sync,
    {
        info!("party {:?} at gf reconstruction handler", self.id);
        if msg.session_id.sub_id() != 0 {
            return Err(GfRanShaError::SessionIdError(msg.session_id));
        }

        let sender_id = msg.sender_id;
        let session_id = msg.session_id;
        // Look up store BEFORE deserialization to queue the raw message when init_ransha_batch
        // hasn't run yet (computed_r_shares not yet set).
        let binding = match self.get_or_create_store(session_id, sender_id).await {
            Some(s) => s,
            None => return Ok(()),
        };
        {
            let mut store = binding.lock().await;
            if store.computed_r_shares.is_empty() {
                // batch_size not yet locally known; park and return. init_ransha_batch will
                // drain and replay these once the trusted value is set.
                //
                // Bound the queue at one parked message per peer. The length check is not
                // redundant with the per-sender check: `sender_id` is only validated against
                // `n_parties` further down, after this point, so a peer forging distinct ids
                // could otherwise grow this vector without limit before ever being rejected.
                if store.pending_recon_messages.len() >= self.n_parties
                    || store
                        .pending_recon_messages
                        .iter()
                        .any(|m| m.sender_id == msg.sender_id)
                {
                    warn!(
                        session_id = msg.session_id.as_u128(),
                        "pending GfRanSha reconstruction queue full or already holds a message from party {}; dropping",
                        msg.sender_id
                    );
                    return Ok(());
                }
                store.pending_recon_messages.push(msg);
                return Ok(());
            }
        }

        // msg.payload not yet consumed — proceed with deserialization.
        let shares: Vec<GfShare<K>> = match msg.payload {
            GfRanShaPayload::Reconstruct(payload) => vec![deser_bounded(&payload)?],
            GfRanShaPayload::ReconstructSharesBatch(payload) => deser_bounded(&payload)?,
            _ => return Err(GfRanShaError::Abort),
        };
        for share in &shares {
            if share.degree != self.threshold {
                return Err(GfRanShaError::ShareError(ShareError::DegreeMismatch));
            }
            if share.id != sender_id {
                return Err(GfRanShaError::ShareError(ShareError::IdMismatch));
            }
        }
        let mut store = binding.lock().await;
        if store.state == GfRanShaState::Finished {
            return Ok(());
        }
        // Always validate against the locally-set batch_size; never adopt peer-controlled length.
        if store.batch_size != shares.len() {
            return Err(GfRanShaError::Abort);
        }
        store.state = GfRanShaState::Reconstruction;
        store.received_r_shares.insert(sender_id, shares);

        if self.id < 2 * self.threshold && store.received_r_shares.len() >= self.n_parties {
            let batch_size = store.batch_size;
            let mut shares_by_batch =
                vec![Vec::with_capacity(store.received_r_shares.len()); batch_size];
            for sender_shares in store.received_r_shares.values() {
                for (batch_index, share) in sender_shares.iter().cloned().enumerate() {
                    shares_by_batch[batch_index].push(share);
                }
            }

            drop(store);

            let mut ok = true;
            for shares in shares_by_batch {
                match GfShare::recover_secret(&shares, self.n_parties, self.threshold) {
                    Ok((coeffs, _)) => {
                        let poly = Poly::from_coeffs(coeffs);
                        if poly.degree() != self.threshold {
                            ok = false;
                            break;
                        }
                    }
                    Err(_) => {
                        ok = false;
                        break;
                    }
                }
            }

            let result = GfRanShaMessage::new(
                self.id,
                GfRanShaMessageType::OutputMessage,
                session_id,
                GfRanShaPayload::Output(ok),
            );
            let bytes = bincode::serialize(&result)?;
            // Derive the caller from the parent session so the reconstruction RBC routes to the
            // correct GfRanSha instance (mirrors RanSha's own sub-session derivation).
            let caller = session_id
                .calling_protocol()
                .unwrap_or(ProtocolType::GfRansha);
            let sessionid = SessionId::new(
                caller,
                SessionId::pack_slot(session_id.exec_id(), self.id as u8, session_id.round_id()),
                session_id.instance_id(),
            );
            self.rbc
                .init(bytes, sessionid, Arc::clone(&network))
                .await?;
        }

        Ok(())
    }

    pub async fn output_handler(&mut self, msg: GfRanShaMessage) -> Result<(), GfRanShaError> {
        info!("party {:?} received gf shares for Output", self.id);
        let ok = match msg.payload {
            GfRanShaPayload::Output(o) => o,
            _ => return Err(GfRanShaError::Abort),
        };
        if !ok {
            return Err(GfRanShaError::Abort);
        }

        if msg.session_id.sub_id() != 0 {
            return Err(GfRanShaError::SessionIdError(msg.session_id));
        }
        if msg.sender_id >= 2 * self.threshold {
            warn!(
                "Rejecting gf output from non-verifier party {}",
                msg.sender_id
            );
            return Err(GfRanShaError::InvalidPartyId);
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
        self.try_finalize(msg.session_id).await?;
        Ok(())
    }

    pub async fn process<N>(
        &mut self,
        msg: GfRanShaMessage,
        network: Arc<N>,
    ) -> Result<(), GfRanShaError>
    where
        N: Network + Send + Sync,
    {
        match msg.msg_type {
            GfRanShaMessageType::ShareMessage => {
                self.receive_shares_handler(msg, network).await?;
                Ok(())
            }
            GfRanShaMessageType::OutputMessage => Ok(()),
            GfRanShaMessageType::ReconstructMessage => {
                self.reconstruction_handler(msg, network).await?;
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::gf2k::field::Gf256;
    use crate::common::rbc::rbc::Avid;
    use crate::honeybadger::SessionId;
    use stoffelmpc_network::fake_network::{FakeInnerNetwork, FakeNetwork, FakeNetworkConfig};

    fn ser_share(share: &GfShare<Gf256>) -> Vec<u8> {
        bincode::serialize(share).unwrap()
    }

    #[tokio::test]
    async fn test_gf_sharegen_storage_limit_in_receive_shares_handler() {
        let mut node = GfRanShaNode::<Gf256, Avid<SessionId>>::new(0, 5, 1, 2).unwrap();
        let inner = FakeInnerNetwork::new(5, None, FakeNetworkConfig::new(10)).0;
        let net = Arc::new(FakeNetwork::new(0, inner));

        let per_peer_limit = MAX_GF_SHARE_GEN_SESSIONS / 5;
        for exec in 0..per_peer_limit as u64 {
            let sid = SessionId::new(ProtocolType::GfRansha, SessionId::pack_slot(exec, 0, 0), 0);
            let share = GfShare::new(Gf256(1), 0, 1);
            let msg = GfRanShaMessage::new(
                0,
                GfRanShaMessageType::ShareMessage,
                sid,
                GfRanShaPayload::Share(ser_share(&share)),
            );
            let _ = node.receive_shares_handler(msg, net.clone()).await;
        }
        assert_eq!(node.store_len().await, per_peer_limit);

        let over_sid = SessionId::new(
            ProtocolType::GfRansha,
            SessionId::pack_slot(per_peer_limit as u64, 0, 0),
            0,
        );
        let share = GfShare::new(Gf256(1), 0, 1);
        let msg = GfRanShaMessage::new(
            0,
            GfRanShaMessageType::ShareMessage,
            over_sid,
            GfRanShaPayload::Share(ser_share(&share)),
        );

        let result = node.receive_shares_handler(msg, net).await;
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
    async fn test_gf_sharegen_storage_limit_in_reconstruction_handler() {
        let mut node = GfRanShaNode::<Gf256, Avid<SessionId>>::new(0, 5, 1, 2).unwrap();
        let inner = FakeInnerNetwork::new(5, None, FakeNetworkConfig::new(10)).0;
        let net = Arc::new(FakeNetwork::new(0, inner));

        let per_peer_limit = MAX_GF_SHARE_GEN_SESSIONS / 5;
        for exec in 0..per_peer_limit as u64 {
            let sid = SessionId::new(ProtocolType::GfRansha, SessionId::pack_slot(exec, 0, 0), 0);
            let share = GfShare::new(Gf256(1), 0, 1);
            let msg = GfRanShaMessage::new(
                0,
                GfRanShaMessageType::ReconstructMessage,
                sid,
                GfRanShaPayload::Reconstruct(ser_share(&share)),
            );
            let _ = node.reconstruction_handler(msg, net.clone()).await;
        }
        assert_eq!(node.store_len().await, per_peer_limit);

        let over_sid = SessionId::new(
            ProtocolType::GfRansha,
            SessionId::pack_slot(per_peer_limit as u64, 0, 0),
            0,
        );
        let share = GfShare::new(Gf256(1), 0, 1);
        let msg = GfRanShaMessage::new(
            0,
            GfRanShaMessageType::ReconstructMessage,
            over_sid,
            GfRanShaPayload::Reconstruct(ser_share(&share)),
        );

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
    async fn test_gf_sharegen_storage_limit_in_output_handler() {
        let mut node = GfRanShaNode::<Gf256, Avid<SessionId>>::new(0, 5, 1, 2).unwrap();

        let per_peer_limit = MAX_GF_SHARE_GEN_SESSIONS / 5;
        for exec in 0..per_peer_limit as u64 {
            let sid = SessionId::new(ProtocolType::GfRansha, SessionId::pack_slot(exec, 0, 0), 0);
            let msg = GfRanShaMessage::new(
                0,
                GfRanShaMessageType::OutputMessage,
                sid,
                GfRanShaPayload::Output(true),
            );
            let _ = node.output_handler(msg).await;
        }
        assert_eq!(node.store_len().await, per_peer_limit);

        let over_sid = SessionId::new(
            ProtocolType::GfRansha,
            SessionId::pack_slot(per_peer_limit as u64, 0, 0),
            0,
        );
        let msg = GfRanShaMessage::new(
            0,
            GfRanShaMessageType::OutputMessage,
            over_sid,
            GfRanShaPayload::Output(true),
        );

        let result = node.output_handler(msg).await;
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

    /// The global cap, distinct from the per-peer cap above — `n_parties = 1` makes the
    /// per-peer cap equal to the global cap (`MAX / 1`), so filling it exercises the *global*
    /// admission path specifically. The F-domain suite doesn't have this test.
    #[tokio::test]
    async fn test_gf_sharegen_global_session_cap() {
        let n_parties = 1;
        let mut node = GfRanShaNode::<Gf256, Avid<SessionId>>::new(0, n_parties, 0, 1).unwrap();
        let inner = FakeInnerNetwork::new(n_parties, None, FakeNetworkConfig::new(10)).0;
        let net = Arc::new(FakeNetwork::new(0, inner));

        for exec in 0..MAX_GF_SHARE_GEN_SESSIONS as u64 {
            let sid = SessionId::new(ProtocolType::GfRansha, SessionId::pack_slot(exec, 0, 0), 0);
            let share = GfShare::new(Gf256(1), 0, 0);
            let msg = GfRanShaMessage::new(
                0,
                GfRanShaMessageType::ShareMessage,
                sid,
                GfRanShaPayload::Share(ser_share(&share)),
            );
            let _ = node.receive_shares_handler(msg, net.clone()).await;
        }
        assert_eq!(node.store_len().await, MAX_GF_SHARE_GEN_SESSIONS);

        let over_sid = SessionId::new(
            ProtocolType::GfRansha,
            SessionId::pack_slot(MAX_GF_SHARE_GEN_SESSIONS as u64, 0, 0),
            0,
        );
        let share = GfShare::new(Gf256(1), 0, 0);
        let msg = GfRanShaMessage::new(
            0,
            GfRanShaMessageType::ShareMessage,
            over_sid,
            GfRanShaPayload::Share(ser_share(&share)),
        );
        let result = node.receive_shares_handler(msg, net).await;
        assert!(result.is_ok(), "handler should silently drop, not error");
        assert_eq!(
            node.store_len().await,
            MAX_GF_SHARE_GEN_SESSIONS,
            "store must not grow past the global cap"
        );
    }

    #[tokio::test]
    async fn test_gf_sharegen_receive_shares_handler_invalid_sub_id() {
        let mut node = GfRanShaNode::<Gf256, Avid<SessionId>>::new(0, 5, 1, 2).unwrap();
        let inner = FakeInnerNetwork::new(5, None, FakeNetworkConfig::new(10)).0;
        let net = Arc::new(FakeNetwork::new(0, inner));

        let session_id = SessionId::new(ProtocolType::GfRansha, SessionId::pack_slot(0, 1, 0), 0);
        let share = GfShare::new(Gf256(1), 0, 1);
        let msg = GfRanShaMessage::new(
            0,
            GfRanShaMessageType::ShareMessage,
            session_id,
            GfRanShaPayload::Share(ser_share(&share)),
        );

        let result = node.receive_shares_handler(msg, net).await;
        match result {
            Err(GfRanShaError::SessionIdError(sid)) => assert_eq!(sid, session_id),
            _ => panic!("Expected SessionIdError for invalid sub_id"),
        }
    }

    #[tokio::test]
    async fn test_gf_sharegen_reconstruction_handler_invalid_sub_id() {
        let mut node = GfRanShaNode::<Gf256, Avid<SessionId>>::new(0, 5, 1, 2).unwrap();
        let inner = FakeInnerNetwork::new(5, None, FakeNetworkConfig::new(10)).0;
        let net = Arc::new(FakeNetwork::new(0, inner));

        let session_id = SessionId::new(ProtocolType::GfRansha, SessionId::pack_slot(0, 1, 0), 0);
        let share = GfShare::new(Gf256(1), 0, 1);
        let msg = GfRanShaMessage::new(
            0,
            GfRanShaMessageType::ReconstructMessage,
            session_id,
            GfRanShaPayload::Reconstruct(ser_share(&share)),
        );

        let result = node.reconstruction_handler(msg, net).await;
        match result {
            Err(GfRanShaError::SessionIdError(sid)) => assert_eq!(sid, session_id),
            _ => panic!("Expected SessionIdError for invalid sub_id"),
        }
    }

    #[tokio::test]
    async fn test_gf_sharegen_output_handler_invalid_sub_id() {
        let mut node = GfRanShaNode::<Gf256, Avid<SessionId>>::new(0, 5, 1, 2).unwrap();

        let session_id = SessionId::new(ProtocolType::GfRansha, SessionId::pack_slot(0, 1, 0), 0);
        let msg = GfRanShaMessage::new(
            0,
            GfRanShaMessageType::OutputMessage,
            session_id,
            GfRanShaPayload::Output(true),
        );

        let result = node.output_handler(msg).await;
        match result {
            Err(GfRanShaError::SessionIdError(sid)) => assert_eq!(sid, session_id),
            _ => panic!("Expected SessionIdError for invalid sub_id"),
        }
    }

    /// Regression coverage matching `share_gen.rs`'s documented fix: a Byzantine peer sending an
    /// oversized `SharesBatch` before this node's own `init_batch` runs must not let the
    /// attacker's message length leak into aggregation and panic once every party has reported.
    #[tokio::test]
    async fn test_gf_sharegen_early_oversized_batch_does_not_panic() {
        let mut node = GfRanShaNode::<Gf256, Avid<SessionId>>::new(0, 5, 1, 2).unwrap();
        let (inner, _inboxes, _) = FakeInnerNetwork::new(5, None, FakeNetworkConfig::new(10));
        let net = Arc::new(FakeNetwork::new(0, inner));
        let session_id = SessionId::new(ProtocolType::GfRansha, SessionId::pack_slot(0, 0, 0), 0);

        let oversized: Vec<GfShare<Gf256>> =
            (0..10).map(|_| GfShare::new(Gf256(1), 0, 1)).collect();
        let attacker_payload = bincode::serialize(&oversized).unwrap();
        let attacker_msg = GfRanShaMessage::new(
            4,
            GfRanShaMessageType::ShareMessage,
            session_id,
            GfRanShaPayload::SharesBatch(attacker_payload),
        );
        node.receive_shares_handler(attacker_msg, net.clone())
            .await
            .unwrap();

        let mut rng = ark_std::test_rng();
        node.init_batch(session_id, 2, &mut rng, net.clone())
            .await
            .unwrap();

        for sender in 0..5usize {
            let shares: Vec<GfShare<Gf256>> =
                (0..2).map(|_| GfShare::new(Gf256(1), 0, 1)).collect();
            let payload = bincode::serialize(&shares).unwrap();
            let msg = GfRanShaMessage::new(
                sender,
                GfRanShaMessageType::ShareMessage,
                session_id,
                GfRanShaPayload::SharesBatch(payload),
            );
            node.receive_shares_handler(msg, net.clone()).await.unwrap();
        }
    }

    /// Coverage gap the F-domain suite doesn't have: a second message from a sender already
    /// holding a parked slot must be dropped by the dedup check, not just rejected once the
    /// length cap is hit.
    #[tokio::test]
    async fn test_gf_sharegen_pending_queue_dedups_by_sender() {
        let mut node = GfRanShaNode::<Gf256, Avid<SessionId>>::new(0, 5, 1, 2).unwrap();
        let inner = FakeInnerNetwork::new(5, None, FakeNetworkConfig::new(10)).0;
        let net = Arc::new(FakeNetwork::new(0, inner));
        let session_id = SessionId::new(ProtocolType::GfRansha, SessionId::pack_slot(0, 0, 0), 0);

        // Node has NOT called init_batch yet, so every share message parks.
        for _ in 0..2 {
            let share = GfShare::new(Gf256(1), 0, 1);
            let msg = GfRanShaMessage::new(
                3, // same sender both times
                GfRanShaMessageType::ShareMessage,
                session_id,
                GfRanShaPayload::Share(ser_share(&share)),
            );
            node.receive_shares_handler(msg, net.clone()).await.unwrap();
        }

        let binding = node.get_or_create_store(session_id, 3).await.unwrap();
        let store = binding.lock().await;
        assert_eq!(
            store.pending_share_messages.len(),
            1,
            "a second message from the same pending sender must be dropped, not queued"
        );
    }

    /// Coverage gap the F-domain suite doesn't have: garbage bytes in a payload must fail
    /// deserialization gracefully (an `Err`, not a panic).
    #[tokio::test]
    async fn test_gf_sharegen_malformed_payload_does_not_panic() {
        let mut node = GfRanShaNode::<Gf256, Avid<SessionId>>::new(0, 5, 1, 2).unwrap();
        // init_batch below actually sends messages — keep the receiver ends alive, or the sends
        // fail with NetworkError::SendError (same caveat as share_gen.rs's own regression test).
        let (inner, _inboxes, _) = FakeInnerNetwork::new(5, None, FakeNetworkConfig::new(10));
        let net = Arc::new(FakeNetwork::new(0, inner));
        let session_id = SessionId::new(ProtocolType::GfRansha, SessionId::pack_slot(0, 0, 0), 0);

        // Move the node past NotInitialized so the malformed payload actually reaches
        // deserialization instead of being parked.
        let mut rng = ark_std::test_rng();
        node.init_batch(session_id, 1, &mut rng, net.clone())
            .await
            .unwrap();

        let garbage = vec![0xFFu8; 3];
        let msg = GfRanShaMessage::new(
            1,
            GfRanShaMessageType::ShareMessage,
            session_id,
            GfRanShaPayload::Share(garbage),
        );
        let result = node.receive_shares_handler(msg, net).await;
        assert!(result.is_err(), "malformed payload must error, not panic");
    }
}
