use ark_ff::FftField;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use bincode::Options;
use std::{collections::HashMap, sync::Arc};
use stoffelnet::network_utils::{Network, PartyId};
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};
use tracing::{info, warn};

use crate::honeybadger::MAX_MESSAGE_SIZE;
use crate::{
    common::{
        share::{apply_vandermonde, make_vandermonde, ShareError},
        utils::deser_bounded_vec,
        ProtocolSessionId, SecretSharingScheme, ShamirShare, RBC,
    },
    honeybadger::{
        robust_interpolate::robust_interpolate::{Robust, RobustShare},
        share_gen::{
            RanShaError, RanShaMessage, RanShaMessageType, RanShaPayload, RanShaState, RanShaStore,
        },
        ProtocolType, SessionId, WrappedMessage,
    },
};

#[derive(Clone, Debug)]
pub struct RanShaNode<F: FftField, R: RBC> {
    pub id: usize,
    pub n_parties: usize,
    pub threshold: usize,
    pub store: Arc<Mutex<HashMap<SessionId, (usize, Arc<Mutex<RanShaStore<F>>>)>>>,
    pub rbc: R,
    pub rbc_output: Arc<Mutex<tokio::sync::mpsc::Receiver<SessionId>>>,
}

impl<F, R> RanShaNode<F, R>
where
    F: FftField,
    R: RBC<Id = SessionId>,
{
    pub fn new(
        id: PartyId,
        n_parties: usize,
        threshold: usize,
        k: usize,
    ) -> Result<Self, RanShaError> {
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
            store: Arc::new(Mutex::new(HashMap::new())),
            rbc,
            rbc_output: Arc::new(Mutex::new(rbc_receiver)),
        })
    }

    pub async fn drain_rbc_output(&mut self) -> Result<(), RanShaError> {
        loop {
            let id = {
                let mut rx = self.rbc_output.lock().await;
                match rx.try_recv() {
                    Ok(id) => id,
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        return Err(RanShaError::Abort);
                    }
                }
            };

            let output = self.rbc.get_store(id).await?;
            let mut msg: RanShaMessage = bincode::DefaultOptions::new()
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
            match self.output_handler(msg).await {
                Ok(()) => {}
                Err(e) => {
                    return Err(e);
                }
            }
        }
        Ok(())
    }
    pub async fn get_or_create_store(
        &mut self,
        session_id: SessionId,
        initiator_id: usize,
    ) -> Result<Arc<Mutex<RanShaStore<F>>>, RanShaError> {
        let mut storage = self.store.lock().await;

        Ok(storage
            .entry(session_id)
            .or_insert((
                initiator_id,
                Arc::new(Mutex::new(RanShaStore::empty(self.n_parties))),
            ))
            .1
            .clone())
    }

    pub async fn clear_store(&self, session_id: SessionId) -> bool {
        let mut store = self.store.lock().await;
        store.remove(&session_id).is_some()
    }

    pub async fn store_len(&self) -> usize {
        self.store.lock().await.len()
    }

    pub async fn wait_for_result(
        &self,
        session_id: SessionId,
        duration: Duration,
    ) -> Result<Vec<RobustShare<F>>, RanShaError> {
        let output_receiver = {
            let storage = self.store.lock().await;
            let storage_bind = match storage.get(&session_id) {
                Some((_, arc)) => arc,
                None => return Err(RanShaError::NoSuchSessionId(session_id)),
            };
            let mut storage = storage_bind.lock().await;

            storage
                .output_receiver
                .take()
                .ok_or(RanShaError::ResultAlreadyReceived(session_id))?
        };

        match timeout(duration, output_receiver).await {
            Err(_) => Err(RanShaError::Timeout(session_id)),
            Ok(Err(_)) => Err(RanShaError::ReceiveError(session_id)),
            Ok(Ok(shares)) => Ok(shares),
        }
    }
    async fn try_finalize(&mut self, session_id: SessionId) -> Result<bool, RanShaError> {
        // phase 1: decide + extract under lock
        let output = {
            let store_bind = self.get_or_create_store(session_id, self.id).await?;
            let mut store = store_bind.lock().await;

            if store.state == RanShaState::Finished {
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
            store.state = RanShaState::Finished;
            store.protocol_output = output.clone();

            let sender = store.output_sender.take().unwrap();
            (sender, output)
        };

        // phase 2: send outside lock (send is sync, but it’s still a good pattern)
        let (sender, output) = output;
        sender
            .send(output)
            .map_err(|_| RanShaError::SendError(session_id))?;
        Ok(true)
    }

    pub async fn init<N, G>(
        &mut self,
        session_id: SessionId,
        rng: &mut G,
        network: Arc<N>,
    ) -> Result<(), RanShaError>
    where
        N: Network,
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
    ) -> Result<(), RanShaError>
    where
        N: Network,
        G: Rng,
    {
        info!("Receiving init for share from {0:?}", self.id);

        assert_eq!(session_id.sub_id(), 0);
        let batch_size = batch_size.max(1);

        let mut shares_by_recipient = vec![Vec::with_capacity(batch_size); self.n_parties];
        for _ in 0..batch_size {
            let secret = F::rand(rng);
            let shares_deg_t =
                RobustShare::compute_shares(secret, self.n_parties, self.threshold, None, rng)?;
            for (recipient_id, share_t) in shares_deg_t.into_iter().enumerate() {
                shares_by_recipient[recipient_id].push(share_t);
            }
        }

        for (recipient_id, shares_t) in shares_by_recipient.into_iter().enumerate() {
            // Create and serialize the payload.
            let payload = if batch_size == 1 {
                let mut payload = Vec::new();
                shares_t[0].serialize_compressed(&mut payload)?;
                RanShaPayload::Share(payload)
            } else {
                let mut payload = Vec::new();
                shares_t.serialize_compressed(&mut payload)?;
                RanShaPayload::SharesBatch(payload)
            };

            // Create and serialize the generic message.
            let generic_message = WrappedMessage::RanSha(RanShaMessage::new(
                self.id,
                RanShaMessageType::ShareMessage,
                session_id,
                payload,
            ));
            let bytes_generic_msg = bincode::serialize(&generic_message)?;

            info!("sending shares from {:?} to {:?}", self.id, recipient_id);
            network.send(recipient_id, &bytes_generic_msg).await?;
        }

        // Update the state of the protocol to Initialized.
        let storage_access = self.get_or_create_store(session_id, self.id).await?;
        let mut storage = storage_access.lock().await;
        storage.batch_size = batch_size;
        storage.state = RanShaState::Initialized;
        Ok(())
    }

    pub async fn receive_shares_handler<N>(
        &mut self,
        msg: RanShaMessage,
        network: Arc<N>,
    ) -> Result<(), RanShaError>
    where
        N: Network,
    {
        if msg.session_id.sub_id() != 0 {
            return Err(RanShaError::SessionIdError(msg.session_id));
        }

        if msg.sender_id >= self.n_parties {
            return Err(RanShaError::InvalidPartyId);
        }

        let shares: Vec<ShamirShare<F, 1, Robust>> = match msg.payload {
            RanShaPayload::Share(payload) => {
                vec![CanonicalDeserialize::deserialize_compressed(
                    payload.as_slice(),
                )?]
            }
            RanShaPayload::SharesBatch(payload) => {
                deser_bounded_vec(&mut payload.as_slice(), payload.len())?
            }
            _ => return Err(RanShaError::Abort),
        };
        for share in &shares {
            if share.id != self.id {
                return Err(ShareError::IdMismatch.into());
            }
            if share.degree != self.threshold {
                return Err(ShareError::DegreeMismatch.into());
            }
        }
        let binding = self
            .get_or_create_store(msg.session_id, msg.sender_id)
            .await?;
        let mut ransha_storage = binding.lock().await;
        if ransha_storage.initial_shares.is_empty() {
            ransha_storage.batch_size = shares.len();
        } else if ransha_storage.batch_size != shares.len() {
            return Err(RanShaError::Abort);
        }

        if ransha_storage.state == RanShaState::FinishedInitialSharing
            || ransha_storage.state == RanShaState::Finished
        {
            return Ok(());
        }

        if ransha_storage.initial_shares.contains_key(&msg.sender_id) {
            warn!(
                session_id = msg.session_id.as_u128(),
                "Duplicate share received from party {:?}, ignoring.", msg.sender_id
            );
            return Ok(());
        }

        ransha_storage.initial_shares.insert(msg.sender_id, shares);
        info!(
            session_id = msg.session_id.as_u128(),
            "party {:?} received shares from {:?}", self.id, msg.sender_id,
        );

        ransha_storage.reception_tracker[msg.sender_id] = true;

        // Check if the protocol has reached an end
        if ransha_storage
            .reception_tracker
            .iter()
            .all(|&received| received)
        {
            ransha_storage.state = RanShaState::FinishedInitialSharing;
            let batch_size = ransha_storage.batch_size;
            let mut shares_deg_t: Vec<(usize, Vec<ShamirShare<F, 1, Robust>>)> = ransha_storage
                .initial_shares
                .iter()
                .map(|(sid, s)| (*sid, s.clone()))
                .collect();
            drop(ransha_storage);
            // sort by sender_id
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
        shares_deg_t: Vec<RobustShare<F>>,
        session_id: SessionId,
        network: Arc<N>,
    ) -> Result<(), RanShaError>
    where
        N: Network,
    {
        self.init_ransha_batch(vec![shares_deg_t], session_id, network)
            .await
    }

    async fn init_ransha_batch<N>(
        &mut self,
        shares_by_batch: Vec<Vec<RobustShare<F>>>,
        session_id: SessionId,
        network: Arc<N>,
    ) -> Result<(), RanShaError>
    where
        N: Network,
    {
        info!(
            "party {:?} received shares for Random sharing generation",
            self.id
        );

        let vandermonde_matrix = make_vandermonde(self.n_parties, self.n_parties - 1)?;
        let mut r_deg_t = Vec::with_capacity(shares_by_batch.len() * self.n_parties);
        for shares_deg_t in shares_by_batch {
            r_deg_t.extend(apply_vandermonde(&vandermonde_matrix, &shares_deg_t)?);
        }

        let bind_store = self.get_or_create_store(session_id, self.id).await?;
        let mut store = bind_store.lock().await;
        store.batch_size = r_deg_t.len() / self.n_parties;
        store.computed_r_shares = r_deg_t.clone();
        drop(store);
        if self.try_finalize(session_id).await? {
            return Ok(());
        }

        for i in 0..2 * self.threshold {
            let shares: Vec<_> = r_deg_t
                .chunks_exact(self.n_parties)
                .map(|batch_shares| batch_shares[i].clone())
                .collect();
            let payload = if shares.len() == 1 {
                let mut bytes_rec_message = Vec::new();
                shares[0].serialize_compressed(&mut bytes_rec_message)?;
                RanShaPayload::Reconstruct(bytes_rec_message)
            } else {
                let mut bytes_rec_messages = Vec::new();
                shares.serialize_compressed(&mut bytes_rec_messages)?;
                RanShaPayload::ReconstructSharesBatch(bytes_rec_messages)
            };
            let message = WrappedMessage::RanSha(RanShaMessage::new(
                self.id,
                RanShaMessageType::ReconstructMessage,
                session_id,
                payload,
            ));
            let bytes = bincode::serialize(&message)?;
            network.send(i, &bytes).await?;
        }
        Ok(())
    }

    pub async fn reconstruction_handler<N>(
        &mut self,
        msg: RanShaMessage,
        network: Arc<N>,
    ) -> Result<(), RanShaError>
    where
        N: Network + Send + Sync,
    {
        info!("party {:?} at reconstruction handler", self.id);
        if msg.session_id.sub_id() != 0 {
            return Err(RanShaError::SessionIdError(msg.session_id));
        }

        let shares: Vec<ShamirShare<F, 1, Robust>> = match msg.payload {
            RanShaPayload::Reconstruct(payload) => {
                vec![CanonicalDeserialize::deserialize_compressed(
                    payload.as_slice(),
                )?]
            }
            RanShaPayload::ReconstructSharesBatch(payload) => {
                deser_bounded_vec(&mut payload.as_slice(), payload.len())?
            }
            _ => return Err(RanShaError::Abort),
        };
        for share in &shares {
            if share.degree != self.threshold {
                return Err(RanShaError::ShareError(ShareError::DegreeMismatch));
            }
            if share.id != msg.sender_id {
                return Err(RanShaError::ShareError(ShareError::IdMismatch));
            }
        }
        let binding = self
            .get_or_create_store(msg.session_id, msg.sender_id)
            .await?;
        let mut store = binding.lock().await;
        if store.state == RanShaState::Finished {
            return Ok(());
        }
        if store.received_r_shares.is_empty() {
            store.batch_size = shares.len();
        } else if store.batch_size != shares.len() {
            return Err(RanShaError::Abort);
        }
        store.state = RanShaState::Reconstruction;
        store.received_r_shares.insert(msg.sender_id, shares);

        if self.id < 2 * self.threshold && store.received_r_shares.len() >= 2 * self.threshold + 1 {
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
                match RobustShare::recover_secret(&shares, self.n_parties, self.threshold) {
                    Ok(r) => {
                        let poly = DensePolynomial::from_coefficients_slice(&r.0);
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

            let result = RanShaMessage::new(
                self.id,
                RanShaMessageType::OutputMessage,
                msg.session_id,
                RanShaPayload::Output(ok),
            );
            let bytes = bincode::serialize(&result)?;
            // Derive the caller from the parent session so the reconstruction RBC
            // routes to the correct (big- or small-field) share_gen instance.
            let caller = msg
                .session_id
                .calling_protocol()
                .unwrap_or(ProtocolType::Ransha);
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
                .init(bytes, sessionid, Arc::clone(&network))
                .await?;
        }

        Ok(())
    }

    pub async fn output_handler(&mut self, msg: RanShaMessage) -> Result<(), RanShaError> {
        info!("party {:?} received shares for Output", self.id);
        let ok = match msg.payload {
            RanShaPayload::Output(o) => o,
            _ => return Err(RanShaError::Abort),
        };
        if !ok {
            return Err(RanShaError::Abort);
        }

        if msg.session_id.sub_id() != 0 {
            return Err(RanShaError::SessionIdError(msg.session_id));
        }
        if msg.sender_id >= 2 * self.threshold {
            warn!("Rejecting output from non-verifier party {}", msg.sender_id);
            return Err(RanShaError::InvalidPartyId);
        }

        let binding = self
            .get_or_create_store(msg.session_id, msg.sender_id)
            .await?;
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
        msg: RanShaMessage,
        network: Arc<N>,
    ) -> Result<(), RanShaError>
    where
        N: Network + Send + Sync,
    {
        match msg.msg_type {
            RanShaMessageType::ShareMessage => {
                self.receive_shares_handler(msg, network).await?;
                Ok(())
            }
            RanShaMessageType::OutputMessage => Ok(()),
            RanShaMessageType::ReconstructMessage => {
                self.reconstruction_handler(msg, network).await?;
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::rbc::rbc::Avid;
    use crate::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
    use crate::honeybadger::share_gen::{RanShaMessage, RanShaMessageType, RanShaPayload};
    use crate::honeybadger::SessionId;
    use ark_bls12_381::Fr;
    use ark_serialize::CanonicalSerialize;
    use std::sync::Arc;
    use stoffelmpc_network::fake_network::{FakeInnerNetwork, FakeNetwork, FakeNetworkConfig};

    #[tokio::test]
    async fn test_sharegen_receive_shares_handler_invalid_sub_id() {
        let mut node = RanShaNode::<Fr, Avid<SessionId>>::new(0, 5, 1, 2).unwrap();
        let inner = FakeInnerNetwork::new(5, None, FakeNetworkConfig::new(10)).0;
        let net = Arc::new(FakeNetwork::new(0, inner));

        // Create a session id with sub_id != 0
        let session_id = SessionId::new(ProtocolType::Ransha, SessionId::pack_slot(0, 1, 0), 0);
        let share = RobustShare::new(Fr::from(1u8), 0, 1);
        let mut payload = Vec::new();
        share.serialize_compressed(&mut payload).unwrap();
        let msg = RanShaMessage::new(
            0,
            RanShaMessageType::ShareMessage,
            session_id,
            RanShaPayload::Share(payload),
        );

        let result = node.receive_shares_handler(msg, net).await;
        match result {
            Err(RanShaError::SessionIdError(sid)) => assert_eq!(sid, session_id),
            _ => panic!("Expected SessionIdError for invalid sub_id"),
        }
    }

    #[tokio::test]
    async fn test_sharegen_reconstruction_handler_invalid_sub_id() {
        let mut node = RanShaNode::<Fr, Avid<SessionId>>::new(0, 5, 1, 2).unwrap();
        let inner = FakeInnerNetwork::new(5, None, FakeNetworkConfig::new(10)).0;
        let net = Arc::new(FakeNetwork::new(0, inner));

        // Create a session id with sub_id != 0
        let session_id = SessionId::new(ProtocolType::Ransha, SessionId::pack_slot(0, 1, 0), 0);
        let share = RobustShare::new(Fr::from(1u8), 0, 1);
        let mut payload = Vec::new();
        share.serialize_compressed(&mut payload).unwrap();
        let msg = RanShaMessage::new(
            0,
            RanShaMessageType::ReconstructMessage,
            session_id,
            RanShaPayload::Reconstruct(payload),
        );

        let result = node.reconstruction_handler(msg, net).await;
        match result {
            Err(RanShaError::SessionIdError(sid)) => assert_eq!(sid, session_id),
            _ => panic!("Expected SessionIdError for invalid sub_id"),
        }
    }

    #[tokio::test]
    async fn test_sharegen_output_handler_invalid_sub_id() {
        let mut node = RanShaNode::<Fr, Avid<SessionId>>::new(0, 5, 1, 2).unwrap();

        // Create a session id with sub_id != 0
        let session_id = SessionId::new(ProtocolType::Ransha, SessionId::pack_slot(0, 1, 0), 0);
        let msg = RanShaMessage::new(
            0,
            RanShaMessageType::OutputMessage,
            session_id,
            RanShaPayload::Output(true),
        );

        let result = node.output_handler(msg).await;
        match result {
            Err(RanShaError::SessionIdError(sid)) => assert_eq!(sid, session_id),
            _ => panic!("Expected SessionIdError for invalid sub_id"),
        }
    }
}
