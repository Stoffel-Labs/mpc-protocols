use ark_ff::FftField;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::Rng;
use std::{collections::HashMap, sync::Arc};
use stoffelnet::network_utils::{Network, PartyId};
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};
use tracing::{error, info};

use crate::{
    common::{
        share::{apply_vandermonde, make_vandermonde, ShareError},
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
    pub store: Arc<Mutex<HashMap<SessionId, Arc<Mutex<RanShaStore<F>>>>>>,
    pub rbc: R,
    pub rbc_output: Arc<Mutex<tokio::sync::mpsc::Receiver<SessionId>>>,
}

pub static MAX_SHARE_GEN_SESSIONS: usize = 1024;

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
            let msg: RanShaMessage = bincode::deserialize(&output)?;

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
    ) -> Result<Arc<Mutex<RanShaStore<F>>>, RanShaError> {
        let mut storage = self.store.lock().await;

        if storage.len() == MAX_SHARE_GEN_SESSIONS {
            return Err(RanShaError::LimitError);
        }

        Ok(storage
            .entry(session_id)
            .or_insert(Arc::new(Mutex::new(RanShaStore::empty(self.n_parties))))
            .clone())
    }

    pub async fn clear_store(&self, session_id: SessionId) -> bool {
        let mut store = self.store.lock().await;
        store.remove(&session_id).is_some()
    }

    pub async fn wait_for_result(
        &self,
        session_id: SessionId,
        duration: Duration,
    ) -> Result<Vec<RobustShare<F>>, RanShaError> {
        let output_receiver = {
            let storage = self.store.lock().await;
            let storage_bind = match storage.get(&session_id) {
                Some(value) => value,
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
            let store_bind = self.get_or_create_store(session_id).await?;
            let mut store = store_bind.lock().await;

            if store.state == RanShaState::Finished {
                return Ok(true);
            }

            if store.received_ok_msg.len() < 2 * self.threshold {
                return Ok(false);
            }
            if store.computed_r_shares.len() < self.n_parties {
                return Ok(false);
            }

            let output = store.computed_r_shares[2 * self.threshold..].to_vec();
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
        info!("Receiving init for share from {0:?}", self.id);

        assert_eq!(session_id.sub_id(), 0);

        let secret = F::rand(rng);

        let shares_deg_t =
            RobustShare::compute_shares(secret, self.n_parties, self.threshold, None, rng)?;

        for (recipient_id, share_t) in shares_deg_t.into_iter().enumerate() {
            // Create and serialize the payload.
            let mut payload = Vec::new();
            share_t.serialize_compressed(&mut payload)?;

            // Create and serialize the generic message.
            let generic_message = WrappedMessage::RanSha(RanShaMessage::new(
                self.id,
                RanShaMessageType::ShareMessage,
                session_id,
                RanShaPayload::Share(payload),
            ));
            let bytes_generic_msg = bincode::serialize(&generic_message)?;

            info!("sending shares from {:?} to {:?}", self.id, recipient_id);
            network.send(recipient_id, &bytes_generic_msg).await?;
        }

        // Update the state of the protocol to Initialized.
        let storage_access = self.get_or_create_store(session_id).await?;
        let mut storage = storage_access.lock().await;
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

        let payload = match msg.payload {
            RanShaPayload::Share(s) => s,
            _ => return Err(RanShaError::Abort),
        };

        let share: ShamirShare<F, 1, Robust> =
            ark_serialize::CanonicalDeserialize::deserialize_compressed(payload.as_slice())
                .inspect_err(|err| {
                    let message_type = msg.msg_type;
                    error!(
                        "Error deserializing in receive_shares_handler: {err:?}, {message_type:?}"
                    );
                })?;

        let binding = self.get_or_create_store(msg.session_id).await?;
        let mut ransha_storage = binding.lock().await;
        ransha_storage.initial_shares.insert(msg.sender_id, share);
        info!(
            session_id = msg.session_id.as_u64(),
            "party {:?} received shares from {:?}", self.id, msg.sender_id,
        );

        if msg.sender_id >= self.n_parties {
            return Err(RanShaError::InvalidPartyId);
        }
        ransha_storage.reception_tracker[msg.sender_id] = true;

        // Check if the protocol has reached an end
        if ransha_storage
            .reception_tracker
            .iter()
            .all(|&received| received)
        {
            ransha_storage.state = RanShaState::FinishedInitialSharing;
            let mut shares_deg_t: Vec<(usize, ShamirShare<F, 1, Robust>)> = ransha_storage
                .initial_shares
                .iter()
                .map(|(sid, s)| (*sid, s.clone()))
                .collect();
            drop(ransha_storage);
            // sort by sender_id
            shares_deg_t.sort_by_key(|(sid, _)| *sid);

            // drop the ids, keep only shares
            let shares_deg_t: Vec<ShamirShare<F, 1, Robust>> =
                shares_deg_t.into_iter().map(|(_, s)| s).collect();
            self.init_ransha(shares_deg_t, msg.session_id, network)
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
        info!(
            "party {:?} received shares for Random sharing generation",
            self.id
        );

        let vandermonde_matrix = make_vandermonde(self.n_parties, self.n_parties - 1)?;
        let r_deg_t = apply_vandermonde(&vandermonde_matrix, &shares_deg_t)?;

        let bind_store = self.get_or_create_store(session_id).await?;
        let mut store = bind_store.lock().await;
        store.computed_r_shares = r_deg_t.clone();
        drop(store);
        if self.try_finalize(session_id).await? {
            return Ok(());
        }

        for i in 0..2 * self.threshold {
            let share_deg_t = r_deg_t[i].clone();

            let mut bytes_rec_message = Vec::new();
            share_deg_t
                .serialize_compressed(&mut bytes_rec_message)
                .inspect_err(|err| error!("error serializing r_deg_t"))?;
            let message = WrappedMessage::RanSha(RanShaMessage::new(
                self.id,
                RanShaMessageType::ReconstructMessage,
                session_id,
                RanShaPayload::Reconstruct(bytes_rec_message),
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
        let payload = match msg.payload {
            RanShaPayload::Reconstruct(s) => s,
            _ => return Err(RanShaError::Abort),
        };

        if msg.session_id.sub_id() != 0 {
            return Err(RanShaError::SessionIdError(msg.session_id));
        }

        let share: ShamirShare<F, 1, Robust> =
            ark_serialize::CanonicalDeserialize::deserialize_compressed(payload.as_slice())?;
        if share.degree != self.threshold {
            return Err(RanShaError::ShareError(ShareError::DegreeMismatch));
        }
        if share.id != msg.sender_id {
            return Err(RanShaError::ShareError(ShareError::IdMismatch));
        }
        let binding = self.get_or_create_store(msg.session_id).await?;
        let mut store = binding.lock().await;
        if store.state == RanShaState::Finished {
            return Ok(());
        }
        store.state = RanShaState::Reconstruction;
        store.received_r_shares.insert(msg.sender_id, share.clone());

        if self.id < 2 * self.threshold && store.received_r_shares.len() >= 2 * self.threshold + 1 {
            let shares: Vec<ShamirShare<F, 1, Robust>> =
                store.received_r_shares.values().cloned().collect();

            drop(store);

            let ok: bool;
            match RobustShare::recover_secret(&shares, self.n_parties, self.threshold) {
                Ok(r) => {
                    let poly = DensePolynomial::from_coefficients_slice(&r.0);
                    ok = poly.degree() == self.threshold;
                }
                Err(_) => ok = false,
            }

            let result = RanShaMessage::new(
                self.id,
                RanShaMessageType::OutputMessage,
                msg.session_id,
                RanShaPayload::Output(ok),
            );
            let bytes = bincode::serialize(&result)?;
            let sessionid = SessionId::new(
                ProtocolType::Ransha,
                SessionId::pack_slot24(
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

        let binding = self.get_or_create_store(msg.session_id).await?;
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
    async fn test_sharegen_storage_limit_in_receive_shares_handler() {
        let mut node = RanShaNode::<Fr, Avid<SessionId>>::new(0, 5, 1, 2).unwrap();
        let inner = FakeInnerNetwork::new(5, None, FakeNetworkConfig::new(10)).0;
        let net = Arc::new(FakeNetwork::new(0, inner));

        // Fill up the storage to the limit by calling receive_shares_handler with unique session IDs
        let mut exec = 0u8;
        let mut round = 0u8;
        for _ in 0..super::MAX_SHARE_GEN_SESSIONS {
            let sid = SessionId::new(
                ProtocolType::Ransha,
                SessionId::pack_slot24(exec, 0, round),
                0,
            );
            let share = RobustShare::new(Fr::from(1u8), 0, 1);
            let mut payload = Vec::new();
            share.serialize_compressed(&mut payload).unwrap();
            let msg = RanShaMessage::new(
                0,
                RanShaMessageType::ShareMessage,
                sid,
                RanShaPayload::Share(payload),
            );
            // Ignore the result, just fill up storage
            let _ = node.receive_shares_handler(msg, net.clone()).await;

            // Increment exec and round to ensure unique session IDs
            if round == u8::MAX {
                round = 0;
                exec = exec.wrapping_add(1);
            } else {
                round = round.wrapping_add(1);
            }
        }

        // Now try to process a message that would require a new session (should hit the limit)
        let over_sid = SessionId::new(ProtocolType::Ransha, SessionId::pack_slot24(255, 0, 255), 0);
        let share = RobustShare::new(Fr::from(1u8), 0, 1);
        let mut payload = Vec::new();
        share.serialize_compressed(&mut payload).unwrap();
        let msg = RanShaMessage::new(
            0,
            RanShaMessageType::ShareMessage,
            over_sid,
            RanShaPayload::Share(payload),
        );

        let result = node.receive_shares_handler(msg, net).await;
        assert!(
            matches!(result, Err(RanShaError::LimitError)),
            "Should error on exceeding storage limit"
        );
    }

    #[tokio::test]
    async fn test_sharegen_storage_limit_in_reconstruction_handler() {
        let mut node = RanShaNode::<Fr, Avid<SessionId>>::new(0, 5, 1, 2).unwrap();
        let inner = FakeInnerNetwork::new(5, None, FakeNetworkConfig::new(10)).0;
        let net = Arc::new(FakeNetwork::new(0, inner));

        // Fill up the storage to the limit by calling reconstruction_handler with unique session IDs
        let mut exec = 0u8;
        let mut round = 0u8;
        for _ in 0..super::MAX_SHARE_GEN_SESSIONS {
            let sid = SessionId::new(
                ProtocolType::Ransha,
                SessionId::pack_slot24(exec, 0, round),
                0,
            );
            let share = RobustShare::new(Fr::from(1u8), 0, 1);
            let mut payload = Vec::new();
            share.serialize_compressed(&mut payload).unwrap();
            let msg = RanShaMessage::new(
                0,
                RanShaMessageType::ReconstructMessage,
                sid,
                RanShaPayload::Reconstruct(payload),
            );
            // Ignore the result, just fill up storage
            let _ = node.reconstruction_handler(msg, net.clone()).await;

            // Increment exec and round to ensure unique session IDs
            if round == u8::MAX {
                round = 0;
                exec = exec.wrapping_add(1);
            } else {
                round = round.wrapping_add(1);
            }
        }

        // Now try to process a message that would require a new session (should hit the limit)
        let over_sid = SessionId::new(ProtocolType::Ransha, SessionId::pack_slot24(255, 0, 255), 0);
        let share = RobustShare::new(Fr::from(1u8), 0, 1);
        let mut payload = Vec::new();
        share.serialize_compressed(&mut payload).unwrap();
        let msg = RanShaMessage::new(
            0,
            RanShaMessageType::ReconstructMessage,
            over_sid,
            RanShaPayload::Reconstruct(payload),
        );

        let result = node.reconstruction_handler(msg, net).await;
        assert!(
            matches!(result, Err(RanShaError::LimitError)),
            "Should error on exceeding storage limit"
        );
    }

    #[tokio::test]
    async fn test_sharegen_storage_limit_in_output_handler() {
        let mut node = RanShaNode::<Fr, Avid<SessionId>>::new(0, 5, 1, 2).unwrap();

        // Fill up the storage to the limit by calling output_handler with unique session IDs
        let mut exec = 0u8;
        let mut round = 0u8;
        for _ in 0..super::MAX_SHARE_GEN_SESSIONS {
            let sid = SessionId::new(
                ProtocolType::Ransha,
                SessionId::pack_slot24(exec, 0, round),
                0,
            );
            let msg = RanShaMessage::new(
                0,
                RanShaMessageType::OutputMessage,
                sid,
                RanShaPayload::Output(true),
            );
            // Ignore the result, just fill up storage
            let _ = node.output_handler(msg).await;

            // Increment exec and round to ensure unique session IDs
            if round == u8::MAX {
                round = 0;
                exec = exec.wrapping_add(1);
            } else {
                round = round.wrapping_add(1);
            }
        }

        // Now try to process a message that would require a new session (should hit the limit)
        let over_sid = SessionId::new(ProtocolType::Ransha, SessionId::pack_slot24(255, 0, 255), 0);
        let msg = RanShaMessage::new(
            0,
            RanShaMessageType::OutputMessage,
            over_sid,
            RanShaPayload::Output(true),
        );

        let result = node.output_handler(msg).await;
        assert!(
            matches!(result, Err(RanShaError::LimitError)),
            "Should error on exceeding storage limit"
        );
    }

    #[tokio::test]
    async fn test_sharegen_receive_shares_handler_invalid_sub_id() {
        let mut node = RanShaNode::<Fr, Avid<SessionId>>::new(0, 5, 1, 2).unwrap();
        let inner = FakeInnerNetwork::new(5, None, FakeNetworkConfig::new(10)).0;
        let net = Arc::new(FakeNetwork::new(0, inner));

        // Create a session id with sub_id != 0
        let session_id = SessionId::new(ProtocolType::Ransha, SessionId::pack_slot24(0, 1, 0), 0);
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
        let session_id = SessionId::new(ProtocolType::Ransha, SessionId::pack_slot24(0, 1, 0), 0);
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
        let session_id = SessionId::new(ProtocolType::Ransha, SessionId::pack_slot24(0, 1, 0), 0);
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
