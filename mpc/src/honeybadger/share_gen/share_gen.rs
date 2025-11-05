use ark_ff::FftField;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::Rng;
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
    pub output_sender: Sender<SessionId>,
}

impl<F, R> RanShaNode<F, R>
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
        &mut self,
        session_id: SessionId,
    ) -> Arc<Mutex<RanShaStore<F>>> {
        let mut storage = self.store.lock().await;
        storage
            .entry(session_id)
            .or_insert(Arc::new(Mutex::new(RanShaStore::empty(self.n_parties))))
            .clone()
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
        let storage_access = self.get_or_create_store(session_id).await;
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
        let payload = match msg.payload {
            RanShaPayload::Share(s) => s,
            _ => return Err(RanShaError::Abort),
        };

        let share: ShamirShare<F, 1, Robust> =
            ark_serialize::CanonicalDeserialize::deserialize_compressed(payload.as_slice())?;

        let binding = self.get_or_create_store(msg.session_id).await;
        let mut ransha_storage = binding.lock().await;
        ransha_storage.initial_shares.insert(msg.sender_id, share);
        info!(
            session_id = msg.session_id.as_u64(),
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

        let bind_store = self.get_or_create_store(session_id).await;
        let mut store = bind_store.lock().await;
        store.computed_r_shares = r_deg_t.clone();
        drop(store);

        for i in 0..2 * self.threshold {
            let share_deg_t = r_deg_t[i].clone();

            let mut bytes_rec_message = Vec::new();
            share_deg_t.serialize_compressed(&mut bytes_rec_message)?;
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

        let share: ShamirShare<F, 1, Robust> =
            ark_serialize::CanonicalDeserialize::deserialize_compressed(payload.as_slice())?;
        if share.degree != self.threshold {
            return Err(RanShaError::ShareError(ShareError::DegreeMismatch));
        }
        let binding = self.get_or_create_store(msg.session_id).await;
        let mut store = binding.lock().await;
        store.state = RanShaState::Reconstruction;
        store.received_r_shares.insert(msg.sender_id, share.clone());

        if self.id < 2 * self.threshold && store.received_r_shares.len() >= 2 * self.threshold + 1 {
            let shares: Vec<ShamirShare<F, 1, Robust>> =
                store.received_r_shares.values().cloned().collect();

            drop(store);

            let ok: bool;
            match RobustShare::recover_secret(&shares, self.n_parties) {
                Ok(r) => {
                    let poly = DensePolynomial::from_coefficients_slice(&r.0);
                    ok = poly.degree() == self.threshold;
                }
                Err(_) => ok = false,
            }

            let result = WrappedMessage::RanSha(RanShaMessage::new(
                self.id,
                RanShaMessageType::OutputMessage,
                msg.session_id,
                RanShaPayload::Output(ok),
            ));
            let bytes = bincode::serialize(&result)?;
            let sessionid = SessionId::new(
                ProtocolType::Ransha,
                msg.session_id.exec_id(),
                self.id as u8,
                msg.session_id.round_id(),
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

        let binding = self.get_or_create_store(msg.session_id).await;
        let mut store = binding.lock().await;
        store.state = RanShaState::Output;

        if !store.received_ok_msg.contains(&msg.sender_id) {
            store.received_ok_msg.push(msg.sender_id);
        }

        if store.received_ok_msg.len() < 2 * self.threshold {
            return Err(RanShaError::WaitForOk);
        }

        if store.computed_r_shares.len() < self.n_parties {
            return Err(RanShaError::WaitForOk);
        }

        let output = store.computed_r_shares[2 * self.threshold..].to_vec();
        store.state = RanShaState::Finished;
        store.protocol_output = output;
        self.output_sender.send(msg.session_id).await?;
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
            RanShaMessageType::OutputMessage => Ok(self.output_handler(msg).await?),
            RanShaMessageType::ReconstructMessage => {
                self.reconstruction_handler(msg, network).await?;
                Ok(())
            }
        }
    }
}
