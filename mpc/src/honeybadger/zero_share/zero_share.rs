use ark_ff::FftField;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::Rng;
use bincode::Options;
use std::{collections::HashMap, sync::Arc};
use stoffelnet::network_utils::{Network, PartyId};
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};
use tracing::warn;

use crate::honeybadger::MAX_MESSAGE_SIZE;
use crate::{
    common::{
        share::{apply_vandermonde, make_vandermonde, ShareError},
        ProtocolSessionId, SecretSharingScheme, ShamirShare, RBC,
    },
    honeybadger::{
        robust_interpolate::robust_interpolate::{Robust, RobustShare},
        zero_share::{
            ZeroShaError, ZeroShaMessage, ZeroShaMessageType, ZeroShaPayload, ZeroShaState,
            ZeroShaStore,
        },
        ProtocolType, SessionId, WrappedMessage,
    },
};

#[derive(Clone, Debug)]
pub struct ZeroShaNode<F: FftField, R: RBC> {
    pub id: usize,
    pub n_parties: usize,
    pub threshold: usize,
    pub store: Arc<Mutex<HashMap<SessionId, Arc<Mutex<ZeroShaStore<F>>>>>>,
    pub rbc: R,
    pub rbc_output: Arc<Mutex<tokio::sync::mpsc::Receiver<SessionId>>>,
}

pub static MAX_ZERO_SHARE_SESSIONS: usize = 1024;

impl<F, R> ZeroShaNode<F, R>
where
    F: FftField,
    R: RBC<Id = SessionId>,
{
    pub fn new(
        id: PartyId,
        n_parties: usize,
        threshold: usize,
        k: usize,
    ) -> Result<Self, ZeroShaError> {
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

    pub async fn drain_rbc_output(&mut self) -> Result<(), ZeroShaError> {
        loop {
            let id = {
                let mut rx = self.rbc_output.lock().await;
                match rx.try_recv() {
                    Ok(id) => id,
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        return Err(ZeroShaError::Abort);
                    }
                }
            };
            let output = self.rbc.get_store(id).await?;
            let mut msg: ZeroShaMessage = bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .allow_trailing_bytes()
                .with_limit(MAX_MESSAGE_SIZE)
                .deserialize(&output)?;
            let authenticated_sender = id.sub_id() as usize;
            if msg.sender_id != authenticated_sender {
                warn!("Dropping RBC output: sender mismatch");
                continue;
            }
            if msg.session_id.exec_id() != id.exec_id()
                || msg.session_id.instance_id() != id.instance_id()
            {
                warn!("Dropping RBC output: session_id mismatch");
                continue;
            }
            if msg.session_id.round_id() != id.round_id() || msg.session_id.sub_id() != 0 {
                warn!("Dropping RBC output: metadata mismatch");
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
    ) -> Result<Arc<Mutex<ZeroShaStore<F>>>, ZeroShaError> {
        let mut storage = self.store.lock().await;
        if storage.len() == MAX_ZERO_SHARE_SESSIONS {
            return Err(ZeroShaError::LimitError);
        }
        Ok(storage
            .entry(session_id)
            .or_insert(Arc::new(Mutex::new(ZeroShaStore::empty(self.n_parties))))
            .clone())
    }

    pub async fn clear_store(&self, session_id: SessionId) -> bool {
        self.store.lock().await.remove(&session_id).is_some()
    }

    pub async fn wait_for_result(
        &self,
        session_id: SessionId,
        duration: Duration,
    ) -> Result<Vec<RobustShare<F>>, ZeroShaError> {
        let output_receiver = {
            let storage = self.store.lock().await;
            let storage_bind = match storage.get(&session_id) {
                Some(value) => value,
                None => return Err(ZeroShaError::NoSuchSessionId(session_id)),
            };
            let mut inner = storage_bind.lock().await;

            inner
                .output_receiver
                .take()
                .ok_or(ZeroShaError::ResultAlreadyReceived(session_id))?
        };
        match timeout(duration, output_receiver).await {
            Err(_) => Err(ZeroShaError::Timeout(session_id)),
            Ok(Err(_)) => Err(ZeroShaError::ReceiveError(session_id)),
            Ok(Ok(shares)) => Ok(shares),
        }
    }

    async fn try_finalize(&mut self, session_id: SessionId) -> Result<bool, ZeroShaError> {
        let output = {
            let store_bind = self.get_or_create_store(session_id).await?;
            let mut store = store_bind.lock().await;
            if store.state == ZeroShaState::Finished {
                return Ok(true);
            }
            if store.received_ok_msg.len() < 2 * self.threshold {
                return Ok(false);
            }
            if store.computed_r_shares.len() < self.n_parties {
                return Ok(false);
            }
            let output = store.computed_r_shares[2 * self.threshold..].to_vec();
            store.state = ZeroShaState::Finished;
            store.protocol_output = output.clone();
            let sender = store.output_sender.take().unwrap();
            (sender, output)
        };
        let (sender, output) = output;
        sender
            .send(output)
            .map_err(|_| ZeroShaError::SendError(session_id))?;
        Ok(true)
    }

    pub async fn init<N, G>(
        &mut self,
        session_id: SessionId,
        rng: &mut G,
        network: Arc<N>,
    ) -> Result<(), ZeroShaError>
    where
        N: Network,
        G: Rng,
    {
        assert_eq!(session_id.sub_id(), 0);

        //secret is zero, degree is 2t
        let shares_deg_2t =
            RobustShare::compute_shares(F::zero(), self.n_parties, 2 * self.threshold, None, rng)?;

        for (recipient_id, share) in shares_deg_2t.into_iter().enumerate() {
            let mut payload = Vec::new();
            share.serialize_compressed(&mut payload)?;
            let msg = WrappedMessage::ZeroSha(ZeroShaMessage::new(
                self.id,
                ZeroShaMessageType::ShareMessage,
                session_id,
                ZeroShaPayload::Share(payload),
            ));
            network
                .send(recipient_id, &bincode::serialize(&msg)?)
                .await?;
        }

        let storage_access = self.get_or_create_store(session_id).await?;
        storage_access.lock().await.state = ZeroShaState::Initialized;
        Ok(())
    }

    pub async fn receive_shares_handler<N>(
        &mut self,
        msg: ZeroShaMessage,
        network: Arc<N>,
    ) -> Result<(), ZeroShaError>
    where
        N: Network,
    {
        if msg.session_id.sub_id() != 0 {
            return Err(ZeroShaError::SessionIdError(msg.session_id));
        }
        let payload = match msg.payload {
            ZeroShaPayload::Share(s) => s,
            _ => return Err(ZeroShaError::Abort),
        };
        if msg.sender_id >= self.n_parties {
            return Err(ZeroShaError::InvalidPartyId);
        }

        let share: ShamirShare<F, 1, Robust> =
            ark_serialize::CanonicalDeserialize::deserialize_compressed(payload.as_slice())?;
        if share.id != self.id {
            return Err(ShareError::IdMismatch.into());
        }
        // degree check uses 2t
        if share.degree != 2 * self.threshold {
            return Err(ShareError::DegreeMismatch.into());
        }

        let binding = self.get_or_create_store(msg.session_id).await?;
        let mut store = binding.lock().await;

        if store.state == ZeroShaState::FinishedInitialSharing
            || store.state == ZeroShaState::Finished
        {
            return Ok(());
        }
        if store.initial_shares.contains_key(&msg.sender_id) {
            warn!("Duplicate share from {:?}, ignoring.", msg.sender_id);
            return Ok(());
        }

        store.initial_shares.insert(msg.sender_id, share);
        store.reception_tracker[msg.sender_id] = true;

        if store.reception_tracker.iter().all(|&r| r) {
            store.state = ZeroShaState::FinishedInitialSharing;
            let mut shares: Vec<(usize, ShamirShare<F, 1, Robust>)> = store
                .initial_shares
                .iter()
                .map(|(sid, s)| (*sid, s.clone()))
                .collect();
            drop(store);
            shares.sort_by_key(|(sid, _)| *sid);
            let shares: Vec<ShamirShare<F, 1, Robust>> =
                shares.into_iter().map(|(_, s)| s).collect();
            self.init_zerosha(shares, msg.session_id, network).await?;
        }
        Ok(())
    }

    pub async fn init_zerosha<N>(
        &mut self,
        shares_deg_2t: Vec<RobustShare<F>>,
        session_id: SessionId,
        network: Arc<N>,
    ) -> Result<(), ZeroShaError>
    where
        N: Network,
    {
        let vandermonde_matrix = make_vandermonde(self.n_parties, self.n_parties - 1)?;
        let r_deg_2t = apply_vandermonde(&vandermonde_matrix, &shares_deg_2t)?;

        let bind_store = self.get_or_create_store(session_id).await?;
        let mut store = bind_store.lock().await;
        store.computed_r_shares = r_deg_2t.clone();
        drop(store);

        if self.try_finalize(session_id).await? {
            return Ok(());
        }

        for i in 0..2 * self.threshold {
            let share = r_deg_2t[i].clone();
            let mut bytes = Vec::new();
            share.serialize_compressed(&mut bytes)?;
            let message = WrappedMessage::ZeroSha(ZeroShaMessage::new(
                self.id,
                ZeroShaMessageType::ReconstructMessage,
                session_id,
                ZeroShaPayload::Reconstruct(bytes),
            ));
            network.send(i, &bincode::serialize(&message)?).await?;
        }
        Ok(())
    }

    pub async fn reconstruction_handler<N>(
        &mut self,
        msg: ZeroShaMessage,
        network: Arc<N>,
    ) -> Result<(), ZeroShaError>
    where
        N: Network + Send + Sync,
    {
        let payload = match msg.payload {
            ZeroShaPayload::Reconstruct(s) => s,
            _ => return Err(ZeroShaError::Abort),
        };
        if msg.session_id.sub_id() != 0 {
            return Err(ZeroShaError::SessionIdError(msg.session_id));
        }

        let share: ShamirShare<F, 1, Robust> =
            ark_serialize::CanonicalDeserialize::deserialize_compressed(payload.as_slice())?;
        // degree is 2t
        if share.degree != 2 * self.threshold {
            return Err(ZeroShaError::ShareError(ShareError::DegreeMismatch));
        }
        if share.id != msg.sender_id {
            return Err(ZeroShaError::ShareError(ShareError::IdMismatch));
        }

        let binding = self.get_or_create_store(msg.session_id).await?;
        let mut store = binding.lock().await;
        if store.state == ZeroShaState::Finished {
            return Ok(());
        }
        store.state = ZeroShaState::Reconstruction;
        store.received_r_shares.insert(msg.sender_id, share);

        if self.id < 2 * self.threshold && store.received_r_shares.len() >= self.n_parties {
            let shares: Vec<ShamirShare<F, 1, Robust>> =
                store.received_r_shares.values().cloned().collect();
            drop(store);

            let ok: bool;
            // recover at degree 2t AND check secret is zero
            match RobustShare::recover_secret(&shares, self.n_parties, self.threshold) {
                Ok(r) => {
                    let poly = DensePolynomial::from_coefficients_slice(&r.0);
                    ok = poly.degree() == 2 * self.threshold && r.1.is_zero();
                }
                Err(_) => ok = false,
            }

            let result = ZeroShaMessage::new(
                self.id,
                ZeroShaMessageType::OutputMessage,
                msg.session_id,
                ZeroShaPayload::Output(ok),
            );
            let bytes = bincode::serialize(&result)?;
            let session_id = SessionId::new(
                ProtocolType::ZeroSha,
                SessionId::pack_slot24(
                    msg.session_id.exec_id(),
                    self.id as u8,
                    msg.session_id.round_id(),
                ),
                msg.session_id.instance_id(),
            );
            self.rbc
                .init(bytes, session_id, Arc::clone(&network))
                .await?;
        }
        Ok(())
    }

    pub async fn output_handler(&mut self, msg: ZeroShaMessage) -> Result<(), ZeroShaError> {
        let ok = match msg.payload {
            ZeroShaPayload::Output(o) => o,
            _ => return Err(ZeroShaError::Abort),
        };
        if !ok {
            return Err(ZeroShaError::NotZero);
        }
        if msg.session_id.sub_id() != 0 {
            return Err(ZeroShaError::SessionIdError(msg.session_id));
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
        msg: ZeroShaMessage,
        network: Arc<N>,
    ) -> Result<(), ZeroShaError>
    where
        N: Network + Send + Sync,
    {
        match msg.msg_type {
            ZeroShaMessageType::ShareMessage => self.receive_shares_handler(msg, network).await,
            ZeroShaMessageType::OutputMessage => Ok(()),
            ZeroShaMessageType::ReconstructMessage => {
                self.reconstruction_handler(msg, network).await
            }
        }
    }
}
