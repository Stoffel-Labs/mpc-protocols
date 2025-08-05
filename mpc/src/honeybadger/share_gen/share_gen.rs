use std::{collections::HashMap, sync::Arc};

use ark_ff::FftField;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_serialize::CanonicalSerialize;
use stoffelmpc_network::{Network, PartyId};
use tokio::sync::Mutex;

use crate::{
    common::{
        share::{
            apply_vandermonde, make_vandermonde,
            shamir::{NonRobust, NonRobustShare},
            ShareError,
        },
        SecretSharingScheme, ShamirShare, RBC,
    },
    honeybadger::{
        share_gen::{
            RanShaError, RanShaMessage, RanShaMessageType, RanShaPayload, RanShaState, RanShaStore,
        },
        ProtocolType, SessionId, WrappedMessage,
    },
};

#[derive(Clone)]
pub struct RanShaNode<F: FftField, R: RBC> {
    pub id: usize,
    pub n_parties: usize,
    pub threshold: usize,
    pub store: Arc<Mutex<HashMap<SessionId, Arc<Mutex<RanShaStore<F>>>>>>,
    pub rbc: R,
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
    ) -> Result<Self, RanShaError> {
        let rbc = R::new(id, n_parties, threshold, k).map_err(RanShaError::RbcError)?;
        Ok(Self {
            id,
            n_parties,
            threshold,
            store: Arc::new(Mutex::new(HashMap::new())),
            rbc,
        })
    }

    pub async fn get_or_create_store(
        &mut self,
        session_id: SessionId,
    ) -> Arc<Mutex<RanShaStore<F>>> {
        let mut storage = self.store.lock().await;
        storage
            .entry(session_id)
            .or_insert(Arc::new(Mutex::new(RanShaStore::empty())))
            .clone()
    }

    pub async fn init<N>(
        &mut self,
        shares_deg_t: Vec<NonRobustShare<F>>,
        session_id: SessionId,
        network: Arc<N>,
    ) -> Result<(), RanShaError>
    where
        N: Network,
    {
        let vandermonde_matrix = make_vandermonde(self.n_parties, self.n_parties - 1)?;
        let r_deg_t = apply_vandermonde(&vandermonde_matrix, &shares_deg_t)?;

        let bind_store = self.get_or_create_store(session_id).await;
        let mut store = bind_store.lock().await;
        store.computed_r_shares = r_deg_t.clone();
        drop(store);

        for i in 0..2 * self.threshold {
            let share_deg_t = r_deg_t[i].clone();

            let mut bytes_rec_message = Vec::new();
            share_deg_t
                .serialize_compressed(&mut bytes_rec_message)
                .map_err(RanShaError::ArkSerialization)?;
            let message = WrappedMessage::RanSha(RanShaMessage::new(
                self.id,
                RanShaMessageType::ReconstructMessage,
                session_id,
                RanShaPayload::Reconstruct(bytes_rec_message),
            ));
            let bytes = bincode::serialize(&message).map_err(RanShaError::SerializationError)?;
            network
                .send(i, &bytes)
                .await
                .map_err(RanShaError::NetworkError)?;
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
        let payload = match msg.payload {
            RanShaPayload::Reconstruct(s) => s,
            RanShaPayload::Output(_) => return Err(RanShaError::Abort),
        };

        let share: ShamirShare<F, 1, NonRobust> =
            ark_serialize::CanonicalDeserialize::deserialize_compressed(payload.as_slice())
                .map_err(RanShaError::ArkDeserialization)?;
        if share.degree != self.threshold {
            return Err(RanShaError::ShareError(ShareError::DegreeMismatch));
        }
        let binding = self.get_or_create_store(msg.session_id).await;
        let mut store = binding.lock().await;
        store.state = RanShaState::Reconstruction;
        store.received_r_shares.insert(msg.sender_id, share);

        if self.id < 2 * self.threshold && store.received_r_shares.len() == self.n_parties {
            let shares: Vec<ShamirShare<F, 1, NonRobust>> =
                store.received_r_shares.values().cloned().collect();

            drop(store);

            let recovered =
                NonRobustShare::recover_secret(&shares).map_err(|e| RanShaError::ShareError(e))?;
            let poly = DensePolynomial::from_coefficients_slice(&recovered.0);
            let ok = poly.degree() == self.threshold;

            let result = WrappedMessage::RanSha(RanShaMessage::new(
                self.id,
                RanShaMessageType::OutputMessage,
                msg.session_id,
                RanShaPayload::Output(ok),
            ));
            let bytes = bincode::serialize(&result).map_err(RanShaError::SerializationError)?;
            let sessionid = SessionId::new(
                ProtocolType::Ransha,
                msg.session_id.as_u64() + self.id as u64,
            );
            self.rbc
                .init(bytes, sessionid, Arc::clone(&network))
                .await
                .map_err(RanShaError::RbcError)?;
        }

        Ok(())
    }

    pub async fn output_handler(
        &mut self,
        msg: RanShaMessage,
    ) -> Result<Vec<NonRobustShare<F>>, RanShaError> {
        let ok = match msg.payload {
            RanShaPayload::Output(o) => o,
            RanShaPayload::Reconstruct(_) => return Err(RanShaError::Abort),
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

        if store.received_ok_msg.len() < self.n_parties - 2 * self.threshold {
            return Err(RanShaError::WaitForOk);
        }

        if store.computed_r_shares.len() < self.n_parties {
            return Err(RanShaError::WaitForOk);
        }

        let output = store.computed_r_shares[2 * self.threshold..].to_vec();
        store.state = RanShaState::Finished;
        Ok(output)
    }

    pub async fn process<N>(
        &mut self,
        msg: RanShaMessage,
        network: Arc<N>,
    ) -> Result<Option<Vec<NonRobustShare<F>>>, RanShaError>
    where
        N: Network + Send + Sync,
    {
        match msg.msg_type {
            RanShaMessageType::OutputMessage => Ok(Some(self.output_handler(msg).await?)),
            RanShaMessageType::ReconstructMessage => {
                self.reconstruction_handler(msg, network).await?;
                Ok(None)
            }
        }
    }
}
