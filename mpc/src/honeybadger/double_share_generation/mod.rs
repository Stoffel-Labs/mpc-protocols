use std::{collections::HashMap, sync::Arc};

use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use bincode::ErrorKind;
use serde::{Deserialize, Serialize};
use stoffelmpc_network::{Message, Network, NetworkError, Node, PartyId, SessionId};
use thiserror::Error;
use tokio::sync::Mutex;

use crate::common::{
    share::{shamir::NonRobustShamirShare, ShareError},
    SecretSharingScheme,
};

use super::DoubleShamirShare;

#[derive(Debug, Error)]
pub enum DouShaError {
    #[error(
        "sender mismatch: expected sender: {expected_sender:?}, actual_sender: {actual_sender:?}"
    )]
    SenderMismatch {
        expected_sender: PartyId,
        actual_sender: PartyId,
    },
    #[error("error in share: {0:?}")]
    ShareError(#[from] ShareError),
    #[error("ark serialization error: {0:?}")]
    ArkSerializationError(#[from] ark_serialize::SerializationError),
    #[error("bincode serialization error: {0:?}")]
    BincodeSerializationError(#[from] Box<ErrorKind>),
    #[error("error in the network: {0:?}")]
    NetworkError(#[from] NetworkError),
}

#[derive(Serialize, Deserialize)]
pub struct DouShaMessage {
    sender_id: PartyId,
    session_id: SessionId,
    msg_type: DouShaMessageType,
    payload: Vec<u8>,
}

impl Message for DouShaMessage {
    fn sender_id(&self) -> PartyId {
        self.sender_id
    }

    fn bytes(&self) -> &[u8] {
        &self.payload
    }
}

impl DouShaMessage {
    pub fn new(
        sender: PartyId,
        session_id: SessionId,
        msg_type: DouShaMessageType,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            sender_id: sender,
            session_id,
            msg_type,
            payload,
        }
    }
}

#[derive(PartialEq, Serialize, Deserialize)]
pub enum DouShaMessageType {
    Initialize,
    Receive,
}

#[derive(Serialize, Deserialize)]
pub struct InitMessage {
    sender: PartyId,
    session_id: SessionId,
}

impl InitMessage {
    pub fn new(sender: PartyId, session_id: SessionId) -> Self {
        Self { sender, session_id }
    }
}

#[derive(CanonicalDeserialize, CanonicalSerialize)]
pub struct ReceiveMessage<F: FftField> {
    /// ID of the sender.
    pub sender_id: PartyId,
    pub session_id: SessionId,
    pub double_share: DoubleShamirShare<F>,
}

impl<F> ReceiveMessage<F>
where
    F: FftField,
{
    pub fn new(
        sender_id: usize,
        session_id: SessionId,
        double_share: DoubleShamirShare<F>,
    ) -> Self {
        Self {
            sender_id,
            session_id,
            double_share,
        }
    }
}

pub struct DouShaStorage<F>
where
    F: FftField,
{
    pub shares: Vec<DoubleShamirShare<F>>,
}

impl<F> DouShaStorage<F>
where
    F: FftField,
{
    pub fn empty() -> Self {
        Self { shares: Vec::new() }
    }
}

/// Node participating in a non-robust double share protocol.
pub struct DoubleShareNode<F>
where
    F: FftField,
{
    pub id: PartyId,
    pub storage: Arc<Mutex<HashMap<SessionId, Arc<Mutex<DouShaStorage<F>>>>>>,
}

impl<F> DoubleShareNode<F>
where
    F: FftField,
{
    /// Returns the storage for a node in the Random Double Sharing protocol. If the storage has
    /// not been created yet, the function will create an empty storage and return it.
    pub async fn get_or_create_store(
        &mut self,
        session_id: SessionId,
    ) -> Arc<Mutex<DouShaStorage<F>>> {
        let mut storage = self.storage.lock().await;
        storage
            .entry(session_id)
            .or_insert(Arc::new(Mutex::new(DouShaStorage::empty())))
            .clone()
    }

    pub async fn init_handler<N, R>(
        &self,
        n: usize,
        t: usize,
        init_msg: InitMessage,
        rng: &mut R,
        network: Arc<N>,
    ) -> Result<(), DouShaError>
    where
        N: Network,
        R: Rng,
    {
        let ids: Vec<PartyId> = network.parties().iter().map(|party| party.id()).collect();

        let secret = F::rand(rng);

        let shares_deg_t = NonRobustShamirShare::compute_shares(secret, n, t, Some(&ids), rng)?;
        let shares_deg_2t =
            NonRobustShamirShare::compute_shares(secret, n, 2 * t, Some(&ids), rng)?;

        for (share_t, share_2t) in shares_deg_t.into_iter().zip(shares_deg_2t) {
            let double_share = DoubleShamirShare::new(share_t, share_2t);
            let message = ReceiveMessage::new(self.id, init_msg.session_id, double_share);

            // Serialization of the payload
            let mut payload = Vec::new();
            message.serialize_compressed(&mut payload)?;

            let generic_message = DouShaMessage::new(
                self.id,
                init_msg.session_id,
                DouShaMessageType::Receive,
                payload,
            );

            // Serialize the generic message
            let bytes_generic_msg = bincode::serialize(&generic_message)?;

            network
                .send(message.double_share.degree_t.id, &bytes_generic_msg)
                .await?;
        }

        Ok(())
    }

    pub async fn receive_double_shares_handler(
        &mut self,
        recv_message: ReceiveMessage<F>,
    ) -> Result<(), DouShaError> {
        let binding = self.get_or_create_store(recv_message.session_id).await;
        let mut dousha_storage = binding.lock().await;
        dousha_storage.shares.push(recv_message.double_share);
        Ok(())
    }
}
