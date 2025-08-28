use std::{collections::BTreeMap, sync::Arc};

use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use itertools::izip;
use stoffelnet::network_utils::{Network, PartyId};
use tokio::sync::{mpsc::Sender, Mutex};
use tracing::info;

use crate::{
    common::{share::shamir::NonRobustShare, SecretSharingScheme},
    honeybadger::{
        double_share::{DouShaError, DouShaMessage, DouShaStorage},
        SessionId, WrappedMessage,
    },
};

use super::DoubleShamirShare;

#[derive(Clone, PartialEq, Debug)]
pub enum ProtocolState {
    Initialized,
    Finished,
    NotInitialized,
}

/// Node participating in a non-robust double share protocol.
#[derive(Clone, Debug)]
pub struct DoubleShareNode<F>
where
    F: FftField,
{
    /// ID of the party.
    pub id: PartyId,
    /// Number of parties participating in the protocol.
    pub n_parties: usize,
    /// Threshold for the corrupted parties.
    pub threshold: usize,
    /// Storage of the party.
    pub storage: Arc<Mutex<BTreeMap<SessionId, Arc<Mutex<DouShaStorage<F>>>>>>,
    pub output_sender: Sender<SessionId>,
}

impl<F> DoubleShareNode<F>
where
    F: FftField,
{
    pub async fn pop_finished_protocol_result(&self) -> Option<Vec<DoubleShamirShare<F>>> {
        let mut storage = self.storage.lock().await;
        let mut finished_sid = None;
        let mut output = Vec::new();
        for (sid, storage_mutex) in storage.iter() {
            let storage_bind = storage_mutex.lock().await;
            if storage_bind.state == ProtocolState::Finished {
                finished_sid = Some(*sid);
                output = storage_bind.protocol_output.clone();
                break;
            }
        }
        match finished_sid {
            Some(sid) => {
                // Remove the entry from the storage
                storage.remove(&sid);
                Some(output)
            }
            None => None,
        }
    }

    pub async fn process(&mut self, message: DouShaMessage) -> Result<(), DouShaError> {
        self.receive_double_shares_handler(message).await?;
        Ok(())
    }

    /// Creates a new node for the faulty double share protocol.
    pub fn new(
        id: PartyId,
        n_parties: usize,
        threshold: usize,
        output_sender: Sender<SessionId>,
    ) -> Self {
        Self {
            id,
            n_parties,
            threshold,
            storage: Arc::new(Mutex::new(BTreeMap::new())),
            output_sender,
        }
    }

    /// Returns the storage for a node in the Random Double Sharing protocol. If the storage has
    /// not been created yet, the function will create an empty storage and return it.
    pub async fn get_or_create_store(
        &mut self,
        session_id: SessionId,
    ) -> Arc<Mutex<DouShaStorage<F>>> {
        let mut storage = self.storage.lock().await;
        storage
            .entry(session_id)
            .or_insert(Arc::new(Mutex::new(DouShaStorage::empty(self.n_parties))))
            .clone()
    }

    pub async fn init<N, R>(
        &mut self,
        session_id: SessionId,
        rng: &mut R,
        network: Arc<N>,
    ) -> Result<(), DouShaError>
    where
        N: Network,
        R: Rng,
    {
        info!("Receiving init for faulty double share from {0:?}", self.id);

        let secret = F::rand(rng);

        let shares_deg_t =
            NonRobustShare::compute_shares(secret, self.n_parties, self.threshold, None, rng)?;
        let shares_deg_2t =
            NonRobustShare::compute_shares(secret, self.n_parties, 2 * self.threshold, None, rng)?;

        for (recipient_id, (share_t, share_2t)) in izip!(shares_deg_t, shares_deg_2t).enumerate() {
            // Create and serialize the payload.
            let double_share = DoubleShamirShare::new(share_t, share_2t);
            let mut payload = Vec::new();
            double_share.serialize_compressed(&mut payload)?;

            // Create and serialize the generic message.
            let generic_message =
                WrappedMessage::Dousha(DouShaMessage::new(self.id, session_id, payload));
            let bytes_generic_msg = bincode::serialize(&generic_message)?;

            info!("sending shares from {:?} to {:?}", self.id, recipient_id);
            network.send(recipient_id, &bytes_generic_msg).await?;
        }

        // Update the state of the protocol to Initialized.
        let storage_access = self.get_or_create_store(session_id).await;
        let mut storage = storage_access.lock().await;
        storage.state = ProtocolState::Initialized;
        Ok(())
    }

    pub async fn receive_double_shares_handler(
        &mut self,
        recv_message: DouShaMessage,
    ) -> Result<(), DouShaError> {
        let double_share: DoubleShamirShare<F> =
            CanonicalDeserialize::deserialize_compressed(recv_message.payload.as_slice())?;
        let binding = self.get_or_create_store(recv_message.session_id).await;
        let mut dousha_storage = binding.lock().await;
        dousha_storage.protocol_output.push(double_share);
        info!(
            session_id = recv_message.session_id.as_u64(),
            share_amount = dousha_storage.protocol_output.len(),
            "party {:?} received shares from {:?}",
            self.id,
            recv_message.sender_id,
        );
        dousha_storage.reception_tracker[recv_message.sender_id] = true;

        // Check if the protocol has reached an end
        if dousha_storage
            .reception_tracker
            .iter()
            .all(|&received| received)
        {
            dousha_storage.state = ProtocolState::Finished;
            self.output_sender.send(recv_message.session_id).await?;
        }

        Ok(())
    }
}
