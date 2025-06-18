pub mod messages;

use crate::honeybadger::batch_recon::batch_recon::{apply_vandermonde, make_vandermonde};
use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use bincode::ErrorKind;
use messages::{
    InitMessage, OutputMessage, RanDouShaMessage, RanDouShaMessageType, ReconstructionMessage,
};
use std::{collections::HashMap, sync::Arc};
use stoffelmpc_common::share::shamir::ShamirSecretSharing;
use thiserror::Error;
use tokio::sync::Mutex;

use stoffelmpc_network::{Network, NetworkError, Node, PartyId, SessionId};

/// Error that occurs during the execution of the Random Double Share Error.
#[derive(Debug, Error)]
pub enum RanDouShaError {
    /// The error occurs when communicating using the network.
    #[error("there was an error in the network: {0:?}")]
    NetworkError(NetworkError),
    #[error("error while serializing an arkworks object: {0:?}")]
    ArkSerialization(SerializationError),
    #[error("error while serializing an arkworks object: {0:?}")]
    ArkDeserialization(SerializationError),
    #[error("error while serializing the object into bytes: {0:?}")]
    SerializationError(Box<ErrorKind>),
    /// The protocol received an abort signal.
    #[error("received abort singal")]
    Abort,
    /// The party is waiting for confirmations.
    #[error("waiting for more confirmations")]
    WaitForOk,
}

/// Storage for the Random Double Sharing protocol.
#[derive(Clone)]
pub struct RanDouShaStore<F: FftField> {
    /// Vector that stores the received degree t shares of r.
    pub received_r_shares_degree_t: HashMap<PartyId, ShamirSecretSharing<F>>,
    /// Vector that stores the received degree 2t shares of r.
    pub received_r_shares_degree_2t: HashMap<PartyId, ShamirSecretSharing<F>>,
    /// Vector of r shares of degree t computed as a result of multiplying the Vandermonde matrix
    /// with the shares of s.
    pub computed_r_shares_degree_t: Vec<ShamirSecretSharing<F>>,
    /// Vector of r shares of degree 2t computed as a result of multiplying the Vandermonde matrix
    /// with the shares of s.
    pub computed_r_shares_degree_2t: Vec<ShamirSecretSharing<F>>,
    /// Vector that stores the nodes who have sent the output ok msg.
    pub received_ok_msg: Vec<usize>,
}

impl<F> RanDouShaStore<F>
where
    F: FftField,
{
    /// Creates a new empty store for the random double sharing node.
    pub fn empty() -> Self {
        Self {
            received_r_shares_degree_t: HashMap::new(),
            received_r_shares_degree_2t: HashMap::new(),
            computed_r_shares_degree_t: Vec::new(),
            computed_r_shares_degree_2t: Vec::new(),
            received_ok_msg: Vec::new(),
        }
    }
}

/// Parameters for the Random Double Share protocol.
#[derive(Clone, Copy)]
pub struct RanDouShaParams {
    /// Number of parties involved in the protocol.
    pub n_parties: usize,
    /// Threshold of corrupted parties.
    pub threshold: usize,
    /// Session ID of the execution.
    pub session_id: SessionId,
}

/// Node representation for the Random Double Share protocol.
#[derive(Clone)]
pub struct RanDouShaNode<F: FftField> {
    /// ID of the node.
    pub id: PartyId,
    /// Storage of the node.
    pub store: Arc<Mutex<HashMap<SessionId, Arc<Mutex<RanDouShaStore<F>>>>>>,
}

impl<F> RanDouShaNode<F>
where
    F: FftField,
{
    /// Returns the storage for a node in the Random Double Sharing protocol. If the storage has
    /// not been created yet, the function will create an empty storage and return it.
    pub async fn get_or_create_store(
        &mut self,
        params: &RanDouShaParams,
    ) -> Arc<Mutex<RanDouShaStore<F>>> {
        let mut storage = self.store.lock().await;
        storage
            .entry(params.session_id)
            .or_insert(Arc::new(Mutex::new(RanDouShaStore::empty())))
            .clone()
    }

    /// Implements the initialization phase of the Random double share protocol. In particular,
    /// this method implements from Step (1) to Step (3) before the reconstruction of the shares
    /// $\llbracket r_i \rrbracket$.
    ///
    /// # Warning
    ///
    /// This method assumes that the [`InitMessage`] contains the shares sorted in such a way that
    /// the share in position `k` is the share $\llbracket r_k \rrbracket_{t}^{(i)} where `i` is
    /// the ID of the current participant.
    ///
    /// # Errors
    ///
    /// If sending the shares through the network fails, the function returns a [`NetworkError`].
    pub async fn init_handler<N>(
        &mut self,
        init_msg: &InitMessage<F>,
        params: &RanDouShaParams,
        network: Arc<Mutex<N>>,
    ) -> Result<(), RanDouShaError>
    where
        N: Network,
    {
        // todo - should check sender.id == self?
        let vandermonde_matrix = make_vandermonde(params.n_parties, params.n_parties);
        let share_values_deg_t: Vec<F> = init_msg
            .s_shares_deg_t
            .iter()
            .map(|share| share.share)
            .collect();
        let share_values_deg_2t: Vec<F> = init_msg
            .s_shares_deg_2t
            .iter()
            .map(|share| share.share)
            .collect();

        // Implementation of Step 1.
        let r_deg_t = apply_vandermonde(&vandermonde_matrix, &share_values_deg_t);

        // Implementation of Step 2.
        let r_deg_2t = apply_vandermonde(&vandermonde_matrix, &share_values_deg_2t);

        // Save the shares of r of degree t and 2t into the storage.
        let bind_store = self.get_or_create_store(params).await;
        let mut store = bind_store.lock().await;
        store.computed_r_shares_degree_t = r_deg_t
            .iter()
            .map(|share_value| {
                ShamirSecretSharing::new(
                    share_value.clone(),
                    F::from(self.id as u64),
                    params.threshold,
                )
            })
            .collect();
        store.computed_r_shares_degree_2t = r_deg_2t
            .iter()
            .map(|share_value| {
                ShamirSecretSharing::new(
                    share_value.clone(),
                    F::from(self.id as u64),
                    2 * params.threshold,
                )
            })
            .collect();

        // The current party with index i sends the share [r_j] to the party P_j so that P_j can
        // reconstruct the value r_j.
        let network_locked = network.lock().await;
        for party in network_locked.parties() {
            if party.id() > params.threshold + 1 && party.id() <= params.n_parties {
                let share_deg_t = ShamirSecretSharing::new(
                    r_deg_t[party.id() - 1],
                    F::from(self.id as u64),
                    params.threshold,
                );
                let share_deg_2t = ShamirSecretSharing::new(
                    r_deg_2t[party.id() - 1],
                    F::from(self.id as u64),
                    2 * params.threshold,
                );

                let reconst_message =
                    ReconstructionMessage::new(self.id, share_deg_t, share_deg_2t);

                // Serializing the reconstruction message and wrapping it into a generic message.
                let mut bytes_rec_message = Vec::new();
                reconst_message
                    .serialize_compressed(&mut bytes_rec_message)
                    .map_err(RanDouShaError::ArkSerialization)?;
                let generic_message = RanDouShaMessage::new(
                    self.id,
                    RanDouShaMessageType::ReconstructMessage,
                    &bytes_rec_message,
                );
                let bytes_generic_message = bincode::serialize(&generic_message)
                    .map_err(RanDouShaError::SerializationError)?;

                // Sending the generic message to the network.
                network_locked
                    .send(party.id(), &bytes_generic_message)
                    .await
                    .map_err(RanDouShaError::NetworkError)?;
            }
        }
        Ok(())
    }

    /// Implements Step (3) Reconstruction of shares of RanDouSha Protocol
    /// https://eprint.iacr.org/2019/883.pdf.
    /// On receiving shares of r_i from each parties of degree t and 2t, the protocol privately reconstructs r_i for both degrees
    /// and checks that both shares are of the correct degree, and that their 0-evaluation is the same.
    /// Broadcast OK if the verification succeeds, ABORT otherwise
    ///
    /// # Errors
    ///
    /// If sending the shares through the network fails, the function returns a [`NetworkError`].
    pub async fn reconstruction_handler<N>(
        &mut self,
        rec_msg: &ReconstructionMessage<F>,
        params: &RanDouShaParams,
        network: Arc<Mutex<N>>,
    ) -> Result<(), RanDouShaError>
    where
        N: Network,
    {
        // --- Step (3) Implementation ---
        // (1) Store the received shares.
        // Each party receives a ReconstructionMessage. This message contains two ShamirSecretSharing objects:
        // one for degree t and one for degree 2t.
        // These shares originate from the *sender* of the message, but they are components of the 'r_j'

        let binding = self.get_or_create_store(params).await;
        let mut store = binding.lock().await;

        let sender_id = rec_msg.sender_id;
        store
            .received_r_shares_degree_t
            .insert(sender_id, rec_msg.r_share_deg_t.clone());
        store
            .received_r_shares_degree_2t
            .insert(sender_id, rec_msg.r_share_deg_2t.clone());

        // (2) Check if this party (self.id) is one of the designated checking parties.
        // Condition from the protocol: `t + 1 < i <= n`
        if self.id > params.threshold + 1 && self.id <= params.n_parties {
            // (3) Check if enough shares have been received to reconstruct.
            // To reconstruct a (t) degree polynomial, you need t+1 distinct shares.
            // To reconstruct a (2t) degree polynomial, you need 2t+1 distinct shares.

            // TODO: do we need to wait for all n shares?
            if store.received_r_shares_degree_t.len() >= params.threshold + 1
                && store.received_r_shares_degree_2t.len() >= 2 * params.threshold + 1
            {
                let mut shares_t_for_recon: Vec<ShamirSecretSharing<F>> = Vec::new();
                let mut shares_2t_for_recon: Vec<ShamirSecretSharing<F>> = Vec::new();

                for (_, share) in store.received_r_shares_degree_t.iter() {
                    shares_t_for_recon.push(share.clone());
                }
                for (_, share) in store.received_r_shares_degree_2t.iter() {
                    shares_2t_for_recon.push(share.clone());
                }

                // (5) Perform reconstruction for both degrees.
                // ShamirSecretSharing::reconstruct expects a vector of shares.
                let reconstructed_r_t = ShamirSecretSharing::recover_secret(&shares_t_for_recon);
                let reconstructed_r_2t = ShamirSecretSharing::recover_secret(&shares_2t_for_recon);

                // if the reconstruction fails, broadcast false
                let mut output_message = OutputMessage::new(self.id, true);

                if reconstructed_r_t.is_err() || reconstructed_r_2t.is_err() {
                    output_message = OutputMessage::new(self.id, false);
                }
                // (6) Check that their 0-evaluation is the same.
                // This means checking if the reconstructed values are equal.
                let verify = reconstructed_r_t.unwrap() == reconstructed_r_2t.unwrap();

                if !verify {
                    // if the verification fails, broadcast false(aka. Abort)
                    output_message = OutputMessage::new(self.id, false);
                }

                // Serializing the output message and wrapping it into a generic message.
                let mut bytes_out_message = Vec::new();
                output_message
                    .serialize_compressed(&mut bytes_out_message)
                    .map_err(RanDouShaError::ArkSerialization)?;
                let generic_message = RanDouShaMessage::new(
                    self.id,
                    RanDouShaMessageType::OutputMessage,
                    &bytes_out_message,
                );
                let bytes_generic_message = bincode::serialize(&generic_message)
                    .map_err(RanDouShaError::SerializationError)?;

                // if the verification succeeds, broadcast true (aka. OK)
                network
                    .lock()
                    .await
                    .broadcast(&bytes_generic_message)
                    .await
                    .map_err(RanDouShaError::NetworkError)?;
            }
        }

        Ok(())
    }

    /// Implements step (4) (5) of Protocol RanDouSha
    /// Wait to receive broadcast of output message from other party.
    /// Return [r_1]_t ... [r_t+1]_t & [r_1]_2t ... [r_t+1]_2t only if one receives more than
    /// (n - (t+1)) Ok message.
    pub async fn output_handler(
        &mut self,
        message: &OutputMessage,
        params: &RanDouShaParams,
    ) -> Result<(Vec<ShamirSecretSharing<F>>, Vec<ShamirSecretSharing<F>>), RanDouShaError> {
        // abort randousha once received the abort message
        if message.msg == false {
            return Err(RanDouShaError::Abort);
        }
        let binding = self.get_or_create_store(params).await;
        let mut store = binding.lock().await;
        // sender already exists, wait for more messages
        if store.received_ok_msg.contains(&message.sender_id) {
            return Err(RanDouShaError::WaitForOk);
        }
        store.received_ok_msg.push(message.sender_id);
        // wait for (n-(t+1)) Ok messages
        if store.received_ok_msg.len() < params.n_parties - (params.threshold + 1) {
            return Err(RanDouShaError::WaitForOk);
        }

        // create vector for share [r_1]_t ... [r_t+1]_t
        let output_r_t = store.computed_r_shares_degree_t[0..params.threshold + 1].to_vec();
        // create vector for share [r_1]_2t ... [r_t+1]_2t
        let output_r_2t = store.computed_r_shares_degree_2t[0..params.threshold + 1].to_vec();

        Ok((output_r_t, output_r_2t))
    }

    pub async fn process<N>(
        &mut self,
        message: &RanDouShaMessage,
        params: &RanDouShaParams,
        network: Arc<Mutex<N>>,
    ) -> Result<(), RanDouShaError>
    where
        N: Network,
    {
        match message.msg_type {
            messages::RanDouShaMessageType::InitMessage => {
                let init_message =
                    InitMessage::<F>::deserialize_compressed(message.payload.as_slice())
                        .map_err(RanDouShaError::ArkDeserialization)?;
                self.init_handler(&init_message, params, network).await?
            }
            messages::RanDouShaMessageType::OutputMessage => {
                let output_message =
                    OutputMessage::deserialize_compressed(message.payload.as_slice())
                        .map_err(RanDouShaError::ArkDeserialization)?;
                self.output_handler(&output_message, params).await?;
            }
            messages::RanDouShaMessageType::ReconstructMessage => {
                let reconstr_message = ark_serialize::CanonicalDeserialize::deserialize_compressed(
                    message.payload.as_slice(),
                )
                .map_err(RanDouShaError::ArkDeserialization)?;
                self.reconstruction_handler(&reconstr_message, params, network)
                    .await?;
            }
        }
        Ok(())
    }
}
