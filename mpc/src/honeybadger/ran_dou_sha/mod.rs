mod messages;

use crate::honeybadger::batch_recon::batch_recon::{apply_vandermonde, make_vandermonde};
use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, SerializationError};
use messages::{InitMessage, OutputMessage, RanDouShaMessage, ReconstructionMessage};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use stoffelmpc_common::share::shamir::ShamirSecretSharing;
use thiserror::Error;

use stoffelmpc_network::{Network, NetworkError, Node, PartyId, SessionId};
use thiserror::Error;

/// Error that occurs during the execution of the Random Double Share Error.
#[derive(Debug, Error)]
pub enum RanDouShaError {
    /// The error occurs when communicating using the network.
    #[error("there was an error in the network: {0:?}")]
    NetworkError(NetworkError),
    /// The error occurs while serializing/deserializing an object comming from the network.
    #[error("error while serializing/deserializing an object: {0:?}")]
    SerializationFailure(SerializationError),
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
pub struct RanDouShaParams {
    /// Number of parties involved in the protocol.
    pub n_parties: usize,
    /// Threshold of corrupted parties.
    pub threshold: usize,
    /// Session ID of the execution.
    pub session_id: SessionId,
}

/// Node representation for the Random Double Share protocol.
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
    fn get_or_create_store(&mut self, params: &RanDouShaParams) -> Arc<Mutex<RanDouShaStore<F>>> {
        let mut storage = self.store.lock().unwrap();
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
    fn init_handler<N, P>(
        &mut self,
        init_msg: &InitMessage<F>,
        params: &RanDouShaParams,
        network: &N,
    ) -> Result<(), NetworkError>
    where
        N: Network<P>,
        P: Node,
    {
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
        let store = self.get_or_create_store(params);
        store.lock().unwrap().computed_r_shares_degree_t = r_deg_t
            .iter()
            .map(|share_value| {
                ShamirSecretSharing::new(
                    share_value.clone(),
                    F::from(self.id as u64),
                    params.threshold,
                )
            })
            .collect();
        store.lock().unwrap().computed_r_shares_degree_2t = r_deg_2t
            .iter()
            .map(|share_value| {
                ShamirSecretSharing::new(
                    share_value.clone(),
                    F::from(self.id as u64),
                    params.threshold,
                )
            })
            .collect();

        // The current party with index i sends the share [r_j] to the party P_j so that P_j can
        // reconstruct the value r_j.
        for party in network.parties() {
            if party.id() > params.threshold + 1 && party.id() <= params.n_parties {
                let share_deg_t = ShamirSecretSharing::new(
                    r_deg_t[party.id()],
                    F::from(self.id as u64),
                    params.threshold,
                );
                let share_deg_2t = ShamirSecretSharing::new(
                    r_deg_2t[party.id()],
                    F::from(self.id as u64),
                    2 * params.threshold,
                );

                let reconst_message =
                    ReconstructionMessage::new(self.id, share_deg_t, share_deg_2t);
                network.send(party.id(), reconst_message)?;
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
    fn reconstruction_handler<N, P>(
        &mut self,
        rec_msg: &ReconstructionMessage<F>,
        params: &RanDouShaParams,
        network: &N,
    ) -> Result<(), NetworkError>
    where
        N: Network<P>,
        P: Node,
    {
        // --- Step (3) Implementation ---
        // (1) Store the received shares.
        // Each party receives a ReconstructionMessage. This message contains two ShamirSecretSharing objects:
        // one for degree t and one for degree 2t.
        // These shares originate from the *sender* of the message, but they are components of the 'r_j'

        let binding = self.get_or_create_store(params);
        let mut store = binding.lock().unwrap();

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

            //TODO: do we need to wait for all n shares?
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
                if reconstructed_r_t.is_err() || reconstructed_r_2t.is_err() {
                    network.broadcast(OutputMessage::new(self.id, false))?;
                }
                // (6) Check that their 0-evaluation is the same.
                // This means checking if the reconstructed values are equal.
                let verify = reconstructed_r_t.unwrap() == reconstructed_r_2t.unwrap();

                if !verify {
                    // if the verification fails, broadcast false(aka. Abort)
                    network.broadcast(OutputMessage::new(self.id, false))?;
                }

                // if the verification succeeds, broadcast true(aka. OK)
                network.broadcast(OutputMessage::new(self.id, true))?;
            }
        }

        Ok(())
    }

    /// Implements step (4) (5) of Protocol RanDouSha
    /// Wait to receive broadcast of output message from other party.
    /// Return [r_1]_t ... [r_t+1]_t & [r_1]_2t ... [r_t+1]_2t only if one receives more than
    /// (n - (t+1)) Ok message.
    fn output_handler(
        &mut self,
        message: &OutputMessage,
        params: &RanDouShaParams,
    ) -> Result<(Vec<ShamirSecretSharing<F>>, Vec<ShamirSecretSharing<F>>), RanDouShaError> {
        // abort randousha once received the abort message
        if msg.msg == false {
            return Err(RanDouShaError::Abort);
        }
        let binding = self.get_or_create_store(params);
        let mut store = binding.lock().unwrap();
        // sender already exists, wait for more messages
        if store.received_ok_msg.contains(&msg.id) {
            return Err(RanDouShaError::WaitForOk);
        }
        store.received_ok_msg.push(msg.id);
        // wait for (n-(t+1)) Ok messages
        if store.received_ok_msg.len() < params.n_parties - (params.threshold + 1) {
            return Err(RanDouShaError::WaitForOk);
        }

        // create vector for share [r_1]_t ... [r_t+1]_t
        let output_r_t = store
            .computed_r_shares_degree_t
            .iter()
            .copied()
            .filter(|share| share.id <= F::from((params.threshold + 1) as u64))
            .collect::<Vec<_>>();
        // create vector for share [r_1]_2t ... [r_t+1]_2t
        let output_r_2t = store
            .computed_r_shares_degree_2t
            .iter()
            .copied()
            .filter(|share| share.id <= F::from((params.threshold + 1) as u64))
            .collect::<Vec<_>>();

        return Ok((output_r_t, output_r_2t));
    }

    fn process<N, P>(
        &mut self,
        message: &RanDouShaMessage,
        params: &RanDouShaParams,
        network: &N,
    ) -> Result<(), RanDouShaError>
    where
        N: Network<P>,
        P: Node,
    {
        match message.msg_type {
            messages::RanDouShaMessageType::InitMessage => {
                let init_message =
                    InitMessage::<F>::deserialize_uncompressed(message.payload.as_slice())
                        .map_err(RanDouShaError::SerializationFailure)?;
                self.init_handler(&init_message, params, network)
                    .map_err(RanDouShaError::NetworkError)?;
            }
            messages::RanDouShaMessageType::OutputMessage => {
                let output_message =
                    OutputMessage::deserialize_uncompressed(message.payload.as_slice())
                        .map_err(RanDouShaError::SerializationFailure)?;
                self.output_handler(&output_message, params)?
            }
            messages::RanDouShaMessageType::ReconstructMessage => {
                let reconstr_message = ReconstructionMessage::<F>::deserialize_uncompressed(
                    message.payload.as_slice(),
                )
                .map_err(RanDouShaError::SerializationFailure)?;
                self.reconstruction_handler(&reconstr_message, params, network)
                    .map_err(RanDouShaError::NetworkError)?;
            }
        }
        Ok(())
    }
}
