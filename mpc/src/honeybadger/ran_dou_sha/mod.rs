mod messages;

use crate::honeybadger::batch_recon::batch_recon::{apply_vandermonde, make_vandermonde};
use ark_ff::FftField;
use messages::{InitMessage, RanDouShaMessage, ReconstructionMessage};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use stoffelmpc_common::share::shamir::ShamirSecretSharing;

use stoffelmpc_network::{Network, NetworkError, Node, PartyId, SessionId};

/// Storage for the Random Double Sharing protocol.
#[derive(Clone)]
pub struct RanDouShaStore<F: FftField> {
    /// Vector that stores the received degree t shares of r.
    pub received_r_shares_degree_t: HashMap<PartyId, ShamirSecretSharing<F>>,
    /// Vector that stores the received degree 2t shares of r.
    pub received_r_shares_degree_2t: HashMap<PartyId, ShamirSecretSharing<F>>,
    pub computed_r_shares_degree_t: Vec<ShamirSecretSharing<F>>,
    pub computed_r_shares_degree_2t: Vec<ShamirSecretSharing<F>>,
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
        network: N,
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

                let reconst_message = ReconstructionMessage::new(share_deg_t, share_deg_2t);
                network.send(party.id(), reconst_message)?;
            }
        }
        Ok(())
    }

    fn reconstruction_handler() {
        todo!()
    }

    fn output_handler() {
        todo!()
    }

    fn process(&self, message: &RanDouShaMessage) {
        match message.msg_type {
            messages::RanDouShaMessageType::InitMessage => {
                // TODO: Deserialize payload, construct InitMessage instance, and call init
                // handler.
                todo!()
            }
            messages::RanDouShaMessageType::OutputMessage => {
                todo!()
            }
            messages::RanDouShaMessageType::ReconstructMessage => {
                todo!()
            }
        }
    }
}
