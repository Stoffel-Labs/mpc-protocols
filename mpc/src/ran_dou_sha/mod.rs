mod messages;

use ark_ff::FftField;
use messages::{InitMessage, ReconstructionMessage};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use stoffelmpc_common::{
    batch_recon::batch_recon::{apply_vandermonde, make_vandermonde},
    share::shamir::ShamirSecretSharing,
};
use stoffelmpc_network::{Network, NetworkError, PartyId};

/// Storage for the Random Double Sharing protocol.
pub struct RanDouShaStore<F: FftField> {
    /// Vector that stores the received degree t shares of r.
    pub r_shares_degree_t: HashMap<PartyId, ShamirSecretSharing<F>>,
    /// Vector that sotres the received degree 2t shares of r.
    pub r_shares_degree_2t: HashMap<PartyId, ShamirSecretSharing<F>>,
}

impl<F> RanDouShaStore<F>
where
    F: FftField,
{
    /// Creates a new empty store for the random double sharing node.
    pub fn empty() -> Self {
        Self {
            r_shares_degree_t: HashMap::new(),
            r_shares_degree_2t: HashMap::new(),
        }
    }
}

/// Parameters for the Random Double Share protocol.
pub struct RanDouShaParams {
    /// Number of parties involved in the protocol.
    pub n_parties: usize,
    /// Threshold of corrupted parties.
    pub threshold: usize,
}

/// Node representation for the Random Double Share protocol.
pub struct RanDouShaNode<F: FftField> {
    /// ID of the node.
    pub id: PartyId,
    /// Storage of the node.
    pub store: Arc<Mutex<RanDouShaStore<F>>>,
}

impl<F> RanDouShaNode<F>
where
    F: FftField,
{
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
    fn init_handler(
        &mut self,
        init_msg: &InitMessage<F>,
        params: &RanDouShaParams,
        network: &impl Network,
    ) -> Result<(), NetworkError> {
        // Creates a store for the node.
        let store = Arc::new(Mutex::new(RanDouShaStore::<F>::empty()));
        self.store = store;

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

        // The current party with index i sends the share [r_j] to the party P_j so that P_j can
        // reconstruct the value r_j.
        for party_id in network.party_ids() {
            let share_deg_t = ShamirSecretSharing::new(
                r_deg_t[*party_id],
                F::from(self.id as u64),
                params.threshold,
            );
            let share_deg_2t = ShamirSecretSharing::new(
                r_deg_2t[*party_id],
                F::from(self.id as u64),
                2 * params.threshold,
            );

            let reconst_message = ReconstructionMessage::new(share_deg_t, share_deg_2t);
            network.send(*party_id, reconst_message)?;
        }
        Ok(())
    }

    fn reconstruction_handler() {
        todo!()
    }

    fn output_handler() {
        todo!()
    }
}
