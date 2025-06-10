use ark_ff::FftField;
use stoffelmpc_common::share::shamir::ShamirSecretSharing;

/// Storage for the Random Double Sharing protocol.
/// TODO: We need to define if the store needs an `Arc` and `Mutex`. Also, for the moment we are
/// using vectors, but vectors may not be the correct struct for this. Feel free to change the
/// struct to the correct type as needed.
struct RanDouShaStore<F: FftField> {
    /// Vector that stores the received degree t shares of r.
    r_shares_degree_t: Vec<ShamirSecretSharing<F>>,
    /// Vector that sotres the received degree 2t shares of r.
    r_shares_degree_2t: Vec<ShamirSecretSharing<F>>,
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
    pub id: usize,
    /// Storage of the node.
    pub store: RanDouShaStore<F>,
}

impl<F> RanDouShaStore<F>
where
    F: FftField,
{
    fn init_handler() {
        todo!()
    }

    fn reconstruction_handler() {
        todo!()
    }

    fn output_handler() {
        todo!()
    }
}
