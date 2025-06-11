use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use stoffelmpc_common::share::shamir::ShamirSecretSharing;
use stoffelmpc_network::Message;

/// Message that arrives to the initialization handler.
#[derive(CanonicalDeserialize, CanonicalSerialize)]
pub struct InitMessage<F: FftField> {
    /// Shares of s of degree `t`.
    pub s_shares_deg_t: Vec<ShamirSecretSharing<F>>,
    /// Shares of s of degree `2t`.
    pub s_shares_deg_2t: Vec<ShamirSecretSharing<F>>,
}

impl<F> Message for InitMessage<F> where F: FftField {}

/// Message that arrives at the beginning of the reconstruction phase. In the reconstruction phase,
/// the parties first receive shares of `r` to be able to reconstruct the value of r.
#[derive(CanonicalDeserialize, CanonicalSerialize)]
pub struct ReconstructionMessage<F: FftField> {
    pub(crate) r_deg_t: ShamirSecretSharing<F>,
    pub(crate) r_deg_2t: ShamirSecretSharing<F>,
}

impl<F> Message for ReconstructionMessage<F> where F: FftField {}

impl<F> ReconstructionMessage<F>
where
    F: FftField,
{
    /// Creates a message for the reconstruction phase.
    pub fn new(r_deg_t: ShamirSecretSharing<F>, r_deg_2t: ShamirSecretSharing<F>) -> Self {
        Self { r_deg_t, r_deg_2t }
    }
}

/// Output message
/// false for ABORT, True for OK
#[derive(Debug, Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct OutputMessage {
    pub id: usize,
    pub msg: bool,
}
impl Message for OutputMessage {}

impl OutputMessage {
    pub fn new(id: usize, msg: bool) -> Self {
        Self { id, msg }
    }
}
