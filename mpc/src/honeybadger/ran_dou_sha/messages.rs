use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use stoffelmpc_common::share::shamir::ShamirSecretSharing;
use stoffelmpc_network::Message;

#[derive(Serialize, Deserialize)]
pub enum RanDouShaMessageType {
    InitMessage,
    ReconstructMessage,
    OutputMessage,
}

#[derive(Serialize, Deserialize)]
pub struct RanDouShaMessage {
    pub msg_type: RanDouShaMessageType,
    pub payload: Vec<u8>,
}

impl Message for RanDouShaMessage {}

/// Message that arrives at the beginning of the reconstruction phase. In the reconstruction phase,
/// the parties first receive shares of `r` to be able to reconstruct the value of r.
#[derive(CanonicalDeserialize, CanonicalSerialize)]
pub struct ReconstructionMessage<F: FftField> {
    pub r_share_deg_t: ShamirSecretSharing<F>,
    pub r_share_deg_2t: ShamirSecretSharing<F>,
}

impl<F> ReconstructionMessage<F>
where
    F: FftField,
{
    /// Creates a message for the reconstruction phase.
    pub fn new(r_deg_t: ShamirSecretSharing<F>, r_deg_2t: ShamirSecretSharing<F>) -> Self {
        Self {
            r_share_deg_t: r_deg_t,
            r_share_deg_2t: r_deg_2t,
        }
    }
}

impl<F> Message for ReconstructionMessage<F> where F: FftField {}

#[derive(CanonicalDeserialize, CanonicalSerialize)]
pub struct InitMessage<F: FftField> {
    pub s_shares_deg_t: Vec<ShamirSecretSharing<F>>,
    pub s_shares_deg_2t: Vec<ShamirSecretSharing<F>>,
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
