use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use stoffelmpc_common::share::shamir::ShamirSecretSharing;
use stoffelmpc_network::{Message, PartyId};

/// Types for the all the possible messages sent during the Random Double Sharing protocol.
#[derive(Serialize, Deserialize)]
pub enum RanDouShaMessageType {
    /// Tag for the message received by the initialization handler.
    InitMessage,
    /// Tag for the message received by the reconstruction handler.
    ReconstructMessage,
    /// Tag for the message received by the output handler.
    OutputMessage,
}

/// Message sent in the Random Double Sharing protocol.
#[derive(Serialize, Deserialize)]
pub struct RanDouShaMessage {
    /// Type of the message according to the handler.
    pub msg_type: RanDouShaMessageType,
    /// Contents of the message in bytes.
    pub payload: Vec<u8>,
}

impl Message for RanDouShaMessage {}

/// Message that arrives at the beginning of the reconstruction phase. In the reconstruction phase,
/// the parties first receive shares of `r` to be able to reconstruct the value of r.
#[derive(CanonicalDeserialize, CanonicalSerialize)]
pub struct ReconstructionMessage<F: FftField> {
    /// ID of the sender of the message.
    pub sender_id: PartyId,
    /// Share of r of degree t.
    pub r_share_deg_t: ShamirSecretSharing<F>,
    /// Share of r of degree 2t.
    pub r_share_deg_2t: ShamirSecretSharing<F>,
}

impl<F> ReconstructionMessage<F>
where
    F: FftField,
{
    /// Creates a message for the reconstruction phase.
    pub fn new(
        sender_id: PartyId,
        r_deg_t: ShamirSecretSharing<F>,
        r_deg_2t: ShamirSecretSharing<F>,
    ) -> Self {
        Self {
            sender_id,
            r_share_deg_t: r_deg_t,
            r_share_deg_2t: r_deg_2t,
        }
    }
}

impl<F> Message for ReconstructionMessage<F> where F: FftField {}

/// Message that represent the initialization message in the Random Double Sharing protocol.
#[derive(CanonicalDeserialize, CanonicalSerialize)]
pub struct InitMessage<F: FftField> {
    /// ID of the sender of the message.
    pub sender_id: PartyId,
    /// Shares of s of degree t provided as input for the protocol.
    pub s_shares_deg_t: Vec<ShamirSecretSharing<F>>,
    /// Shares of s of degree 2t provided as input for the protocol.
    pub s_shares_deg_2t: Vec<ShamirSecretSharing<F>>,
}

/// This struct represents an output message in the Random Double Sharing protocol.
/// The message contains a boolean that is `false` if the protocol abors and `true` if the
/// protocol finishes correctly.
#[derive(Debug, Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct OutputMessage {
    /// ID of the sender of the message.
    pub sender_id: PartyId,
    /// Status of the protocol. If this field is `false`, this means that the protocol aborted,
    /// otherwise, the this field will have the value `true`.
    pub msg: bool,
}

impl Message for OutputMessage {}

impl OutputMessage {
    /// Constructs a new output message.
    pub fn new(sender_id: PartyId, msg: bool) -> Self {
        Self { sender_id, msg }
    }
}
