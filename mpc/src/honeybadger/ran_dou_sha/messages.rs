use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use stoffelmpc_network::{Message, PartyId};

use crate::common::share::shamir::NonRobustShare;

/// Types for the all the possible messages sent during the Random Double Sharing protocol.
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum RanDouShaMessageType {
    /// Tag for the message received by the initialization handler.
    InitMessage,
    /// Tag for the message received by the reconstruction handler.
    ReconstructMessage,
    /// Tag for the message received by the output handler.
    OutputMessage,
}

/// Message sent in the Random Double Sharing protocol.
#[derive(Serialize, Deserialize, Debug)]
pub struct RanDouShaMessage {
    /// ID of the sender of the message.
    pub sender_id: PartyId,
    /// Type of the message according to the handler.
    pub msg_type: RanDouShaMessageType,
    /// Contents of the message in bytes.
    pub payload: Vec<u8>,
}

impl RanDouShaMessage {
    pub fn new(sender_id: PartyId, msg_type: RanDouShaMessageType, message_bytes: &[u8]) -> Self {
        Self {
            sender_id,
            msg_type,
            payload: message_bytes.to_vec(),
        }
    }
}

impl Message for RanDouShaMessage {
    fn sender_id(&self) -> PartyId {
        self.sender_id
    }

    fn bytes(&self) -> &[u8] {
        &self.payload
    }
}

/// Message that arrives at the beginning of the reconstruction phase. In the reconstruction phase,
/// the parties first receive shares of `r` to be able to reconstruct the value of r. This message
/// represents the payload of a Reconstruction message.
#[derive(CanonicalDeserialize, CanonicalSerialize)]
pub struct ReconstructionMessage<F: FftField> {
    /// ID of the sender of the message.
    pub sender_id: PartyId,
    /// Share of r of degree t.
    pub r_share_deg_t: NonRobustShare<F>,
    /// Share of r of degree 2t.
    pub r_share_deg_2t: NonRobustShare<F>,
}

impl<F> ReconstructionMessage<F>
where
    F: FftField,
{
    /// Creates a message for the reconstruction phase.
    pub fn new(
        sender_id: PartyId,
        r_deg_t: NonRobustShare<F>,
        r_deg_2t: NonRobustShare<F>,
    ) -> Self {
        Self {
            sender_id,
            r_share_deg_t: r_deg_t,
            r_share_deg_2t: r_deg_2t,
        }
    }
}

/// Message that represent the initialization message in the Random Double Sharing protocol. This
/// message represents a payload for the Initialization message.
#[derive(CanonicalDeserialize, CanonicalSerialize)]
pub struct InitMessage<F: FftField> {
    /// ID of the sender of the message.
    pub sender_id: PartyId,
    /// Shares of s of degree t provided as input for the protocol.
    pub s_shares_deg_t: Vec<NonRobustShare<F>>,
    /// Shares of s of degree 2t provided as input for the protocol.
    pub s_shares_deg_2t: Vec<NonRobustShare<F>>,
}

/// This struct represents an output message in the Random Double Sharing protocol.
/// The message contains a boolean that is `false` if the protocol abors and `true` if the
/// protocol finishes correctly. This message represents a payload for the Output message.
#[derive(Debug, Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct OutputMessage {
    /// ID of the sender of the message.
    pub sender_id: PartyId,
    /// Status of the protocol. If this field is `false`, this means that the protocol aborted,
    /// otherwise, the this field will have the value `true`.
    pub msg: bool,
}

impl OutputMessage {
    /// Constructs a new output message.
    pub fn new(sender_id: PartyId, msg: bool) -> Self {
        Self { sender_id, msg }
    }
}
