use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use stoffelnet::network_utils::PartyId;

use crate::{common::share::shamir::NonRobustShare, honeybadger::SessionId};


#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum RanDouShaPayload {
    Reconstruct(Vec<u8>),
    Output(bool),
}

/// Message sent in the Random Double Sharing protocol.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RanDouShaMessage {
    /// ID of the sender of the message.
    pub sender_id: PartyId,
    /// Session ID of the execution.
    pub session_id: SessionId,
    /// Contents of the message in bytes.
    pub payload: RanDouShaPayload,
}

impl RanDouShaMessage {
    pub fn new(
        sender_id: PartyId,
        session_id: SessionId,
        payload: RanDouShaPayload,
    ) -> Self {
        Self {
            sender_id,
            session_id,
            payload,
        }
    }
}

/// Message that arrives at the beginning of the reconstruction phase. In the reconstruction phase,
/// the parties first receive shares of `r` to be able to reconstruct the value of r. This message
/// represents the payload of a Reconstruction message.
#[derive(CanonicalDeserialize, CanonicalSerialize)]
pub struct ReconstructionMessage<F: FftField> {
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
    pub fn new(r_deg_t: NonRobustShare<F>, r_deg_2t: NonRobustShare<F>) -> Self {
        Self {
            r_share_deg_t: r_deg_t,
            r_share_deg_2t: r_deg_2t,
        }
    }
}
