use ark_ff::FftField;
use stoffelmpc_network::{PartyId, SessionId};

use super::{triple_generation::ShamirBeaverTriple, DoubleShamirShare};

pub enum HoneyBadgerMessageType {
    DouShaFinished,
    TripleGenFinished,
}

pub struct HoneyBadgerMessage {
    pub session_id: SessionId,
    pub sender: PartyId,
    pub payload: Vec<u8>,
    pub message_type: HoneyBadgerMessageType,
}

pub struct DouShaFinishedMessage<F: FftField> {
    pub session_id: SessionId,
    pub sender: PartyId,
    pub faulty_dou_sha: Vec<DoubleShamirShare<F>>,
}

pub struct RanDouShaFinishedMessage<F: FftField> {
    pub session_id: SessionId,
    pub sender: PartyId,
    pub ran_dou_shares: Vec<DoubleShamirShare<F>>,
}

pub struct TripleGenFinishedMessage<F: FftField> {
    pub session_id: SessionId,
    pub sender: PartyId,
    pub triples: Vec<ShamirBeaverTriple<F>>,
}
