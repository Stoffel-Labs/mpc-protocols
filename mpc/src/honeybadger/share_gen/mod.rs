use serde::{Deserialize, Serialize};

pub mod share_gen;

/// Types for all the possible messages sent during the Random Single Sharing protocol.
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub enum RanShaMessageType {
    /// Tag for the message received by the reconstruction handler.
    ReconstructMessage,
    /// Tag for the message received by the output handler.
    OutputMessage,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum RanShaPayload {
    /// Contains the share of r sent during reconstruction.
    Reconstruct(Vec<u8>),
    /// Output message confirming reconstruction success or failure.
    Output(bool),
}

/// Message sent in the Random Single Sharing protocol.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RanShaMessage {
    /// ID of the sender of the message.
    pub sender_id: usize,
    /// Type of the message according to the handler.
    pub msg_type: RanShaMessageType,
    /// Session ID of the execution.
    pub session_id: usize,
    /// Contents of the message.
    pub payload: RanShaPayload,
}

impl RanShaMessage {
    pub fn new(
        sender_id: usize,
        msg_type: RanShaMessageType,
        session_id: usize,
        payload: RanShaPayload,
    ) -> Self {
        Self {
            sender_id,
            msg_type,
            session_id,
            payload,
        }
    }
}
