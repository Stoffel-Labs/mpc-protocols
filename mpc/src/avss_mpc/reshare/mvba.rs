use crate::avss_mpc::AvssSessionId;

#[derive(thiserror::Error, Debug)]
pub enum MbvaError {}

/// Message sent during the MBVA protocol.
pub struct MbvaMessage {
    /// Session ID of the instance for this message.
    session_id: AvssSessionId,
    /// Message type.
    msg_type: MbvaMsgType,
    /// Contents of the message.
    bytes: Vec<u8>,
}

/// Type of the message sent in a MBVA protocol.
pub struct MbvaMsgType;

/// Store for a party in the MBVA protocol.
pub struct MbvaStore;

/// An node executing the MBVA protocol.
pub struct MbvaNode;
