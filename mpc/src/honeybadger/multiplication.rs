use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use stoffelmpc_network::{Message, PartyId, SessionId};

/// Message that contains the result of opening the subtraction of a beaver triple element and the
/// input of the multiplication.
#[derive(CanonicalDeserialize, CanonicalSerialize)]
pub struct OpenMultMessage<F: FftField>(Vec<F>);

impl<F> OpenMultMessage<F>
where
    F: FftField,
{
    /// Creates a new instance of [`OpenMultMessage`].
    ///
    /// The content of the message is either the subtraction `triple.a - x` or `triple.b - y`.
    pub fn new(subtraction_values: Vec<F>) -> Self {
        Self(subtraction_values)
    }

    pub fn values(self) -> Vec<F> {
        self.0
    }
}

#[derive(Serialize, Deserialize)]
pub enum MultMessageType {
    FirstOpen,
    SecondOpen,
}

/// Generic message for the multiplication protocol.
#[derive(Serialize, Deserialize)]
pub struct MultMessage {
    /// ID of the sender of the message.
    pub sender: PartyId,

    /// Session ID of the current instance of the protocol.
    pub session_id: SessionId,

    /// Payload contained in the message.
    ///
    /// This payload is a serialized field element containing either `triple.a - x` or
    /// `triple.b - y`.
    pub payload: Vec<u8>,

    /// Content type of the message.
    pub message_type: MultMessageType,
}

impl MultMessage {
    /// Creates a new generic multiplication message [`MultMessage`].
    pub fn new(
        sender: PartyId,
        session_id: SessionId,
        msg_type: MultMessageType,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            sender,
            session_id,
            payload,
            message_type: msg_type,
        }
    }
}

impl Message for MultMessage {
    fn sender_id(&self) -> PartyId {
        self.sender
    }

    fn bytes(&self) -> &[u8] {
        &self.payload
    }
}

pub enum MultProtocolState {
    NotInitialized,
    Finished,
    NotFinished,
}
