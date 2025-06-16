pub mod fake_network;

use ark_ff::Field;
use serde::{Deserialize, Serialize};
use std::sync::mpsc::Receiver;
use thiserror::Error;

/// Error type for network related issues.
#[derive(Error, Debug, PartialEq)]
pub enum NetworkError {
    #[error("The message was not sent correctly")]
    SendError,
    /// The request reached a time out.
    #[error("timeout reached.")]
    Timeout,
    #[error("the party with ID {0:?} is not in the network")]
    PartyNotFound(PartyId),
}

/// Type to identify a party in a protocol.
pub type PartyId = usize;

/// Type to identify a session.
pub type SessionId = usize;

/// Time that the network needs to wait until the operation returns a timeout.
pub type Timeout = usize;

/// Trait for messages sent in a protocol.
pub trait Message: Serialize + for<'a> Deserialize<'a> + Sized + 'static {
    /// Returns the ID of the sender of the message.
    fn sender_id(&self) -> PartyId;
    /// Returns the message as little endiand bytes.
    fn bytes(&self) -> &[u8];
}

/// Trait that represents a network used to communicate messages during the execution of a
/// protocol.
pub trait Network {
    /// Type of the node in the network.
    type NodeType: Node;
    /// Configuration of the network.
    type NetworkConfig;
    /// Send a message through the network to the given party. The function returns the number of
    /// bytes sent to the recipient.
    fn send(&self, recipient: PartyId, message: &[u8]) -> Result<usize, NetworkError>;
    /// Broadcasts a message to all the parties connected to the network. The function returns the
    /// number of bytes broadcasted to the network.
    fn broadcast(&self, message: &[u8]) -> Result<usize, NetworkError>;
    /// Returns the participants connected to this network.
    fn parties(&self) -> Vec<&Self::NodeType>;
    /// Returns mutable references to the participants connected to this network.
    fn parties_mut(&mut self) -> Vec<&mut Self::NodeType>;
    /// Returns the configuration of the network.
    fn config(&self) -> &Self::NetworkConfig;
    /// Returns the node with the given ID.
    fn node(&self, id: PartyId) -> Option<&Self::NodeType>;
}

/// Participant of an MPC protocol.
pub trait Node {
    /// Returns the ID of this node.
    fn id(&self) -> PartyId;
    /// Returns the ID of this node as a field element for protocol specific usage.
    fn scalar_id<F: Field>(&self) -> F;

    fn new(id: PartyId, receiver: Receiver<Vec<u8>>) -> Self;
}
