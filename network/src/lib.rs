use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Error type for network related issues.
#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("the participant is not connected.")]
    NotConnected,
}

/// Type to identify a party in a protocol.
pub type PartyId = usize;

/// Trait for messages sent in a protocol.
pub trait Message: CanonicalDeserialize + CanonicalSerialize {}

/// Trait that represents a network used to communicate messages during the execution of a
/// protocol.
pub trait Network {
    /// Send a message through the network to the given party. The function returns the number of
    /// bytes sent to the recipient.
    fn send(&self, recipient: PartyId, message: impl Message) -> Result<usize, NetworkError>;
    /// Broadcasts a message to all the parties connected to the network. The function returns the
    /// number of bytes broadcasted to the network.
    fn broadcast(&self, message: impl Message) -> Result<usize, NetworkError>;
    /// Returns the ID of the participants connected to this network.
    fn party_ids(&self) -> Vec<&PartyId>;
}
