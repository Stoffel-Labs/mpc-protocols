mod fake_network;

use thiserror::Error;

/// Error type for network related issues.
#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("the participant is not connected.")]
    NotConnected,
    #[error("timeout reached.")]
    TimeOut,
}

/// Type to identify a party in a protocol.
pub type PartyId = usize;

/// Trait for messages sent in a protocol.
pub trait Message {}

/// Trait that represents a network used to communicate messages during the execution of a
/// protocol.
pub trait Network<N: Node> {
    /// Send a message through the network to the given party. The function returns the number of
    /// bytes sent to the recipient.
    fn send(&self, recipient: PartyId, message: impl Message) -> Result<usize, NetworkError>;
    /// Broadcasts a message to all the parties connected to the network. The function returns the
    /// number of bytes broadcasted to the network.
    fn broadcast(&self, message: impl Message) -> Result<usize, NetworkError>;
    /// Returns the ID of the participants connected to this network.
    fn parties(&self) -> Vec<N>;
}

pub trait Node {
    /// Returns the ID of this node.
    fn id(&self) -> PartyId;
}
