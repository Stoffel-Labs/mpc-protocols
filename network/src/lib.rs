pub mod fake_network;

use ark_ff::Field;
use async_trait::async_trait;
use thiserror::Error;

/// Error type for network related issues.
#[derive(Error, Debug, PartialEq)]
pub enum NetworkError {
    #[error("The message was not sent correctly")]
    SendError,
    /// The request reached a time out.
    #[error("timeout reached.")]
    Timeout,
    /// The party is not found in the network.
    #[error("the party with ID {0:?} is not in the network")]
    PartyNotFound(PartyId),
    #[error("the client with ID {0:?} is not connected")]
    ClientNotFound(ClientId),
}

/// Type to identify a party in a protocol.
pub type PartyId = usize;
pub type ClientId = usize;

/// Time that the network needs to wait until the operation returns a timeout.
pub type Timeout = usize;

/// Trait that represents a network used to communicate messages during the execution of a
/// protocol.
#[async_trait]
pub trait Network {
    /// Type of the node in the network.
    type NodeType: Node;
    /// Configuration of the network.
    type NetworkConfig;
    /// Send a message through the network to the given party. The function returns the number of
    /// bytes sent to the recipient.
    async fn send(&self, recipient: PartyId, message: &[u8]) -> Result<usize, NetworkError>;
    /// Broadcasts a message to all the parties connected to the network. The function returns the
    /// number of bytes broadcasted to the network.
    async fn broadcast(&self, message: &[u8]) -> Result<usize, NetworkError>;
    /// Returns the participants connected to this network.
    fn parties(&self) -> Vec<&Self::NodeType>;
    /// Returns mutable references to the participants connected to this network.
    fn parties_mut(&mut self) -> Vec<&mut Self::NodeType>;
    /// Returns the configuration of the network.
    fn config(&self) -> &Self::NetworkConfig;
    /// Returns the node with the given ID.
    fn node(&self, id: PartyId) -> Option<&Self::NodeType>;
    /// Returns a mutable reference of the node with the given ID.
    fn node_mut(&mut self, id: PartyId) -> Option<&mut Self::NodeType>;
    // --- server-to-client communication ---
    /// Send a message to a client.
    async fn send_to_client(&self, client: ClientId, message: &[u8])
        -> Result<usize, NetworkError>;
    
    /// Returns the connected clients.
    fn clients(&self) -> Vec<ClientId>;

    /// Checks whether a client is connected.
    fn is_client_connected(&self, client: ClientId) -> bool;
}

/// Participant of an MPC protocol.
pub trait Node: Send + Sync {
    /// Returns the ID of this node.
    fn id(&self) -> PartyId;
    /// Returns the ID of this node as a field element for protocol specific usage.
    fn scalar_id<F: Field>(&self) -> F;
}
