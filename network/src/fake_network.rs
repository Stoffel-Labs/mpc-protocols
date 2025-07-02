use async_trait::async_trait;
use futures::future::join_all;
use tokio::sync::mpsc::{self, Receiver, Sender};

use crate::{Network, NetworkError, Node, PartyId};

/// Simulates a network for testing purposes. The channels for the network are simulated as `tokio`
/// channels.
pub struct FakeNetwork {
    /// Fake nodes channels to send information to the network
    node_channels: Vec<Sender<Vec<u8>>>,
    /// Configuration of the network.
    config: FakeNetworkConfig,
    /// Fake nodes connected to the network
    nodes: Vec<FakeNode>,
}

impl FakeNetwork {
    /// Creates a new fake network for testing using the given number of nodes and configuration.
    pub fn new(n_nodes: usize, config: FakeNetworkConfig) -> (Self, Vec<Receiver<Vec<u8>>>) {
        let mut node_channels = Vec::new();
        let mut nodes = Vec::new();
        let mut receivers = Vec::new();
        for id in 1..=n_nodes {
            let (sender, receiver) = mpsc::channel(config.channel_buff_size);
            node_channels.push(sender);
            nodes.push(FakeNode::new(id));
            receivers.push(receiver);
        }
        (
            Self {
                node_channels,
                config,
                nodes,
            },
            receivers,
        )
    }
}

#[async_trait]
impl Network for FakeNetwork {
    type NodeType = FakeNode;
    type NetworkConfig = FakeNetworkConfig;

    async fn send(&self, recipient: PartyId, message: &[u8]) -> Result<usize, NetworkError> {
        if let Some(sender) = self.node_channels.get(recipient - 1) {
            sender
                .send(message.to_vec())
                .await
                .map_err(|_| NetworkError::SendError)?;
            Ok(message.len())
        } else {
            Err(NetworkError::PartyNotFound(recipient))
        }
    }

    fn node(&self, id: PartyId) -> Option<&Self::NodeType> {
        self.nodes.iter().find(|node| node.id() == id)
    }

    fn node_mut(&mut self, id: PartyId) -> Option<&mut Self::NodeType> {
        self.nodes.iter_mut().find(|node| node.id == id)
    }

    async fn broadcast(&self, message: &[u8]) -> Result<usize, NetworkError> {
        let msg = message.to_vec();

        let futures = self
            .node_channels
            .iter()
            .map(|sender| sender.send(msg.clone()));

        let results = join_all(futures).await;

        if results.iter().any(|r| r.is_err()) {
            return Err(NetworkError::SendError);
        }

        Ok(message.len())
    }

    fn parties(&self) -> Vec<&Self::NodeType> {
        self.nodes.iter().collect()
    }

    fn parties_mut(&mut self) -> Vec<&mut Self::NodeType> {
        self.nodes.iter_mut().collect()
    }

    fn config(&self) -> &Self::NetworkConfig {
        &self.config
    }
}

/// Represents a node in the FakeNetwork.
pub struct FakeNode {
    /// The id of the node.
    id: PartyId,
    // The channel in which the party receives the messages.
    //receiver_channel: Receiver<Vec<u8>>,
}

impl FakeNode {
    /// Creates a new fake node.
    pub fn new(id: PartyId) -> Self {
        Self {
            id,
            //receiver_channel: receiver,
        }
    }
}

impl Node for FakeNode {
    fn id(&self) -> PartyId {
        self.id
    }

    fn scalar_id<F: ark_ff::Field>(&self) -> F {
        F::from(self.id as u64)
    }
}

/// Configuration for the fake network.
pub struct FakeNetworkConfig {
    /// Size of the buffer for the channels in the fake network.
    pub channel_buff_size: usize,
}

impl FakeNetworkConfig {
    /// Creates a new configuration for the fake network.
    pub fn new(channel_buff_size: usize) -> Self {
        Self { channel_buff_size }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::Mutex;

    use super::*;
    use crate::Network;

    #[tokio::test]
    async fn test_fake_network_new() {
        let n_nodes = 5;
        let config = FakeNetworkConfig::new(100);
        let (network, _) = FakeNetwork::new(n_nodes, config);

        let channels = network.node_channels.clone();

        assert_eq!(network.nodes.len(), n_nodes);
        assert_eq!(channels.len(), n_nodes);

        for i in 1..=n_nodes {
            assert!(channels.get(i - 1).is_some());
            assert!(network.node(i).is_some());
            assert_eq!(network.node(i).unwrap().id(), i);
        }
    }

    #[tokio::test]
    async fn test_fake_network_send_and_receive() {
        let n_nodes = 3;
        let config = FakeNetworkConfig::new(100);
        let (network, mut receivers) = FakeNetwork::new(n_nodes, config);

        let sender_id = 1;
        let recipient_id = 2;
        let message = b"hello";

        // Send a message from the perspective of the network
        let send_result = network.send(recipient_id, message).await;
        assert!(send_result.is_ok());
        assert_eq!(send_result.unwrap(), message.len());

        // Get the recipient node and try to receive the message
        let recipient_node = &mut receivers[recipient_id - 1];
        let received_message_result = recipient_node.try_recv();

        assert!(received_message_result.is_ok());
        assert_eq!(received_message_result.unwrap(), message.to_vec());

        // Ensure the other node didn't receive the message
        let other_node1 = &mut receivers[sender_id - 1];
        let other_received_message_result = other_node1.try_recv();
        assert!(other_received_message_result.is_err()); // Should be empty

        let other_node2 = &mut receivers[2];
        let other_received_message_result = other_node2.try_recv();
        assert!(other_received_message_result.is_err()); // Should be empty
    }

    #[tokio::test]
    async fn test_fake_network_broadcast() {
        let n_nodes = 3;
        let config = FakeNetworkConfig::new(100);
        let (network, mut receivers) = FakeNetwork::new(n_nodes, config);
        let network = Arc::new(Mutex::new(network));

        let message = b"broadcast";

        let network = network.lock().await;
        let broadcast_result = network.broadcast(message).await;
        assert!(broadcast_result.is_ok());
        assert_eq!(broadcast_result.unwrap(), message.len());

        // Verify all nodes received the message
        for i in 0..n_nodes {
            let node_recv = &mut receivers[i];
            let received_message_result = node_recv.try_recv();
            assert!(received_message_result.is_ok());
            assert_eq!(received_message_result.unwrap(), message.to_vec());
        }
    }

    #[test]
    fn test_fake_node_id_and_scalar_id() {
        use ark_bls12_381::Fr;

        //let (sender, receiver) = mpsc::channel(100);
        let node_id = 123;
        let node = FakeNode::new(node_id);

        assert_eq!(node.id(), node_id);
        let scalar_id: Fr = node.scalar_id();
        assert_eq!(scalar_id, Fr::from(node_id as u64));
        //drop(sender);
    }

    // #[tokio::test]
    // async fn test_network_error_on_send_failure() {
    //     let n_nodes = 2;
    //     let config = FakeNetworkConfig::new(100);
    //     let (network, _) = FakeNetwork::new(n_nodes, config);
    //     // The network needs to be mutable to modify its `node_channels` HashMap
    //     let network = Arc::new(Mutex::new(network));

    //     let recipient_id = 1;
    //     let message = b"test";

    //     // To simulate a send failure with an unbounded mpsc channel:
    //     // The most direct way is to remove the recipient from the network's map.
    //     let network = network.lock().await;

    //     // This scope is necessary so that the variable channels is dropped and network is accessed again later
    //     // without blocking the thread.
    //     {
    //         let mut channels = network.node_channels.clone();
    //         let removed_recipient = channels.remove(&recipient_id);
    //         assert!(removed_recipient.is_some(), "should exist for recipient_id");
    //     }

    //     // Now that the recipient is removed, the send should fail
    //     let send_result = network.send(recipient_id, message).await;
    //     assert!(
    //         send_result.is_err(),
    //         "Send should fail after sender is removed."
    //     );
    //     assert_eq!(
    //         send_result.unwrap_err(),
    //         NetworkError::PartyNotFound(recipient_id)
    //     );
    // }
}
