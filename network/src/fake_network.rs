use std::{
    collections::HashMap,
    sync::mpsc::{self, Receiver, Sender},
};

use crate::{Network, NetworkError, Node, PartyId};

pub struct FakeNetwork {
    /// Fake nodes channels to send information to the network
    node_channels: HashMap<PartyId, Sender<Vec<u8>>>,
    /// Configuration of the network.
    config: FakeNetworkConfig,
    /// Fake nodes connected to the network
    nodes: Vec<FakeNode>,
}

impl FakeNetwork {
    pub fn new(n_nodes: usize) -> Self {
        let mut node_channels = HashMap::new();
        let mut nodes = Vec::new();
        for id in 1..n_nodes + 1 {
            let (sender, receiver) = mpsc::channel();
            node_channels.insert(id, sender);
            let node = FakeNode::new(id, receiver);
            nodes.push(node);
        }
        let config = FakeNetworkConfig;
        Self {
            node_channels,
            config,
            nodes,
        }
    }
}

impl Network for FakeNetwork {
    type NodeType = FakeNode;
    type NetworkConfig = FakeNetworkConfig;

    fn send(&self, recipient: PartyId, message: &[u8]) -> Result<usize, NetworkError> {
        let node = self.node_channels.get(&recipient);

        if node.is_none() {
            return Err(NetworkError::PartyNotFound(recipient));
        }

        node.unwrap()
            .send(message.to_vec())
            .map_err(|_| NetworkError::SendError)?;
        Ok(message.len())
    }

    fn node(&self, id: PartyId) -> Option<&Self::NodeType> {
        self.nodes.iter().find(|node| node.id() == id)
    }

    fn broadcast(&self, message: &[u8]) -> Result<usize, NetworkError> {
        for node in self.node_channels.values() {
            node.send(message.to_vec())
                .map_err(|_| NetworkError::SendError)?;
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

pub struct FakeNode {
    pub id: PartyId,
    pub receiver_channel: Receiver<Vec<u8>>,
}

impl FakeNode {
    pub fn new(id: PartyId, receiver: Receiver<Vec<u8>>) -> Self {
        Self {
            id,
            receiver_channel: receiver,
        }
    }
}

impl Node for FakeNode {
    fn id(&self) -> crate::PartyId {
        self.id
    }

    fn scalar_id<F: ark_ff::Field>(&self) -> F {
        F::from(self.id as u64)
    }
}

pub struct FakeNetworkConfig;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Network;

    #[test]
    fn test_fake_network_new() {
        let n_nodes = 5;
        let network: FakeNetwork = FakeNetwork::new(n_nodes);

        assert_eq!(network.nodes.len(), n_nodes);
        assert_eq!(network.node_channels.len(), n_nodes);

        for i in 0..n_nodes {
            assert!(network.node_channels.contains_key(&(i + 1)));
            assert!(network.node(i + 1).is_some());
            assert_eq!(network.node(i + 1).unwrap().id(), i + 1);
        }
    }

    #[test]
    fn test_fake_network_send_and_receive() {
        let n_nodes = 3;
        let network: FakeNetwork = FakeNetwork::new(n_nodes);

        let sender_id = 1;
        let recipient_id = 2;
        let message = b"hello";

        // Send a message from the perspective of the network
        let send_result = network.send(recipient_id, message);
        assert!(send_result.is_ok());
        assert_eq!(send_result.unwrap(), message.len());

        // Get the recipient node and try to receive the message
        let recipient_node = network.node(recipient_id).unwrap();
        let received_message_result = recipient_node.receiver_channel.try_recv();

        assert!(received_message_result.is_ok());
        assert_eq!(received_message_result.unwrap(), message.to_vec());

        // Ensure the other node didn't receive the message
        let other_node1 = network.node(sender_id).unwrap();
        let other_received_message_result = other_node1.receiver_channel.try_recv();
        assert!(other_received_message_result.is_err()); // Should be empty

        let other_node2 = network.node(3).unwrap();
        let other_received_message_result = other_node2.receiver_channel.try_recv();
        assert!(other_received_message_result.is_err()); // Should be empty
    }

    #[test]
    fn test_fake_network_broadcast() {
        let n_nodes = 3;
        let network: FakeNetwork = FakeNetwork::new(n_nodes);
        let message = b"broadcast";

        let broadcast_result = network.broadcast(message);
        assert!(broadcast_result.is_ok());
        assert_eq!(broadcast_result.unwrap(), message.len());

        // Verify all nodes received the message
        for i in 0..n_nodes {
            let node = network.node(i + 1).unwrap();
            let received_message_result = node.receiver_channel.try_recv();
            assert!(received_message_result.is_ok());
            assert_eq!(received_message_result.unwrap(), message.to_vec());
        }
    }

    #[test]
    fn test_fake_node_id_and_scalar_id() {
        use ark_bls12_381::Fr;

        let (sender, receiver) = mpsc::channel();
        let node_id = 123;
        let node = FakeNode::new(node_id, receiver);

        assert_eq!(node.id(), node_id);
        let scalar_id: Fr = node.scalar_id();
        assert_eq!(scalar_id, Fr::from(node_id as u64));
        drop(sender);
    }

    #[test]
    fn test_network_error_on_send_failure() {
        let n_nodes = 2;
        // The network needs to be mutable to modify its `node_channels` HashMap
        let mut network: FakeNetwork = FakeNetwork::new(n_nodes);

        let recipient_id = 1;
        let message = b"test";

        // To simulate a send failure with an unbounded mpsc channel:
        // The most direct way is to remove the recipient from the network's map.
        let removed_recipient = network.node_channels.remove(&recipient_id);
        assert!(removed_recipient.is_some(), "should exist for recipient_id");

        // Now that the recipient is removed, the send should fail
        let send_result = network.send(recipient_id, message);
        assert!(
            send_result.is_err(),
            "Send should fail after sender is removed."
        );
        assert_eq!(
            send_result.unwrap_err(),
            NetworkError::PartyNotFound(recipient_id)
        );
    }
}
