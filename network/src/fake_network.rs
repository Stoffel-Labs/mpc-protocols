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
        for id in 0..n_nodes {
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
        self.node_channels
            .get(&recipient)
            .unwrap()
            .send(message.to_vec())
            .map_err(|_| NetworkError::SendError)?;
        Ok(message.len())
    }

    fn node(&self, id: PartyId) -> Option<&Self::NodeType> {
        self.nodes.iter().find(|node| node.id == id)
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
    id: PartyId,
    receiver_channel: Receiver<Vec<u8>>,
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
