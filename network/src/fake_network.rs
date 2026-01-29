use async_trait::async_trait;
use futures::future::join_all;
use std::collections::HashMap;
use tokio::sync::mpsc::{self, Receiver, Sender};

use stoffelnet::network_utils::{ClientId, Network, NetworkError, Node, PartyId};

/// Simulates a network for testing purposes. The channels for the network are simulated as `tokio`
/// channels.
#[derive(Clone)]
pub struct FakeInnerNetwork {
    /// Fake nodes channels to send information to the network
    node_channels: Vec<Vec<Sender<Vec<u8>>>>, // [sender][node] where sender = node | client.
    /// Configuration of the network.
    config: FakeNetworkConfig,
    /// Fake nodes connected to the network
    nodes: Vec<FakeNode>,
    /// Channels to send messages to clients.
    to_client_channels: HashMap<ClientId, Vec<Sender<Vec<u8>>>>,
    client_channels: HashMap<ClientId, Vec<Sender<Vec<u8>>>>, // [client][to_node]
}

impl FakeInnerNetwork {
    /// Creates a new fake network for testing using the given number of nodes and configuration.
    #[allow(clippy::type_complexity)]
    pub fn new(
        n_nodes: usize,
        n_clients: Option<Vec<ClientId>>,
        config: FakeNetworkConfig,
    ) -> (
        Self,
        Vec<Vec<Receiver<Vec<u8>>>>, // inboxes[to][sender_index]
        HashMap<ClientId, Vec<Receiver<Vec<u8>>>>,
    ) {
        // ---- nodes ----
        let mut nodes = Vec::with_capacity(n_nodes);
        for id in 0..n_nodes {
            nodes.push(FakeNode::new(id));
        }

        // ---- inboxes: one Vec per node ----
        let mut inboxes: Vec<Vec<Receiver<Vec<u8>>>> = (0..n_nodes).map(|_| Vec::new()).collect();

        // ---- node → node channels ----
        let mut node_channels = vec![Vec::with_capacity(n_nodes); n_nodes];

        for from in node_channels.iter_mut().take(n_nodes) {
            for to in inboxes.iter_mut().take(n_nodes) {
                let (tx, rx) = mpsc::channel::<Vec<u8>>(config.channel_buff_size);
                from.push(tx);
                to.push(rx);
            }
        }

        // ---- client → node channels ----
        let mut client_channels: HashMap<ClientId, Vec<Sender<Vec<u8>>>> = HashMap::new();

        if let Some(client_ids) = n_clients.clone() {
            for client_id in client_ids {
                let mut row = Vec::with_capacity(n_nodes);

                for to in inboxes.iter_mut().take(n_nodes) {
                    let (tx, rx) = mpsc::channel::<Vec<u8>>(config.channel_buff_size);
                    row.push(tx);
                    to.push(rx);
                }

                client_channels.insert(client_id, row);
            }
        }

        // ---- client receivers (node → client handled elsewhere) ----
        let mut client_receivers = HashMap::new();
        let mut to_client_channels = HashMap::new();

        if let Some(client_ids) = n_clients {
            for client_id in client_ids {
                let mut senders = Vec::with_capacity(n_nodes);
                let mut receivers = Vec::with_capacity(n_nodes);

                for _from in 0..n_nodes {
                    let (tx, rx) = mpsc::channel::<Vec<u8>>(config.channel_buff_size);
                    senders.push(tx);
                    receivers.push(rx);
                }

                to_client_channels.insert(client_id, senders);
                client_receivers.insert(client_id, receivers);
            }
        }

        (
            Self {
                node_channels,
                config,
                nodes,
                to_client_channels,
                client_channels,
            },
            inboxes,
            client_receivers,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SenderId {
    Node(PartyId),
    Client(ClientId),
}

#[derive(Clone)]
pub struct FakeNetwork {
    sender: SenderId,
    inner: FakeInnerNetwork,
}
impl FakeNetwork {
    pub fn new(id: PartyId, inner: FakeInnerNetwork) -> Self {
        Self {
            sender: SenderId::Node(id),
            inner,
        }
    }

    pub fn new_client(id: ClientId, inner: FakeInnerNetwork) -> Self {
        Self {
            sender: SenderId::Client(id),
            inner,
        }
    }
}

#[async_trait]
impl Network for FakeNetwork {
    type NodeType = FakeNode;
    type NetworkConfig = FakeNetworkConfig;

    async fn send(&self, recipient: PartyId, message: &[u8]) -> Result<usize, NetworkError> {
        match self.sender {
            SenderId::Node(from) => {
                let tx = self
                    .inner
                    .node_channels
                    .get(from)
                    .and_then(|row| row.get(recipient))
                    .ok_or(NetworkError::PartyNotFound(recipient))?;

                tx.send(message.to_vec())
                    .await
                    .map_err(|_| NetworkError::SendError)?;
            }

            SenderId::Client(client_id) => {
                let row = self
                    .inner
                    .client_channels
                    .get(&client_id)
                    .ok_or(NetworkError::ClientNotFound(client_id))?;

                let tx = row
                    .get(recipient)
                    .ok_or(NetworkError::PartyNotFound(recipient))?;

                tx.send(message.to_vec())
                    .await
                    .map_err(|_| NetworkError::SendError)?;
            }
        }

        Ok(message.len())
    }

    fn node(&self, id: PartyId) -> Option<&Self::NodeType> {
        self.inner.nodes.iter().find(|node| node.id() == id)
    }

    fn node_mut(&mut self, id: PartyId) -> Option<&mut Self::NodeType> {
        self.inner.nodes.iter_mut().find(|node| node.id == id)
    }

    async fn broadcast(&self, message: &[u8]) -> Result<usize, NetworkError> {
        let msg = message.to_vec();

        let sends = match self.sender {
            SenderId::Node(from) => self
                .inner
                .node_channels
                .get(from)
                .ok_or(NetworkError::PartyNotFound(from))?
                .iter()
                .map(|tx| tx.send(msg.clone()))
                .collect::<Vec<_>>(),

            SenderId::Client(client_id) => self
                .inner
                .client_channels
                .get(&client_id)
                .ok_or(NetworkError::ClientNotFound(client_id))?
                .iter()
                .map(|tx| tx.send(msg.clone()))
                .collect::<Vec<_>>(),
        };

        let results = join_all(sends).await;
        if results.iter().any(|r| r.is_err()) {
            return Err(NetworkError::SendError);
        }

        Ok(message.len())
    }

    fn parties(&self) -> Vec<&Self::NodeType> {
        self.inner.nodes.iter().collect()
    }

    fn parties_mut(&mut self) -> Vec<&mut Self::NodeType> {
        self.inner.nodes.iter_mut().collect()
    }

    fn config(&self) -> &Self::NetworkConfig {
        &self.inner.config
    }

    // --- New client communication methods ---

    async fn send_to_client(
        &self,
        client: ClientId,
        message: &[u8],
    ) -> Result<usize, NetworkError> {
        let from = match self.sender {
            SenderId::Node(id) => id,
            SenderId::Client(_) => {
                return Err(NetworkError::SendError);
            }
        };

        let row = self
            .inner
            .to_client_channels
            .get(&client)
            .ok_or(NetworkError::ClientNotFound(client))?;

        let tx = row.get(from).ok_or(NetworkError::PartyNotFound(from))?;

        tx.send(message.to_vec())
            .await
            .map_err(|_| NetworkError::SendError)?;

        Ok(message.len())
    }

    fn clients(&self) -> Vec<ClientId> {
        self.inner.client_channels.keys().copied().collect()
    }

    fn is_client_connected(&self, client: ClientId) -> bool {
        self.inner.client_channels.contains_key(&client)
    }

    // fn local_party_id(&self) -> PartyId {
    //     match self.sender {
    //         SenderId::Node(i) => i,
    //         SenderId::Client(i) => i,
    //     }
    // }

    // fn party_count(&self) -> usize {
    //     self.inner.nodes.len()
    // }
}

/// Represents a node in the FakeNetwork.
#[derive(Clone)]
pub struct FakeNode {
    /// The id of the node.
    pub id: PartyId,
    // The channel in which the party receives the messages.
    // pub receiver_channel: Receiver<Vec<u8>>,
}

impl FakeNode {
    /// Creates a new fake node.
    pub fn new(id: PartyId) -> Self {
        Self {
            id,
            // receiver_channel: receiver,
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
#[derive(Clone)]
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
    use super::*;

    #[tokio::test]
    async fn test_fake_network_new() {
        let n_nodes = 5;
        let config = FakeNetworkConfig::new(100);

        let (inner, inboxes, _) = FakeInnerNetwork::new(n_nodes, None, config);

        // One inbox matrix per node
        assert_eq!(inboxes.len(), n_nodes);
        for to in 0..n_nodes {
            assert_eq!(inboxes[to].len(), n_nodes);
        }

        // Create per-node handles
        let networks: Vec<_> = (0..n_nodes)
            .map(|id| FakeNetwork::new(id, inner.clone()))
            .collect();

        assert_eq!(inner.nodes.len(), n_nodes);

        for i in 0..n_nodes {
            // assert_eq!(networks[i].local_party_id(), i);
            assert!(networks[i].node(i).is_some());
            assert_eq!(networks[i].node(i).unwrap().id(), i);
        }
    }

    #[tokio::test]
    async fn test_fake_network_send_and_receive() {
        let n_nodes = 3;
        let config = FakeNetworkConfig::new(100);

        let (inner, mut inboxes, _) = FakeInnerNetwork::new(n_nodes, None, config);

        let networks: Vec<_> = (0..n_nodes)
            .map(|id| FakeNetwork::new(id, inner.clone()))
            .collect();

        let sender_id = 1;
        let recipient_id = 2;
        let message = b"hello";

        let send_result = networks[sender_id].send(recipient_id, message).await;

        assert!(send_result.is_ok());
        assert_eq!(send_result.unwrap(), message.len());

        // Receiver reads specifically from sender_id
        let received = inboxes[recipient_id][sender_id]
            .try_recv()
            .expect("message should exist");

        assert_eq!(received, message.to_vec());

        // Ensure no other sender channel fired
        for from in 0..n_nodes {
            if from != sender_id {
                assert!(inboxes[recipient_id][from].try_recv().is_err());
            }
        }
    }

    #[tokio::test]
    async fn test_fake_network_broadcast() {
        let n_nodes = 3;
        let config = FakeNetworkConfig::new(100);

        let (inner, mut inboxes, _) = FakeInnerNetwork::new(n_nodes, None, config);
        let networks: Vec<_> = (0..n_nodes)
            .map(|id| FakeNetwork::new(id, inner.clone()))
            .collect();

        let sender_id = 0;
        let message = b"broadcast";

        let broadcast_result = networks[sender_id].broadcast(message).await;

        assert!(broadcast_result.is_ok());
        assert_eq!(broadcast_result.unwrap(), message.len());

        // Each node receives from sender_id
        for to in 0..n_nodes {
            let received = inboxes[to][sender_id]
                .try_recv()
                .expect("broadcast message missing");

            assert_eq!(received, message.to_vec());
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

    #[tokio::test]
    async fn test_network_error_on_send_failure() {
        let n_nodes = 2;
        let config = FakeNetworkConfig::new(1);

        let (mut inner, _, _) = FakeInnerNetwork::new(n_nodes, None, config);

        let from = 0;
        let to = 1;

        // Close the (from -> to) channel
        inner.node_channels[from][to] = {
            let (tx, rx) = mpsc::channel(1);
            drop(rx);
            tx
        };

        let network = FakeNetwork::new(from, inner);

        let message = b"test";

        let send_result = network.send(to, message).await;

        assert!(send_result.is_err());
        assert_eq!(send_result.unwrap_err(), NetworkError::SendError);
    }
}
