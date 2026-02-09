use async_trait::async_trait;
use futures::future::join_all;
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::mpsc::{self, Receiver, Sender};

use stoffelnet::network_utils::{ClientId, Network, NetworkError, Node, PartyId};
use stoffelnet::transports::quic::{NetworkManager, PeerConnection};

use crate::peer_connection::FakeConnectionBroker;

/// Simulates a network for testing purposes. The channels for the network are simulated as `tokio`
/// channels.
pub struct FakeNetwork {
    /// Fake nodes channels to send information to the network
    node_channels: Vec<Sender<Vec<u8>>>,
    /// Configuration of the network.
    config: FakeNetworkConfig,
    /// Fake nodes connected to the network
    nodes: Vec<FakeNode>,
    /// Channels to send messages to clients.
    client_channels: HashMap<ClientId, Sender<Vec<u8>>>,
    /// The sender ID of this network instance (i.e., which party this represents)
    self_id: PartyId,
    /// Shared connection broker for establishing peer connections
    broker: Option<Arc<FakeConnectionBroker>>,
    /// Channel for receiving incoming connections from accept()
    incoming_rx: Option<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Arc<dyn PeerConnection>>>>,
    /// Established peer connections, keyed by remote party ID
    peer_connections: HashMap<PartyId, Arc<dyn PeerConnection>>,
}

impl FakeNetwork {
    /// Returns a reference to the established peer connections.
    pub fn get_peer_connections(&self) -> &HashMap<PartyId, Arc<dyn PeerConnection>> {
        &self.peer_connections
    }

    /// Creates a new fake network for testing using the given number of nodes and configuration.
    #[allow(clippy::type_complexity)]
    pub fn new(
        self_id: PartyId,
        n_nodes: usize,
        n_clients: Option<Vec<ClientId>>,
        config: FakeNetworkConfig,
    ) -> (
        Self,
        Vec<Receiver<Vec<u8>>>,
        HashMap<ClientId, Receiver<Vec<u8>>>,
    ) {
        let mut node_channels = Vec::new();
        let mut nodes = Vec::new();
        let mut receivers = Vec::new();
        for id in 0..n_nodes {
            let (sender, receiver) = mpsc::channel(config.channel_buff_size);
            node_channels.push(sender);
            nodes.push(FakeNode::new(PartyId::from(id)));
            receivers.push(receiver);
        }
        let mut client_channels = HashMap::new();
        let mut client_receivers = HashMap::new();

        if let Some(clients) = n_clients {
            for id in clients {
                let (client_tx, client_rx) = mpsc::channel(config.channel_buff_size);
                client_channels.insert(id, client_tx);
                client_receivers.insert(id, client_rx);
            }
        }

        (
            Self {
                node_channels,
                config,
                nodes,
                client_channels: client_channels.clone(),
                self_id,
                broker: None,
                incoming_rx: None,
                peer_connections: HashMap::new(),
            },
            receivers,
            client_receivers,
        )
    }

    /// Creates a mesh of N FakeNetworks, one per node, sharing a connection broker.
    /// Each network has its own self_id (0..n_nodes-1) and can establish PeerConnections
    /// with any other network in the mesh via the NetworkManager trait.
    ///
    /// Returns a vector of (FakeNetwork, Receiver, ClientReceivers) tuples - one per node.
    #[allow(clippy::type_complexity)]
    pub fn new_mesh(
        n_nodes: usize,
        n_clients: Option<Vec<ClientId>>,
        config: FakeNetworkConfig,
    ) -> Vec<(Self, Receiver<Vec<u8>>, HashMap<ClientId, Receiver<Vec<u8>>>)> {
        let broker = Arc::new(FakeConnectionBroker::new());

        // Create one set of node channels shared by all networks
        let mut all_senders = Vec::new();
        let mut all_receivers = Vec::new();
        for _ in 0..n_nodes {
            let (tx, rx) = mpsc::channel(config.channel_buff_size);
            all_senders.push(tx);
            all_receivers.push(rx);
        }

        // Create client channels (shared across all networks)
        let mut client_channels = HashMap::new();
        let mut client_receivers_vec: Vec<HashMap<ClientId, Receiver<Vec<u8>>>> = Vec::new();
        if let Some(ref clients) = n_clients {
            for id in clients {
                let (client_tx, client_rx) = mpsc::channel(config.channel_buff_size);
                client_channels.insert(*id, client_tx);
                // Only the first network gets the client receivers; others get empty maps
                if client_receivers_vec.is_empty() {
                    let mut m = HashMap::new();
                    m.insert(*id, client_rx);
                    client_receivers_vec.push(m);
                } else {
                    client_receivers_vec[0].insert(*id, client_rx);
                }
            }
        }

        let mut result = Vec::new();
        for i in 0..n_nodes {
            let self_id = PartyId::from(i);
            let addr = SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                self_id as u16,
            );

            // Create incoming connection channel for this node
            let (incoming_tx, incoming_rx) =
                tokio::sync::mpsc::channel::<Arc<dyn PeerConnection>>(config.channel_buff_size);

            // Register this node's listener with the broker
            broker.register_listener(addr, incoming_tx);

            // Create nodes list for this network
            let mut nodes = Vec::new();
            for id in 0..n_nodes {
                nodes.push(FakeNode::new(PartyId::from(id)));
            }

            let client_recv = if i < client_receivers_vec.len() {
                std::mem::take(&mut client_receivers_vec[i])
            } else {
                HashMap::new()
            };

            let network = FakeNetwork {
                node_channels: all_senders.clone(),
                config: FakeNetworkConfig::new(config.channel_buff_size),
                nodes,
                client_channels: client_channels.clone(),
                self_id,
                broker: Some(broker.clone()),
                incoming_rx: Some(tokio::sync::Mutex::new(incoming_rx)),
                peer_connections: HashMap::new(),
            };

            // Take receiver[i] out - we need to move it
            // We'll collect all receivers first and distribute after
            result.push((network, client_recv));
        }

        // Pair each network with its receiver
        let mut final_result = Vec::new();
        for (i, (network, client_recv)) in result.into_iter().enumerate() {
            // We need to take receiver i - but we moved them into a Vec already
            // Let's restructure: swap in a dummy and take the real one
            final_result.push((network, std::mem::replace(&mut all_receivers[i], mpsc::channel(1).1), client_recv));
        }

        final_result
    }
}

#[async_trait]
impl Network for FakeNetwork {
    type NodeType = FakeNode;
    type NetworkConfig = FakeNetworkConfig;

    async fn send(&self, recipient: PartyId, message: &[u8]) -> Result<usize, NetworkError> {
        let idx: usize = recipient.into();
        if let Some(sender) = self.node_channels.get(idx) {
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

    // --- New client communication methods ---

    async fn send_to_client(
        &self,
        client: ClientId,
        message: &[u8],
    ) -> Result<usize, NetworkError> {
        if let Some(sender) = self.client_channels.get(&client) {
            sender
                .send(message.to_vec())
                .await
                .map_err(|_| NetworkError::SendError)?;
            Ok(message.len())
        } else {
            Err(NetworkError::ClientNotFound(client))
        }
    }

    fn clients(&self) -> Vec<ClientId> {
        self.client_channels.keys().copied().collect()
    }

    fn is_client_connected(&self, client: ClientId) -> bool {
        self.client_channels.contains_key(&client)
    }

    fn local_party_id(&self) -> PartyId {
        self.self_id
    }

    fn party_count(&self) -> usize {
        if self.peer_connections.is_empty() {
            return self.nodes.len();
        }
        1 + self.peer_connections.len()
    }
}

impl FakeNetwork {
    pub fn sender_id(&self) -> PartyId {
        if self.peer_connections.is_empty() {
            return self.self_id;
        }
        let mut all_ids: Vec<PartyId> = vec![self.self_id];
        all_ids.extend(self.peer_connections.keys());
        all_ids.sort();
        all_ids.iter().position(|&id| id == self.self_id).unwrap_or(self.self_id)
    }

    pub fn assign_sender_ids(&self) -> usize {
        if self.peer_connections.is_empty() {
            return self.nodes.len();
        }
        let mut all_ids: Vec<PartyId> = vec![self.self_id];
        all_ids.extend(self.peer_connections.keys());
        all_ids.sort();

        let mut assigned = 0;
        for (&peer_id, conn) in &self.peer_connections {
            if let Some(pos) = all_ids.iter().position(|&id| id == peer_id) {
                conn.set_remote_party_id(pos);
                assigned += 1;
            }
        }
        assigned
    }

    pub fn is_fully_connected(&self, expected_count: usize) -> bool {
        if self.peer_connections.is_empty() {
            return self.nodes.len() >= expected_count;
        }
        self.peer_connections.len() >= expected_count.saturating_sub(1)
    }
}

impl NetworkManager for FakeNetwork {
    fn connect<'a>(
        &'a mut self,
        address: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = Result<Arc<dyn PeerConnection>, String>> + Send + 'a>> {
        Box::pin(async move {
            let broker = self
                .broker
                .as_ref()
                .ok_or_else(|| {
                    "No broker configured. Use new_mesh() to create connected networks.".to_string()
                })?;
            let our_addr = SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                self.self_id as u16,
            );
            let conn = broker
                .connect(
                    address,
                    our_addr,
                    Some(self.self_id),
                    self.config.channel_buff_size,
                )
                .await?;
            let remote_id = address.port() as PartyId;
            self.peer_connections.insert(remote_id, conn.clone());
            Ok(conn)
        })
    }

    fn accept<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Arc<dyn PeerConnection>, String>> + Send + 'a>> {
        Box::pin(async move {
            let incoming_rx = self.incoming_rx.as_ref().ok_or_else(|| {
                "No listener configured. Use new_mesh() or call listen() first.".to_string()
            })?;
            let mut rx = incoming_rx.lock().await;
            let conn = rx.recv()
                .await
                .ok_or_else(|| "Listener channel closed".to_string())?;
            if let Some(remote_id) = conn.remote_party_id() {
                self.peer_connections.insert(remote_id, conn.clone());
            }
            Ok(conn)
        })
    }

    fn listen<'a>(
        &'a mut self,
        bind_address: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let broker = self.broker.as_ref().ok_or_else(|| {
                "No broker configured. Use new_mesh() to create connected networks.".to_string()
            })?;
            let (tx, rx) =
                tokio::sync::mpsc::channel(self.config.channel_buff_size);
            self.incoming_rx = Some(tokio::sync::Mutex::new(rx));
            broker.register_listener(bind_address, tx);
            Ok(())
        })
    }
}

/// Represents a node in the FakeNetwork.
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
        let id: usize = self.id.into();
        F::from(id as u64)
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

    #[tokio::test]
    async fn test_fake_network_new() {
        let n_nodes = 5;
        let config = FakeNetworkConfig::new(100);
        let (network, _, _) = FakeNetwork::new(0, n_nodes, None, config);

        let channels = network.node_channels.clone();

        assert_eq!(network.nodes.len(), n_nodes);
        assert_eq!(channels.len(), n_nodes);

        for i in 0..n_nodes {
            assert!(channels.get(i).is_some());
            assert!(network.node(PartyId::from(i)).is_some());
            assert_eq!(network.node(PartyId::from(i)).unwrap().id(), PartyId::from(i));
        }
    }

    #[tokio::test]
    async fn test_fake_network_send_and_receive() {
        let n_nodes = 3;
        let config = FakeNetworkConfig::new(100);
        let (network, mut receivers, _) = FakeNetwork::new(0, n_nodes, None, config);

        let sender_id: usize = 1;
        let recipient_id = PartyId::from(2usize);
        let message = b"hello";

        // Send a message from the perspective of the network
        let send_result = network.send(recipient_id, message).await;
        assert!(send_result.is_ok());
        assert_eq!(send_result.unwrap(), message.len());

        // Get the recipient node and try to receive the message
        let recipient_idx: usize = recipient_id.into();
        let recipient_node = &mut receivers[recipient_idx];
        let received_message_result = recipient_node.try_recv();

        assert!(received_message_result.is_ok());
        assert_eq!(received_message_result.unwrap(), message.to_vec());

        // Ensure the other node didn't receive the message
        let other_node1 = &mut receivers[sender_id];
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
        let (network, mut receivers, _) = FakeNetwork::new(0, n_nodes, None, config);
        let network = Arc::new(Mutex::new(network));

        let message = b"broadcast";

        let network = network.lock().await;
        let broadcast_result = network.broadcast(message).await;
        assert!(broadcast_result.is_ok());
        assert_eq!(broadcast_result.unwrap(), message.len());

        // Verify all nodes received the message
        for node_recv in receivers.iter_mut().take(n_nodes) {
            let received_message_result = node_recv.try_recv();
            assert!(received_message_result.is_ok());
            assert_eq!(received_message_result.unwrap(), message.to_vec());
        }
    }

    #[test]
    fn test_fake_node_id_and_scalar_id() {
        use ark_bls12_381::Fr;

        //let (sender, receiver) = mpsc::channel(100);
        let node_id = PartyId::from(123usize);
        let node = FakeNode::new(node_id);

        assert_eq!(node.id(), node_id);
        let scalar_id: Fr = node.scalar_id();
        let expected_id: usize = node_id.into();
        assert_eq!(scalar_id, Fr::from(expected_id as u64));
        //drop(sender);
    }

    #[tokio::test]
    async fn test_network_error_on_send_failure() {
        let n_nodes = 2;
        let config = FakeNetworkConfig::new(100);
        let (mut network, _, _) = FakeNetwork::new(0, n_nodes, None, config);

        let recipient_id = PartyId::from(1usize);
        let message = b"test";

        // Simulate send failure by removing the recipient's sender
        let recipient_idx: usize = recipient_id.into();
        assert!(
            recipient_idx < network.node_channels.len(),
            "Recipient must exist"
        );

        network.node_channels[recipient_idx] = {
            // Drop the sender by replacing it with a closed channel
            let (closed_sender, _): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = mpsc::channel(1);
            drop(closed_sender); // explicitly drop so that send fails
            mpsc::channel(1).0 // use a channel with no receiver
        };

        // Now, sending should fail
        let send_result = network.send(recipient_id, message).await;
        assert!(
            send_result.is_err(),
            "Send should fail after sender is closed."
        );

        // Since the channel exists but is closed, expect a SendError (not PartyNotFound)
        assert_eq!(send_result.unwrap_err(), NetworkError::SendError);
    }

    #[tokio::test]
    async fn test_sender_id() {
        let config = FakeNetworkConfig::new(100);
        let (network, _, _) = FakeNetwork::new(3, 5, None, config);
        assert_eq!(network.sender_id(), 3);
    }

    #[tokio::test]
    async fn test_mesh_peer_connection() {
        let n_nodes = 3;
        let config = FakeNetworkConfig::new(100);
        let mut networks = FakeNetwork::new_mesh(n_nodes, None, config);

        // Take out network 0 and network 1
        let (mut net0, _rx0, _) = networks.remove(0);
        let (mut net1, _rx1, _) = networks.remove(0);

        // Network 0 connects to network 1 (address 127.0.0.1:1)
        let addr1 = SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            1,
        );

        let conn0 = net0.connect(addr1).await.unwrap();

        // Network 1 accepts the connection
        let conn1 = net1.accept().await.unwrap();

        // Verify sender_ids
        // conn0 should know the remote is party 1 (port-based)
        assert_eq!(conn0.remote_party_id(), Some(1));
        // conn1 should know the remote is party 0
        assert_eq!(conn1.remote_party_id(), Some(0));

        // Test bidirectional communication
        conn0.send(b"hello from 0").await.unwrap();
        let msg = conn1.receive().await.unwrap();
        assert_eq!(msg, b"hello from 0");

        conn1.send(b"hello from 1").await.unwrap();
        let msg = conn0.receive().await.unwrap();
        assert_eq!(msg, b"hello from 1");
    }

    #[tokio::test]
    async fn test_assign_sender_ids() {
        let n_nodes = 3;
        let config = FakeNetworkConfig::new(100);
        let mut networks = FakeNetwork::new_mesh(n_nodes, None, config);

        // Take out all three networks
        let (mut net0, _rx0, _) = networks.remove(0);
        let (mut net1, _rx1, _) = networks.remove(0);
        let (mut net2, _rx2, _) = networks.remove(0);

        // Establish connections: 0->1, 0->2
        let addr1 = SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 1);
        let addr2 = SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 2);

        let conn0_to_1 = net0.connect(addr1).await.unwrap();
        let conn1_from_0 = net1.accept().await.unwrap();

        let conn0_to_2 = net0.connect(addr2).await.unwrap();
        let conn2_from_0 = net2.accept().await.unwrap();

        // Before assign_sender_ids, connections have port-based sender_ids
        assert_eq!(conn0_to_1.remote_party_id(), Some(1));
        assert_eq!(conn1_from_0.remote_party_id(), Some(0));
        assert_eq!(conn0_to_2.remote_party_id(), Some(2));
        assert_eq!(conn2_from_0.remote_party_id(), Some(0));

        // Call assign_sender_ids on net0 (has connections to 1 and 2)
        // all_ids = [0, 1, 2] sorted -> positions: 0->0, 1->1, 2->2
        let assigned = net0.assign_sender_ids();
        assert_eq!(assigned, 2); // assigned to 2 peer connections

        // Verify net0's own sender_id is its position in sorted list
        assert_eq!(net0.sender_id(), 0);

        // Verify peer connections got position-based sender_ids
        assert_eq!(conn0_to_1.remote_party_id(), Some(1)); // peer_id=1, position=1
        assert_eq!(conn0_to_2.remote_party_id(), Some(2)); // peer_id=2, position=2

        // Verify party_count and is_fully_connected
        assert_eq!(net0.party_count(), 3); // self + 2 peers
        assert!(net0.is_fully_connected(3));
        assert!(!net0.is_fully_connected(4));

        // net1 only has connection from 0
        let assigned1 = net1.assign_sender_ids();
        assert_eq!(assigned1, 1);
        assert_eq!(net1.sender_id(), 1); // position 1 in [0, 1]
        assert_eq!(net1.party_count(), 2); // self + 1 peer
        assert!(net1.is_fully_connected(2));

        // Verify conn1_from_0 got reassigned by net1.assign_sender_ids()
        // all_ids for net1 = [0, 1] -> peer 0 is at position 0
        assert_eq!(conn1_from_0.remote_party_id(), Some(0));
    }

    #[tokio::test]
    async fn test_mesh_broadcast_still_works() {
        let n_nodes = 3;
        let config = FakeNetworkConfig::new(100);
        let mut networks = FakeNetwork::new_mesh(n_nodes, None, config);

        let message = b"broadcast from mesh";

        // Use the first network to broadcast
        let (ref net0, _, _) = networks[0];
        let broadcast_result = net0.broadcast(message).await;
        assert!(broadcast_result.is_ok());

        // Each network's receiver should have the broadcast message
        for (_, rx, _) in networks.iter_mut() {
            let received = rx.try_recv();
            assert!(received.is_ok());
            assert_eq!(received.unwrap(), message.to_vec());
        }
    }
}
