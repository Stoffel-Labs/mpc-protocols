use async_trait::async_trait;
use futures::future::join_all;
use futures::stream::SelectAll;
use futures::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use turmoil::{net::{TcpListener, TcpStream}, Sim};
use stoffelnet::network_utils::{ClientId, Network, NetworkError, Node, PartyId};

pub struct TurmoilNode {
    pub id: PartyId,
}

impl TurmoilNode {
    pub fn new(id: PartyId) -> Self {
        Self { id }
    }
}

impl Node for TurmoilNode {
    fn id(&self) -> PartyId {
        self.id
    }

    fn scalar_id<F: ark_ff::Field>(&self) -> F {
        F::from(self.id as u64)
    }
}

// --- Local Role ---

/// Identifies what kind of peer this network interface is acting as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalRole {
    Node(PartyId),
    Client(ClientId),
}

// --- Pure TCP Network Implementation ---

type OutgoingConn = Framed<TcpStream, LengthDelimitedCodec>;

pub struct TurmoilNetwork {
    pub role: LocalRole,
    total_nodes: usize,
    
    /// Outgoing TCP streams to other nodes
    node_conns: Mutex<HashMap<PartyId, OutgoingConn>>,
    
    /// Outgoing TCP streams to clients
    client_conns: Mutex<HashMap<ClientId, OutgoingConn>>,
    
    /// The TCP Listener to accept incoming connections (from nodes OR clients)
    listener: TcpListener,
    
    /// A single merged async stream of all active incoming TCP connections
    incoming_streams: Mutex<SelectAll<Framed<TcpStream, LengthDelimitedCodec>>>,
    
    nodes: Vec<TurmoilNode>,
}

impl TurmoilNetwork {
    pub fn node_addr(id: PartyId) -> String {
        format!("node_{}", id)
    }

    pub fn client_addr(id: ClientId) -> String {
        format!("client_{}", id)
    }

    /// Initializes the network for a specific NODE and binds its TCP listener.
    pub async fn new_node(
        my_id: PartyId,
        total_nodes: usize,
    ) -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind("0.0.0.0:8080").await?;

        Ok(Self {
            role: LocalRole::Node(my_id),
            total_nodes,
            node_conns: Mutex::new(HashMap::new()),
            client_conns: Mutex::new(HashMap::new()),
            listener,
            incoming_streams: Mutex::new(SelectAll::new()),
            nodes: (0..total_nodes).map(|id| TurmoilNode::new(id as PartyId)).collect(),
        })
    }

    /// Initializes the network for a specific CLIENT and binds its TCP listener.
    pub async fn new_client(
        my_id: ClientId,
        total_nodes: usize,
    ) -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind("0.0.0.0:8080").await?;

        Ok(Self {
            role: LocalRole::Client(my_id),
            total_nodes,
            node_conns: Mutex::new(HashMap::new()),
            client_conns: Mutex::new(HashMap::new()),
            listener,
            incoming_streams: Mutex::new(SelectAll::new()),
            nodes: (0..total_nodes).map(|id| TurmoilNode::new(id as PartyId)).collect(),
        })
    }

    /// Multiplexes the TCP listener and all active TCP connections into a single message queue.
    pub async fn recv(&self) -> Option<Vec<u8>> {
        let mut incoming = self.incoming_streams.lock().await;

        loop {
            let has_streams = !incoming.is_empty();

            tokio::select! {
                Ok((stream, _)) = self.listener.accept() => {
                    incoming.push(Framed::new(stream, LengthDelimitedCodec::new()));
                }
                
                Some(Ok(bytes)) = incoming.next(), if has_streams => {
                    return Some(bytes.to_vec());
                }
            }
        }
    }

    async fn send_internal(&self, peer_id: PartyId, message: &[u8]) -> Result<usize, NetworkError> {
        let mut conns = self.node_conns.lock().await;
        
        if !conns.contains_key(&peer_id) {
            let addr = format!("{}:8080", Self::node_addr(peer_id));
            let stream = TcpStream::connect(&addr).await.map_err(|_| NetworkError::PartyNotFound(peer_id))?;
            conns.insert(peer_id, Framed::new(stream, LengthDelimitedCodec::new()));
        }

        let conn = conns.get_mut(&peer_id).unwrap();
        conn.send(bytes::Bytes::copy_from_slice(message))
            .await
            .map_err(|_| NetworkError::SendError)?;
            
        Ok(message.len())
    }

    async fn send_to_client_internal(&self, client_id: ClientId, message: &[u8]) -> Result<usize, NetworkError> {
        let mut conns = self.client_conns.lock().await;
        
        if !conns.contains_key(&client_id) {
            let addr = format!("{}:8080", Self::client_addr(client_id));
            let stream = TcpStream::connect(&addr).await.map_err(|_| NetworkError::ClientNotFound(client_id))?;
            conns.insert(client_id, Framed::new(stream, LengthDelimitedCodec::new()));
        }

        let conn = conns.get_mut(&client_id).unwrap();
        conn.send(bytes::Bytes::copy_from_slice(message))
            .await
            .map_err(|_| NetworkError::SendError)?;
            
        Ok(message.len())
    }
}

#[async_trait]
impl Network for TurmoilNetwork {
    type NodeType = TurmoilNode;
    type NetworkConfig = ();

    async fn send(&self, recipient: PartyId, message: &[u8]) -> Result<usize, NetworkError> {
        self.send_internal(recipient, message).await
    }

    async fn broadcast(&self, message: &[u8]) -> Result<usize, NetworkError> {
        let mut futures = Vec::new();
        for peer_id in 0..self.total_nodes {
            let id = peer_id as PartyId;
            // Skip sending if we are a node broadcasting to ourselves
            if self.role != LocalRole::Node(id) {
                futures.push(self.send_internal(id, message));
            }
        }
        
        let results = join_all(futures).await;
        if results.iter().any(|r| r.is_err()) {
            return Err(NetworkError::SendError);
        }
        Ok(message.len())
    }

    async fn send_to_client(&self, client: ClientId, message: &[u8]) -> Result<usize, NetworkError> {
        self.send_to_client_internal(client, message).await
    }

    fn is_client_connected(&self, client: ClientId) -> bool {
        if let Ok(conns) = self.client_conns.try_lock() {
            conns.contains_key(&client)
        } else {
            false
        }
    }

    fn clients(&self) -> Vec<ClientId> {
        if let Ok(conns) = self.client_conns.try_lock() {
            conns.keys().copied().collect()
        } else {
            vec![]
        }
    }

    fn config(&self) -> &Self::NetworkConfig {
        &()
    }

    fn node(&self, id: PartyId) -> Option<&Self::NodeType> {
        self.nodes.iter().find(|n| n.id == id)
    }

    fn parties(&self) -> Vec<&Self::NodeType> {
        self.nodes.iter().collect()
    }
    
    fn node_mut(&mut self, _id: PartyId) -> Option<&mut Self::NodeType> { None }
    fn parties_mut(&mut self) -> Vec<&mut Self::NodeType> { vec![] }
}

// --- Test Harness ---

use std::future::Future;

pub struct TurmoilTestHarness<'a> {
    pub sim: Sim<'a>,
    pub total_nodes: usize,
    pub clients: HashMap<ClientId, bool>,
    pub nodes: HashMap<PartyId, bool>,
}

impl TurmoilTestHarness<'_> {
    pub fn setup(total_nodes: usize, clients: Vec<ClientId>) -> Self {
        let mut builder = turmoil::Builder::new();
        builder.simulation_duration(tokio::time::Duration::from_secs(60));

        let sim = builder.build();
        
        Self {
            sim,
            total_nodes,
            clients: (clients.into_iter().map(|id| (id, false)).collect()),
            nodes: (0..total_nodes).map(|id| (id as PartyId, false)).collect(),
        }
    }

    pub fn add_client<F, Fut>(&mut self, cid: ClientId, client_logic: F)
    where
        F: FnOnce(Arc<TurmoilNetwork>) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), Box<dyn std::error::Error>>> + Send + 'static,
    {
        if !self.clients.contains_key(&cid) {
            panic!("Client with ID {} is not registered in the test harness!", cid);
        }

        if self.clients[&cid] {
            panic!("Client with ID {} has already been added!", cid);
        }

        let total_nodes = self.total_nodes;

        self.sim.client(format!("client_{}", cid), async move {
            let network = Arc::new(TurmoilNetwork::new_client(cid, total_nodes).await.unwrap());
            client_logic(network).await
        });

        self.clients.insert(cid, true);
    }

    pub fn add_node<F, Fut>(&mut self, id: PartyId, node_logic: F)
    where
        F: FnOnce(Arc<TurmoilNetwork>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), Box<dyn std::error::Error>>> + Send + 'static
    {
        if !self.nodes.contains_key(&id) {
            panic!("Node with ID {} is not registered in the test harness!", id);
        }

        if self.nodes[&id] {
            panic!("Node with ID {} has already been added!", id);
        }

        let total_nodes = self.total_nodes;
        let node_logic = Arc::new(std::sync::Mutex::new(Some(node_logic)));

        self.sim.host(format!("node_{}", id), move || {
            let node_logic = node_logic.lock().unwrap().take().expect("rebooting nodes not supported");

            async move {
                let network = Arc::new(TurmoilNetwork::new_node(id, total_nodes).await.unwrap());
                node_logic(network).await
            }
        });

        self.nodes.insert(id, true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::sleep;

    /// Client sends a "Ping" to Node 0, Node 0 replies with "Pong".
    #[test]
    fn test_client_to_node_ping_pong() {
        let mut harness = TurmoilTestHarness::setup(1, vec![100]);

        harness.add_node(0, |network| async move {
            while let Some(msg) = network.recv().await {
                if msg == b"Ping" {
                    network.send_to_client(100, b"Pong").await.unwrap();
                    break;
                }
            }
            Ok(())
        });

        // Add Client 100 (The Test Orchestrator)
        harness.add_client(100, |network| async move {
            sleep(Duration::from_millis(50)).await;

            network.send(0, b"Ping").await.unwrap();

            let response = network.recv().await.unwrap();
            assert_eq!(response, b"Pong");

            Ok(())
        });

        harness.sim.run().unwrap();
    }

    /// Client triggers Node 0 -> Node 0 sends to Node 1 -> Node 1 acks to Client.
    #[test]
    fn test_node_to_node_communication() {
        let mut harness = TurmoilTestHarness::setup(2, vec![100]);

        // Node 1: Waits for a message from Node 0, then ACKs to the Client
        harness.add_node(1, |network| async move {
            let msg = network.recv().await.unwrap();
            assert_eq!(msg, b"Hello from Node 0");
            
            network.send_to_client(100, b"Node 1 Received").await.unwrap();
            Ok(())
        });

        harness.add_node(0, |network| async move {
            let msg = network.recv().await.unwrap();
            assert_eq!(msg, b"Trigger");
            
            network.send(1, b"Hello from Node 0").await.unwrap();
            Ok(())
        });

        harness.add_client(100, |network| async move {
            sleep(Duration::from_millis(50)).await;
            
            network.send(0, b"Trigger").await.unwrap();
            
            let ack = network.recv().await.unwrap();
            assert_eq!(ack, b"Node 1 Received");
            
            Ok(())
        });

        harness.sim.run().unwrap();
    }

    /// Client triggers Node 0 -> Node 0 broadcasts -> Nodes 1 & 2 receive and ACK back to Client.
    #[test]
    fn test_node_broadcast() {
        let mut harness = TurmoilTestHarness::setup(3, vec![99]);

        for id in 1..=2 {
            harness.add_node(id, move |network| async move {
                let msg = network.recv().await.unwrap();
                assert_eq!(msg, b"Broadcast Data");
                
                // Tell the client we successfully received the broadcast
                let ack_msg = format!("Ack {}", id);
                network.send_to_client(99, ack_msg.as_bytes()).await.unwrap();
                Ok(())
            });
        }

        harness.add_node(0, |network| async move {
            let msg = network.recv().await.unwrap();
            assert_eq!(msg, b"Do Broadcast");
            
            network.broadcast(b"Broadcast Data").await.unwrap();
            Ok(())
        });

        harness.add_client(99, |network| async move {
            sleep(Duration::from_millis(50)).await;
            
            network.send(0, b"Do Broadcast").await.unwrap();

            let mut acks = vec![];
            for _ in 0..2 {
                let ack = network.recv().await.unwrap();
                acks.push(String::from_utf8(ack).unwrap());
            }

            assert!(acks.contains(&"Ack 1".to_string()));
            assert!(acks.contains(&"Ack 2".to_string()));

            Ok(())
        });

        harness.sim.run().unwrap();
    }
}
