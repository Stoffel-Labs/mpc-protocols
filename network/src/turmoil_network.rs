use crate::fake_network::{FakeNetworkConfig, FakeNode, SenderId};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use stoffelnet::network_utils::{ClientId, Network, NetworkError, PartyId, VerifiedOrdering};
use tokio::sync::mpsc::Sender;
use tokio::sync::{Barrier, Mutex};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc::{self, Receiver},
};
use turmoil::net::{TcpListener, TcpStream};

#[derive(Clone)]
pub struct TurmoilInnerNetwork {
    pub config: FakeNetworkConfig,
    pub nodes: Vec<FakeNode>,
    pub hostnames: Vec<String>,
    pub ports: Vec<u16>,
    pub client_ids: Vec<ClientId>,
    pub client_hostnames: Vec<String>,
    pub client_ports: Vec<u16>,
    // Released only after every host (and client) finishes TurmoilNetwork::new.
    // Prevents the Turmoil pathology where a TcpStream::connect future never
    // resolves if it arrives after the peer's main task has already moved past
    // TurmoilNetwork::new. See TURMOIL_CONNECT_HANG_REPORT.md.
    pub setup_barrier: Arc<Barrier>,
}

impl TurmoilInnerNetwork {
    pub fn new(
        n_nodes: usize,
        client_ids: Option<Vec<ClientId>>,
        config: FakeNetworkConfig,
        base_port: u16,
        base_client_port: u16,
    ) -> Self {
        let nodes = (0..n_nodes).map(FakeNode::new).collect();

        let hostnames = (0..n_nodes).map(|i| format!("node{}", i)).collect();

        let ports = (0..n_nodes).map(|i| base_port + i as u16).collect();

        let client_ids = client_ids.unwrap_or_default(); // normalize immediately

        let client_hostnames = client_ids
            .iter()
            .map(|id| format!("client{}", id))
            .collect();
        let client_ports = client_ids
            .iter()
            .enumerate()
            .map(|(i, _)| base_client_port + i as u16)
            .collect();

        let participant_count = n_nodes + client_ids.len();
        let setup_barrier = Arc::new(Barrier::new(participant_count));

        Self {
            config,
            nodes,
            hostnames,
            ports,
            client_ids,
            client_hostnames,
            client_ports,
            setup_barrier,
        }
    }

    pub fn listen_addr(&self, id: PartyId) -> String {
        format!("0.0.0.0:{}", self.ports[id])
    }

    pub fn dial_addr(&self, id: PartyId) -> String {
        format!("{}:{}", self.hostnames[id], self.ports[id])
    }

    pub fn client_listen_addr(&self, client_id: ClientId) -> String {
        let idx = self
            .client_ids
            .iter()
            .position(|&id| id == client_id)
            .unwrap();
        format!("0.0.0.0:{}", self.client_ports[idx])
    }

    pub fn client_dial_addr(&self, client_id: ClientId) -> String {
        let idx = self
            .client_ids
            .iter()
            .position(|&id| id == client_id)
            .unwrap();
        format!("{}:{}", self.client_hostnames[idx], self.client_ports[idx])
    }
}

#[derive(Clone)]
pub struct TurmoilNetwork {
    sender: SenderId,
    peers: HashMap<PartyId, Arc<Mutex<TcpStream>>>, // node → node, client → node
    client_streams: HashMap<ClientId, Arc<Mutex<TcpStream>>>, // node → client
    inner: TurmoilInnerNetwork,
    inbound_tx: Sender<(SenderId, Vec<u8>)>,
}

impl TurmoilNetwork {
    pub async fn new(
        sender: SenderId,
        inner: TurmoilInnerNetwork,
    ) -> (Self, Receiver<(SenderId, Vec<u8>)>) {
        let (tx, rx) = mpsc::channel(inner.config.channel_buff_size);

        // bind listener — nodes listen on node port, clients on client port
        let my_addr = match sender {
            SenderId::Node(id) => inner.listen_addr(id),
            SenderId::Client(id) => inner.client_listen_addr(id),
        };
        tokio::spawn(start_listener(my_addr, tx.clone()));
        tokio::time::sleep(Duration::from_millis(1)).await;

        // dial peers — nodes dial other nodes, clients dial all nodes
        let mut peers = HashMap::new();
        match sender {
            SenderId::Node(id) => {
                for peer_id in 0..inner.nodes.len() {
                    if peer_id == id {
                        continue;
                    }
                    let addr = inner.dial_addr(peer_id);
                    let stream = connect_with_handshake(sender, &addr)
                        .await
                        .expect("node→node connection failed");
                    peers.insert(peer_id, Arc::new(Mutex::new(stream)));
                }
            }
            SenderId::Client(_) => {
                for node_id in 0..inner.nodes.len() {
                    let addr = inner.dial_addr(node_id);
                    let stream = connect_with_handshake(sender, &addr)
                        .await
                        .expect("client→node connection failed");
                    peers.insert(node_id, Arc::new(Mutex::new(stream)));
                }
            }
        }

        // nodes dial clients for send_to_client; clients have no client_streams
        let mut client_streams = HashMap::new();
        if let SenderId::Node(_) = sender {
            for client_id in &inner.client_ids {
                let addr = inner.client_dial_addr(*client_id);
                let stream = connect_with_handshake(sender, &addr)
                    .await
                    .expect("node→client connection failed");
                client_streams.insert(*client_id, Arc::new(Mutex::new(stream)));
            }
        }
        // Wait until every participant has finished dialing. This prevents any
        // host's main task from moving past TurmoilNetwork::new while other
        // hosts still have pending dials to it — which would trigger Turmoil's
        // "connect arrives after listener-parent moved on" hang.
        // See TURMOIL_CONNECT_HANG_REPORT.md.
        inner.setup_barrier.wait().await;

        (
            Self {
                sender,
                peers,
                client_streams,
                inner,
                inbound_tx: tx,
            },
            rx,
        )
    }

    async fn send_to_self(&self, message: &[u8]) -> Result<usize, NetworkError> {
        self.inbound_tx
            .send((self.sender, message.to_vec()))
            .await
            .map_err(|_| NetworkError::SendError)?;
        Ok(message.len())
    }
}

#[async_trait]
impl Network for TurmoilNetwork {
    type NodeType = FakeNode;
    type NetworkConfig = FakeNetworkConfig;

    async fn send(&self, recipient: PartyId, message: &[u8]) -> Result<usize, NetworkError> {
        if let SenderId::Node(_) = self.sender {
            if recipient == self.local_party_id() {
                return self.send_to_self(message).await;
            }
        }

        let stream = self
            .peers
            .get(&recipient)
            .ok_or(NetworkError::PartyNotFound(recipient))?;

        let mut stream = stream.lock().await;

        let len = (message.len() as u32).to_be_bytes();

        stream
            .write_all(&len)
            .await
            .map_err(|_| NetworkError::SendError)?;
        stream
            .write_all(message)
            .await
            .map_err(|_| NetworkError::SendError)?;
        stream.flush().await.map_err(|_| NetworkError::SendError)?;

        Ok(message.len())
    }

    async fn broadcast(&self, message: &[u8]) -> Result<usize, NetworkError> {
        let futures = (0..self.party_count()).map(|i| self.send(i, message));

        let results = futures::future::join_all(futures).await;

        if results.iter().any(|r| r.is_err()) {
            return Err(NetworkError::SendError);
        }

        Ok(message.len())
    }

    fn node(&self, id: PartyId) -> Option<&Self::NodeType> {
        self.inner.nodes.iter().find(|n| n.id == id)
    }

    fn node_mut(&mut self, id: PartyId) -> Option<&mut Self::NodeType> {
        self.inner.nodes.iter_mut().find(|n| n.id == id)
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

    fn local_party_id(&self) -> PartyId {
        match self.sender {
            SenderId::Node(i) => i,
            SenderId::Client(i) => i,
        }
    }

    fn party_count(&self) -> usize {
        self.inner.nodes.len()
    }

    fn clients(&self) -> Vec<ClientId> {
        self.inner.client_ids.clone()
    }

    fn is_client_connected(&self, client: ClientId) -> bool {
        self.inner.client_ids.contains(&client)
    }

    async fn send_to_client(
        &self,
        client: ClientId,
        message: &[u8],
    ) -> Result<usize, NetworkError> {
        if let SenderId::Client(_) = self.sender {
            return Err(NetworkError::SendError); // clients can't send to clients
        }
        let stream = self
            .client_streams
            .get(&client)
            .ok_or(NetworkError::ClientNotFound(client))?;

        let mut stream = stream.lock().await;
        let len = (message.len() as u32).to_be_bytes();
        stream
            .write_all(&len)
            .await
            .map_err(|_| NetworkError::SendError)?;
        stream
            .write_all(message)
            .await
            .map_err(|_| NetworkError::SendError)?;
        stream.flush().await.map_err(|_| NetworkError::SendError)?;

        Ok(message.len())
    }

    fn verified_ordering(&self) -> Option<VerifiedOrdering> {
        None
    }
}

pub async fn start_listener(addr: String, inbound: Sender<(SenderId, Vec<u8>)>) {
    let listener = TcpListener::bind(addr).await.unwrap();

    loop {
        let (mut socket, _) = listener.accept().await.unwrap();
        let inbound = inbound.clone();

        tokio::spawn(async move {
            let mut id_buf = [0u8; 8];
            if socket.read_exact(&mut id_buf).await.is_err() {
                return;
            }

            let raw = u64::from_be_bytes(id_buf);
            let sender = if raw & (1u64 << 63) != 0 {
                SenderId::Client((raw & !(1u64 << 63)) as ClientId)
            } else {
                SenderId::Node(raw as PartyId)
            };

            loop {
                let mut len_buf = [0u8; 4];
                if socket.read_exact(&mut len_buf).await.is_err() {
                    break;
                }

                let len = u32::from_be_bytes(len_buf) as usize;
                let mut msg = vec![0u8; len];

                if socket.read_exact(&mut msg).await.is_err() {
                    break;
                }

                if inbound.send((sender, msg)).await.is_err() {
                    break;
                }
            }
        });
    }
}

async fn connect_with_handshake(sender: SenderId, addr: &str) -> Result<TcpStream, NetworkError> {
    let handshake = match sender {
        SenderId::Node(i) => i as u64,
        SenderId::Client(i) => (1u64 << 63) | (i as u64),
    };

    loop {
        match TcpStream::connect(addr).await {
            Ok(mut stream) => {
                stream
                    .write_all(&handshake.to_be_bytes())
                    .await
                    .map_err(|_| NetworkError::SendError)?;
                stream.flush().await.map_err(|_| NetworkError::SendError)?;
                return Ok(stream);
            }
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake_network::{FakeNetworkConfig, SenderId};
    use std::sync::Arc;
    use tokio::sync::Barrier;
    use tokio::time::{sleep, Duration};
    use turmoil::Builder;

    fn run_and_collect(
        mut sim: turmoil::Sim,
        rx_done: std::sync::mpsc::Receiver<Result<(), String>>,
        expected: usize,
    ) {
        sim.run().unwrap();
        let results: Vec<_> = std::iter::from_fn(|| rx_done.try_recv().ok()).collect();
        assert_eq!(
            results.len(),
            expected,
            "not all hosts reported: got {}/{}",
            results.len(),
            expected
        );
        for r in results {
            assert!(r.is_ok(), "host failed: {}", r.unwrap_err());
        }
    }

    #[test]
    fn test_node_to_node_send() {
        let mut sim = Builder::new().build();
        let inner = TurmoilInnerNetwork::new(2, None, FakeNetworkConfig::new(100), 7000, 0);
        let (tx, rx_done) = std::sync::mpsc::channel::<Result<(), String>>();
        let barrier = Arc::new(Barrier::new(2));

        for id in 0..2usize {
            let inner = inner.clone();
            let tx = tx.clone();
            let barrier = barrier.clone();

            sim.host(format!("node{}", id), move || {
                let inner = inner.clone();
                let tx = tx.clone();
                let barrier = barrier.clone();

                async move {
                    let (network, mut rx) = TurmoilNetwork::new(SenderId::Node(id), inner).await;
                    let network = Arc::new(network);
                    barrier.wait().await;

                    if id == 0 {
                        network.send(1, b"hello from node0").await.unwrap();
                        let _ = rx.recv().await; // wait for ack
                        let _ = tx.send(Ok(()));
                    } else {
                        let (sender, msg) = rx.recv().await.unwrap();
                        if sender != SenderId::Node(0) {
                            let _ = tx.send(Err(format!("wrong sender: {:?}", sender)));
                            return Ok(());
                        }
                        if msg != b"hello from node0" {
                            let _ = tx.send(Err(format!("wrong msg: {:?}", msg)));
                            return Ok(());
                        }
                        network.send(0, b"ack").await.unwrap();
                        let _ = tx.send(Ok(()));
                    }
                    Ok(())
                }
            });
        }

        drop(tx);
        sim.client("driver", async {
            sleep(Duration::from_secs(5)).await;
            Ok::<(), Box<dyn std::error::Error>>(())
        });

        run_and_collect(sim, rx_done, 2);
    }

    #[test]
    fn test_node_broadcast() {
        let n = 3usize;
        let mut sim = Builder::new().build();
        let inner = TurmoilInnerNetwork::new(n, None, FakeNetworkConfig::new(100), 7000, 0);
        let (tx, rx_done) = std::sync::mpsc::channel::<Result<(), String>>();
        let barrier = Arc::new(Barrier::new(n));

        for id in 0..n {
            let inner = inner.clone();
            let tx = tx.clone();
            let barrier = barrier.clone();

            sim.host(format!("node{}", id), move || {
                let inner = inner.clone();
                let tx = tx.clone();
                let barrier = barrier.clone();

                async move {
                    let (network, mut rx) = TurmoilNetwork::new(SenderId::Node(id), inner).await;
                    let network = Arc::new(network);
                    barrier.wait().await;

                    if id == 0 {
                        network.broadcast(b"broadcast").await.unwrap();
                        for _ in 0..n - 1 {
                            let _ = rx.recv().await; // wait for ack from all
                        }
                        let _ = tx.send(Ok(()));
                    } else {
                        let (sender, msg) = rx.recv().await.unwrap();
                        if sender != SenderId::Node(0) {
                            let _ = tx.send(Err(format!("wrong sender: {:?}", sender)));
                            return Ok(());
                        }
                        if msg != b"broadcast" {
                            let _ = tx.send(Err(format!("wrong msg: {:?}", msg)));
                            return Ok(());
                        }
                        network.send(0, b"ack").await.unwrap();
                        let _ = tx.send(Ok(()));
                    }
                    Ok(())
                }
            });
        }

        drop(tx);
        sim.client("driver", async {
            sleep(Duration::from_secs(5)).await;
            Ok::<(), Box<dyn std::error::Error>>(())
        });

        run_and_collect(sim, rx_done, n);
    }

    #[test]
    fn test_node_send_to_self() {
        let mut sim = Builder::new().build();
        let inner = TurmoilInnerNetwork::new(1, None, FakeNetworkConfig::new(100), 7000, 0);
        let (tx, rx_done) = std::sync::mpsc::channel::<Result<(), String>>();

        let tx_clone = tx.clone();
        sim.host("node0", move || {
            let inner = inner.clone();
            let tx = tx_clone.clone();

            async move {
                let (network, mut rx) = TurmoilNetwork::new(SenderId::Node(0), inner).await;
                // no barrier needed, single node
                network.send(0, b"self").await.unwrap();
                let (sender, msg) = rx.recv().await.unwrap();
                if sender != SenderId::Node(0) {
                    let _ = tx.send(Err(format!("wrong sender: {:?}", sender)));
                    return Ok(());
                }
                if msg != b"self" {
                    let _ = tx.send(Err(format!("wrong msg: {:?}", msg)));
                    return Ok(());
                }
                let _ = tx.send(Ok(()));
                Ok(())
            }
        });

        drop(tx);
        sim.client("driver", async {
            sleep(Duration::from_secs(5)).await;
            Ok::<(), Box<dyn std::error::Error>>(())
        });

        run_and_collect(sim, rx_done, 1);
    }

    #[test]
    fn test_client_send_to_node() {
        let mut sim = Builder::new().build();
        let inner =
            TurmoilInnerNetwork::new(2, Some(vec![0]), FakeNetworkConfig::new(100), 7000, 8000);
        let (tx, rx_done) = std::sync::mpsc::channel::<Result<(), String>>();
        // 2 nodes + 1 client
        let barrier = Arc::new(Barrier::new(3));

        // client registered first so its listener binds before nodes dial it
        let inner_c = inner.clone();
        let tx_c = tx.clone();
        let barrier_c = barrier.clone();
        sim.host("client0", move || {
            let inner = inner_c.clone();
            let tx = tx_c.clone();
            let barrier = barrier_c.clone();

            async move {
                let (network, mut rx) = TurmoilNetwork::new(SenderId::Client(0), inner).await;
                barrier.wait().await;

                network.send(0, b"hello from client").await.unwrap();
                let _ = rx.recv().await; // wait for ack from node0
                let _ = tx.send(Ok(()));
                Ok(())
            }
        });

        for id in 0..2usize {
            let inner = inner.clone();
            let tx = tx.clone();
            let barrier = barrier.clone();

            sim.host(format!("node{}", id), move || {
                let inner = inner.clone();
                let tx = tx.clone();
                let barrier = barrier.clone();

                async move {
                    let (network, mut rx) = TurmoilNetwork::new(SenderId::Node(id), inner).await;
                    barrier.wait().await;

                    if id == 0 {
                        let (sender, msg) = rx.recv().await.unwrap();
                        if sender != SenderId::Client(0) {
                            let _ = tx.send(Err(format!("expected Client(0), got {:?}", sender)));
                            return Ok(());
                        }
                        if msg != b"hello from client" {
                            let _ = tx.send(Err(format!("wrong msg: {:?}", msg)));
                            return Ok(());
                        }
                        network.send_to_client(0, b"ack").await.unwrap();
                        let _ = tx.send(Ok(()));
                    } else {
                        let _ = tx.send(Ok(()));
                    }
                    Ok(())
                }
            });
        }

        drop(tx);
        sim.client("driver", async {
            sleep(Duration::from_secs(5)).await;
            Ok::<(), Box<dyn std::error::Error>>(())
        });

        run_and_collect(sim, rx_done, 3);
    }

    #[test]
    fn test_client_broadcast_to_nodes() {
        let n = 3usize;
        let mut sim = Builder::new().build();
        let inner =
            TurmoilInnerNetwork::new(n, Some(vec![0]), FakeNetworkConfig::new(100), 7000, 8000);
        let (tx, rx_done) = std::sync::mpsc::channel::<Result<(), String>>();
        // n nodes + 1 client
        let barrier = Arc::new(Barrier::new(n + 1));

        // client first
        let inner_c = inner.clone();
        let tx_c = tx.clone();
        let barrier_c = barrier.clone();
        sim.host("client0", move || {
            let inner = inner_c.clone();
            let tx = tx_c.clone();
            let barrier = barrier_c.clone();

            async move {
                let (network, mut rx) = TurmoilNetwork::new(SenderId::Client(0), inner).await;
                barrier.wait().await;

                network.broadcast(b"client broadcast").await.unwrap();
                for _ in 0..n {
                    let _ = rx.recv().await; // wait for ack from each node
                }
                let _ = tx.send(Ok(()));
                Ok(())
            }
        });

        for id in 0..n {
            let inner = inner.clone();
            let tx = tx.clone();
            let barrier = barrier.clone();

            sim.host(format!("node{}", id), move || {
                let inner = inner.clone();
                let tx = tx.clone();
                let barrier = barrier.clone();

                async move {
                    let (network, mut rx) = TurmoilNetwork::new(SenderId::Node(id), inner).await;
                    barrier.wait().await;

                    let (sender, msg) = rx.recv().await.unwrap();
                    if sender != SenderId::Client(0) {
                        let _ = tx.send(Err(format!("expected Client(0), got {:?}", sender)));
                        return Ok(());
                    }
                    if msg != b"client broadcast" {
                        let _ = tx.send(Err(format!("wrong msg: {:?}", msg)));
                        return Ok(());
                    }
                    network.send_to_client(0, b"ack").await.unwrap();
                    let _ = tx.send(Ok(()));
                    Ok(())
                }
            });
        }

        drop(tx);
        sim.client("driver", async {
            sleep(Duration::from_secs(5)).await;
            Ok::<(), Box<dyn std::error::Error>>(())
        });

        run_and_collect(sim, rx_done, n + 1);
    }

    #[test]
    fn test_node_send_to_client() {
        let mut sim = Builder::new().build();
        let inner =
            TurmoilInnerNetwork::new(2, Some(vec![0]), FakeNetworkConfig::new(100), 7000, 8000);
        let (tx, rx_done) = std::sync::mpsc::channel::<Result<(), String>>();
        // 2 nodes + 1 client
        let barrier = Arc::new(Barrier::new(3));

        // client first
        let inner_c = inner.clone();
        let tx_c = tx.clone();
        let barrier_c = barrier.clone();
        sim.host("client0", move || {
            let inner = inner_c.clone();
            let tx = tx_c.clone();
            let barrier = barrier_c.clone();

            async move {
                let (network, mut rx) = TurmoilNetwork::new(SenderId::Client(0), inner).await;
                barrier.wait().await;

                let (sender, msg) = rx.recv().await.unwrap();
                if sender != SenderId::Node(0) {
                    let _ = tx.send(Err(format!("expected Node(0), got {:?}", sender)));
                    return Ok(());
                }
                if msg != b"hello from node" {
                    let _ = tx.send(Err(format!("wrong msg: {:?}", msg)));
                    return Ok(());
                }
                network.send(0, b"ack").await.unwrap();
                let _ = tx.send(Ok(()));
                Ok(())
            }
        });

        let inner_n0 = inner.clone();
        let tx_n0 = tx.clone();
        let barrier_n0 = barrier.clone();
        sim.host("node0", move || {
            let inner = inner_n0.clone();
            let tx = tx_n0.clone();
            let barrier = barrier_n0.clone();

            async move {
                let (network, mut rx) = TurmoilNetwork::new(SenderId::Node(0), inner).await;
                barrier.wait().await;

                network.send_to_client(0, b"hello from node").await.unwrap();
                let _ = rx.recv().await; // wait for ack from client
                let _ = tx.send(Ok(()));
                Ok(())
            }
        });

        let inner_n1 = inner.clone();
        let tx_n1 = tx.clone();
        let barrier_n1 = barrier.clone();
        sim.host("node1", move || {
            let inner = inner_n1.clone();
            let tx = tx_n1.clone();
            let barrier = barrier_n1.clone();

            async move {
                TurmoilNetwork::new(SenderId::Node(1), inner).await;
                barrier.wait().await;
                let _ = tx.send(Ok(()));
                Ok(())
            }
        });

        drop(tx);
        sim.client("driver", async {
            sleep(Duration::from_secs(5)).await;
            Ok::<(), Box<dyn std::error::Error>>(())
        });

        run_and_collect(sim, rx_done, 3);
    }

    #[test]
    fn test_client_cannot_send_to_client() {
        let mut sim = Builder::new().build();
        let inner =
            TurmoilInnerNetwork::new(1, Some(vec![0]), FakeNetworkConfig::new(100), 7000, 8000);
        let (tx, rx_done) = std::sync::mpsc::channel::<Result<(), String>>();
        let barrier = Arc::new(Barrier::new(2)); // node0 + client0

        // client first so its listener binds before node0 dials it
        let inner_c = inner.clone();
        let tx_c = tx.clone();
        let barrier_c = barrier.clone();
        sim.host("client0", move || {
            let inner = inner_c.clone();
            let tx = tx_c.clone();
            let barrier = barrier_c.clone();

            async move {
                let (network, _rx) = TurmoilNetwork::new(SenderId::Client(0), inner).await;
                barrier.wait().await;

                let result = network.send_to_client(0, b"should fail").await;
                if result.is_err() {
                    let _ = tx.send(Ok(()));
                } else {
                    let _ = tx.send(Err("expected error, got Ok".to_string()));
                }
                Ok(())
            }
        });

        let inner_n = inner.clone();
        let barrier_n = barrier.clone();
        sim.host("node0", move || {
            let inner = inner_n.clone();
            let barrier = barrier_n.clone();

            async move {
                TurmoilNetwork::new(SenderId::Node(0), inner).await;
                barrier.wait().await;
                Ok(())
            }
        });

        drop(tx);
        sim.client("driver", async {
            sleep(Duration::from_secs(5)).await;
            Ok::<(), Box<dyn std::error::Error>>(())
        });

        run_and_collect(sim, rx_done, 1);
    }
}
