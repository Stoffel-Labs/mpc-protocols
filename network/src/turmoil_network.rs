use crate::fake_network::{FakeNetworkConfig, FakeNode, SenderId};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use stoffelnet::network_utils::{ClientId, Network, NetworkError, PartyId, VerifiedOrdering};
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;
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
}

impl TurmoilInnerNetwork {
    pub fn new(n_nodes: usize, config: FakeNetworkConfig, base_port: u16) -> Self {
        let nodes = (0..n_nodes).map(FakeNode::new).collect();

        let hostnames = (0..n_nodes).map(|i| format!("node{}", i)).collect();

        let ports = (0..n_nodes).map(|i| base_port + i as u16).collect();

        Self {
            config,
            nodes,
            hostnames,
            ports,
        }
    }

    pub fn listen_addr(&self, id: PartyId) -> String {
        format!("0.0.0.0:{}", self.ports[id])
    }

    pub fn dial_addr(&self, id: PartyId) -> String {
        format!("{}:{}", self.hostnames[id], self.ports[id])
    }
}

#[derive(Clone)]
pub struct TurmoilNetwork {
    sender: SenderId,
    peers: HashMap<PartyId, Arc<Mutex<TcpStream>>>,
    inner: TurmoilInnerNetwork,
    inbound_tx: Sender<(PartyId, Vec<u8>)>,
}

impl TurmoilNetwork {
    pub async fn new(
        id: PartyId,
        inner: TurmoilInnerNetwork,
    ) -> (Self, Receiver<(PartyId, Vec<u8>)>) {
        let (tx, rx) = mpsc::channel(inner.config.channel_buff_size);

        // bind address
        let my_addr = inner.listen_addr(id);
        tokio::spawn(start_listener(my_addr, tx.clone()));

        let mut peers = HashMap::new();

        for peer_id in 0..inner.nodes.len() {
            if peer_id == id {
                continue;
            }
            // dial address
            let addr = inner.dial_addr(peer_id);

            let stream = connect_to_peer(id, &addr).await.expect("connection failed");

            peers.insert(peer_id, Arc::new(Mutex::new(stream)));
        }

        (
            Self {
                sender: SenderId::Node(id),
                peers,
                inner,
                inbound_tx: tx,
            },
            rx,
        )
    }

    async fn send_to_self(&self, message: &[u8]) -> Result<usize, NetworkError> {
        let sender = self.local_party_id();
        self.inbound_tx
            .send((sender, message.to_vec()))
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
        if recipient == self.local_party_id() {
            return self.send_to_self(message).await;
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
        vec![]
    }

    fn is_client_connected(&self, _client: ClientId) -> bool {
        false
    }

    async fn send_to_client(
        &self,
        _client: ClientId,
        _message: &[u8],
    ) -> Result<usize, NetworkError> {
        Err(NetworkError::SendError)
    }

    fn verified_ordering(&self) -> Option<VerifiedOrdering> {
        None
    }
}

pub async fn start_listener(addr: String, inbound: Sender<(PartyId, Vec<u8>)>) {
    let listener = TcpListener::bind(addr).await.unwrap();

    loop {
        let (mut socket, _) = listener.accept().await.unwrap();
        let inbound = inbound.clone();

        tokio::spawn(async move {
            let mut id_buf = [0u8; 8];
            if socket.read_exact(&mut id_buf).await.is_err() {
                return;
            }

            let sender = u64::from_be_bytes(id_buf) as PartyId;

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

async fn connect_to_peer(my_id: PartyId, addr: &str) -> Result<TcpStream, NetworkError> {
    loop {
        match TcpStream::connect(addr).await {
            Ok(mut stream) => {
                stream
                    .write_all(&(my_id as u64).to_be_bytes())
                    .await
                    .map_err(|_| NetworkError::SendError)?;

                stream.flush().await.map_err(|_| NetworkError::SendError)?;

                return Ok(stream);
            }
            Err(_) => {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        }
    }
}
