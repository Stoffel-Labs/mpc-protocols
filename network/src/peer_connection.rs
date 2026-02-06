use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::mpsc::{self, Receiver, Sender};

use stoffelnet::network_utils::{ClientType, PartyId};
use stoffelnet::transports::quic::{ConnectionState, PeerConnection};

/// A fake peer connection for testing purposes.
/// Implements the `PeerConnection` trait from the QUIC transport layer,
/// providing sender_id authentication support.
///
/// Uses interior mutability via `tokio::sync::Mutex` for the receiver
/// and `std::sync::Mutex` for synchronous fields.
pub struct FakePeerConnection {
    tx: Sender<Vec<u8>>,
    rx: tokio::sync::Mutex<Receiver<Vec<u8>>>,
    remote_addr: SocketAddr,
    connection_role: ClientType,
    sender_id_value: std::sync::Mutex<Option<PartyId>>,
    closed: std::sync::atomic::AtomicBool,
}

impl FakePeerConnection {
    /// Creates a new `FakePeerConnection`.
    ///
    /// # Arguments
    /// * `tx` - Channel sender for outgoing data to the remote peer
    /// * `rx` - Channel receiver for incoming data from the remote peer
    /// * `remote_addr` - The (fake) remote address of the peer
    /// * `connection_role` - Whether this connection is from a Server or Client
    /// * `sender_id` - The initial sender ID (party ID of the remote peer)
    pub fn new(
        tx: Sender<Vec<u8>>,
        rx: Receiver<Vec<u8>>,
        remote_addr: SocketAddr,
        connection_role: ClientType,
        sender_id: Option<PartyId>,
    ) -> Self {
        Self {
            tx,
            rx: tokio::sync::Mutex::new(rx),
            remote_addr,
            connection_role,
            sender_id_value: std::sync::Mutex::new(sender_id),
            closed: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

impl PeerConnection for FakePeerConnection {
    fn send<'a>(
        &'a self,
        data: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            if self.closed.load(std::sync::atomic::Ordering::Relaxed) {
                return Err("Connection closed".to_string());
            }
            self.tx
                .send(data.to_vec())
                .await
                .map_err(|e| format!("Send failed: {}", e))
        })
    }

    fn receive<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
        Box::pin(async move {
            if self.closed.load(std::sync::atomic::Ordering::Relaxed) {
                return Err("Connection closed".to_string());
            }
            let mut rx = self.rx.lock().await;
            rx.recv()
                .await
                .ok_or_else(|| "Channel closed".to_string())
        })
    }

    fn remote_address(&self) -> SocketAddr {
        self.remote_addr
    }

    fn close<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            self.closed
                .store(true, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        })
    }

    fn state<'a>(&'a self) -> Pin<Box<dyn Future<Output = ConnectionState> + Send + 'a>> {
        Box::pin(async move {
            if self.closed.load(std::sync::atomic::Ordering::Relaxed) {
                ConnectionState::Closed
            } else {
                ConnectionState::Connected
            }
        })
    }

    fn is_connected<'a>(&'a self) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move { !self.closed.load(std::sync::atomic::Ordering::Relaxed) })
    }

    fn get_connection_role(&self) -> ClientType {
        self.connection_role
    }

    fn sender_id(&self) -> Option<PartyId> {
        *self.sender_id_value.lock().unwrap()
    }

    fn set_sender_id(&self, sender_id: PartyId) {
        *self.sender_id_value.lock().unwrap() = Some(sender_id);
    }
}

/// A broker that mediates fake connections between `FakeNetwork` instances.
///
/// All `FakeNetwork` instances that need to connect to each other must share
/// the same `FakeConnectionBroker`. The broker maps bind addresses to incoming
/// connection channels, enabling `connect()` on one network to deliver a
/// `PeerConnection` to another network's `accept()`.
pub struct FakeConnectionBroker {
    listeners:
        std::sync::Mutex<HashMap<SocketAddr, Sender<Arc<dyn PeerConnection>>>>,
}

impl FakeConnectionBroker {
    pub fn new() -> Self {
        Self {
            listeners: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Registers a listener at the given address.
    /// The sender is used to deliver incoming connections to the listener's `accept()`.
    pub fn register_listener(
        &self,
        addr: SocketAddr,
        sender: Sender<Arc<dyn PeerConnection>>,
    ) {
        self.listeners.lock().unwrap().insert(addr, sender);
    }

    /// Removes a listener at the given address.
    pub fn remove_listener(&self, addr: &SocketAddr) {
        self.listeners.lock().unwrap().remove(addr);
    }

    /// Establishes a fake connection to the listener at `target_addr`.
    ///
    /// Creates a bidirectional channel pair and two `FakePeerConnection` instances:
    /// - One for the connecting side (returned to the caller)
    /// - One for the accepting side (delivered to the listener)
    ///
    /// # Arguments
    /// * `target_addr` - The address of the listener to connect to
    /// * `our_addr` - The address of the connecting side (for the remote_address of the peer's connection)
    /// * `our_sender_id` - The sender ID of the connecting side (set on the peer's connection)
    /// * `channel_buffer_size` - Buffer size for the mpsc channels
    pub async fn connect(
        &self,
        target_addr: SocketAddr,
        our_addr: SocketAddr,
        our_sender_id: Option<PartyId>,
        channel_buffer_size: usize,
    ) -> Result<Arc<dyn PeerConnection>, String> {
        // Create bidirectional channels
        let (tx_to_peer, rx_from_us) = mpsc::channel(channel_buffer_size);
        let (tx_to_us, rx_from_peer) = mpsc::channel(channel_buffer_size);

        // Get the target sender_id from the listener's address port (convention: port = party_id)
        let target_sender_id = Some(target_addr.port() as PartyId);

        // Create our side of the connection
        let our_conn = Arc::new(FakePeerConnection::new(
            tx_to_peer,
            rx_from_peer,
            target_addr,
            ClientType::Client,
            target_sender_id,
        ));

        // Create the peer's side of the connection
        let peer_conn: Arc<dyn PeerConnection> = Arc::new(FakePeerConnection::new(
            tx_to_us,
            rx_from_us,
            our_addr,
            ClientType::Server,
            our_sender_id,
        ));

        // Deliver the peer's side to the listener
        let listener_tx = {
            let listeners = self.listeners.lock().unwrap();
            listeners
                .get(&target_addr)
                .cloned()
                .ok_or_else(|| format!("No listener at {}", target_addr))?
        };

        listener_tx
            .send(peer_conn)
            .await
            .map_err(|_| "Failed to deliver connection to listener".to_string())?;

        Ok(our_conn as Arc<dyn PeerConnection>)
    }
}

impl Default for FakeConnectionBroker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fake_peer_connection_send_receive() {
        let (tx1, rx1) = mpsc::channel(10);
        let (tx2, rx2) = mpsc::channel(10);

        let addr1: SocketAddr = "127.0.0.1:1001".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:1002".parse().unwrap();

        let conn1 = FakePeerConnection::new(tx1, rx2, addr2, ClientType::Client, Some(2));
        let conn2 = FakePeerConnection::new(tx2, rx1, addr1, ClientType::Server, Some(1));

        // Send from conn1, receive on conn2
        conn1.send(b"hello").await.unwrap();
        let received = conn2.receive().await.unwrap();
        assert_eq!(received, b"hello");

        // Check sender_id
        assert_eq!(conn1.sender_id(), Some(2));
        assert_eq!(conn2.sender_id(), Some(1));

        // Test set_sender_id
        conn1.set_sender_id(42);
        assert_eq!(conn1.sender_id(), Some(42));

        // Check remote address
        assert_eq!(conn1.remote_address(), addr2);
        assert_eq!(conn2.remote_address(), addr1);
    }

    #[tokio::test]
    async fn test_fake_peer_connection_close() {
        let (tx, rx) = mpsc::channel(10);
        let addr: SocketAddr = "127.0.0.1:1001".parse().unwrap();
        let conn = FakePeerConnection::new(tx, rx, addr, ClientType::Client, Some(1));

        assert!(conn.is_connected().await);
        conn.close().await.unwrap();
        assert!(!conn.is_connected().await);

        // Send/receive should fail after close
        assert!(conn.send(b"data").await.is_err());
        assert!(conn.receive().await.is_err());
    }

    #[tokio::test]
    async fn test_fake_connection_broker() {
        let broker = Arc::new(FakeConnectionBroker::new());

        let server_addr: SocketAddr = "127.0.0.1:1000".parse().unwrap();
        let client_addr: SocketAddr = "127.0.0.1:2000".parse().unwrap();

        // Server registers listener
        let (listener_tx, mut listener_rx) = mpsc::channel::<Arc<dyn PeerConnection>>(10);
        broker.register_listener(server_addr, listener_tx);

        // Client connects
        let client_conn = broker
            .connect(server_addr, client_addr, Some(1), 100)
            .await
            .unwrap();

        // Server accepts
        let server_conn = listener_rx.recv().await.unwrap();

        // Verify sender_ids
        assert_eq!(client_conn.sender_id(), Some(1000)); // server addr port
        assert_eq!(server_conn.sender_id(), Some(1)); // client sender_id

        // Test bidirectional communication
        client_conn.send(b"from client").await.unwrap();
        let msg = server_conn.receive().await.unwrap();
        assert_eq!(msg, b"from client");

        server_conn.send(b"from server").await.unwrap();
        let msg = client_conn.receive().await.unwrap();
        assert_eq!(msg, b"from server");
    }
}
