use ark_std::rand::{distributions::Distribution, rngs::StdRng};
use async_trait::async_trait;
use futures::future::join_all;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::{
    cmp::{Ord, Ordering, PartialEq, PartialOrd, Reverse},
    collections::{BinaryHeap, HashMap},
    marker::Send,
};
use tokio::{
    spawn,
    sync::mpsc::{self, Receiver, Sender},
    task::JoinHandle,
    time::{sleep, Duration, Instant},
};

use once_cell::sync::Lazy;
#[cfg(debug_assertions)]
use tokio::sync::Mutex;
#[cfg(debug_assertions)]
use tracing::debug;
use stoffelnet::transports::quic::{NetworkManager, PeerConnection};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::FmtSubscriber;

use crate::peer_connection::FakeConnectionBroker;
/*
 * This is a fake network with delays. Every sent message is assigned a delay sampled from some
 * distribution. The message is inserted into a min-heap with the delay as its key.
 * At any given moment, there is a timer running that expires once the soonest delay expires (if no
 * message is present, a timer with Duration::MAX is running).
 * The algorithm waits for either a next message to arrive or a timer to expire.
 * If a message arrives, it is assigned a delay and added to the min-heap and the elapsed time is
 * checked and delays are updated.
 * Messages are sent if delays have expired in either case, so a burst of arriving messages cannot
 * block sending.
 *
 * Only messages to nodes are delayed, messages to clients are sent immediately.
 */

static TRACING_INIT: Lazy<()> = Lazy::new(|| {
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
        .pretty()
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    let old_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        old_hook(info);
        tracing::error!("{}", info);
        std::process::exit(1);
    }));
});

pub fn setup_tracing() {
    Lazy::force(&TRACING_INIT);
}

#[cfg(debug_assertions)]
static MAX: Mutex<Duration> = Mutex::const_new(Duration::ZERO);

use stoffelnet::network_utils::{ClientId, Network, NetworkError, Node, PartyId};

/// 1. Check if there are any messages whose delay has not yet expired. If not, go to step 5.
/// 2. Get the next message with the smallest delay.
/// 3. If the delay has expired (i.e., elapsed_time >= delay), send the message.
/// 4. If the delay has not yet expired, update the delay by subtracting the elapsed time.
///    Go to step 1.
/// 5. Add a newly received message (if any).
/// 6. Update the min-heap with the changes.
/// 7. Set a timer for the next message to expire or set it to Duration::MAX if there are no
///    messages.
async fn send_next_msgs(
    net_msgs: &mut BinaryHeap<KeyedMessage>,
    node_channels: &mut [Sender<Vec<u8>>],
    recvd_msg: Option<KeyedMessage>,
    elapsed_time: Duration,
) -> Duration {
    let mut new_net_msgs = BinaryHeap::new();

    // 1.
    while !net_msgs.is_empty() {
        // 2.
        let mut msg = net_msgs.pop().unwrap();
        if elapsed_time >= msg.0 {
            #[cfg(debug_assertions)]
            {
                {
                    let mut max = MAX.lock().await;

                    if elapsed_time - msg.0 > *max {
                        *max = elapsed_time - msg.0;
                        debug!("TIME: new MAX={:?}", *max);
                    }
                }
                debug!(
                    "TIME: sent to {} with elapsed_time={:?} >= delay={:?}",
                    msg.1 .0, elapsed_time, msg.0
                );
            }

            // 3.
            let idx: usize = msg.1 .0.into();
            let result = node_channels[idx].send(msg.1 .1.to_vec()).await;
            if let Err(e) = result {
                panic!("network thread encountered error {}", e);
            }
        } else {
            #[cfg(debug_assertions)]
            debug!(
                "TIME: msg for {} not ready yet: elapsed_time={:?} < delay={:?}",
                msg.1 .0, elapsed_time, msg.0
            );

            // 4.
            msg.0 -= elapsed_time;
            new_net_msgs.push(msg);
        }
    }

    // 5.
    if let Some(msg) = recvd_msg {
        new_net_msgs.push(msg);
    }

    // 6.
    *net_msgs = new_net_msgs;

    // 7.
    net_msgs.peek().map_or(Duration::MAX, |msg| msg.0)
}

#[derive(Debug)]
struct KeyedMessage(Duration, (PartyId, Vec<u8>));

impl PartialEq for KeyedMessage {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for KeyedMessage {}
impl PartialOrd for KeyedMessage {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for KeyedMessage {
    fn cmp(&self, other: &Self) -> Ordering {
        Reverse(self.0).cmp(&Reverse(other.0))
    }
}

/// Simulates a network for testing purposes. The channels for the network are simulated as `tokio`
/// channels.
pub struct BadFakeNetwork {
    /// Fake nodes channels to send information to the network
    net_channels: Vec<Sender<(PartyId, Vec<u8>)>>,
    /// Configuration of the network.
    config: BadFakeNetworkConfig,
    /// Fake nodes connected to the network
    nodes: Vec<FakeBadNode>,
    /// Channels to send messages to clients.
    client_channels: HashMap<ClientId, Sender<Vec<u8>>>,
    /// The sender ID of this network instance (which party this represents)
    self_id: PartyId,
    /// Shared connection broker for establishing peer connections
    broker: Option<Arc<FakeConnectionBroker>>,
    /// Channel for receiving incoming connections from accept()
    incoming_rx: Option<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Arc<dyn PeerConnection>>>>,
    /// Established peer connections, keyed by remote party ID
    peer_connections: HashMap<PartyId, Arc<dyn PeerConnection>>,
}

impl BadFakeNetwork {
    /// Returns a reference to the established peer connections.
    pub fn get_peer_connections(&self) -> &HashMap<PartyId, Arc<dyn PeerConnection>> {
        &self.peer_connections
    }

    /// Creates a new bad fake network for testing using the given number of nodes and configuration.
    /// Returns
    ///   1. a receiving endpoint to receive messages sent by nodes at the delaying thread
    ///   2. sending endpoints to deliver messages to nodes from the delaying thread, connected to
    ///      those in (1)
    ///   3. receiving endpoints to receive messages from the network, connected to those in (2)
    ///   4. a mapping of client IDs to their corresponding receiving endpoints at the client
    ///      The sending endpoints connected to (1) and (4) are managed by the network and exposed via
    ///      the `BadFakeNetwork::send` and `BadFakeNetwork::send_to_client` functions.
    #[allow(clippy::type_complexity)]
    pub fn new(
        self_id: PartyId,
        n_nodes: usize,
        n_clients: Option<Vec<ClientId>>,
        config: BadFakeNetworkConfig,
    ) -> (
        Self,
        Receiver<(PartyId, Vec<u8>)>,
        Vec<Sender<Vec<u8>>>,
        Vec<Receiver<Vec<u8>>>,
        HashMap<ClientId, Receiver<Vec<u8>>>,
    ) {
        let (net_channel, net_rx) = mpsc::channel(config.channel_buff_size);
        let mut net_channels = vec![net_channel];
        for _ in 1..n_nodes {
            net_channels.push(net_channels[0].clone());
        }

        let mut node_channels = Vec::new();
        let mut nodes = Vec::new();
        let mut receivers = Vec::new();
        for id in 0..n_nodes {
            let (sender, receiver) = mpsc::channel(config.channel_buff_size);
            node_channels.push(sender);
            nodes.push(FakeBadNode::new(PartyId::from(id)));
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
                net_channels,
                config,
                nodes,
                client_channels: client_channels.clone(),
                self_id,
                broker: None,
                incoming_rx: None,
                peer_connections: HashMap::new(),
            },
            net_rx,
            node_channels,
            receivers,
            client_receivers,
        )
    }

    /// Creates a mesh of N BadFakeNetworks, one per node, sharing a connection broker.
    /// Each network can establish PeerConnections with any other network in the mesh
    /// via the NetworkManager trait.
    ///
    /// Returns a vector of tuples containing each network's components.
    #[allow(clippy::type_complexity)]
    pub fn new_mesh(
        n_nodes: usize,
        n_clients: Option<Vec<ClientId>>,
        config: BadFakeNetworkConfig,
    ) -> Vec<(
        Self,
        Receiver<(PartyId, Vec<u8>)>,
        Vec<Sender<Vec<u8>>>,
        Vec<Receiver<Vec<u8>>>,
        HashMap<ClientId, Receiver<Vec<u8>>>,
    )> {
        let broker = Arc::new(FakeConnectionBroker::new());
        let mut results = Vec::with_capacity(n_nodes);

        for i in 0..n_nodes {
            let node_config = BadFakeNetworkConfig::new(config.channel_buff_size);
            let self_id = PartyId::from(i);
            let (mut net, net_rx, node_channels, receivers, client_receivers) =
                Self::new(self_id, n_nodes, n_clients.clone(), node_config);

            net.broker = Some(Arc::clone(&broker));

            // Create incoming connection channel and register with broker
            let (incoming_tx, incoming_rx) =
                tokio::sync::mpsc::channel(config.channel_buff_size);
            let addr = SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                self_id as u16,
            );
            broker.register_listener(addr, incoming_tx);
            net.incoming_rx = Some(tokio::sync::Mutex::new(incoming_rx));

            results.push((net, net_rx, node_channels, receivers, client_receivers));
        }

        results
    }

    /// Starts the thread, which delays messages and then sends them to the receivers.
    /// Messages can be sent before calling this function, but they will only arrive after starting
    /// this function.
    ///
    /// Repeat this forever:
    /// 1. Wait for either 2. or 3. to happen using `tokio::select!`.
    /// 2. If a message is received by the delaying thread from a node first,
    ///    a. a random delay for the message is sampled from the given distribution
    ///    b. `send_next_msgs` is called to add the new message and send any messages whose
    ///    delay has expired
    ///    c. The timer's expiration time is updated for the next iteration.
    /// 3. If the current timer expires first,
    ///    a. `send_next_msgs` is called to send any messages whose delay has expired
    ///    b. The timer's expiration time is updated for the next iteration.
    pub fn start(
        mut net_rx: Receiver<(PartyId, Vec<u8>)>,
        mut node_channels: Vec<Sender<Vec<u8>>>,
        mut rng: StdRng,
        delay_dist: impl Distribution<u64> + 'static + Send,
    ) -> JoinHandle<()> {
        spawn(async move {
            let mut net_msgs = BinaryHeap::new();
            let mut duration = Duration::MAX;
            let mut timer_start = Instant::now();

            loop {
                let timer = sleep(duration);

                #[cfg(debug_assertions)]
                debug!("TIME: new timer started with duration={:?}", duration);

                tokio::pin!(timer);

                // 1.
                tokio::select! {
                    // 2.
                    id_msg = net_rx.recv() => {
                        if id_msg.is_none() {
                            panic!("channel closed");
                        }

                        let now = Instant::now();

                        let (id, msg) = id_msg.unwrap();
                        // a.
                        let delay = Duration::from_millis(delay_dist.sample(&mut rng));

                        #[cfg(debug_assertions)]
                        debug!("TIME: recvd msg for {} with delay {:?}", id, delay);

                        // b.
                        duration = send_next_msgs(
                            &mut net_msgs,
                            &mut node_channels,
                            Some(KeyedMessage(delay, (id, msg))),
                            now - timer_start
                        ).await;

                        // c.
                        timer_start = now;
                    }
                    // 3.
                    _ = &mut timer => {
                        let now = Instant::now();

                        #[cfg(debug_assertions)]
                        debug!("TIME: expired, should after {:?}, did after {:?}", duration, now - timer_start);

                        // a.
                        duration = send_next_msgs(&mut net_msgs, &mut node_channels, None, now - timer_start).await;
                        // b.
                        timer_start = now;
                    }
                }
            }
        })
    }
}

#[async_trait]
impl Network for BadFakeNetwork {
    type NodeType = FakeBadNode;
    type NetworkConfig = BadFakeNetworkConfig;

    // Sends a message from a node to the delaying thread, which later forwards it to the right
    // node.
    async fn send(&self, recipient: PartyId, message: &[u8]) -> Result<usize, NetworkError> {
        let idx: usize = recipient.into();
        if self.net_channels.get(idx).is_some() {
            self.net_channels[idx]
                .send((recipient, message.to_vec()))
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
            .net_channels
            .iter()
            .enumerate()
            .map(|(i, sender)| sender.send((PartyId::from(i), msg.clone())));

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

    // Sends a message from a client to the delaying thread, which later forwards it to the right
    // node.
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

    // --- sender_id management (fake network implementations) ---

    fn sender_id(&self) -> PartyId {
        if self.peer_connections.is_empty() {
            return self.self_id;
        }
        let mut all_ids: Vec<PartyId> = vec![self.self_id];
        all_ids.extend(self.peer_connections.keys());
        all_ids.sort();
        all_ids.iter().position(|&id| id == self.self_id).unwrap_or(self.self_id)
    }

    fn assign_sender_ids(&self) -> usize {
        if self.peer_connections.is_empty() {
            return self.nodes.len();
        }
        let mut all_ids: Vec<PartyId> = vec![self.self_id];
        all_ids.extend(self.peer_connections.keys());
        all_ids.sort();

        let mut assigned = 0;
        for (&peer_id, conn) in &self.peer_connections {
            if let Some(pos) = all_ids.iter().position(|&id| id == peer_id) {
                conn.set_sender_id(pos);
                assigned += 1;
            }
        }
        assigned
    }

    fn party_count(&self) -> usize {
        if self.peer_connections.is_empty() {
            return self.nodes.len();
        }
        1 + self.peer_connections.len()
    }

    fn is_fully_connected(&self, expected_count: usize) -> bool {
        if self.peer_connections.is_empty() {
            return self.nodes.len() >= expected_count;
        }
        self.peer_connections.len() >= expected_count.saturating_sub(1)
    }
}

impl NetworkManager for BadFakeNetwork {
    fn connect<'a>(
        &'a mut self,
        address: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = Result<Arc<dyn PeerConnection>, String>> + Send + 'a>> {
        Box::pin(async move {
            let broker = self.broker.as_ref().ok_or_else(|| {
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
            if let Some(remote_id) = conn.sender_id() {
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
            let (tx, rx) = tokio::sync::mpsc::channel(self.config.channel_buff_size);
            self.incoming_rx = Some(tokio::sync::Mutex::new(rx));
            broker.register_listener(bind_address, tx);
            Ok(())
        })
    }
}

/// Represents a node in the BadFakeNetwork.
pub struct FakeBadNode {
    /// The id of the node.
    pub id: PartyId,
    // The channel in which the party receives the messages.
    // pub receiver_channel: Receiver<Vec<u8>>,
}

impl FakeBadNode {
    /// Creates a new fake node.
    pub fn new(id: PartyId) -> Self {
        Self {
            id,
            // receiver_channel: receiver,
        }
    }
}

impl Node for FakeBadNode {
    fn id(&self) -> PartyId {
        self.id
    }

    fn scalar_id<F: ark_ff::Field>(&self) -> F {
        let id: usize = self.id.into();
        F::from(id as u64)
    }
}

/// Configuration for the fake network.
pub struct BadFakeNetworkConfig {
    /// Size of the buffer for the channels in the fake network.
    pub channel_buff_size: usize,
}

impl BadFakeNetworkConfig {
    /// Creates a new configuration for the fake network.
    pub fn new(channel_buff_size: usize) -> Self {
        Self { channel_buff_size }
    }
}

#[cfg(test)]
mod tests {
    use ark_std::rand::{distributions::Uniform, SeedableRng};
    use std::collections::HashSet;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    use super::*;

    #[tokio::test]
    async fn test_fake_network_new() {
        setup_tracing();

        let n_nodes = 5;
        let config = BadFakeNetworkConfig::new(100);
        let (network, _, _, _, _) = BadFakeNetwork::new(0, n_nodes, None, config);

        let channels = network.net_channels.clone();

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
        setup_tracing();

        let n_nodes = 3;
        let config = BadFakeNetworkConfig::new(100);
        let (network, net_rx, node_channels, mut receivers, _) =
            BadFakeNetwork::new(0, n_nodes, None, config);

        BadFakeNetwork::start(
            net_rx,
            node_channels,
            StdRng::seed_from_u64(1u64),
            Uniform::new_inclusive(1, 1),
        );

        let sender_idx: usize = 1;
        let recipient_id = PartyId::from(2usize);
        let recipient_idx: usize = recipient_id.into();
        let message = b"hello";

        // Send a message from the perspective of the network
        let send_result = network.send(recipient_id, message).await;
        sleep(Duration::from_millis(10)).await; // wait for message to make it through the network

        assert!(send_result.is_ok());
        assert_eq!(send_result.unwrap(), message.len());

        // Get the recipient node and try to receive the message
        let recipient_node = &mut receivers[recipient_idx];
        let received_message_result = recipient_node.try_recv();

        assert!(received_message_result.is_ok());
        assert_eq!(received_message_result.unwrap(), message.to_vec());

        // Ensure the other node didn't receive the message
        let other_node1 = &mut receivers[sender_idx];
        let other_received_message_result = other_node1.try_recv();
        assert!(other_received_message_result.is_err()); // Should be empty

        let other_node2 = &mut receivers[2];
        let other_received_message_result = other_node2.try_recv();
        assert!(other_received_message_result.is_err()); // Should be empty
    }

    #[tokio::test]
    async fn test_fake_network_broadcast() {
        setup_tracing();

        let n_nodes = 3;
        let config = BadFakeNetworkConfig::new(100);
        let (network, net_rx, node_channels, mut receivers, _) =
            BadFakeNetwork::new(0, n_nodes, None, config);
        let network = Arc::new(Mutex::new(network));

        BadFakeNetwork::start(
            net_rx,
            node_channels,
            StdRng::seed_from_u64(1u64),
            Uniform::new_inclusive(1, 1),
        );

        let message = b"broadcast";

        let network = network.lock().await;
        let broadcast_result = network.broadcast(message).await;
        assert!(broadcast_result.is_ok());
        assert_eq!(broadcast_result.unwrap(), message.len());

        sleep(Duration::from_millis(10)).await; // wait for broadcast to make it through the network

        // Verify all nodes received the message
        for node_recv in receivers.iter_mut().take(n_nodes) {
            let received_message_result = node_recv.try_recv();
            assert!(received_message_result.is_ok());
            assert_eq!(received_message_result.unwrap(), message.to_vec());
        }
    }

    #[test]
    fn test_fake_node_id_and_scalar_id() {
        setup_tracing();

        use ark_bls12_381::Fr;

        //let (sender, receiver) = mpsc::channel(100);
        let node_id = PartyId::from(123usize);
        let node = FakeBadNode::new(node_id);

        assert_eq!(node.id(), node_id);
        let scalar_id: Fr = node.scalar_id();
        let expected_id: usize = node_id.into();
        assert_eq!(scalar_id, Fr::from(expected_id as u64));
        //drop(sender);
    }

    #[tokio::test]
    async fn test_network_error_on_send_failure() {
        setup_tracing();

        let n_nodes = 2;
        let config = BadFakeNetworkConfig::new(100);
        let (mut network, net_rx, node_channels, _, _) = BadFakeNetwork::new(0, n_nodes, None, config);

        BadFakeNetwork::start(
            net_rx,
            node_channels,
            StdRng::seed_from_u64(1u64),
            Uniform::new_inclusive(1, 1),
        );

        let recipient_id = PartyId::from(1usize);
        let recipient_idx: usize = recipient_id.into();
        let message = b"test";

        // Simulate send failure by removing the recipient's sender
        assert!(
            recipient_idx < network.net_channels.len(),
            "Recipient must exist"
        );

        network.net_channels[recipient_idx] = {
            // Drop the sender by replacing it with a closed channel
            let (closed_sender, _): (Sender<(PartyId, Vec<u8>)>, Receiver<(PartyId, Vec<u8>)>) = mpsc::channel(1);
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
    async fn test_out_of_order() {
        setup_tracing();

        let n_nodes = 2;
        let config = BadFakeNetworkConfig::new(500);
        let (network, net_rx, node_channels, mut receivers, _) =
            BadFakeNetwork::new(0, n_nodes, None, config);

        BadFakeNetwork::start(
            net_rx,
            node_channels,
            StdRng::seed_from_u64(1u64),
            Uniform::new_inclusive(1, 100),
        );

        let n_msgs = 3u32;
        let recipient_id = PartyId::from(1usize);
        let recipient_idx: usize = recipient_id.into();

        for i in 0u32..n_msgs {
            let message = i.to_be_bytes();

            // Send a message from the perspective of the network
            let send_result = network.send(recipient_id, &message[..]).await;

            assert!(send_result.is_ok());
            assert_eq!(send_result.unwrap(), message.len());
        }

        let mut out_of_order = false;
        let recipient_node = &mut receivers[recipient_idx];
        let mut i_recvd = HashSet::new();

        for i in 0..n_msgs {
            let received_message_result = recipient_node.recv().await;

            assert!(received_message_result.is_some());

            let i_msg = u32::from_be_bytes(
                received_message_result
                    .unwrap()
                    .try_into()
                    .expect("received unexpected message"),
            );

            assert!(i_msg < n_msgs);
            assert!(!i_recvd.contains(&i_msg));

            i_recvd.insert(i_msg);

            if i_msg != i {
                out_of_order = true;
            }
        }

        // this can theoretically fail, but with enough messages it is very unlikely
        assert!(out_of_order);
    }

    #[tokio::test]
    async fn test_network_manager_connect_accept() {
        setup_tracing();

        let n_nodes = 3;
        let config = BadFakeNetworkConfig::new(100);
        let mut mesh = BadFakeNetwork::new_mesh(n_nodes, None, config);

        // Take out two networks (delay threads not needed for NetworkManager test)
        let (mut net0, _net_rx0, _node_channels0, _receivers0, _) = mesh.remove(0);
        let (net1, _net_rx1, _node_channels1, _receivers1, _) = mesh.remove(0);

        // net0 connects to net1
        let addr1 = SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            1,
        );

        // Use a shared wrapper so net1 stays alive
        let net1 = Arc::new(Mutex::new(net1));
        let net1_clone = Arc::clone(&net1);

        // Spawn accept on net1 in background
        let accept_handle = tokio::spawn(async move {
            let mut net = net1_clone.lock().await;
            net.accept().await.unwrap()
        });

        // Give accept a moment to be ready, then connect
        tokio::time::sleep(Duration::from_millis(10)).await;
        let client_conn = net0.connect(addr1).await.unwrap();
        let server_conn = accept_handle.await.unwrap();

        // Verify sender_ids
        assert_eq!(client_conn.sender_id(), Some(1)); // net1's self_id
        assert_eq!(server_conn.sender_id(), Some(0)); // net0's self_id

        // Test data exchange
        client_conn.send(b"hello from 0").await.unwrap();
        let msg = server_conn.receive().await.unwrap();
        assert_eq!(msg, b"hello from 0");
    }

    #[tokio::test]
    async fn test_assign_sender_ids() {
        setup_tracing();

        let n_nodes = 3;
        let config = BadFakeNetworkConfig::new(100);
        let mut mesh = BadFakeNetwork::new_mesh(n_nodes, None, config);

        // Take out all three networks (delay threads not needed)
        let (mut net0, _rx0, _nc0, _r0, _) = mesh.remove(0);
        let (mut net1, _rx1, _nc1, _r1, _) = mesh.remove(0);
        let (mut net2, _rx2, _nc2, _r2, _) = mesh.remove(0);

        // Establish connections: 0->1, 0->2
        let addr1 = SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 1);
        let addr2 = SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 2);

        // 0 connects to 1: use a channel to return the accepted conn AND the modified net1
        let (net1_tx, mut net1_rx) = tokio::sync::mpsc::channel::<(Arc<dyn PeerConnection>, BadFakeNetwork)>(1);
        tokio::spawn(async move {
            let conn = net1.accept().await.unwrap();
            net1_tx.send((conn, net1)).await.unwrap();
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        let conn0_to_1 = net0.connect(addr1).await.unwrap();
        let (conn1_from_0, net1) = net1_rx.recv().await.unwrap();

        // 0 connects to 2
        let (net2_tx, mut net2_rx) = tokio::sync::mpsc::channel::<(Arc<dyn PeerConnection>, BadFakeNetwork)>(1);
        tokio::spawn(async move {
            let conn = net2.accept().await.unwrap();
            net2_tx.send((conn, net2)).await.unwrap();
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        let conn0_to_2 = net0.connect(addr2).await.unwrap();
        let (_conn2_from_0, _net2) = net2_rx.recv().await.unwrap();

        // Call assign_sender_ids on net0
        // all_ids = [0, 1, 2] sorted -> positions: 0->0, 1->1, 2->2
        let assigned = net0.assign_sender_ids();
        assert_eq!(assigned, 2);

        // Verify net0's own sender_id is position-based
        assert_eq!(net0.sender_id(), 0);

        // Verify peer connections got position-based sender_ids
        assert_eq!(conn0_to_1.sender_id(), Some(1));
        assert_eq!(conn0_to_2.sender_id(), Some(2));

        // Verify party_count and is_fully_connected
        assert_eq!(net0.party_count(), 3);
        assert!(net0.is_fully_connected(3));
        assert!(!net0.is_fully_connected(4));

        // net1 only accepted from 0, check its state
        let assigned1 = net1.assign_sender_ids();
        assert_eq!(assigned1, 1);
        assert_eq!(net1.sender_id(), 1); // position 1 in [0, 1]
        assert_eq!(net1.party_count(), 2);
        assert!(net1.is_fully_connected(2));
        // conn1_from_0 was reassigned: peer 0 at position 0
        assert_eq!(conn1_from_0.sender_id(), Some(0));
    }
}
