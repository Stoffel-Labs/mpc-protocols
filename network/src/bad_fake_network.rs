use ark_std::rand::{distributions::Distribution, rngs::StdRng};
use async_trait::async_trait;
use futures::future::join_all;
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
use tracing_subscriber::EnvFilter;
use tracing_subscriber::FmtSubscriber;
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
    node_channels: &mut [Vec<Sender<Vec<u8>>>],
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
                    msg.1 .1, elapsed_time, msg.0
                );
            }

            // 3.
            let (from, to, payload) = &msg.1;
            let result = node_channels[*from][*to].send(payload.to_vec()).await;
            if let Err(e) = result {
                panic!("network thread encountered error {}", e);
            }
        } else {
            #[cfg(debug_assertions)]
            debug!(
                "TIME: msg for {} not ready yet: elapsed_time={:?} < delay={:?}",
                msg.1 .1, elapsed_time, msg.0
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
    let next_msg = net_msgs.peek();
    if let Some(m) = next_msg {
        m.0
    } else {
        Duration::MAX
    }
}

#[derive(Debug)]
struct KeyedMessage(Duration, (PartyId, PartyId, Vec<u8>));
// (from, to, msg)

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
#[derive(Clone)]
pub struct BadFakeInnerNetwork {
    /// Fake nodes channels to send information to the network
    net_channels: Vec<Sender<(PartyId, PartyId, Vec<u8>)>>,
    /// Configuration of the network.
    config: BadFakeNetworkConfig,
    /// Fake nodes connected to the network
    nodes: Vec<FakeBadNode>,
    /// Channels to send messages to clients.
    to_client_channels: HashMap<ClientId, Vec<Sender<Vec<u8>>>>,
    client_channels: HashMap<ClientId, Vec<Sender<Vec<u8>>>>, // [client][to_node]
}

impl BadFakeInnerNetwork {
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
        n_nodes: usize,
        n_clients: Option<Vec<ClientId>>,
        config: BadFakeNetworkConfig,
    ) -> (
        Self,
        Receiver<(PartyId, PartyId, Vec<u8>)>,
        Vec<Vec<Sender<Vec<u8>>>>,
        Vec<Vec<Receiver<Vec<u8>>>>,
        HashMap<ClientId, Vec<Receiver<Vec<u8>>>>,
    ) {
        let (net_channel, net_rx) = mpsc::channel(config.channel_buff_size);
        let mut net_channels = Vec::new();
        for _ in 0..n_nodes {
            net_channels.push(net_channel.clone());
        }

        // ---- nodes ----
        let mut nodes = Vec::with_capacity(n_nodes);
        for id in 0..n_nodes {
            nodes.push(FakeBadNode::new(id));
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
        let mut to_client_channels = HashMap::new();
        let mut client_receivers = HashMap::new();

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
                net_channels,
                config,
                nodes,
                to_client_channels,
                client_channels,
            },
            net_rx,
            node_channels,
            inboxes,
            client_receivers,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum BadSenderId {
    Node(PartyId),
    Client(ClientId),
}

#[derive(Clone)]
pub struct BadFakeNetwork {
    sender: BadSenderId,
    inner: BadFakeInnerNetwork,
}
impl BadFakeNetwork {
    pub fn new(id: PartyId, inner: BadFakeInnerNetwork) -> Self {
        Self {
            sender: BadSenderId::Node(id),
            inner,
        }
    }

    pub fn new_client(id: ClientId, inner: BadFakeInnerNetwork) -> Self {
        Self {
            sender: BadSenderId::Client(id),
            inner,
        }
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
        mut net_rx: Receiver<(PartyId, PartyId, Vec<u8>)>,
        mut node_channels: Vec<Vec<Sender<Vec<u8>>>>,
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

                        let (from, to, msg) = id_msg.unwrap();

                        // a.
                        let delay = Duration::from_millis(delay_dist.sample(&mut rng));

                        #[cfg(debug_assertions)]
                        debug!("TIME: recvd msg for {} with delay {:?}", to, delay);

                        // b.
                        duration = send_next_msgs(
                            &mut net_msgs,
                            &mut node_channels,
                            Some(KeyedMessage(delay, (from, to, msg))),
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
        match self.sender {
            BadSenderId::Node(from) => {
                self.inner.net_channels[from]
                    .send((from, recipient, message.to_vec()))
                    .await
                    .map_err(|_| NetworkError::SendError)?;
            }

            BadSenderId::Client(client_id) => {
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

        match self.sender {
            BadSenderId::Node(from) => {
                if from >= self.inner.net_channels.len() {
                    return Err(NetworkError::PartyNotFound(from));
                }

                let futures = (0..self.inner.nodes.len())
                    .map(|to| self.inner.net_channels[from].send((from, to, msg.clone())));

                let results = join_all(futures).await;

                if results.iter().any(|r| r.is_err()) {
                    return Err(NetworkError::SendError);
                }
            }
            BadSenderId::Client(client_id) => {
                let row = self
                    .inner
                    .client_channels
                    .get(&client_id)
                    .ok_or(NetworkError::ClientNotFound(client_id))?;

                let futures = row.iter().map(|tx| tx.send(msg.clone()));

                let results = join_all(futures).await;

                if results.iter().any(|r| r.is_err()) {
                    return Err(NetworkError::SendError);
                }
            }
        };

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

    // Sends a message from a client to the delaying thread, which later forwards it to the right
    // node.
    async fn send_to_client(
        &self,
        client: ClientId,
        message: &[u8],
    ) -> Result<usize, NetworkError> {
        let from = match self.sender {
            BadSenderId::Node(id) => id,
            BadSenderId::Client(_) => {
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

    fn local_party_id(&self) -> PartyId {
        match self.sender {
            BadSenderId::Node(i) => i,
            BadSenderId::Client(i) => i,
        }
    }

    fn party_count(&self) -> usize {
        self.inner.nodes.len()
    }
}

/// Represents a node in the BadFakeNetwork.
#[derive(Clone)]
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
        F::from(self.id as u64)
    }
}

/// Configuration for the fake network.
#[derive(Clone)]
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
    use tokio::time::timeout;

    use super::*;

    pub fn fan_in_inboxes(
        inboxes: Vec<(BadSenderId, Receiver<Vec<u8>>)>,
    ) -> Receiver<(BadSenderId, Vec<u8>)> {
        let (tx, rx) = mpsc::channel(300);

        for (sender, mut rx_i) in inboxes {
            let tx_i = tx.clone();
            tokio::spawn(async move {
                while let Some(msg) = rx_i.recv().await {
                    let _ = tx_i.send((sender, msg)).await;
                }
            });
        }

        rx
    }

    #[tokio::test]
    async fn test_fake_network_new() {
        setup_tracing();

        let n_nodes = 5;
        let config = BadFakeNetworkConfig::new(100);
        let (inner, _, _, _, _) = BadFakeInnerNetwork::new(n_nodes, None, config);
        let network = BadFakeNetwork::new(0, inner);
        let channels = network.inner.net_channels.clone();

        assert_eq!(network.inner.nodes.len(), n_nodes);
        assert_eq!(channels.len(), n_nodes);

        for i in 0..n_nodes {
            assert!(channels.get(i).is_some());
            assert!(network.node(i).is_some());
            assert_eq!(network.node(i).unwrap().id(), i);
        }
    }

    #[tokio::test]
    async fn test_fake_network_send_and_receive() {
        setup_tracing();

        let n_nodes = 3;
        let config = BadFakeNetworkConfig::new(100);
        let (inner, net_rx, node_channels, mut receivers, _) =
            BadFakeInnerNetwork::new(n_nodes, None, config);
        let network = BadFakeNetwork::new(0, inner);

        BadFakeNetwork::start(
            net_rx,
            node_channels,
            StdRng::seed_from_u64(1u64),
            Uniform::new_inclusive(1, 1),
        );

        let recipient_id = 2;
        let message = b"hello";

        // Send a message from the perspective of the network
        let send_result = network.send(recipient_id, message).await;
        sleep(Duration::from_millis(10)).await; // wait for message to make it through the network

        assert!(send_result.is_ok());
        assert_eq!(send_result.unwrap(), message.len());

        // Get the recipient node and try to receive the message
        let recipient_node = receivers.remove(recipient_id);
        let inbox: Vec<(BadSenderId, Receiver<Vec<u8>>)> = recipient_node
            .into_iter() // MOVE the receivers
            .enumerate()
            .map(|(i, r)| (BadSenderId::Node(i), r))
            .collect();
        let mut merge_rx = fan_in_inboxes(inbox);
        let received_message_result = timeout(Duration::from_millis(50), merge_rx.recv())
            .await
            .expect("timed out waiting for merged message");

        assert!(received_message_result.is_some());
        assert_eq!(received_message_result.unwrap().1, message.to_vec());

        // Ensure the other node didn't receive the message
        for _ in 0..2 {
            let other_node1 = receivers.remove(0);
            let inbox: Vec<(BadSenderId, Receiver<Vec<u8>>)> = other_node1
                .into_iter() // MOVE the receivers
                .enumerate()
                .map(|(i, r)| (BadSenderId::Node(i), r))
                .collect();
            let mut merge_rx = fan_in_inboxes(inbox);
            let other_received_message_result = merge_rx.try_recv();
            assert!(other_received_message_result.is_err()); // Should be empty
        }
    }

    #[tokio::test]
    async fn test_fake_network_broadcast() {
        setup_tracing();

        let n_nodes = 3;
        let config = BadFakeNetworkConfig::new(100);
        let (inner, net_rx, node_channels, mut receivers, _) =
            BadFakeInnerNetwork::new(n_nodes, None, config);
        let network = Arc::new(Mutex::new(BadFakeNetwork::new(0, inner)));

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
        for _ in 0..n_nodes {
            let node_recv = receivers.remove(0);
            let inbox: Vec<(BadSenderId, Receiver<Vec<u8>>)> = node_recv
                .into_iter() // MOVE the receivers
                .enumerate()
                .map(|(i, r)| (BadSenderId::Node(i), r))
                .collect();
            let mut merge_rx = fan_in_inboxes(inbox);
            let received_message_result = timeout(Duration::from_millis(50), merge_rx.recv())
                .await
                .expect("timed out waiting for merged message");
            assert!(received_message_result.is_some());
            assert_eq!(received_message_result.unwrap().1, message.to_vec());
        }
    }

    #[test]
    fn test_fake_node_id_and_scalar_id() {
        setup_tracing();

        use ark_bls12_381::Fr;

        //let (sender, receiver) = mpsc::channel(100);
        let node_id = 123;
        let node = FakeBadNode::new(node_id);

        assert_eq!(node.id(), node_id);
        let scalar_id: Fr = node.scalar_id();
        assert_eq!(scalar_id, Fr::from(node_id as u64));
        //drop(sender);
    }

    #[tokio::test]
    async fn test_network_error_on_send_failure() {
        setup_tracing();

        let n_nodes = 2;
        let config = BadFakeNetworkConfig::new(100);
        let (inner, net_rx, node_channels, _, _) = BadFakeInnerNetwork::new(n_nodes, None, config);
        let mut network = BadFakeNetwork::new(0, inner);

        BadFakeNetwork::start(
            net_rx,
            node_channels,
            StdRng::seed_from_u64(1u64),
            Uniform::new_inclusive(1, 1),
        );

        let recipient_id = 1;
        let message = b"test";

        // Simulate send failure by removing the recipient's sender
        assert!(
            recipient_id < network.inner.net_channels.len(),
            "Recipient must exist"
        );

        network.inner.net_channels[0] = {
            let (tx, rx) = mpsc::channel::<(PartyId, PartyId, Vec<u8>)>(1);
            drop(rx); // no receiver alive
            tx
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
        let (inner, net_rx, node_channels, mut receivers, _) =
            BadFakeInnerNetwork::new(n_nodes, None, config);
        let network = BadFakeNetwork::new(0, inner);

        BadFakeNetwork::start(
            net_rx,
            node_channels,
            StdRng::seed_from_u64(1u64),
            Uniform::new_inclusive(1, 100),
        );

        let n_msgs = 3u32;
        let recipient_id = 1;

        for i in 0u32..n_msgs {
            let message = i.to_be_bytes();

            // Send a message from the perspective of the network
            let send_result = network.send(recipient_id, &message[..]).await;

            assert!(send_result.is_ok());
            assert_eq!(send_result.unwrap(), message.len());
        }

        let mut out_of_order = false;
        let recipient_node = receivers.remove(recipient_id);
        let inbox: Vec<(BadSenderId, Receiver<Vec<u8>>)> = recipient_node
            .into_iter() // MOVE the receivers
            .enumerate()
            .map(|(i, r)| (BadSenderId::Node(i), r))
            .collect();
        let mut merge_rx = fan_in_inboxes(inbox);
        let mut i_recvd = HashSet::new();

        for i in 0..n_msgs {
            let received_message_result = merge_rx.recv().await;

            assert!(received_message_result.is_some());

            let i_msg = u32::from_be_bytes(
                received_message_result
                    .unwrap()
                    .1
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
}
