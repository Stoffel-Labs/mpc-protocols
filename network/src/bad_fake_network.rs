use async_trait::async_trait;
use futures::future::join_all;
use std::{cmp::{Ord, PartialOrd, PartialEq, Ordering, Reverse}, collections::{HashMap, BinaryHeap}, marker::Send};
use tokio::{spawn, time::{sleep, Duration, Instant}, sync::mpsc::{self, Receiver, Sender}, task::JoinHandle};
use ark_std::rand::{
    distributions::Distribution,
    rngs::StdRng,
};
use tracing::{info, warn};

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
 */

//pub static mut MAX: Duration = Duration::ZERO;

use stoffelnet::network_utils::{ClientId, Network, NetworkError, Node, PartyId};

async fn send_next_msgs(net_msgs: &mut BinaryHeap<KeyedMessage>, node_channels: &mut Vec<Sender<Vec<u8>>>, recvd_msg: Option<KeyedMessage>, elapsed_time: Duration) -> Duration {
    let mut new_net_msgs = BinaryHeap::new();

    while !net_msgs.is_empty() {
        let mut msg = net_msgs.pop().unwrap();
        if elapsed_time >= msg.0 {
            //unsafe {
            //if elapsed_time - msg.0 > MAX {
            //    MAX = elapsed_time - msg.0;
            //    warn!("TIME: new MAX={:?}", MAX);
            //}}
            //warn!("TIME: sent to {} with elapsed_time={:?} >= delay={:?}", msg.1.0, elapsed_time, msg.0);
            let result = node_channels[msg.1.0].send(msg.1.1.to_vec()).await;
            if result.is_err() {
                panic!("network thread encountered error {}", result.unwrap_err());
            }
        } else {
            //warn!("TIME: msg for {} not ready yet: elapsed_time={:?} < delay={:?}", msg.1.0, elapsed_time, msg.0);
            msg.0 -= elapsed_time;
            new_net_msgs.push(msg);
        }
    }

    if recvd_msg.is_some() {
        new_net_msgs.push(recvd_msg.unwrap());
    }

    *net_msgs = new_net_msgs;
    let next_msg = net_msgs.peek();
    if next_msg.is_none() { Duration::MAX } else { next_msg.unwrap().0 }
}

#[derive(Debug)]
struct KeyedMessage(Duration, (PartyId, Vec<u8>));

impl PartialEq for KeyedMessage {
    fn eq(&self, other: &Self) -> bool {
        return self.0 == other.0;
    }
}

impl Eq for KeyedMessage { }
impl PartialOrd for KeyedMessage {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        return Some(Reverse(self.0).cmp(&Reverse(other.0)));
    }
}

impl Ord for KeyedMessage {
    fn cmp(&self, other: &Self) -> Ordering {
        return Reverse(self.0).cmp(&Reverse(other.0));
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
    client_channels: HashMap<ClientId, Sender<Vec<u8>>>
}

impl BadFakeNetwork {
    /// Creates a new fake network for testing using the given number of nodes and configuration.
    pub fn new(
        n_nodes: usize,
        n_clients: Option<Vec<ClientId>>,
        config: BadFakeNetworkConfig
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
            nodes.push(FakeBadNode::new(id));
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
                client_channels: client_channels.clone()
            },
            net_rx,
            node_channels,
            receivers,
            client_receivers,
        )
    }

    /// Starts the thread, which delays messages and then sends them to the receivers.
    /// Messages can be sent before calling this function, but they will only arrive after starting
    /// this function.
    pub fn start(mut net_rx: Receiver<(PartyId, Vec<u8>)>, mut node_channels: Vec<Sender<Vec<u8>>>, mut rng: StdRng, delay_dist: impl Distribution<u64> + 'static + Send) -> JoinHandle<()> {
        spawn(async move {
            let mut net_msgs = BinaryHeap::new();
            let mut duration = Duration::MAX;
            let mut timer_start = Instant::now();
    
            loop {
                let timer = sleep(duration);
                //info!("TIME: new timer started with duration={:?}", duration);
                tokio::pin!(timer);
    
                tokio::select! {
                    id_msg = net_rx.recv() => {
                        if id_msg.is_none() {
                            panic!("channel closed");
                        }

                        let now = Instant::now();
    
                        let (id, msg) = id_msg.unwrap();
                        let delay = Duration::from_millis(delay_dist.sample(&mut rng));
                        //info!("TIME: recvd msg for {} with delay {:?}", id, delay);
    
                        duration = send_next_msgs(
                            &mut net_msgs, 
                            &mut node_channels, 
                            Some(KeyedMessage(delay, (id, msg))),
                            now - timer_start
                        ).await;

                        timer_start = now;
                    }
                    _ = &mut timer => {
                        let now = Instant::now();
                        //info!("TIME: expired, should after {:?}, did after {:?}", duration, now - timer_start);

                        duration = send_next_msgs(&mut net_msgs, &mut node_channels, None, now - timer_start).await;
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

    async fn send(&self, recipient: PartyId, message: &[u8]) -> Result<usize, NetworkError> {
        if !self.net_channels.get(recipient).is_none() {
            self.net_channels[recipient]
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
            .map(|(i, sender)| sender.send((i, msg.clone())));

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
        F::from(self.id as u64)
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
    use std::sync::Arc;
    use std::collections::HashSet;
    use ark_std::rand::{distributions::Uniform, SeedableRng};
    use tokio::sync::Mutex;

    use super::*;

    #[tokio::test]
    async fn test_fake_network_new() {
        let n_nodes = 5;
        let config = BadFakeNetworkConfig::new(100);
        let (network, _, _, _, _) = BadFakeNetwork::new(n_nodes, None, config);

        let channels = network.net_channels.clone();

        assert_eq!(network.nodes.len(), n_nodes);
        assert_eq!(channels.len(), n_nodes);

        for i in 0..n_nodes {
            assert!(channels.get(i).is_some());
            assert!(network.node(i).is_some());
            assert_eq!(network.node(i).unwrap().id(), i);
        }
    }

    #[tokio::test]
    async fn test_fake_network_send_and_receive() {
        let n_nodes = 3;
        let config = BadFakeNetworkConfig::new(100);
        let (network, net_rx, node_channels, mut receivers, _) = BadFakeNetwork::new(n_nodes, None, config);

        BadFakeNetwork::start(net_rx, node_channels, StdRng::seed_from_u64(1u64), Uniform::new_inclusive(1, 1));

        let sender_id = 1;
        let recipient_id = 2;
        let message = b"hello";

        // Send a message from the perspective of the network
        let send_result = network.send(recipient_id, message).await;
        sleep(Duration::from_millis(10)).await; // wait for message to make it through the network

        assert!(send_result.is_ok());
        assert_eq!(send_result.unwrap(), message.len());

        // Get the recipient node and try to receive the message
        let recipient_node = &mut receivers[recipient_id];
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
        let config = BadFakeNetworkConfig::new(100);
        let (network, net_rx, node_channels, mut receivers, _) = BadFakeNetwork::new(n_nodes, None, config);
        let network = Arc::new(Mutex::new(network));

        BadFakeNetwork::start(net_rx, node_channels, StdRng::seed_from_u64(1u64), Uniform::new_inclusive(1, 1));

        let message = b"broadcast";

        let network = network.lock().await;
        let broadcast_result = network.broadcast(message).await;
        assert!(broadcast_result.is_ok());
        assert_eq!(broadcast_result.unwrap(), message.len());

        sleep(Duration::from_millis(10)).await; // wait for broadcast to make it through the network

        // Verify all nodes received the message
        for i in 0..n_nodes {
            let node_recv = &mut receivers[i];
            let received_message_result = node_recv.try_recv();
            assert!(received_message_result.is_ok());
            assert_eq!(received_message_result.unwrap(), message.to_vec());
        }
    }

    #[test]
    fn test_fake_node_id_and_scalar_id() {
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
        let n_nodes = 2;
        let config = BadFakeNetworkConfig::new(100);
        let (mut network, net_rx, node_channels, _, _) = BadFakeNetwork::new(n_nodes, None, config);

        BadFakeNetwork::start(net_rx, node_channels, StdRng::seed_from_u64(1u64), Uniform::new_inclusive(1, 1));

        let recipient_id = 1;
        let message = b"test";

        // Simulate send failure by removing the recipient's sender
        assert!(
            recipient_id < network.net_channels.len(),
            "Recipient must exist"
        );

        network.net_channels[recipient_id] = {
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
    async fn test_out_of_order() {
        let n_nodes = 2;
        let config = BadFakeNetworkConfig::new(500);
        let (network, net_rx, node_channels, mut receivers, _) = BadFakeNetwork::new(n_nodes, None, config);

        BadFakeNetwork::start(net_rx, node_channels, StdRng::seed_from_u64(1u64), Uniform::new_inclusive(1, 100));

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
        let recipient_node = &mut receivers[recipient_id];
        let mut i_recvd = HashSet::new();

        for i in 0..n_msgs {
            let received_message_result = recipient_node.recv().await;

            assert!(received_message_result.is_some());

            let i_msg = u32::from_be_bytes(received_message_result.unwrap().try_into().expect("received unexpected message"));

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
