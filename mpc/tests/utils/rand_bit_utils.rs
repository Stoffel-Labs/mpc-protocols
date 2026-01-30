use ark_ff::FftField;
use ark_std::test_rng;
use std::sync::Arc;
use stoffelmpc_mpc::common::{SecretSharingScheme, RBC};
use stoffelmpc_mpc::honeybadger::fpmul::rand_bit::{RandBit, RandBitError};
use stoffelmpc_mpc::honeybadger::fpmul::ProtocolState;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::triple_gen::ShamirBeaverTriple;
use stoffelmpc_mpc::honeybadger::{SessionId, WrappedMessage};
use stoffelmpc_network::fake_network::{FakeNetwork, FakeNode};
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{error, info, warn};

pub fn create_nodes<F: FftField, R: RBC>(
    n_parties: usize,
    threshold: usize,
    senders: Vec<Sender<SessionId>>,
) -> Vec<RandBit<F, R>> {
    (0..n_parties)
        .zip(senders)
        .map(|(id, sender)| RandBit::new(id, n_parties, threshold, sender).unwrap())
        .collect()
}

pub enum TestEvent<F: FftField> {
    IoMessage {
        message_bytes: Vec<u8>,
    },
    InitializeNode {
        a_shares: Vec<RobustShare<F>>,
        mult_triples: Vec<ShamirBeaverTriple<F>>,
        session_id: SessionId,
    },
    Shutdown,
}

pub struct NodeHandler<F: FftField, R: RBC + 'static> {
    pub node: RandBit<F, R>,
    pub event_channel: Receiver<TestEvent<F>>,
    node_state: NodeState,
    final_result_data_chan: Sender<(usize, Vec<RobustShare<F>>)>,
    network: Arc<FakeNetwork>,
}

pub enum NodeState {
    NotInitialized,
    Initializing,
    Initialized,
}

impl<F, R> NodeHandler<F, R>
where
    F: FftField,
    R: RBC + 'static,
{
    pub fn new(
        node: RandBit<F, R>,
        event_channel: Receiver<TestEvent<F>>,
        network: Arc<FakeNetwork>,
        final_result_data_chan: Sender<(usize, Vec<RobustShare<F>>)>,
    ) -> Self {
        Self {
            node,
            event_channel,
            network,
            final_result_data_chan,
            node_state: NodeState::NotInitialized,
        }
    }

    pub fn spawn_node_handler_task(mut self) {
        tokio::spawn(async move {
            while let Some(event) = self.event_channel.recv().await {
                match event {
                    TestEvent::IoMessage { message_bytes } => {
                        self.process_message(
                            message_bytes,
                            self.final_result_data_chan.clone(),
                            self.network.clone(),
                        )
                        .await
                    }
                    TestEvent::InitializeNode {
                        a_shares,
                        mult_triples,
                        session_id,
                    } => {
                        self.node
                            .init(a_shares, mult_triples, session_id, self.network.clone())
                            .await
                            .unwrap();
                    }
                    TestEvent::Shutdown => {
                        info!("Shutting down node handler task");
                        break;
                    }
                }
            }
        });
    }

    async fn process_message(
        &mut self,
        message_bytes: Vec<u8>,
        final_result_data_chan: Sender<(usize, Vec<RobustShare<F>>)>,
        network: Arc<FakeNetwork>,
    ) {
        let wrapped: WrappedMessage = match bincode::deserialize(&message_bytes) {
            Ok(m) => m,
            Err(_) => {
                error!("Malformed or unrecognized message format.");
                return;
            }
        };

        match wrapped {
            WrappedMessage::RandBit(rand_bit_message) => {
                info!(
                    self_id = self.node.id,
                    remote_id = rand_bit_message.sender,
                    "Received RandBit message"
                );
                let result = { self.node.process(rand_bit_message.clone()).await };
                match result {
                    Ok(_) => {
                        let protocol_state = {
                            let node_storage_guard = self.node.storage.lock().await;
                            let node_storage_for_sid = node_storage_guard
                                .get(&rand_bit_message.session_id)
                                .unwrap()
                                .lock()
                                .await;
                            node_storage_for_sid.protocol_state.clone()
                        };
                        if protocol_state == ProtocolState::Finished {
                            let resulting_rand_bits = {
                                let node_storage_guard = self.node.storage.lock().await;
                                let node_storage_for_sid = node_storage_guard
                                    .get(&rand_bit_message.session_id)
                                    .unwrap()
                                    .lock()
                                    .await;
                                node_storage_for_sid.protocol_output.clone()
                            };
                            final_result_data_chan
                                .send((self.node.id, resulting_rand_bits.unwrap()))
                                .await
                                .unwrap();
                        }
                    }
                    Err(RandBitError::WaitForAllBatches) => {
                        warn!("Waiting for all batches in RandBit protocol");
                        return;
                    }
                    Err(e) => {
                        return;
                    }
                }
            }
            WrappedMessage::BatchRecon(batch_recon_message) => {
                let result = if batch_recon_message.session_id.sub_id() == 0 {
                    info!(
                        self_id = self.node.id,
                        remote_id = batch_recon_message.sender_id,
                        "Processing message for the RandBit > Multiplication > BatchRecon node"
                    );
                    info!(
                        self_id = self.node.id,
                        remote_id = batch_recon_message.sender_id,
                        "RandBit node lock aquired successfully"
                    );
                    self.node
                        .mult_node
                        .batch_recon
                        .process(batch_recon_message, network.clone())
                        .await
                } else {
                    info!(
                        self_id = self.node.id,
                        remote_id = batch_recon_message.sender_id,
                        "Processing message for the RandBit > BatchRecon node"
                    );
                    info!(
                        self_id = self.node.id,
                        remote_id = batch_recon_message.sender_id,
                        "RandBit node lock aquired successfully"
                    );
                    self.node
                        .batch_recon
                        .process(batch_recon_message, network.clone())
                        .await
                };

                if let Err(e) = result {
                    error!("Encountered an error in batch reconstruction: {:?}", e);
                    return;
                }
            }
            WrappedMessage::Mul(multiplication_message) => {
                info!(
                    self_id = self.node.id,
                    remote_id = multiplication_message.sender,
                    "Received Multiplication message"
                );
                let result = { self.node.mult_node.process(multiplication_message).await };
                if let Err(e) = result {
                    error!("Encountered an error in multiplication: {:?}", e);
                    return;
                }
            }
            message => {
                error!(self_id = self.node.id, "Unexpected message: {message:?}");
            }
        }
    }
}

pub fn spawn_receiver_tasks<F: FftField, R: RBC + 'static>(
    event_senders: Vec<Sender<TestEvent<F>>>,
    receivers: Vec<Receiver<Vec<u8>>>,
) {
    assert_eq!(event_senders.len(), receivers.len());
    for (event_sender, mut receiver) in event_senders.into_iter().zip(receivers.into_iter()) {
        tokio::spawn(async move {
            while let Some(message_bytes) = receiver.recv().await {
                event_sender
                    .send(TestEvent::IoMessage { message_bytes })
                    .await
                    .unwrap();
            }
        });
    }
}

/// Creates dummy inputs for the RandBit protocol.
///
/// # Returns
///
/// - A vector of shares of `a` for each party.
/// - A vector of Beaver triples for each party.
pub fn create_rand_bit_input<F>(
    n_parties: usize,
    threshold: usize,
    batch_size: usize,
) -> (Vec<Vec<RobustShare<F>>>, Vec<Vec<ShamirBeaverTriple<F>>>)
where
    F: FftField,
{
    let mut a_shares = vec![vec![]; n_parties];
    let mut mult_triples = vec![vec![]; n_parties];

    let mut rng = test_rng();

    for _ in 0..batch_size {
        // Computation of the value a.
        let a = F::rand(&mut rng);
        let shares_a =
            RobustShare::<F>::compute_shares(a, n_parties, threshold, None, &mut rng).unwrap();

        // Computation of multiplication triple.
        let x = F::rand(&mut rng);
        let y = F::rand(&mut rng);
        let mult = x * y;
        let x_shares =
            RobustShare::<F>::compute_shares(x, n_parties, threshold, None, &mut rng).unwrap();
        let y_shares =
            RobustShare::<F>::compute_shares(y, n_parties, threshold, None, &mut rng).unwrap();
        let mult_shares =
            RobustShare::<F>::compute_shares(mult, n_parties, threshold, None, &mut rng).unwrap();
        for party_id in 0..n_parties {
            a_shares[party_id].push(shares_a[party_id].clone());
            let mult_triple = ShamirBeaverTriple::new(
                x_shares[party_id].clone(),
                y_shares[party_id].clone(),
                mult_shares[party_id].clone(),
            );
            mult_triples[party_id].push(mult_triple);
        }
    }
    (a_shares, mult_triples)
}
