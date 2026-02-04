use crate::utils::rand_bit_utils::{
    create_nodes, create_rand_bit_input, spawn_receiver_tasks, NodeHandler, TestEvent,
};
use crate::utils::test_utils::{setup_tracing, test_setup};
use ark_ff::{AdditiveGroup, Field};
use std::collections::HashMap;
use std::time::Duration;
use stoffelmpc_mpc::common::math::goldilocks::GoldilocksField;
use stoffelmpc_mpc::common::rbc::rbc::Avid;
use stoffelmpc_mpc::common::SecretSharingScheme;
use stoffelmpc_mpc::honeybadger::fpmul::rand_bit::RandBit;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::{ProtocolType, SessionId, WrappedMessage};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::info;

mod utils;

#[tokio::test]
async fn rand_bit_with_small_field_e2e() {
    // Set up test.
    setup_tracing();
    let n_parties = 5;
    let threshold = 1;
    let batch_size = threshold + 1;

    // Create the network for the test.
    let session_id = SessionId::new(ProtocolType::RandBit, 123, 1, 0, 111);
    let (network, receivers, _) = test_setup(n_parties, vec![]);

    // Create the input for the RandBit protocol.
    let (a_shares, mult_triples) =
        create_rand_bit_input::<GoldilocksField>(n_parties, threshold, batch_size);

    // Sender channels for finalized sessions.
    let mut sender_output_channels = Vec::new();
    let mut receiver_output_chanels = Vec::new();
    for _ in 0..n_parties {
        let (sender, receiver) = mpsc::channel(128);
        sender_output_channels.push(sender);
        receiver_output_chanels.push(receiver);
    }

    // Create the nodes for the RandBit protocol.
    let rand_bit_nodes =
        create_nodes::<GoldilocksField, Avid>(n_parties, threshold, sender_output_channels);

    // Chanels to return the output of the computation.
    let (finalization_send, mut finalization_recv) =
        mpsc::channel::<(usize, Vec<RobustShare<GoldilocksField>>)>(128);

    info!("Receiver tasks spawned successfully");

    // Spawn node handlers.
    let mut event_senders = Vec::new();
    for node in rand_bit_nodes {
        let (event_sender, event_receiver) = mpsc::channel(128);
        let node_id = node.id;
        let node_handler = NodeHandler::new(
            node,
            event_receiver,
            network.clone(),
            finalization_send.clone(),
        );
        node_handler.spawn_node_handler_task();
        event_sender
            .send(TestEvent::InitializeNode {
                a_shares: a_shares[node_id].clone(),
                mult_triples: mult_triples[node_id].clone(),
                session_id,
            })
            .await
            .unwrap();
        event_senders.push(event_sender);
    }

    info!("Node handlers spawned successfully");

    spawn_receiver_tasks::<_, Avid>(event_senders, receivers);

    let mut final_results = HashMap::new();
    while let Some((id, rand_bit_shares)) = finalization_recv.recv().await {
        final_results.insert(id, rand_bit_shares);
        if final_results.len() == n_parties {
            for (_, final_result) in final_results {
                assert_eq!(final_result.len(), batch_size);
            }
            break;
        }
    }
}

#[tokio::test]
async fn rand_bit_with_small_field_e2e_simple() {
    setup_tracing();

    let n = 5;
    let t = 1;
    let batch_size = t + 1;

    let session_id = SessionId::new(ProtocolType::RandBit, 123, 0, 0, 111);

    // === Build fake network ===
    let (network, mut receivers, _) = test_setup(n, vec![]);

    // === Create RandBit nodes ===
    let (out_tx, _) = mpsc::channel(128);
    let mut nodes: Vec<RandBit<GoldilocksField, Avid>> = (0..n)
        .map(|i| RandBit::new(i, n, t, out_tx.clone()).unwrap())
        .collect();

    // === Create protocol inputs ===
    let (a_shares, mult_triples) = create_rand_bit_input::<GoldilocksField>(n, t, batch_size);

    // === Spawn receiver tasks ===
    let mut set = tokio::task::JoinSet::new();

    for i in 0..n {
        let mut receiver = receivers.remove(0);
        let mut node = nodes[i].clone();
        let net = network.clone();

        set.spawn(async move {
            while let Some(bytes) = receiver.recv().await {
                let wrapped: WrappedMessage = bincode::deserialize(&bytes).unwrap();
                match wrapped {
                    WrappedMessage::RandBit(msg) => {
                        let _ = node.process(msg).await;
                    }
                    WrappedMessage::BatchRecon(msg) => {
                        if msg.session_id.sub_id() == 0 {
                            let _ = node.batch_recon.process(msg, net.clone()).await;
                        } else {
                            let _ = node.mult_node.batch_recon.process(msg, net.clone()).await;
                        }
                    }
                    WrappedMessage::Mul(msg) => {
                        let _ = node.mult_node.process(msg).await;
                    }
                    _ => {}
                }
            }
        });
    }

    // === Initialize nodes ===
    let mut init_set = JoinSet::new();
    for i in 0..n {
        let mut node = nodes[i].clone();
        let net = network.clone();
        let a = a_shares[i].clone();
        let triples = mult_triples[i].clone();

        init_set.spawn(async move {
            node.init(a, triples, session_id, net).await.unwrap();
        });
    }

    while let Some(res) = init_set.join_next().await {
        res.unwrap();
    }
    // Allow protocol to finish
    tokio::time::sleep(Duration::from_millis(200)).await;

    // === Collect outputs ===
    let mut all_outputs = Vec::new();

    for node in &mut nodes {
        let store = node.get_or_create_storage(session_id).await;
        let s = store.lock().await;

        assert!(
            s.protocol_output.is_some(),
            "Node {} missing RandBit output",
            node.id
        );

        let out = s.protocol_output.clone().unwrap();
        assert_eq!(out.len(), batch_size);

        all_outputs.push(out);
    }

    for j in 0..batch_size {
        let mut shares = Vec::new();
        for i in 0..n {
            shares.push(all_outputs[i][j].clone());
        }
        let (_, bit) = RobustShare::recover_secret(&shares, n).unwrap();
        assert!(
            bit == GoldilocksField::ZERO || bit == GoldilocksField::ONE,
            "Invalid RandBit output: {:?}",
            bit
        );
    }
}
