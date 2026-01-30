use crate::utils::rand_bit_utils::{
    create_nodes, create_rand_bit_input, spawn_receiver_tasks, NodeHandler, TestEvent,
};
use crate::utils::test_utils::{setup_tracing, test_setup};
use std::collections::HashMap;
use stoffelmpc_mpc::common::math::goldilocks::GoldilocksField;
use stoffelmpc_mpc::common::rbc::rbc::Avid;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::{ProtocolType, SessionId};
use tokio::sync::mpsc;
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
