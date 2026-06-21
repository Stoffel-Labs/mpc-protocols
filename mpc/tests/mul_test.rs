pub mod utils;

use crate::utils::test_utils::{
    construct_e2e_input_mul, fan_in_inboxes, setup_tracing, test_setup,
};
use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_std::test_rng;
use std::{collections::HashMap, sync::Arc, time::Duration, vec};
use stoffelcrypto::common::ProtocolSessionId;
use stoffelcrypto::common::{rbc::rbc::Avid, SecretSharingScheme, RBC};
use stoffelcrypto::honeybadger::{
    mul::multiplication::Multiply, robust_interpolate::robust_interpolate::RobustShare,
    ProtocolType, SessionId, WrappedMessage,
};
use stoffelmpc_network::fake_network::SenderId;
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinSet;
use tracing::{info, warn};

#[tokio::test]
async fn mul_e2e_batch_recon_and_rbc() {
    let n_parties = 10;
    let t = 3;
    let no_of_mul = 10;
    // 2 times batch recon for chunks of size t+1=4
    // 1 time RBC for the residue 2

    mul_e2e(n_parties, t, no_of_mul).await;
}

#[tokio::test]
async fn mul_e2e_only_batch_recon() {
    let n_parties = 10;
    let t = 3;
    let no_of_mul = 8;
    // 2 times batch recon for chunks of size t+1=4
    // 0 times RBC for the residue 0

    mul_e2e(n_parties, t, no_of_mul).await;
}

#[tokio::test]
async fn mul_e2e_only_rbc() {
    let n_parties = 10;
    let t = 3;
    let no_of_mul = 3;
    // 0 times batch recon for chunks of size t+1=4
    // 1 time RBC for the residue 3

    mul_e2e(n_parties, t, no_of_mul).await;
}

// Steps:
// 1. setup network
// 2. generate Beaver triples
// 3. Prepare inputs for multiplication
// 4. Create nodes
// 5. Init multiplication at each node
// 6. Setup receive function for each node
// 7. Collect results
// 8. Compare with expected results
async fn mul_e2e(n_parties: usize, t: usize, no_of_mul: usize) {
    setup_tracing();

    let mut rng = test_rng();
    let session_id = SessionId::new(ProtocolType::Mul, SessionId::pack_slot(123, 0, 0), 111);

    // 1. Setup network
    let (network, mut receivers, _, _) = test_setup(n_parties, vec![]);
    // 2. Generate Beaver triples
    let (_, beaver_triples) = construct_e2e_input_mul(n_parties, no_of_mul, t);

    // 3. Prepare inputs for multiplication
    let mut x_values = Vec::new();
    let mut y_values = Vec::new();
    let mut x_inputs_per_node = vec![Vec::new(); n_parties];
    let mut y_inputs_per_node = vec![Vec::new(); n_parties];

    for _i in 0..no_of_mul {
        let x_value = Fr::rand(&mut rng);
        x_values.push(x_value);
        let y_value = Fr::rand(&mut rng);
        y_values.push(y_value);

        let shares_x = RobustShare::compute_shares(x_value, n_parties, t, None, &mut rng).unwrap();
        let shares_y = RobustShare::compute_shares(y_value, n_parties, t, None, &mut rng).unwrap();

        for p in 0..n_parties {
            x_inputs_per_node[p].push(shares_x[p].clone());
            y_inputs_per_node[p].push(shares_y[p].clone());
        }
    }

    // 4. Create nodes
    let mut mul_nodes: Vec<_> = (0..n_parties)
        .map(|id| Multiply::<Fr, Avid<SessionId>>::new(id, n_parties, t).unwrap())
        .collect();

    // 5. Init multiplication at each node
    for i in 0..n_parties {
        match mul_nodes[i]
            .init(
                session_id,
                x_inputs_per_node[i].clone(),
                y_inputs_per_node[i].clone(),
                beaver_triples[i].clone(),
                network[i].clone(),
            )
            .await
        {
            Ok(()) => (),
            Err(e) => {
                panic!(
                    "Test: Unexpected error during init_handler for node {}: {:?}",
                    mul_nodes[i].id, e
                );
            }
        }
    }
    info!("nodes initialized");

    // 6. Setup receive function for each node
    let mut set = JoinSet::new();
    for node in &mul_nodes {
        let mut mul_node = node.clone();
        let receiver = receivers.remove(0);
        let net_clone = network[node.id].clone();
        let inbox: Vec<(SenderId, Receiver<Vec<u8>>)> = receiver
            .into_iter() // MOVE the receivers
            .enumerate()
            .map(|(i, r)| (SenderId::Node(i), r))
            .collect();
        let mut merged_rx = fan_in_inboxes(inbox);

        set.spawn(async move {
            while let Some(msg_bytes) = merged_rx.recv().await {
                // Attempt to deserialize into WrappedMessage
                let wrapped: WrappedMessage = match bincode::deserialize(&msg_bytes.1) {
                    Ok(m) => m,
                    Err(_) => {
                        warn!("failed to deserialize into wrapped message");
                        continue;
                    }
                };
                // Match the message type and route it appropriately
                match &wrapped {
                    WrappedMessage::Rbc(msg) => {
                        if let Err(e) = mul_node
                            .rbc
                            .process(msg.clone(), Arc::clone(&net_clone))
                            .await
                        {
                            warn!("RBC processing error: {e}");
                        }
                        if let Err(e) = mul_node.drain_rbc_output().await {
                            warn!("RBC output handling error: {e}");
                        }
                    }
                    WrappedMessage::BatchRecon(batch_msg) => {
                        match batch_msg.session_id.calling_protocol() {
                            Some(ProtocolType::Mul) => {
                                mul_node
                                    .batch_recon
                                    .process(batch_msg.clone(), Arc::clone(&net_clone))
                                    .await
                                    .expect("batch recon error");
                                mul_node.drain_batch_recon_output().await.unwrap();
                            }
                            _ => {
                                panic!("Unexpected caller of batch recon");
                            }
                        }
                    }
                    _ => {
                        panic!("Unexpected protocol type");
                    }
                }
            }
        });
    }

    info!("receiver task spawned");

    // 7. Collect results
    let mut final_results = HashMap::<usize, Vec<RobustShare<Fr>>>::new();
    for i in 0..n_parties {
        let node = &mul_nodes[i];
        let final_shares = node
            .wait_for_result(session_id, Duration::from_millis(1500))
            .await
            .unwrap();

        final_results.insert(node.id, final_shares);
        if final_results.len() == n_parties {
            // check final_shares consist of correct shares
            for (_, mul_shares) in &final_results {
                assert_eq!(mul_shares.len(), no_of_mul);
                let _ = mul_shares.iter().map(|mul_share| {
                    assert_eq!(mul_share.degree, t);
                    assert_eq!(mul_share.id, node.id);
                });
            }
            break;
        }
    }

    // 8. Compare with expected results
    let mut per_multiplication_shares: Vec<Vec<RobustShare<Fr>>> = vec![Vec::new(); no_of_mul];

    for pid in 0..n_parties {
        for i in 0..no_of_mul {
            per_multiplication_shares[i].push(final_results.get(&pid).unwrap()[i].clone());
        }
    }

    for i in 0..no_of_mul {
        let shares_for_i = per_multiplication_shares[i][0..=(2 * t)].to_vec();
        let (_, z_rec) =
            RobustShare::recover_secret(&shares_for_i, n_parties, t).expect("interpolate failed");
        let expected = x_values[i] * y_values[i];

        assert_eq!(z_rec, expected, "multiplication mismatch at index {}", i);
    }
}
