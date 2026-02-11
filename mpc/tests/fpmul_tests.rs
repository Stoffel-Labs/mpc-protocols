use crate::utils::fpmul_utils::{
    generate_beaver_triple, generate_random_input, initialize_nodes, spawn_receiver_tasks,
};
use crate::utils::test_utils::{setup_tracing, test_setup};
use crate::utils::truncpr_utils::{generate_random_shared_bits, generate_random_shared_int};
use ark_bn254::Fr;
use ark_ff::One;
use stoffelmpc_mpc::common::rbc::rbc::Avid;
use stoffelmpc_mpc::common::SecretSharingScheme;
use stoffelmpc_mpc::honeybadger::fpmul::fpmul::FPMulNode;
use stoffelmpc_mpc::honeybadger::fpmul::ProtocolState;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::{ProtocolType, SessionId};
use tracing::info;

mod utils;

#[tokio::test]
async fn fpmul_e2e() {
    setup_tracing();
    let num_parties = 5;
    let threshold = 1;
    let f = 8;
    let k = 10;
    let kappa = 10;

    let session_id = SessionId::new(ProtocolType::FpMul, 123, 0, 0, 111);

    // Build a fake network.
    let (network, receivers, _) = test_setup(num_parties, vec![]);

    // Create nodes for the protocol.
    let (protocol_out_tx, _protocol_out_rx) = tokio::sync::mpsc::channel(128);
    let mut nodes: Vec<FPMulNode<Fr, Avid>> = (0..num_parties)
        .map(|node_id| {
            FPMulNode::new(node_id, num_parties, threshold, protocol_out_tx.clone()).unwrap()
        })
        .collect();

    // Generate inputs for the protocol.
    let (a, a_input_shares) = generate_random_input(num_parties, threshold, k);
    let (b, b_input_shares) = generate_random_input(num_parties, threshold, k);
    let r_bits_shares = generate_random_shared_bits(num_parties, threshold, f);
    let r_int_shares =
        generate_random_shared_int(num_parties, threshold, (kappa + 2 * k - f) as u64);
    let mult_triple = generate_beaver_triple(num_parties, threshold);

    // Spawn the receiver tasks to forward the messages.
    let _set = spawn_receiver_tasks(num_parties, receivers, nodes.clone(), network.clone()).await;

    // Initialize the nodes.
    let mut init_set = initialize_nodes(
        num_parties,
        a_input_shares,
        b_input_shares,
        mult_triple,
        r_bits_shares,
        r_int_shares,
        session_id,
        nodes.clone(),
        network.clone(),
    )
    .await;

    while let Some(init_task) = init_set.join_next().await {
        init_task.unwrap();
    }

    // Wait for all the protocols to finish.
    tokio::time::sleep(std::time::Duration::from_millis(1000)).await;

    // Compute the expected result.
    let mult = a * b;
    let trunc_mult = mult / (1 << f);
    let expected_result = Fr::from(trunc_mult);

    // Reconstruct the output from the protocol.
    let mut result_shares = Vec::with_capacity(num_parties);
    for node in &mut nodes {
        let storage = node.get_or_create_store(session_id).await;
        let storage_guard = storage.lock().await;
        assert_eq!(storage_guard.protocol_state, ProtocolState::Finished);
        let output = storage_guard.protocol_output.clone().unwrap();
        result_shares.push(output.value().clone());
    }

    let (_, result) = RobustShare::recover_secret(&result_shares, num_parties).unwrap();
    info!("expected: {}, result: {}", expected_result, result);
    assert!(expected_result == result || expected_result + Fr::one() == result);
}
