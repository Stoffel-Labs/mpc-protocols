use crate::utils::test_utils::{setup_tracing, test_setup};
use crate::utils::truncpr_utils::{
    generate_input_integer, generate_random_shared_bits, generate_random_shared_int,
    spawn_receiver_tasks,
};
use ark_bls12_381::Fr;
use ark_ff::One;
use stoffelmpc_mpc::common::rbc::rbc::Avid;
use stoffelmpc_mpc::common::SecretSharingScheme;
use stoffelmpc_mpc::honeybadger::fpmul::truncpr::TruncPrNode;
use stoffelmpc_mpc::honeybadger::fpmul::ProtocolState;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::{ProtocolType, SessionId};
use tracing::info;

mod utils;

#[tokio::test]
async fn truncpr_e2e() {
    setup_tracing();
    let num_parties = 5;
    let threshold = 1;
    let k = 10;
    let m = 8;
    let kappa = 20;

    let session_id = SessionId::new(ProtocolType::Trunc, 123, 0, 0, 111);

    // Generate the inputs for the protocol.
    let (a, a_input_shares) = generate_input_integer(num_parties, threshold, k);
    let r_bits = generate_random_shared_bits(num_parties, threshold, m);
    let r_int = generate_random_shared_int(num_parties, threshold, (kappa + k - m) as u64);

    // build a fake network.
    let (network, receivers, _) = test_setup(num_parties, vec![]);

    let (protocol_out_tx, _protocol_out_rx) = tokio::sync::mpsc::channel(128);
    let mut nodes: Vec<TruncPrNode<Fr, Avid>> = (0..num_parties)
        .map(|id| TruncPrNode::new(id, num_parties, threshold, protocol_out_tx.clone()).unwrap())
        .collect();

    let _set = spawn_receiver_tasks(num_parties, receivers, nodes.clone(), network.clone()).await;

    for node in &mut nodes {
        node.init(
            a_input_shares[node.id].clone(),
            k,
            m,
            r_bits[node.id].clone(),
            r_int[node.id].clone(),
            session_id.clone(),
            network.clone(),
        )
        .await
        .unwrap();
    }

    // Wait for all the protocols to finish.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let mut result_shares = Vec::with_capacity(num_parties);
    for node in &mut nodes {
        let store = node.get_or_create_store(session_id.clone()).await;
        let store_guard = store.lock().await;
        assert_eq!(store_guard.protocol_state, ProtocolState::Finished);

        result_shares.push(store_guard.share_d.clone().unwrap())
    }

    let (_, result) = RobustShare::recover_secret(&result_shares, num_parties).unwrap();

    // Compute the real result.
    let real_result = a / (1 << m);
    let real_result_field = Fr::from(real_result as u32);
    info!("real result: {}, result: {}", real_result_field, result);
    assert!(real_result_field == result || real_result_field + Fr::one() == result);
}
