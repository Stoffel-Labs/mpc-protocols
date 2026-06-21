use crate::utils::prandbitd_utils::{generate_small_field_bits, spawn_receiver_tasks};
use crate::utils::test_utils::{setup_tracing, test_setup};
use ark_bls12_381::Fr;
use ark_ff::{One, PrimeField, Zero};
use num_integer::binomial;
use std::time::Duration;
use stoffelmpc_mpc::common::math::goldilocks::GoldilocksField;
use stoffelmpc_mpc::common::{ProtocolSessionId, SecretSharingScheme};
use stoffelmpc_mpc::honeybadger::fpmul::f256::{lagrange_interpolate_f2_8, Gf256Domain};
use stoffelmpc_mpc::honeybadger::fpmul::prandbitd::PRandBitDNode;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::{ProtocolType, SessionId};
use tokio::task::JoinSet;
use tracing::info;

mod utils;

#[tokio::test]
async fn prandbitd_correctness_e2e() {
    setup_tracing();

    let num_parties = 5;
    let threshold = 1;
    let batch_size = threshold + 1;
    let k = 16;
    let kappa = 20;
    let nu = f64::log2(binomial(num_parties, threshold) as f64).ceil() as usize;
    let l = k + kappa + nu;

    info!("l value: {}, Bits big field: {}", l, Fr::MODULUS_BIT_SIZE);

    let session_id = SessionId::new(ProtocolType::PRandBit, SessionId::pack_slot(123, 0, 0), 111);

    // Build a fake network.
    let (network, receivers, _, _) = test_setup(num_parties, vec![]);

    // Create nodes for the protocol.
    let mut nodes: Vec<PRandBitDNode<GoldilocksField, Fr>> = (0..num_parties)
        .map(|i| PRandBitDNode::new(i, num_parties, threshold).unwrap())
        .collect();

    // Spawn receiver tasks.
    let _set = spawn_receiver_tasks(num_parties, receivers, nodes.clone(), network.clone()).await;

    // Generate inputs for the protocol.
    let small_field_bits = generate_small_field_bits(num_parties, threshold, batch_size);

    // Initialize nodes.
    let mut set = JoinSet::new();
    for node in &nodes {
        let id = node.id;
        set.spawn({
            let session_id = session_id.clone();
            let small_field_bits = small_field_bits[id].clone();
            let network = network[id].clone();
            let mut node = node.clone();
            async move {
                node.generate_riss(session_id, small_field_bits, l, k, batch_size, network)
                    .await
                    .unwrap()
            }
        });
    }

    while let Some(result) = set.join_next().await {
        result.unwrap();
    }

    // Wait for all the protocols to finish.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut all_outputs_bit = Vec::new();
    let mut all_outputs_int = Vec::new();
    let mut evaluation_points = Vec::new();
    let binary_domain = Gf256Domain::new(num_parties).unwrap();
    for node in &mut nodes {
        let store = node.get_or_create_store(session_id.clone()).await.unwrap();
        let node_id = node.id;
        let store_guard = store.lock().await;

        let shares_bit = store_guard.share_b_2.clone();
        let shares_int = store_guard.share_b_p.clone();

        assert_eq!(shares_bit.len(), batch_size);
        assert_eq!(shares_int.len(), batch_size);

        // Reconstruct the outputs and check that they are bits.
        all_outputs_int.push(shares_int);
        all_outputs_bit.push(shares_bit);
        evaluation_points.push(binary_domain.element(node_id));
    }

    for idx_share in 0..batch_size {
        let mut shares_int = Vec::new();
        let mut shares_bit = Vec::new();
        for node in &nodes {
            shares_int.push(all_outputs_int[node.id][idx_share].clone());
            shares_bit.push(all_outputs_bit[node.id][idx_share].clone());
        }
        let (_, value_int) =
            RobustShare::recover_secret(&shares_int, num_parties, threshold).unwrap();
        assert!(value_int.is_zero() || value_int.is_one());

        let bin_poly = lagrange_interpolate_f2_8(&evaluation_points, &shares_bit);
        let value_bit = bin_poly.coeffs[0];
        assert!(value_bit.is_zero() || value_bit.is_one());

        assert!(
            (value_int.is_zero() && value_bit.is_zero())
                || (value_int.is_one() && value_bit.is_one())
        );
    }
}
