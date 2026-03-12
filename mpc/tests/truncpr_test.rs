use crate::utils::test_utils::{setup_tracing, test_setup};
use crate::utils::truncpr_utils::{
    generate_input_integer_z_k, generate_random_shared_bits, generate_random_shared_int,
    spawn_receiver_tasks,
};
use ark_bls12_381::Fr;
use ark_ff::{Field, One, Zero};
use stoffelmpc_mpc::common::rbc::rbc::Avid;
use stoffelmpc_mpc::common::{ProtocolSessionId, SecretSharingScheme};
use stoffelmpc_mpc::honeybadger::fpmul::truncpr::TruncPrNode;
use stoffelmpc_mpc::honeybadger::fpmul::{mod_pow_2_from_field, ProtocolState};
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::{ProtocolType, SessionId};
use tracing::{info, warn};

mod utils;

#[tokio::test]
async fn truncpr_e2e() {
    setup_tracing();
    let num_parties = 5;
    let threshold = 1;
    let k = 20;
    let m = 2;
    let kappa = 10;

    let session_id = SessionId::new(ProtocolType::Trunc, SessionId::pack_slot24(123, 0, 0), 111);
    // Generate the inputs for the protocol.
    let (a, a_input_shares) = generate_input_integer_z_k(num_parties, threshold, k);
    let r_bits = generate_random_shared_bits(num_parties, threshold, m);
    let r_int = generate_random_shared_int(num_parties, threshold, (kappa + k - m) as u64);

    // build a fake network.
    let (network, receivers, _) = test_setup(num_parties, vec![]);

    let mut nodes: Vec<TruncPrNode<Fr, Avid<SessionId>>> = (0..num_parties)
        .map(|id| TruncPrNode::new(id, num_parties, threshold).unwrap())
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
    tokio::time::sleep(std::time::Duration::from_millis(2000)).await;

    let mut result_shares = Vec::with_capacity(num_parties);
    for node in &mut nodes {
        let store = node.get_or_create_store(session_id.clone()).await;
        let store_guard = store.lock().await;

        result_shares.push(store_guard.share_d.clone().unwrap())
    }

    let (_, result) = RobustShare::recover_secret(&result_shares, num_parties).unwrap();

    // Compute the real result.
    let real_result = a >> m;
    let real_result_field = Fr::from(real_result as u32);
    info!(
        "a: {}, real result: {}, result: {}",
        a, real_result_field, result
    );
    assert!(real_result_field == result || real_result_field + Fr::one() == result);
}

#[test]
fn test_mod_2_pow_m() {
    // Tests for m = 10
    let m = 10;
    let x = Fr::from(1u64);
    let expected = Fr::from(1u64 % 2u64.pow(m as u32));
    assert_eq!(mod_pow_2_from_field(x, m), expected);

    let x = Fr::zero();
    assert_eq!(mod_pow_2_from_field(x, m), Fr::zero());

    let x = Fr::from(2u64.pow(m as u32));
    assert_eq!(mod_pow_2_from_field(x, m), Fr::zero());

    let x = Fr::from(2u64.pow(m as u32) + 1);
    assert_eq!(mod_pow_2_from_field(x, m), Fr::one());

    let x = Fr::from(2u64.pow((m + 2) as u32));
    assert_eq!(mod_pow_2_from_field(x, m), Fr::zero());

    // Tests for m = 8
    let m = 8;
    let x = Fr::from(1u64);
    let expected = Fr::from(1u64 % 2u64.pow(m as u32));
    assert_eq!(mod_pow_2_from_field(x, m), expected);

    let x = Fr::zero();
    assert_eq!(mod_pow_2_from_field(x, m), Fr::zero());

    let x = Fr::from(2u64.pow(m as u32));
    assert_eq!(mod_pow_2_from_field(x, m), Fr::zero());

    let x = Fr::from(2u64.pow((m + 1) as u32));
    assert_eq!(mod_pow_2_from_field(x, m), Fr::zero());

    let x = Fr::from(2u64.pow((m + 5) as u32) + 1);
    assert_eq!(mod_pow_2_from_field(x, m), Fr::one());
}
