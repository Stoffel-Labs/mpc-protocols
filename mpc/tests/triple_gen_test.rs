mod utils;
use ark_ff::UniformRand;
use ark_std::test_rng;
use std::{matches, net};
use stoffelmpc_mpc::{
    common::{share::shamir::NonRobustShamirShare, SecretSharingScheme},
    honeybadger::{
        robust_interpolate::robust_interpolate::RobustShamirShare,
        triple_generation::ProtocolState, DoubleShamirShare,
    },
};

use crate::utils::{
    test_utils::{construct_e2e_input, setup_tracing},
    triple_gen_utils::{
        create_nodes, get_triple_init_test_shares, spawn_receiver_tasks, test_setup,
    },
};
use ark_bls12_381::Fr;

#[tokio::test]
async fn test_init() {
    setup_tracing();
    let n_parties = 10;
    let threshold = 3;
    let n_shares = 5;
    let session_id = 1111;
    let (random_shares_a, random_shares_b, randousha_pairs, a_values, b_values, pairs_values) =
        get_triple_init_test_shares(n_shares, n_parties, threshold);
    let (params, network, receivers) = test_setup(n_parties, threshold, n_shares);
    let (nodes, tripe_finish_receivers) = create_nodes(n_parties, params.clone());

    spawn_receiver_tasks(&nodes, receivers, network.clone());
    for (i, node) in nodes.iter().enumerate() {
        node.lock()
            .await
            .init(
                random_shares_a[i].clone(),
                random_shares_b[i].clone(),
                randousha_pairs[i].clone(),
                session_id,
                network.clone(),
            )
            .await
            .unwrap();
        let node_binding = node.lock().await;
        let s_map = node_binding.storage.lock().await;
        let session_storage = s_map.get(&session_id).unwrap().lock().await;
        assert!(matches!(
            session_storage.protocol_state,
            ProtocolState::Initialized
        ))
    }
}

#[tokio::test]
async fn test_triple_init_test_shares() {
    let n_parties = 10;
    let threshold = 3;
    let n_shares = 5;
    let (random_shares_a, random_shares_b, randousha_pairs, a_values, b_values, pairs_values) =
        get_triple_init_test_shares(n_shares, n_parties, threshold);
    for i in 0..n_shares {
        let mut a_i = vec![];
        let mut b_i = vec![];
        let mut randousha_pairs_t_i = vec![];
        let mut randousha_pairs_2t_i = vec![];
        for p in 0..n_parties {
            // let a_i_p = random_shares_a[p][i].clone();
            // let b_i_p = random_shares_b[p][i].clone();
            a_i.push(random_shares_a[p][i].clone());
            b_i.push(random_shares_b[p][i].clone());
            randousha_pairs_t_i.push(randousha_pairs[p][i].degree_t.clone());
            randousha_pairs_2t_i.push(randousha_pairs[p][i].degree_2t.clone());
        }
        assert_eq!(
            RobustShamirShare::recover_secret(&a_i).unwrap().1,
            a_values[i]
        );
        assert_eq!(
            RobustShamirShare::recover_secret(&b_i).unwrap().1,
            b_values[i]
        );
        assert_eq!(
            NonRobustShamirShare::recover_secret(&randousha_pairs_t_i)
                .unwrap()
                .1,
            pairs_values[i]
        );
        assert_eq!(
            NonRobustShamirShare::recover_secret(&randousha_pairs_2t_i)
                .unwrap()
                .1,
            pairs_values[i]
        );
    }
}
