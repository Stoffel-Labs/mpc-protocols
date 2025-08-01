mod utils;
use ark_ff::UniformRand;
use ark_std::test_rng;
use std::matches;
use stoffelmpc_mpc::{
    common::{share::shamir::NonRobustShamirShare, SecretSharingScheme},
    honeybadger::{
        robust_interpolate::robust_interpolate::RobustShamirShare,
        triple_generation::ProtocolState, DoubleShamirShare,
    },
};

use crate::utils::triple_gen_utils::{create_nodes, get_triple_init_test_shares, test_setup};
use ark_bls12_381::Fr;

#[tokio::test]
async fn test_init() {
    let n_parties = 10;
    let threshold = 3;
    let n_shares = 5;
    let session_id = 1111;
    let (random_shares_a, random_shares_b, randousha_pairs, a_values, b_values, pairs_values) =
        get_triple_init_test_shares(n_shares, n_parties, threshold);
    let (params, network, receivers) = test_setup(n_parties, threshold, n_shares);
    let (nodes, receivers) = create_nodes(n_parties, params.clone());
    println!("{:?}", random_shares_a[0]);
    println!("{:?}", random_shares_b[0]);
    println!("{:?}", randousha_pairs[0][0].degree_2t);
    nodes[0]
        .lock()
        .await
        .init(
            random_shares_a[0].clone(),
            random_shares_b[0].clone(),
            randousha_pairs[0].clone(),
            session_id,
            network.clone(),
        )
        .await
        .unwrap();
    let node0 = nodes[0].lock().await;
    let s_map = node0.storage.lock().await;
    let session_storage = s_map.get(&session_id).unwrap().lock().await;
    assert!(matches!(
        session_storage.protocol_state,
        ProtocolState::Initialized
    ))
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
