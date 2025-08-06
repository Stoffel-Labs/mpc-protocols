mod utils;
use crate::utils::triple_gen_utils::{
    create_nodes, get_triple_init_test_shares, spawn_receiver_tasks, test_setup,
};
use ark_bls12_381::Fr;
use itertools::izip;
use std::matches;
use stoffelmpc_mpc::{
    common::{share::shamir::NonRobustShamirShare, SecretSharingScheme},
    honeybadger::{
        robust_interpolate::robust_interpolate::RobustShamirShare, triple_generation::ProtocolState,
    },
};

#[tokio::test]
async fn test_triple_gen_e2e() {
    // setup_tracing();
    let n_parties = 13;
    let threshold = 2;
    let n_shares = 5;
    let session_id = 1111;
    let (random_shares_a, random_shares_b, randousha_pairs, a_values, b_values, _) =
        get_triple_init_test_shares(n_shares, n_parties, threshold);
    let (params, network, receivers) = test_setup(n_parties, threshold, n_shares);
    let (nodes, mut triple_finish_receivers) = create_nodes(n_parties, params.clone());

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
    }
    spawn_receiver_tasks(&nodes, receivers, network.clone());

    // vec[[a_1_1, a_1_2,..., a_1_nparties],..., [a_nshares_1, ... , a_nshares_nparties]]
    let mut a_shares =
        vec![vec![RobustShamirShare::new(Fr::from(0), 0, 0, 0); n_parties]; n_shares];
    let mut b_shares =
        vec![vec![RobustShamirShare::new(Fr::from(0), 0, 0, 0); n_parties]; n_shares];
    let mut ab_shares =
        vec![vec![NonRobustShamirShare::new(Fr::from(0), 0, 0, 0); n_parties]; n_shares];
    for p in 0..n_parties {
        let session = triple_finish_receivers[p].recv().await.unwrap();
        let node = nodes[p].lock().await;
        let storage = node.storage.lock().await;
        let triple_data = storage.get(&session).unwrap().lock().await;
        assert!(matches!(
            triple_data.protocol_state,
            ProtocolState::Finished
        ));

        for (i, triples) in triple_data.protocol_output.iter().enumerate() {
            a_shares[i][p] = triples.a.clone();
            b_shares[i][p] = triples.b.clone();
            ab_shares[i][p] = triples.mult.clone();
        }
    }

    for i in 0..n_shares {
        let (_, a) = RobustShamirShare::recover_secret(&a_shares[i]).unwrap();
        let (_, b) = RobustShamirShare::recover_secret(&b_shares[i]).unwrap();
        let (_, ab) = NonRobustShamirShare::recover_secret(&ab_shares[i]).unwrap();
        assert!(a * b == ab);
        assert!(a == a_values[i]);
        assert!(b == b_values[i]);
    }
}

#[tokio::test]
async fn test_triple_init_test_shares() {
    let n_parties = 15;
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

    // test compute open(ab-r)
    let mut sub_shares_deg_2t_all = Vec::new();

    for p in 0..n_parties {
        let random_shares_a_p = random_shares_a[p].clone();
        let random_shares_b_p = random_shares_b[p].clone();
        let randousha_pairs_p = randousha_pairs[p].clone();
        let mut sub_shares_deg_2t = Vec::new();
        for (share_a, share_b, ran_dou_sha) in
            izip!(&random_shares_a_p, &random_shares_b_p, &randousha_pairs_p)
        {
            let mult_share_deg_2t = share_a.share_mul(share_b).unwrap();
            let sub_share_deg_2t = (mult_share_deg_2t
                - &RobustShamirShare::from(ran_dou_sha.degree_2t.clone()))
                .unwrap();
            sub_shares_deg_2t.push(sub_share_deg_2t);
        }
        sub_shares_deg_2t_all.push(sub_shares_deg_2t);
    }
    for i in 0..n_shares {
        // shares for share i from every party
        let mut shares_i = vec![];
        for p in 0..n_parties {
            let share_i_p = sub_shares_deg_2t_all[p][i].clone();
            shares_i.push(share_i_p);
        }
        let r = RobustShamirShare::recover_secret(&shares_i).unwrap();
        assert!(r.1 == (a_values[i] * b_values[i]) - pairs_values[i]);
    }
}
