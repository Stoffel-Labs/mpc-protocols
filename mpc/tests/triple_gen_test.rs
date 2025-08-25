mod utils;
use crate::utils::{
    test_utils::{setup_tracing, test_setup},
    triple_gen_utils::{create_nodes, get_triple_init_test_shares, spawn_receiver_tasks},
};
use ark_bls12_381::Fr;
use itertools::izip;
use std::matches;
use stoffelmpc_mpc::{
    common::{share::shamir::NonRobustShare, SecretSharingScheme},
    honeybadger::{
        robust_interpolate::robust_interpolate::RobustShare,
        triple_gen::triple_generation::ProtocolState, ProtocolType, SessionId,
    },
};

#[tokio::test]
async fn test_triple_gen_e2e() {
    setup_tracing();
    let n_parties = 13;
    let threshold = 2;
    let n_shares = 5;
    let session_id = SessionId::new(ProtocolType::Triple, 111);
    let (random_shares_a, random_shares_b, randousha_pairs, a_values, b_values, _) =
        get_triple_init_test_shares(n_shares, n_parties, threshold);
    let (network, receivers, _) = test_setup(n_parties, vec![]);
    let (nodes, mut triple_finish_receivers) = create_nodes(n_parties, threshold, n_shares);

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
    let mut a_shares = vec![vec![RobustShare::new(Fr::from(0), 0, 0); n_parties]; n_shares];
    let mut b_shares = vec![vec![RobustShare::new(Fr::from(0), 0, 0); n_parties]; n_shares];
    let mut ab_shares = vec![vec![RobustShare::new(Fr::from(0), 0, 0); n_parties]; n_shares];
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
        let (_, a) = RobustShare::recover_secret(&a_shares[i], n_parties).unwrap();
        let (_, b) = RobustShare::recover_secret(&b_shares[i], n_parties).unwrap();
        let (_, ab) = RobustShare::recover_secret(&ab_shares[i], n_parties).unwrap();
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
            RobustShare::recover_secret(&a_i, n_parties)
                .unwrap()
                .1,
            a_values[i]
        );
        assert_eq!(
            RobustShare::recover_secret(&b_i, n_parties)
                .unwrap()
                .1,
            b_values[i]
        );
        assert_eq!(
            NonRobustShare::recover_secret(&randousha_pairs_t_i, n_parties)
                .unwrap()
                .1,
            pairs_values[i]
        );
        assert_eq!(
            NonRobustShare::recover_secret(&randousha_pairs_2t_i, n_parties)
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
                - RobustShare::from(ran_dou_sha.degree_2t.clone()))
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
        let r = RobustShare::recover_secret(&shares_i, n_parties).unwrap();
        assert!(r.1 == (a_values[i] * b_values[i]) - pairs_values[i]);
    }
}
