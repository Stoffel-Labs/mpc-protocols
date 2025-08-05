use std::{collections::HashMap, sync::Arc, thread, time::Duration};

use ark_bls12_381::Fr;
use ark_std::test_rng;
use stoffelmpc_mpc::common::SecretSharingScheme;
use stoffelmpc_mpc::common::{share::shamir::NonRobustShamirShare, ShamirShare};
use tokio::sync::mpsc;
use tracing::info;
use utils::{
    double_share_utils::{create_nodes, spawn_receiver_tasks, test_setup},
    test_utils::{construct_e2e_input, setup_tracing},
};

pub mod utils;

#[tokio::test]
async fn generate_faulty_double_shares_e2e() {
    setup_tracing();
    let n_parties = 5;
    let threshold = 2;
    let session_id = 1111;

    let (params, network, receivers) = test_setup(n_parties, threshold, session_id);

    let mut sender_channels = Vec::new();
    let mut receiver_channels = Vec::new();
    for _ in 0..n_parties {
        let (sender, receiver) = mpsc::channel(128);
        sender_channels.push(sender);
        receiver_channels.push(receiver);
    }

    let dou_sha_nodes = create_nodes(n_parties, sender_channels);
    let mut rng = test_rng();

    let (final_result_sender, mut final_result_receiver) = mpsc::channel(1024);

    // Setup the receivers and spawn receivers tasks.
    spawn_receiver_tasks(
        &dou_sha_nodes,
        receivers,
        &params,
        Arc::clone(&network),
        final_result_sender,
    );

    // Wait a bit until all the receivers are ready.
    thread::sleep(Duration::from_millis(300));

    // Initialize nodes.
    for node in &dou_sha_nodes {
        let mut node_locked = node.lock().await;
        node_locked
            .init(session_id, &params, &mut rng, Arc::clone(&network))
            .await
            .unwrap();
    }

    // Wait a bit until all parties have interaction.
    thread::sleep(Duration::from_millis(300));

    let mut resulting_shares = HashMap::new();
    while let Some((id, shares)) = final_result_receiver.recv().await {
        resulting_shares.insert(id, shares);
        if resulting_shares.len() == n_parties {
            // Assert that the shares received have the correct properties.
            for (id, final_double_shares) in &resulting_shares {
                assert_eq!(final_double_shares.len(), n_parties);
                for double_share in final_double_shares {
                    assert_eq!(*id, double_share.degree_t.id);
                    assert_eq!(*id, double_share.degree_2t.id);
                    assert_eq!(double_share.degree_t.degree, params.threshold);
                    assert_eq!(double_share.degree_2t.degree, 2 * params.threshold);
                }
            }
            break;
        }
    }

    // extracting all the shares for degree t and 2t from each party
    // and recovering the secrets
    // and asserting that recovered secrets are equal
    for i in 0..n_parties {
        let shares_t: Vec<_> = resulting_shares
            .values()
            .map(|shares| shares[i].degree_t.clone())
            .collect();

        let shares_2t: Vec<_> = resulting_shares
            .values()
            .map(|shares| shares[i].degree_2t.clone())
            .collect();

        let secret_t = NonRobustShamirShare::recover_secret(&shares_t);
        let secret_2t = NonRobustShamirShare::recover_secret(&shares_2t);

        assert_eq!(
            secret_t.unwrap().1,
            secret_2t.unwrap().1,
            "Mismatch for secret {i}"
        );
    }
}
