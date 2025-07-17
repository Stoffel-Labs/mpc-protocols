use std::{collections::HashMap, sync::Arc, thread, time::Duration};

use ark_std::test_rng;
use stoffelmpc_mpc::honeybadger::double_share_generation::InitMessage;
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
    let n_parties = 10;
    let threshold = 3;
    let session_id = 1111;

    let (params, network, receivers) = test_setup(n_parties, threshold, session_id);

    let dou_sha_nodes = create_nodes(n_parties);
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
        let node_locked = node.lock().await;
        let init_msg = InitMessage::new(node_locked.id, params.session_id);
        node_locked
            .init_handler(&init_msg, &params, &mut rng, Arc::clone(&network))
            .await
            .unwrap();
    }

    // Wait a bit until all parties have interaction.
    thread::sleep(Duration::from_millis(300));

    let mut resulting_shares = HashMap::new();
    while let Some((id, shares)) = final_result_receiver.recv().await {
        resulting_shares.insert(id, shares);
        if resulting_shares.len() == n_parties {
            info!(
                amount = resulting_shares.len(),
                "all parties received the shares"
            );

            // Assert that the shares received have the correct properties.
            for (id, final_double_shares) in &resulting_shares {
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
}
