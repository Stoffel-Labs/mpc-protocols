use ark_bls12_381::Fr;
use futures::future::join_all;
use std::{sync::Arc, time::Duration};
use stoffelmpc_mpc::{common::rbc::rbc::Avid, honeybadger::ran_dou_sha::RanDouShaState};
use tokio::time::{sleep, timeout};

use crate::utils::test_utils::{
    construct_e2e_input, create_global_nodes, initialize_global_nodes_randousha, receive,
    setup_tracing, test_setup,
};

pub mod utils;

#[tokio::test]
async fn randousha_e2e() {
    setup_tracing();
    let n_parties = 10;
    let t = 3;
    let session_id = 1111;
    let degree_t = 3;

    //Setup
    let (network, receivers) = test_setup(n_parties);
    let (_, n_shares_t, n_shares_2t) = construct_e2e_input(n_parties, degree_t);
    // create global nodes
    let mut nodes = create_global_nodes::<Fr, Avid>(n_parties, t, t + 1);
    // spawn tasks to process received messages
    receive(receivers, nodes.clone(), network.clone());

    // init all randousha nodes
    initialize_global_nodes_randousha(
        nodes.clone(),
        &n_shares_t,
        &n_shares_2t,
        session_id,
        Arc::clone(&network),
    )
    .await;

    let result = timeout(
        Duration::from_secs(5),
        join_all(nodes.iter_mut().map(|node| async move {
            let store = node
                .preprocessing
                .randousha
                .get_or_create_store(session_id)
                .await;

            loop {
                let store = store.lock().await;
                if store.state == RanDouShaState::Finished {
                    break;
                }
                store
                    .computed_r_shares_degree_t
                    .iter()
                    .zip(&store.computed_r_shares_degree_2t)
                    .for_each(|(s_t, s_2t)| {
                        assert_eq!(s_t.degree, t);
                        assert_eq!(s_2t.degree, 2 * t);
                        assert_eq!(s_t.id, node.id + 1);
                        assert_eq!(s_2t.id, node.id + 1);
                    });
                sleep(Duration::from_millis(10)).await;
            }
        })),
    )
    .await;

    assert!(
        result.is_ok(),
        "RanDouSha did not complete within the timeout"
    );
}
