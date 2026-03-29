mod utils;

use crate::utils::test_utils::create_global_nodes;
use ark_bls12_381::Fr;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use chacha20poly1305::aead::OsRng;
use std::sync::Arc;
use stoffelmpc_mpc::{
    common::{rbc::rbc::Avid, MPCProtocol, ProtocolSessionId},
    honeybadger::{
        robust_interpolate::robust_interpolate::RobustShare,
        share_gen::{RanShaError, RanShaState},
        ProtocolType, SessionId,
    },
};
use stoffelmpc_network::{
    bad_fake_network::setup_tracing,
    fake_network::FakeNetworkConfig,
    turmoil_network::{TurmoilInnerNetwork, TurmoilNetwork},
};
use stoffelnet::network_utils::NetworkError;
use tokio::time::{sleep, timeout, Duration};
use turmoil::Builder;

#[test]
fn ransha_e2e_turmoil() {
    setup_tracing();

    let n_parties = 4;
    let t = 1;

    let session_id = SessionId::new(
        ProtocolType::Randousha,
        SessionId::pack_slot24(123, 0, 0),
        111,
    );

    let mut sim = Builder::new().build();
    let inner = TurmoilInnerNetwork::new(n_parties, FakeNetworkConfig::new(100), 7000);
    let nodes = create_global_nodes::<Fr, Avid<SessionId>, RobustShare<Fr>, TurmoilNetwork>(
        n_parties,
        t,
        0,
        0,
        111,
        0,
        0,
        0,
        0,
        Duration::from_secs(30),
        vec![],
    );

    let (tx, rx_done) = std::sync::mpsc::channel::<Result<(), String>>();

    for id in 0..n_parties {
        let inner = inner.clone();
        let node = nodes[id].clone();
        let tx = tx.clone();

        sim.host(format!("node{}", id), move || {
            let inner = inner.clone();
            let mut node = node.clone();
            let tx = tx.clone();

            async move {
                let (network, mut rx) = TurmoilNetwork::new(id, inner.clone()).await;
                sleep(Duration::from_millis(50)).await;

                let network_arc = Arc::new(network);
                let mut rng = StdRng::from_rng(OsRng).unwrap();
                let node_id = node.preprocess.share_gen.id;

                match node
                    .preprocess
                    .share_gen
                    .init(session_id, &mut rng, network_arc.clone())
                    .await
                {
                    Ok(()) => {}
                    Err(RanShaError::NetworkError(NetworkError::SendError)) => {}
                    Err(e) => {
                        let _ = tx.send(Err(format!("node {} init error: {:?}", node_id, e)));
                        return Ok(());
                    }
                }

                let mut msg_count = 0usize;
                let result = timeout(Duration::from_secs(5), async {
                    loop {
                        match rx.recv().await {
                            Some((sender, msg)) => {
                                msg_count += 1;
                                node.process(sender, msg, network_arc.clone())
                                    .await
                                    .unwrap();
                            }
                            None => break,
                        }

                        let store = node
                            .preprocess
                            .share_gen
                            .get_or_create_store(session_id)
                            .await
                            .unwrap();
                        if store.lock().await.state == RanShaState::Finished {
                            break;
                        }
                    }
                })
                .await;

                if result.is_err() {
                    let _ = tx.send(Err(format!(
                        "node {} timed out after {} msgs",
                        node_id, msg_count
                    )));
                    return Ok(());
                }

                let store = node
                    .preprocess
                    .share_gen
                    .get_or_create_store(session_id)
                    .await
                    .unwrap();
                let store = store.lock().await;

                for s_t in store.computed_r_shares.iter() {
                    if s_t.degree != t {
                        let _ = tx.send(Err(format!(
                            "node {} share degree {} != {}",
                            node_id, s_t.degree, t
                        )));
                        return Ok(());
                    }
                    if s_t.id != node.id {
                        let _ = tx.send(Err(format!("node {} share id mismatch", node_id)));
                        return Ok(());
                    }
                }

                if store.computed_r_shares.len() != n_parties {
                    let _ = tx.send(Err(format!(
                        "node {} expected {} shares, got {}",
                        node_id,
                        n_parties,
                        store.computed_r_shares.len()
                    )));
                    return Ok(());
                }

                let _ = tx.send(Ok(()));
                Ok(())
            }
        });
    }

    drop(tx);

    sim.client("driver", async move {
        sleep(Duration::from_secs(10)).await;
        Ok::<(), Box<dyn std::error::Error>>(())
    });

    sim.run().unwrap();

    let results: Vec<_> = std::iter::from_fn(|| rx_done.try_recv().ok()).collect();

    assert_eq!(
        results.len(),
        n_parties,
        "not all nodes reported: got {}/{}",
        results.len(),
        n_parties
    );
    for r in results {
        assert!(r.is_ok(), "node failed: {}", r.unwrap_err());
    }
}
