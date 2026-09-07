pub mod utils;

use crate::utils::test_utils::{fan_in_inboxes, setup_tracing, test_setup};
use std::{sync::Arc, time::Duration};
use stoffelcrypto::{
    common::{
        gf2k::{field::Gf256, share::GfShare, BinaryField},
        rbc::rbc::Avid,
        ProtocolSessionId, RBC,
    },
    honeybadger::{
        gf_ran_dou_sha::{
            gf_ran_dou_sha::GfRanDouShaNode, GfRanDouShaError, GfRanDouShaMessage,
            GfRanDouShaPayload,
        },
        ProtocolType, SessionId, WrappedMessage,
    },
};
use stoffelmpc_network::fake_network::SenderId;
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinSet;

/// Direct port of `randousha_test.rs`'s `construct_e2e_input`: for each of `n` dealers, a random
/// secret double-shared at degree `t` and `2t`, indexed `[recipient][dealer]`.
fn construct_e2e_input(
    n: usize,
    degree_t: usize,
    rng: &mut impl ark_std::rand::Rng,
) -> (Vec<Gf256>, Vec<Vec<GfShare<Gf256>>>, Vec<Vec<GfShare<Gf256>>>) {
    let mut n_shares_t = vec![vec![]; n];
    let mut n_shares_2t = vec![vec![]; n];
    let mut secrets = Vec::new();

    for _ in 0..n {
        let secret = Gf256::random(rng);
        secrets.push(secret);
        let shares_si_t = GfShare::compute_shares(secret, n, degree_t, rng).unwrap();
        let shares_si_2t = GfShare::compute_shares(secret, n, degree_t * 2, rng).unwrap();
        for j in 0..n {
            n_shares_t[j].push(shares_si_t[j].clone());
            n_shares_2t[j].push(shares_si_2t[j].clone());
        }
    }
    (secrets, n_shares_t, n_shares_2t)
}

#[tokio::test]
async fn test_gf_output_handler() {
    setup_tracing();
    let n_parties = 10;
    let threshold = 3;
    let session_id = SessionId::new(
        ProtocolType::GfRandousha,
        SessionId::pack_slot(123, 0, 0),
        111,
    );
    let degree_t = 3;

    let (network, _receivers, _, _) = test_setup(n_parties, vec![]);
    let mut rng = ark_std::test_rng();
    let (_, shares_si_t, shares_si_2t) = construct_e2e_input(n_parties, degree_t, &mut rng);
    let receiver_id = 1;

    let mut node: GfRanDouShaNode<Gf256, Avid<SessionId>> =
        GfRanDouShaNode::new(receiver_id, n_parties, threshold, threshold + 1).unwrap();
    node.init(
        shares_si_t[receiver_id].clone(),
        shares_si_2t[receiver_id].clone(),
        session_id,
        network[node.id].clone(),
    )
    .await
    .unwrap();

    let node_store = node.get_or_create_store(session_id, node.id).await.unwrap();

    for i in (threshold + 1)..(n_parties - 1) {
        let output_message = GfRanDouShaMessage::new(i, session_id, GfRanDouShaPayload::Output(true));
        let _ = node.output_handler(output_message).await;
    }
    assert_eq!(
        node_store.lock().await.received_ok_msg.len(),
        n_parties - (threshold + 2)
    );

    // Duplicate sender must not double-count.
    let output_message =
        GfRanDouShaMessage::new(threshold + 1, session_id, GfRanDouShaPayload::Output(true));
    let _ = node.output_handler(output_message).await;
    assert_eq!(
        node_store.lock().await.received_ok_msg.len(),
        n_parties - (threshold + 2)
    );

    // Output(false) must abort.
    let output_message =
        GfRanDouShaMessage::new(n_parties - 1, session_id, GfRanDouShaPayload::Output(false));
    let e = node
        .output_handler(output_message)
        .await
        .expect_err("should return abort");
    assert_eq!(e.to_string(), GfRanDouShaError::Abort.to_string());
    assert_eq!(
        node_store.lock().await.received_ok_msg.len(),
        n_parties - (threshold + 2)
    );

    // The n-(t+1)-th distinct OK message finalizes.
    let output_message =
        GfRanDouShaMessage::new(n_parties - 1, session_id, GfRanDouShaPayload::Output(true));
    node.output_handler(output_message)
        .await
        .expect("output handler should not fail");

    let storage_mutex = node.get_or_create_store(session_id, node.id).await.unwrap();
    let output = {
        let storage = storage_mutex.lock().await;
        storage.protocol_output.clone()
    }; // guard dropped here — the assert below re-locks the same mutex via `node_store`
    assert_eq!(output.len(), threshold + 1);
    for double_share in output {
        assert_eq!(double_share.degree_t.degree, threshold);
        assert_eq!(double_share.degree_2t.degree, 2 * threshold);
    }
    assert_eq!(
        node_store.lock().await.received_ok_msg.len(),
        n_parties - (threshold + 1)
    );
}

/// End-to-end: for a corrupted degree-t/degree-2t pair (same shape as `randousha_test.rs`'s
/// `test_reconstruct_handler_mismatch_r_t_2t`, driven fully through RBC), the checking parties'
/// cross-degree checksum must catch the mismatch and no party should accumulate any OK votes.
#[tokio::test]
async fn test_gf_reconstruct_handler_mismatch_r_t_2t() {
    setup_tracing();
    let n_parties = 10;
    let threshold = 3;
    let session_id = SessionId::new(
        ProtocolType::GfRandousha,
        SessionId::pack_slot(123, 0, 0),
        111,
    );

    let (network, mut receivers, _, _) = test_setup(n_parties, vec![]);
    let mut rng = ark_std::test_rng();
    let secret = Gf256(42);
    let secret_2t = Gf256(99); // deliberately different secret at degree 2t
    let degree_t = 3;
    let degree_2t = 6;

    let receiver_id = threshold + 2;

    let shares_ri_t = GfShare::compute_shares(secret, n_parties, degree_t, &mut rng).unwrap();
    let shares_ri_2t = GfShare::compute_shares(secret_2t, n_parties, degree_2t, &mut rng).unwrap();

    let mut nodes: Vec<GfRanDouShaNode<Gf256, Avid<SessionId>>> = (0..n_parties)
        .map(|i| GfRanDouShaNode::new(i, n_parties, threshold, threshold + 1).unwrap())
        .collect();

    {
        let store_bind = nodes[receiver_id]
            .get_or_create_store(session_id, receiver_id)
            .await
            .unwrap();
        let mut store = store_bind.lock().await;
        store.computed_r_shares_degree_t = shares_ri_t.clone();
        store.computed_r_shares_degree_2t = shares_ri_2t.clone();
        store.batch_size = 1;
    }

    for i in 0..n_parties {
        use stoffelcrypto::honeybadger::gf_ran_dou_sha::GfReconstructionMessage;
        let rec_msg = GfReconstructionMessage::new(shares_ri_t[i].clone(), shares_ri_2t[i].clone());
        let payload = bincode::serialize(&rec_msg).unwrap();
        let rds_message =
            GfRanDouShaMessage::new(i, session_id, GfRanDouShaPayload::Reconstruct(payload));
        nodes[receiver_id]
            .reconstruction_handler(rds_message, network[receiver_id].clone())
            .await
            .unwrap();
    }

    let mut set = JoinSet::new();
    for i in 0..n_parties {
        let receiver = receivers.remove(0);
        let mut node = nodes[i].clone();
        let net = network[i].clone();
        let inbox: Vec<(SenderId, Receiver<Vec<u8>>)> = receiver
            .into_iter()
            .enumerate()
            .map(|(j, r)| (SenderId::Node(j), r))
            .collect();
        let mut merged_rx = fan_in_inboxes(inbox);

        set.spawn(async move {
            let _ = tokio::time::timeout(Duration::from_secs(1), async {
                while let Some(received) = merged_rx.recv().await {
                    let wrapped: WrappedMessage = match bincode::deserialize(&received.1) {
                        Ok(w) => w,
                        Err(_) => continue,
                    };
                    match wrapped {
                        WrappedMessage::GfRanDouSha(_) => {}
                        WrappedMessage::Rbc(msg) => {
                            let _ = node.rbc.process(msg, Arc::clone(&net)).await;
                            let _ = node.drain_rbc_output().await;
                        }
                        _ => {}
                    }
                }
            })
            .await;
        });
    }
    while let Some(res) = set.join_next().await {
        res.expect("Task panicked");
    }

    let binding = nodes[receiver_id]
        .get_or_create_store(session_id, receiver_id)
        .await
        .unwrap();
    let store = binding.lock().await;
    assert_eq!(store.received_r_shares_degree_t.len(), n_parties);
    assert_eq!(store.received_r_shares_degree_2t.len(), n_parties);
    assert_eq!(
        store.received_ok_msg.len(),
        0,
        "mismatched degree-t/degree-2t secrets must never produce an OK vote"
    );
}
