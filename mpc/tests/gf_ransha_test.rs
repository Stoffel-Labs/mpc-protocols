//! Integration tests for the GF(2^k) RanSha-equivalent (`gf_share_gen`), mirroring
//! `ransha_test.rs`'s structure. Unlike `ransha_test.rs`, these construct standalone
//! `GfRanShaNode` instances directly rather than via `create_global_nodes`/`HoneyBadgerMPCNode`,
//! since `GfRanShaNode` isn't wired into a full node yet (that integration is a later phase) —
//! the protocol logic and message flow are independently testable without it, the same way
//! `test_output_handler` in `ransha_test.rs` already exercises `RanShaNode` standalone.

use ark_std::test_rng;
use std::{sync::Arc, time::Duration};
use stoffelcrypto::{
    common::{
        gf2k::field::{BinaryField, Gf256},
        gf2k::share::GfShare,
        rbc::rbc::Avid,
        ProtocolSessionId, RBC,
    },
    honeybadger::{
        gf_share_gen::{
            gf_share_gen::GfRanShaNode, GfRanShaError, GfRanShaMessage, GfRanShaMessageType,
            GfRanShaPayload, GfRanShaState,
        },
        ProtocolType, SessionId, WrappedMessage,
    },
};
use stoffelmpc_network::fake_network::{FakeInnerNetwork, FakeNetwork, FakeNetworkConfig, SenderId};
use tokio::{sync::mpsc::Receiver, task::JoinSet, time::timeout};
use tracing::warn;

mod utils;
use utils::test_utils::{fan_in_inboxes, setup_tracing};

fn ser(share: &GfShare<Gf256>) -> Vec<u8> {
    bincode::serialize(share).unwrap()
}

#[tokio::test]
async fn test_gf_reconstruct_handler_incorrect_share() {
    setup_tracing();
    let n_parties = 10;
    let t = 3;
    let session_id = SessionId::new(ProtocolType::GfRansha, SessionId::pack_slot(123, 0, 0), 111);

    let (inner, receivers, _client_recv) = FakeInnerNetwork::new(n_parties, None, FakeNetworkConfig::new(500));
    let network: Vec<Arc<FakeNetwork>> = (0..n_parties)
        .map(|id| Arc::new(FakeNetwork::new(id, inner.clone())))
        .collect();

    let mut rng = test_rng();
    let secret = Gf256(0xAB);
    let degree_t = 3;

    let receiver_id = t + 2;

    let mut shares_ri_t = GfShare::compute_shares(secret, n_parties, degree_t, &mut rng).unwrap();

    // Corrupt more than t shares (4 > t=3).
    let corruption_indices = [0, 1, 3, 4];
    for &i in &corruption_indices {
        shares_ri_t[i].share = shares_ri_t[i].share + Gf256(0x07);
    }

    let mut nodes: Vec<GfRanShaNode<Gf256, Avid<SessionId>>> = (0..n_parties)
        .map(|id| GfRanShaNode::new(id, n_parties, t, t + 1).unwrap())
        .collect();

    // Simulate init_ransha_batch having already run, so reconstruction_handler accepts messages.
    {
        let binding = nodes[receiver_id]
            .get_or_create_store(session_id, receiver_id)
            .await
            .unwrap();
        let mut store = binding.lock().await;
        store.computed_r_shares = shares_ri_t.clone();
        store.batch_size = 1;
    }

    for i in 0..n_parties {
        let message = GfRanShaMessage::new(
            i,
            GfRanShaMessageType::ReconstructMessage,
            session_id,
            GfRanShaPayload::Reconstruct(ser(&shares_ri_t[i])),
        );
        nodes[receiver_id]
            .reconstruction_handler(message, network[i].clone())
            .await
            .unwrap();
    }

    // Drive every node's RBC processing loop so any (there should be none) output attestation
    // propagates.
    let mut set = JoinSet::new();
    let mut receivers = receivers;
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
            let _ = timeout(Duration::from_secs(1), async {
                while let Some(received) = merged_rx.recv().await {
                    let wrapped: WrappedMessage = match bincode::deserialize(&received.1) {
                        Ok(w) => w,
                        Err(_) => continue,
                    };
                    match wrapped {
                        WrappedMessage::GfRansha(_) => {}
                        WrappedMessage::Rbc(msg) => {
                            if let Err(e) = node.rbc.process(msg, Arc::clone(&net)).await {
                                warn!("Rbc processing error: {e}");
                            }
                            if let Err(e) = node.drain_rbc_output().await {
                                warn!("RBC output handling error: {e}");
                            }
                        }
                        _ => continue,
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
    assert_eq!(store.received_r_shares.len(), n_parties);
    assert_eq!(
        store.received_ok_msg.len(),
        0,
        "exceeding the Byzantine bound (t+1 corrupted shares) must not produce any OK attestation"
    );
    assert_eq!(store.state, GfRanShaState::Reconstruction);
}

#[tokio::test]
async fn test_gf_output_handler() {
    setup_tracing();
    let n_parties = 10;
    let threshold = 3;
    let session_id = SessionId::new(ProtocolType::GfRansha, SessionId::pack_slot(123, 0, 0), 111);
    let degree_t = 3;

    let (inner, _receivers, _client_recv) = FakeInnerNetwork::new(n_parties, None, FakeNetworkConfig::new(500));
    let network: Vec<Arc<FakeNetwork>> = (0..n_parties)
        .map(|id| Arc::new(FakeNetwork::new(id, inner.clone())))
        .collect();

    let mut rng = test_rng();
    let mut n_shares_t = vec![vec![]; n_parties];
    for _ in 0..n_parties {
        let secret = Gf256::random(&mut rng);
        let shares = GfShare::compute_shares(secret, n_parties, degree_t, &mut rng).unwrap();
        for j in 0..n_parties {
            n_shares_t[j].push(shares[j].clone());
        }
    }

    let receiver_id = 1;
    let mut node: GfRanShaNode<Gf256, Avid<SessionId>> =
        GfRanShaNode::new(receiver_id, n_parties, threshold, threshold + 1).unwrap();
    node.init_ransha(
        n_shares_t[receiver_id].clone(),
        session_id,
        network[node.id].clone(),
    )
    .await
    .unwrap();

    let node_store = node.get_or_create_store(session_id, node.id).await.unwrap();

    // First 2t-1 OK messages: not enough to finalize.
    for i in 0..(2 * threshold - 1) {
        let output_message = GfRanShaMessage::new(
            i,
            GfRanShaMessageType::OutputMessage,
            session_id,
            GfRanShaPayload::Output(true),
        );
        let _ = node.output_handler(output_message).await;
    }
    assert_eq!(node_store.lock().await.received_ok_msg.len(), 2 * threshold - 1);

    // Duplicate sender must not double-count.
    let output_message = GfRanShaMessage::new(
        1,
        GfRanShaMessageType::OutputMessage,
        session_id,
        GfRanShaPayload::Output(true),
    );
    let _ = node.output_handler(output_message).await;
    assert_eq!(node_store.lock().await.received_ok_msg.len(), 2 * threshold - 1);

    // Output(false) must abort without polluting received_ok_msg.
    let output_message = GfRanShaMessage::new(
        1,
        GfRanShaMessageType::OutputMessage,
        session_id,
        GfRanShaPayload::Output(false),
    );
    let e = node
        .output_handler(output_message)
        .await
        .expect_err("should return abort");
    assert_eq!(e.to_string(), GfRanShaError::Abort.to_string());
    assert_eq!(node_store.lock().await.received_ok_msg.len(), 2 * threshold - 1);

    // The 2t-th distinct OK message finalizes.
    let output_message = GfRanShaMessage::new(
        2 * threshold - 1,
        GfRanShaMessageType::OutputMessage,
        session_id,
        GfRanShaPayload::Output(true),
    );
    node.output_handler(output_message)
        .await
        .expect("output handler should not fail");

    let v = node_store.lock().await.protocol_output.clone();
    assert_eq!(v.len(), n_parties - 2 * threshold);
    for share in v {
        assert_eq!(share.degree, threshold);
    }
    assert_eq!(node_store.lock().await.received_ok_msg.len(), 2 * threshold);
    assert_eq!(node_store.lock().await.state, GfRanShaState::Finished);
}
