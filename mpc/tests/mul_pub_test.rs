pub mod utils;

use crate::utils::test_utils::{fan_in_inboxes, setup_tracing, test_setup};
use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_ff::Zero;
use ark_std::test_rng;
use std::{sync::Arc, time::Duration};
use stoffelmpc_mpc::{
    common::{ProtocolSessionId, SecretSharingScheme},
    honeybadger::{
        mul_pub::{mul_pub::MulPubNode, MulPubError, MulPubStore},
        robust_interpolate::robust_interpolate::RobustShare,
        ProtocolType, SessionId, WrappedMessage,
    },
};
use stoffelmpc_network::fake_network::SenderId;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tracing::warn;
const N: usize = 10;
const T: usize = 3;

fn make_node() -> MulPubNode<Fr> {
    MulPubNode::new(0, N, T).unwrap()
}

fn make_session(exec_id: u8) -> SessionId {
    SessionId::new(
        ProtocolType::MulPub,
        SessionId::pack_slot24(exec_id, 0, 0),
        1,
    )
}

fn make_shares(degree: usize, k: usize) -> Vec<RobustShare<Fr>> {
    let mut rng = test_rng();
    (0..k)
        .map(|_| {
            RobustShare::compute_shares(Fr::zero(), N, degree, None, &mut rng).unwrap()[0].clone()
        })
        .collect()
}

// ── Input validation ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_init_mismatched_ab_lengths() {
    let mut node = make_node();
    let (network, _, _, _) = test_setup(N, vec![]);
    let err = node
        .init(
            make_session(1),
            make_shares(T, 2),
            make_shares(T, 3),
            make_shares(2 * T, 2),
            network[0].clone(),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, MulPubError::InvalidInput(_)));
}

#[tokio::test]
async fn test_init_empty_input() {
    let mut node = make_node();
    let (network, _, _, _) = test_setup(N, vec![]);
    let err = node
        .init(make_session(1), vec![], vec![], vec![], network[0].clone())
        .await
        .unwrap_err();
    assert!(matches!(err, MulPubError::InvalidInput(_)));
}

#[tokio::test]
async fn test_init_wrong_zero_share_count() {
    let mut node = make_node();
    let (network, _, _, _) = test_setup(N, vec![]);
    let err = node
        .init(
            make_session(1),
            make_shares(T, 2),
            make_shares(T, 2),
            make_shares(2 * T, 3), // k=2 but 3 zero shares
            network[0].clone(),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, MulPubError::InvalidInput(_)));
}

#[tokio::test]
async fn test_init_wrong_zero_share_degree() {
    let mut node = make_node();
    let (network, _, _, _) = test_setup(N, vec![]);
    let err = node
        .init(
            make_session(1),
            make_shares(T, 2),
            make_shares(T, 2),
            make_shares(T, 2), // degree t instead of 2t
            network[0].clone(),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, MulPubError::InvalidInput(_)));
}

#[tokio::test]
async fn test_init_nonzero_sub_id() {
    let mut node = make_node();
    let (network, _, _, _) = test_setup(N, vec![]);
    let bad_sid = SessionId::new(ProtocolType::Mul, SessionId::pack_slot24(0, 1, 0), 1);
    let err = node
        .init(
            bad_sid,
            make_shares(T, 1),
            make_shares(T, 1),
            make_shares(2 * T, 1),
            network[0].clone(),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, MulPubError::InvalidInput(_)));
}

#[tokio::test]
async fn test_init_nonzero_round_id() {
    let mut node = make_node();
    let (network, _, _, _) = test_setup(N, vec![]);
    let bad_sid = SessionId::new(ProtocolType::Mul, SessionId::pack_slot24(0, 0, 1), 1);
    let err = node
        .init(
            bad_sid,
            make_shares(T, 1),
            make_shares(T, 1),
            make_shares(2 * T, 1),
            network[0].clone(),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, MulPubError::InvalidInput(_)));
}

// ── Session limit ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_session_limit() {
    setup_tracing();
    let mut node = make_node();
    let (network, _, _, _) = test_setup(N, vec![]);

    {
        let mut store = node.store.lock().await;
        for i in 0..256usize {
            let sid = SessionId::new(ProtocolType::Mul, SessionId::pack_slot24(0, 0, 0), i as u32);
            store.insert(sid, Arc::new(Mutex::new(MulPubStore::new(1))));
        }
    }

    let new_sid = SessionId::new(ProtocolType::Mul, SessionId::pack_slot24(0, 0, 0), 9999);
    let err = node
        .init(
            new_sid,
            make_shares(T, 1),
            make_shares(T, 1),
            make_shares(2 * T, 1),
            network[0].clone(),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, MulPubError::LimitError));
}

fn fabricate_zero_shares(n: usize, t: usize, k: usize) -> Vec<Vec<RobustShare<Fr>>> {
    let mut rng = test_rng();
    let mut per_node: Vec<Vec<RobustShare<Fr>>> = vec![vec![]; n];
    for _ in 0..k {
        let shares = RobustShare::compute_shares(Fr::zero(), n, 2 * t, None, &mut rng).unwrap();
        for i in 0..n {
            per_node[i].push(shares[i].clone());
        }
    }
    per_node
}

// ── End-to-end ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_mul_pub_e2e_single_batch() {
    mul_pub_e2e(10, 3, 4).await; // k = t+1, one full batch
}

#[tokio::test]
async fn test_mul_pub_e2e_with_padding() {
    mul_pub_e2e(10, 3, 5).await; // k = t+2, last batch needs padding
}

#[tokio::test]
async fn test_mul_pub_e2e_two_batches() {
    mul_pub_e2e(10, 3, 8).await; // k = 2*(t+1), two full batches
}

async fn mul_pub_e2e(n: usize, t: usize, k: usize) {
    setup_tracing();
    let mut rng = test_rng();

    let session_id = SessionId::new(ProtocolType::MulPub, SessionId::pack_slot24(1, 0, 0), 42);
    let (network, mut receivers, _, _) = test_setup(n, vec![]);

    let a_secrets: Vec<Fr> = (0..k).map(|_| Fr::rand(&mut rng)).collect();
    let b_secrets: Vec<Fr> = (0..k).map(|_| Fr::rand(&mut rng)).collect();

    let mut a_per_node: Vec<Vec<RobustShare<Fr>>> = vec![vec![]; n];
    let mut b_per_node: Vec<Vec<RobustShare<Fr>>> = vec![vec![]; n];
    let z_per_node = fabricate_zero_shares(n, t, k);

    for j in 0..k {
        let a_sh = RobustShare::compute_shares(a_secrets[j], n, t, None, &mut rng).unwrap();
        let b_sh = RobustShare::compute_shares(b_secrets[j], n, t, None, &mut rng).unwrap();
        for i in 0..n {
            a_per_node[i].push(a_sh[i].clone());
            b_per_node[i].push(b_sh[i].clone());
        }
    }

    let mut nodes: Vec<MulPubNode<Fr>> = (0..n)
        .map(|id| MulPubNode::new(id, n, t).unwrap())
        .collect();

    for i in 0..n {
        nodes[i]
            .init(
                session_id,
                a_per_node[i].clone(),
                b_per_node[i].clone(),
                z_per_node[i].clone(),
                network[i].clone(),
            )
            .await
            .unwrap();
    }

    let mut set = JoinSet::new();
    for i in 0..n {
        let mut node = nodes[i].clone();
        let receiver = receivers.remove(0);
        let net = network[i].clone();
        let inbox = receiver
            .into_iter()
            .enumerate()
            .map(|(j, r)| (SenderId::Node(j), r))
            .collect();
        let mut merged_rx = fan_in_inboxes(inbox);

        set.spawn(async move {
            while let Some((_, bytes)) = merged_rx.recv().await {
                let wrapped: WrappedMessage = match bincode::deserialize(&bytes) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                if let WrappedMessage::BatchRecon(msg) = wrapped {
                    if let Err(e) = node.batch_recon.process(msg, net.clone()).await {
                        warn!("batch recon error: {e}");
                    }
                    node.drain_batch_recon_output().await.unwrap();
                }
            }
        });
    }

    for i in 0..n {
        let results = nodes[i]
            .wait_for_result(session_id, Duration::from_millis(1500))
            .await
            .unwrap();
        assert_eq!(results.len(), k, "party {i}: wrong number of results");
        for j in 0..k {
            assert_eq!(
                results[j],
                a_secrets[j] * b_secrets[j],
                "party {i}: product mismatch at index {j}"
            );
        }
    }
}
