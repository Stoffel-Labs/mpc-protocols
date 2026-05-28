use crate::utils::test_utils::{fan_in_inboxes, setup_tracing, test_setup};
use ark_bls12_381::Fr;
use ark_ff::{UniformRand, Zero};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_serialize::CanonicalSerialize;
use ark_std::test_rng;
use std::{sync::Arc, time::Duration};
use stoffelmpc_mpc::{
    common::{rbc::rbc::Avid, ProtocolSessionId as _, SecretSharingScheme, RBC},
    honeybadger::{
        robust_interpolate::robust_interpolate::RobustShare,
        zero_share::{
            zero_share::ZeroShaNode, ZeroShaError, ZeroShaMessage, ZeroShaMessageType,
            ZeroShaPayload, ZeroShaState,
        },
        ProtocolType, SessionId, WrappedMessage,
    },
};
use stoffelmpc_network::fake_network::{FakeNetwork, SenderId};
use tokio::{sync::mpsc::Receiver, task::JoinSet, time::timeout};
use tracing::warn;

pub mod utils;

// ── Direct recover_secret logic tests ──────────────────────────────────────

/// Zero polynomial → constant term is zero → ok=true
#[tokio::test]
async fn test_recover_secret_zero_polynomial() {
    let n = 10;
    let t = 3;
    let mut rng = test_rng();
    let shares = RobustShare::compute_shares(Fr::zero(), n, 2 * t, None, &mut rng).unwrap();
    let (coeffs, secret) = RobustShare::recover_secret(&shares, n, t).unwrap();
    let poly = DensePolynomial::from_coefficients_slice(&coeffs);
    assert!(
        secret.is_zero(),
        "zero polynomial must have zero constant term"
    );
    assert_eq!(poly.degree(), 2 * t, "degree must be exactly 2t");
}

/// Non-zero polynomial → constant term is not zero → ok=false
#[tokio::test]
async fn test_recover_secret_nonzero_detected() {
    let n = 10;
    let t = 3;
    let mut rng = test_rng();
    let nonzero = Fr::from(99u64);
    let shares = RobustShare::compute_shares(nonzero, n, 2 * t, None, &mut rng).unwrap();
    let (_, secret) = RobustShare::recover_secret(&shares, n, t).unwrap();
    assert!(!secret.is_zero(), "non-zero secret must be detected");
    assert_eq!(secret, nonzero, "recovered secret must match original");
}

/// Security: adversary forges t reconstruction shares to disguise a non-zero sharing as zero.
/// With degree=2t and n=3t+1, recover_secret cannot error-correct t faults, returning Err.
/// The reconstruction handler maps Err → ok=false, so the sharing is correctly rejected.
/// This test documents the actual failure mode: algorithm refusal, not zero-check detection.
#[tokio::test]
async fn test_recover_secret_resists_t_forged_shares() {
    let n = 10; // n = 3t+1, t = 3
    let t = 3;
    let mut rng = test_rng();
    let nonzero_secret = Fr::from(42u64);
    let mut shares = RobustShare::compute_shares(nonzero_secret, n, 2 * t, None, &mut rng).unwrap();

    // Adversary corrupts t shares
    for i in 0..t {
        shares[i].share[0] = Fr::rand(&mut rng);
    }

    // oec_decode needs degree+t+2 = 4t+2 shares per iteration, but only 3t+1 are available.
    // The algorithm correctly refuses to decode rather than risk returning a wrong result.
    // In the protocol, Err → ok=false → manipulation caught.
    match RobustShare::recover_secret(&shares, n, t) {
        Err(_) => {
            // Expected: algorithm refuses to decode t errors in a degree-2t polynomial.
            // Protocol maps this to ok=false — the forged sharing is rejected.
        }
        Ok((_, secret)) => {
            // If somehow decoding succeeds, the secret must still be non-zero.
            assert!(
                !secret.is_zero(),
                "decoding t forged shares must never produce a zero secret"
            );
        }
    }
}

// ── Protocol-level reconstruction handler tests ────────────────────────────

fn make_nodes(n_parties: usize, t: usize) -> Vec<ZeroShaNode<Fr, Avid<SessionId>>> {
    (0..n_parties)
        .map(|id| ZeroShaNode::new(id, n_parties, t, t + 1).unwrap())
        .collect()
}

async fn run_rbc_joinset(
    nodes: Vec<ZeroShaNode<Fr, Avid<SessionId>>>,
    receivers: Vec<Vec<Receiver<Vec<u8>>>>,
    network: Vec<Arc<FakeNetwork>>,
) {
    let n = nodes.len();
    let mut set = JoinSet::new();
    let mut receivers = receivers;

    for i in 0..n {
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
                        WrappedMessage::ZeroSha(_) => {}
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
}

/// Non-zero sharing is caught end-to-end: reconstruction broadcasts ok=false via RBC,
/// output_handler returns NotZero, and received_ok_msg stays empty.
#[tokio::test]
async fn test_reconstruction_handler_nonzero_caught() {
    setup_tracing();
    let n_parties = 10;
    let t = 3;
    let session_id = SessionId::new(
        ProtocolType::ZeroSha,
        SessionId::pack_slot24(123, 0, 0),
        111,
    );

    let (network, receivers, _, _) = test_setup(n_parties, vec![]);
    let mut rng = test_rng();

    let shares =
        RobustShare::compute_shares(Fr::from(12345u64), n_parties, 2 * t, None, &mut rng).unwrap();

    let receiver_id = 1; // must be < 2t
    let nodes = make_nodes(n_parties, t);
    let mut receiver_node = nodes[receiver_id].clone();

    for i in 0..n_parties {
        let mut bytes = Vec::new();
        shares[i].clone().serialize_compressed(&mut bytes).unwrap();
        let msg = ZeroShaMessage::new(
            i,
            ZeroShaMessageType::ReconstructMessage,
            session_id,
            ZeroShaPayload::Reconstruct(bytes),
        );
        receiver_node
            .reconstruction_handler(msg, network[i].clone())
            .await
            .unwrap();
    }

    run_rbc_joinset(nodes, receivers, network).await;

    let binding = receiver_node.get_or_create_store(session_id).await.unwrap();
    let store = binding.lock().await;
    assert_eq!(
        store.received_r_shares.len(),
        n_parties,
        "all reconstruction shares must be collected"
    );
    assert_eq!(
        store.received_ok_msg.len(),
        0,
        "non-zero sharing must not produce any ok messages"
    );
    assert_eq!(store.state, ZeroShaState::Reconstruction);
}

/// Adversary forges t reconstruction shares to try to make a non-zero sharing pass.
/// With the n_parties threshold, honest 2t+1 shares dominate: received_ok_msg stays empty.
#[tokio::test]
async fn test_reconstruction_handler_manipulation_caught() {
    setup_tracing();
    let n_parties = 10;
    let t = 3;
    let session_id = SessionId::new(ProtocolType::ZeroSha, SessionId::pack_slot24(46, 0, 0), 222);

    let (network, receivers, _, _) = test_setup(n_parties, vec![]);
    let mut rng = test_rng();

    let nonzero_secret = Fr::from(777u64);
    let mut shares =
        RobustShare::compute_shares(nonzero_secret, n_parties, 2 * t, None, &mut rng).unwrap();

    // Adversary corrupts t reconstruction shares with random values
    for i in 0..t {
        shares[i].share[0] = Fr::rand(&mut rng);
    }
    // Remaining 2t+1 honest shares identify the true non-zero polynomial

    let receiver_id = 2; // must be < 2t
    let nodes = make_nodes(n_parties, t);
    let mut receiver_node = nodes[receiver_id].clone();

    for i in 0..n_parties {
        let mut bytes = Vec::new();
        shares[i].clone().serialize_compressed(&mut bytes).unwrap();
        let msg = ZeroShaMessage::new(
            i,
            ZeroShaMessageType::ReconstructMessage,
            session_id,
            ZeroShaPayload::Reconstruct(bytes),
        );
        receiver_node
            .reconstruction_handler(msg, network[i].clone())
            .await
            .unwrap();
    }

    run_rbc_joinset(nodes, receivers, network).await;

    let binding = receiver_node.get_or_create_store(session_id).await.unwrap();
    let store = binding.lock().await;
    assert_eq!(store.received_r_shares.len(), n_parties);
    assert_eq!(
        store.received_ok_msg.len(),
        0,
        "adversary forging {} of {} reconstruction shares must still be caught",
        t,
        n_parties
    );
}

// ── Simple handler unit tests ───────────────────────────────────────────────

/// output_handler with ok=false must return NotZero immediately (before touching the store).
#[tokio::test]
async fn test_output_handler_not_zero_error() {
    let n = 10;
    let t = 3;
    let session_id = SessionId::new(ProtocolType::ZeroSha, SessionId::pack_slot24(99, 0, 0), 333);

    let mut node: ZeroShaNode<Fr, Avid<SessionId>> = ZeroShaNode::new(0, n, t, t + 1).unwrap();

    let msg = ZeroShaMessage::new(
        1,
        ZeroShaMessageType::OutputMessage,
        session_id,
        ZeroShaPayload::Output(false),
    );
    let err = node
        .output_handler(msg)
        .await
        .expect_err("false output payload must return NotZero");
    assert!(
        matches!(err, ZeroShaError::NotZero),
        "expected ZeroShaError::NotZero, got: {err:?}"
    );
}

/// A share with degree ≠ 2t sent in the initial share phase must be rejected.
#[tokio::test]
async fn test_receive_shares_wrong_degree_rejected() {
    let n = 10;
    let t = 3;
    let session_id = SessionId::new(ProtocolType::ZeroSha, SessionId::pack_slot24(11, 0, 0), 444);
    let (network, _, _, _) = test_setup(n, vec![]);

    let mut node: ZeroShaNode<Fr, Avid<SessionId>> = ZeroShaNode::new(5, n, t, t + 1).unwrap();

    // degree t instead of the required 2t
    let wrong_degree_share = RobustShare::new(Fr::zero(), 5, t);
    let mut bytes = Vec::new();
    wrong_degree_share.serialize_compressed(&mut bytes).unwrap();

    let msg = ZeroShaMessage::new(
        0,
        ZeroShaMessageType::ShareMessage,
        session_id,
        ZeroShaPayload::Share(bytes),
    );
    let err = node
        .receive_shares_handler(msg, network[0].clone())
        .await
        .expect_err("wrong degree share must be rejected");
    assert!(
        matches!(err, ZeroShaError::ShareError(..)),
        "expected ShareError(DegreeMismatch), got: {err:?}"
    );
}

// ── End-to-end ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_zero_share_e2e_basic() {
    zero_share_e2e(10, 3).await; // n=10, t=3: output = n-2t = 4 shares
}

#[tokio::test]
async fn test_zero_share_e2e_minimal() {
    zero_share_e2e(7, 2).await; // n=7, t=2: smallest valid config (n=3t+1), output = 3
}

/// Runs the full zero-share protocol across n honest parties and verifies that
/// each output column reconstructs to zero.
async fn zero_share_e2e(n: usize, t: usize) {
    setup_tracing();
    let mut rng = test_rng();
    let session_id = SessionId::new(ProtocolType::ZeroSha, SessionId::pack_slot24(1, 0, 0), 1);
    let (network, mut receivers, _, _) = test_setup(n, vec![]);

    let mut nodes: Vec<ZeroShaNode<Fr, Avid<SessionId>>> = (0..n)
        .map(|id| ZeroShaNode::new(id, n, t, t + 1).unwrap())
        .collect();

    for i in 0..n {
        nodes[i]
            .init(session_id, &mut rng, network[i].clone())
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
                match wrapped {
                    WrappedMessage::ZeroSha(msg) => {
                        if let Err(e) = node.process(msg, net.clone()).await {
                            warn!("ZeroSha process error: {e}");
                        }
                    }
                    WrappedMessage::Rbc(msg) => {
                        if let Err(e) = node.rbc.process(msg, net.clone()).await {
                            warn!("RBC process error: {e}");
                        }
                        if let Err(e) = node.drain_rbc_output().await {
                            warn!("RBC drain error: {e}");
                        }
                    }
                    _ => {}
                }
            }
        });
    }

    let expected_output_count = n - 2 * t;
    let mut all_outputs: Vec<Vec<RobustShare<Fr>>> = Vec::with_capacity(n);
    for i in 0..n {
        let output = nodes[i]
            .wait_for_result(session_id, Duration::from_secs(5))
            .await
            .unwrap_or_else(|e| panic!("party {i} wait_for_result failed: {e}"));
        assert_eq!(
            output.len(),
            expected_output_count,
            "party {i}: wrong output count"
        );
        all_outputs.push(output);
    }

    // Each output column must be a valid secret sharing of zero
    for j in 0..expected_output_count {
        let shares: Vec<RobustShare<Fr>> = (0..n).map(|i| all_outputs[i][j].clone()).collect();
        let (_, secret) = RobustShare::recover_secret(&shares, n, t)
            .unwrap_or_else(|e| panic!("output column {j}: reconstruction failed: {e}"));
        assert!(
            secret.is_zero(),
            "output column {j}: reconstructed secret must be zero"
        );
    }
}
