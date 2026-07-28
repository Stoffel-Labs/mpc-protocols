pub mod utils;

use crate::utils::test_utils::{fan_in_inboxes, setup_tracing, test_setup};
use ark_bls12_381::{Fr, G1Projective as G};
use ark_ec::PrimeGroup;
use ark_ff::UniformRand;
use ark_std::test_rng;
use std::sync::Arc;
use stoffelcrypto::avss_mpc::{AvssSessionId, AvssWrappedMessage, ProtocolType};
use stoffelcrypto::common::ProtocolSessionId;
use stoffelcrypto::common::{rbc::rbc::Avid, ShamirShare};
use stoffelcrypto::common::{share::avss::verify_feldman, SecretSharingScheme};
use stoffelcrypto::common::{share::avss::AvssNode, RBC};
use stoffelmpc_network::fake_network::SenderId;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::task::JoinSet;
use tokio::time::Duration;
use tracing::info;

#[tokio::test]
async fn test_avss_end_to_end() {
    setup_tracing();

    let n = 4;
    let t = 1;
    let session_id = AvssSessionId::new(ProtocolType::Avss, AvssSessionId::pack_slot(0, 0, 0), 111);
    let mut rng = test_rng();

    // --- Fake network ---
    let (network, mut recv, _, _) = test_setup(n, vec![]);

    // --- PKI setup (one-time) ---
    let mut sks = Vec::new();
    let mut pks = Vec::new();
    for _ in 0..n {
        let sk = Fr::rand(&mut rng);
        let pk = G::generator() * sk;
        sks.push(sk);
        pks.push(pk);
    }
    let pk_map = Arc::new(pks);

    // --- Output channels ---
    let sender_channels: Vec<Sender<_>> = (0..n)
        .map(|_| {
            let (sender, _) = mpsc::channel(128);
            sender
        })
        .collect();

    // --- Initialize AVSS nodes ---
    let mut nodes: Vec<AvssNode<Fr, Avid<AvssSessionId>, G, AvssSessionId>> = (0..n)
        .map(|i| {
            AvssNode::new(
                i,
                n,
                (1..=n).collect(),
                t,
                sks[i],
                pk_map.clone(),
                sender_channels[i].clone(),
                Arc::new(AvssWrappedMessage::rbc_wrap),
                Arc::new(AvssWrappedMessage::avss_wrap),
            )
            .unwrap()
        })
        .collect();

    // --- Dealer starts AVSS ---
    let secrets = vec![Fr::from(50), Fr::from(60), Fr::from(70)];
    nodes[0]
        .init(secrets.clone(), session_id, &mut rng, network[0].clone())
        .await
        .unwrap();

    // --- Spawn receiver loops ---
    let mut set = JoinSet::new();
    for i in 0..n {
        let receiver = recv.remove(0);
        let mut node = nodes[i].clone();
        let net = network[i].clone();
        let inbox: Vec<(SenderId, Receiver<Vec<u8>>)> = receiver
            .into_iter() // MOVE the receivers
            .enumerate()
            .map(|(i, r)| (SenderId::Node(i), r))
            .collect();
        let mut merged_rx = fan_in_inboxes(inbox);

        set.spawn(async move {
            while let Some(received) = merged_rx.recv().await {
                let wrapped: AvssWrappedMessage = bincode::deserialize(&received.1).unwrap();
                match wrapped {
                    AvssWrappedMessage::Rbc(msg) => {
                        node.rbc.process(msg, net.clone()).await.unwrap();
                        let _ = node.drain_rbc_output().await;
                    }
                    _ => {}
                }
            }
        });
    }

    // --- Allow protocol to finish ---
    tokio::time::sleep(Duration::from_millis(300)).await;
    // --- Check outputs ---
    let mut shares = vec![Vec::new(); 3];
    for node in &nodes {
        let map = node.shares.lock().await;
        let share = map
            .get(&session_id)
            .expect("missing AVSS output")
            .1
            .as_ref()
            .expect("empty share");

        // Feldman verification already checked in protocol
        for (i, s) in share.iter().enumerate() {
            assert_eq!(s.feldmanshare.degree, t);
            assert!(verify_feldman(s.clone(), s.feldmanshare.id));
            shares[i].push(s.feldmanshare.clone());
        }
    }

    // --- Reconstruct secret ---
    for (i, s) in shares.iter().enumerate() {
        let recovered = ShamirShare::recover_secret(&s, n, t).unwrap();
        assert_eq!(secrets[i], recovered.1);
        info!("Recovered AVSS secret = {:?}", recovered.1);
    }
}

/// Regression test: when the AVSS share cache is full and a completed RBC session
/// is rejected, the RBC layer must release the payload it was still holding for
/// that session instead of leaking it. Previously `process()` returned
/// `Err(AvssError::LimitExceeded)` on a full cache without ever calling
/// `rbc.clear_session`, so a flood of unsolicited sessions that complete at the
/// RBC layer but get rejected here would leave RBC holding their payloads (up to
/// 10 MiB each) until RBC's own, much larger cap/TTL eventually reclaimed them.
#[tokio::test]
async fn test_avss_rejected_session_clears_rbc_store() {
    setup_tracing();

    let n = 4;
    let t = 1;
    let session_id = AvssSessionId::new(ProtocolType::Avss, AvssSessionId::pack_slot(0, 0, 0), 222);
    let mut rng = test_rng();

    let (network, mut recv, _, _) = test_setup(n, vec![]);

    let mut sks = Vec::new();
    let mut pks = Vec::new();
    for _ in 0..n {
        let sk = Fr::rand(&mut rng);
        let pk = G::generator() * sk;
        sks.push(sk);
        pks.push(pk);
    }
    let pk_map = Arc::new(pks);

    let sender_channels: Vec<Sender<_>> = (0..n)
        .map(|_| {
            let (sender, _) = mpsc::channel(128);
            sender
        })
        .collect();

    let mut nodes: Vec<AvssNode<Fr, Avid<AvssSessionId>, G, AvssSessionId>> = (0..n)
        .map(|i| {
            AvssNode::new(
                i,
                n,
                (1..=n).collect(),
                t,
                sks[i],
                pk_map.clone(),
                sender_channels[i].clone(),
                Arc::new(AvssWrappedMessage::rbc_wrap),
                Arc::new(AvssWrappedMessage::avss_wrap),
            )
            .unwrap()
        })
        .collect();

    // Fill node 1's AVSS share cache to capacity (MAX_PENDING_SESSIONS = 512 in
    // avss.rs) with unrelated, freshly-timestamped sessions so they aren't reclaimed
    // as stale, forcing the real dealer message below to be admitted-rejected.
    {
        let mut map = nodes[1].shares.lock().await;
        for k in 1..=512u64 {
            let filler_id =
                AvssSessionId::new(ProtocolType::Avss, AvssSessionId::pack_slot(k, 0, 0), 222);
            map.insert(filler_id, (std::time::Instant::now(), None));
        }
    }

    let secrets = vec![Fr::from(50)];
    nodes[0]
        .init(secrets.clone(), session_id, &mut rng, network[0].clone())
        .await
        .unwrap();

    let mut set = JoinSet::new();
    for i in 0..n {
        let receiver = recv.remove(0);
        let mut node = nodes[i].clone();
        let net = network[i].clone();
        let inbox: Vec<(SenderId, Receiver<Vec<u8>>)> = receiver
            .into_iter()
            .enumerate()
            .map(|(i, r)| (SenderId::Node(i), r))
            .collect();
        let mut merged_rx = fan_in_inboxes(inbox);

        set.spawn(async move {
            while let Some(received) = merged_rx.recv().await {
                let wrapped: AvssWrappedMessage = bincode::deserialize(&received.1).unwrap();
                if let AvssWrappedMessage::Rbc(msg) = wrapped {
                    node.rbc.process(msg, net.clone()).await.unwrap();
                    let _ = node.drain_rbc_output().await;
                }
            }
        });
    }

    tokio::time::sleep(Duration::from_millis(300)).await;

    // The cache was full: the session must have been rejected, not stored...
    assert!(
        !nodes[1].shares.lock().await.contains_key(&session_id),
        "session should have been rejected, cache was at capacity"
    );
    // ...and the RBC-layer session for it must be gone too.
    assert!(
        nodes[1].rbc.get_store(session_id).await.is_err(),
        "RBC-layer session must be cleared when the AVSS layer rejects the session"
    );
}

/// Regression test: a full AVSS output-notification channel must not stall message
/// processing. Previously `process()` used a blocking `output_sender.send(...).await`;
/// since that channel is only drained by a caller actively waiting on a specific
/// session, completions for unsolicited sessions nobody is waiting on can pile up
/// and fill it, after which the blocking send — on the same task that also drives
/// inbound RBC message processing — would stall forever.
#[tokio::test]
async fn test_avss_full_output_channel_does_not_block() {
    setup_tracing();

    let n = 4;
    let t = 1;
    let session_id_1 =
        AvssSessionId::new(ProtocolType::Avss, AvssSessionId::pack_slot(0, 0, 0), 333);
    let session_id_2 =
        AvssSessionId::new(ProtocolType::Avss, AvssSessionId::pack_slot(1, 0, 0), 333);
    let mut rng = test_rng();

    let (network, mut recv, _, _) = test_setup(n, vec![]);

    let mut sks = Vec::new();
    let mut pks = Vec::new();
    for _ in 0..n {
        let sk = Fr::rand(&mut rng);
        let pk = G::generator() * sk;
        sks.push(sk);
        pks.push(pk);
    }
    let pk_map = Arc::new(pks);

    // Capacity-1 output channel. The receivers are kept alive (never dropped) but
    // never read from, so the channel is genuinely full rather than closed — a
    // closed channel would make `send` fail fast, which isn't the scenario here.
    let mut output_receivers = Vec::with_capacity(n);
    let sender_channels: Vec<Sender<_>> = (0..n)
        .map(|_| {
            let (sender, receiver) = mpsc::channel(1);
            output_receivers.push(receiver);
            sender
        })
        .collect();

    let mut nodes: Vec<AvssNode<Fr, Avid<AvssSessionId>, G, AvssSessionId>> = (0..n)
        .map(|i| {
            AvssNode::new(
                i,
                n,
                (1..=n).collect(),
                t,
                sks[i],
                pk_map.clone(),
                sender_channels[i].clone(),
                Arc::new(AvssWrappedMessage::rbc_wrap),
                Arc::new(AvssWrappedMessage::avss_wrap),
            )
            .unwrap()
        })
        .collect();

    nodes[0]
        .init(
            vec![Fr::from(50)],
            session_id_1,
            &mut rng,
            network[0].clone(),
        )
        .await
        .unwrap();
    nodes[0]
        .init(
            vec![Fr::from(60)],
            session_id_2,
            &mut rng,
            network[0].clone(),
        )
        .await
        .unwrap();

    // Relay RBC messages only — deliberately not calling `drain_rbc_output` here, so
    // both sessions finish at the RBC layer (queued in `rbc_output`) before this test
    // drives `drain_rbc_output` itself, directly and once, below. That makes the
    // full-channel scenario deterministic instead of racing background tasks.
    let mut set = JoinSet::new();
    for i in 0..n {
        let receiver = recv.remove(0);
        let node = nodes[i].clone();
        let net = network[i].clone();
        let inbox: Vec<(SenderId, Receiver<Vec<u8>>)> = receiver
            .into_iter()
            .enumerate()
            .map(|(i, r)| (SenderId::Node(i), r))
            .collect();
        let mut merged_rx = fan_in_inboxes(inbox);

        set.spawn(async move {
            while let Some(received) = merged_rx.recv().await {
                let wrapped: AvssWrappedMessage = bincode::deserialize(&received.1).unwrap();
                if let AvssWrappedMessage::Rbc(msg) = wrapped {
                    node.rbc.process(msg, net.clone()).await.unwrap();
                }
            }
        });
    }

    // Let RBC converge for both sessions on every node.
    tokio::time::sleep(Duration::from_millis(300)).await;
    set.abort_all();

    // Both sessions are now sitting in node 1's `rbc_output` queue. Draining them
    // calls `process()` for each in turn: the first send fills the capacity-1
    // output channel, the second must find it full. With the blocking `.send().await`
    // this hangs forever (nobody ever reads `output_receivers`); the fix must let it
    // return promptly instead.
    let drain_result = tokio::time::timeout(Duration::from_secs(2), nodes[1].drain_rbc_output())
        .await
        .expect("drain_rbc_output must not block once the output channel is full");
    assert!(
        drain_result.is_ok(),
        "drain_rbc_output should succeed, got {:?}",
        drain_result
    );

    // Both sessions must still have completed and been stored, even though only
    // one notification could fit in the channel.
    let map = nodes[1].shares.lock().await;
    assert!(
        map.contains_key(&session_id_1),
        "first session should have completed and been stored"
    );
    assert!(
        map.contains_key(&session_id_2),
        "second session should have completed and been stored despite the full output channel"
    );
}
