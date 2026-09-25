pub mod utils;

use crate::utils::test_utils::{fan_in_inboxes, setup_tracing, test_setup};
use ark_bls12_381::{Fr, G1Projective as G};
use ark_ec::PrimeGroup;
use ark_ff::UniformRand;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::Rng;
use ark_std::test_rng;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use stoffelcrypto::avss_mpc::{AvssSessionId, AvssWrappedMessage, ProtocolType};
use stoffelcrypto::common::ProtocolSessionId;
use stoffelcrypto::common::{rbc::rbc::Avid, ShamirShare};
use stoffelcrypto::common::{
    share::avss::{verify_feldman, AvssAgreementMessage, AvssMessage},
    SecretSharingScheme,
};
use stoffelcrypto::common::{
    share::{avss::AvssNode, feldman::FeldmanShamirShare},
    RBC,
};
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
                Arc::new(AvssWrappedMessage::agreement_wrap),
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
                        let _ = node.drain_rbc_output(net.clone()).await;
                    }
                    AvssWrappedMessage::Agreement(msg) => {
                        node.process_agreement(msg, net.clone()).await.unwrap();
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
                Arc::new(AvssWrappedMessage::agreement_wrap),
            )
            .unwrap()
        })
        .collect();

    // Fill node 1's AVSS agreement cache to capacity (MAX_PENDING_SESSIONS = 512 in
    // avss.rs) with unrelated, freshly-created sessions so they aren't reclaimed as
    // stale, forcing the real dealer message below to be admitted-rejected. Each is
    // admitted by a single OK vote, which lazily creates the agreement entry, charged to
    // the (authenticated) voter rather than the session id's embedded (unauthenticated)
    // dealer bits — spread evenly across all `n` voters so no single voter's per-peer
    // quota (MAX_PENDING_SESSIONS / n) is hit before all 512 fills land and the global
    // cap does.
    for k in 1..=512u64 {
        let voter = (k % n as u64) as usize;
        let filler_id =
            AvssSessionId::new(ProtocolType::Avss, AvssSessionId::pack_slot(k, 0, 0), 222);
        nodes[1]
            .process_agreement(
                AvssAgreementMessage::Ok {
                    session_id: filler_id,
                    voter,
                },
                network[1].clone(),
            )
            .await
            .unwrap();
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
                match wrapped {
                    AvssWrappedMessage::Rbc(msg) => {
                        node.rbc.process(msg, net.clone()).await.unwrap();
                        let _ = node.drain_rbc_output(net.clone()).await;
                    }
                    AvssWrappedMessage::Agreement(msg) => {
                        node.process_agreement(msg, net.clone()).await.unwrap();
                    }
                    _ => {}
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
                Arc::new(AvssWrappedMessage::agreement_wrap),
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

    // Run both sessions to completion concurrently on every node, including node 1
    // whose output channel has capacity 1: whichever session's agreement quorum
    // completes second on node 1 must find that channel full. With a blocking
    // `.send().await` in `finalize` this would hang forever (nobody ever reads
    // `output_receivers`); the fix must let it drop the notification and carry on.
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
                match wrapped {
                    AvssWrappedMessage::Rbc(msg) => {
                        node.rbc.process(msg, net.clone()).await.unwrap();
                        let _ = node.drain_rbc_output(net.clone()).await;
                    }
                    AvssWrappedMessage::Agreement(msg) => {
                        node.process_agreement(msg, net.clone()).await.unwrap();
                    }
                    _ => {}
                }
            }
        });
    }

    // Both sessions must complete on node 1 well within the timeout; if `finalize`
    // ever blocks on a full output channel again, this hangs instead.
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            {
                let map = nodes[1].shares.lock().await;
                if map.contains_key(&session_id_1) && map.contains_key(&session_id_2) {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    set.abort_all();

    assert!(
        result.is_ok(),
        "both sessions should complete even with a capacity-1 output channel; \
         a blocking send in `finalize` would hang this instead"
    );

    // Both sessions must have completed and been stored, even though only one
    // notification could fit in the channel.
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

/// Replicates `AvssNode::init`'s private KDF exactly, so a test can hand-craft a
/// dealing without access to the module's private encryption helpers.
fn test_kdf_from_point(p: &G) -> [u8; 32] {
    let mut buf = Vec::new();
    p.serialize_compressed(&mut buf).unwrap();
    let hash = Sha256::digest(&buf);
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    key
}

/// Replicates `AvssNode::init`'s private encryption helper exactly (nonce-prefixed
/// ChaCha20Poly1305), for the same reason as `test_kdf_from_point`.
fn test_encrypt(key: [u8; 32], plaintext: &[u8], rng: &mut impl Rng) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);
    let mut ct = cipher.encrypt(&nonce, plaintext).unwrap();
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.append(&mut ct);
    out
}

/// Regression test for the AVSS completeness bug this module's OK/READY/Reveal
/// agreement layer fixes: a dealer sends every party a valid row of the dealing
/// except one, deliberately corrupted row for a single victim. Under plain AVSS the
/// victim's own Feldman check simply fails and there is no recourse — it is
/// permanently, silently stuck while every other party proceeds normally. With
/// agreement in place, the victim's failed check triggers a `Reveal` (an implicate);
/// the other, already-valid parties respond by revealing their own per-dealing keys,
/// and the victim recovers its share by Lagrange-interpolating their Feldman-verified
/// rows — landing on the exact same polynomial (and hence secret) everyone else holds.
#[tokio::test]
async fn test_avss_targeted_victim_recovers_via_reveal() {
    setup_tracing();

    let n = 4;
    let t = 1;
    let victim = 2usize; // distinct from the dealer (party 0)
    let session_id = AvssSessionId::new(ProtocolType::Avss, AvssSessionId::pack_slot(0, 0, 0), 444);
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

    let nodes: Vec<AvssNode<Fr, Avid<AvssSessionId>, G, AvssSessionId>> = (0..n)
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
                Arc::new(AvssWrappedMessage::agreement_wrap),
            )
            .unwrap()
        })
        .collect();

    // Hand-craft a dealing exactly like an honest `AvssNode::init` would produce,
    // except the victim's row is encrypted under an unrelated key — indistinguishable,
    // from the victim's side, from a dealer that simply sent it garbage.
    let secrets = vec![Fr::from(50), Fr::from(60)];
    let ids: Vec<usize> = (1..=n).collect();
    let shares: Vec<Vec<FeldmanShamirShare<Fr, G>>> =
        FeldmanShamirShare::compute_shares_batch(&secrets, n, t, Some(&ids), &mut rng).unwrap();

    let sk_d = Fr::rand(&mut rng);
    let pk_d = G::generator() * sk_d;
    let mut pk_d_bytes = Vec::new();
    pk_d.serialize_compressed(&mut pk_d_bytes).unwrap();

    let mut public_commitments = Vec::with_capacity(shares.len());
    let mut encrypted_shares: Vec<Vec<Vec<u8>>> = vec![Vec::with_capacity(shares.len()); n];
    for per_secret in &shares {
        let commitment_bytes = per_secret[0]
            .commitments
            .iter()
            .map(|c| {
                let mut b = Vec::new();
                c.serialize_compressed(&mut b).unwrap();
                b
            })
            .collect::<Vec<_>>();
        public_commitments.push(commitment_bytes);

        for (party_idx, share) in per_secret.iter().enumerate() {
            let key = if party_idx == victim {
                // Wrong key: unrelated to `pk_map[victim] * sk_d`, so the victim's own
                // (correctly-derived) key will never decrypt this.
                test_kdf_from_point(&(pk_d * Fr::rand(&mut rng)))
            } else {
                test_kdf_from_point(&(pk_map[party_idx] * sk_d))
            };
            let mut pt = Vec::new();
            share.feldmanshare.serialize_compressed(&mut pt).unwrap();
            encrypted_shares[party_idx].push(test_encrypt(key, &pt, &mut rng));
        }
    }

    let msg = AvssMessage::new(session_id, pk_d_bytes, public_commitments, encrypted_shares);
    let bytes = bincode::serialize(&msg).unwrap();
    // Broadcast directly through RBC — bypassing `AvssNode::init`, whose crypto always
    // produces a valid row for every party — so every party (including the victim)
    // receives this identical, partially-corrupted dealing, matching the real attack.
    nodes[0]
        .rbc
        .init(bytes, session_id, network[0].clone())
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
                match wrapped {
                    AvssWrappedMessage::Rbc(msg) => {
                        node.rbc.process(msg, net.clone()).await.unwrap();
                        let _ = node.drain_rbc_output(net.clone()).await;
                    }
                    AvssWrappedMessage::Agreement(msg) => {
                        node.process_agreement(msg, net.clone()).await.unwrap();
                    }
                    _ => {}
                }
            }
        });
    }

    let result = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let mut all_done = true;
            for node in &nodes {
                if !node.shares.lock().await.contains_key(&session_id) {
                    all_done = false;
                    break;
                }
            }
            if all_done {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    set.abort_all();

    assert!(
        result.is_ok(),
        "the victim must recover its share via Reveal instead of getting stuck forever"
    );

    // Every node — including the victim, whose direct row was corrupted — ends up
    // with a Feldman-consistent share of the exact same polynomial the dealer
    // committed to for everyone else.
    let mut shares_by_secret = vec![Vec::new(); secrets.len()];
    for node in &nodes {
        let map = node.shares.lock().await;
        let share = map.get(&session_id).unwrap().1.as_ref().unwrap();
        for (i, s) in share.iter().enumerate() {
            assert!(verify_feldman(s.clone(), s.feldmanshare.id));
            shares_by_secret[i].push(s.feldmanshare.clone());
        }
    }
    for (i, s) in shares_by_secret.iter().enumerate() {
        let recovered = ShamirShare::recover_secret(s, n, t).unwrap();
        assert_eq!(
            secrets[i], recovered.1,
            "recovered secret mismatch for batch index {i}"
        );
    }
}
