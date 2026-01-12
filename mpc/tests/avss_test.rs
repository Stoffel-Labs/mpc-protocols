pub mod utils;

use crate::utils::test_utils::{fan_in_inboxes, setup_tracing, test_setup};
use ark_bls12_381::{Fr, G1Projective as G};
use ark_ec::PrimeGroup;
use ark_ff::UniformRand;
use ark_std::test_rng;
use std::sync::Arc;
use stoffelmpc_mpc::common::{share::avss::verify_feldman, SecretSharingScheme};
use stoffelmpc_mpc::common::{share::avss::AvssNode, RBC};
use stoffelmpc_mpc::honeybadger::{ProtocolType, SessionId};
use stoffelmpc_mpc::{
    common::{rbc::rbc::Avid, ShamirShare},
    honeybadger::WrappedMessage,
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
    let session_id = SessionId::new(ProtocolType::Avss, 0, 0, 0, 111);
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
    let mut nodes: Vec<AvssNode<Fr, Avid, G>> = (0..n)
        .map(|i| {
            AvssNode::new(i, n, t, sks[i], pk_map.clone(), sender_channels[i].clone()).unwrap()
        })
        .collect();

    // --- Dealer starts AVSS ---
    nodes[0]
        .init(Fr::from(50), session_id, &mut rng, network[0].clone())
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
                let wrapped: WrappedMessage = bincode::deserialize(&received.1).unwrap();
                match wrapped {
                    WrappedMessage::Rbc(msg) => {
                        node.rbc.process(msg, net.clone()).await.unwrap();
                        node.drain_rbc_output().await.unwrap();
                    }
                    _ => {}
                }
            }
        });
    }

    // --- Allow protocol to finish ---
    tokio::time::sleep(Duration::from_millis(300)).await;
    // --- Check outputs ---
    let mut shares = Vec::new();
    for node in &nodes {
        let map = node.shares.lock().await;
        let share = map
            .get(&session_id)
            .expect("missing AVSS output")
            .as_ref()
            .expect("empty share");

        // Feldman verification already checked in protocol
        assert_eq!(share.feldmanshare.degree, t);
        assert!(verify_feldman(share.clone()));
        shares.push(share.feldmanshare.clone());
    }

    // --- Reconstruct secret ---
    let recovered = ShamirShare::recover_secret(&shares, n, t).unwrap();
    assert_eq!(Fr::from(50), recovered.1);
    info!("Recovered AVSS secret = {:?}", recovered.1);
}
