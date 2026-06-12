use crate::utils::test_utils::setup_tracing;
use crate::utils::turmoil::turmoil_setup;
use ark_bls12_381::{Fr, G1Projective as G};
use ark_ec::PrimeGroup;
use ark_ff::UniformRand;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use ark_std::test_rng;
use chacha20poly1305::aead::OsRng;
use std::sync::Arc;
use stoffelmpc_mpc::avss_mpc::{AvssSessionId, AvssWrappedMessage, ProtocolType};
use stoffelmpc_mpc::common::ProtocolSessionId;
use stoffelmpc_mpc::common::{rbc::rbc::Avid, ShamirShare};
use stoffelmpc_mpc::common::{share::avss::verify_feldman, SecretSharingScheme};
use stoffelmpc_mpc::common::{share::avss::AvssNode, RBC};
use stoffelmpc_network::fake_network::SenderId;
use stoffelmpc_network::turmoil_network::TurmoilNetwork;
use tokio::sync::mpsc::{self, Sender};
use tokio::time::Duration;
use tracing::{error, info};

mod utils;

#[test]
fn avss_e2e() {
    setup_tracing();

    let n_parties = 4;
    let t = 1;

    // Setup of the network.
    let (mut sim, inner) = turmoil_setup(n_parties, vec![], Some((10, 2000)));
    let (tx_out, rx_out) = std::sync::mpsc::channel::<Result<(usize, Vec<_>), String>>();
    let (tx_client, mut rx_client) = tokio::sync::broadcast::channel::<()>(n_parties);

    let session_id =
        AvssSessionId::new(ProtocolType::Avss, AvssSessionId::pack_slot24(0, 0, 0), 111);
    let mut rng = test_rng();

    // PKI setup. This is executed once.
    let mut sks = Vec::new();
    let mut pks = Vec::new();
    for _ in 0..n_parties {
        let sk = Fr::rand(&mut rng);
        let pk = G::generator() * sk;
        sks.push(sk);
        pks.push(pk);
    }
    let pk_map = Arc::new(pks);

    let sender_channels: Vec<Sender<_>> = (0..n_parties)
        .map(|_| {
            let (sender, _) = mpsc::channel(128);
            sender
        })
        .collect();

    let secrets = vec![Fr::from(50), Fr::from(60), Fr::from(70)];

    let nodes: Vec<AvssNode<Fr, Avid<AvssSessionId>, G, AvssSessionId>> = (0..n_parties)
        .map(|i| {
            AvssNode::new(
                i,
                n_parties,
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

    for id in 0..n_parties {
        let node = nodes[id].clone();
        let tx = tx_out.clone();
        let tx_client = tx_client.clone();
        let inner = inner.clone();

        sim.host(format!("node{}", id), move || {
            let inner = inner.clone();
            let tx = tx.clone();
            let mut node = node.clone();
            let tx_client = tx_client.clone();

            async move {
                let (network, mut rx) = TurmoilNetwork::new(SenderId::Node(id), inner).await;
                tokio::time::sleep(Duration::from_millis(50)).await;

                let network_arc = Arc::new(network);
                let mut rng = StdRng::from_rng(OsRng).unwrap();

                // Simulates the dealer at ID = 0.
                if id == 0 {
                    let secrets = vec![Fr::from(50), Fr::from(60), Fr::from(70)];
                    node.init(secrets.clone(), session_id, &mut rng, network_arc.clone())
                        .await
                        .unwrap();
                }

                let mut msg_count = 0;
                let result = tokio::time::timeout(Duration::from_secs(30), async {
                    loop {
                        match rx.recv().await {
                            Some((_, message)) => {
                                let wrapped: AvssWrappedMessage = bincode::deserialize(&message)
                                    .expect("The deserialization must work correctly");
                                msg_count += 1;
                                match wrapped {
                                    AvssWrappedMessage::Rbc(msg) => {
                                        node.rbc
                                            .process(msg, network_arc.clone())
                                            .await
                                            .expect("The node should process the RBC message");
                                        let _ = node.drain_rbc_output().await;
                                    }
                                    _ => {}
                                }
                            }
                            None => {
                                error!("Unexpected message reception stop");
                                break;
                            }
                        }

                        tokio::task::yield_now().await;

                        let shares_guard = node.shares.lock().await;
                        if shares_guard.contains_key(&session_id) {
                            break;
                        }
                    }
                })
                .await;

                if result.is_err() {
                    error!(
                        "Error simulating the process loop for Party {}: {:?}, {msg_count}",
                        id, result
                    );
                    tx.send(Err(format!(
                        "node {} timed out after {} msgs",
                        id, msg_count
                    )))
                    .unwrap();
                }

                {
                    let map = node.shares.lock().await;
                    let share = map
                        .get(&session_id)
                        .expect("missing AVSS output")
                        .as_ref()
                        .expect("empty share");

                    tx.send(Ok((id, share.clone()))).unwrap();
                }
                tx_client.send(()).unwrap();
                Ok(())
            }
        });
    }

    drop(tx_out);
    drop(tx_client);

    sim.client("driver", async move {
        let mut count = 0;
        while count < n_parties {
            match rx_client.recv().await {
                Ok(()) => count += 1,
                Err(_) => break,
            }
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    });

    sim.run().unwrap();

    let protocol_outputs: Vec<_> = std::iter::from_fn(|| rx_out.try_recv().ok()).collect();

    // Feldman verification already checked in protocol.
    let mut shares = vec![Vec::new(); 3];
    for output in protocol_outputs {
        let (_, share) = output.expect("The output should be correct");
        for (i, s) in share.iter().enumerate() {
            assert_eq!(s.feldmanshare.degree, t);
            assert!(verify_feldman(s.clone()));
            shares[i].push(s.feldmanshare.clone());
        }
    }

    // --- Reconstruct secret ---
    for (i, s) in shares.iter().enumerate() {
        let recovered = ShamirShare::recover_secret(&s, n_parties, t).unwrap();
        assert_eq!(secrets[i], recovered.1);
        info!("Recovered AVSS secret = {:?}", recovered.1);
    }
}
