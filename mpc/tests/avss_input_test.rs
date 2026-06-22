use utils::test_utils::{fan_in_inboxes, setup_tracing, test_setup};

use ark_bls12_381::{Fr, G1Projective as G};
use ark_ff::UniformRand;
use ark_std::test_rng;
use std::time::Duration;
use stoffelcrypto::{
    avss_mpc::{input::input::AvssInputServer, AvssMPCClient, AvssSessionId, AvssWrappedMessage},
    common::{rbc::rbc::Avid, share::feldman::FeldmanShamirShare, SecretSharingScheme, RBC},
};
use stoffelmpc_network::fake_network::SenderId;
use tokio::time::sleep;

pub mod utils;

/// End-to-end test for the AVSS input protocol.
///
/// 4 servers, 1 client, t=1.
/// - Servers generate random FeldmanShamirShares and send to client
/// - Client verifies Feldman commitments, reconstructs random value at t+1 shares
/// - Client broadcasts masked input via RBC
/// - Servers receive masked input, compute input shares
/// - Verify: reconstruct input from all server shares matches original
#[tokio::test]
async fn test_avss_input_e2e() {
    setup_tracing();

    let n = 4;
    let t = 1;
    let clientid = 100;
    let instance_id = 111;
    let input = Fr::from(42u64);
    let ids: Vec<usize> = (1..=n).collect();

    // Setup network with one client
    let (network, mut receivers, client_networks, mut client_recv) = test_setup(n, vec![clientid]);
    let client_inboxes = client_recv.remove(&clientid).unwrap();
    let client_network = client_networks.get(&clientid).unwrap().clone();

    let inbox: Vec<(SenderId, tokio::sync::mpsc::Receiver<Vec<u8>>)> = client_inboxes
        .into_iter()
        .enumerate()
        .map(|(i, r)| (SenderId::Node(i), r))
        .collect();
    let mut client_recv = fan_in_inboxes(inbox);

    // Generate random shares for masking (one per input per server)
    let mut rng = test_rng();
    let rand_secret = Fr::rand(&mut rng);
    let rand_shares =
        FeldmanShamirShare::<Fr, G>::compute_shares(rand_secret, n, t, Some(&ids), &mut rng)
            .unwrap();

    // Create client
    let mut client = AvssMPCClient::<Fr, Avid<AvssSessionId>, G>::new(
        clientid,
        n,
        t,
        instance_id,
        vec![input],
        1,
    )
    .unwrap();

    // Create input servers
    let mut nodes: Vec<_> = (0..n)
        .map(|i| {
            AvssInputServer::<Fr, Avid<AvssSessionId>, G>::new(i, n, t, vec![clientid]).unwrap()
        })
        .collect();

    // All but one node call init (to test the late-init case)
    for i in 0..nodes.len() - 1 {
        assert!(nodes[i]
            .init(
                clientid,
                vec![rand_shares[i].clone()],
                1,
                network[i].clone()
            )
            .await
            .is_ok());
    }

    // Receive random shares at client and process them
    for _ in 0..(n - 1) {
        let (_, raw) = client_recv.recv().await.unwrap();
        let wrapped: AvssWrappedMessage =
            bincode::deserialize(&raw).expect("deserialization error");
        match wrapped {
            AvssWrappedMessage::Input(msg) => {
                assert!(client
                    .input
                    .process(msg, client_network.clone())
                    .await
                    .is_ok());
            }
            _ => panic!("Unexpected message type"),
        }
    }

    // Run RBC for masked input broadcast and process at each server
    for (i, node) in nodes.iter_mut().enumerate() {
        let network = network.clone();
        let mut node = node.clone();
        let receiver = receivers.remove(0);
        let inbox: Vec<(SenderId, tokio::sync::mpsc::Receiver<Vec<u8>>)> = receiver
            .into_iter()
            .enumerate()
            .map(|(j, r)| (SenderId::Node(j), r))
            .collect();
        let mut merged_rx = fan_in_inboxes(inbox);
        tokio::spawn(async move {
            while let Some(raw_msg) = merged_rx.recv().await {
                let wrapped: AvssWrappedMessage =
                    bincode::deserialize(&raw_msg.1).expect("deserialization error");
                match wrapped {
                    AvssWrappedMessage::Rbc(rbc_msg) => {
                        let _ = node.rbc.process(rbc_msg, network[i].clone()).await;
                        let _ = node.drain_rbc_output().await;
                    }
                    _ => {}
                }
            }
        });
    }

    // Wait for RBC to complete
    sleep(Duration::from_millis(200)).await;

    // Late init for the last server - should compute input shares directly
    nodes[n - 1]
        .init(
            clientid,
            vec![rand_shares[n - 1].clone()],
            1,
            network[n - 1].clone(),
        )
        .await
        .unwrap();

    // Verify all servers have input shares and they reconstruct to the original input
    let mut recovered_shares = vec![];
    for node in &mut nodes {
        let shares = node
            .wait_for_all_inputs(Duration::from_millis(100))
            .await
            .expect("input error");
        let client_shares = shares.get(&clientid).unwrap();
        recovered_shares.push(client_shares[0].clone());
    }

    let (_, recovered_input) = FeldmanShamirShare::<Fr, G>::recover_secret(&recovered_shares, n, t)
        .expect("recovery failed");
    assert_eq!(recovered_input, input, "Recovered input does not match");
}
