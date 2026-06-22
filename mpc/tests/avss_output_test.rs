use utils::test_utils::setup_tracing;

use ark_bls12_381::{Fr, G1Projective as G};
use ark_ff::UniformRand;
use ark_serialize::CanonicalSerialize;
use ark_std::test_rng;
use stoffelcrypto::{
    avss_mpc::output::{output::AvssOutputClient, AvssOutputMessage},
    common::{share::feldman::FeldmanShamirShare, SecretSharingScheme},
};
use tokio::time::Duration;

pub mod utils;

/// Test that output reconstruction works correctly with t+1 shares.
#[tokio::test]
async fn test_avss_output_get_output() {
    setup_tracing();

    let n = 5;
    let t = 1;
    let input_len = 1;
    let client_id = 7;
    let ids: Vec<usize> = (1..=n).collect();
    let mut rng = test_rng();

    let mut client = AvssOutputClient::<Fr, G>::new(client_id, n, t, input_len).unwrap();
    let secret = Fr::rand(&mut rng);

    // Generate FeldmanShamirShares for the secret
    let shares_vec =
        FeldmanShamirShare::<Fr, G>::compute_shares(secret, n, t, Some(&ids), &mut rng).unwrap();

    // Send only 1 share (less than t+1 = 2)
    {
        let mut payload = Vec::new();
        vec![shares_vec[0].clone()]
            .serialize_compressed(&mut payload)
            .unwrap();
        let msg = AvssOutputMessage::new(1, payload); // sender_id matches share id
        client.output_handler(msg).await.unwrap();
    }

    // get_output should return None since not enough shares have been received
    assert_eq!(client.get_output(), None);

    // Send one more share (total 2 = t+1)
    {
        let mut payload = Vec::new();
        vec![shares_vec[1].clone()]
            .serialize_compressed(&mut payload)
            .unwrap();
        let msg = AvssOutputMessage::new(2, payload);
        client.output_handler(msg).await.unwrap();
    }

    // get_output should now return the reconstructed secret
    assert_eq!(client.get_output(), Some(vec![secret]));
}

/// Test wait_for_output with timeout.
#[tokio::test]
async fn test_avss_output_wait_for_output() {
    setup_tracing();

    let n = 5;
    let t = 1;
    let input_len = 1;
    let client_id = 7;
    let ids: Vec<usize> = (1..=n).collect();
    let mut rng = test_rng();

    let mut client = AvssOutputClient::<Fr, G>::new(client_id, n, t, input_len).unwrap();
    let secret = Fr::rand(&mut rng);

    let shares_vec =
        FeldmanShamirShare::<Fr, G>::compute_shares(secret, n, t, Some(&ids), &mut rng).unwrap();

    // Send 1 share (not enough)
    {
        let mut payload = Vec::new();
        vec![shares_vec[0].clone()]
            .serialize_compressed(&mut payload)
            .unwrap();
        let msg = AvssOutputMessage::new(1, payload);
        client.output_handler(msg).await.unwrap();
    }

    // wait_for_output should timeout
    let result = client.wait_for_output(Duration::from_millis(10)).await;
    assert!(
        result.is_err(),
        "Expected timeout error when only 1 share is sent"
    );

    // Send one more share (total t+1 = 2)
    {
        let mut payload = Vec::new();
        vec![shares_vec[1].clone()]
            .serialize_compressed(&mut payload)
            .unwrap();
        let msg = AvssOutputMessage::new(2, payload);
        client.output_handler(msg).await.unwrap();
    }

    // Now wait_for_output should succeed
    let result2 = client.wait_for_output(Duration::from_millis(10)).await;
    assert!(
        result2.is_ok(),
        "Expected output to be reconstructed after enough shares"
    );
    assert_eq!(result2.unwrap(), vec![secret]);
}

/// Test that duplicate shares are rejected.
#[tokio::test]
async fn test_avss_output_duplicate_rejection() {
    setup_tracing();

    let n = 5;
    let t = 1;
    let input_len = 1;
    let client_id = 7;
    let ids: Vec<usize> = (1..=n).collect();
    let mut rng = test_rng();

    let mut client = AvssOutputClient::<Fr, G>::new(client_id, n, t, input_len).unwrap();
    let secret = Fr::rand(&mut rng);

    let shares_vec =
        FeldmanShamirShare::<Fr, G>::compute_shares(secret, n, t, Some(&ids), &mut rng).unwrap();

    // Send share from server 1
    let mut payload = Vec::new();
    vec![shares_vec[0].clone()]
        .serialize_compressed(&mut payload)
        .unwrap();
    let msg1 = AvssOutputMessage::new(1, payload.clone());
    client.output_handler(msg1).await.unwrap();

    // Try sending from the same server again - should fail
    let msg2 = AvssOutputMessage::new(1, payload);
    let result = client.output_handler(msg2).await;
    assert!(result.is_err(), "Expected duplicate error");
}

/// Test output reconstruction with multiple output values.
#[tokio::test]
async fn test_avss_output_multiple_values() {
    setup_tracing();

    let n = 4;
    let t = 1;
    let input_len = 3;
    let client_id = 10;
    let ids: Vec<usize> = (1..=n).collect();
    let mut rng = test_rng();

    let mut client = AvssOutputClient::<Fr, G>::new(client_id, n, t, input_len).unwrap();

    let secrets: Vec<Fr> = (0..input_len).map(|_| Fr::rand(&mut rng)).collect();

    // Generate shares for each secret
    let all_shares: Vec<Vec<FeldmanShamirShare<Fr, G>>> = secrets
        .iter()
        .map(|s| {
            FeldmanShamirShare::<Fr, G>::compute_shares(*s, n, t, Some(&ids), &mut rng).unwrap()
        })
        .collect();

    // Send t+1 shares from different servers
    for server_idx in 0..(t + 1) {
        let shares_for_server: Vec<FeldmanShamirShare<Fr, G>> = all_shares
            .iter()
            .map(|shares| shares[server_idx].clone())
            .collect();

        let mut payload = Vec::new();
        shares_for_server
            .serialize_compressed(&mut payload)
            .unwrap();
        let msg = AvssOutputMessage::new(server_idx + 1, payload);
        client.output_handler(msg).await.unwrap();
    }

    // Should have reconstructed all secrets
    let output = client.get_output().expect("Expected output to be ready");
    assert_eq!(output.len(), input_len);
    for (i, s) in secrets.iter().enumerate() {
        assert_eq!(output[i], *s, "Output mismatch at index {}", i);
    }
}
