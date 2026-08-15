pub mod utils;
use crate::utils::fpmul_utils::{generate_beaver_triple, spawn_receiver_tasks};
use crate::utils::test_utils::{fan_in_inboxes, setup_tracing, test_setup};
use crate::utils::truncpr_utils::{
    generate_input_integer_z_k, generate_random_shared_bits, generate_random_shared_int,
};
use ark_bls12_381::Fr as G;
use ark_bn254::{Fr as F, Fr};
use ark_ff::PrimeField;
use ark_std::test_rng;
use futures::future::join_all;
use itertools::Itertools;
use num_bigint::BigUint;
use std::collections::HashMap;
use std::time::Duration;
use stoffelcrypto::common::types::fixed::{FixedPointPrecision, SecretFixedPoint};
use stoffelcrypto::common::{ProtocolSessionId, SecretSharingScheme, ShamirShare};
use stoffelcrypto::honeybadger::fpmul::fpmul::FPMulNode;
use stoffelcrypto::honeybadger::fpmul::prandint::PRandIntNode;
use stoffelcrypto::honeybadger::fpmul::truncpr::TruncPrNode;
use stoffelcrypto::honeybadger::robust_interpolate::robust_interpolate::{Robust, RobustShare};
use stoffelcrypto::honeybadger::{ProtocolType, SessionId, WrappedMessage};
use stoffelmpc_network::fake_network::SenderId;
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinSet;
use tracing::info;

/// Verifies that the RISS-folded `r_t` values every node agrees on (Step 1-2) are exactly what
/// `share_r_p` robustly reconstructs to (Step 3) — the core correctness property PRandInt relies
/// on: the same replicated secret is what actually ends up Shamir-shared in the output field.
#[tokio::test]
async fn prandint_r_reconstruction() {
    setup_tracing();
    let n = 4;
    let t = 1;
    let l = 8;
    let k = 4;
    let batch_size = 2;
    let session_id = SessionId::new(ProtocolType::PRandInt, SessionId::pack_slot(123, 0, 0), 222);
    // Build fake network
    let (network, mut recv, _, _) = test_setup(n, vec![]);

    // Initialize nodes
    let mut nodes: Vec<PRandIntNode<G>> = (0..n)
        .map(|i| PRandIntNode::new(i, n, t).unwrap())
        .collect();

    for node in &mut nodes {
        node.generate_riss(session_id, l, k, batch_size, network[node.id].clone())
            .await
            .unwrap();
    }

    // Spawn receivers for each node
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
                    WrappedMessage::PRandInt(msg) => {
                        let _ = node.process(msg, net.clone()).await;
                    }
                    WrappedMessage::PRandIntEcho(msg) => {
                        let _ = node.process_echo(msg).await;
                    }
                    _ => continue,
                }
            }
        });
    }

    // Wait for all messages to process
    tokio::time::sleep(Duration::from_millis(500)).await;

    // === Step 1: Collect all r_T values from all nodes ===
    let mut all_r_t: HashMap<Vec<usize>, Vec<BigUint>> = HashMap::new();
    for node in &mut nodes {
        let binding = node.get_or_create_store(session_id, node.id).await.unwrap();
        let store = binding.lock().await;
        for (tset, val) in &store.r_t {
            // all parties that know this T should agree
            if let Some(existing) = all_r_t.get(tset) {
                assert_eq!(
                    existing, val,
                    "Inconsistent r_T for tset {:?} between parties",
                    tset
                );
            } else {
                all_r_t.insert(tset.clone(), val.clone());
            }
        }
    }

    // === Step 2: Compute ground truth replicated secret ===
    let mut r_int = Vec::new();
    for vec in all_r_t.values() {
        if r_int.is_empty() {
            r_int = vec.clone();
        } else {
            for (i, val) in vec.iter().enumerate() {
                r_int[i] += val;
            }
        }
    }
    println!("Ground truth r (vector sum) = {:?}", r_int);

    // === Step 3: Reconstruct from all (t+1)-subsets of Shamir shares ===
    let needed = 2 * t + 1;
    let all_ids: Vec<usize> = (0..n).collect();

    for combo in all_ids.iter().copied().combinations(needed) {
        let mut shares: Vec<Vec<ShamirShare<_, 1, Robust>>> =
            vec![Vec::with_capacity(needed); batch_size];

        for &id in &combo {
            let binding = nodes[id].get_or_create_store(session_id, id).await.unwrap();
            let store = binding.lock().await;
            let share = store.share_r_p.clone().expect("missing share_r_p");

            for (i, y) in share.iter().enumerate() {
                shares[i].push(y.clone());
            }
        }

        for i in 0..batch_size {
            let (_, rec_r) = RobustShare::recover_secret(&shares[i], n, t).unwrap();
            assert_eq!(
                rec_r,
                G::from_le_bytes_mod_order(&r_int[i].to_bytes_le()),
                "Reconstructed r mismatch for combo {:?}",
                combo
            );
        }
    }

    println!("All r_t values consistent and all Shamir reconstructions matched ground truth");
}

#[tokio::test]
async fn test_truncpr_end_to_end() {
    setup_tracing();
    let n = 4;
    let t = 1;
    let k = 16; // total bitlength (example)
    let m = 4; // fractional bits to truncate
    let session_id = SessionId::new(ProtocolType::Trunc, SessionId::pack_slot(123, 0, 0), 999);

    // === Build fake network ===
    let (network, mut recv, _, _) = test_setup(n, vec![]);

    // === Initialize nodes ===
    let mut nodes: Vec<TruncPrNode<F>> =
        (0..n).map(|i| TruncPrNode::new(i, n, t).unwrap()).collect();

    // === Input secret [a] (same across parties for test) ===
    let mut rng = test_rng();
    let a_val = RobustShare::compute_shares(F::from(12345u64), n, t, None, &mut rng).unwrap();
    let r_int = RobustShare::compute_shares(F::from(3), n, t, None, &mut rng).unwrap();
    let mut r_bits = vec![Vec::new(); n];
    for j in 0..m {
        let x = RobustShare::compute_shares(F::from((j % 2) as u64), n, t, None, &mut rng).unwrap();
        for (i, share) in x.iter().enumerate() {
            r_bits[i].push(share.clone());
        }
    }

    // === Spawn receivers to process messages ===
    let mut set = JoinSet::new();
    for i in 0..n {
        let receiver = recv.remove(0);
        let mut node = nodes[i].clone();
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
                    WrappedMessage::Trunc(msg) => {
                        let _ = node.process(msg).await;
                    }
                    _ => continue,
                }
            }
        });
    }

    // === Run init() for each node ===
    let futures = nodes.iter_mut().map(|node| {
        node.init(
            a_val[node.id].clone(),
            k,
            m,
            r_bits[node.id].clone(),
            r_int[node.id].clone(),
            session_id,
            network[node.id].clone(),
        )
    });

    join_all(futures).await.into_iter().for_each(|res| {
        res.unwrap();
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    // === Reconstruct [d] (the truncated output) ===
    let mut shares = Vec::new();

    for node in &mut nodes {
        let store = node.get_or_create_store(session_id, node.id).await.unwrap();
        let s = store.lock().await;

        assert!(s.share_d.is_some(), "Node {:?} missing share_d", node.id);
        shares.push(s.share_d.clone().unwrap());
    }

    let (_, d_reconstructed) = RobustShare::recover_secret(&shares, n, t).unwrap();
    println!("Reconstructed [d] = {:?}", d_reconstructed);

    // === Verify correctness: expected floor(a / 2^m) ===
    let expected = F::from((12345u64 >> m) as u64);
    let expected_plus1 = F::from(((12345u64 >> m) + 1) as u64);
    assert!(
        d_reconstructed == expected || d_reconstructed == expected_plus1,
        "TruncPr probabilistic mismatch: got {:?}, expected {:?} or {:?}",
        d_reconstructed,
        expected,
        expected_plus1
    );
}

#[tokio::test]
async fn fpmul_e2e() {
    setup_tracing();
    let num_parties = 5;
    let threshold = 1;
    let f = 2;
    let k = 10;
    let kappa = 10;
    let duration = Duration::from_secs(20);

    let precision = FixedPointPrecision::new(k, f);

    let session_id = SessionId::new(ProtocolType::FpMul, SessionId::pack_slot(123, 0, 0), 111);
    info!("Session ID: {:?}", session_id);

    // Build a fake network.
    let (network, receivers, _, _) = test_setup(num_parties, vec![]);

    // Create nodes for the protocol.
    let mut nodes: Vec<FPMulNode<Fr>> = (0..num_parties)
        .map(|node_id| FPMulNode::new(node_id, num_parties, threshold).unwrap())
        .collect();

    // Generate inputs for the protocol.
    let (a, a_input_int_shares) = generate_input_integer_z_k(num_parties, threshold, k);
    let (b, b_input_int_shares) = generate_input_integer_z_k(num_parties, threshold, k);

    assert_eq!(
        a_input_int_shares.len(),
        num_parties,
        "Incorrect number of a inputs"
    );
    assert_eq!(
        b_input_int_shares.len(),
        num_parties,
        "Incorrect number of b inputs"
    );

    let mut a_input_shares = Vec::with_capacity(num_parties);
    let mut b_input_shares = Vec::with_capacity(num_parties);
    for share in a_input_int_shares.iter() {
        a_input_shares.push(SecretFixedPoint::new_with_precision(
            share.clone(),
            precision.clone(),
        ));
    }
    for share in b_input_int_shares.iter() {
        b_input_shares.push(SecretFixedPoint::new_with_precision(
            share.clone(),
            precision.clone(),
        ));
    }

    let r_bits_shares = generate_random_shared_bits(num_parties, threshold, f);
    let r_int_shares =
        generate_random_shared_int(num_parties, threshold, (kappa + 2 * k - f) as u64);
    let mult_triple = generate_beaver_triple(num_parties, threshold);

    info!("kappa + 2 * k - f: {}", kappa + 2 * k - f);

    // Spawn the receiver tasks to forward the messages.
    let _set = spawn_receiver_tasks(num_parties, receivers, nodes.clone(), network.clone()).await;

    // Initialize the nodes.
    let mut set = JoinSet::new();
    for node in &mut nodes {
        let mut node = node.clone();
        let a = a_input_shares[node.id].clone();
        let b = b_input_shares[node.id].clone();
        let triple = mult_triple[node.id].clone();
        let r_bits = r_bits_shares[node.id].clone();
        let r_int = r_int_shares[node.id].clone();
        let net = network[node.id].clone();
        set.spawn(async move {
            node.init(a, b, triple, r_bits, r_int, duration, session_id, net)
                .await
                .unwrap()
                .value()
                .clone()
        });
    }

    let mut result_shares = Vec::with_capacity(num_parties);
    while let Some(result) = set.join_next().await {
        result_shares.push(result.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Compute the expected result.
    let mult = a * b;
    let trunc_mult = mult >> f;
    let expected_result = Fr::from(trunc_mult);
    let expected_result_plus_one = Fr::from((trunc_mult + 1) as u64);

    let (_, result) = RobustShare::recover_secret(&result_shares, num_parties, threshold).unwrap();
    info!(
        "expected: {}, result: {}, a: {}, b: {}",
        expected_result, result, a, b
    );
    assert!(expected_result == result || expected_result_plus_one == result);
}

/// PRandInt via PRSS: every party derives its mask shares from pre-distributed keys with **no
/// messages at all**, and the result must still reconstruct as a valid degree-`t` sharing of a
/// value inside the summed bound.
///
/// The keys come from the dev dealer, which is a total privacy break (one party sees every key)
/// and exists only until the distributed setup lands. It is fine here because the property under
/// test is the derivation and conversion path, not key secrecy.
#[tokio::test]
async fn prandint_via_prss_needs_no_network() {
    setup_tracing();
    let n = 4;
    let t = 1;
    let count = 6;
    let bits = 12;
    let instance_id = 222u32;

    let mut rng = test_rng();
    let dealt = crate::utils::prss_utils::deal_keys(n, t, &mut rng);

    let nodes: Vec<PRandIntNode<G>> = (0..n)
        .map(|i| {
            let mut node = PRandIntNode::new(i, n, t).unwrap();
            let keys =
                stoffelcrypto::honeybadger::prss::prss::PrssKeys::<G>::new(i, n, t, &dealt[i])
                    .unwrap();
            node.install_prss_keys(keys);
            node
        })
        .collect();

    // No network is constructed anywhere in this test -- that is the point.
    let per_party: Vec<Vec<RobustShare<G>>> = nodes
        .iter()
        .map(|node| node.generate_prss_at(instance_id, 0, count, bits).unwrap())
        .collect();

    let n_tsets = (0..n).combinations(t).count();
    let bound = BigUint::from(n_tsets) << bits;

    for i in 0..count {
        let shares: Vec<RobustShare<G>> = (0..n).map(|id| per_party[id][i].clone()).collect();
        let (coeffs, secret) = RobustShare::recover_secret(&shares, n, t).unwrap();
        assert!(coeffs.len() <= t + 1, "mask {i} is not a degree-t sharing");
        assert_eq!(coeffs[0], secret);
        assert!(
            BigUint::from(secret.into_bigint()) < bound,
            "mask {i} exceeded C(n,t)*2^bits"
        );
    }

    // Re-deriving the same range must be byte-identical; a different instance must differ.
    let again = nodes[0]
        .generate_prss_at(instance_id, 0, count, bits)
        .unwrap();
    assert_eq!(again, per_party[0]);

    let different = nodes[0]
        .generate_prss_at(instance_id + 1, 0, count, bits)
        .unwrap();
    assert_ne!(different, per_party[0]);

    // Topping up from a pool depth must land on the same values as the one-shot derivation --
    // the property `ensure_prandint_shares` relies on when a node restarts mid-fill.
    let tail = nodes[0]
        .generate_prss_at(instance_id, 2, count - 2, bits)
        .unwrap();
    assert_eq!(tail, per_party[0][2..]);
}

/// A width the summed value cannot fit must be refused rather than silently wrapping the field.
#[tokio::test]
async fn prandint_prss_rejects_an_oversized_mask() {
    let n = 4;
    let t = 1;
    let mut rng = test_rng();
    let dealt = crate::utils::prss_utils::deal_keys(n, t, &mut rng);
    let mut node = PRandIntNode::<G>::new(0, n, t).unwrap();
    node.install_prss_keys(
        stoffelcrypto::honeybadger::prss::prss::PrssKeys::<G>::new(0, n, t, &dealt[0]).unwrap(),
    );

    assert!(node
        .generate_prss_at(222, 0, 1, node.max_mask_bits())
        .is_ok());
    assert!(node
        .generate_prss_at(222, 0, 1, node.max_mask_bits() + 1)
        .is_err());
}
