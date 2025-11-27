pub mod utils;
use crate::utils::test_utils::{setup_tracing, test_setup};
use ark_bls12_381::Fr as G;
use ark_bn254::Fr as F;
use ark_ff::Field;
use ark_std::test_rng;
use itertools::Itertools;
use std::collections::HashMap;
use std::{sync::Arc, time::Duration};
use stoffelmpc_mpc::common::rbc::rbc::Avid;
use stoffelmpc_mpc::common::{SecretSharingScheme, ShamirShare, RBC};
use stoffelmpc_mpc::honeybadger::fpmul::f256::{
    build_all_f_polys_2_8, lagrange_interpolate_f2_8, F2_8Domain, F2_8,
};
use stoffelmpc_mpc::honeybadger::fpmul::prandbitd::PRandBitNode;
use stoffelmpc_mpc::honeybadger::fpmul::truncpr::TruncPrNode;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::{Robust, RobustShare};
use stoffelmpc_mpc::honeybadger::{ProtocolType, SessionId, WrappedMessage};
use tokio::sync::mpsc::{self, Sender};
use tokio::task::JoinSet;

#[tokio::test]
async fn test_prandbitd_end_to_end() {
    setup_tracing();
    let n = 4;
    let t = 1;
    let l = 8;
    let k = 4;
    let batch_size = 2;
    let session_id = SessionId::new(ProtocolType::PRandBit, 0, 0, 111);
    let mut rng = test_rng();
    // Build fake network
    let (network, mut recv, _) = test_setup(n, vec![]);

    let sender_channels: Vec<Sender<_>> = (0..n)
        .map(|_| {
            let (sender, _) = mpsc::channel(128);
            sender
        })
        .collect();

    // Initialize nodes
    let mut nodes: Vec<PRandBitNode<F, G>> = (0..n)
        .map(|i| {
            PRandBitNode::new(
                i,
                n,
                t,
                sender_channels[i].clone(),
                sender_channels[i].clone(),
            )
            .unwrap()
        })
        .collect();

    // Run distributed RISS generation
    let mut node_shares: Vec<Vec<RobustShare<F>>> = vec![Vec::new(); n];
    for _ in 0..batch_size {
        let shares = RobustShare::compute_shares(F::ONE, n, t, None, &mut rng)
            .expect("share generation failed");
        for (j, share) in shares.into_iter().enumerate() {
            node_shares[j].push(share);
        }
    }

    for (i, node) in &mut nodes.iter_mut().enumerate() {
        node.generate_riss(
            session_id,
            node_shares[i].clone(),
            l,
            k,
            batch_size,
            network.clone(),
        )
        .await
        .unwrap();
    }

    // Process all messages
    let mut set = JoinSet::new();
    for i in 0..n {
        let mut receiver = recv.remove(0);
        let mut node = nodes[i].clone();
        let net = Arc::clone(&network);

        set.spawn(async move {
            while let Some(received) = receiver.recv().await {
                let wrapped: WrappedMessage = bincode::deserialize(&received).unwrap();
                match wrapped {
                    WrappedMessage::PRandBit(msg) => {
                        let _ = node.process(msg, net.clone()).await;
                    }
                    WrappedMessage::BatchRecon(msg) => {
                        let _ = node.batch_recon.process(msg, net.clone()).await;
                    }
                    _ => continue,
                }
            }
        });
    }

    tokio::time::sleep(Duration::from_millis(300)).await;

    //Check outputs
    let mut x_vals_2 = Vec::new();
    let mut y_vals_2 = vec![Vec::new(); batch_size];
    let domain_2 = F2_8Domain::new(n).unwrap();

    for node in &mut nodes {
        let binding = node.get_or_create_store(session_id).await;
        let store = binding.lock().await;
        assert!(
            store.share_b_2.len() == batch_size,
            "Node {:?} missing share_b_2",
            node.id
        );
        x_vals_2.push(domain_2.element(node.id));
        for (i, y) in store.share_b_2.iter().enumerate() {
            y_vals_2[i].push(*y);
        }
    }

    for y in y_vals_2 {
        let poly_2 = lagrange_interpolate_f2_8(&x_vals_2, &y);
        let recovered_b_2 = poly_2.coeffs[0];
        println!("Recovered b (GF(2^8)) = {:?}", recovered_b_2);
        assert_eq!(recovered_b_2, F2_8::from(1u16), "Recovered b_2 != expected");
    }

    // === Reconstruct [b]_p in G (bigger prime field) ===
    let mut shares = vec![Vec::new(); batch_size];

    for node in &mut nodes {
        let binding = node.get_or_create_store(session_id).await;
        {
            let store = binding.lock().await;

            assert!(
                store.share_b_p.len() == batch_size,
                "Node {:?} missing share_b_p",
                node.id
            );

            for (i, y) in store.share_b_p.iter().enumerate() {
                shares[i].push(y.clone());
            }
        }
    }

    for y in shares {
        let owned: Vec<ShamirShare<_, 1, Robust>> = y.iter().map(|s| (*s).clone()).collect();
        let (_, v) = RobustShare::recover_secret(&owned, n).unwrap();
        let recovered_b_p = v;

        println!("Recovered b (prime field G) = {:?}", recovered_b_p);
        assert_eq!(recovered_b_p, G::from(1u64), "Recovered b_p != expected");
    }
}

#[tokio::test]
async fn test_prandbitd_r_reconstruction() {
    setup_tracing();
    let n = 4;
    let t = 1;
    let l = 8;
    let k = 4;
    let batch_size = 2;
    let session_id = SessionId::new(ProtocolType::PRandBit, 0, 0, 222);
    let mut rng = test_rng();
    // Build fake network
    let (network, mut recv, _) = test_setup(n, vec![]);

    let sender_channels: Vec<Sender<_>> = (0..n)
        .map(|_| {
            let (sender, _) = mpsc::channel(128);
            sender
        })
        .collect();

    // Initialize nodes
    let mut nodes: Vec<PRandBitNode<F, G>> = (0..n)
        .map(|i| {
            PRandBitNode::new(
                i,
                n,
                t,
                sender_channels[i].clone(),
                sender_channels[i].clone(),
            )
            .unwrap()
        })
        .collect();

    // Run distributed RISS generation
    let mut node_shares: Vec<Vec<RobustShare<F>>> = vec![Vec::new(); n];
    for _ in 0..batch_size {
        let shares = RobustShare::compute_shares(F::ONE, n, t, None, &mut rng)
            .expect("share generation failed");
        for (j, share) in shares.into_iter().enumerate() {
            node_shares[j].push(share);
        }
    }
    for node in &mut nodes {
        node.generate_riss(
            session_id,
            node_shares[node.id].clone(),
            l,
            k,
            batch_size,
            network.clone(),
        )
        .await
        .unwrap();
    }

    // Spawn receivers for each node
    let mut set = JoinSet::new();
    for i in 0..n {
        let mut receiver = recv.remove(0);
        let mut node = nodes[i].clone();
        let net = Arc::clone(&network);

        set.spawn(async move {
            while let Some(received) = receiver.recv().await {
                let wrapped: WrappedMessage = bincode::deserialize(&received).unwrap();
                match wrapped {
                    WrappedMessage::PRandBit(msg) => {
                        let _ = node.process(msg, net.clone()).await;
                    }
                    WrappedMessage::BatchRecon(msg) => {
                        let _ = node.batch_recon.process(msg, net.clone()).await;
                    }
                    _ => continue,
                }
            }
        });
    }

    // Wait for all messages to process
    tokio::time::sleep(Duration::from_millis(500)).await;

    // === Step 1: Collect all r_T values from all nodes ===
    let mut all_r_t: HashMap<Vec<usize>, Vec<i64>> = HashMap::new();
    for node in &mut nodes {
        let binding = node.get_or_create_store(session_id).await;
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
            let binding = nodes[id].get_or_create_store(session_id).await;
            let store = binding.lock().await;
            let share = store.share_r_q.clone().expect("missing share_r_q");

            for (i, y) in share.iter().enumerate() {
                shares[i].push(y.clone());
            }
        }

        for i in 0..batch_size {
            let (_, rec_r) = RobustShare::recover_secret(&shares[i], n).unwrap();
            assert_eq!(
                rec_r,
                F::from(r_int[i]),
                "Reconstructed r mismatch for combo {:?}",
                combo
            );
        }
    }

    println!("All r_t values consistent and all Shamir reconstructions matched ground truth");
    // === Step 4: Reconstruct r0 (GF(2^8)) ===
    let domain_2 = F2_8Domain::new(n).unwrap();
    let expected_r0: Vec<F2_8> = r_int.iter().map(|i| F2_8::from((i & 1) as u8)).collect();

    let mut shares_r2 = Vec::new();
    for node in &mut nodes {
        let binding = node.get_or_create_store(session_id).await;
        let store = binding.lock().await;
        shares_r2.push((node.id, store.share_r_2.clone().expect("missing share_r_2")));
    }

    for combo in all_ids.iter().copied().combinations(needed) {
        let mut xs = Vec::new();
        let mut ys = vec![Vec::new(); batch_size];
        for &id in &combo {
            xs.push(domain_2.element(id));
            let val = shares_r2.iter().find(|(i, _)| *i == id).unwrap().1.clone();
            for (i, y) in val.iter().enumerate() {
                ys[i].push(*y);
            }
        }
        for i in 0..batch_size {
            let poly = lagrange_interpolate_f2_8(&xs, &ys[i]);
            let rec_r0 = poly.evaluate(F2_8::zero());
            assert_eq!(
                rec_r0, expected_r0[i],
                "Mismatch in r0 for combo {:?}",
                combo
            );
        }
    }
    println!("Shamir reconstruction of r0 matched expected parity");

    // === Step 5: Per-node sanity: recompute share_r_2 from r_T values ===
    for node in &mut nodes {
        let binding = node.get_or_create_store(session_id).await;
        let store = binding.lock().await;
        let tsets: Vec<Vec<usize>> = store.r_t.keys().cloned().collect();
        let poly_f2 = build_all_f_polys_2_8(n, tsets).unwrap();
        let xi2 = domain_2.element(node.id);
        let mut recomputed = vec![F2_8::zero(); batch_size];
        for (tset, r_t) in store.r_t.iter() {
            let coeff = poly_f2[tset].evaluate(xi2);
            for i in 0..batch_size {
                let r2 = F2_8::from((r_t[i] & 1) as u8);
                recomputed[i] = recomputed[i] + (r2 * coeff);
            }
        }
        let stored = store.share_r_2.clone().expect("missing share_r_2");
        assert_eq!(recomputed, stored, "Node {}: share_r_2 mismatch", node.id);
    }
    println!("Per-node share_r_2 matches recomputation");
}

#[tokio::test]
async fn test_truncpr_end_to_end() {
    setup_tracing();
    let n = 4;
    let t = 1;
    let k = 16; // total bitlength (example)
    let m = 4; // fractional bits to truncate
    let session_id = SessionId::new(ProtocolType::Trunc, 0, 0, 999);

    // === Build fake network ===
    let (network, mut recv, _) = test_setup(n, vec![]);

    // === Initialize nodes ===
    let (trunc_sender, _) = mpsc::channel(128);
    let mut nodes: Vec<TruncPrNode<F, Avid>> = (0..n)
        .map(|i| TruncPrNode::new(i, n, t, trunc_sender.clone()).unwrap())
        .collect();

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
    // === Run init() for each node ===
    for node in &mut nodes {
        node.init(
            a_val[node.id].clone(),
            k,
            m,
            r_bits[node.id].clone(),
            r_int[node.id].clone(),
            session_id,
            network.clone(),
        )
        .await
        .unwrap();
    }

    // === Spawn receivers to process messages ===
    let mut set = JoinSet::new();
    for i in 0..n {
        let mut receiver = recv.remove(0);
        let mut node = nodes[i].clone();
        let net = Arc::clone(&network);

        set.spawn(async move {
            while let Some(received) = receiver.recv().await {
                let wrapped: WrappedMessage = bincode::deserialize(&received).unwrap();
                match wrapped {
                    WrappedMessage::Trunc(msg) => {
                        let _ = node.process(msg, net.clone()).await;
                    }
                    WrappedMessage::Rbc(msg) => {
                        let _ = node.rbc.process(msg, net.clone()).await;
                    }
                    _ => continue,
                }
            }
        });
    }

    tokio::time::sleep(Duration::from_millis(200)).await;

    // === Reconstruct [d] (the truncated output) ===
    let mut shares = Vec::new();

    for node in &mut nodes {
        let store = node.get_or_create_store(session_id).await;
        let s = store.lock().await;

        assert!(s.share_d.is_some(), "Node {:?} missing share_d", node.id);
        shares.push(s.share_d.clone().unwrap());
    }

    let (_, d_reconstructed) = RobustShare::recover_secret(&shares, n).unwrap();
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
