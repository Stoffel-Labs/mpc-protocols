pub mod utils;
use crate::utils::test_utils::{setup_tracing, test_setup};
use ark_bls12_381::Fr as F;
use ark_poly::Polynomial;
use itertools::Itertools;
use std::{sync::Arc, time::Duration};
use stoffelmpc_mpc::common::types::f256::{lagrange_interpolate_f2_8, F2_8};
use stoffelmpc_mpc::{
    common::types::{prandbitd::PRandBitDNode, PRandBitDMessage},
    honeybadger::{ProtocolType, SessionId},
};
use tokio::task::JoinSet; // Example prime field

#[tokio::test]
async fn test_prandbitd_end_to_end() {
    setup_tracing();
    let n = 4;
    let t = 1;
    let l = 8;
    let k = 4;
    let session_id = SessionId::new(ProtocolType::None, 0, 0, 111);

    // Build fake network
    let (network, mut recv, _) = test_setup(n, vec![]);
    // Initialize nodes
    let mut nodes: Vec<PRandBitDNode<F>> =
        (0..n).map(|i| PRandBitDNode::new(i, n, t, l, k)).collect();

    // Manually set share_b_q for each node (simulate [b]_p)
    for node in &mut nodes {
        let binding = node.get_or_create_store(session_id).await;
        let mut store = binding.lock().await;
        store.share_b_q = Some(F::from(1u64)); // bit b=1
    }

    // Run distributed RISS generation
    for node in &mut nodes {
        node.generate_riss(session_id, network.clone())
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
                let msg: PRandBitDMessage = match bincode::deserialize(&received) {
                    Ok(w) => w,
                    Err(_) => continue,
                };

                let _ = node.process(msg, net.clone()).await;
            }
        });
    }

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Check outputs
    let mut x_vals = Vec::new();
    let mut y_vals = Vec::new();

    for node in &mut nodes {
        let binding = node.get_or_create_store(session_id).await;
        let store = binding.lock().await;
        assert!(
            store.share_b_2.is_some(),
            "Node {:?} missing share_b_2",
            node.id
        );
        println!("Node {} final [b]_2 share: {:?}", node.id, store.share_b_2);
        x_vals.push(F2_8::from(node.id as u16 + 1));
        y_vals.push(store.share_b_2.unwrap());
    }

    let poly = lagrange_interpolate_f2_8(&x_vals, &y_vals);
    let recovered_b: F2_8 = poly.evaluate(F2_8::zero());

    println!("Recovered b (GF(2^8)) = {:?}", recovered_b);

    // Expected b was 1 (set in share_b_q)
    assert_eq!(recovered_b, F2_8::from(1u16), "Recovered b != expected");
}

#[tokio::test]
async fn test_prandbitd_r_reconstruction() {
    setup_tracing();
    let n = 4;
    let t = 1;
    let l = 8;
    let k = 4;
    let session_id = SessionId::new(ProtocolType::None, 0, 0, 222);

    // Build fake network
    let (network, mut recv, _) = test_setup(n, vec![]);

    // Initialize nodes
    let mut nodes: Vec<PRandBitDNode<F>> =
        (0..n).map(|i| PRandBitDNode::new(i, n, t, l, k)).collect();

    // Manually set share_b_q (not used in this test, but required by protocol)
    for node in &mut nodes {
        let binding = node.get_or_create_store(session_id).await;
        let mut store = binding.lock().await;
        store.share_b_q = Some(F::from(1u64));
    }

    // Run distributed RISS generation
    for node in &mut nodes {
        node.generate_riss(session_id, network.clone())
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
                let msg: PRandBitDMessage = match bincode::deserialize(&received) {
                    Ok(w) => w,
                    Err(_) => continue,
                };
                let _ = node.process(msg, net.clone()).await;
            }
        });
    }

    // Wait for all messages to process
    tokio::time::sleep(Duration::from_millis(500)).await;

    // === Step 1: Collect all r_T values from all nodes ===
    let mut all_r_t: std::collections::HashMap<Vec<usize>, i64> = std::collections::HashMap::new();
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
                all_r_t.insert(tset.clone(), *val);
            }
        }
    }

    // === Step 2: Compute ground truth replicated secret ===
    let r_int: i64 = all_r_t.values().copied().sum();
    println!("Ground truth r (integer) = {}", r_int);

    // === Step 3: Reconstruct from all (t+1)-subsets of Shamir shares ===
    let needed = t + 1;
    let all_ids: Vec<usize> = (0..n).collect();

    for combo in all_ids.iter().copied().combinations(needed) {
        let mut x_vals = Vec::with_capacity(needed);
        let mut y_vals = Vec::with_capacity(needed);

        for &id in &combo {
            let binding = nodes[id].get_or_create_store(session_id).await;
            let store = binding.lock().await;
            let share = store.share_r_q.expect("missing share_r_q");

            x_vals.push(F::from((id + 1) as u64));
            y_vals.push(share);
        }

        let rec_r = reconstruct::<F>(&x_vals, &y_vals).unwrap();
        assert_eq!(
            rec_r,
            F::from(r_int),
            "Reconstructed r mismatch for combo {:?}",
            combo
        );
    }

    println!("All r_t values consistent and all Shamir reconstructions matched ground truth");
}

fn reconstruct<F: ark_ff::PrimeField>(
    x_vals: &[F],
    y_vals: &[F],
) -> Result<F, stoffelmpc_mpc::common::share::ShareError> {
    let poly = stoffelmpc_mpc::common::lagrange_interpolate(x_vals, y_vals)?;
    Ok(poly.evaluate(&F::zero()))
}
