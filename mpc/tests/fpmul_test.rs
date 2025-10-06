pub mod utils;
use crate::utils::test_utils::{setup_tracing, test_setup};
use ark_bls12_381::Fr as G;
use ark_bn254::Fr as F; // smaller prime field
use ark_poly::univariate::DensePolynomial;
use ark_poly::{DenseUVPolynomial, Polynomial};
use ark_std::test_rng;
use itertools::Itertools;
use std::{sync::Arc, time::Duration};
use stoffelmpc_mpc::common::lagrange_interpolate;
use stoffelmpc_mpc::honeybadger::fpmul::f256::{
    build_all_f_polys_2_8, lagrange_interpolate_f2_8, F2_8,
};
use stoffelmpc_mpc::honeybadger::fpmul::prandbitd::PRandBitDNode;
use stoffelmpc_mpc::honeybadger::fpmul::truncpr::TruncPrNode;
use stoffelmpc_mpc::honeybadger::fpmul::{PRandBitDMessage, TruncPrMessage};
use stoffelmpc_mpc::honeybadger::{ProtocolType, SessionId};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

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
    let mut nodes: Vec<PRandBitDNode<F, G>> =
        (0..n).map(|i| PRandBitDNode::new(i, n, t, l, k)).collect();

    // Manually set share_b_q for each node (simulate [b]_q)
    for node in &mut nodes {
        let binding = node.get_or_create_store(session_id).await;
        let mut store = binding.lock().await;
        store.share_b_q = Some(F::from(1u64)); //if all the shares are 1 then the secret is 1
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
    let mut x_vals_2 = Vec::new();
    let mut y_vals_2 = Vec::new();

    for node in &mut nodes {
        let binding = node.get_or_create_store(session_id).await;
        let store = binding.lock().await;
        assert!(
            store.share_b_2.is_some(),
            "Node {:?} missing share_b_2",
            node.id
        );
        x_vals_2.push(F2_8::from(node.id as u16 + 1));
        y_vals_2.push(store.share_b_2.unwrap());
    }

    let poly_2 = lagrange_interpolate_f2_8(&x_vals_2, &y_vals_2);
    let recovered_b_2 = poly_2.coeffs[0];
    println!("Recovered b (GF(2^8)) = {:?}", recovered_b_2);
    assert_eq!(recovered_b_2, F2_8::from(1u16), "Recovered b_2 != expected");

    // === Reconstruct [b]_p in G (bigger prime field) ===
    let mut x_vals_p = Vec::new();
    let mut y_vals_p = Vec::new();

    for node in &mut nodes {
        let binding = node.get_or_create_store(session_id).await;
        let store = binding.lock().await;

        assert!(
            store.share_b_p.is_some(),
            "Node {:?} missing share_b_p",
            node.id
        );
        x_vals_p.push(G::from((node.id + 1) as u64));
        y_vals_p.push(store.share_b_p.unwrap());
    }

    let poly_p = lagrange_interpolate(&x_vals_p, &y_vals_p).unwrap();
    let recovered_b_p = poly_p.coeffs[0];
    println!("Recovered b (prime field G) = {:?}", recovered_b_p);
    assert_eq!(recovered_b_p, G::from(1u64), "Recovered b_p != expected");
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
    let mut nodes: Vec<PRandBitDNode<F, G>> =
        (0..n).map(|i| PRandBitDNode::new(i, n, t, l, k)).collect();

    // Manually set share_b_q (not used in this test, but required by protocol)
    for node in &mut nodes {
        let binding = node.get_or_create_store(session_id).await;
        let mut store = binding.lock().await;
        store.share_b_q = Some(F::from(1u64)); //if all the shares are 1 then the secret is 1
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
    // === Step 4: Reconstruct r0 (GF(2^8)) ===
    let expected_r0 = F2_8::from((r_int & 1) as u8);

    let mut shares_r2 = Vec::new();
    for node in &mut nodes {
        let binding = node.get_or_create_store(session_id).await;
        let store = binding.lock().await;
        shares_r2.push((node.id, store.share_r_2.expect("missing share_r_2")));
    }

    for combo in all_ids.iter().copied().combinations(needed) {
        let mut xs = Vec::new();
        let mut ys = Vec::new();
        for &id in &combo {
            xs.push(F2_8::from((id + 1) as u16));
            let val = shares_r2.iter().find(|(i, _)| *i == id).unwrap().1;
            ys.push(val);
        }
        let poly = lagrange_interpolate_f2_8(&xs, &ys);
        let rec_r0 = poly.evaluate(F2_8::zero());
        assert_eq!(rec_r0, expected_r0, "Mismatch in r0 for combo {:?}", combo);
    }
    println!("Shamir reconstruction of r0 matched expected parity");

    // === Step 5: Per-node sanity: recompute share_r_2 from r_T values ===
    for node in &mut nodes {
        let binding = node.get_or_create_store(session_id).await;
        let store = binding.lock().await;
        let poly_f2 = build_all_f_polys_2_8(store.r_t.clone());
        let xi2 = F2_8::from((node.id + 1) as u16);
        let mut recomputed = F2_8::zero();
        for (tset, r_t) in store.r_t.iter() {
            let r2 = F2_8::from((r_t & 1) as u8);
            let coeff = poly_f2[tset].evaluate(xi2);
            recomputed = recomputed + (r2 * coeff);
        }
        let stored = store.share_r_2.expect("missing share_r_2");
        assert_eq!(recomputed, stored, "Node {}: share_r_2 mismatch", node.id);
    }
    println!("Per-node share_r_2 matches recomputation");
}

fn reconstruct<F: ark_ff::PrimeField>(
    x_vals: &[F],
    y_vals: &[F],
) -> Result<F, stoffelmpc_mpc::common::share::ShareError> {
    let poly = stoffelmpc_mpc::common::lagrange_interpolate(x_vals, y_vals)?;
    Ok(poly.evaluate(&F::zero()))
}

#[tokio::test]
async fn test_truncpr_end_to_end() {
    use ark_std::Zero;

    setup_tracing();
    let n = 4;
    let t = 1;
    let k = 16; // total bitlength (example)
    let m = 4; // fractional bits to truncate
    let session_id = SessionId::new(ProtocolType::None, 0, 0, 999);

    // === Build fake network ===
    let (network, mut recv, _) = test_setup(n, vec![]);

    // === Initialize nodes ===
    let (trunc_sender, _) = mpsc::channel(128);
    let mut nodes: Vec<TruncPrNode<F>> = (0..n)
        .map(|i| TruncPrNode::new(i, n, t, trunc_sender.clone()))
        .collect();

    // === Preload randomness (simulate PRandBitL + PRandInt) ===
    // Fake random bits [r_i]
    let r_bits: Vec<F> = (0..m).map(|i| F::from((i % 2) as u64)).collect();
    // Fake random integer [r'']
    let r_int = F::from(3 as u64);
    for node in &mut nodes {
        let store = node.get_or_create_store(session_id).await;
        let mut s = store.lock().await;
        s.r_bits = Some(r_bits.clone());
        s.r_int = Some(r_int);
    }

    // === Input secret [a] (same across parties for test) ===
    let mut rng = test_rng();
    let mut poly = DensePolynomial::rand(t, &mut rng);
    poly[0] = F::from(12345u64);
    let a_val: Vec<F> = (0..n)
        .map(|id| {
            let x = F::from(id as u64);
            poly.evaluate(&x)
        })
        .collect();

    // === Run init() for each node ===
    for node in &mut nodes {
        node.init(a_val[node.id], k, m, session_id, network.clone())
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
                let msg: TruncPrMessage = match bincode::deserialize(&received) {
                    Ok(w) => w,
                    Err(_) => continue,
                };
                let _ = node.process(msg, net.clone()).await;
            }
        });
    }

    tokio::time::sleep(Duration::from_millis(500)).await;

    // === Reconstruct [d] (the truncated output) ===
    let mut xs = Vec::new();
    let mut ys = Vec::new();

    for node in &mut nodes {
        let store = node.get_or_create_store(session_id).await;
        let s = store.lock().await;

        assert!(s.share_d.is_some(), "Node {:?} missing share_d", node.id);
        xs.push(F::from(node.id as u64));
        ys.push(s.share_d.unwrap());
    }

    let poly = lagrange_interpolate(&xs, &ys).unwrap();
    let d_reconstructed = poly.evaluate(&F::zero());

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
