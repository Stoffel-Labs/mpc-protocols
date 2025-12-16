//! Large-scale preprocessing stress test
//!
//! Run with: cargo test --release large_scale_preprocessing -- --nocapture --ignored
//!
//! This test generates large amounts of preprocessing material to identify bottlenecks.

mod utils;

use crate::utils::test_utils::setup_tracing;
use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_std::test_rng;
use futures::future::join_all;
use std::sync::Arc;
use std::time::Instant;
use stoffelmpc_mpc::{
    common::{
        rbc::rbc::Avid,
        share::shamir::NonRobustShare,
        SecretSharingScheme, RBC,
    },
    honeybadger::{
        ran_dou_sha::{
            batched_ran_dou_sha::BatchedRanDouShaNode, RanDouShaNode, RanDouShaState,
        },
        robust_interpolate::robust_interpolate::RobustShare,
        share_gen::{share_gen::RanShaNode, batched_share_gen::BatchedRanShaNode, RanShaState},
        ProtocolType, SessionId, WrappedMessage,
    },
};
use stoffelmpc_network::fake_network::{FakeNetwork, FakeNetworkConfig};
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

/// Generate test inputs for RanDouSha protocol
fn generate_randousha_inputs(
    n_parties: usize,
    degree_t: usize,
    n_secrets: usize,
) -> (Vec<Vec<NonRobustShare<Fr>>>, Vec<Vec<NonRobustShare<Fr>>>) {
    let mut rng = test_rng();
    let mut n_shares_t = vec![vec![]; n_parties];
    let mut n_shares_2t = vec![vec![]; n_parties];

    for _ in 0..n_secrets {
        let secret = Fr::rand(&mut rng);
        let shares_t = NonRobustShare::compute_shares(secret, n_parties, degree_t, None, &mut rng).unwrap();
        let shares_2t = NonRobustShare::compute_shares(secret, n_parties, degree_t * 2, None, &mut rng).unwrap();

        for p in 0..n_parties {
            n_shares_t[p].push(shares_t[p].clone());
            n_shares_2t[p].push(shares_2t[p].clone());
        }
    }

    (n_shares_t, n_shares_2t)
}

/// Setup network with larger buffer for stress testing
fn setup_large_network(n_parties: usize) -> (Arc<FakeNetwork>, Vec<mpsc::Receiver<Vec<u8>>>) {
    let config = FakeNetworkConfig::new(10000); // Larger buffer
    let (network, receivers, _) = FakeNetwork::new(n_parties, None, config);
    (Arc::new(network), receivers)
}

#[tokio::test]
#[ignore]
async fn large_scale_randousha_stress_test() {
    setup_tracing();

    let n_parties = 5;
    let t = 1;
    // RanDouSha produces (n - 2t) double-shares per run
    // To get 20000 double-shares, we need 20000 / (n - 2t) runs
    // For n=5, t=1: n - 2t = 3, so we need ~6667 runs
    let n_runs = 100; // Start with fewer runs to test

    println!("\n================================================================");
    println!("RANDOUSHA STRESS TEST");
    println!("Parties: {}, Threshold: {}, Runs: {}", n_parties, t, n_runs);
    println!("Expected output per run: {} double-shares", n_parties - 2 * t);
    println!("================================================================\n");

    // Setup
    let (network, receivers) = setup_large_network(n_parties);

    // For RanDouSha, each party contributes n_parties secrets per run
    // We'll run the protocol n_runs times
    println!("Generating test inputs for {} runs...", n_runs);
    let gen_start = Instant::now();
    // Generate inputs for first run only - each party needs n_parties secrets
    let (n_shares_t, n_shares_2t) = generate_randousha_inputs(n_parties, t, n_parties);
    println!("Input generation took: {:?}", gen_start.elapsed());

    // Create RanDouSha nodes
    let mut output_receivers = Vec::new();
    let mut nodes = Vec::new();

    for i in 0..n_parties {
        let (tx, rx) = mpsc::channel(n_runs * 10);
        output_receivers.push(rx);
        // RanDouShaNode::new(id, output_sender, n_parties, threshold, k)
        let node = RanDouShaNode::<Fr, Avid>::new(i, tx, n_parties, t, t + 1).unwrap();
        nodes.push(Arc::new(tokio::sync::Mutex::new(node)));
    }

    let session_id = SessionId::new(ProtocolType::Randousha, 0, 0, 0, 0);

    // Spawn receiver tasks
    for (i, mut receiver) in receivers.into_iter().enumerate() {
        let node = nodes[i].clone();
        let net = network.clone();

        tokio::spawn(async move {
            while let Some(msg) = receiver.recv().await {
                let wrapped: WrappedMessage = match bincode::deserialize(&msg) {
                    Ok(w) => w,
                    Err(_) => continue,
                };

                match wrapped {
                    WrappedMessage::RanDouSha(rds_msg) => {
                        let node = node.lock().await;
                        let _ = node.process(rds_msg, net.clone()).await;
                    }
                    WrappedMessage::Rbc(rbc_msg) => {
                        let node = node.lock().await;
                        let _ = node.rbc.process(rbc_msg, net.clone()).await;
                    }
                    _ => {}
                }
            }
        });
    }

    // Initialize all nodes
    println!("Initializing {} RanDouSha nodes...", n_parties);
    let init_start = Instant::now();

    for i in 0..n_parties {
        let node = nodes[i].lock().await;
        node.init(
            n_shares_t[i].clone(),
            n_shares_2t[i].clone(),
            session_id,
            network.clone(),
        )
        .await
        .unwrap();
    }
    println!("Initialization took: {:?}", init_start.elapsed());

    // Wait for completion
    println!("Waiting for protocol completion...");
    let protocol_start = Instant::now();

    let result = timeout(
        Duration::from_secs(60),
        join_all(nodes.iter().map(|node| {
            let node = node.clone();
            async move {
                loop {
                    let node = node.lock().await;
                    let store = node.get_or_create_store(session_id).await;
                    let store = store.lock().await;
                    if store.state == RanDouShaState::Finished {
                        return store.protocol_output.len();
                    }
                    drop(store);
                    drop(node);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        })),
    )
    .await;

    let protocol_time = protocol_start.elapsed();

    match result {
        Ok(outputs) => {
            println!("\n=== Results ===");
            println!("Protocol completed in: {:?}", protocol_time);
            println!("Output shares per party: {:?}", outputs);
            let total_outputs: usize = outputs.iter().sum();
            println!("Total output double-shares: {}", total_outputs);
            println!(
                "Throughput: {:.0} double-shares/sec",
                total_outputs as f64 / protocol_time.as_secs_f64()
            );
        }
        Err(_) => {
            println!("ERROR: Protocol timed out after 60 seconds");

            // Debug: check state of each node
            for (i, node) in nodes.iter().enumerate() {
                let node = node.lock().await;
                let store = node.get_or_create_store(session_id).await;
                let store = store.lock().await;
                println!(
                    "Node {}: state={:?}, computed_t={}, computed_2t={}, received_ok={}",
                    i,
                    store.state,
                    store.computed_r_shares_degree_t.len(),
                    store.computed_r_shares_degree_2t.len(),
                    store.received_ok_msg.len()
                );
            }
        }
    }
}

#[tokio::test]
#[ignore]
async fn large_scale_ransha_stress_test() {
    setup_tracing();

    let n_parties = 5;
    let t = 1;

    println!("\n================================================================");
    println!("RANSHA STRESS TEST");
    println!("Parties: {}, Threshold: {}", n_parties, t);
    println!("================================================================\n");

    // Setup
    let (network, receivers) = setup_large_network(n_parties);

    // Create RanSha nodes
    let mut output_receivers = Vec::new();
    let mut nodes = Vec::new();

    for i in 0..n_parties {
        let (tx, rx) = mpsc::channel(1000);
        output_receivers.push(rx);
        // RanShaNode::new(id, n_parties, threshold, k, output_sender)
        let node = RanShaNode::<Fr, Avid>::new(i, n_parties, t, t + 1, tx).unwrap();
        nodes.push(Arc::new(tokio::sync::Mutex::new(node)));
    }

    let session_id = SessionId::new(ProtocolType::Ransha, 0, 0, 0, 0);

    // Spawn receiver tasks
    for (i, mut receiver) in receivers.into_iter().enumerate() {
        let node = nodes[i].clone();
        let net = network.clone();

        tokio::spawn(async move {
            while let Some(msg) = receiver.recv().await {
                let wrapped: WrappedMessage = match bincode::deserialize(&msg) {
                    Ok(w) => w,
                    Err(_) => continue,
                };

                match wrapped {
                    WrappedMessage::RanSha(rs_msg) => {
                        let node = node.lock().await;
                        let _ = node.process(rs_msg, net.clone()).await;
                    }
                    WrappedMessage::Rbc(rbc_msg) => {
                        let node = node.lock().await;
                        let _ = node.rbc.process(rbc_msg, net.clone()).await;
                    }
                    _ => {}
                }
            }
        });
    }

    // Initialize all nodes
    println!("Initializing {} RanSha nodes...", n_parties);
    let init_start = Instant::now();

    let mut rng = test_rng();
    for i in 0..n_parties {
        let node = nodes[i].lock().await;
        node.init(session_id, &mut rng, network.clone()).await.unwrap();
    }
    println!("Initialization took: {:?}", init_start.elapsed());

    // Wait for completion
    println!("Waiting for protocol completion...");
    let protocol_start = Instant::now();

    let result = timeout(
        Duration::from_secs(30),
        join_all(nodes.iter().map(|node| {
            let node = node.clone();
            async move {
                loop {
                    let node = node.lock().await;
                    let store = node.get_or_create_store(session_id).await;
                    let store = store.lock().await;
                    if store.state == RanShaState::Finished {
                        return store.protocol_output.len();
                    }
                    drop(store);
                    drop(node);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        })),
    )
    .await;

    let protocol_time = protocol_start.elapsed();

    match result {
        Ok(outputs) => {
            println!("\n=== Results ===");
            println!("Protocol completed in: {:?}", protocol_time);
            println!("Output shares per party: {:?}", outputs);
            let expected_per_run = n_parties - 2 * t; // n - 2t shares per run
            println!("Expected per run: {}", expected_per_run);
        }
        Err(_) => {
            println!("ERROR: Protocol timed out after 30 seconds");
        }
    }
}

#[tokio::test]
#[ignore]
async fn large_scale_batched_ransha_stress_test() {
    setup_tracing();

    let n_parties = 5;
    let t = 1;
    // K = batch size - how many secrets each party generates per run
    // Output per run = K * (n - 2t)
    // For K=1000, n=5, t=1: output = 1000 * 3 = 3000 shares per run
    // To get 20,000 shares: batch_size * (n - 2t) = 20000
    // For n=5, t=1: batch_size * 3 = 20000 → batch_size = 6667
    let batch_size = 6667;
    let expected_output = batch_size * (n_parties - 2 * t);

    println!("\n================================================================");
    println!("BATCHED RANSHA STRESS TEST");
    println!("Parties: {}, Threshold: {}, Batch size: {}", n_parties, t, batch_size);
    println!("Expected output per run: {} random shares", expected_output);
    println!("================================================================\n");

    // Setup with larger buffer for batched messages
    let config = FakeNetworkConfig::new(50000);
    let (network, receivers, _) = FakeNetwork::new(n_parties, None, config);
    let network = Arc::new(network);

    // Create BatchedRanSha nodes
    let mut output_receivers = Vec::new();
    let mut nodes = Vec::new();

    for i in 0..n_parties {
        let (tx, rx) = mpsc::channel(100);
        output_receivers.push(rx);
        let node = BatchedRanShaNode::<Fr, Avid>::new(i, n_parties, t, t + 1, tx).unwrap();
        nodes.push(Arc::new(tokio::sync::Mutex::new(node)));
    }

    let session_id = SessionId::new(ProtocolType::BatchedRansha, 0, 0, 0, 0);

    // Spawn receiver tasks
    for (i, mut receiver) in receivers.into_iter().enumerate() {
        let node = nodes[i].clone();
        let net = network.clone();

        tokio::spawn(async move {
            while let Some(msg) = receiver.recv().await {
                let wrapped: WrappedMessage = match bincode::deserialize(&msg) {
                    Ok(w) => w,
                    Err(_) => continue,
                };

                match wrapped {
                    WrappedMessage::RanSha(rs_msg) => {
                        let node = node.lock().await;
                        let _ = node.process(rs_msg, net.clone()).await;
                    }
                    WrappedMessage::Rbc(rbc_msg) => {
                        let node = node.lock().await;
                        let _ = node.rbc.process(rbc_msg, net.clone()).await;
                    }
                    _ => {}
                }
            }
        });
    }

    // Initialize all nodes with batched generation
    println!("Initializing {} BatchedRanSha nodes with batch_size={}...", n_parties, batch_size);
    let init_start = Instant::now();

    let mut rng = test_rng();
    for i in 0..n_parties {
        let node = nodes[i].lock().await;
        node.init(session_id, batch_size, &mut rng, network.clone()).await.unwrap();
    }
    println!("Initialization took: {:?}", init_start.elapsed());

    // Wait for completion
    println!("Waiting for protocol completion...");
    let protocol_start = Instant::now();

    let result = timeout(
        Duration::from_secs(120), // Longer timeout for batched
        join_all(nodes.iter().map(|node| {
            let node = node.clone();
            async move {
                loop {
                    let node = node.lock().await;
                    let store = node.get_or_create_store(session_id, batch_size).await;
                    let store = store.lock().await;
                    if store.state == RanShaState::Finished {
                        return store.protocol_output.len();
                    }
                    drop(store);
                    drop(node);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        })),
    )
    .await;

    let protocol_time = protocol_start.elapsed();

    match result {
        Ok(outputs) => {
            println!("\n=== Results ===");
            println!("Protocol completed in: {:?}", protocol_time);
            println!("Output shares per party: {:?}", outputs);
            let total_outputs: usize = outputs.iter().sum();
            println!("Total output random shares: {}", total_outputs);
            println!(
                "Throughput: {:.0} random-shares/sec",
                total_outputs as f64 / protocol_time.as_secs_f64()
            );

            // Compare with non-batched
            // Non-batched: ~190 shares/sec (from earlier test)
            // Expected improvement: batch_size / 1 = 1000x fewer protocol runs
            let non_batched_estimate = 190.0;
            let actual_throughput = total_outputs as f64 / protocol_time.as_secs_f64();
            println!(
                "\nSpeedup vs non-batched (~190/s): {:.1}x",
                actual_throughput / non_batched_estimate
            );
        }
        Err(_) => {
            println!("ERROR: Protocol timed out after 120 seconds");

            // Debug: check state of each node
            for (i, node) in nodes.iter().enumerate() {
                let node = node.lock().await;
                let store = node.get_or_create_store(session_id, batch_size).await;
                let store = store.lock().await;
                println!(
                    "Node {}: state={:?}, computed={}, received_ok={}",
                    i,
                    store.state,
                    store.computed_r_shares.len(),
                    store.received_ok_msg.len()
                );
            }
        }
    }
}

#[tokio::test]
#[ignore]
async fn benchmark_local_preprocessing_operations() {
    println!("\n================================================================");
    println!("LOCAL PREPROCESSING OPERATIONS BENCHMARK");
    println!("================================================================\n");

    let mut rng = test_rng();
    let n_parties = 5;
    let t = 1;
    let count = 20000;

    // Benchmark share generation
    println!("=== Share Generation ({} shares) ===", count);
    let start = Instant::now();
    let shares: Vec<Vec<RobustShare<Fr>>> = (0..count)
        .map(|_| {
            let secret = Fr::rand(&mut rng);
            RobustShare::compute_shares(secret, n_parties, t, None, &mut rng).unwrap()
        })
        .collect();
    let gen_time = start.elapsed();
    println!("Time: {:?}", gen_time);
    println!("Throughput: {:.0} shares/sec", count as f64 / gen_time.as_secs_f64());

    // Benchmark double share generation (for RanDouSha)
    println!("\n=== Double Share Generation ({} pairs) ===", count);
    let start = Instant::now();
    let _double_shares: Vec<(Vec<NonRobustShare<Fr>>, Vec<NonRobustShare<Fr>>)> = (0..count)
        .map(|_| {
            let secret = Fr::rand(&mut rng);
            let shares_t = NonRobustShare::compute_shares(secret, n_parties, t, None, &mut rng).unwrap();
            let shares_2t = NonRobustShare::compute_shares(secret, n_parties, 2 * t, None, &mut rng).unwrap();
            (shares_t, shares_2t)
        })
        .collect();
    let double_gen_time = start.elapsed();
    println!("Time: {:?}", double_gen_time);
    println!("Throughput: {:.0} pairs/sec", count as f64 / double_gen_time.as_secs_f64());

    // Benchmark recovery (using IFFT for power-of-2)
    println!("\n=== Secret Recovery ({} recoveries, n={}) ===", count, n_parties);
    let start = Instant::now();
    for share_set in &shares {
        let _ = RobustShare::recover_secret(share_set, n_parties).unwrap();
    }
    let recover_time = start.elapsed();
    println!("Time: {:?}", recover_time);
    println!("Throughput: {:.0} recoveries/sec", count as f64 / recover_time.as_secs_f64());

    // Benchmark with power-of-2 parties (should use IFFT)
    let n_parties_pow2 = 8;
    let t_pow2 = 2;
    println!("\n=== Secret Recovery with IFFT ({} recoveries, n={}) ===", count, n_parties_pow2);
    let shares_pow2: Vec<Vec<NonRobustShare<Fr>>> = (0..count)
        .map(|_| {
            let secret = Fr::rand(&mut rng);
            NonRobustShare::compute_shares(secret, n_parties_pow2, t_pow2, None, &mut rng).unwrap()
        })
        .collect();

    let start = Instant::now();
    for share_set in &shares_pow2 {
        let _ = NonRobustShare::recover_secret(share_set, n_parties_pow2).unwrap();
    }
    let recover_ifft_time = start.elapsed();
    println!("Time: {:?}", recover_ifft_time);
    println!("Throughput: {:.0} recoveries/sec", count as f64 / recover_ifft_time.as_secs_f64());
    println!("Speedup vs non-power-of-2: {:.1}x", recover_time.as_secs_f64() / recover_ifft_time.as_secs_f64());

    // Summary
    println!("\n=== Summary for {} items ===", count);
    println!("Share generation:     {:>8.1} ms ({:.0}/s)", gen_time.as_secs_f64() * 1000.0, count as f64 / gen_time.as_secs_f64());
    println!("Double share gen:     {:>8.1} ms ({:.0}/s)", double_gen_time.as_secs_f64() * 1000.0, count as f64 / double_gen_time.as_secs_f64());
    println!("Recovery (n=5):       {:>8.1} ms ({:.0}/s)", recover_time.as_secs_f64() * 1000.0, count as f64 / recover_time.as_secs_f64());
    println!("Recovery (n=8 IFFT):  {:>8.1} ms ({:.0}/s)", recover_ifft_time.as_secs_f64() * 1000.0, count as f64 / recover_ifft_time.as_secs_f64());
}

#[tokio::test]
#[ignore]
async fn large_scale_batched_randousha_stress_test() {
    setup_tracing();

    let n_parties = 5;
    let t = 1;
    // K = batch size - how many secrets each party generates per run
    // Output per run = K * (t + 1)
    // For K=10000, n=5, t=1: output = 10000 * 2 = 20000 double shares per run
    let batch_size = 10000;
    let expected_output_per_party = batch_size * (t + 1);

    println!("\n================================================================");
    println!("BATCHED RANDOUSHA STRESS TEST");
    println!("Parties: {}, Threshold: {}, Batch size: {}", n_parties, t, batch_size);
    println!("Expected output per party per run: {} double shares", expected_output_per_party);
    println!("================================================================\n");

    // Setup with larger buffer for batched messages
    let config = FakeNetworkConfig::new(100000);
    let (network, receivers, _) = FakeNetwork::new(n_parties, None, config);
    let network = Arc::new(network);

    // Create BatchedRanDouSha nodes
    let mut output_receivers = Vec::new();
    let mut nodes = Vec::new();

    for i in 0..n_parties {
        let (tx, rx) = mpsc::channel(100);
        output_receivers.push(rx);
        // BatchedRanDouShaNode::new(id, output_sender, n_parties, threshold, k)
        let node = BatchedRanDouShaNode::<Fr, Avid>::new(i, tx, n_parties, t, t + 1).unwrap();
        nodes.push(Arc::new(tokio::sync::Mutex::new(node)));
    }

    let session_id = SessionId::new(ProtocolType::BatchedRandousha, 0, 0, 0, 0);

    // Spawn receiver tasks
    for (i, mut receiver) in receivers.into_iter().enumerate() {
        let node = nodes[i].clone();
        let net = network.clone();

        tokio::spawn(async move {
            while let Some(msg) = receiver.recv().await {
                let wrapped: WrappedMessage = match bincode::deserialize(&msg) {
                    Ok(w) => w,
                    Err(_) => continue,
                };

                match wrapped {
                    WrappedMessage::RanDouSha(rds_msg) => {
                        let node = node.lock().await;
                        let _ = node.process(rds_msg, net.clone()).await;
                    }
                    WrappedMessage::Rbc(rbc_msg) => {
                        let node = node.lock().await;
                        let _ = node.rbc.process(rbc_msg, net.clone()).await;
                    }
                    _ => {}
                }
            }
        });
    }

    // Initialize all nodes with batched generation
    println!(
        "Initializing {} BatchedRanDouSha nodes with batch_size={}...",
        n_parties, batch_size
    );
    let init_start = Instant::now();

    let mut rng = test_rng();
    for i in 0..n_parties {
        let node = nodes[i].lock().await;
        node.init(session_id, batch_size, &mut rng, network.clone())
            .await
            .unwrap();
    }
    println!("Initialization took: {:?}", init_start.elapsed());

    // Wait for completion
    println!("Waiting for protocol completion...");
    let protocol_start = Instant::now();

    let result = timeout(
        Duration::from_secs(180), // Longer timeout for batched
        join_all(nodes.iter().map(|node| {
            let node = node.clone();
            async move {
                loop {
                    let node = node.lock().await;
                    let store = node.get_or_create_store(session_id, batch_size).await;
                    let store = store.lock().await;
                    if store.state == RanDouShaState::Finished {
                        return store.protocol_output.len();
                    }
                    drop(store);
                    drop(node);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        })),
    )
    .await;

    let protocol_time = protocol_start.elapsed();

    match result {
        Ok(outputs) => {
            println!("\n=== Results ===");
            println!("Protocol completed in: {:?}", protocol_time);
            println!("Output double shares per party: {:?}", outputs);
            let total_outputs: usize = outputs.iter().sum();
            println!("Total output double shares: {}", total_outputs);
            println!(
                "Throughput: {:.0} double-shares/sec",
                total_outputs as f64 / protocol_time.as_secs_f64()
            );

            // Compare with non-batched (RanDouSha ~190 double-shares/sec)
            let non_batched_estimate = 190.0;
            let actual_throughput = total_outputs as f64 / protocol_time.as_secs_f64();
            println!(
                "\nSpeedup vs non-batched (~190/s): {:.1}x",
                actual_throughput / non_batched_estimate
            );
        }
        Err(_) => {
            println!("ERROR: Protocol timed out after 180 seconds");

            // Debug: check state of each node
            for (i, node) in nodes.iter().enumerate() {
                let node = node.lock().await;
                let store = node.get_or_create_store(session_id, batch_size).await;
                let store = store.lock().await;
                println!(
                    "Node {}: state={:?}, computed_t={}, computed_2t={}, received_ok={}",
                    i,
                    store.state,
                    store.computed_r_shares_degree_t.len(),
                    store.computed_r_shares_degree_2t.len(),
                    store.received_ok_msg.len()
                );
            }
        }
    }
}
