//! Race Condition Tests for MPC Protocols
//!
//! These tests demonstrate race conditions where messages arrive before protocol
//! sessions are properly initialized, causing `MulError::WaitForOk` errors.
//!
//! ## Background
//!
//! The multiplication protocol uses a pattern where:
//! 1. Storage is created on-demand when messages arrive (`get_or_create_mult_storage`)
//! 2. But `no_of_mul` is only set by `init()`
//! 3. If messages arrive before `init()`, `open_mult_handler()` can't validate completion
//! 4. Data IS buffered in storage, but `WaitForOk` is returned
//!
//! This is different from STO-484 (premature cleanup) - this tests "late initialization"
//! where messages arrive before protocol sessions are created.

pub mod utils;

use crate::utils::test_utils::{construct_e2e_input_mul, setup_tracing, test_setup};
use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_std::test_rng;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{sync::Arc, time::Duration};
use stoffelmpc_mpc::common::rbc::rbc::Avid;
use stoffelmpc_mpc::common::{ProtocolSessionId, SecretSharingScheme, RBC};
use stoffelmpc_mpc::honeybadger::{
    mul::{multiplication::Multiply, MulError},
    robust_interpolate::robust_interpolate::RobustShare,
    ProtocolType, SessionId, WrappedMessage,
};
use tokio::task::JoinSet;
use tracing::{info, warn};

/// Test that demonstrates the WaitForOk race condition when messages arrive
/// before init() is called on slow nodes.
///
/// This test:
/// 1. Creates nodes but deliberately delays init() for one node
/// 2. Fast nodes call init() and send messages immediately
/// 3. The slow node receives messages BEFORE its init() is called
/// 4. This triggers WaitForOk errors because `no_of_mul` is None
///
/// Expected behavior: WaitForOk errors should be logged for the slow node
/// Actual behavior: The protocol should eventually complete if messages are retried
#[tokio::test]
async fn test_waitforok_late_initialization() {
    setup_tracing();

    let n_parties = 5;
    let t = 1;
    let no_of_mul = 4;
    let slow_node_id = 2;
    let init_delay_ms = 200; // How long to delay slow node's init()

    let mut rng = test_rng();
    let session_id = SessionId::new(ProtocolType::Mul, SessionId::pack_slot24(99, 0, 0), 42);

    // Track WaitForOk errors
    let waitforok_count = Arc::new(AtomicUsize::new(0));

    // 1. Setup network
    let (network, mut receivers, _) = test_setup(n_parties, vec![]);

    // 2. Generate Beaver triples
    let (_, beaver_triples) = construct_e2e_input_mul(n_parties, no_of_mul, t).await;

    // 3. Prepare inputs for multiplication
    let mut x_inputs_per_node = vec![Vec::new(); n_parties];
    let mut y_inputs_per_node = vec![Vec::new(); n_parties];

    for _i in 0..no_of_mul {
        let x_value = Fr::rand(&mut rng);
        let y_value = Fr::rand(&mut rng);

        let shares_x = RobustShare::compute_shares(x_value, n_parties, t, None, &mut rng).unwrap();
        let shares_y = RobustShare::compute_shares(y_value, n_parties, t, None, &mut rng).unwrap();

        for p in 0..n_parties {
            x_inputs_per_node[p].push(shares_x[p].clone());
            y_inputs_per_node[p].push(shares_y[p].clone());
        }
    }

    // 4. Create nodes
    let mut mul_nodes: Vec<_> = (0..n_parties)
        .map(|id| Multiply::<Fr, Avid<SessionId>>::new(id, n_parties, t).unwrap())
        .collect();

    // 5. Setup receive function for each node BEFORE init
    // This is key - messages will arrive and be processed before init() is called on slow node
    let mut set = JoinSet::new();
    for node in &mul_nodes {
        let mut mul_node = node.clone();
        let mut receiver = receivers.remove(0);
        let net_clone = Arc::clone(&network);
        let waitforok_counter = waitforok_count.clone();
        let is_slow_node = mul_node.id == slow_node_id;

        set.spawn(async move {
            while let Some(msg_bytes) = receiver.recv().await {
                let wrapped: WrappedMessage = match bincode::deserialize(&msg_bytes) {
                    Ok(m) => m,
                    Err(_) => {
                        warn!("failed to deserialize into wrapped message");
                        continue;
                    }
                };

                match &wrapped {
                    WrappedMessage::Mul(msg) => {
                        let result = mul_node.process(msg.clone()).await;

                        match result {
                            Ok(()) => {}
                            Err(MulError::WaitForOk) => {
                                if is_slow_node {
                                    // This is the race condition we're demonstrating!
                                    // Messages arrived before init() was called
                                    waitforok_counter.fetch_add(1, Ordering::SeqCst);
                                    info!(
                                        "Node {} got WaitForOk (message arrived before init!)",
                                        mul_node.id
                                    );
                                } else {
                                    info!("Node {} waiting (normal)", mul_node.id);
                                }
                            }
                            Err(MulError::ResultAlreadyReceived(_)) => {
                                info!("{} already received result", mul_node.id);
                            }
                            Err(e) => {
                                // Don't panic on errors for this test - we expect some
                                warn!("Node {} encountered error: {e}", mul_node.id);
                            }
                        }
                    }
                    WrappedMessage::Rbc(msg) => {
                        if let Err(e) = mul_node
                            .rbc
                            .process(msg.clone(), Arc::clone(&net_clone))
                            .await
                        {
                            warn!("RBC processing error: {e}");
                        }
                    }
                    WrappedMessage::BatchRecon(batch_msg) => {
                        match batch_msg.session_id.calling_protocol() {
                            Some(ProtocolType::Mul) => {
                                if let Err(e) = mul_node
                                    .batch_recon
                                    .process(batch_msg.clone(), Arc::clone(&net_clone))
                                    .await
                                {
                                    warn!("Batch recon error: {e}");
                                }
                            }
                            _ => {
                                warn!("Unexpected caller of batch recon");
                            }
                        }
                    }
                    _ => {
                        warn!("Unexpected protocol type");
                    }
                }
            }
        });
    }

    info!("Receiver tasks spawned BEFORE init - messages can now arrive");

    // 6. Init fast nodes immediately (all except slow node)
    for i in 0..n_parties {
        if i == slow_node_id {
            continue; // Skip slow node
        }

        match mul_nodes[i]
            .init(
                session_id,
                x_inputs_per_node[i].clone(),
                y_inputs_per_node[i].clone(),
                beaver_triples[i].clone(),
                Arc::clone(&network),
            )
            .await
        {
            Ok(()) => info!("Fast node {} initialized", i),
            Err(e) => warn!("Fast node {} init error: {:?}", i, e),
        }
    }

    info!(
        "Fast nodes initialized, waiting {}ms before slow node init...",
        init_delay_ms
    );

    // 7. Delay before initializing slow node - messages will arrive during this window
    tokio::time::sleep(Duration::from_millis(init_delay_ms)).await;

    // Check how many WaitForOk errors occurred during the delay
    let errors_during_delay = waitforok_count.load(Ordering::SeqCst);
    info!(
        "WaitForOk errors during delay (before slow node init): {}",
        errors_during_delay
    );

    // 8. Now init the slow node
    info!("Initializing slow node {}...", slow_node_id);
    match mul_nodes[slow_node_id]
        .init(
            session_id,
            x_inputs_per_node[slow_node_id].clone(),
            y_inputs_per_node[slow_node_id].clone(),
            beaver_triples[slow_node_id].clone(),
            Arc::clone(&network),
        )
        .await
    {
        Ok(()) => info!("Slow node {} initialized", slow_node_id),
        Err(e) => warn!("Slow node {} init error: {:?}", slow_node_id, e),
    }

    // 9. Give some time for messages to process after init
    tokio::time::sleep(Duration::from_millis(500)).await;

    let final_waitforok_count = waitforok_count.load(Ordering::SeqCst);
    info!(
        "Total WaitForOk errors for slow node: {}",
        final_waitforok_count
    );

    // NOTE: In the test environment with FakeNetwork, the race condition may not
    // manifest because message delivery is synchronous. In production with real
    // network latency, WaitForOk errors occur when messages arrive before init().
    //
    // This test demonstrates the setup that triggers the issue. The actual race
    // condition is more reliably observed in stoffel-analytics-node logs during
    // MPC preprocessing with real network conditions.
    if errors_during_delay > 0 || final_waitforok_count > 0 {
        info!(
            "Test demonstrated {} WaitForOk errors from late initialization",
            final_waitforok_count
        );
    } else {
        info!(
            "Race condition not triggered in this run (timing-dependent). \
             In production, WaitForOk errors occur when messages arrive before init()."
        );
    }

    // The test passes regardless - it documents the setup for the race condition
    info!("Test completed: Late initialization setup demonstrated");
}

/// Test that shows the normal case where init() is called before messages arrive.
/// This should NOT trigger WaitForOk errors for the slow node.
#[tokio::test]
async fn test_no_waitforok_when_init_first() {
    setup_tracing();

    let n_parties = 5;
    let t = 1;
    let no_of_mul = 4;

    let mut rng = test_rng();
    let session_id = SessionId::new(ProtocolType::Mul, SessionId::pack_slot24(88, 0, 0), 43);

    // 1. Setup network
    let (network, mut receivers, _) = test_setup(n_parties, vec![]);

    // 2. Generate Beaver triples
    let (_, beaver_triples) = construct_e2e_input_mul(n_parties, no_of_mul, t).await;

    // 3. Prepare inputs
    let mut x_inputs_per_node = vec![Vec::new(); n_parties];
    let mut y_inputs_per_node = vec![Vec::new(); n_parties];

    for _i in 0..no_of_mul {
        let x_value = Fr::rand(&mut rng);
        let y_value = Fr::rand(&mut rng);

        let shares_x = RobustShare::compute_shares(x_value, n_parties, t, None, &mut rng).unwrap();
        let shares_y = RobustShare::compute_shares(y_value, n_parties, t, None, &mut rng).unwrap();

        for p in 0..n_parties {
            x_inputs_per_node[p].push(shares_x[p].clone());
            y_inputs_per_node[p].push(shares_y[p].clone());
        }
    }

    // 4. Create nodes
    let mut mul_nodes: Vec<_> = (0..n_parties)
        .map(|id| Multiply::<Fr, Avid<SessionId>>::new(id, n_parties, t).unwrap())
        .collect();

    // 5. Init ALL nodes BEFORE setting up receivers (proper order)
    for i in 0..n_parties {
        match mul_nodes[i]
            .init(
                session_id,
                x_inputs_per_node[i].clone(),
                y_inputs_per_node[i].clone(),
                beaver_triples[i].clone(),
                Arc::clone(&network),
            )
            .await
        {
            Ok(()) => info!("Node {} initialized", i),
            Err(e) => panic!("Node {} init error: {:?}", i, e),
        }
    }
    info!("All nodes initialized BEFORE message processing");

    // 6. Setup receive function AFTER init
    let mut set = JoinSet::new();
    for node in &mul_nodes {
        let mut mul_node = node.clone();
        let mut receiver = receivers.remove(0);
        let net_clone = Arc::clone(&network);

        set.spawn(async move {
            while let Some(msg_bytes) = receiver.recv().await {
                let wrapped: WrappedMessage = match bincode::deserialize(&msg_bytes) {
                    Ok(m) => m,
                    Err(_) => continue,
                };

                match &wrapped {
                    WrappedMessage::Mul(msg) => {
                        let result = mul_node.process(msg.clone()).await;
                        match result {
                            Ok(()) => {}
                            Err(MulError::WaitForOk) => {
                                // This should be a normal "waiting for more messages" case
                                // NOT a "session not initialized" case
                                info!("Node {} waiting (normal batch completion)", mul_node.id);
                            }
                            Err(MulError::ResultAlreadyReceived(_)) => {}
                            Err(e) => panic!("Unexpected error: {e}"),
                        }
                    }
                    WrappedMessage::Rbc(msg) => {
                        let _ = mul_node.rbc.process(msg.clone(), Arc::clone(&net_clone)).await;
                    }
                    WrappedMessage::BatchRecon(batch_msg) => {
                        if let Some(ProtocolType::Mul) = batch_msg.session_id.calling_protocol() {
                            let _ = mul_node
                                .batch_recon
                                .process(batch_msg.clone(), Arc::clone(&net_clone))
                                .await;
                        }
                    }
                    _ => {}
                }
            }
        });
    }

    // 7. Wait and collect results
    let mut results_received = 0;
    for i in 0..n_parties {
        match mul_nodes[i]
            .wait_for_result(session_id, Duration::from_millis(1000))
            .await
        {
            Ok(shares) => {
                info!("Node {} got result with {} shares", i, shares.len());
                results_received += 1;
            }
            Err(e) => warn!("Node {} wait_for_result error: {:?}", i, e),
        }
    }

    assert_eq!(
        results_received, n_parties,
        "Expected all nodes to complete successfully when init() is called first"
    );
    info!("Test passed: All nodes completed when init() was called before message processing");
}
