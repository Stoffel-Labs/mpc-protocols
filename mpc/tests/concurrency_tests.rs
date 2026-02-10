//! Concurrency tests for preprocessing material access.
//!
//! These tests verify that the atomic check-and-take patterns in
//! HoneyBadgerMPCNode prevent TOCTOU race conditions when multiple
//! tasks concurrently access preprocessing material.

use ark_bls12_381::Fr;
use std::sync::Arc;
use stoffelmpc_mpc::honeybadger::preprocessing::HoneyBadgerMPCNodePreprocMaterial;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::triple_gen::ShamirBeaverTriple;
use tokio::sync::Mutex;

/// Helper to create test preprocessing material with specified counts
fn create_test_material(
    n_triples: usize,
    n_random_shares: usize,
) -> HoneyBadgerMPCNodePreprocMaterial<Fr> {
    let mut material = HoneyBadgerMPCNodePreprocMaterial::<Fr>::empty();

    // Add beaver triples
    let triples: Vec<ShamirBeaverTriple<Fr>> = (0..n_triples)
        .map(|i| {
            let share = RobustShare::new(Fr::from(i as u64), i, 1);
            ShamirBeaverTriple {
                a: share.clone(),
                b: share.clone(),
                mult: share,
            }
        })
        .collect();

    // Add random shares
    let random_shares: Vec<RobustShare<Fr>> = (0..n_random_shares)
        .map(|i| RobustShare::new(Fr::from(i as u64), i, 1))
        .collect();

    material.add(Some(triples), Some(random_shares), None, None);
    material
}

/// Test that concurrent take_beaver_triples operations don't cause
/// over-consumption (each triple is taken exactly once).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_take_beaver_triples_no_overflow() {
    const TOTAL_TRIPLES: usize = 100;
    const N_TASKS: usize = 10;
    const TRIPLES_PER_TASK: usize = 10;

    let material = Arc::new(Mutex::new(create_test_material(TOTAL_TRIPLES, 0)));

    let mut handles = Vec::new();

    for task_id in 0..N_TASKS {
        let material = Arc::clone(&material);
        handles.push(tokio::spawn(async move {
            let mut store = material.lock().await;
            match store.take_beaver_triples(TRIPLES_PER_TASK) {
                Ok(triples) => {
                    assert_eq!(
                        triples.len(),
                        TRIPLES_PER_TASK,
                        "Task {} got wrong number of triples",
                        task_id
                    );
                    Ok(triples.len())
                }
                Err(_) => Err(()),
            }
        }));
    }

    let mut total_taken = 0;
    let mut errors = 0;

    for handle in handles {
        match handle.await.unwrap() {
            Ok(count) => total_taken += count,
            Err(_) => errors += 1,
        }
    }

    // All tasks should have succeeded and taken exactly TOTAL_TRIPLES in total
    assert_eq!(errors, 0, "No task should fail with exact allocation");
    assert_eq!(
        total_taken, TOTAL_TRIPLES,
        "Total taken should equal total available"
    );

    // Verify store is now empty
    let store = material.lock().await;
    let (remaining, _, _, _) = store.len();
    assert_eq!(remaining, 0, "All triples should be consumed");
}

/// Test that concurrent tasks properly fail when there's not enough material,
/// rather than causing undefined behavior or panics.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_take_insufficient_material() {
    const TOTAL_TRIPLES: usize = 50;
    const N_TASKS: usize = 10;
    const TRIPLES_PER_TASK: usize = 10; // 10 tasks * 10 = 100, but only 50 available

    let material = Arc::new(Mutex::new(create_test_material(TOTAL_TRIPLES, 0)));

    let mut handles = Vec::new();

    for _ in 0..N_TASKS {
        let material = Arc::clone(&material);
        handles.push(tokio::spawn(async move {
            let mut store = material.lock().await;
            store.take_beaver_triples(TRIPLES_PER_TASK).is_ok()
        }));
    }

    let mut successes = 0;
    let mut failures = 0;

    for handle in handles {
        if handle.await.unwrap() {
            successes += 1;
        } else {
            failures += 1;
        }
    }

    // Exactly 5 tasks should succeed (50 / 10 = 5)
    assert_eq!(successes, 5, "5 tasks should succeed");
    assert_eq!(failures, 5, "5 tasks should fail");

    // Verify store is now empty
    let store = material.lock().await;
    let (remaining, _, _, _) = store.len();
    assert_eq!(remaining, 0, "All triples should be consumed by successful tasks");
}

/// Test that concurrent take_random_shares operations work correctly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_take_random_shares_no_double_take() {
    const TOTAL_SHARES: usize = 100;
    const N_TASKS: usize = 20;
    const SHARES_PER_TASK: usize = 5;

    let material = Arc::new(Mutex::new(create_test_material(0, TOTAL_SHARES)));

    let mut handles = Vec::new();

    for _ in 0..N_TASKS {
        let material = Arc::clone(&material);
        handles.push(tokio::spawn(async move {
            let mut store = material.lock().await;
            store.take_random_shares(SHARES_PER_TASK).is_ok()
        }));
    }

    let mut successes = 0;

    for handle in handles {
        if handle.await.unwrap() {
            successes += 1;
        }
    }

    // All 20 tasks should succeed (100 / 5 = 20)
    assert_eq!(successes, N_TASKS, "All tasks should succeed");

    // Verify store is now empty
    let store = material.lock().await;
    let (_, remaining, _, _) = store.len();
    assert_eq!(remaining, 0, "All shares should be consumed");
}

/// Test interleaved add and take operations.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_add_and_take_material() {
    let material = Arc::new(Mutex::new(create_test_material(0, 0)));
    let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    // Producer tasks
    let mut producer_handles = Vec::new();
    for i in 0..5 {
        let material = Arc::clone(&material);
        producer_handles.push(tokio::spawn(async move {
            let share = RobustShare::new(Fr::from(i as u64), i, 1);
            let triple = ShamirBeaverTriple {
                a: share.clone(),
                b: share.clone(),
                mult: share,
            };

            let mut store = material.lock().await;
            store.add(Some(vec![triple; 10]), None, None, None);
        }));
    }

    // Wait for producers to finish
    for handle in producer_handles {
        handle.await.unwrap();
    }

    // Consumer tasks
    let mut consumer_handles = Vec::new();
    for _ in 0..10 {
        let material = Arc::clone(&material);
        let counter = Arc::clone(&counter);
        consumer_handles.push(tokio::spawn(async move {
            let mut store = material.lock().await;
            if let Ok(triples) = store.take_beaver_triples(5) {
                counter.fetch_add(triples.len(), std::sync::atomic::Ordering::SeqCst);
            }
        }));
    }

    for handle in consumer_handles {
        handle.await.unwrap();
    }

    // Total added: 5 producers * 10 = 50
    // Consumers tried to take: 10 * 5 = 50
    let taken = counter.load(std::sync::atomic::Ordering::SeqCst);
    let store = material.lock().await;
    let (remaining, _, _, _) = store.len();

    assert_eq!(
        taken + remaining, 50,
        "Total taken + remaining should equal total added"
    );
}

/// Stress test with many concurrent operations.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_stress_concurrent_preprocessing_access() {
    const ITERATIONS: usize = 100;
    const N_TASKS: usize = 20;

    for iteration in 0..ITERATIONS {
        let material = Arc::new(Mutex::new(create_test_material(N_TASKS, N_TASKS)));

        let mut handles = Vec::new();

        for _ in 0..N_TASKS {
            let material = Arc::clone(&material);
            handles.push(tokio::spawn(async move {
                let mut store = material.lock().await;
                let triple_ok = store.take_beaver_triples(1).is_ok();
                let share_ok = store.take_random_shares(1).is_ok();
                (triple_ok, share_ok)
            }));
        }

        let mut triple_successes = 0;
        let mut share_successes = 0;

        for handle in handles {
            let (t, s) = handle.await.unwrap();
            if t {
                triple_successes += 1;
            }
            if s {
                share_successes += 1;
            }
        }

        assert_eq!(
            triple_successes, N_TASKS,
            "Iteration {}: All triple takes should succeed",
            iteration
        );
        assert_eq!(
            share_successes, N_TASKS,
            "Iteration {}: All share takes should succeed",
            iteration
        );
    }
}
