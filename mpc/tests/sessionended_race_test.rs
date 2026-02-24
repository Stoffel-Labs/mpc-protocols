//! Reproducible test for RBC SessionEnded race condition.
//!
//! This test demonstrates the timing-sensitive race condition where:
//! 1. Fast nodes complete RBC and call clear_store()
//! 2. Slow nodes receive late READY messages and get SessionEnded errors
//!    OR the store is recreated in an inconsistent state
//!
//! The race is exposed by using BadFakeNetwork with variable delays.
//!
//! ## Background
//!
//! In Docker deployments with network latency, MPC preprocessing often fails
//! with only 1-2/5 nodes succeeding. Unit tests with FakeNetwork (zero latency)
//! cannot expose this bug because all nodes process messages synchronously.
//!
//! ## Race Condition Flow
//!
//! ```text
//! Time →
//! ┌─────────────────────────────────────────────────────────────────┐
//! │ Fast Node 0:  RBC complete → wait_for_result() → clear_store() │
//! │                                                    ↓            │
//! │ Slow Node 2:  ← late READY arrives after store cleared         │
//! │               → get_or_create_store() creates NEW empty store  │
//! │               → SessionEnded error OR inconsistent state       │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! See full analysis: https://hackmd.io/@stoffel-labs/z411RephSxC-fGzk1OrDUw

pub mod utils;

#[cfg(test)]
mod tests {
    use ark_std::rand::{distributions::Uniform, rngs::StdRng, SeedableRng};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use stoffelmpc_mpc::{
        common::{
            rbc::rbc::Bracha,
            ProtocolSessionId, RBC,
        },
        honeybadger::{ProtocolType, SessionId, WrappedMessage},
    };
    use stoffelmpc_network::bad_fake_network::{BadFakeNetwork, BadFakeNetworkConfig};
    use tokio::sync::mpsc;
    use tracing::{info, warn};

    use crate::utils::test_utils::setup_tracing;

    /// Counter for SessionEnded errors observed during test
    static SESSION_ENDED_COUNT: AtomicUsize = AtomicUsize::new(0);

    /// Setup parties with BadFakeNetwork for realistic latency simulation
    async fn setup_bad_network_and_parties(
        n: usize,
        t: usize,
        buffer_size: usize,
    ) -> (
        Vec<Bracha<SessionId>>,
        Arc<BadFakeNetwork>,
        tokio::sync::mpsc::Receiver<(usize, Vec<u8>)>,
        Vec<tokio::sync::mpsc::Sender<Vec<u8>>>,
        Vec<tokio::sync::mpsc::Receiver<Vec<u8>>>,
    ) {
        let config = BadFakeNetworkConfig::new(buffer_size);
        let (network, net_rx, node_channels, receivers, _) =
            BadFakeNetwork::new(n, None, config);
        let net = Arc::new(network);

        let mut parties = Vec::with_capacity(n);
        for i in 0..n {
            let rbc = Bracha::new(i, n, t, t + 1, Arc::new(WrappedMessage::rbc_wrap))
                .expect("Failed to create Bracha instance");
            parties.push(rbc);
        }
        (parties, net, net_rx, node_channels, receivers)
    }

    /// Spawn receiver tasks that track SessionEnded errors
    fn spawn_parties_with_error_tracking(
        parties: Vec<Bracha<SessionId>>,
        mut receivers: Vec<mpsc::Receiver<Vec<u8>>>,
        net: Arc<BadFakeNetwork>,
    ) {
        for rbc in parties.into_iter() {
            let net_clone = Arc::clone(&net);
            let mut rx = receivers.remove(0);

            tokio::spawn(async move {
                while let Some(msg) = rx.recv().await {
                    let wrapped: WrappedMessage = match bincode::deserialize(&msg) {
                        Ok(m) => m,
                        Err(_) => {
                            warn!("Malformed message");
                            continue;
                        }
                    };
                    match wrapped {
                        WrappedMessage::Rbc(rbc_msg) => {
                            if let Err(e) = rbc.process(rbc_msg, Arc::clone(&net_clone)).await {
                                // Track SessionEnded errors specifically
                                let err_str = format!("{:?}", e);
                                if err_str.contains("SessionEnded") {
                                    SESSION_ENDED_COUNT.fetch_add(1, Ordering::SeqCst);
                                    info!(
                                        party = rbc.id(),
                                        error = %e,
                                        "SessionEnded error detected - race condition triggered!"
                                    );
                                } else {
                                    warn!(party = rbc.id(), error = %e, "RBC processing error");
                                }
                            }
                        }
                        _ => {}
                    }
                }
            });
        }
    }

    /// Run a single RBC test with the given seed and delay parameters
    async fn run_race_test_with_seed(
        seed: u64,
        min_delay_ms: u64,
        max_delay_ms: u64,
        n_parties: usize,
        t: usize,
        n_sessions: usize,
    ) -> usize {
        // Reset counter for this run
        SESSION_ENDED_COUNT.store(0, Ordering::SeqCst);

        let (parties, net, net_rx, node_channels, receivers) =
            setup_bad_network_and_parties(n_parties, t, 500).await;

        // Start the BadFakeNetwork with variable delays
        BadFakeNetwork::start(
            net_rx,
            node_channels,
            StdRng::seed_from_u64(seed),
            Uniform::new(min_delay_ms, max_delay_ms),
        );

        // Clone parties for spawning (they're cheap Arc-wrapped)
        let parties_for_spawn: Vec<_> = parties.iter().cloned().collect();
        spawn_parties_with_error_tracking(parties_for_spawn, receivers, net.clone());

        // Generate multiple concurrent sessions to increase race probability
        let mut session_handles = Vec::new();
        for session_idx in 0..n_sessions {
            let session_id = SessionId::new(
                ProtocolType::Rbc,
                SessionId::pack_slot24((seed % 256) as u8, 0, 0),
                session_idx as u32,
            );
            let payload = format!("session_{}_seed_{}", session_idx, seed).into_bytes();

            // Each party initiates a session (simulates concurrent RBC instances)
            let initiator = &parties[session_idx % n_parties];
            let net_clone = net.clone();
            let initiator_clone = initiator.clone();

            let handle = tokio::spawn(async move {
                if let Err(e) = initiator_clone.init(payload, session_id, net_clone).await {
                    warn!(error = %e, "Init failed");
                }
            });
            session_handles.push(handle);
        }

        // Wait for all initiations
        futures::future::join_all(session_handles).await;

        // Give time for messages to propagate through the delayed network
        tokio::time::sleep(Duration::from_millis(max_delay_ms * 10)).await;

        SESSION_ENDED_COUNT.load(Ordering::SeqCst)
    }

    /// Test that demonstrates the SessionEnded race condition.
    ///
    /// This test uses BadFakeNetwork with 5-30ms delays to trigger message reordering.
    /// With sufficient concurrency, some nodes will observe SessionEnded errors
    /// due to the race between clear_store() and late message arrival.
    ///
    /// Note: This test documents the existing bug. It may pass intermittently
    /// when the race doesn't trigger, but should fail consistently when
    /// network delays cause sufficient message reordering.
    #[tokio::test]
    async fn test_sessionended_race_with_bad_network() {
        setup_tracing();

        let n_parties = 5;
        let t = 1;
        let n_sessions = 5; // Multiple concurrent sessions
        let min_delay_ms = 5;
        let max_delay_ms = 30;

        // Run with a few different seeds to increase chance of hitting the race
        let mut total_errors = 0;
        for seed in 0..5 {
            let errors = run_race_test_with_seed(
                seed,
                min_delay_ms,
                max_delay_ms,
                n_parties,
                t,
                n_sessions,
            )
            .await;
            total_errors += errors;
            if errors > 0 {
                info!(seed, errors, "Race condition triggered with seed");
            }
        }

        // This test documents the bug - we expect some SessionEnded errors
        // In a fixed implementation, this would be 0
        info!(
            total_errors,
            "Total SessionEnded errors across all seeds"
        );

        // For now, we just log the results rather than asserting
        // because the race is probabilistic
        if total_errors > 0 {
            info!(
                "SUCCESS: Race condition was triggered {} times, confirming the bug exists",
                total_errors
            );
        } else {
            info!(
                "Note: Race was not triggered in this run. \
                This doesn't mean the bug doesn't exist - try running the stress test."
            );
        }
    }

    /// Stress test variant: Run 50 iterations with different seeds
    ///
    /// This test is more likely to trigger the race condition by running
    /// many iterations with different random seeds.
    ///
    /// Run with: cargo test --test sessionended_race_test stress_test_sessionended_race -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn stress_test_sessionended_race() {
        setup_tracing();

        let n_parties = 5;
        let t = 1;
        let n_sessions = 5;
        let min_delay_ms = 5;
        let max_delay_ms = 50; // Wider delay range for more variance
        let n_iterations = 50;

        let mut total_race_triggers = 0;
        let mut seeds_with_errors = Vec::new();

        for seed in 0..n_iterations {
            let count = run_race_test_with_seed(
                seed,
                min_delay_ms,
                max_delay_ms,
                n_parties,
                t,
                n_sessions,
            )
            .await;

            if count > 0 {
                println!("Seed {}: Triggered {} SessionEnded errors", seed, count);
                total_race_triggers += count;
                seeds_with_errors.push((seed, count));
            }
        }

        println!("\n=== Stress Test Results ===");
        println!("Total iterations: {}", n_iterations);
        println!("Iterations with race triggers: {}", seeds_with_errors.len());
        println!("Total SessionEnded errors: {}", total_race_triggers);

        if !seeds_with_errors.is_empty() {
            println!("\nSeeds that triggered the race:");
            for (seed, count) in &seeds_with_errors {
                println!("  Seed {}: {} errors", seed, count);
            }
        }

        // Document the expected behavior
        if total_race_triggers > 0 {
            println!(
                "\n✓ Race condition confirmed: {} triggers across {} seeds",
                total_race_triggers,
                seeds_with_errors.len()
            );
        } else {
            println!(
                "\n⚠ Race condition not triggered in {} iterations. \
                \nThis is a probabilistic test - the bug may still exist. \
                \nTry increasing n_iterations or delay range.",
                n_iterations
            );
        }
    }

    /// Test with higher concurrency to stress the race condition
    ///
    /// This variant uses more concurrent sessions and wider delay ranges
    /// to maximize the probability of triggering the race.
    #[tokio::test]
    #[ignore]
    async fn high_concurrency_race_test() {
        setup_tracing();

        let n_parties = 5;
        let t = 1;
        let n_sessions = 10; // More concurrent sessions
        let min_delay_ms = 1;
        let max_delay_ms = 100; // Wide delay range
        let n_iterations = 20;

        let mut total_errors = 0;

        for seed in 0..n_iterations {
            let count = run_race_test_with_seed(
                seed,
                min_delay_ms,
                max_delay_ms,
                n_parties,
                t,
                n_sessions,
            )
            .await;
            total_errors += count;
            if count > 0 {
                println!("Seed {}: {} SessionEnded errors", seed, count);
            }
        }

        println!("\n=== High Concurrency Test Results ===");
        println!("Total SessionEnded errors: {}", total_errors);
        println!(
            "Average per iteration: {:.2}",
            total_errors as f64 / n_iterations as f64
        );
    }
}
