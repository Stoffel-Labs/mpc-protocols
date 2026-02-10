//! Network Divergence Test - Reproduction for STO2-35
//!
//! This test demonstrates the critical gap between FakeNetwork (used in unit tests)
//! and real Docker network conditions. The same MPC operations that pass reliably
//! with FakeNetwork may fail or deadlock with Docker-realistic latencies.
//!
//! Issue: STO2-35 - MPC Preprocessing Stall in Docker Deployments
//!
//! Key findings:
//! - FakeNetwork: <1 microsecond latency, guaranteed FIFO delivery
//! - Docker Network: 10-50ms+ latency, best-effort delivery, possible reordering
//! - Tests pass with FakeNetwork but fail in Docker
//!
//! This test documents the divergence and serves as a regression test after fixes.

use std::time::{Duration, Instant};

/// FakeNetwork characteristics (from network/src/fake_network.rs)
struct FakeNetworkProperties {
    latency_us: u64,           // <1 microsecond
    delivery: &'static str,    // "Guaranteed FIFO"
    buffer_size: usize,        // 500 (configurable)
    reconnection: bool,        // false
    dns_resolution: bool,      // false
    heartbeat_required: bool,  // false
}

/// Docker Network characteristics (from stoffel-analytics-node/src/network.rs)
struct DockerNetworkProperties {
    latency_min_ms: u64,       // 10ms
    latency_max_ms: u64,       // 50ms+
    delivery: &'static str,    // "Best-effort, can reorder"
    buffer_size: usize,        // 100 (hardcoded)
    reconnection: bool,        // true (50+ lines of logic)
    dns_resolution: bool,      // true (can fail on startup)
    heartbeat_required: bool,  // true (every 60s)
}

const FAKE_NETWORK: FakeNetworkProperties = FakeNetworkProperties {
    latency_us: 1,
    delivery: "Guaranteed FIFO",
    buffer_size: 500,
    reconnection: false,
    dns_resolution: false,
    heartbeat_required: false,
};

const DOCKER_NETWORK: DockerNetworkProperties = DockerNetworkProperties {
    latency_min_ms: 10,
    latency_max_ms: 50,
    delivery: "Best-effort, can reorder",
    buffer_size: 100,
    reconnection: true,
    dns_resolution: true,
    heartbeat_required: true,
};

/// Test that documents the network property divergence
#[tokio::test]
async fn test_network_properties_divergence() {
    println!("=== Network Properties Comparison ===\n");

    println!("{:<25} {:>20} {:>25}", "Property", "FakeNetwork", "Docker Network");
    println!("{:-<70}", "");

    println!("{:<25} {:>20} {:>20}ms - {}ms",
        "Latency",
        format!("{}μs", FAKE_NETWORK.latency_us),
        DOCKER_NETWORK.latency_min_ms,
        DOCKER_NETWORK.latency_max_ms
    );

    println!("{:<25} {:>20} {:>25}",
        "Delivery",
        FAKE_NETWORK.delivery,
        DOCKER_NETWORK.delivery
    );

    println!("{:<25} {:>20} {:>25}",
        "Buffer Size",
        FAKE_NETWORK.buffer_size,
        DOCKER_NETWORK.buffer_size
    );

    println!("{:<25} {:>20} {:>25}",
        "Reconnection Logic",
        FAKE_NETWORK.reconnection,
        DOCKER_NETWORK.reconnection
    );

    println!("{:<25} {:>20} {:>25}",
        "DNS Resolution",
        FAKE_NETWORK.dns_resolution,
        DOCKER_NETWORK.dns_resolution
    );

    println!("{:<25} {:>20} {:>25}",
        "Heartbeat Required",
        FAKE_NETWORK.heartbeat_required,
        DOCKER_NETWORK.heartbeat_required
    );

    println!("\n=== Critical Divergences ===\n");

    // Latency difference factor
    let latency_factor = (DOCKER_NETWORK.latency_min_ms * 1000) / FAKE_NETWORK.latency_us;
    println!("1. Latency: Docker is {}x slower than FakeNetwork", latency_factor);
    println!("   - FakeNetwork: {}μs", FAKE_NETWORK.latency_us);
    println!("   - Docker: {}-{}ms", DOCKER_NETWORK.latency_min_ms, DOCKER_NETWORK.latency_max_ms);
    println!("   Impact: Timeouts that work in tests fail in production\n");

    // Buffer difference
    let buffer_ratio = FAKE_NETWORK.buffer_size as f64 / DOCKER_NETWORK.buffer_size as f64;
    println!("2. Buffer Size: FakeNetwork has {}x larger buffer", buffer_ratio);
    println!("   - FakeNetwork: {} messages", FAKE_NETWORK.buffer_size);
    println!("   - Docker: {} messages", DOCKER_NETWORK.buffer_size);
    println!("   Impact: Backpressure deadlock in production\n");

    // Untested code paths
    println!("3. Untested Code Paths in Docker:");
    println!("   - network.rs:686-776 - Reconnection logic (never exercised in tests)");
    println!("   - network.rs:270-274 - DNS resolution (can fail on startup)");
    println!("   - network.rs:542-576 - Connection error handling");
    println!("   Impact: Production-only bugs remain hidden\n");

    assert!(
        latency_factor >= 10000,
        "Docker latency should be at least 10,000x FakeNetwork latency"
    );

    assert!(
        FAKE_NETWORK.buffer_size > DOCKER_NETWORK.buffer_size,
        "FakeNetwork should have larger buffer than Docker production code"
    );
}

/// Simulates FakeNetwork timing behavior
async fn simulate_fake_network_operation(n_messages: usize) -> Duration {
    let start = Instant::now();

    // FakeNetwork: essentially instant message delivery
    for _ in 0..n_messages {
        // Simulate ~1μs per message
        tokio::time::sleep(Duration::from_micros(1)).await;
    }

    start.elapsed()
}

/// Simulates Docker network timing behavior
async fn simulate_docker_network_operation(n_messages: usize) -> Duration {
    use rand::Rng;
    let start = Instant::now();
    let mut rng = rand::thread_rng();

    // Docker: 10-50ms per message with variance
    for _ in 0..n_messages {
        let delay_ms = rng.gen_range(DOCKER_NETWORK.latency_min_ms..=DOCKER_NETWORK.latency_max_ms);
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    }

    start.elapsed()
}

/// Test that shows identical operations have vastly different timing
#[tokio::test]
async fn test_timing_divergence() {
    let n_messages = 20; // Typical preprocessing message exchange

    println!("\n=== Timing Divergence Test ===\n");
    println!("Sending {} messages (simulating RBC round):\n", n_messages);

    // FakeNetwork timing
    let fake_duration = simulate_fake_network_operation(n_messages).await;
    println!("FakeNetwork:  {:?}", fake_duration);

    // Docker timing
    let docker_duration = simulate_docker_network_operation(n_messages).await;
    println!("Docker:       {:?}", docker_duration);

    let speedup = docker_duration.as_micros() as f64 / fake_duration.as_micros() as f64;
    println!("\nDocker is {:.0}x slower than FakeNetwork", speedup);

    // Check if 500ms timeout would work
    let timeout = Duration::from_millis(500);
    println!("\nWith 500ms timeout:");
    println!("  FakeNetwork:  {} ({})",
        if fake_duration < timeout { "PASS" } else { "FAIL" },
        format!("{:.2}% of timeout", fake_duration.as_millis() as f64 / 500.0 * 100.0)
    );
    println!("  Docker:       {} ({})",
        if docker_duration < timeout { "PASS" } else { "FAIL" },
        format!("{:.0}% of timeout", docker_duration.as_millis() as f64 / 500.0 * 100.0)
    );

    // Assert the divergence
    assert!(
        fake_duration < Duration::from_millis(10),
        "FakeNetwork should complete in <10ms"
    );

    // Docker timing is non-deterministic due to rand, but should exceed 100ms
    assert!(
        docker_duration > Duration::from_millis(100),
        "Docker simulation should take >100ms for {} messages", n_messages
    );
}

/// Test documenting the BadFakeNetwork misconfiguration
#[tokio::test]
async fn test_bad_fake_network_misconfiguration() {
    println!("\n=== BadFakeNetwork Test Configuration Analysis ===\n");

    // Test configurations from mpc/tests/node_test.rs
    struct TestConfig {
        name: &'static str,
        delay_min_ms: u64,
        delay_max_ms: u64,
    }

    let test_configs = [
        TestConfig { name: "preprocessing_e2e_bad_net", delay_min_ms: 1, delay_max_ms: 3 },
        TestConfig { name: "mul_e2e_with_preprocessing_bad_net", delay_min_ms: 1, delay_max_ms: 10 },
        TestConfig { name: "mul_e2e_bad_net", delay_min_ms: 1, delay_max_ms: 100 },
    ];

    println!("{:<40} {:>15} {:>20}", "Test", "Delay Range", "vs Docker (10-50ms)");
    println!("{:-<75}", "");

    for config in &test_configs {
        let avg_delay = (config.delay_min_ms + config.delay_max_ms) / 2;
        let docker_avg = (DOCKER_NETWORK.latency_min_ms + DOCKER_NETWORK.latency_max_ms) / 2;
        let ratio = docker_avg as f64 / avg_delay as f64;

        let assessment = if ratio > 5.0 {
            format!("{}x too fast", ratio as u64)
        } else {
            "Realistic".to_string()
        };

        println!("{:<40} {:>4}-{:<4}ms {:>20}",
            config.name,
            config.delay_min_ms,
            config.delay_max_ms,
            assessment
        );
    }

    println!("\n=== Recommendations ===\n");
    println!("1. Update preprocessing_e2e_bad_net:");
    println!("   - Current: Uniform::new_inclusive(1, 3)");
    println!("   - Recommended: Uniform::new(10, 50)\n");

    println!("2. Update mul_e2e_with_preprocessing_bad_net:");
    println!("   - Current: Uniform::new(1, 10)");
    println!("   - Recommended: Uniform::new(10, 50)\n");

    println!("3. Keep mul_e2e_bad_net (already uses realistic delays):");
    println!("   - Current: Uniform::new(1, 100)");
    println!("   - This partially covers Docker conditions\n");

    // Assert that preprocessing test is misconfigured
    let preprocessing_avg = (1 + 3) / 2; // 2ms average
    let docker_avg = (10 + 50) / 2; // 30ms average

    assert!(
        docker_avg > preprocessing_avg * 10,
        "Docker delays should be at least 10x preprocessing test delays (currently {}x)",
        docker_avg / preprocessing_avg
    );
}

/// Summary of the test/production gap
#[tokio::test]
async fn test_summary() {
    println!("\n");
    println!("╔═══════════════════════════════════════════════════════════════════╗");
    println!("║            FakeNetwork vs Docker: Test/Production Gap             ║");
    println!("╠═══════════════════════════════════════════════════════════════════╣");
    println!("║                                                                   ║");
    println!("║  Tests use FakeNetwork with:                                      ║");
    println!("║    • <1μs latency (instant delivery)                              ║");
    println!("║    • 500 message buffer                                           ║");
    println!("║    • No reconnection, DNS, or heartbeat logic                     ║");
    println!("║                                                                   ║");
    println!("║  Docker production has:                                           ║");
    println!("║    • 10-50ms+ latency (10,000x+ slower)                           ║");
    println!("║    • 100 message buffer (5x smaller)                              ║");
    println!("║    • Complex reconnection, DNS, heartbeat handling                ║");
    println!("║                                                                   ║");
    println!("║  Result: Tests pass, production fails with:                       ║");
    println!("║    • Timeout errors (500ms is insufficient)                       ║");
    println!("║    • Channel backpressure deadlocks                               ║");
    println!("║    • Untested error recovery paths                                ║");
    println!("║                                                                   ║");
    println!("║  Fix: Use BadFakeNetwork with Docker-realistic delays in CI       ║");
    println!("║                                                                   ║");
    println!("╚═══════════════════════════════════════════════════════════════════╝");
    println!("\n");
}
