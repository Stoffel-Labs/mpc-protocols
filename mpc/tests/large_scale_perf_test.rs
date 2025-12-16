//! Large-scale performance test for preprocessing
//!
//! Run with: cargo test --release large_scale_perf -- --nocapture --ignored
//!
//! This test generates large amounts of preprocessing material to identify bottlenecks.

mod utils;

use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_std::test_rng;
use std::sync::Arc;
use std::time::Instant;
use stoffelmpc_mpc::{
    common::{
        lagrange_interpolate, share::shamir::NonRobustShare, SecretSharingScheme,
    },
    honeybadger::robust_interpolate::robust_interpolate::RobustShare,
};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};

/// Benchmark Lagrange interpolation at various scales
fn bench_lagrange_interpolation(sizes: &[usize]) {
    println!("\n=== Lagrange Interpolation Benchmark ===\n");
    println!("{:>8} | {:>12} | {:>12}", "n", "Time (ms)", "Throughput");
    println!("{}", "-".repeat(40));

    let mut rng = test_rng();

    for &n in sizes {
        let x_vals: Vec<Fr> = (1..=n).map(|i| Fr::from(i as u64)).collect();
        let y_vals: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();

        let start = Instant::now();
        let iterations = if n < 50 { 100 } else if n < 200 { 10 } else { 1 };

        for _ in 0..iterations {
            let _ = lagrange_interpolate(&x_vals, &y_vals).unwrap();
        }

        let elapsed = start.elapsed();
        let avg_ms = elapsed.as_secs_f64() * 1000.0 / iterations as f64;

        println!(
            "{:>8} | {:>9.3} ms | {:>8.1}/s",
            n,
            avg_ms,
            1000.0 / avg_ms
        );
    }
}

/// Benchmark share generation at various scales
fn bench_share_generation(n_parties: usize, threshold: usize, counts: &[usize]) {
    println!("\n=== Share Generation Benchmark (n={}, t={}) ===\n", n_parties, threshold);
    println!("{:>10} | {:>12} | {:>15}", "Shares", "Time (ms)", "Shares/sec");
    println!("{}", "-".repeat(45));

    let mut rng = test_rng();

    for &count in counts {
        let start = Instant::now();

        for _ in 0..count {
            let secret = Fr::rand(&mut rng);
            let _ = RobustShare::compute_shares(secret, n_parties, threshold, None, &mut rng).unwrap();
        }

        let elapsed = start.elapsed();
        let ms = elapsed.as_secs_f64() * 1000.0;
        let throughput = count as f64 / elapsed.as_secs_f64();

        println!(
            "{:>10} | {:>9.1} ms | {:>12.0}/s",
            count,
            ms,
            throughput
        );
    }
}

/// Benchmark secret recovery at various scales
fn bench_secret_recovery(n_parties: usize, threshold: usize, counts: &[usize]) {
    println!("\n=== Secret Recovery Benchmark (n={}, t={}) ===\n", n_parties, threshold);
    println!("{:>10} | {:>12} | {:>15}", "Recoveries", "Time (ms)", "Recoveries/sec");
    println!("{}", "-".repeat(50));

    let mut rng = test_rng();

    for &count in counts {
        // Pre-generate shares
        let shares_list: Vec<Vec<RobustShare<Fr>>> = (0..count)
            .map(|_| {
                let secret = Fr::rand(&mut rng);
                RobustShare::compute_shares(secret, n_parties, threshold, None, &mut rng).unwrap()
            })
            .collect();

        let start = Instant::now();

        for shares in &shares_list {
            let _ = RobustShare::recover_secret(shares, n_parties).unwrap();
        }

        let elapsed = start.elapsed();
        let ms = elapsed.as_secs_f64() * 1000.0;
        let throughput = count as f64 / elapsed.as_secs_f64();

        println!(
            "{:>10} | {:>9.1} ms | {:>12.0}/s",
            count,
            ms,
            throughput
        );
    }
}

/// Benchmark batch share multiplication (local, no network)
fn bench_share_multiplication(n_parties: usize, threshold: usize, counts: &[usize]) {
    println!("\n=== Local Share Multiplication Benchmark (n={}, t={}) ===\n", n_parties, threshold);
    println!("{:>10} | {:>12} | {:>15}", "Mults", "Time (ms)", "Mults/sec");
    println!("{}", "-".repeat(50));

    let mut rng = test_rng();

    for &count in counts {
        // Pre-generate pairs of shares
        let pairs: Vec<(Vec<RobustShare<Fr>>, Vec<RobustShare<Fr>>)> = (0..count)
            .map(|_| {
                let a = Fr::rand(&mut rng);
                let b = Fr::rand(&mut rng);
                let shares_a = RobustShare::compute_shares(a, n_parties, threshold, None, &mut rng).unwrap();
                let shares_b = RobustShare::compute_shares(b, n_parties, threshold, None, &mut rng).unwrap();
                (shares_a, shares_b)
            })
            .collect();

        let start = Instant::now();

        // Simulate local multiplication for party 0
        for (shares_a, shares_b) in &pairs {
            let _ = shares_a[0].share_mul(&shares_b[0]).unwrap();
        }

        let elapsed = start.elapsed();
        let ms = elapsed.as_secs_f64() * 1000.0;
        let throughput = count as f64 / elapsed.as_secs_f64();

        println!(
            "{:>10} | {:>9.1} ms | {:>12.0}/s",
            count,
            ms,
            throughput
        );
    }
}

/// Memory usage estimation for preprocessing material
fn estimate_memory_usage(n_shares: usize, n_triples: usize, n_parties: usize) {
    println!("\n=== Memory Usage Estimation ===\n");

    // RobustShare<Fr>: ~64 bytes (Fr is 32 bytes, + id, degree, phantom)
    // ShamirBeaverTriple: 3 x RobustShare = ~192 bytes

    let share_size = 64_usize;
    let triple_size = 192_usize;

    let shares_mem = n_shares * share_size;
    let triples_mem = n_triples * triple_size;
    let total_mem = shares_mem + triples_mem;

    println!("Configuration:");
    println!("  Parties: {}", n_parties);
    println!("  Random shares: {}", n_shares);
    println!("  Beaver triples: {}", n_triples);
    println!();
    println!("Estimated memory per party:");
    println!("  Random shares: {:.2} MB", shares_mem as f64 / 1_000_000.0);
    println!("  Beaver triples: {:.2} MB", triples_mem as f64 / 1_000_000.0);
    println!("  Total: {:.2} MB", total_mem as f64 / 1_000_000.0);
    println!();
    println!("Network data per party (approx):");
    // Each share needs to be sent to each party during generation
    let share_network = n_shares * share_size * n_parties;
    let triple_network = n_triples * triple_size * n_parties * 2; // triples have more rounds
    println!("  Share generation: {:.2} MB", share_network as f64 / 1_000_000.0);
    println!("  Triple generation: {:.2} MB", triple_network as f64 / 1_000_000.0);
}

#[test]
#[ignore]
fn large_scale_perf_lagrange() {
    println!("\n{}", "=".repeat(60));
    println!("LARGE SCALE PERFORMANCE TEST - LAGRANGE INTERPOLATION");
    println!("{}", "=".repeat(60));

    bench_lagrange_interpolation(&[5, 10, 20, 50, 100, 200]);
}

#[test]
#[ignore]
fn large_scale_perf_shares() {
    println!("\n{}", "=".repeat(60));
    println!("LARGE SCALE PERFORMANCE TEST - SHARE OPERATIONS");
    println!("{}", "=".repeat(60));

    let n_parties = 5;
    let threshold = 1;

    bench_share_generation(n_parties, threshold, &[100, 1000, 5000, 10000, 20000]);
    bench_secret_recovery(n_parties, threshold, &[100, 1000, 5000, 10000, 20000]);
    bench_share_multiplication(n_parties, threshold, &[100, 1000, 5000, 10000, 20000]);
}

#[test]
#[ignore]
fn large_scale_perf_full() {
    println!("\n================================================================");
    println!("LARGE SCALE PERFORMANCE TEST - FULL ANALYSIS");
    println!("================================================================");

    let n_parties = 5;
    let threshold = 1;
    let n_shares = 20000;
    let n_triples = 20000;

    // Memory estimation
    estimate_memory_usage(n_shares, n_triples, n_parties);

    // Lagrange interpolation (core operation)
    bench_lagrange_interpolation(&[5, 7, 10, 13, 15, 20]);

    // Share operations
    bench_share_generation(n_parties, threshold, &[1000, 5000, 10000, 20000]);
    bench_secret_recovery(n_parties, threshold, &[1000, 5000, 10000, 20000]);
    bench_share_multiplication(n_parties, threshold, &[1000, 5000, 10000, 20000]);

    // Summary
    println!("\n=== Performance Summary ===\n");
    println!("Target: {} random shares, {} beaver triples", n_shares, n_triples);
    println!("Parties: {}, Threshold: {}", n_parties, threshold);
}

/// Benchmark IFFT vs Lagrange recovery for NonRobustShare
fn bench_ifft_optimization(count: usize) {
    println!("\n=== IFFT Optimization Benchmark ===\n");
    println!("Note: IFFT fast path only triggers when domain.size() == n (powers of 2)\n");

    let mut rng = test_rng();

    // Test with various sizes - powers of 2 should use IFFT, others use Lagrange
    let test_cases = [
        (4, 1, "power of 2 - IFFT"),
        (5, 1, "non-power - Lagrange"),
        (8, 2, "power of 2 - IFFT"),
        (10, 3, "non-power - Lagrange"),
        (16, 5, "power of 2 - IFFT"),
        (20, 6, "non-power - Lagrange"),
        (32, 10, "power of 2 - IFFT"),
    ];

    println!("{:>4} | {:>6} | {:>20} | {:>12} | {:>12}", "n", "t", "Expected Path", "Time (ms)", "Ops/sec");
    println!("{}", "-".repeat(70));

    for (n, t, expected_path) in test_cases {
        let shares_list: Vec<Vec<NonRobustShare<Fr>>> = (0..count)
            .map(|_| {
                let secret = Fr::rand(&mut rng);
                NonRobustShare::compute_shares(secret, n, t, None, &mut rng).unwrap()
            })
            .collect();

        let start = Instant::now();
        for shares in &shares_list {
            let _ = NonRobustShare::recover_secret(shares, n).unwrap();
        }
        let elapsed = start.elapsed();

        println!(
            "{:>4} | {:>6} | {:>20} | {:>9.2} ms | {:>9.0}/s",
            n,
            t,
            expected_path,
            elapsed.as_secs_f64() * 1000.0,
            count as f64 / elapsed.as_secs_f64()
        );
    }
}

/// Compare RobustShare vs NonRobustShare recovery to isolate error-correction overhead
fn bench_robust_vs_nonrobust(n_parties: usize, threshold: usize, count: usize) {
    println!("\n=== Robust vs NonRobust Recovery (n={}, t={}, count={}) ===\n", n_parties, threshold, count);

    let mut rng = test_rng();

    // Generate RobustShares
    let robust_shares_list: Vec<Vec<RobustShare<Fr>>> = (0..count)
        .map(|_| {
            let secret = Fr::rand(&mut rng);
            RobustShare::compute_shares(secret, n_parties, threshold, None, &mut rng).unwrap()
        })
        .collect();

    // Generate NonRobustShares
    let nonrobust_shares_list: Vec<Vec<NonRobustShare<Fr>>> = (0..count)
        .map(|_| {
            let secret = Fr::rand(&mut rng);
            NonRobustShare::compute_shares(secret, n_parties, threshold, None, &mut rng).unwrap()
        })
        .collect();

    // Benchmark RobustShare recovery
    let start = Instant::now();
    for shares in &robust_shares_list {
        let _ = RobustShare::recover_secret(shares, n_parties).unwrap();
    }
    let robust_time = start.elapsed();

    // Benchmark NonRobustShare recovery
    let start = Instant::now();
    for shares in &nonrobust_shares_list {
        let _ = NonRobustShare::recover_secret(shares, n_parties).unwrap();
    }
    let nonrobust_time = start.elapsed();

    // Benchmark raw Lagrange interpolation (what NonRobust uses internally)
    let domain = GeneralEvaluationDomain::<Fr>::new(n_parties).unwrap();
    let x_vals: Vec<Fr> = (0..n_parties).map(|i| domain.element(i)).collect();
    let y_vals_list: Vec<Vec<Fr>> = nonrobust_shares_list.iter()
        .map(|shares| shares.iter().map(|s| s.share[0]).collect())
        .collect();

    let start = Instant::now();
    for y_vals in &y_vals_list {
        let _ = lagrange_interpolate(&x_vals, y_vals).unwrap();
    }
    let lagrange_time = start.elapsed();

    println!("{:<25} | {:>12} | {:>15}", "Method", "Time (ms)", "Ops/sec");
    println!("{}", "-".repeat(55));
    println!(
        "{:<25} | {:>9.1} ms | {:>12.0}/s",
        "RobustShare (error corr)",
        robust_time.as_secs_f64() * 1000.0,
        count as f64 / robust_time.as_secs_f64()
    );
    println!(
        "{:<25} | {:>9.1} ms | {:>12.0}/s",
        "NonRobustShare",
        nonrobust_time.as_secs_f64() * 1000.0,
        count as f64 / nonrobust_time.as_secs_f64()
    );
    println!(
        "{:<25} | {:>9.1} ms | {:>12.0}/s",
        "Raw lagrange_interpolate",
        lagrange_time.as_secs_f64() * 1000.0,
        count as f64 / lagrange_time.as_secs_f64()
    );

    let overhead = robust_time.as_secs_f64() / nonrobust_time.as_secs_f64();
    println!("\nRobust overhead vs NonRobust: {:.1}x", overhead);
}

/// Analyze where time is spent in recovery by breaking down operations
fn bench_recovery_breakdown(n_parties: usize, threshold: usize) {
    println!("\n=== Recovery Operation Breakdown (n={}, t={}) ===\n", n_parties, threshold);

    let mut rng = test_rng();
    let count = 1000;

    let domain = GeneralEvaluationDomain::<Fr>::new(n_parties).unwrap();
    let x_vals: Vec<Fr> = (0..n_parties).map(|i| domain.element(i)).collect();

    // Pre-generate test data
    let secrets: Vec<Fr> = (0..count).map(|_| Fr::rand(&mut rng)).collect();
    let y_vals_list: Vec<Vec<Fr>> = secrets.iter()
        .map(|&secret| {
            let shares = RobustShare::compute_shares(secret, n_parties, threshold, None, &mut rng).unwrap();
            shares.iter().map(|s| s.share[0]).collect()
        })
        .collect();

    // 1. Time just the sorting (simulating what recover_secret does)
    let mut shares_for_sort: Vec<Vec<(usize, Fr)>> = y_vals_list.iter()
        .map(|ys| ys.iter().enumerate().map(|(i, &y)| (i, y)).collect())
        .collect();

    let start = Instant::now();
    for shares in &mut shares_for_sort {
        shares.sort_by_key(|(id, _)| *id);
    }
    let sort_time = start.elapsed();

    // 2. Time Lagrange interpolation alone
    let start = Instant::now();
    for y_vals in &y_vals_list {
        let _ = lagrange_interpolate(&x_vals, y_vals).unwrap();
    }
    let lagrange_time = start.elapsed();

    // 3. Time polynomial evaluation (for verification step)
    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
    let test_poly = DensePolynomial::from_coefficients_vec(
        (0..=threshold).map(|_| Fr::rand(&mut rng)).collect()
    );

    let start = Instant::now();
    for _ in 0..count {
        for i in 0..n_parties {
            let _ = test_poly.evaluate(&x_vals[i]);
        }
    }
    let eval_time = start.elapsed();

    // 4. Time FFT-based operations (what compute_shares uses)
    let start = Instant::now();
    for _ in 0..count {
        let poly = DensePolynomial::from_coefficients_vec(
            (0..=threshold).map(|_| Fr::rand(&mut rng)).collect()
        );
        let _ = domain.fft(&poly);
    }
    let fft_time = start.elapsed();

    println!("{:<30} | {:>12} | {:>10}", "Operation", "Time (ms)", "% of Total");
    println!("{}", "-".repeat(60));

    let total = lagrange_time.as_secs_f64();
    println!(
        "{:<30} | {:>9.1} ms | {:>9.1}%",
        "Sort shares",
        sort_time.as_secs_f64() * 1000.0,
        sort_time.as_secs_f64() / total * 100.0
    );
    println!(
        "{:<30} | {:>9.1} ms | {:>9.1}%",
        "Lagrange interpolation",
        lagrange_time.as_secs_f64() * 1000.0,
        100.0
    );
    println!(
        "{:<30} | {:>9.1} ms | {:>9.1}%",
        "Poly eval (n evals × count)",
        eval_time.as_secs_f64() * 1000.0,
        eval_time.as_secs_f64() / total * 100.0
    );
    println!(
        "{:<30} | {:>9.1} ms | {:>9.1}%",
        "FFT (what gen uses)",
        fft_time.as_secs_f64() * 1000.0,
        fft_time.as_secs_f64() / total * 100.0
    );

    println!("\nKey insight: FFT is {:.1}x faster than Lagrange interpolation",
        lagrange_time.as_secs_f64() / fft_time.as_secs_f64());
}

#[test]
#[ignore]
fn large_scale_perf_recovery_analysis() {
    println!("\n================================================================");
    println!("SECRET RECOVERY BOTTLENECK ANALYSIS");
    println!("================================================================");

    bench_ifft_optimization(5000);

    bench_robust_vs_nonrobust(5, 1, 5000);
    bench_robust_vs_nonrobust(8, 2, 5000);  // Power of 2 for IFFT comparison

    bench_recovery_breakdown(5, 1);
    bench_recovery_breakdown(8, 2);  // Power of 2
}

#[test]
#[ignore]
fn large_scale_perf_varying_parties() {
    println!("\n================================================================");
    println!("PERFORMANCE VS NUMBER OF PARTIES");
    println!("================================================================");

    let party_configs = [(5, 1), (7, 2), (10, 3), (13, 4), (20, 6)];
    let count = 5000;

    println!("\n=== Share Generation (5000 shares) ===\n");
    println!("{:>6} | {:>4} | {:>12} | {:>15}", "n", "t", "Time (ms)", "Shares/sec");
    println!("{}", "-".repeat(50));

    let mut rng = test_rng();

    for (n_parties, threshold) in party_configs {
        let start = Instant::now();

        for _ in 0..count {
            let secret = Fr::rand(&mut rng);
            let _ = RobustShare::compute_shares(secret, n_parties, threshold, None, &mut rng).unwrap();
        }

        let elapsed = start.elapsed();
        let ms = elapsed.as_secs_f64() * 1000.0;
        let throughput = count as f64 / elapsed.as_secs_f64();

        println!(
            "{:>6} | {:>4} | {:>9.1} ms | {:>12.0}/s",
            n_parties, threshold, ms, throughput
        );
    }

    println!("\n=== Secret Recovery (5000 recoveries) ===\n");
    println!("{:>6} | {:>4} | {:>12} | {:>15}", "n", "t", "Time (ms)", "Recoveries/sec");
    println!("{}", "-".repeat(55));

    for (n_parties, threshold) in party_configs {
        // Pre-generate
        let shares_list: Vec<Vec<RobustShare<Fr>>> = (0..count)
            .map(|_| {
                let secret = Fr::rand(&mut rng);
                RobustShare::compute_shares(secret, n_parties, threshold, None, &mut rng).unwrap()
            })
            .collect();

        let start = Instant::now();

        for shares in &shares_list {
            let _ = RobustShare::recover_secret(shares, n_parties).unwrap();
        }

        let elapsed = start.elapsed();
        let ms = elapsed.as_secs_f64() * 1000.0;
        let throughput = count as f64 / elapsed.as_secs_f64();

        println!(
            "{:>6} | {:>4} | {:>9.1} ms | {:>12.0}/s",
            n_parties, threshold, ms, throughput
        );
    }
}
