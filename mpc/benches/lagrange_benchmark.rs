//! Criterion benchmarks for Lagrange interpolation threshold analysis.
//!
//! Run with: cargo bench --package stoffelmpc-mpc
//!
//! This will generate HTML reports in target/criterion/

use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_std::test_rng;
use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion, PlotConfiguration,
    AxisScale,
};
use stoffelmpc_mpc::common::{
    lagrange_interpolate_parallel_exposed, lagrange_interpolate_sequential_exposed,
};

fn generate_test_data(n: usize) -> (Vec<Fr>, Vec<Fr>) {
    let mut rng = test_rng();
    let x_vals: Vec<Fr> = (1..=n).map(|i| Fr::from(i as u64)).collect();
    let y_vals: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
    (x_vals, y_vals)
}

fn bench_sequential(c: &mut Criterion) {
    let mut group = c.benchmark_group("lagrange_sequential");

    for n in [3, 4, 5, 6, 7, 8, 10, 12, 15, 20, 25, 30] {
        let (x_vals, y_vals) = generate_test_data(n);

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                lagrange_interpolate_sequential_exposed(black_box(&x_vals), black_box(&y_vals))
            })
        });
    }

    group.finish();
}

fn bench_parallel(c: &mut Criterion) {
    let mut group = c.benchmark_group("lagrange_parallel");

    for n in [3, 4, 5, 6, 7, 8, 10, 12, 15, 20, 25, 30] {
        let (x_vals, y_vals) = generate_test_data(n);

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                lagrange_interpolate_parallel_exposed(black_box(&x_vals), black_box(&y_vals))
            })
        });
    }

    group.finish();
}

fn bench_comparison(c: &mut Criterion) {
    let plot_config = PlotConfiguration::default()
        .summary_scale(AxisScale::Logarithmic);

    let mut group = c.benchmark_group("lagrange_comparison");
    group.plot_config(plot_config);

    for n in [3, 4, 5, 6, 7, 8, 10, 12, 15, 20, 25, 30] {
        let (x_vals, y_vals) = generate_test_data(n);

        group.bench_with_input(BenchmarkId::new("sequential", n), &n, |b, _| {
            b.iter(|| {
                lagrange_interpolate_sequential_exposed(black_box(&x_vals), black_box(&y_vals))
            })
        });

        group.bench_with_input(BenchmarkId::new("parallel", n), &n, |b, _| {
            b.iter(|| {
                lagrange_interpolate_parallel_exposed(black_box(&x_vals), black_box(&y_vals))
            })
        });
    }

    group.finish();
}

fn bench_threshold_finder(c: &mut Criterion) {
    let mut group = c.benchmark_group("threshold_finder");

    // Fine-grained analysis around the expected threshold
    for n in 3..=12 {
        let (x_vals, y_vals) = generate_test_data(n);

        group.bench_with_input(BenchmarkId::new("seq", n), &n, |b, _| {
            b.iter(|| {
                lagrange_interpolate_sequential_exposed(black_box(&x_vals), black_box(&y_vals))
            })
        });

        group.bench_with_input(BenchmarkId::new("par", n), &n, |b, _| {
            b.iter(|| {
                lagrange_interpolate_parallel_exposed(black_box(&x_vals), black_box(&y_vals))
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_sequential,
    bench_parallel,
    bench_comparison,
    bench_threshold_finder,
);

criterion_main!(benches);
