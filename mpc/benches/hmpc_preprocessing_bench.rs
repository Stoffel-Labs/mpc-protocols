#[path = "bench_utils.rs"]
mod bench_utils;
use crate::bench_utils::{create_nodes, spawn_receivers};
use ark_std::rand::rngs::StdRng;
use ark_std::rand::{rngs::OsRng, SeedableRng};
use bench_utils::test_setup;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::env;
use std::time::Duration;
use stoffelmpc_mpc::common::PreprocessingMPCProtocol;

async fn run_preprocessing(
    n_parties: usize,
    t: usize,
    n_triples: usize,
    n_shares: usize,
    n_prandbit: usize,
    n_prandint: usize,
) {
    let (network, receivers) = test_setup(n_parties);
    let nodes = create_nodes(n_parties, t, n_triples, n_shares, n_prandbit, n_prandint, 1);

    let receiver_handles = spawn_receivers(receivers, nodes.clone(), network.clone());

    let handles: Vec<_> = (0..n_parties)
        .map(|pid| {
            let mut node = nodes[pid].clone();
            let net = network[pid].clone();
            let mut rng = StdRng::from_rng(OsRng).unwrap();
            tokio::spawn(async move {
                node.run_preprocessing(net, &mut rng)
                    .await
                    .expect("preprocessing failed");
            })
        })
        .collect();

    for result in futures::future::join_all(handles).await {
        result.expect("preprocessing task panicked");
    }

    for handle in receiver_handles {
        handle.abort();
    }
}

fn bench_preprocessing(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    // (n_parties, t, n_triples, n_shares)
    let mut params: Vec<(usize, usize, usize, usize, usize, usize)> = vec![
        (4, 1, 10, 10, 0, 0),     // triples+shares only (baseline)
        (4, 1, 10, 10, 10, 10),   // full pipeline, n=4
        (7, 2, 12, 12, 10, 10),   // full pipeline, n=7 — needs 12 to cover ceil(10/3)*3=12
        (7, 2, 100, 100, 50, 50), // full pipeline, n=7 large
    ];

    if env::var_os("HMPC_PREPROCESSING_STRESS").is_some() {
        let stress_counts = env::var("HMPC_PREPROCESSING_STRESS_COUNTS")
            .ok()
            .map(|counts| {
                counts
                    .split(',')
                    .filter_map(|count| count.trim().parse::<usize>().ok())
                    .collect::<Vec<_>>()
            })
            .filter(|counts| !counts.is_empty())
            .unwrap_or_else(|| vec![250, 1_000, 5_000]);

        params.clear();
        params.extend(stress_counts.into_iter().map(|count| {
            // Full pipeline pressure: triples/shares scale together while bit/int pools scale
            // lower, matching the AES-shaped workload where multiplication dominates.
            (7, 2, count, count, count / 2, count / 2)
        }));
    }

    let mut group = c.benchmark_group("preprocessing");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));

    for &(n, t, triples, shares, n_prandbit, n_prandint) in &params {
        group.bench_with_input(
            BenchmarkId::new(
                "e2e",
                format!("n{n}_t{t}_tri{triples}_sh{shares}_pb{n_prandbit}_pi{n_prandint}"),
            ),
            &(n, t, triples, shares, n_prandbit, n_prandint),
            |b, &(n, t, triples, shares, n_prandbit, n_prandint)| {
                b.to_async(&rt)
                    .iter(|| run_preprocessing(n, t, triples, shares, n_prandbit, n_prandint))
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_preprocessing);
criterion_main!(benches);
