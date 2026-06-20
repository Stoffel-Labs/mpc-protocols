#[path = "bench_utils.rs"]
mod bench_utils;
use bench_utils::{create_nodes, spawn_receivers, test_setup};

use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_std::rand::{
    rngs::{OsRng, StdRng},
    SeedableRng,
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::{sync::Arc, time::Duration};
use stoffelmpc_mpc::common::rbc::rbc::Avid;
use stoffelmpc_mpc::common::{MPCProtocol, PreprocessingMPCProtocol, SecretSharingScheme};
use stoffelmpc_mpc::honeybadger::{
    robust_interpolate::robust_interpolate::RobustShare, triple_gen::ShamirBeaverTriple,
    HoneyBadgerMPCNode, SessionId,
};
use stoffelmpc_network::fake_network::FakeNetwork;

async fn setup_mul(
    n_parties: usize,
    t: usize,
    n_muls: usize,
) -> (
    Vec<HoneyBadgerMPCNode<Fr, Avid<SessionId>>>,
    Vec<Arc<FakeNetwork>>,
    Vec<Vec<RobustShare<Fr>>>,
    Vec<Vec<RobustShare<Fr>>>,
) {
    let (network, receivers) = test_setup(n_parties);
    let nodes = create_nodes(n_parties, t, n_muls, 0, 0, 0, 1);
    spawn_receivers(receivers, nodes.clone(), network.clone());

    // Run preprocessing — generates n_muls triples into each node's store
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
    futures::future::join_all(handles).await;

    // Generate random x/y input shares (not preprocessing — just random inputs)
    let mut rng = StdRng::from_rng(OsRng).unwrap();
    let mut x_per_node = vec![Vec::new(); n_parties];
    let mut y_per_node = vec![Vec::new(); n_parties];
    for _ in 0..n_muls {
        let sx =
            RobustShare::compute_shares(Fr::rand(&mut rng), n_parties, t, None, &mut rng).unwrap();
        let sy =
            RobustShare::compute_shares(Fr::rand(&mut rng), n_parties, t, None, &mut rng).unwrap();
        for pid in 0..n_parties {
            x_per_node[pid].push(sx[pid].clone());
            y_per_node[pid].push(sy[pid].clone());
        }
    }

    (nodes, network, x_per_node, y_per_node)
}

async fn setup_mul_with_synthetic_triples(
    n_parties: usize,
    t: usize,
    n_muls: usize,
) -> (
    Vec<HoneyBadgerMPCNode<Fr, Avid<SessionId>>>,
    Vec<Arc<FakeNetwork>>,
    Vec<Vec<RobustShare<Fr>>>,
    Vec<Vec<RobustShare<Fr>>>,
) {
    let (network, receivers) = test_setup(n_parties);
    let nodes = create_nodes(n_parties, t, 0, 0, 0, 0, 1);
    spawn_receivers(receivers, nodes.clone(), network.clone());

    let mut rng = StdRng::from_rng(OsRng).unwrap();
    let mut triples_per_node = vec![Vec::with_capacity(n_muls); n_parties];
    let mut x_per_node = vec![Vec::with_capacity(n_muls); n_parties];
    let mut y_per_node = vec![Vec::with_capacity(n_muls); n_parties];

    for _ in 0..n_muls {
        let a = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);
        let c = a * b;
        let a_shares = RobustShare::compute_shares(a, n_parties, t, None, &mut rng).unwrap();
        let b_shares = RobustShare::compute_shares(b, n_parties, t, None, &mut rng).unwrap();
        let c_shares = RobustShare::compute_shares(c, n_parties, t, None, &mut rng).unwrap();
        let x_shares =
            RobustShare::compute_shares(Fr::rand(&mut rng), n_parties, t, None, &mut rng).unwrap();
        let y_shares =
            RobustShare::compute_shares(Fr::rand(&mut rng), n_parties, t, None, &mut rng).unwrap();

        for pid in 0..n_parties {
            triples_per_node[pid].push(ShamirBeaverTriple::new(
                a_shares[pid].clone(),
                b_shares[pid].clone(),
                c_shares[pid].clone(),
            ));
            x_per_node[pid].push(x_shares[pid].clone());
            y_per_node[pid].push(y_shares[pid].clone());
        }
    }

    for pid in 0..n_parties {
        nodes[pid].preprocessing_material.lock().await.add(
            Some(triples_per_node[pid].clone()),
            None,
            None,
            None,
            None,
            None,
        );
    }

    (nodes, network, x_per_node, y_per_node)
}

async fn run_mul(
    nodes: Vec<HoneyBadgerMPCNode<Fr, Avid<SessionId>>>,
    network: Vec<Arc<FakeNetwork>>,
    x_per_node: Vec<Vec<RobustShare<Fr>>>,
    y_per_node: Vec<Vec<RobustShare<Fr>>>,
) {
    let handles: Vec<_> = (0..nodes.len())
        .map(|pid| {
            let mut node = nodes[pid].clone();
            let net = network[pid].clone();
            let x = x_per_node[pid].clone();
            let y = y_per_node[pid].clone();
            tokio::spawn(async move {
                node.mul(x, y, net).await.expect("mul failed");
            })
        })
        .collect();
    futures::future::join_all(handles).await;
}

async fn run_mul_sequential(
    mut nodes: Vec<HoneyBadgerMPCNode<Fr, Avid<SessionId>>>,
    network: Vec<Arc<FakeNetwork>>,
    x_per_node: Vec<Vec<RobustShare<Fr>>>,
    y_per_node: Vec<Vec<RobustShare<Fr>>>,
) {
    let n_muls = x_per_node[0].len();
    for i in 0..n_muls {
        let handles: Vec<_> = (0..nodes.len())
            .map(|pid| {
                let mut node = nodes[pid].clone();
                let net = network[pid].clone();
                let x = vec![x_per_node[pid][i].clone()];
                let y = vec![y_per_node[pid][i].clone()];
                tokio::spawn(async move {
                    let result = node.mul(x, y, net).await.expect("mul failed");
                    (pid, node, result)
                })
            })
            .collect();

        for result in futures::future::join_all(handles).await {
            let (pid, node, _shares) = result.expect("mul task failed");
            nodes[pid] = node;
        }
    }
}

fn stress_counts_from_env() -> Vec<usize> {
    std::env::var("HMPC_MUL_STRESS_COUNTS")
        .ok()
        .map(|value| {
            value
                .split(',')
                .filter_map(|part| part.trim().parse::<usize>().ok())
                .filter(|count| *count > 0)
                .collect::<Vec<_>>()
        })
        .filter(|counts| !counts.is_empty())
        .unwrap_or_else(|| vec![10, 100, 200])
}

fn bench_mul(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let params: &[(usize, usize, usize)] = &[(5, 1, 1), (5, 1, 10), (10, 3, 1), (10, 3, 10)];

    if std::env::var_os("HMPC_MUL_STRESS_ONLY").is_none() {
        let mut group = c.benchmark_group("mul");
        group.sample_size(10);
        group.measurement_time(Duration::from_secs(60));

        for &(n, t, m) in params {
            group.bench_with_input(
                BenchmarkId::new("protocol", format!("n{n}_t{t}_m{m}")),
                &(n, t, m),
                |b, &(n, t, m)| {
                    b.to_async(&rt).iter_custom(|iters| async move {
                        let mut total = Duration::ZERO;
                        for _ in 0..iters {
                            let (nodes, network, x, y) = setup_mul(n, t, m).await;
                            let start = std::time::Instant::now();
                            run_mul(nodes, network, x, y).await;
                            total += start.elapsed();
                        }
                        total
                    })
                },
            );
        }

        group.finish();
    }

    if std::env::var_os("HMPC_MUL_STRESS").is_some()
        || std::env::var_os("HMPC_MUL_STRESS_ONLY").is_some()
    {
        let mut stress = c.benchmark_group("mul_stress");
        stress.sample_size(10);
        stress.measurement_time(Duration::from_secs(30));

        for m in stress_counts_from_env() {
            stress.bench_with_input(
                BenchmarkId::new("batched_synthetic_triples", format!("n5_t1_m{m}")),
                &m,
                |b, &m| {
                    b.to_async(&rt).iter_custom(|iters| async move {
                        let mut total = Duration::ZERO;
                        for _ in 0..iters {
                            let (nodes, network, x, y) =
                                setup_mul_with_synthetic_triples(5, 1, m).await;
                            let start = std::time::Instant::now();
                            run_mul(nodes, network, x, y).await;
                            total += start.elapsed();
                        }
                        total
                    })
                },
            );

            stress.bench_with_input(
                BenchmarkId::new("sequential_synthetic_triples", format!("n5_t1_m{m}")),
                &m,
                |b, &m| {
                    b.to_async(&rt).iter_custom(|iters| async move {
                        let mut total = Duration::ZERO;
                        for _ in 0..iters {
                            let (nodes, network, x, y) =
                                setup_mul_with_synthetic_triples(5, 1, m).await;
                            let start = std::time::Instant::now();
                            run_mul_sequential(nodes, network, x, y).await;
                            total += start.elapsed();
                        }
                        total
                    })
                },
            );
        }

        stress.finish();
    }
}

criterion_group!(benches, bench_mul);
criterion_main!(benches);
