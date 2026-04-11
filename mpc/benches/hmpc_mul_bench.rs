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
    robust_interpolate::robust_interpolate::RobustShare, HoneyBadgerMPCNode, SessionId,
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

fn bench_mul(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let params: &[(usize, usize, usize)] = &[(5, 1, 1), (5, 1, 10), (10, 3, 1), (10, 3, 10)];

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

criterion_group!(benches, bench_mul);
criterion_main!(benches);
