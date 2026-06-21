#[path = "bench_utils.rs"]
mod bench_utils;
use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_std::rand::{
    rngs::{OsRng, StdRng},
    SeedableRng,
};
use bench_utils::{create_nodes, spawn_receivers, test_setup};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::{sync::Arc, time::Duration};
use stoffelcrypto::common::rbc::rbc::Avid;
use stoffelcrypto::common::types::fixed::{FixedPointPrecision, SecretFixedPoint};
use stoffelcrypto::common::MPCTypeOps;
use stoffelcrypto::common::{PreprocessingMPCProtocol, SecretSharingScheme};
use stoffelcrypto::honeybadger::{
    robust_interpolate::robust_interpolate::RobustShare, HoneyBadgerMPCNode, SessionId,
};
use stoffelmpc_network::fake_network::FakeNetwork;

async fn setup_fpmul(
    n_parties: usize,
    t: usize,
    k: usize,
    m: usize,
    n_muls: usize,
) -> (
    Vec<HoneyBadgerMPCNode<Fr, Avid<SessionId>>>,
    Vec<Arc<FakeNetwork>>,
    Vec<Vec<SecretFixedPoint<Fr, RobustShare<Fr>>>>,
    Vec<Vec<SecretFixedPoint<Fr, RobustShare<Fr>>>>,
) {
    // Compute preprocessing requirements
    let batch = t + 1;
    let n_prandbit = n_muls * m;
    let total_randbit = (n_prandbit + batch - 1) / batch * batch;
    let n_triples = n_muls + total_randbit; // fpmul triples + prandbit's consumption
    let n_shares = total_randbit;
    let n_prandint = n_muls;

    let (network, receivers) = test_setup(n_parties);
    let nodes = create_nodes(n_parties, t, n_triples, n_shares, n_prandbit, n_prandint, 1);
    spawn_receivers(receivers, nodes.clone(), network.clone());

    // Run preprocessing — generates all required materials
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

    // Generate fixed-point input shares
    let precision = FixedPointPrecision::new(k, m);
    let mut rng = StdRng::from_rng(OsRng).unwrap();
    let mut a_per_node = vec![Vec::new(); n_parties];
    let mut b_per_node = vec![Vec::new(); n_parties];
    for _ in 0..n_muls {
        let sx =
            RobustShare::compute_shares(Fr::rand(&mut rng), n_parties, t, None, &mut rng).unwrap();
        let sy =
            RobustShare::compute_shares(Fr::rand(&mut rng), n_parties, t, None, &mut rng).unwrap();
        for pid in 0..n_parties {
            a_per_node[pid].push(SecretFixedPoint::new_with_precision(
                sx[pid].clone(),
                precision,
            ));
            b_per_node[pid].push(SecretFixedPoint::new_with_precision(
                sy[pid].clone(),
                precision,
            ));
        }
    }

    (nodes, network, a_per_node, b_per_node)
}

async fn run_fpmul(
    nodes: Vec<HoneyBadgerMPCNode<Fr, Avid<SessionId>>>,
    network: Vec<Arc<FakeNetwork>>,
    a_per_node: Vec<Vec<SecretFixedPoint<Fr, RobustShare<Fr>>>>,
    b_per_node: Vec<Vec<SecretFixedPoint<Fr, RobustShare<Fr>>>>,
) {
    let handles: Vec<_> = (0..nodes.len())
        .map(|pid| {
            let mut node = nodes[pid].clone();
            let net = network[pid].clone();
            let a = a_per_node[pid].clone();
            let b = b_per_node[pid].clone();
            tokio::spawn(async move {
                for (ai, bi) in a.into_iter().zip(b) {
                    node.mul_fixed(ai, bi, net.clone())
                        .await
                        .expect("fpmul failed");
                }
            })
        })
        .collect();
    futures::future::join_all(handles).await;
}

fn bench_fpmul(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    // (n_parties, t, k, m, n_muls) — k=total bits, m=fractional bits
    let params: &[(usize, usize, usize, usize, usize)] = &[
        (4, 1, 16, 4, 1),
        (4, 1, 16, 4, 5),
        (7, 2, 16, 4, 1),
        (7, 2, 16, 4, 5),
    ];

    let mut group = c.benchmark_group("fpmul");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));

    for &(n, t, k, m, muls) in params {
        group.bench_with_input(
            BenchmarkId::new("protocol", format!("n{n}_t{t}_k{k}_m{m}_muls{muls}")),
            &(n, t, k, m, muls),
            |b, &(n, t, k, m, muls)| {
                b.to_async(&rt).iter_custom(|iters| async move {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let (nodes, network, a, b) = setup_fpmul(n, t, k, m, muls).await;
                        let start = std::time::Instant::now();
                        run_fpmul(nodes, network, a, b).await;
                        total += start.elapsed();
                    }
                    total
                })
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_fpmul);
criterion_main!(benches);
