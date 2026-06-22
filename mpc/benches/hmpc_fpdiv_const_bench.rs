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
use stoffelcrypto::common::types::fixed::{ClearFixedPoint, FixedPointPrecision, SecretFixedPoint};
use stoffelcrypto::common::MPCTypeOps;
use stoffelcrypto::common::{PreprocessingMPCProtocol, SecretSharingScheme};
use stoffelcrypto::honeybadger::{
    robust_interpolate::robust_interpolate::RobustShare, HoneyBadgerMPCNode, SessionId,
};
use stoffelmpc_network::fake_network::FakeNetwork;

async fn setup_fpdiv(
    n_parties: usize,
    t: usize,
    k: usize,
    m: usize,
    n_divs: usize,
) -> (
    Vec<HoneyBadgerMPCNode<Fr, Avid<SessionId>>>,
    Vec<Arc<FakeNetwork>>,
    Vec<Vec<SecretFixedPoint<Fr, RobustShare<Fr>>>>,
    Vec<ClearFixedPoint<Fr>>,
) {
    // fpdiv needs f prandbits and 1 prandint per division
    let batch = t + 1;
    let n_prandbit = n_divs * m;
    let total_randbit = (n_prandbit + batch - 1) / batch * batch;
    let n_triples = total_randbit; // only for prandbit generation
    let n_shares = total_randbit;
    let n_prandint = n_divs;

    let (network, receivers) = test_setup(n_parties);
    let nodes = create_nodes(n_parties, t, n_triples, n_shares, n_prandbit, n_prandint, 1);
    spawn_receivers(receivers, nodes.clone(), network.clone());

    // Run preprocessing
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

    // Generate secret fixed-point input shares
    let precision = FixedPointPrecision::new(k, m);
    let mut rng = StdRng::from_rng(OsRng).unwrap();
    let mut x_per_node = vec![Vec::new(); n_parties];
    for _ in 0..n_divs {
        let sx =
            RobustShare::compute_shares(Fr::rand(&mut rng), n_parties, t, None, &mut rng).unwrap();
        for pid in 0..n_parties {
            x_per_node[pid].push(SecretFixedPoint::new_with_precision(
                sx[pid].clone(),
                precision,
            ));
        }
    }

    // Generate clear divisors (non-zero integers encoded in fixed-point)
    let divisors: Vec<ClearFixedPoint<Fr>> = (1..=n_divs)
        .map(|i| {
            let scaled = Fr::from((i as u64) << m); // encode integer i in fixed-point
            ClearFixedPoint::new_with_precision(scaled, precision)
        })
        .collect();

    (nodes, network, x_per_node, divisors)
}

async fn run_fpdiv(
    nodes: Vec<HoneyBadgerMPCNode<Fr, Avid<SessionId>>>,
    network: Vec<Arc<FakeNetwork>>,
    x_per_node: Vec<Vec<SecretFixedPoint<Fr, RobustShare<Fr>>>>,
    divisors: Vec<ClearFixedPoint<Fr>>,
) {
    let handles: Vec<_> = (0..nodes.len())
        .map(|pid| {
            let mut node = nodes[pid].clone();
            let net = network[pid].clone();
            let xs = x_per_node[pid].clone();
            let divs = divisors.clone();
            tokio::spawn(async move {
                for (xi, di) in xs.into_iter().zip(divs) {
                    node.div_with_const_fixed(xi, di, net.clone())
                        .await
                        .expect("fpdiv failed");
                }
            })
        })
        .collect();
    futures::future::join_all(handles).await;
}

fn bench_fpdiv(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    // (n_parties, t, k, m, n_divs) — k=total bits, m=fractional bits
    let params: &[(usize, usize, usize, usize, usize)] = &[
        (4, 1, 16, 4, 1),
        (4, 1, 16, 4, 5),
        (7, 2, 16, 4, 1),
        (7, 2, 16, 4, 5),
    ];

    let mut group = c.benchmark_group("fpdiv_with_const");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));

    for &(n, t, k, m, divs) in params {
        group.bench_with_input(
            BenchmarkId::new("protocol", format!("n{n}_t{t}_k{k}_m{m}_divs{divs}")),
            &(n, t, k, m, divs),
            |b, &(n, t, k, m, divs)| {
                b.to_async(&rt).iter_custom(|iters| async move {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let (nodes, network, xs, divs_vec) = setup_fpdiv(n, t, k, m, divs).await;
                        let start = std::time::Instant::now();
                        run_fpdiv(nodes, network, xs, divs_vec).await;
                        total += start.elapsed();
                    }
                    total
                })
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_fpdiv);
criterion_main!(benches);
