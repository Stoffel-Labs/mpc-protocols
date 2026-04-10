#[path = "bench_utils.rs"]
mod bench_utils;

use ark_bls12_381::{Fr, G1Projective as G};
use ark_ec::PrimeGroup;
use ark_ff::UniformRand;
use ark_std::rand::{
    rngs::{OsRng, StdRng},
    SeedableRng,
};
use ark_std::test_rng;
use bench_utils::{fan_in_inboxes, test_setup};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::{sync::Arc, time::Duration};
use stoffelmpc_mpc::{
    avss_mpc::{triple_gen::BeaverTriple, AvssMPCNode, AvssMPCNodeOpts, AvssSessionId},
    common::{
        rbc::rbc::Avid, share::feldman::FeldmanShamirShare, MPCProtocol, PreprocessingMPCProtocol,
        SecretSharingScheme,
    },
};
use stoffelmpc_network::fake_network::{FakeNetwork, SenderId};
use tokio::sync::mpsc::Receiver;


fn create_avss_nodes(
    n_parties: usize,
    t: usize,
    n_v_random_shares: usize,
    n_triples: usize,
) -> Vec<AvssMPCNode<Fr, Avid<AvssSessionId>, G>> {
    let mut rng = test_rng();
    let mut sks = Vec::new();
    let mut pks = Vec::new();
    for _ in 0..n_parties {
        let sk = Fr::rand(&mut rng);
        let pk = G::generator() * sk;
        sks.push(sk);
        pks.push(pk);
    }
    let pk_map = Arc::new(pks);

    (0..n_parties)
        .map(|id| {
            let opts = AvssMPCNodeOpts::new(
                n_parties,
                t,
                n_v_random_shares,
                n_triples,
                sks[id],
                pk_map.clone(),
                1,
                Duration::from_secs(60),
            )
            .unwrap();
            <AvssMPCNode<Fr, Avid<AvssSessionId>, G> as MPCProtocol<
                Fr,
                FeldmanShamirShare<Fr, G>,
                FakeNetwork,
            >>::setup(id, opts, vec![])
            .unwrap()
        })
        .collect()
}

fn spawn_avss_receivers(
    mut receivers: Vec<Vec<Receiver<Vec<u8>>>>,
    nodes: Vec<AvssMPCNode<Fr, Avid<AvssSessionId>, G>>,
    network: Vec<Arc<FakeNetwork>>,
) {
    for (i, (inbox_row, mut node)) in receivers.drain(..).zip(nodes.into_iter()).enumerate() {
        let net = network[i].clone();
        let labeled: Vec<(SenderId, Receiver<Vec<u8>>)> = inbox_row
            .into_iter()
            .enumerate()
            .map(|(j, r)| (SenderId::Node(j), r))
            .collect();
        let mut merged = fan_in_inboxes(labeled);
        tokio::spawn(async move {
            while let Some((sender, raw)) = merged.recv().await {
                let id = match sender {
                    SenderId::Node(i) | SenderId::Client(i) => i,
                };
                let _ = node.process(id, raw, net.clone()).await;
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Preprocessing bench
// ---------------------------------------------------------------------------

async fn run_avss_preprocessing(n_parties: usize, t: usize, n_v_shares: usize, n_triples: usize) {
    let (network, receivers) = test_setup(n_parties);
    let nodes = create_avss_nodes(n_parties, t, n_v_shares, n_triples);
    spawn_avss_receivers(receivers, nodes.clone(), network.clone());

    let handles: Vec<_> = (0..n_parties)
        .map(|pid| {
            let mut node = nodes[pid].clone();
            let net = network[pid].clone();
            let mut rng = StdRng::from_rng(OsRng).unwrap();
            tokio::spawn(async move {
                node.run_preprocessing(net, &mut rng)
                    .await
                    .expect("avss preprocessing failed");
            })
        })
        .collect();
    futures::future::join_all(handles).await;
}

fn bench_avss_preprocessing(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    // (n_parties, t, n_v_shares, n_triples)
    let params: &[(usize, usize, usize, usize)] =
        &[(4, 1, 4, 4), (4, 1, 10, 10), (7, 2, 4, 4), (7, 2, 10, 10)];

    let mut group = c.benchmark_group("avss_preprocessing");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));

    for &(n, t, v, tri) in params {
        group.bench_with_input(
            BenchmarkId::new("e2e", format!("n{n}_t{t}_v{v}_tri{tri}")),
            &(n, t, v, tri),
            |b, &(n, t, v, tri)| {
                b.to_async(&rt)
                    .iter(|| run_avss_preprocessing(n, t, v, tri))
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Mul bench
// ---------------------------------------------------------------------------

fn build_triples(n_parties: usize, t: usize, n_muls: usize) -> Vec<Vec<BeaverTriple<Fr, G>>> {
    let mut rng = test_rng();
    let ids: Vec<_> = (1..=n_parties).collect();
    let mut per_party: Vec<Vec<BeaverTriple<Fr, G>>> = vec![Vec::new(); n_parties];

    for _ in 0..n_muls {
        let a = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);
        let c = a * b;
        let sa = FeldmanShamirShare::compute_shares(a, n_parties, t, Some(&ids), &mut rng).unwrap();
        let sb = FeldmanShamirShare::compute_shares(b, n_parties, t, Some(&ids), &mut rng).unwrap();
        let sc = FeldmanShamirShare::compute_shares(c, n_parties, t, Some(&ids), &mut rng).unwrap();
        for pid in 0..n_parties {
            per_party[pid].push(BeaverTriple {
                a: sa[pid].clone(),
                b: sb[pid].clone(),
                c: sc[pid].clone(),
            });
        }
    }
    per_party
}

async fn setup_avss_mul(
    n_parties: usize,
    t: usize,
    n_muls: usize,
) -> (
    Vec<AvssMPCNode<Fr, Avid<AvssSessionId>, G>>,
    Vec<Arc<FakeNetwork>>,
    Vec<Vec<FeldmanShamirShare<Fr, G>>>,
    Vec<Vec<FeldmanShamirShare<Fr, G>>>,
) {
    let (network, receivers) = test_setup(n_parties);
    let nodes = create_avss_nodes(n_parties, t, 0, n_muls);
    spawn_avss_receivers(receivers, nodes.clone(), network.clone());

    // Inject pre-built triples — isolates mul from preprocessing cost
    let triples = build_triples(n_parties, t, n_muls);
    for pid in 0..n_parties {
        nodes[pid]
            .preprocessing_material
            .lock()
            .await
            .add(Some(triples[pid].clone()), None);
    }

    let ids: Vec<_> = (1..=n_parties).collect();
    let mut rng = test_rng();
    let mut x_per_node = vec![Vec::new(); n_parties];
    let mut y_per_node = vec![Vec::new(); n_parties];
    for _ in 0..n_muls {
        let x = Fr::rand(&mut rng);
        let y = Fr::rand(&mut rng);
        let sx = FeldmanShamirShare::compute_shares(x, n_parties, t, Some(&ids), &mut rng).unwrap();
        let sy = FeldmanShamirShare::compute_shares(y, n_parties, t, Some(&ids), &mut rng).unwrap();
        for pid in 0..n_parties {
            x_per_node[pid].push(sx[pid].clone());
            y_per_node[pid].push(sy[pid].clone());
        }
    }

    (nodes, network, x_per_node, y_per_node)
}

async fn run_avss_mul(
    nodes: Vec<AvssMPCNode<Fr, Avid<AvssSessionId>, G>>,
    network: Vec<Arc<FakeNetwork>>,
    x_per_node: Vec<Vec<FeldmanShamirShare<Fr, G>>>,
    y_per_node: Vec<Vec<FeldmanShamirShare<Fr, G>>>,
) {
    let handles: Vec<_> = (0..nodes.len())
        .map(|pid| {
            let mut node = nodes[pid].clone();
            let net = network[pid].clone();
            let x = x_per_node[pid].clone();
            let y = y_per_node[pid].clone();
            tokio::spawn(async move {
                node.mul(x, y, net).await.expect("avss mul failed");
            })
        })
        .collect();
    futures::future::join_all(handles).await;
}

fn bench_avss_mul(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    // (n_parties, t, n_muls)
    let params: &[(usize, usize, usize)] = &[(4, 1, 1), (4, 1, 10), (7, 2, 1), (7, 2, 10)];

    let mut group = c.benchmark_group("avss_mul");
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
                        let (nodes, network, x, y) = setup_avss_mul(n, t, m).await;
                        let start = std::time::Instant::now();
                        run_avss_mul(nodes, network, x, y).await;
                        total += start.elapsed();
                    }
                    total
                })
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_avss_preprocessing, bench_avss_mul);
criterion_main!(benches);
