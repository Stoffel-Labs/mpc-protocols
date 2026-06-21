//! End-to-end batched-multiply bench: timed `mul()` wall-clock, total delivered message count,
//! and a correctness check, swept over `(n, t, N)`.
//!
//! Isolates `mul` from preprocessing by injecting synthetic Beaver triples (mirrors
//! `hmpc_mul_bench::setup_mul_with_synthetic_triples`). Receiver loops tolerate the benign
//! late/duplicate batch-recon messages that the node surfaces as errors (same as the existing
//! `hmpc_mul_bench`, which uses `let _ = node.process(...)`), and count every delivered message.
//!
//! Run:
//!   cargo bench -p stoffelmpc-mpc --bench hmpc_mul_e2e_bench
//!   HMPC_MUL_E2E_STRESS=1                                  # enable large-N sweep
//!   HMPC_MUL_E2E_COUNTS=256,1024,4096                      # custom N list
//!   HMPC_MUL_E2E_CONFIGS=n10_t3,n5_t1                      # custom (n,t) list

#[path = "bench_utils.rs"]
mod bench_utils;

use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::{rngs::OsRng, SeedableRng};
use bench_utils::{create_nodes, test_setup};
use criterion::{criterion_group, criterion_main, Criterion};
use std::{
    sync::atomic::{AtomicU64, Ordering},
    sync::Arc,
    time::{Duration, Instant},
};
use stoffelmpc_mpc::common::{rbc::rbc::Avid, MPCProtocol, SecretSharingScheme};
use stoffelmpc_mpc::honeybadger::{
    robust_interpolate::robust_interpolate::RobustShare, triple_gen::ShamirBeaverTriple,
    HoneyBadgerMPCNode, SessionId,
};
use stoffelmpc_network::fake_network::{FakeNetwork, SenderId};
use tokio::task::JoinHandle;

/// Per-case result captured for the report.
struct CaseResult {
    n: usize,
    t: usize,
    n_muls: usize,
    wall_us: f64,
    msgs: u64,
    correct: bool,
    no_sessions: usize, // 2 * ceil(N/(t+1)) batch-recon sessions issued per node
}

impl CaseResult {
    fn print(&self) {
        let per_pair_us = if self.n_muls > 0 {
            self.wall_us / self.n_muls as f64
        } else {
            0.0
        };
        let msgs_per_pair = if self.n_muls > 0 {
            self.msgs as f64 / self.n_muls as f64
        } else {
            0.0
        };
        eprintln!(
            "[mul_e2e] n={n} t={t} N={N}: wall={wall_us:.1} us ({per_pair_us:.2} us/pair) | \
             msgs={msgs} ({msgs_per_pair:.1} msg/pair) | sessions/node={sess} | correct={correct}",
            n = self.n,
            t = self.t,
            N = self.n_muls,
            wall_us = self.wall_us,
            msgs = self.msgs,
            sess = self.no_sessions,
            correct = self.correct,
        );
    }
}

/// Like `bench_utils::spawn_receivers` but counts delivered messages and returns the handles so
/// they can be aborted once `mul` completes (prevents task leakage across iterations).
fn spawn_counting_receivers(
    mut receivers: Vec<Vec<tokio::sync::mpsc::Receiver<Vec<u8>>>>,
    nodes: Vec<HoneyBadgerMPCNode<Fr, Avid<SessionId>>>,
    network: Vec<Arc<FakeNetwork>>,
    counter: Arc<AtomicU64>,
) -> Vec<JoinHandle<()>> {
    let mut handles = Vec::new();
    for i in 0..nodes.len() {
        let inbox_row = receivers.remove(0);
        let mut node = nodes[i].clone();
        let net = network[i].clone();
        let counter = counter.clone();
        let labeled: Vec<(SenderId, tokio::sync::mpsc::Receiver<Vec<u8>>)> = inbox_row
            .into_iter()
            .enumerate()
            .map(|(j, r)| (SenderId::Node(j), r))
            .collect();
        let (mut merged, fan_in_handles) = fan_in_inboxes_counting(labeled, counter.clone());
        handles.extend(fan_in_handles);
        handles.push(tokio::spawn(async move {
            while let Some((sender, raw)) = merged.recv().await {
                counter.fetch_add(1, Ordering::Relaxed);
                let id = match sender {
                    SenderId::Node(i) | SenderId::Client(i) => i,
                };
                // Tolerate benign late/duplicate batch-recon errors (same as hmpc_mul_bench).
                let _ = node.process(id, raw, net.clone()).await;
            }
        }));
    }
    handles
}

fn fan_in_inboxes_counting(
    inboxes: Vec<(SenderId, tokio::sync::mpsc::Receiver<Vec<u8>>)>,
    _counter: Arc<AtomicU64>,
) -> (
    tokio::sync::mpsc::Receiver<(SenderId, Vec<u8>)>,
    Vec<JoinHandle<()>>,
) {
    let (tx, rx) = tokio::sync::mpsc::channel(262_144);
    let mut handles = Vec::with_capacity(inboxes.len());
    for (sender, mut rx_i) in inboxes {
        let tx_i = tx.clone();
        handles.push(tokio::spawn(async move {
            while let Some(msg) = rx_i.recv().await {
                if tx_i.send((sender, msg)).await.is_err() {
                    break;
                }
            }
        }));
    }
    (rx, handles)
}

/// Build synthetic triples + random x/y inputs and the plaintext secrets for verification.
async fn synthetic_inputs(
    n: usize,
    t: usize,
    n_muls: usize,
    nodes: &[HoneyBadgerMPCNode<Fr, Avid<SessionId>>],
) -> (
    Vec<Vec<RobustShare<Fr>>>,
    Vec<Vec<RobustShare<Fr>>>,
    Vec<Fr>,
    Vec<Fr>,
) {
    let mut rng = StdRng::from_rng(OsRng).unwrap();
    let mut triples_per_node = vec![Vec::with_capacity(n_muls); n];
    let mut x_per_node = vec![Vec::with_capacity(n_muls); n];
    let mut y_per_node = vec![Vec::with_capacity(n_muls); n];
    let mut x_secret = Vec::with_capacity(n_muls);
    let mut y_secret = Vec::with_capacity(n_muls);

    for _ in 0..n_muls {
        let xv = Fr::rand(&mut rng);
        let yv = Fr::rand(&mut rng);
        x_secret.push(xv);
        y_secret.push(yv);
        let a = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);
        let c = a * b;
        let a_sh = RobustShare::compute_shares(a, n, t, None, &mut rng).unwrap();
        let b_sh = RobustShare::compute_shares(b, n, t, None, &mut rng).unwrap();
        let c_sh = RobustShare::compute_shares(c, n, t, None, &mut rng).unwrap();
        let x_sh = RobustShare::compute_shares(xv, n, t, None, &mut rng).unwrap();
        let y_sh = RobustShare::compute_shares(yv, n, t, None, &mut rng).unwrap();
        for pid in 0..n {
            triples_per_node[pid].push(ShamirBeaverTriple::new(
                a_sh[pid].clone(),
                b_sh[pid].clone(),
                c_sh[pid].clone(),
            ));
            x_per_node[pid].push(x_sh[pid].clone());
            y_per_node[pid].push(y_sh[pid].clone());
        }
    }

    // Inject triples into each node's preprocessing store (mul() consumes them).
    for pid in 0..n {
        nodes[pid].preprocessing_material.lock().await.add(
            Some(triples_per_node[pid].clone()),
            None,
            None,
            None,
            None,
            None,
        );
    }

    (x_per_node, y_per_node, x_secret, y_secret)
}

/// Verify every multiplication reconstructed to x*y across (2t+1) parties.
fn verify(
    results: &[Vec<RobustShare<Fr>>],
    x_secret: &[Fr],
    y_secret: &[Fr],
    n: usize,
    t: usize,
) -> bool {
    let n_muls = x_secret.len();
    for i in 0..n_muls {
        let shares: Vec<RobustShare<Fr>> = (0..n).map(|pid| results[pid][i].clone()).collect();
        let needed = &shares[0..=(2 * t)];
        match RobustShare::recover_secret(needed, n, t) {
            Ok((_, z)) if z == x_secret[i] * y_secret[i] => {}
            _ => return false,
        }
    }
    true
}

fn run_case(n: usize, t: usize, n_muls: usize) -> CaseResult {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async move {
        let (network, receivers) = test_setup(n);
        let nodes = create_nodes(n, t, n_muls, 0, 0, 0, 1);
        // Receivers must be spawned before mul so messages are drained.
        let counter = Arc::new(AtomicU64::new(0));
        let recv_handles =
            spawn_counting_receivers(receivers, nodes.clone(), network.clone(), counter.clone());

        let (x_per_node, y_per_node, x_secret, y_secret) =
            synthetic_inputs(n, t, n_muls, &nodes).await;

        let start = Instant::now();
        let mul_handles: Vec<_> = (0..n)
            .map(|pid| {
                let mut node = nodes[pid].clone();
                let net = network[pid].clone();
                let x = x_per_node[pid].clone();
                let y = y_per_node[pid].clone();
                tokio::spawn(async move { node.mul(x, y, net).await.expect("mul failed") })
            })
            .collect();
        let mut results = Vec::with_capacity(n);
        for h in mul_handles {
            results.push(h.await.expect("mul task panicked"));
        }
        let wall = start.elapsed();

        for h in recv_handles {
            h.abort();
        }

        let correct = verify(&results, &x_secret, &y_secret, n, t);
        // Batched batch-recon: 2 sessions (a-x + b-y) when there is at least one full (t+1)-chunk,
        // else 0 (all-RBC path). (Pre-Task#2 this was 2*ceil(N/(t+1)).)
        let no_sessions = if n_muls / (t + 1) > 0 { 2 } else { 0 };

        CaseResult {
            n,
            t,
            n_muls,
            wall_us: wall.as_secs_f64() * 1e6,
            msgs: counter.load(Ordering::Relaxed),
            correct,
            no_sessions,
        }
    })
}

fn parse_configs() -> Vec<(usize, usize)> {
    if let Ok(v) = std::env::var("HMPC_MUL_E2E_CONFIGS") {
        let parsed: Vec<(usize, usize)> = v
            .split(',')
            .filter_map(|s| {
                let s = s.trim();
                let (n, t) = s.split_once('_')?;
                let n = n.trim_start_matches('n').parse::<usize>().ok()?;
                let t = t.trim_start_matches('t').parse::<usize>().ok()?;
                Some((n, t))
            })
            .collect();
        if !parsed.is_empty() {
            return parsed;
        }
    }
    vec![(5, 1), (10, 3)]
}

fn parse_counts(default: &[usize]) -> Vec<usize> {
    if let Ok(v) = std::env::var("HMPC_MUL_E2E_COUNTS") {
        let parsed: Vec<usize> = v
            .split(',')
            .filter_map(|s| s.trim().parse::<usize>().ok())
            .filter(|c| *c > 0)
            .collect();
        if !parsed.is_empty() {
            return parsed;
        }
    }
    default.to_vec()
}

fn bench_mul_e2e(c: &mut Criterion) {
    let stress = std::env::var_os("HMPC_MUL_E2E_STRESS").is_some();
    let configs = parse_configs();
    let counts = if stress {
        parse_counts(&[256, 1024, 4096])
    } else {
        parse_counts(&[1, 64])
    };

    let mut group = c.benchmark_group("mul_e2e");
    group.sample_size(10); // criterion hard minimum
    group.measurement_time(Duration::from_secs(if stress { 30 } else { 15 }));

    for &(n, t) in &configs {
        let max_pairs = 128 * (t + 1); // one mul session holds this many pairs
        for &n_muls in &counts {
            // For the non-stress small run, also exercise the multi-session path at N = max_pairs.
            let label = format!("n{n}_t{t}_N{n_muls}");
            group.bench_with_input(label.as_str(), &(n, t, n_muls), |b, &(n, t, n_muls)| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let r = run_case(n, t, n_muls);
                        r.print();
                        total += Duration::from_micros(r.wall_us as u64);
                    }
                    total
                })
            });
            let _ = max_pairs; // keep available for future per-session annotation
        }
    }
    group.finish();
}

criterion_group!(benches, bench_mul_e2e);
criterion_main!(benches);
