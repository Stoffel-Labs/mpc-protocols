//! Certainty A/B: reconstruct the *same* `N` secrets two ways using `BatchReconNode` directly,
//! isolating the single variable that differs between them — session structure.
//!
//!   - Path **A (per-chunk, current `Multiply::init` behavior):** `ceil(N/(t+1))` independent
//!     `init_batch_reconstruct` sessions, one per `(t+1)`-chunk (this is exactly what
//!     `mul/multiplication.rs:418–446` does). Each session = 2 network rounds × n messages.
//!   - Path **B (batched):** a single `init_batch_reconstruct_many` session covering all `N`
//!     secrets (the already-implemented `EvalBatch`/`RevealBatch` path the multiply does *not*
//!     use). One message per recipient per round.
//!
//! Both reconstruct identical secrets (asserted). The wall-clock and message-count delta is the
//! cost of the per-chunk-session design — causation-isolated because nothing else varies.
//!
//! Run:
//!   cargo bench -p stoffelcrypto --bench hmpc_batchrecon_ab_bench
//!   HMPC_BRAB_CONFIGS=n10_t3,n5_t1 HMPC_BRAB_COUNTS=64,256,1024

use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_serialize::CanonicalDeserialize;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::{rngs::OsRng, SeedableRng};
use criterion::{criterion_group, criterion_main, Criterion};
use std::{
    collections::HashMap,
    sync::atomic::{AtomicU64, Ordering},
    sync::Arc,
    time::{Duration, Instant},
};
use stoffelcrypto::common::{ProtocolSessionId, SecretSharingScheme};
use stoffelcrypto::honeybadger::{
    batch_recon::batch_recon::BatchReconNode, robust_interpolate::robust_interpolate::RobustShare,
    ProtocolType, SessionId, WrappedMessage,
};
use stoffelmpc_network::fake_network::{
    FakeInnerNetwork, FakeNetwork, FakeNetworkConfig, SenderId,
};

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    PerChunk,
    Batched,
}

impl Mode {
    fn label(self) -> &'static str {
        match self {
            Mode::PerChunk => "per_chunk",
            Mode::Batched => "batched",
        }
    }
}

const EXEC: u64 = 1;

/// Distinct session id for chunk `c` (used as a store key; fields are not inspected by the
/// batch-recon handler, which we drive directly here).
fn sid_for(chunk: u8) -> SessionId {
    SessionId::new(
        ProtocolType::BatchRecon,
        SessionId::pack_slot(EXEC, chunk, 1),
        1,
    )
}

/// `shares_per_node[p][k]` = party p's share of secret k.
fn share_secrets(secrets: &[Fr], n: usize, t: usize) -> Vec<Vec<RobustShare<Fr>>> {
    let mut rng = StdRng::from_rng(OsRng).unwrap();
    let mut per_node = vec![Vec::with_capacity(secrets.len()); n];
    for &s in secrets {
        let sh = RobustShare::compute_shares(s, n, t, None, &mut rng).unwrap();
        for p in 0..n {
            per_node[p].push(sh[p].clone());
        }
    }
    per_node
}

/// Run one configuration under `mode`. Returns (wall, total delivered msgs, reconstructed secrets).
fn run(n: usize, t: usize, secrets: &[Fr], mode: Mode) -> (Duration, u64, Vec<Fr>) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async move {
        let n_muls = secrets.len();
        let width = t + 1;
        assert!(
            n_muls % width == 0 && n_muls > 0,
            "N must be a positive multiple of t+1 for a clean A/B"
        );
        let num_chunks = n_muls / width;
        let counter = Arc::new(AtomicU64::new(0));

        let config = FakeNetworkConfig::new(262_144);
        let (inner, mut inboxes, _) = FakeInnerNetwork::new(n, None, config);
        let network: Vec<Arc<FakeNetwork>> = (0..n)
            .map(|id| Arc::new(FakeNetwork::new(id, inner.clone())))
            .collect();

        let mut nodes: Vec<BatchReconNode<Fr>> = Vec::with_capacity(n);
        let mut out_rxs: Vec<tokio::sync::mpsc::Receiver<SessionId>> = Vec::with_capacity(n);
        for id in 0..n {
            let (tx, rx) = tokio::sync::mpsc::channel(1024);
            nodes.push(BatchReconNode::<Fr>::new(id, n, t, t, tx).unwrap());
            out_rxs.push(rx);
        }

        let shares_per_node = share_secrets(secrets, n, t);
        let expected = match mode {
            Mode::PerChunk => num_chunks,
            Mode::Batched => 1,
        };

        // Spawn per-node driver tasks (clone the node; move its inbox row + completion receiver).
        let mut drivers = Vec::with_capacity(n);
        let mut out_rxs_iter = out_rxs.into_iter();
        for id in 0..n {
            let mut node = nodes[id].clone();
            let net = network[id].clone();
            let mut out_rx = out_rxs_iter.next().unwrap();
            let inbox_row = std::mem::take(&mut inboxes[id]);
            let counter = counter.clone();

            drivers.push(tokio::spawn(async move {
                // Fan in this node's n per-sender inbox channels into one (sender-labeled) stream.
                let (mtx, mut mrx) = tokio::sync::mpsc::channel::<(SenderId, Vec<u8>)>(262_144);
                for (from, rxi) in inbox_row.into_iter().enumerate() {
                    let mtx = mtx.clone();
                    let mut rxi = rxi;
                    tokio::spawn(async move {
                        while let Some(b) = rxi.recv().await {
                            if mtx.send((SenderId::Node(from), b)).await.is_err() {
                                break;
                            }
                        }
                    });
                }

                let mut reconstructed: HashMap<SessionId, Vec<Fr>> = HashMap::new();
                loop {
                    tokio::select! {
                        biased;
                        sid = out_rx.recv() => {
                            match sid {
                                Some(sid) => {
                                    if let Ok(bytes) = node.get_store(sid).await {
                                        if let Ok(vals) = Vec::<Fr>::deserialize_compressed(&bytes[..]) {
                                            reconstructed.insert(sid, vals);
                                        }
                                    }
                                    if reconstructed.len() >= expected {
                                        break;
                                    }
                                }
                                None => break,
                            }
                        }
                        msg = mrx.recv() => {
                            match msg {
                                Some((_sender, raw)) => {
                                    counter.fetch_add(1, Ordering::Relaxed);
                                    let w: WrappedMessage = match bincode::deserialize(&raw) {
                                        Ok(w) => w,
                                        Err(_) => continue,
                                    };
                                    if let WrappedMessage::BatchRecon(bm) = w {
                                        // Tolerate benign late/duplicate errors.
                                        let _ = node.process(bm, net.clone()).await;
                                    }
                                }
                                None => break,
                            }
                        }
                    }
                }
                reconstructed
            }));
        }

        // Initiate (sends round-1 messages). Drivers are already listening.
        let start = Instant::now();
        for id in 0..n {
            let net = network[id].clone();
            match mode {
                Mode::PerChunk => {
                    for c in 0..num_chunks {
                        let chunk: Vec<RobustShare<Fr>> =
                            shares_per_node[id][c * width..(c + 1) * width].to_vec();
                        nodes[id]
                            .init_batch_reconstruct(&chunk, sid_for(c as u8), net.clone())
                            .await
                            .unwrap();
                    }
                }
                Mode::Batched => {
                    let all = shares_per_node[id].clone();
                    nodes[id]
                        .init_batch_reconstruct_many(&all, sid_for(0), net.clone())
                        .await
                        .unwrap();
                }
            }
        }

        // Await completion.
        let mut per_node = Vec::with_capacity(n);
        for h in drivers {
            per_node.push(h.await.expect("driver panicked"));
        }
        let wall = start.elapsed();

        // Order reconstructed secrets from node 0's map.
        let map = std::mem::take(&mut per_node[0]);
        let mut reconstructed = Vec::with_capacity(n_muls);
        match mode {
            Mode::PerChunk => {
                for c in 0..num_chunks {
                    reconstructed.extend(map.get(&sid_for(c as u8)).expect("chunk missing"));
                }
            }
            Mode::Batched => {
                reconstructed.extend(map.get(&sid_for(0)).expect("batch session missing"));
            }
        }

        (wall, counter.load(Ordering::Relaxed), reconstructed)
    })
}

fn parse_configs() -> Vec<(usize, usize)> {
    if let Ok(v) = std::env::var("HMPC_BRAB_CONFIGS") {
        let parsed: Vec<(usize, usize)> = v
            .split(',')
            .filter_map(|s| {
                let s = s.trim();
                let (n, t) = s.split_once('_')?;
                Some((
                    n.trim_start_matches('n').parse().ok()?,
                    t.trim_start_matches('t').parse().ok()?,
                ))
            })
            .collect();
        if !parsed.is_empty() {
            return parsed;
        }
    }
    vec![(10, 3), (5, 1)]
}

fn parse_counts() -> Vec<usize> {
    if let Ok(v) = std::env::var("HMPC_BRAB_COUNTS") {
        let parsed: Vec<usize> = v
            .split(',')
            .filter_map(|s| s.trim().parse::<usize>().ok())
            .collect();
        if !parsed.is_empty() {
            return parsed;
        }
    }
    vec![4, 16, 64, 256]
}

fn bench_batchrecon_ab(c: &mut Criterion) {
    let configs = parse_configs();
    let counts = parse_counts();

    let mut group = c.benchmark_group("batchrecon_ab");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(15));

    for &(n, t) in &configs {
        let width = t + 1;
        for &n_muls in &counts {
            // Ensure N is a multiple of t+1 (clean A/B requirement).
            let n_muls = (n_muls / width).max(1) * width;
            let mut rng = StdRng::from_rng(OsRng).unwrap();
            let secrets: Vec<Fr> = (0..n_muls).map(|_| Fr::rand(&mut rng)).collect();

            for mode in [Mode::PerChunk, Mode::Batched] {
                let label = format!("{}_n{}_t{}_N{}", mode.label(), n, t, n_muls);
                group.bench_function(label.as_str(), |b| {
                    b.iter_custom(|iters| {
                        let mut total = Duration::ZERO;
                        for _ in 0..iters {
                            let (wall, msgs, recon) = run(n, t, &secrets, mode);
                            // Correctness gate: every run must reconstruct the originals.
                            assert_eq!(
                                recon,
                                secrets,
                                "{} reconstructed wrong secrets",
                                mode.label()
                            );
                            eprintln!(
                                "[batchrecon_ab] {}: wall={:.1} us | msgs={} | correct=true",
                                label,
                                wall.as_secs_f64() * 1e6,
                                msgs
                            );
                            total += wall;
                        }
                        total
                    })
                });
            }
        }
    }
    group.finish();
}

criterion_group!(benches, bench_batchrecon_ab);
criterion_main!(benches);
