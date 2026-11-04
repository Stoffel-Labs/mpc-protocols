//! **Measured** real wire cost of `ltz_int`/`eqz_int` on this (`fpdiv`) branch, head to toe:
//! preprocessing generation (triples, PRandBit, PRandInt, PreMulC bundles, rand-inv-pairs — all
//! generated for real over the network, lazily, the first time a call finds the pool short) AND
//! the online protocol (`PreBitLT`/`PreMod2m` for LTZ, `KOrCL`/`KOrCS` for EQZ), via the real
//! `HoneyBadgerMPCNode::ltz_int`/`eqz_int` entry points — not a hand-assembled sub-protocol chain.
//!
//! This is the F-side counterpart to `mpc/tests/ltz_eqz_cost_measurement.rs` on
//! `feature/a2b-b2a-share-conversion`, built in an isolated worktree so as not to disturb either
//! branch. Same methodology: a `Network` wrapper tallies real bytes, a batch of `count` comparisons
//! is declared up front via `add_ltz_ops`/`add_eqz_ops` so preprocessing is sized and generated
//! ONCE for the whole batch (mirroring the GF side's batched-not-serial fix), then `count` online
//! calls draw from that pool.
//!
//! Run with:
//! ```text
//! cargo test -p stoffelcrypto --test f_side_cost_measurement --release -- --ignored --nocapture --test-threads=1
//! ```
//!
//! This branch has no `statistics` cargo feature (confirmed absent from `mpc/Cargo.toml`), so the
//! byte counter here is a small, self-contained `Network` wrapper — not a port of the other
//! branch's `CountingNetwork`, to avoid touching `src/` on a branch nothing here should modify.

mod utils;

use crate::utils::test_utils::{receive, setup_tracing};
use ark_bls12_381::Fr;
use ark_std::rand::SeedableRng;
use async_trait::async_trait;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use stoffelcrypto::{
    common::{
        rbc::rbc::Avid, types::integer::SecretInt, MPCProtocol, MPCTypeOps,
        PreprocessingMPCProtocol, SecretSharingScheme,
    },
    honeybadger::{
        robust_interpolate::robust_interpolate::RobustShare, HoneyBadgerMPCNode,
        HoneyBadgerMPCNodeOpts, SessionId,
    },
};
use stoffelmpc_network::fake_network::{FakeInnerNetwork, FakeNetwork, FakeNetworkConfig};
use stoffelnet::network_utils::{
    ClientId, Network, NetworkError, PartyId, VerifiedOrdering,
};

type Node = HoneyBadgerMPCNode<Fr, Avid<SessionId>>;

/// Shared, atomic byte tally. Counts every `send`/`broadcast` this party issues, broadcast
/// charged once per recipient — same convention `conv_cost_measurement.rs` uses on the other
/// branch, for comparability.
#[derive(Default)]
struct ByteTally {
    bytes_sent: AtomicU64,
}

/// Transparent `Network` wrapper: tally bytes, then forward unchanged. See
/// `mpc/src/honeybadger/statistics.rs` on `feature/a2b-b2a-share-conversion` for the sibling
/// version of this — not reused directly because this branch has no `statistics` feature and nothing
/// here should add one.
struct CountingNet<N: Network> {
    inner: N,
    tally: Arc<ByteTally>,
}

#[async_trait]
impl<N: Network + Send + Sync> Network for CountingNet<N> {
    type NodeType = N::NodeType;
    type NetworkConfig = N::NetworkConfig;

    async fn send(&self, recipient: PartyId, message: &[u8]) -> Result<usize, NetworkError> {
        self.tally.bytes_sent.fetch_add(message.len() as u64, Ordering::Relaxed);
        self.inner.send(recipient, message).await
    }

    async fn broadcast(&self, message: &[u8]) -> Result<usize, NetworkError> {
        let n = self.inner.party_count() as u64;
        self.tally.bytes_sent.fetch_add(message.len() as u64 * n, Ordering::Relaxed);
        self.inner.broadcast(message).await
    }

    async fn send_to_client(&self, client: ClientId, message: &[u8]) -> Result<usize, NetworkError> {
        self.inner.send_to_client(client, message).await
    }
    fn parties(&self) -> Vec<&Self::NodeType> {
        self.inner.parties()
    }
    fn parties_mut(&mut self) -> Vec<&mut Self::NodeType> {
        self.inner.parties_mut()
    }
    fn config(&self) -> &Self::NetworkConfig {
        self.inner.config()
    }
    fn node(&self, id: PartyId) -> Option<&Self::NodeType> {
        self.inner.node(id)
    }
    fn node_mut(&mut self, id: PartyId) -> Option<&mut Self::NodeType> {
        self.inner.node_mut(id)
    }
    fn clients(&self) -> Vec<ClientId> {
        self.inner.clients()
    }
    fn is_client_connected(&self, client: ClientId) -> bool {
        self.inner.is_client_connected(client)
    }
    fn local_party_id(&self) -> PartyId {
        self.inner.local_party_id()
    }
    fn party_count(&self) -> usize {
        self.inner.party_count()
    }
    fn verified_ordering(&self) -> Option<VerifiedOrdering> {
        self.inner.verified_ordering()
    }
}

fn share_i128(v: i128, n: usize, t: usize) -> Vec<RobustShare<Fr>> {
    // Matches `comparison_utils::share_signed_fixed`'s convention: encode negative values as
    // `p - |v|` (the repo's standard convention), then Shamir-share.
    let field_val = if v >= 0 {
        Fr::from(v as u64)
    } else {
        -Fr::from((-v) as u64)
    };
    RobustShare::compute_shares(field_val, n, t, None, &mut ark_std::test_rng()).unwrap()
}

async fn reconstruct_bit(outputs: Vec<SecretInt<Fr, RobustShare<Fr>>>, n: usize, t: usize) -> bool {
    let shares: Vec<_> = outputs.iter().map(|s| s.share().clone()).collect();
    let (_, value) = RobustShare::recover_secret(&shares[0..n], n, t).expect("interpolate failed");
    value == Fr::from(1u64)
}

const K: usize = 64;

async fn measure_ltz_batch(n: usize, t: usize, batch: usize) {
    setup_tracing();
    let config = FakeNetworkConfig::new(512);
    let (inner, receivers, _) = FakeInnerNetwork::new(n, None, config);
    let tally = Arc::new(ByteTally::default());
    let network: Vec<Arc<CountingNet<FakeNetwork>>> = (0..n)
        .map(|id| {
            Arc::new(CountingNet {
                inner: FakeNetwork::new(id, inner.clone()),
                tally: Arc::clone(&tally),
            })
        })
        .collect();

    let opts = HoneyBadgerMPCNodeOpts::new(n, t, 777, crate::utils::test_utils::unused_precision(), 40, Duration::from_secs(60)).unwrap();
    let mut nodes: Vec<Node> = (0..n)
        .map(|id| {
            <Node as MPCProtocol<Fr, RobustShare<Fr>, CountingNet<FakeNetwork>>>::setup(
                id,
                opts.clone(),
                vec![],
            )
            .unwrap()
        })
        .collect();
    for node in nodes.iter_mut() {
        node.params.add_ltz_ops(K, batch);
    }

    receive::<Fr, Avid<SessionId>, RobustShare<Fr>, CountingNet<FakeNetwork>>(
        receivers,
        nodes.clone(),
        network.clone(),
        None,
    );

    let x: i128 = -5; // small, fits any K >= 3
    // One sharing of `x`, split n ways — not one independent sharing per
    // party, which would hand each party a share of an unrelated polynomial
    // (ark_std::test_rng() is thread_rng()-backed, not fixed-seed, unless
    // DETERMINISTIC_TEST_RNG=1) and abort the first real reveal.
    let shares = share_i128(x, n, t);
    let mut handles = Vec::new();
    for pid in 0..n {
        let mut node = nodes[pid].clone();
        let net = network[pid].clone();
        let share_pid = shares[pid].clone();
        handles.push(tokio::spawn(async move {
            let mut results = Vec::with_capacity(batch);
            for _ in 0..batch {
                let a = SecretInt::new(share_pid.clone(), K);
                let out = node.ltz_int(a, net.clone()).await.expect("ltz_int failed");
                results.push(out);
            }
            results
        }));
    }

    let mut per_party_results = Vec::with_capacity(n);
    for h in handles {
        per_party_results.push(h.await.expect("task panicked"));
    }

    for i in 0..batch {
        let outputs: Vec<_> = per_party_results.iter().map(|r| r[i].clone()).collect();
        let bit = reconstruct_bit(outputs, n, t).await;
        assert!(bit, "ltz_int({x}) call {i} should be true (negative)");
    }

    let bytes = tally.bytes_sent.load(Ordering::Relaxed);
    println!(
        "MEASURE f_side_op=ltz n={n} t={t} batch={batch} bytes_sent={bytes} bytes_per_op={:.1}",
        bytes as f64 / batch as f64
    );
}

async fn measure_eqz_batch(n: usize, t: usize, batch: usize) {
    setup_tracing();
    let config = FakeNetworkConfig::new(512);
    let (inner, receivers, _) = FakeInnerNetwork::new(n, None, config);
    let tally = Arc::new(ByteTally::default());
    let network: Vec<Arc<CountingNet<FakeNetwork>>> = (0..n)
        .map(|id| {
            Arc::new(CountingNet {
                inner: FakeNetwork::new(id, inner.clone()),
                tally: Arc::clone(&tally),
            })
        })
        .collect();

    let opts = HoneyBadgerMPCNodeOpts::new(n, t, 778, crate::utils::test_utils::unused_precision(), 40, Duration::from_secs(60)).unwrap();
    let mut nodes: Vec<Node> = (0..n)
        .map(|id| {
            <Node as MPCProtocol<Fr, RobustShare<Fr>, CountingNet<FakeNetwork>>>::setup(
                id,
                opts.clone(),
                vec![],
            )
            .unwrap()
        })
        .collect();
    for node in nodes.iter_mut() {
        node.params.add_eqz_ops(K, batch);
    }

    receive::<Fr, Avid<SessionId>, RobustShare<Fr>, CountingNet<FakeNetwork>>(
        receivers,
        nodes.clone(),
        network.clone(),
        None,
    );

    let x: i128 = 5; // small non-zero, fits any K >= 3
    // See measure_ltz_batch: one sharing of `x`, split n ways.
    let shares = share_i128(x, n, t);
    let mut handles = Vec::new();
    for pid in 0..n {
        let mut node = nodes[pid].clone();
        let net = network[pid].clone();
        let share_pid = shares[pid].clone();
        handles.push(tokio::spawn(async move {
            let mut results = Vec::with_capacity(batch);
            for _ in 0..batch {
                let a = SecretInt::new(share_pid.clone(), K);
                let out = node.eqz_int(a, net.clone()).await.expect("eqz_int failed");
                results.push(out);
            }
            results
        }));
    }

    let mut per_party_results = Vec::with_capacity(n);
    for h in handles {
        per_party_results.push(h.await.expect("task panicked"));
    }

    for i in 0..batch {
        let outputs: Vec<_> = per_party_results.iter().map(|r| r[i].clone()).collect();
        let bit = reconstruct_bit(outputs, n, t).await;
        assert!(!bit, "eqz_int({x}) call {i} should be false (non-zero)");
    }

    let bytes = tally.bytes_sent.load(Ordering::Relaxed);
    println!(
        "MEASURE f_side_op=eqz n={n} t={t} batch={batch} bytes_sent={bytes} bytes_per_op={:.1}",
        bytes as f64 / batch as f64
    );
}

macro_rules! f_side_suite {
    ($name_ltz:ident, $name_eqz:ident, $n:expr, $t:expr, $batch:expr) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        #[ignore = "measurement harness; run explicitly with --ignored"]
        async fn $name_ltz() {
            measure_ltz_batch($n, $t, $batch).await;
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        #[ignore = "measurement harness; run explicitly with --ignored"]
        async fn $name_eqz() {
            measure_eqz_batch($n, $t, $batch).await;
        }
    };
}

f_side_suite!(measured_ltz_batch1_n10, measured_eqz_batch1_n10, 10, 3, 1);
f_side_suite!(measured_ltz_batch10_n10, measured_eqz_batch10_n10, 10, 3, 10);
f_side_suite!(measured_ltz_batch50_n10, measured_eqz_batch50_n10, 10, 3, 50);
f_side_suite!(measured_ltz_batch200_n10, measured_eqz_batch200_n10, 10, 3, 200);

// ── Offline (preprocessing generation) vs online (the protocol itself) split ──────────────────
//
// Every measurement above tallies BOTH phases together, since `ltz_int`/`eqz_int` triggers
// preprocessing lazily on first use. This splits them: call `run_preprocessing` explicitly first
// (reading the tally at that checkpoint = offline bytes), then run the online calls (the further
// delta = online bytes).

async fn measure_ltz_split(n: usize, t: usize, batch: usize) {
    setup_tracing();
    let config = FakeNetworkConfig::new(512);
    let (inner, receivers, _) = FakeInnerNetwork::new(n, None, config);
    let tally = Arc::new(ByteTally::default());
    let network: Vec<Arc<CountingNet<FakeNetwork>>> = (0..n)
        .map(|id| {
            Arc::new(CountingNet {
                inner: FakeNetwork::new(id, inner.clone()),
                tally: Arc::clone(&tally),
            })
        })
        .collect();

    let opts = HoneyBadgerMPCNodeOpts::new(
        n,
        t,
        779,
        crate::utils::test_utils::unused_precision(),
        40,
        Duration::from_secs(60),
    )
    .unwrap();
    let mut nodes: Vec<Node> = (0..n)
        .map(|id| {
            <Node as MPCProtocol<Fr, RobustShare<Fr>, CountingNet<FakeNetwork>>>::setup(
                id,
                opts.clone(),
                vec![],
            )
            .unwrap()
        })
        .collect();
    for node in nodes.iter_mut() {
        node.params.add_ltz_ops(K, batch);
    }

    receive::<Fr, Avid<SessionId>, RobustShare<Fr>, CountingNet<FakeNetwork>>(
        receivers,
        nodes.clone(),
        network.clone(),
        None,
    );

    // Phase 1: offline. Explicitly run preprocessing to completion for every party before any
    // online call exists to trigger it lazily.
    let mut prep_handles = Vec::new();
    for pid in 0..n {
        let mut node = nodes[pid].clone();
        let net = network[pid].clone();
        prep_handles.push(tokio::spawn(async move {
            let mut rng = ark_std::rand::rngs::StdRng::from_rng(ark_std::rand::rngs::OsRng).unwrap();
            <Node as PreprocessingMPCProtocol<Fr, RobustShare<Fr>, CountingNet<FakeNetwork>>>::run_preprocessing(
                &mut node, net, &mut rng,
            )
            .await
            .expect("run_preprocessing failed")
        }));
    }
    for h in prep_handles {
        h.await.expect("preprocessing task panicked");
    }
    let offline_bytes = tally.bytes_sent.load(Ordering::Relaxed);

    // Phase 2: online. The pool is already full, so no further preprocessing should trigger.
    let x: i128 = -5;
    let shares = share_i128(x, n, t);
    let mut handles = Vec::new();
    for pid in 0..n {
        let mut node = nodes[pid].clone();
        let net = network[pid].clone();
        let share_pid = shares[pid].clone();
        handles.push(tokio::spawn(async move {
            let mut results = Vec::with_capacity(batch);
            for _ in 0..batch {
                let a = SecretInt::new(share_pid.clone(), K);
                results.push(node.ltz_int(a, net.clone()).await.expect("ltz_int failed"));
            }
            results
        }));
    }
    let mut per_party_results = Vec::with_capacity(n);
    for h in handles {
        per_party_results.push(h.await.expect("task panicked"));
    }
    for i in 0..batch {
        let outputs: Vec<_> = per_party_results.iter().map(|r| r[i].clone()).collect();
        assert!(reconstruct_bit(outputs, n, t).await, "ltz_int({x}) call {i} should be true");
    }

    let total_bytes = tally.bytes_sent.load(Ordering::Relaxed);
    let online_bytes = total_bytes - offline_bytes;
    println!(
        "MEASURE f_side_op=ltz_split n={n} t={t} batch={batch} offline_bytes={offline_bytes} \
         online_bytes={online_bytes} total_bytes={total_bytes} offline_pct={:.1}",
        100.0 * offline_bytes as f64 / total_bytes as f64
    );
}

async fn measure_eqz_split(n: usize, t: usize, batch: usize) {
    setup_tracing();
    let config = FakeNetworkConfig::new(512);
    let (inner, receivers, _) = FakeInnerNetwork::new(n, None, config);
    let tally = Arc::new(ByteTally::default());
    let network: Vec<Arc<CountingNet<FakeNetwork>>> = (0..n)
        .map(|id| {
            Arc::new(CountingNet {
                inner: FakeNetwork::new(id, inner.clone()),
                tally: Arc::clone(&tally),
            })
        })
        .collect();

    let opts = HoneyBadgerMPCNodeOpts::new(
        n,
        t,
        780,
        crate::utils::test_utils::unused_precision(),
        40,
        Duration::from_secs(60),
    )
    .unwrap();
    let mut nodes: Vec<Node> = (0..n)
        .map(|id| {
            <Node as MPCProtocol<Fr, RobustShare<Fr>, CountingNet<FakeNetwork>>>::setup(
                id,
                opts.clone(),
                vec![],
            )
            .unwrap()
        })
        .collect();
    for node in nodes.iter_mut() {
        node.params.add_eqz_ops(K, batch);
    }

    receive::<Fr, Avid<SessionId>, RobustShare<Fr>, CountingNet<FakeNetwork>>(
        receivers,
        nodes.clone(),
        network.clone(),
        None,
    );

    let mut prep_handles = Vec::new();
    for pid in 0..n {
        let mut node = nodes[pid].clone();
        let net = network[pid].clone();
        prep_handles.push(tokio::spawn(async move {
            let mut rng = ark_std::rand::rngs::StdRng::from_rng(ark_std::rand::rngs::OsRng).unwrap();
            <Node as PreprocessingMPCProtocol<Fr, RobustShare<Fr>, CountingNet<FakeNetwork>>>::run_preprocessing(
                &mut node, net, &mut rng,
            )
            .await
            .expect("run_preprocessing failed")
        }));
    }
    for h in prep_handles {
        h.await.expect("preprocessing task panicked");
    }
    let offline_bytes = tally.bytes_sent.load(Ordering::Relaxed);

    let x: i128 = 5;
    let shares = share_i128(x, n, t);
    let mut handles = Vec::new();
    for pid in 0..n {
        let mut node = nodes[pid].clone();
        let net = network[pid].clone();
        let share_pid = shares[pid].clone();
        handles.push(tokio::spawn(async move {
            let mut results = Vec::with_capacity(batch);
            for _ in 0..batch {
                let a = SecretInt::new(share_pid.clone(), K);
                results.push(node.eqz_int(a, net.clone()).await.expect("eqz_int failed"));
            }
            results
        }));
    }
    let mut per_party_results = Vec::with_capacity(n);
    for h in handles {
        per_party_results.push(h.await.expect("task panicked"));
    }
    for i in 0..batch {
        let outputs: Vec<_> = per_party_results.iter().map(|r| r[i].clone()).collect();
        assert!(!reconstruct_bit(outputs, n, t).await, "eqz_int({x}) call {i} should be false");
    }

    let total_bytes = tally.bytes_sent.load(Ordering::Relaxed);
    let online_bytes = total_bytes - offline_bytes;
    println!(
        "MEASURE f_side_op=eqz_split n={n} t={t} batch={batch} offline_bytes={offline_bytes} \
         online_bytes={online_bytes} total_bytes={total_bytes} offline_pct={:.1}",
        100.0 * offline_bytes as f64 / total_bytes as f64
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement harness; run explicitly with --ignored"]
async fn measured_ltz_split_n10() {
    measure_ltz_split(10, 3, 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement harness; run explicitly with --ignored"]
async fn measured_eqz_split_n10() {
    measure_eqz_split(10, 3, 1).await;
}

// ── Online-only amortization sweep ────────────────────────────────────────────
//
// Does F's ONLINE per-op cost drop with batch size the way its combined cost does, or is the
// amortization all in preprocessing? The split functions already take `batch`; these sweep it.
// LTZ stops at 10: generating 50+ LTZ ops' preprocessing in one declared workload still hits the
// PreMulC session cap (`PreMulCError(LimitError)`), a separate issue from the fixed RandBit cap.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement harness; run explicitly with --ignored"]
async fn measured_ltz_split_batch10_n10() {
    measure_ltz_split(10, 3, 10).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement harness; run explicitly with --ignored"]
async fn measured_eqz_split_batch10_n10() {
    measure_eqz_split(10, 3, 10).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement harness; run explicitly with --ignored"]
async fn measured_eqz_split_batch50_n10() {
    measure_eqz_split(10, 3, 50).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement harness; run explicitly with --ignored"]
async fn measured_eqz_split_batch200_n10() {
    measure_eqz_split(10, 3, 200).await;
}
