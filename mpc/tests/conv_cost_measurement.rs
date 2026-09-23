//! **Measured** wire cost of A2B and B2A, and of the preprocessing each spends.
//!
//! Every cost figure in the share-conversion work so far was *derived*: constants read out of the
//! code (`A2BNode::gf_triples_per_conversion`, `rand_bits_per_dabit`, the AND counts) multiplied
//! through the opening-cost formulas `O1 = 2n/(t+1)` and `O2 = 2n/(2t+1)`. Nothing had been
//! observed on the wire. This harness observes it.
//!
//! Runs are `#[ignore]`d **and** behind the non-default `statistics` feature, so neither a default
//! `cargo test` nor CI picks them up:
//!
//! ```text
//! cargo test -p stoffelcrypto --features statistics --test conv_cost_measurement \
//!     --release -- --ignored --nocapture --test-threads=1
//! ```
//!
//! Each test prints `MEASURE ...` lines of `key=value` pairs. The groups are
//! `measured_cost_n*` (one A2B and one B2A end to end, split preprocessing vs online),
//! `measured_rounds_{a2b,b2a}_n*` (round counts), `measured_gf_prss_n*` and `measured_gf_dealt_n*`
//! (GF Beaver triple cost from each source), `dealt_gf_random_share_generation_stalls_above_a_batch_size`
//! (a liveness gap this walked into), and `message_framing_and_per_element_cost`, which is the only
//! one that is not `#[ignore]`d because it is instantaneous.
//!
//! # What is measured, and why it does not depend on machine load
//!
//! Two instruments, stacked on one `FakeNetwork` mesh:
//!
//! * [`stoffelcrypto::honeybadger::statistics::CountingNetwork`] — the repo's own wrapper, sharing
//!   each node's `NodeStatisticsCounters`. It gives `bytes_sent` (counting a broadcast once per
//!   recipient, which is the convention the derived model uses) and `bytes_received`, plus the
//!   per-subprotocol message breakdown `statistics_snapshot()` prints.
//! * `WireTally`, defined here, wrapping the counting network. It separates *unicast* from
//!   *broadcast* so the self-delivered copy of a broadcast can be subtracted, counts messages
//!   (`CountingNetwork` classifies only the subprotocols that predate the GF and conversion work,
//!   so `GfMult`/`GfBatchRecon`/`DaBit` messages are invisible to its per-type counters), and
//!   carries the Lamport clock below.
//!
//! Rounds come from a **second** instrument, and the two must not be confused.
//!
//! The `rounds` field of every `Tally` below is a Lamport clock: each node keeps a logical clock,
//! a message is stamped with its sender's clock at send time, and on delivery the receiver sets
//! `clock = max(clock, stamp+1)` *before* `process` runs. Stamping happens in a side table keyed by
//! the message bytes rather than in the message, so nothing on the wire changes and no byte figure
//! is perturbed. It is only an **upper bound**, and a loose one: a party's `n` sends in one opening
//! burst are separate `net.send` calls, the receive task can raise that party's clock between two
//! of them, and the inflation compounds across waves. On B2A's single two-round opening it reads
//! 3 to 5. Treat it as a smoke signal, never as a round count.
//!
//! The round counts that are *reported* come from `measured_rounds_*`, which run one conversion
//! under turmoil at a fixed one-way latency and read the simulated elapsed time. See the section
//! at the bottom of this file.
//!
//! Byte figures are a function of the protocol transcript, not of scheduling, so they are
//! unaffected by machine load; so is turmoil's simulated clock. No wall-clock figure is reported.
//!
//! # A2B's online figure is a LOWER BOUND, and two mechanisms move it
//!
//! * **Data dependence.** A2B's circuit plan depends on the mask it opens, which is fresh
//!   preprocessing each time, so the realised AND count moves inside the `[642, 695]` band the
//!   cost model brackets. Take the median of repeats.
//! * **Snapshot truncation, which is the larger of the two.** `run_a2b` returns as soon as the
//!   *local* node holds its output shares, and the tally is read immediately after. A party whose
//!   last broadcast has not yet issued is booked short, so the transcript is truncated rather
//!   than mismodelled. It shows up as a non-structural message count: the online `GfMult` row
//!   reads 25 / 46 / 66 / 88 messages at `n = 4/7/10/13` where the structural figure — 7 layers,
//!   one all-to-all wave each — is 28 / 49 / 70 / 91, i.e. 3-11% short, and bytes track messages
//!   almost linearly. `conv_cost_model::and_layer_cost` awaits *every* party before reading its
//!   ledger and reproduces the model at 0.000000% on all 168 configurations; that is the control
//!   showing the mechanism is the snapshot point and not a missing term.
//!
//! So the A2B totals printed here understate by roughly 5-10%. Quote them as lower bounds, or
//! quote the model in `conv_cost_model.rs` applied to the measured layer widths.
#![cfg(feature = "statistics")]

pub mod utils;

use crate::utils::test_utils::{fan_in_inboxes, setup_quiet_tracing};
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use async_trait::async_trait;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use stoffelcrypto::{
    common::{
        convert::{bit_to_binary, canonical_bits, field_bit_width},
        gf2k::field::{BinaryField, Gf256},
        gf2k::share::GfShare,
        math::goldilocks::GoldilocksField,
        rbc::rbc::Avid,
        types::fixed::FixedPointPrecision,
        ConversionPreprocessingProtocol, GfPreprocessingMPCProtocol, MPCProtocol,
        SecretSharingScheme, ShareConversionProtocol,
    },
    honeybadger::{
        a2b::a2b::A2BNode, dabit::edabit::EdaBitFilterNode,
        robust_interpolate::robust_interpolate::RobustShare, statistics::CountingNetwork,
        HoneyBadgerMPCNode, HoneyBadgerMPCNodeOpts, SessionId, MIN_STATISTICAL_SECURITY,
    },
};
use stoffelmpc_network::fake_network::{
    FakeInnerNetwork, FakeNetwork, FakeNetworkConfig, SenderId,
};
use stoffelnet::network_utils::{ClientId, Network, NetworkError, PartyId, VerifiedOrdering};

type F = GoldilocksField;
type K = Gf256;
type Node = HoneyBadgerMPCNode<F, Avid<SessionId>>;
type Net = WireTally<CountingNetwork<FakeNetwork>>;

/// Whole degree-`2t` opening groups in the two GF triple batches the marginal cost is read from.
///
/// Deliberately small. A single dealt batch of all 695 triples an A2B spends does **not** complete
/// on this mesh — see `dealt_gf_triple_generation_does_not_scale_to_one_whole_a2b` — so the dealt
/// figure has to come from batches that do, and the PRSS figure is taken at the same sizes so the
/// two are comparable. `measured_cost_n*` separately measures the PRSS path at the full 695.
const GF_BATCH_GROUPS_SMALL: usize = 4;
const GF_BATCH_GROUPS_LARGE: usize = 12;

/// Per-session timeout for the dealt GF triple path, which does not complete at every `n`.
///
/// Small by default so that a stall is reported quickly rather than hanging the run. Raise it with
/// `CONV_DEALT_TIMEOUT_SECS` to give a slow-but-live dealt run more room before concluding it is
/// stuck.
fn dealt_timeout_secs() -> u64 {
    std::env::var("CONV_DEALT_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60)
}

/// Attempts per dealt batch. The stall is intermittent at `n = 4`, so one DNF proves nothing.
const DEALT_ATTEMPTS: usize = 3;

// ── Lamport stamping side table ──────────────────────────────────────────────

/// Maps a message's byte hash to the sender's logical clock at send time.
///
/// Keyed by content rather than by identity because `FakeNetwork` moves opaque `Vec<u8>` and there
/// is nowhere to attach metadata without changing the wire. Two *different* messages colliding
/// here would merge two rounds into one, i.e. under-count; a 64-bit content hash makes that
/// negligible, and `max` on insert makes a genuinely repeated payload take its latest round.
#[derive(Default)]
struct Stamps(Mutex<HashMap<u64, u64>>);

fn digest(bytes: &[u8]) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut h);
    h.finish()
}

impl Stamps {
    fn put(&self, bytes: &[u8], clock: u64) {
        let mut map = self.0.lock().unwrap();
        let slot = map.entry(digest(bytes)).or_insert(0);
        *slot = (*slot).max(clock);
    }
    fn get(&self, bytes: &[u8]) -> u64 {
        *self.0.lock().unwrap().get(&digest(bytes)).unwrap_or(&0)
    }
    fn clear(&self) {
        self.0.lock().unwrap().clear();
    }
}

// ── per-party wire counters ──────────────────────────────────────────────────

/// `WrappedMessage` variants, in declaration order — which is the bincode wire format, since the
/// enum carries no version tag and is documented as append-only. The first four bytes of every
/// serialized message are this index under `bincode::serialize`'s default u32 variant encoding, so
/// a message can be attributed to its subprotocol without deserializing it.
const VARIANTS: [&str; 17] = [
    "RanDouSha",
    "Rbc",
    "BatchRecon",
    "Input",
    "RanSha",
    "Dousha",
    "Output",
    "PRandInt",
    "Mult",
    "Trunc",
    "ZeroSha",
    "GfRansha",
    "GfBatchRecon",
    "GfDousha",
    "GfRanDouSha",
    "GfMult",
    "DaBit",
];

fn variant_of(bytes: &[u8]) -> usize {
    if bytes.len() < 4 {
        return VARIANTS.len();
    }
    let idx = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    idx.min(VARIANTS.len())
}

#[derive(Default, Debug)]
struct Wire {
    unicast_msgs: AtomicU64,
    unicast_bytes: AtomicU64,
    broadcast_calls: AtomicU64,
    /// Payload bytes of one copy of each broadcast; multiply by `n` or `n - 1` as wanted.
    broadcast_bytes: AtomicU64,
    recv_msgs: AtomicU64,
    recv_bytes: AtomicU64,
    clock: AtomicU64,
    max_clock: AtomicU64,
    /// Bytes and messages per `WrappedMessage` variant, `n`-weighted for a broadcast. One extra
    /// slot for anything that does not parse as a variant index.
    by_variant_bytes: [AtomicU64; 18],
    by_variant_msgs: [AtomicU64; 18],
}

impl Wire {
    fn bump_to(&self, stamp: u64) {
        let next = stamp + 1;
        let mut cur = self.clock.load(Ordering::SeqCst);
        while cur < next {
            match self
                .clock
                .compare_exchange(cur, next, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => break,
                Err(seen) => cur = seen,
            }
        }
        let now = self.clock.load(Ordering::SeqCst);
        let mut hi = self.max_clock.load(Ordering::SeqCst);
        while hi < now {
            match self
                .max_clock
                .compare_exchange(hi, now, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => break,
                Err(seen) => hi = seen,
            }
        }
    }
    fn attribute(&self, message: &[u8], copies: u64) {
        let v = variant_of(message);
        self.by_variant_bytes[v].fetch_add(message.len() as u64 * copies, Ordering::Relaxed);
        self.by_variant_msgs[v].fetch_add(copies, Ordering::Relaxed);
    }

    fn reset_clock(&self) {
        self.clock.store(0, Ordering::SeqCst);
        self.max_clock.store(0, Ordering::SeqCst);
    }
}

// ── the network wrapper ──────────────────────────────────────────────────────

/// Wraps `CountingNetwork` and records what it cannot: unicast vs broadcast, message counts for
/// the GF and conversion subprotocols, and the Lamport stamp.
pub struct WireTally<N: Network> {
    inner: N,
    wire: Arc<Wire>,
    stamps: Arc<Stamps>,
}

impl<N: Network> WireTally<N> {
    fn new(inner: N, wire: Arc<Wire>, stamps: Arc<Stamps>) -> Self {
        Self {
            inner,
            wire,
            stamps,
        }
    }
}

#[async_trait]
impl<N: Network + Send + Sync> Network for WireTally<N> {
    type NodeType = N::NodeType;
    type NetworkConfig = N::NetworkConfig;

    async fn send(&self, recipient: PartyId, message: &[u8]) -> Result<usize, NetworkError> {
        self.wire.unicast_msgs.fetch_add(1, Ordering::Relaxed);
        self.wire
            .unicast_bytes
            .fetch_add(message.len() as u64, Ordering::Relaxed);
        self.wire.attribute(message, 1);
        self.stamps
            .put(message, self.wire.clock.load(Ordering::SeqCst));
        self.inner.send(recipient, message).await
    }

    async fn broadcast(&self, message: &[u8]) -> Result<usize, NetworkError> {
        self.wire.broadcast_calls.fetch_add(1, Ordering::Relaxed);
        self.wire
            .broadcast_bytes
            .fetch_add(message.len() as u64, Ordering::Relaxed);
        self.wire
            .attribute(message, self.inner.party_count() as u64);
        self.stamps
            .put(message, self.wire.clock.load(Ordering::SeqCst));
        self.inner.broadcast(message).await
    }

    async fn send_to_client(
        &self,
        client: ClientId,
        message: &[u8],
    ) -> Result<usize, NetworkError> {
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

// ── a measured phase ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Tally {
    /// `unicast_bytes + n * broadcast_bytes` — a broadcast charged to every recipient including
    /// the sender's own loopback copy. This is what the derived model's `2n/(t+1)` counts.
    bytes_sent_n: u64,
    /// `unicast_bytes + (n - 1) * broadcast_bytes` — the self-delivered copy of a broadcast
    /// subtracted, i.e. bytes that would actually cross a link.
    bytes_sent_wire: u64,
    /// `CountingNetwork::bytes_sent`, independent of the two above. Cross-check only.
    bytes_sent_counting: u64,
    bytes_received: u64,
    msgs_sent_n: u64,
    msgs_received: u64,
    /// Lamport-clock upper bound on the phase's sequential rounds — see the module header. Not a
    /// round count; `measured_rounds_*` is where round counts come from.
    rounds: u64,
    /// `n`-weighted bytes and messages per `WrappedMessage` variant.
    variant_bytes: [u64; 18],
    variant_msgs: [u64; 18],
}

impl Tally {
    fn plus(&self, other: &Tally) -> Tally {
        Tally {
            bytes_sent_n: self.bytes_sent_n + other.bytes_sent_n,
            bytes_sent_wire: self.bytes_sent_wire + other.bytes_sent_wire,
            bytes_sent_counting: self.bytes_sent_counting + other.bytes_sent_counting,
            bytes_received: self.bytes_received + other.bytes_received,
            msgs_sent_n: self.msgs_sent_n + other.msgs_sent_n,
            msgs_received: self.msgs_received + other.msgs_received,
            rounds: self.rounds + other.rounds,
            variant_bytes: std::array::from_fn(|v| self.variant_bytes[v] + other.variant_bytes[v]),
            variant_msgs: std::array::from_fn(|v| self.variant_msgs[v] + other.variant_msgs[v]),
        }
    }

    fn per_party(&self, n: usize) -> f64 {
        self.bytes_sent_n as f64 / n as f64
    }
    fn per_party_wire(&self, n: usize) -> f64 {
        self.bytes_sent_wire as f64 / n as f64
    }
}

struct Rig {
    n: usize,
    nodes: Vec<Node>,
    nets: Vec<Arc<Net>>,
    wires: Vec<Arc<Wire>>,
    stamps: Arc<Stamps>,
}

impl Rig {
    fn new(
        n: usize,
        t: usize,
        instance_id: u32,
        configure: impl Fn(&mut HoneyBadgerMPCNodeOpts),
    ) -> Self {
        let mut params = HoneyBadgerMPCNodeOpts::new(
            n,
            t,
            0,
            0,
            instance_id,
            0,
            0,
            conv_precision(),
            MIN_STATISTICAL_SECURITY,
            Duration::from_secs(1800),
            0,
            0,
        )
        .unwrap();
        configure(&mut params);

        let nodes: Vec<Node> = (0..n)
            .map(|id| {
                <Node as MPCProtocol<F, RobustShare<F>, Net>>::setup(id, params.clone(), vec![])
                    .unwrap()
            })
            .collect();

        // 4096-deep channels: the batched GF waves at n = 13 put far more than the 500 the shared
        // `test_setup` uses in flight at once, and a full channel deadlocks rather than slows.
        let (inner, receivers, _) =
            FakeInnerNetwork::new(n, Some(vec![]), FakeNetworkConfig::new(500));

        let stamps = Arc::new(Stamps::default());
        let wires: Vec<Arc<Wire>> = (0..n).map(|_| Arc::new(Wire::default())).collect();
        let nets: Vec<Arc<Net>> = (0..n)
            .map(|id| {
                let fake = FakeNetwork::new(id, inner.clone());
                let counting = nodes[id].counting_network(fake);
                Arc::new(WireTally::new(counting, wires[id].clone(), stamps.clone()))
            })
            .collect();

        spawn_receivers(receivers, &nodes, &nets, &wires, &stamps);

        Rig {
            n,
            nodes,
            nets,
            wires,
            stamps,
        }
    }

    fn mark(&self) {
        for w in &self.wires {
            w.reset_clock();
        }
        self.stamps.clear();
    }

    /// Totals since the last `mark`, over every party.
    fn take(&self, base: &Raw) -> Tally {
        let now = self.raw();
        let n = self.n as u64;
        let uc = now.unicast_bytes - base.unicast_bytes;
        let bc = now.broadcast_bytes - base.broadcast_bytes;
        Tally {
            bytes_sent_n: uc + n * bc,
            bytes_sent_wire: uc + (n - 1) * bc,
            bytes_sent_counting: now.counting_sent - base.counting_sent,
            bytes_received: now.recv_bytes - base.recv_bytes,
            msgs_sent_n: (now.unicast_msgs - base.unicast_msgs)
                + n * (now.broadcast_calls - base.broadcast_calls),
            msgs_received: now.recv_msgs - base.recv_msgs,
            rounds: self
                .wires
                .iter()
                .map(|w| w.max_clock.load(Ordering::SeqCst))
                .max()
                .unwrap_or(0),
            variant_bytes: std::array::from_fn(|v| now.variant_bytes[v] - base.variant_bytes[v]),
            variant_msgs: std::array::from_fn(|v| now.variant_msgs[v] - base.variant_msgs[v]),
        }
    }

    fn raw(&self) -> Raw {
        let mut r = Raw::default();
        for (i, w) in self.wires.iter().enumerate() {
            r.unicast_msgs += w.unicast_msgs.load(Ordering::SeqCst);
            r.unicast_bytes += w.unicast_bytes.load(Ordering::SeqCst);
            r.broadcast_calls += w.broadcast_calls.load(Ordering::SeqCst);
            r.broadcast_bytes += w.broadcast_bytes.load(Ordering::SeqCst);
            r.recv_msgs += w.recv_msgs.load(Ordering::SeqCst);
            r.recv_bytes += w.recv_bytes.load(Ordering::SeqCst);
            r.counting_sent += self.nodes[i].statistics_snapshot().bytes_sent;
            for v in 0..18 {
                r.variant_bytes[v] += w.by_variant_bytes[v].load(Ordering::SeqCst);
                r.variant_msgs[v] += w.by_variant_msgs[v].load(Ordering::SeqCst);
            }
        }
        r
    }
}

#[derive(Default, Clone, Copy)]
struct Raw {
    unicast_msgs: u64,
    unicast_bytes: u64,
    broadcast_calls: u64,
    broadcast_bytes: u64,
    recv_msgs: u64,
    recv_bytes: u64,
    counting_sent: u64,
    variant_bytes: [u64; 18],
    variant_msgs: [u64; 18],
}

fn spawn_receivers(
    mut receivers: Vec<Vec<tokio::sync::mpsc::Receiver<Vec<u8>>>>,
    nodes: &[Node],
    nets: &[Arc<Net>],
    wires: &[Arc<Wire>],
    stamps: &Arc<Stamps>,
) {
    let n = nodes.len();
    for i in 0..n {
        let inbox_row = receivers.remove(0);
        let mut node = nodes[i].clone();
        let net = nets[i].clone();
        let wire = wires[i].clone();
        let stamps = stamps.clone();
        let labelled: Vec<_> = inbox_row
            .into_iter()
            .enumerate()
            .filter(|(idx, _)| *idx < n)
            .map(|(idx, rx)| (SenderId::Node(idx), rx))
            .collect();
        let mut merged = fan_in_inboxes(labelled);
        tokio::spawn(async move {
            while let Some((sender, raw)) = merged.recv().await {
                wire.recv_msgs.fetch_add(1, Ordering::Relaxed);
                wire.recv_bytes
                    .fetch_add(raw.len() as u64, Ordering::Relaxed);
                // Before `process`, so any send this message causes carries the raised clock.
                wire.bump_to(stamps.get(&raw));
                let from = match sender {
                    SenderId::Node(i) => i,
                    SenderId::Client(i) => i,
                };
                if let Err(e) = node.process(from, raw, net.clone()).await {
                    tracing::error!("node {i} failed to process from {from:?}: {e:?}");
                }
            }
        });
    }
}

// ── drivers ─────────────────────────────────────────────────────────────────

async fn drive<T, Fut>(rig: &mut Rig, f: impl Fn(Node, Arc<Net>, usize) -> Fut) -> Vec<T>
where
    Fut: std::future::Future<Output = (Node, T)> + Send + 'static,
    T: Send + 'static,
{
    let mut handles = Vec::new();
    for pid in 0..rig.n {
        handles.push(tokio::spawn(f(
            rig.nodes[pid].clone(),
            rig.nets[pid].clone(),
            pid,
        )));
    }
    let mut out = Vec::new();
    for (pid, h) in handles.into_iter().enumerate() {
        let (node, val) = h.await.unwrap();
        rig.nodes[pid] = node;
        out.push(val);
    }
    out
}

/// Runs one phase: reset clocks, snapshot, run, tally.
macro_rules! phase {
    ($rig:expr, $body:expr) => {{
        $rig.mark();
        let base = $rig.raw();
        $body;
        $rig.take(&base)
    }};
}

fn report(label: &str, n: usize, t: usize, tag: &str, ta: &Tally, unit: f64) {
    println!(
        "MEASURE cfg={label} n={n} t={t} phase={tag} bytes_sent_n={} bytes_sent_wire={} \
         bytes_counting={} bytes_recv={} msgs_sent={} msgs_recv={} rounds={} \
         per_party_n={:.3} per_party_wire={:.3} per_unit={:.4}",
        ta.bytes_sent_n,
        ta.bytes_sent_wire,
        ta.bytes_sent_counting,
        ta.bytes_received,
        ta.msgs_sent_n,
        ta.msgs_received,
        ta.rounds,
        ta.per_party(n),
        ta.per_party_wire(n),
        if unit > 0.0 {
            ta.per_party(n) / unit
        } else {
            0.0
        },
    );
    let mut split = String::new();
    for v in 0..18 {
        if ta.variant_msgs[v] == 0 {
            continue;
        }
        let name = VARIANTS.get(v).copied().unwrap_or("Unparsed");
        split.push_str(&format!(
            " {name}={:.1}/{:.1}",
            ta.variant_bytes[v] as f64 / n as f64,
            ta.variant_msgs[v] as f64 / n as f64,
        ));
    }
    println!("MEASURE cfg={label} n={n} t={t} phase={tag} split_bytes_per_msgs_per_party{split}");
}

/// Precision the PRSS key setup can actually carry on Goldilocks.
///
/// `setup_prss_keys` derives its RISS batch width from `params.mask_bits() = (2k - f) + kappa`,
/// and `PRandIntNode` refuses a mask wider than
/// `MODULUS_BIT_SIZE - 2 - ceil(log2 n) - ceil(log2 C(n,t))`. On a 64-bit field at `n = 13, t = 4`
/// that leaves `2k - f <= 8`, so the shared `unused_precision()` (32/16, i.e. `2k - f = 48`) —
/// which is fine on the 255-bit BLS scalar field every other PRSS test uses — fails here with
/// `SurpassedFieldCapacity`. Nothing on the conversion path masks a fixed-point value, so the
/// figure only has to be legal; `5/4` gives `mask_bits = 46` and clears the bound at every `n`
/// measured.
///
/// It is also cost-neutral for what is measured: mask width changes how many keystream bytes a
/// PRSS derivation consumes locally, not how many openings go on the wire.
fn conv_precision() -> FixedPointPrecision {
    FixedPointPrecision::new(5, 4)
}

fn field_shares(n: usize, t: usize, v: F, rng: &mut StdRng) -> Vec<RobustShare<F>> {
    RobustShare::compute_shares(v, n, t, None, rng).unwrap()
}

async fn install_prss(rig: &mut Rig) -> Tally {
    let tally = phase!(rig, {
        drive(rig, |mut node, net, _| async move {
            node.setup_prss_keys(net).await.expect("prss setup");
            (node, ())
        })
        .await
    });
    for (pid, node) in rig.nodes.iter().enumerate() {
        assert!(
            node.gf_dn07_uses_prss(),
            "node {pid} has no GF PRSS source: the PRSS path would be measured vacuously"
        );
    }
    tally
}

// ── the measurements ────────────────────────────────────────────────────────

/// One 64-bit A2B and one 63-bit B2A, each end to end, split preprocessing vs online; plus the
/// GF triple cost on both the PRSS and the fully dealt path.
async fn measure(n: usize, t: usize) {
    setup_quiet_tracing();

    let width = field_bit_width::<F>();
    let b2a_width = stoffelcrypto::honeybadger::b2a::b2a::max_width::<F>();
    let per_conversion = A2BNode::<F, K>::gf_triples_per_conversion().unwrap();
    let filter_ands = EdaBitFilterNode::<F, K>::gf_doubles_per_edabit().unwrap();
    let filter_layers = EdaBitFilterNode::<F, K>::edabit_filter_layers().unwrap();
    println!(
        "MEASURE cfg=const n={n} t={t} a2b_width={width} b2a_width={b2a_width} \
         gf_triples_per_conversion={per_conversion} edabit_filter_ands={filter_ands} \
         edabit_filter_layers={filter_layers}"
    );

    // ---------------------------------------------------------------- A2B ----
    {
        let mut rig = Rig::new(n, t, 900 + n as u32, |p| {
            p.set_n_edabits(1);
            p.set_n_dabits(0);
            p.n_gf_triples = per_conversion;
            p.n_gf_random_shares = 0;
        });
        let dabits_per_edabit = rig.nodes[0].conv.dabit_gen.rand_bits_per_dabit();
        println!("MEASURE cfg=const n={n} t={t} rand_bits_per_dabit={dabits_per_edabit}");

        let setup = install_prss(&mut rig).await;
        report("a2b", n, t, "prss_key_setup", &setup, 1.0);

        let conv = phase!(rig, {
            drive(&mut rig, |mut node, net, pid| async move {
                let mut rng = StdRng::seed_from_u64(pid as u64 + 7);
                node.run_conversion_preprocessing(net, &mut rng)
                    .await
                    .expect("conversion preprocessing");
                (node, ())
            })
            .await
        });
        report("a2b", n, t, "pre_conv", &conv, width as f64);

        let gf = phase!(rig, {
            drive(&mut rig, |mut node, net, pid| async move {
                let mut rng = StdRng::seed_from_u64(pid as u64 + 17);
                node.run_gf_preprocessing(net, &mut rng)
                    .await
                    .expect("gf preprocessing");
                (node, ())
            })
            .await
        });
        let triples_made = rig.nodes[0]
            .gf_preprocessing_material
            .lock()
            .await
            .length()
            .beaver_triples;
        println!("MEASURE cfg=a2b n={n} t={t} gf_triples_generated={triples_made}");
        report("a2b", n, t, "pre_gf_prss", &gf, triples_made as f64);

        let mut rng = StdRng::seed_from_u64(n as u64);
        let value = F::from(0u64) - F::from(1u64);
        let shares = field_shares(n, t, value, &mut rng);
        let online = phase!(rig, {
            let out = drive(&mut rig, {
                let shares = shares.clone();
                move |mut node, net, pid| {
                    let x = shares[pid].clone();
                    async move {
                        let bits = node.a2b(vec![x], net).await.expect("a2b");
                        (node, bits)
                    }
                }
            })
            .await;
            // Correctness, so a cheap-because-broken run cannot masquerade as a cheap one.
            let want = canonical_bits::<F>(value, width).unwrap();
            for bit in 0..width {
                let col: Vec<GfShare<K>> = (0..n).map(|p| out[p][0][bit].clone()).collect();
                let (_, got) = GfShare::recover_secret(&col[0..=2 * t], n, t).unwrap();
                assert_eq!(got, bit_to_binary::<K>(want[bit]), "A2B bit {bit}");
            }
        });
        report("a2b", n, t, "online", &online, 1.0);

        let total = conv.plus(&gf).plus(&online);
        report("a2b", n, t, "TOTAL_excl_prss_setup", &total, 1.0);
        println!(
            "MEASURE cfg=a2b n={n} t={t} total_KiB_per_party_n={:.3} total_KiB_per_party_wire={:.3} \
             a2b_message_rounds_claimed={}",
            total.per_party(n) / 1024.0,
            total.per_party_wire(n) / 1024.0,
            rig.nodes[0].conv.a2b.message_rounds().unwrap(),
        );
    }

    // ---------------------------------------------------------------- B2A ----
    {
        let mut rig = Rig::new(n, t, 1900 + n as u32, |p| {
            p.set_n_edabits(0);
            p.set_n_dabits(b2a_width);
        });
        let setup = install_prss(&mut rig).await;
        report("b2a", n, t, "prss_key_setup", &setup, 1.0);

        let conv = phase!(rig, {
            drive(&mut rig, |mut node, net, pid| async move {
                let mut rng = StdRng::seed_from_u64(pid as u64 + 27);
                node.run_conversion_preprocessing(net, &mut rng)
                    .await
                    .expect("conversion preprocessing");
                (node, ())
            })
            .await
        });
        let dabits = rig.nodes[0]
            .conv_preprocessing_material
            .lock()
            .await
            .length()
            .dabits;
        println!("MEASURE cfg=b2a n={n} t={t} dabits_generated={dabits}");
        report("b2a", n, t, "pre_dabits", &conv, dabits as f64);

        // Every bit set: the widest payload this width can carry.
        let mut rng = StdRng::seed_from_u64(n as u64 + 100);
        let value: u64 = (1u64 << b2a_width) - 1;
        let mut columns: Vec<Vec<GfShare<K>>> = vec![Vec::new(); n];
        for _ in 0..b2a_width {
            let sh = GfShare::compute_shares(K::one(), n, t, &mut rng).unwrap();
            for p in 0..n {
                columns[p].push(sh[p].clone());
            }
        }
        let online = phase!(rig, {
            let out = drive(&mut rig, {
                let columns = columns.clone();
                move |mut node, net, pid| {
                    let bits = vec![columns[pid].clone()];
                    async move {
                        let v = node.b2a(bits, net).await.expect("b2a");
                        (node, v)
                    }
                }
            })
            .await;
            let col: Vec<RobustShare<F>> = (0..n).map(|p| out[p][0].clone()).collect();
            let (_, got) = RobustShare::recover_secret(&col[0..=2 * t], n, t).unwrap();
            assert_eq!(got, F::from(value), "B2A recomposition");
        });
        report("b2a", n, t, "online", &online, 1.0);

        let total = conv.plus(&online);
        report("b2a", n, t, "TOTAL_excl_prss_setup", &total, 1.0);
        println!(
            "MEASURE cfg=b2a n={n} t={t} total_KiB_per_party_n={:.3} total_KiB_per_party_wire={:.3}",
            total.per_party(n) / 1024.0,
            total.per_party_wire(n) / 1024.0,
        );
    }
}

/// GF Beaver triple cost, both sources, as a **marginal** figure.
///
/// Measured at two batch sizes and differenced, rather than read off one batch and divided: a
/// batch carries fixed per-session framing that a single division silently attributes to the
/// triples, and the derived model's `O2` is a marginal quantity. The totals are printed too.
///
/// The dealt path is reached by simply never establishing PRSS keys — `gf_dn07_uses_prss()`'s own
/// predicate — so this is the **fully dealt** baseline (`2 x GfRanSha` for `[a]`/`[b]` plus
/// `GfRanDouSha` for the mask). It is *not* the state immediately before this workflow's change
/// (PRSS doubles with dealt `[a]`/`[b]`); that intermediate is unreachable without editing the
/// source, and is reconstructed from `gf_ransha_only` plus the PRSS triple figure instead.
async fn measure_gf_prss(n: usize, t: usize) {
    setup_quiet_tracing();
    let group = 2 * t + 1;
    let small = GF_BATCH_GROUPS_SMALL * group;
    let large = GF_BATCH_GROUPS_LARGE * group;
    println!("MEASURE cfg=const n={n} t={t} gf_batch_small={small} gf_batch_large={large}");

    for (label, batch) in [("small", small), ("large", large)] {
        let mut rig = Rig::new(n, t, 2900 + 100 * batch as u32 + n as u32, |p| {
            p.n_gf_triples = batch;
            p.n_gf_random_shares = 0;
        });
        let setup = install_prss(&mut rig).await;
        report("gf_prss", n, t, "prss_key_setup", &setup, 1.0);
        let gf = phase!(rig, {
            drive(&mut rig, |mut node, net, pid| async move {
                let mut rng = StdRng::seed_from_u64(pid as u64 + 37);
                node.run_gf_preprocessing(net, &mut rng)
                    .await
                    .expect("gf preprocessing");
                (node, ())
            })
            .await
        });
        let made = check_triples(&rig, n, t, group, "gf_prss").await;
        println!("MEASURE cfg=gf_prss n={n} t={t} batch={label} gf_triples_generated={made}");
        report(
            "gf_prss",
            n,
            t,
            &format!("triples_{label}"),
            &gf,
            made as f64,
        );
    }

    // `[a]` and `[b]` of a *dealt* triple are two `GfRanSha` output shares. Measuring the share
    // generator on its own gives the measured `P1` the pre-change intermediate needs. Tolerant of
    // failure for the same reason the dealt triple path is: dealt `GfRanSha` does not complete at
    // every `n` — see `dealt_gf_random_share_generation_stalls_above_a_batch_size`.
    for (label, want) in [("small", 2 * small), ("large", 2 * large)] {
        let mut rig = Rig::new(n, t, 3900 + 100 * want as u32 + n as u32, |p| {
            p.n_gf_triples = 0;
            p.n_gf_random_shares = want;
            p.timeout = Duration::from_secs(dealt_timeout_secs());
        });
        let failures;
        let gf = phase!(rig, {
            failures = drive(&mut rig, |mut node, net, pid| async move {
                let mut rng = StdRng::seed_from_u64(pid as u64 + 47);
                let err = node
                    .run_gf_preprocessing(net, &mut rng)
                    .await
                    .err()
                    .map(|e| format!("{e:?}"));
                (node, err)
            })
            .await;
        });
        let failed: Vec<_> = failures.into_iter().flatten().collect();
        let made = rig.nodes[0]
            .gf_preprocessing_material
            .lock()
            .await
            .length()
            .random_shr;
        if failed.is_empty() {
            println!(
                "MEASURE cfg=gf_ransha n={n} t={t} batch={label} gf_random_shares_generated={made}"
            );
            report(
                "gf_ransha",
                n,
                t,
                &format!("ransha_{label}"),
                &gf,
                made as f64,
            );
        } else {
            println!(
                "MEASURE cfg=gf_ransha n={n} t={t} batch={label} DID_NOT_COMPLETE failures={} \
                 first_error={}",
                failed.len(),
                failed[0].replace(' ', "_")
            );
            report(
                "gf_ransha",
                n,
                t,
                &format!("ransha_{label}_DNF"),
                &gf,
                want as f64,
            );
        }
    }
}

/// The **fully dealt** GF triple path: `2 x GfRanSha` for `[a]`/`[b]` plus `GfRanDouSha` for the
/// mask, reached by simply never establishing PRSS keys — `gf_dn07_uses_prss()`'s own predicate.
///
/// This is *not* the state immediately before this workflow's change (PRSS doubles with dealt
/// `[a]`/`[b]`); that intermediate is unreachable without editing the source, and is reconstructed
/// from the `gf_ransha` figure plus the PRSS triple figure instead.
///
/// The node timeout is cut to [`dealt_timeout_secs`] and a failure is *reported*, not asserted: this
/// path does not complete at every `n` on this mesh, and a hang would take the whole measurement
/// with it.
async fn measure_gf_dealt(n: usize, t: usize) {
    setup_quiet_tracing();
    let group = 2 * t + 1;
    for (label, batch) in [
        ("small", GF_BATCH_GROUPS_SMALL * group),
        ("large", GF_BATCH_GROUPS_LARGE * group),
    ] {
        // Retried, because the stall this walks into is intermittent at `n = 4`: the same call
        // that completes on one attempt hangs on the next. A single DNF would therefore be an
        // unsound thing to report as "the dealt path does not run here".
        let mut done = false;
        for attempt in 0..DEALT_ATTEMPTS {
            let mut rig = Rig::new(
                n,
                t,
                4900 + 100 * batch as u32 + 10 * attempt as u32 + n as u32,
                |p| {
                    p.n_gf_triples = batch;
                    p.n_gf_random_shares = 0;
                    p.timeout = Duration::from_secs(dealt_timeout_secs());
                },
            );
            assert!(
                !rig.nodes[0].gf_dn07_uses_prss(),
                "no PRSS keys installed, so the dealt path must be selected"
            );
            let failures;
            let gf = phase!(rig, {
                failures = drive(&mut rig, |mut node, net, pid| async move {
                    let mut rng = StdRng::seed_from_u64(pid as u64 + 57);
                    let err = node
                        .run_gf_preprocessing(net, &mut rng)
                        .await
                        .err()
                        .map(|e| format!("{e:?}"));
                    (node, err)
                })
                .await;
            });
            let failed: Vec<_> = failures.into_iter().flatten().collect();
            if failed.is_empty() {
                let made = check_triples(&rig, n, t, group, "gf_dealt").await;
                println!(
                    "MEASURE cfg=gf_dealt n={n} t={t} batch={label} attempt={attempt} \
                     gf_triples_generated={made}"
                );
                report(
                    "gf_dealt",
                    n,
                    t,
                    &format!("triples_{label}"),
                    &gf,
                    made as f64,
                );
                done = true;
                break;
            }
            println!(
                "MEASURE cfg=gf_dealt n={n} t={t} batch={label} attempt={attempt} \
                 DID_NOT_COMPLETE failures={} first_error={}",
                failed.len(),
                failed[0].replace(' ', "_"),
            );
            report(
                "gf_dealt",
                n,
                t,
                &format!("triples_{label}_DNF_attempt{attempt}"),
                &gf,
                batch as f64,
            );
        }
        println!("MEASURE cfg=gf_dealt n={n} t={t} batch={label} completed={done}");
    }
}

/// Reconstructs one whole opening group and asserts it really is a batch of Beaver triples, so a
/// path that is cheap because it is broken cannot look cheap. Returns the pool size.
async fn check_triples(rig: &Rig, n: usize, t: usize, group: usize, tag: &str) -> usize {
    let made = rig.nodes[0]
        .gf_preprocessing_material
        .lock()
        .await
        .length()
        .beaver_triples;
    let mut per_party = Vec::with_capacity(n);
    for node in rig.nodes.iter() {
        per_party.push(
            node.gf_preprocessing_material
                .lock()
                .await
                .take_beaver_triples(group)
                .unwrap(),
        );
    }
    let mut nonzero = false;
    for i in 0..group {
        let col = |f: fn(&GfBeaverTriple<K>) -> GfShare<K>| {
            (0..n).map(|p| f(&per_party[p][i])).collect::<Vec<_>>()
        };
        let (_, a) = GfShare::recover_secret(&col(|x| x.a.clone()), n, t).unwrap();
        let (_, b) = GfShare::recover_secret(&col(|x| x.b.clone()), n, t).unwrap();
        let (_, c) = GfShare::recover_secret(&col(|x| x.mult.clone()), n, t).unwrap();
        assert_eq!(c, a * b, "{tag} triple {i} is not a triple");
        nonzero |= a != K::zero();
    }
    // `c == a * b` is satisfied vacuously by an all-zero batch, which is what a source that
    // silently derived nothing would hand back.
    assert!(
        nonzero,
        "{tag}: every [a] in the batch reconstructed to zero"
    );
    made
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement harness; run explicitly with --ignored"]
async fn measured_cost_n4() {
    measure(4, 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement harness; run explicitly with --ignored"]
async fn measured_cost_n7() {
    measure(7, 2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement harness; run explicitly with --ignored"]
async fn measured_cost_n10() {
    measure(10, 3).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement harness; run explicitly with --ignored"]
async fn measured_cost_n13() {
    measure(13, 4).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement harness; run explicitly with --ignored"]
async fn measured_gf_prss_n4() {
    measure_gf_prss(4, 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement harness; run explicitly with --ignored"]
async fn measured_gf_dealt_n4() {
    measure_gf_dealt(4, 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement harness; run explicitly with --ignored"]
async fn measured_gf_prss_n7() {
    measure_gf_prss(7, 2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement harness; run explicitly with --ignored"]
async fn measured_gf_dealt_n7() {
    measure_gf_dealt(7, 2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement harness; run explicitly with --ignored"]
async fn measured_gf_prss_n10() {
    measure_gf_prss(10, 3).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement harness; run explicitly with --ignored"]
async fn measured_gf_dealt_n10() {
    measure_gf_dealt(10, 3).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement harness; run explicitly with --ignored"]
async fn measured_gf_prss_n13() {
    measure_gf_prss(13, 4).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement harness; run explicitly with --ignored"]
async fn measured_gf_dealt_n13() {
    measure_gf_dealt(13, 4).await;
}

// ── rounds, measured on a simulated clock ────────────────────────────────────
//
// The Lamport clock above is an **upper bound**, and a loose one. A party's `n` sends in one
// opening burst are separate `net.send` calls, and the receive task can bump that party's clock
// between two of them; the later sends then carry a stamp one higher than the burst's true depth,
// and the inflation compounds across waves. Calibrate it on a protocol whose round count is not in
// doubt — B2A online is one degree-`t` batched opening, i.e. two rounds — and the measured 3..5
// says the bound runs 1.5x to 2.5x high on a two-round protocol. It cannot, therefore, be read as
// a refutation of A2B's claimed 16.
//
// What can: turmoil's simulated clock. With `min_message_latency == max_message_latency == L`,
// a party's `tokio::time::Instant::elapsed()` across the conversion is `L` times the number of
// sequential message rounds — compute costs no simulated time, so nothing else contributes. The
// drain loop breaks on a completion signal rather than a polling timeout, because an elapsed
// timeout *would* advance the simulated clock and corrupt the reading (the same care
// `mul_bench_turmoil` takes).
//
// Preprocessing is dealt here rather than generated, exactly as `convert_turmoil_test.rs` deals
// it: the question is the online round count, and preprocessing rounds would otherwise be folded
// into the same elapsed time.

use ark_ff::UniformRand;
use stoffelcrypto::honeybadger::dabit::{DaBit, EdaBit};
use stoffelcrypto::honeybadger::gf_triple_gen::GfBeaverTriple;
use stoffelmpc_network::turmoil_network::TurmoilNetwork;

/// `p = 2^64 - 2^32 + 1`.
const P: u64 = 0xFFFF_FFFF_0000_0001;
/// One-way message latency in the round simulation. Elapsed / this = rounds.
const LATENCY_MS: u64 = 100;

fn deal_dabits(n: usize, t: usize, count: usize, rng: &mut StdRng) -> Vec<Vec<DaBit<F, K>>> {
    let mut per_party: Vec<Vec<DaBit<F, K>>> = vec![Vec::new(); n];
    for index in 0..count {
        let bit = index % 2 == 0;
        let arith = RobustShare::compute_shares(F::from(bit as u64), n, t, None, rng).unwrap();
        let bin = GfShare::compute_shares(bit_to_binary::<K>(bit), n, t, rng).unwrap();
        for party in 0..n {
            per_party[party].push(DaBit::new(arith[party].clone(), bin[party].clone(), t).unwrap());
        }
    }
    per_party
}

fn deal_edabits(n: usize, t: usize, count: usize, rng: &mut StdRng) -> Vec<Vec<EdaBit<F, K>>> {
    let width = field_bit_width::<F>();
    let mut per_party: Vec<Vec<EdaBit<F, K>>> = vec![Vec::new(); n];
    for _ in 0..count {
        let r = loop {
            let candidate: u64 = ark_std::rand::Rng::gen(rng);
            if candidate < P {
                break candidate;
            }
        };
        let bits = canonical_bits::<F>(F::from(r), width).unwrap();
        let mut per_party_dabits: Vec<Vec<DaBit<F, K>>> = vec![Vec::new(); n];
        for bit in bits {
            let arith = RobustShare::compute_shares(F::from(bit as u64), n, t, None, rng).unwrap();
            let bin = GfShare::compute_shares(bit_to_binary::<K>(bit), n, t, rng).unwrap();
            for party in 0..n {
                per_party_dabits[party]
                    .push(DaBit::new(arith[party].clone(), bin[party].clone(), t).unwrap());
            }
        }
        for party in 0..n {
            per_party[party]
                .push(EdaBit::compose_full_width(&per_party_dabits[party], false).unwrap());
        }
    }
    per_party
}

fn deal_gf_triples(
    n: usize,
    t: usize,
    count: usize,
    rng: &mut StdRng,
) -> Vec<Vec<GfBeaverTriple<K>>> {
    let mut per_party: Vec<Vec<GfBeaverTriple<K>>> = vec![Vec::new(); n];
    for _ in 0..count {
        let a = K::random(rng);
        let b = K::random(rng);
        let a_s = GfShare::compute_shares(a, n, t, rng).unwrap();
        let b_s = GfShare::compute_shares(b, n, t, rng).unwrap();
        let c_s = GfShare::compute_shares(a * b, n, t, rng).unwrap();
        for party in 0..n {
            per_party[party].push(GfBeaverTriple::new(
                a_s[party].clone(),
                b_s[party].clone(),
                c_s[party].clone(),
            ));
        }
    }
    per_party
}

fn turmoil_nodes(n: usize, t: usize, instance_id: u32) -> Vec<Node> {
    let mut params = HoneyBadgerMPCNodeOpts::new(
        n,
        t,
        0,
        0,
        instance_id,
        0,
        0,
        conv_precision(),
        MIN_STATISTICAL_SECURITY,
        Duration::from_secs(3600),
        0,
        0,
    )
    .unwrap();
    params.set_n_edabits(0);
    params.set_n_dabits(0);
    (0..n)
        .map(|id| {
            <Node as MPCProtocol<F, RobustShare<F>, TurmoilNetwork>>::setup(
                id,
                params.clone(),
                vec![],
            )
            .unwrap()
        })
        .collect()
}

/// Runs one online conversion per node under a fixed one-way latency and reports
/// `elapsed / LATENCY_MS` — the sequential round count — for each.
fn measure_online_rounds(n: usize, t: usize, which: &str) {
    setup_quiet_tracing();
    let width = field_bit_width::<F>();
    let b2a_width = stoffelcrypto::honeybadger::b2a::b2a::max_width::<F>();
    let per_conversion = A2BNode::<F, K>::gf_triples_per_conversion().unwrap();
    let nodes = turmoil_nodes(n, t, 7000 + n as u32 + if which == "a2b" { 0 } else { 50 });

    let mut rng = StdRng::seed_from_u64(n as u64 * 31 + 5);
    let value = F::rand(&mut rng);
    let x_shares = RobustShare::compute_shares(value, n, t, None, &mut rng).unwrap();
    let edabits = deal_edabits(n, t, 1, &mut rng);
    let gf_triples = deal_gf_triples(n, t, per_conversion, &mut rng);
    let dabits = deal_dabits(n, t, b2a_width, &mut rng);
    let mut bit_columns: Vec<Vec<GfShare<K>>> = vec![Vec::new(); n];
    for _ in 0..b2a_width {
        let sh = GfShare::compute_shares(K::one(), n, t, &mut rng).unwrap();
        for p in 0..n {
            bit_columns[p].push(sh[p].clone());
        }
    }

    tokio::runtime::Runtime::new().unwrap().block_on(async {
        for pid in 0..n {
            nodes[pid]
                .conv_preprocessing_material
                .lock()
                .await
                .add(Some(dabits[pid].clone()), Some(edabits[pid].clone()));
            nodes[pid]
                .gf_preprocessing_material
                .lock()
                .await
                .add(Some(gf_triples[pid].clone()), None);
        }
    });

    let (mut sim, inner) = crate::utils::turmoil::turmoil_setup_with_duration(
        n,
        vec![],
        Some((LATENCY_MS, LATENCY_MS)),
        Duration::from_secs(3600),
    );
    let (tx, rx_done) = std::sync::mpsc::channel::<Result<(usize, u128), String>>();
    let (done_tx, mut done_rx) = tokio::sync::broadcast::channel::<()>(n);
    let barrier = Arc::new(tokio::sync::Barrier::new(n));
    let which = which.to_string();

    for id in 0..n {
        let inner = inner.clone();
        let node = nodes[id].clone();
        let tx = tx.clone();
        let done_tx = done_tx.clone();
        let barrier = barrier.clone();
        let x = x_shares[id].clone();
        let bits = bit_columns[id].clone();
        let which = which.clone();
        sim.host(format!("node{id}"), move || {
            let inner = inner.clone();
            let mut node = node.clone();
            let mut driver = node.clone();
            let tx = tx.clone();
            let done_tx = done_tx.clone();
            let barrier = barrier.clone();
            let x = x.clone();
            let bits = bits.clone();
            let which = which.clone();
            async move {
                let (network, mut rx) = TurmoilNetwork::new(SenderId::Node(id), inner).await;
                let net = Arc::new(network);
                barrier.wait().await;

                let net2 = net.clone();
                let (fin_tx, mut fin_rx) = tokio::sync::oneshot::channel::<()>();
                let handle = tokio::spawn(async move {
                    let t0 = tokio::time::Instant::now();
                    let outcome = if which == "a2b" {
                        driver.a2b(vec![x], net2).await.map(|_| ())
                    } else {
                        driver.b2a(vec![bits], net2).await.map(|_| ())
                    };
                    let _ = fin_tx.send(());
                    outcome.map(|_| t0.elapsed())
                });

                loop {
                    tokio::select! {
                        biased;
                        _ = &mut fin_rx => break,
                        msg = rx.recv() => match msg {
                            Some((sender, m)) => {
                                let from = match sender {
                                    SenderId::Node(i) | SenderId::Client(i) => i,
                                };
                                if let Err(e) = node.process(from, m, net.clone()).await {
                                    tracing::warn!(node = id, error = ?e, "tolerated");
                                }
                            }
                            None => break,
                        },
                    }
                }

                match handle.await {
                    Ok(Ok(elapsed)) => {
                        let _ = tx.send(Ok((id, elapsed.as_millis())));
                    }
                    Ok(Err(e)) => {
                        let _ = tx.send(Err(format!("node {id} failed: {e:?}")));
                    }
                    Err(e) => {
                        let _ = tx.send(Err(format!("node {id} join: {e:?}")));
                    }
                }
                let _ = done_tx.send(());
                Ok(())
            }
        });
    }
    drop(tx);
    drop(done_tx);
    sim.client("driver", async move {
        let mut count = 0;
        while count < n {
            if done_rx.recv().await.is_ok() {
                count += 1;
            } else {
                break;
            }
        }
        Ok(())
    });
    sim.run().unwrap();

    let results: Vec<_> = std::iter::from_fn(|| rx_done.try_recv().ok()).collect();
    assert_eq!(results.len(), n, "not every node reported");
    let mut rounds = Vec::new();
    for r in results {
        let (id, ms) = r.unwrap_or_else(|e| panic!("{e}"));
        let r = (ms as f64) / (LATENCY_MS as f64);
        println!("MEASURE cfg=rounds_{which} n={n} t={t} node={id} elapsed_ms={ms} rounds={r:.2}");
        rounds.push(r);
    }
    let max = rounds.iter().cloned().fold(0.0f64, f64::max);
    let claimed = if which == "a2b" {
        nodes[0].conv.a2b.message_rounds().unwrap() as f64
    } else {
        0.0
    };
    println!(
        "MEASURE cfg=rounds_{which} n={n} t={t} width={} max_rounds={max:.2} claimed={claimed}",
        if which == "a2b" { width } else { b2a_width }
    );
}

#[test]
#[ignore = "measurement harness; run explicitly with --ignored"]
fn measured_rounds_a2b_n4() {
    measure_online_rounds(4, 1, "a2b");
}
#[test]
#[ignore = "measurement harness; run explicitly with --ignored"]
fn measured_rounds_a2b_n7() {
    measure_online_rounds(7, 2, "a2b");
}
#[test]
#[ignore = "measurement harness; run explicitly with --ignored"]
fn measured_rounds_a2b_n10() {
    measure_online_rounds(10, 3, "a2b");
}
#[test]
#[ignore = "measurement harness; run explicitly with --ignored"]
fn measured_rounds_a2b_n13() {
    measure_online_rounds(13, 4, "a2b");
}
#[test]
#[ignore = "measurement harness; run explicitly with --ignored"]
fn measured_rounds_b2a_n4() {
    measure_online_rounds(4, 1, "b2a");
}
#[test]
#[ignore = "measurement harness; run explicitly with --ignored"]
fn measured_rounds_b2a_n7() {
    measure_online_rounds(7, 2, "b2a");
}
#[test]
#[ignore = "measurement harness; run explicitly with --ignored"]
fn measured_rounds_b2a_n10() {
    measure_online_rounds(10, 3, "b2a");
}
#[test]
#[ignore = "measurement harness; run explicitly with --ignored"]
fn measured_rounds_b2a_n13() {
    measure_online_rounds(13, 4, "b2a");
}

// ── message framing, measured directly ───────────────────────────────────────

/// The per-message cost the element-counting cost model does not have a term for.
///
/// `O1 = 2n/(t+1)` and `O2 = 2n/(2t+1)` price an opening in *field elements*: one byte for a
/// `Gf256` element, eight for a Goldilocks one. A message carries more than its elements — the
/// `WrappedMessage` discriminant, the `SessionId`, a sender id, a message-type tag and a length
/// prefix — and a batched GF opening's payload at these widths is tens of bytes, so the constant
/// is not a rounding error. This serializes the two shapes the conversions actually put on the
/// wire and prints the intercept and the slope, so the analysis below rests on a measurement
/// rather than on a subtraction.
///
/// Not `#[ignore]`d: it is instantaneous, and the numbers it asserts are the ones the report uses.
#[test]
fn message_framing_and_per_element_cost() {
    use stoffelcrypto::common::ProtocolSessionId;
    use stoffelcrypto::honeybadger::batch_recon::{BatchReconMsg, BatchReconMsgType};
    use stoffelcrypto::honeybadger::gf_batch_recon::{GfBatchReconMsg, GfBatchReconMsgType};
    use stoffelcrypto::honeybadger::gf_mul::{GfMultMessage, GfMultReconstructionMessage};
    use stoffelcrypto::honeybadger::{ProtocolType, WrappedMessage};

    let sid = SessionId::new(ProtocolType::A2BGfMul, SessionId::pack_slot(1, 2, 3), 9);
    let batched = |m: usize| {
        let payload = bincode::serialize(&vec![K::zero(); m]).unwrap();
        bincode::serialize(&WrappedMessage::GfBatchRecon(GfBatchReconMsg::new(
            0,
            sid,
            GfBatchReconMsgType::EvalBatch,
            payload,
        )))
        .unwrap()
        .len()
    };
    let direct = |m: usize| {
        let shares: Vec<GfShare<K>> = (0..m).map(|_| GfShare::new(K::zero(), 0, 1)).collect();
        let payload =
            bincode::serialize(&GfMultReconstructionMessage::new(&shares, &shares, 0, 1).unwrap())
                .unwrap();
        bincode::serialize(&WrappedMessage::GfMult(GfMultMessage::new(0, sid, payload)))
            .unwrap()
            .len()
    };

    // The `F`-domain equivalent: the daBit Mod2 opening, the RandBit MulPub opening and A2B's own
    // mask opening all ride `BatchReconNode`.
    let f_batched = |m: usize| {
        let mut payload = Vec::new();
        ark_serialize::CanonicalSerialize::serialize_compressed(
            &vec![F::from(0u64); m],
            &mut payload,
        )
        .unwrap();
        bincode::serialize(&WrappedMessage::BatchRecon(BatchReconMsg::new(
            0,
            sid,
            BatchReconMsgType::EvalBatch,
            payload,
        )))
        .unwrap()
        .len()
    };
    let (f0, f100) = (f_batched(0), f_batched(100));
    println!(
        "MEASURE cfg=framing f_batched_empty={f0} f_batched_100={f100} f_per_elem={}",
        (f100 - f0) as f64 / 100.0
    );
    assert_eq!(
        f100 - f0,
        800,
        "a Goldilocks element is 8 bytes on the wire"
    );
    assert_eq!(
        f0, 48,
        "the F and GF batch-recon frames are the same 48 bytes; only the element width differs"
    );

    let (b0, b1, b100) = (batched(0), batched(1), batched(100));
    let (d0, d1, d100) = (direct(0), direct(1), direct(100));
    println!(
        "MEASURE cfg=framing batched_empty={b0} batched_1={b1} batched_100={b100} \
         batched_per_elem={} direct_empty={d0} direct_1={d1} direct_100={d100} \
         direct_per_elem_pair={}",
        (b100 - b0) as f64 / 100.0,
        (d100 - d0) as f64 / 100.0,
    );

    // A batched GF opening carries one byte per element, so the model's element count is right —
    // and 48 bytes of frame that the model has no term for at all.
    assert_eq!(
        b100 - b0,
        100,
        "a batched GF payload must be 1 byte/element"
    );
    assert_eq!(b0, 48, "batched GF frame");

    // The direct path now carries `GfShareWire`: bare field elements, one byte each, two shares
    // (`a-x` and `b-y`) per multiplication — exactly the model's 2 bytes.
    //
    // **This is the measurement that changed.** It used to read `100 * 2 * 17`: a `GfShare`
    // serialised to 17 bytes to carry one, because it shipped `id` and `degree` as `usize`
    // alongside the element. Both are re-derived by the receiver (the authenticated sender, and
    // the node's own threshold) and are no longer on the wire, so the direct path's slope fell
    // from 34 to 2 bytes per multiplication — a 17x reduction in its marginal cost, leaving the
    // 52-byte frame as the whole of its remaining premium over the batched path.
    const LEGACY_DIRECT_PER_MULT: usize = 2 * 17;
    assert_eq!(
        d100 - d0,
        100 * 2,
        "a direct GF opening must carry 1 byte per share (bare element), two shares per \
         multiplication; it carried {LEGACY_DIRECT_PER_MULT} per multiplication before \
         `GfShareWire`"
    );
    assert_eq!(
        d100 - d0,
        2 * (b100 - b0),
        "per element the direct and batched paths now cost the same; what separates them is the \
         frame and the all-to-all fan-out, not the share encoding"
    );
}

// ── a liveness gap the measurement walked into ───────────────────────────────

/// **Dealt `GfRanSha` does not reliably complete.** Found while measuring the fully dealt GF triple
/// path as the baseline for this workflow's PRSS change.
///
/// Deliberately built with the *shared* helpers — `test_setup`'s plain `FakeNetwork` and
/// `test_utils::receive` — with no `CountingNetwork`, no `WireTally` and no Lamport table, so the
/// result is a statement about `gf_share_gen` and not about this file's instrumentation.
///
/// Observed, requesting 8 / 16 / 24 / 32 / 48 / 64 GF random shares at each `n`:
///
/// | `n`, `t`  | completes |
/// |-----------|-----------|
/// | 4, 1      | all six   |
/// | 7, 2      | **none**  |
/// | 10, 3     | 8..32 yes, 48 and 64 no |
/// | 13, 4     | **none**  |
///
/// So it is neither `n` alone nor batch size alone. One correlation worth handing on rather than
/// asserting: `n - 2t`, the number of outputs a dealing yields, is even (2, 4) exactly at the two
/// `n` that work at all and odd (3, 5) at the two that never do.
///
/// A stall is not wall clock running out. Under `setup_quiet_tracing` the same configuration logs
/// every party's `output_handler` taking the `Output(false)` branch and returning
/// `GfRanShaError::Abort` within milliseconds of the dealing; `wait_for_result` then waits out the
/// whole timeout with nothing further arriving. `try_finalize` gates on `2 * threshold` OK votes
/// **and** `batch_size * n_parties` computed shares, and one of those two is never reached.
///
/// The existing coverage is why this had not been seen. `gf_node_mul_test.rs` is the only
/// node-level test of the dealt GF path and runs at `n = 4`; `gf_ransha_test.rs` runs at `n = 10`
/// but drives `GfRanShaNode` directly, and only on the *negative* path (a corrupted share must
/// abort). Nobody had asked the positive question anywhere else.
///
/// **It is not on the A2B/B2A critical path.** Once PRSS keys exist — which every conversion path
/// establishes — `gf_dn07_uses_prss()` is true, `[a]`, `[b]` and the double sharing are all
/// derived, and `GfRanSha` is not called at all. It is reachable only by a deployment that declines
/// PRSS key setup and still asks for GF triples or GF random shares, which after this workflow's
/// change is the only remaining caller of the dealt path. The practical consequence for the cost
/// work is narrower and worth stating plainly: the *fully dealt* baseline that the plan's
/// "6.6x cheaper than `GfRanDouSha`" is quoted against cannot be measured at `n >= 7` at all,
/// because it does not run.
///
/// This prints what it observes and asserts only `n = 4`, the configuration `gf_node_mul_test`
/// covers, so that it documents the gap without pinning a bug in place as expected behaviour.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "diagnostic for a liveness gap; run explicitly with --ignored"]
async fn dealt_gf_random_share_generation_stalls_above_a_batch_size() {
    use crate::utils::test_utils::{receive, test_setup};

    for (n, t) in [(4usize, 1usize), (7, 2), (10, 3), (13, 4)] {
        let mut largest_ok = 0usize;
        for want in [8usize, 16, 24, 32, 48, 64] {
            let mut params = HoneyBadgerMPCNodeOpts::new(
                n,
                t,
                0,
                0,
                6100 + 10 * want as u32 + n as u32,
                0,
                0,
                conv_precision(),
                MIN_STATISTICAL_SECURITY,
                Duration::from_secs(30),
                0,
                want,
            )
            .unwrap();
            params.set_n_dabits(0);
            params.set_n_edabits(0);

            let (network, receivers, _, _) = test_setup(n, vec![]);
            let nodes: Vec<Node> = (0..n)
                .map(|id| {
                    <Node as MPCProtocol<F, RobustShare<F>, FakeNetwork>>::setup(
                        id,
                        params.clone(),
                        vec![],
                    )
                    .unwrap()
                })
                .collect();
            receive::<F, Avid<SessionId>, RobustShare<F>, FakeNetwork>(
                receivers,
                nodes.clone(),
                network.clone(),
                None,
            );

            let mut handles = Vec::new();
            for pid in 0..n {
                let mut node = nodes[pid].clone();
                let net = network[pid].clone();
                handles.push(tokio::spawn(async move {
                    let mut rng = StdRng::seed_from_u64(pid as u64 + 67);
                    node.run_gf_preprocessing(net, &mut rng)
                        .await
                        .err()
                        .map(|e| format!("{e:?}"))
                }));
            }
            let mut failed = Vec::new();
            for h in handles {
                if let Some(e) = h.await.unwrap() {
                    failed.push(e);
                }
            }
            let produced = nodes[0]
                .gf_preprocessing_material
                .lock()
                .await
                .length()
                .random_shr;
            let ok = failed.is_empty() && produced >= want;
            if ok {
                largest_ok = want;
            }
            println!(
                "MEASURE cfg=dealt_ransha_liveness n={n} t={t} requested={want} \
                 produced={produced} ok={ok} failures={} first_error={}",
                failed.len(),
                failed
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "none".to_string())
                    .replace(' ', "_")
            );
        }
        println!(
            "MEASURE cfg=dealt_ransha_liveness n={n} t={t} largest_completing_request={largest_ok}"
        );
        if n == 4 {
            // `n = 4` is the configuration `gf_node_mul_test` covers, and it is the one half of
            // this that is not in dispute. Every larger `n` is left as an observation rather than
            // an assertion, so that a fix makes this test print something different instead of
            // making it fail.
            assert!(
                largest_ok >= 64,
                "dealt GfRanSha must still work at n = 4, which is what gf_node_mul_test covers"
            );
        }
    }
}
