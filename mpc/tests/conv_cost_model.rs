//! The **corrected** wire-cost model for A2B/B2A: framing, share encoding, and the
//! direct-vs-batched crossover, each measured rather than derived.
//!
//! `conv_cost_measurement.rs` established the end-to-end totals and found that the derived,
//! element-counting model misses them by 2.3x-8.5x. This file measures the three mechanisms that
//! account for the gap, so that a closed-form `bytes = f(n, t, counts, policy)` can be written
//! down and checked against those totals:
//!
//! 1. **Framing.** Every message carries a fixed envelope the element-counting model has no term
//!    for. [`framing_law_itemised`] takes it apart field by field, so the constant is an
//!    itemisation rather than an intercept read off a regression.
//! 2. **Share encoding.** [`share_encoding_itemised`] serialises the two share types and shows
//!    which of their fields the receiver already knows from session state and the authenticated
//!    sender id — i.e. which bytes are redundant and recoverable.
//! 3. **The crossover.** [`crossover_and_layer_n4`] and friends drive one real AND layer of width
//!    `w` through [`GfMultiply`] under [`OpeningPolicy::Batched`], [`OpeningPolicy::Direct`] and
//!    [`OpeningPolicy::Auto`], record what each puts on the wire, and assert the byte and round
//!    figures against the model `Auto` decides on — so a residual here is a policy choosing on a
//!    fiction. This is where the `t <= 1` rule was shown to be keyed on the wrong variable, and
//!    it is what the rule that replaced it is derived from.
//! 4. **The conversion.** [`a2b_policy_comparison_n4`] and friends run one whole 64-bit A2B under
//!    each policy over a booked mesh, which gives the before-and-after for the `Auto` change
//!    directly: the old rule *was* `Direct` at `t <= 1` and `Batched` above, so those two rows
//!    are the old default measured on this tree rather than carried over from a tree with a
//!    different share encoding.
//!
//! The first two are instantaneous and run in the normal suite - they need no feature gate,
//! because nothing here touches the `statistics` instrumentation: the ledger below wraps the
//! network directly. The crossover measurements are `#[ignore]`d because they stand up a mesh per
//! width:
//!
//! ```text
//! cargo test -p stoffelcrypto --test conv_cost_model \
//!     --release -- --ignored --nocapture --test-threads=1
//! ```
//!
//! Byte figures are a function of the transcript, not of scheduling, so nothing here is
//! load-sensitive. Broadcast is charged to all `n` recipients, which is the convention every
//! figure in the cost work uses.
pub mod utils;

use crate::utils::test_utils::fan_in_inboxes;
use async_trait::async_trait;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use stoffelcrypto::{
    common::{
        convert::{bit_to_binary, canonical_bits, field_bit_width},
        gf2k::field::{BinaryField, Gf256},
        gf2k::share::{GfShare, GfShareWire},
        math::goldilocks::GoldilocksField,
        ProtocolSessionId, SecretSharingScheme,
    },
    honeybadger::{
        a2b::a2b::A2BNode,
        dabit::{DaBit, EdaBit},
        gf_mul::{
            gf_multiplication::GfMultiply, OpeningPolicy, DIRECT_BYTES_PER_MULT,
            GF_BATCH_RECON_FRAME_BYTES, GF_DIRECT_FRAME_BYTES,
        },
        gf_triple_gen::GfBeaverTriple,
        robust_interpolate::robust_interpolate::RobustShare,
        ProtocolType, SessionId, WrappedMessage,
    },
};
use stoffelmpc_network::fake_network::{
    FakeInnerNetwork, FakeNetwork, FakeNetworkConfig, SenderId,
};
use stoffelnet::network_utils::{ClientId, Network, NetworkError, PartyId, VerifiedOrdering};
use tokio::{sync::mpsc::Receiver, task::JoinSet};

type F = GoldilocksField;
type K = Gf256;

// ── the tally ────────────────────────────────────────────────────────────────

/// One measured message class: `GfBatchRecon/EvalBatch`, `GfMult`, and so on.
///
/// Keyed by a human-readable label so the ledger a test prints is the ledger the model is written
/// against, with no index-to-name step in between where an off-by-one could hide.
#[derive(Default)]
struct Ledger {
    rows: Mutex<BTreeMap<String, (u64, u64)>>,
    total_bytes: AtomicU64,
    total_msgs: AtomicU64,
    /// One entry per multiplication wave, keyed by the `GfMultiply` session's `exec_id`.
    ///
    /// This is what makes the per-layer figures *measured* rather than assumed: a wave that put a
    /// `GfBatchRecon` message on the wire took two rounds, one that put only a `GfMult` message
    /// took one, and a direct message's own length gives that wave's width back exactly, since
    /// `len = 52 + 2w` is the frame law this file pins.
    waves: Mutex<BTreeMap<u64, WaveObs>>,
}

/// What one multiplication wave was observed to put on the wire.
#[derive(Default, Clone, Copy, Debug)]
struct WaveObs {
    batched_msgs: u64,
    direct_msgs: u64,
    /// Serialized length of one direct message from this wave, or 0 if it sent none.
    direct_msg_bytes: u64,
    /// Serialized length of one batched message from this wave, or 0 if it sent none.
    batched_msg_bytes: u64,
}

impl WaveObs {
    /// Sequential rounds this wave took: `Eval`+`Reveal` when anything was batched, one
    /// all-to-all wave otherwise. The two paths overlap, so a mixed wave is 2 and not 3.
    fn rounds(&self) -> usize {
        if self.batched_msgs > 0 {
            2
        } else {
            1
        }
    }

    /// Multiplications in this wave, read back off a direct message: `len = 52 + 2w`.
    fn direct_width(&self) -> Option<usize> {
        (self.direct_msg_bytes > 0).then(|| {
            (self.direct_msg_bytes as usize - GF_DIRECT_FRAME_BYTES) / DIRECT_BYTES_PER_MULT
        })
    }
}

impl Ledger {
    fn record(&self, label: String, bytes: u64, copies: u64) {
        let mut rows = self.rows.lock().unwrap();
        let e = rows.entry(label).or_insert((0, 0));
        e.0 += bytes * copies;
        e.1 += copies;
        drop(rows);
        self.total_bytes
            .fetch_add(bytes * copies, Ordering::Relaxed);
        self.total_msgs.fetch_add(copies, Ordering::Relaxed);
    }

    fn snapshot(&self) -> BTreeMap<String, (u64, u64)> {
        self.rows.lock().unwrap().clone()
    }

    /// Books one *message* (not one copy of it) against the wave that sent it.
    fn note_wave(&self, bytes: &[u8]) {
        let (sid, batched) = match bincode::deserialize::<WrappedMessage>(bytes) {
            Ok(WrappedMessage::GfBatchRecon(m)) => (m.session_id, true),
            Ok(WrappedMessage::GfMult(m)) => (m.session_id, false),
            _ => return,
        };
        let mut waves = self.waves.lock().unwrap();
        let e = waves.entry(sid.exec_id()).or_default();
        if batched {
            e.batched_msgs += 1;
            e.batched_msg_bytes = bytes.len() as u64;
        } else {
            e.direct_msgs += 1;
            e.direct_msg_bytes = bytes.len() as u64;
        }
    }

    fn waves(&self) -> BTreeMap<u64, WaveObs> {
        self.waves.lock().unwrap().clone()
    }
}

/// Classifies a serialized [`WrappedMessage`] without perturbing it.
///
/// Deserialises a *copy* purely to read the discriminant and, for batch reconstruction, the
/// message type that distinguishes round 1 from round 2. Nothing is written back, so the bytes
/// counted are exactly the bytes the protocol chose to send.
fn classify(bytes: &[u8]) -> String {
    match bincode::deserialize::<WrappedMessage>(bytes) {
        Ok(WrappedMessage::GfBatchRecon(m)) => format!("GfBatchRecon/{:?}", m.msg_type),
        Ok(WrappedMessage::BatchRecon(m)) => format!("BatchRecon/{:?}", m.msg_type),
        Ok(WrappedMessage::GfMult(_)) => "GfMult/Direct".to_string(),
        Ok(other) => variant_name(&other).to_string(),
        Err(_) => "Undecodable".to_string(),
    }
}

fn variant_name(m: &WrappedMessage) -> &'static str {
    match m {
        WrappedMessage::RanDouSha(_) => "RanDouSha",
        WrappedMessage::Rbc(_) => "Rbc",
        WrappedMessage::BatchRecon(_) => "BatchRecon",
        WrappedMessage::Input(_) => "Input",
        WrappedMessage::RanSha(_) => "RanSha",
        WrappedMessage::Dousha(_) => "Dousha",
        WrappedMessage::Output(_) => "Output",
        WrappedMessage::PRandInt(_) => "PRandInt",
        WrappedMessage::Mult(_) => "Mult",
        WrappedMessage::Trunc(_) => "Trunc",
        WrappedMessage::ZeroSha(_) => "ZeroSha",
        WrappedMessage::GfRansha(_) => "GfRansha",
        WrappedMessage::GfBatchRecon(_) => "GfBatchRecon",
        WrappedMessage::GfDousha(_) => "GfDousha",
        WrappedMessage::GfRanDouSha(_) => "GfRanDouSha",
        WrappedMessage::GfMult(_) => "GfMult",
        WrappedMessage::DaBit(_) => "DaBit",
    }
}

/// Wraps a network and books every send into a [`Ledger`], charging a broadcast to all `n`.
pub struct Booked<N: Network> {
    inner: N,
    ledger: Arc<Ledger>,
}

#[async_trait]
impl<N: Network + Send + Sync> Network for Booked<N> {
    type NodeType = N::NodeType;
    type NetworkConfig = N::NetworkConfig;

    async fn send(&self, recipient: PartyId, message: &[u8]) -> Result<usize, NetworkError> {
        self.ledger
            .record(classify(message), message.len() as u64, 1);
        self.ledger.note_wave(message);
        self.inner.send(recipient, message).await
    }

    async fn broadcast(&self, message: &[u8]) -> Result<usize, NetworkError> {
        self.ledger.record(
            classify(message),
            message.len() as u64,
            self.inner.party_count() as u64,
        );
        self.ledger.note_wave(message);
        self.inner.broadcast(message).await
    }

    async fn send_to_client(&self, c: ClientId, m: &[u8]) -> Result<usize, NetworkError> {
        self.inner.send_to_client(c, m).await
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
    fn is_client_connected(&self, c: ClientId) -> bool {
        self.inner.is_client_connected(c)
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

// ── one AND layer, end to end, under a chosen policy ─────────────────────────

/// What one AND layer of width `w` cost, per party, with broadcast charged to all `n`.
struct LayerCost {
    rows: BTreeMap<String, (u64, u64)>,
    bytes_per_party: f64,
    msgs_per_party: f64,
    /// Sequential message rounds the layer actually took: 2 when any part of it was batched (the
    /// `Reveal` round cannot start before the `Eval` round completes), 1 when the whole layer went
    /// direct in a single all-to-all wave.
    rounds: usize,
}

/// Drives one real [`GfMultiply`] session of `w` multiplications under `policy` and books the wire.
///
/// Deliberately the *whole* multiplication, triples included at the input, so what is measured is
/// the online cost of an AND layer exactly as A2B spends it — both the `a-x` and the `b-y`
/// opening, and the sub-`t+1` remainder that `Batched` still sends directly.
async fn and_layer_cost(n: usize, t: usize, w: usize, policy: OpeningPolicy) -> LayerCost {
    let mut rng = ark_std::test_rng();
    let session_id = SessionId::new(ProtocolType::GfMul, SessionId::pack_slot(7, 0, 0), 1);

    let config = FakeNetworkConfig::new(400);
    let (inner, mut receivers, _) = FakeInnerNetwork::new(n, None, config);
    let ledger = Arc::new(Ledger::default());
    let network: Vec<Arc<Booked<FakeNetwork>>> = (0..n)
        .map(|id| {
            Arc::new(Booked {
                inner: FakeNetwork::new(id, inner.clone()),
                ledger: Arc::clone(&ledger),
            })
        })
        .collect();

    // Beaver triples, x and y, dealt locally: the layer's inputs, not part of its wire cost.
    let mut triples: Vec<Vec<GfBeaverTriple<K>>> = vec![Vec::new(); n];
    let mut xs: Vec<Vec<GfShare<K>>> = vec![Vec::new(); n];
    let mut ys: Vec<Vec<GfShare<K>>> = vec![Vec::new(); n];
    for _ in 0..w {
        let (a, b) = (K::random(&mut rng), K::random(&mut rng));
        let sa = GfShare::compute_shares(a, n, t, &mut rng).unwrap();
        let sb = GfShare::compute_shares(b, n, t, &mut rng).unwrap();
        let sc = GfShare::compute_shares(a * b, n, t, &mut rng).unwrap();
        let sx = GfShare::compute_shares(K::random(&mut rng), n, t, &mut rng).unwrap();
        let sy = GfShare::compute_shares(K::random(&mut rng), n, t, &mut rng).unwrap();
        for p in 0..n {
            triples[p].push(GfBeaverTriple::new(
                sa[p].clone(),
                sb[p].clone(),
                sc[p].clone(),
            ));
            xs[p].push(sx[p].clone());
            ys[p].push(sy[p].clone());
        }
    }

    let mut nodes: Vec<_> = (0..n)
        .map(|id| GfMultiply::<K>::new_with_policy(id, n, t, policy).unwrap())
        .collect();

    for i in 0..n {
        nodes[i]
            .init(
                session_id,
                xs[i].clone(),
                ys[i].clone(),
                triples[i].clone(),
                network[i].clone(),
            )
            .await
            .unwrap_or_else(|e| panic!("init failed at node {i}: {e:?}"));
    }

    let mut set = JoinSet::new();
    for node in &nodes {
        let mut mul_node = node.clone();
        let receiver = std::mem::take(&mut receivers[node.id]);
        let net = network[node.id].clone();
        let inbox: Vec<(SenderId, Receiver<Vec<u8>>)> = receiver
            .into_iter()
            .enumerate()
            .map(|(i, r)| (SenderId::Node(i), r))
            .collect();
        let mut merged = fan_in_inboxes(inbox);
        set.spawn(async move {
            while let Some(msg) = merged.recv().await {
                let wrapped: WrappedMessage = match bincode::deserialize(&msg.1) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                match &wrapped {
                    WrappedMessage::GfMult(m) => {
                        let _ = mul_node
                            .process(m.sender, m.session_id, m.payload.clone())
                            .await;
                    }
                    WrappedMessage::GfBatchRecon(b) => {
                        mul_node
                            .batch_recon
                            .process(b.clone(), Arc::clone(&net))
                            .await
                            .expect("batch recon");
                        mul_node.drain_batch_recon_output().await.unwrap();
                    }
                    _ => panic!("unexpected traffic on a gf_mul mesh"),
                }
            }
        });
    }

    // Every party must finish, so the ledger is a whole transcript rather than a prefix: a tally
    // read while a straggler still owes its last broadcast under-counts that party's share.
    for node in &nodes {
        let out = node
            .wait_for_result(session_id, Duration::from_secs(20))
            .await
            .unwrap_or_else(|e| panic!("n={n} t={t} w={w} {policy:?} did not complete: {e:?}"));
        assert_eq!(out.len(), w, "wrong output width at node {}", node.id);
    }
    set.shutdown().await;

    let rows = ledger.snapshot();
    let rounds = if rows.keys().any(|k| k.starts_with("GfBatchRecon")) {
        2
    } else {
        1
    };
    LayerCost {
        bytes_per_party: ledger.total_bytes.load(Ordering::Relaxed) as f64 / n as f64,
        msgs_per_party: ledger.total_msgs.load(Ordering::Relaxed) as f64 / n as f64,
        rows,
        rounds,
    }
}

/// The widths the crossover is read at.
///
/// Dense at the bottom because that is where the `Batched` remainder bites: every AND layer's
/// sub-`t+1` remainder is a direct open of width `< t+1` no matter how wide the layer is, and at
/// `n = 13` those remainders are where a third of A2B's online traffic goes. The last two entries
/// are past `Auto`'s crossover at `t >= 3`, which is the only regime where `Auto` batches — and
/// so the only one that exercises its **padding**, the plan no other policy produces.
const WIDTHS: [usize; 14] = [1, 2, 3, 4, 5, 6, 8, 12, 16, 32, 64, 128, 256, 384];

/// Bytes per party the model says one wave costs, from the plan alone.
///
/// The same two terms [`OpeningPolicy`] documents: `4n * (48 + groups)` for the batched run —
/// `a-x` and `b-y`, `Eval` and `Reveal` — and `n * (52 + 2 * direct)` for the direct one. A plan
/// that uses both pays both; the padding is already inside `groups`.
fn model_bytes(n: usize, t: usize, plan: stoffelcrypto::honeybadger::gf_mul::OpeningPlan) -> f64 {
    let batched = if plan.padded > 0 {
        4 * n * (GF_BATCH_RECON_FRAME_BYTES + plan.groups(t))
    } else {
        0
    };
    let direct = if plan.direct > 0 {
        n * (GF_DIRECT_FRAME_BYTES + DIRECT_BYTES_PER_MULT * plan.direct)
    } else {
        0
    };
    (batched + direct) as f64
}

async fn crossover(n: usize, t: usize) {
    println!("MODEL cfg=crossover_begin n={n} t={t} group={}", t + 1);
    for w in WIDTHS {
        let mut line = Vec::new();
        for policy in [
            OpeningPolicy::Batched,
            OpeningPolicy::Direct,
            OpeningPolicy::Auto,
        ] {
            let c = and_layer_cost(n, t, w, policy).await;
            let plan = policy.plan(n, t, w);
            let predicted = model_bytes(n, t, plan);
            let detail: Vec<String> = c
                .rows
                .iter()
                .map(|(k, (b, m))| format!("{k}={}/{}", *b as f64 / n as f64, *m as f64 / n as f64))
                .collect();
            println!(
                "MODEL cfg=crossover n={n} t={t} w={w} policy={policy:?} \
                 bytes_per_party={:.1} predicted={predicted:.1} msgs_per_party={:.1} rounds={} \
                 plan={plan:?} per_and={:.3} rows[{}]",
                c.bytes_per_party,
                c.msgs_per_party,
                c.rounds,
                c.bytes_per_party / w as f64,
                detail.join(" ")
            );
            // The model is the thing the policy decides on, so a residual here is a policy
            // deciding on a fiction. Exact, not approximate: these are counted bytes.
            assert_eq!(
                c.bytes_per_party, predicted,
                "model residual at n={n} t={t} w={w} {policy:?}"
            );
            assert_eq!(
                c.rounds,
                plan.rounds(),
                "round residual at n={n} t={t} w={w} {policy:?}"
            );
            line.push((policy, c.bytes_per_party, c.rounds));
        }
        let (_, batched_b, batched_r) = line[0];
        let (_, direct_b, direct_r) = line[1];
        let (_, auto_b, auto_r) = line[2];
        println!(
            "MODEL cfg=crossover_ratio n={n} t={t} w={w} direct_over_batched_bytes={:.3} \
             batched_rounds={batched_r} direct_rounds={direct_r} remainder={} \
             auto_over_best_bytes={:.3} auto_rounds={auto_r}",
            direct_b / batched_b,
            w % (t + 1),
            auto_b / direct_b.min(batched_b)
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "stands up a mesh per width; run explicitly with --ignored"]
async fn crossover_and_layer_n4() {
    crossover(4, 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "stands up a mesh per width; run explicitly with --ignored"]
async fn crossover_and_layer_n7() {
    crossover(7, 2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "stands up a mesh per width; run explicitly with --ignored"]
async fn crossover_and_layer_n10() {
    crossover(10, 3).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "stands up a mesh per width; run explicitly with --ignored"]
async fn crossover_and_layer_n13() {
    crossover(13, 4).await;
}

// ── the framing law, itemised ────────────────────────────────────────────────

/// Where the 48- and 52-byte frames come from, field by field.
///
/// `conv_cost_measurement::message_framing_and_per_element_cost` establishes *that* the intercepts
/// are 48 / 48 / 52 by serialising whole messages at two payload sizes and subtracting. That is a
/// measurement of the total but not an explanation, and an unexplained constant is one nobody can
/// safely change. This one serialises each constituent separately and asserts the parts sum to the
/// whole, so the model's framing term is an inventory.
///
/// The finding worth carrying forward: **the payload is bincoded twice.** Every one of these
/// messages declares `payload: Vec<u8>` and stores an independently-serialized body inside it, so
/// one logical list of elements pays *two* 8-byte length prefixes — the outer `Vec<u8>`'s and the
/// inner list's. That is 16 of the 48 bytes, and it is pure redundancy: the outer length already
/// determines the inner one given the element width.
#[test]
fn framing_law_itemised() {
    use stoffelcrypto::honeybadger::batch_recon::{BatchReconMsg, BatchReconMsgType};
    use stoffelcrypto::honeybadger::gf_batch_recon::{GfBatchReconMsg, GfBatchReconMsgType};
    use stoffelcrypto::honeybadger::gf_mul::{GfMultMessage, GfMultReconstructionMessage};

    let sid = SessionId::new(ProtocolType::A2BGfMul, SessionId::pack_slot(1, 2, 3), 9);

    // The atoms.
    let disc = 4u64; // bincode encodes an enum discriminant as u32
    let session = bincode::serialize(&sid).unwrap().len() as u64;
    let sender = bincode::serialize(&0usize).unwrap().len() as u64;
    let msgtype = bincode::serialize(&GfBatchReconMsgType::EvalBatch)
        .unwrap()
        .len() as u64;
    let veclen = bincode::serialize(&Vec::<u8>::new()).unwrap().len() as u64;

    println!(
        "MODEL cfg=framing_atoms wrapped_discriminant={disc} session_id={session} \
         sender_id={sender} msg_type={msgtype} vec_len_prefix={veclen}"
    );
    assert_eq!(session, 16, "SessionId is a u128");
    assert_eq!(sender, 8, "usize under bincode fixint");
    assert_eq!(msgtype, 4, "an enum discriminant is a u32");
    assert_eq!(veclen, 8, "a Vec length prefix is a u64");

    // GF batch reconstruction: discriminant + session + sender + msg_type + outer Vec<u8> length
    // + inner Vec<K> length. The last two are the double-serialization.
    let gf_frame = bincode::serialize(&WrappedMessage::GfBatchRecon(GfBatchReconMsg::new(
        0,
        sid,
        GfBatchReconMsgType::EvalBatch,
        bincode::serialize(&Vec::<K>::new()).unwrap(),
    )))
    .unwrap()
    .len() as u64;
    let gf_itemised = disc + session + sender + msgtype + veclen + veclen;
    println!(
        "MODEL cfg=framing_gf_batchrecon measured={gf_frame} itemised={gf_itemised} \
         = disc {disc} + session {session} + sender {sender} + msgtype {msgtype} \
         + outer_vec_len {veclen} + inner_vec_len {veclen}"
    );
    assert_eq!(gf_frame, 48);
    assert_eq!(gf_frame, gf_itemised, "the GF frame must be fully itemised");

    // The F batch-recon frame is the same 48 by coincidence of two 8-byte length prefixes: ark's
    // `serialize_compressed` writes its own u64 count ahead of the elements, exactly where bincode
    // would have written the inner `Vec`'s.
    let mut f_body = Vec::new();
    ark_serialize::CanonicalSerialize::serialize_compressed(&Vec::<F>::new(), &mut f_body).unwrap();
    let f_frame = bincode::serialize(&WrappedMessage::BatchRecon(BatchReconMsg::new(
        0,
        sid,
        BatchReconMsgType::EvalBatch,
        f_body.clone(),
    )))
    .unwrap()
    .len() as u64;
    println!(
        "MODEL cfg=framing_f_batchrecon measured={f_frame} ark_empty_vec_body={} \
         itemised={}",
        f_body.len(),
        disc + session + sender + msgtype + veclen + f_body.len() as u64
    );
    assert_eq!(f_body.len(), 8, "ark writes a u64 element count");
    assert_eq!(f_frame, 48);
    assert_eq!(
        f_frame,
        disc + session + sender + msgtype + veclen + f_body.len() as u64
    );

    // The direct path: no `msg_type` (there is only one kind of direct message) but *two* inner
    // vectors, `a_sub_x` and `b_sub_y`, so two inner length prefixes instead of one.
    let empty: Vec<GfShare<K>> = Vec::new();
    let direct_body =
        bincode::serialize(&GfMultReconstructionMessage::new(&empty, &empty, 0, 1).unwrap())
            .unwrap();
    let direct_frame = bincode::serialize(&WrappedMessage::GfMult(GfMultMessage::new(
        0,
        sid,
        direct_body.clone(),
    )))
    .unwrap()
    .len() as u64;
    let direct_itemised = disc + sender + session + veclen + veclen + veclen;
    println!(
        "MODEL cfg=framing_gfmult measured={direct_frame} itemised={direct_itemised} \
         = disc {disc} + sender {sender} + session {session} + outer_vec_len {veclen} \
         + a_sub_x_len {veclen} + b_sub_y_len {veclen}  (no msg_type field)"
    );
    assert_eq!(direct_frame, 52);
    assert_eq!(direct_frame, direct_itemised);

    // Slopes, restated here so the frame and the per-element term are asserted in one place.
    let gf_with = |m: usize| {
        bincode::serialize(&WrappedMessage::GfBatchRecon(GfBatchReconMsg::new(
            0,
            sid,
            GfBatchReconMsgType::EvalBatch,
            bincode::serialize(&vec![K::zero(); m]).unwrap(),
        )))
        .unwrap()
        .len() as u64
    };
    let direct_with = |m: usize| {
        let s: Vec<GfShare<K>> = (0..m).map(|_| GfShare::new(K::zero(), 0, 1)).collect();
        bincode::serialize(&WrappedMessage::GfMult(GfMultMessage::new(
            0,
            sid,
            bincode::serialize(&GfMultReconstructionMessage::new(&s, &s, 0, 1).unwrap()).unwrap(),
        )))
        .unwrap()
        .len() as u64
    };
    assert_eq!(gf_with(64), 48 + 64, "GF batched: 1 byte per element");
    assert_eq!(
        direct_with(64),
        52 + 64 * 2,
        "GF direct: 2 bytes per multiplication (one bare `a-x` element and one bare `b-y`)"
    );
    println!(
        "MODEL cfg=framing_law gf_batched=48+1*elements f_batched=48+8*elements \
         gf_direct=52+2*multiplications"
    );
}

// ── the share encoding, itemised ─────────────────────────────────────────────

/// What a share costs on the wire, and how much of it the receiver already knew.
///
/// A `GfShare` is 17 bytes carrying **one** byte of secret. The other 16 are `id` and `degree`,
/// both `usize`. Neither is information the receiver lacks:
///
/// * `id` is the sender's own evaluation index. The envelope already carries an authenticated
///   `sender` field which `GfMultiply::process` checks, and every call site sets `id` to the
///   sender's party id — so `id` is a restatement of a field the message already has, and one the
///   receiver must *reject* on mismatch rather than believe.
/// * `degree` is a session-wide constant. Every share in a `GfMultiply` opening is at the node's
///   own `threshold`, and `process` rejects anything else; it cannot legitimately vary within a
///   session, let alone within a message.
///
/// Both are now **off the wire**: `GfMultReconstructionMessage` carries `GfShareWire`, a bare run
/// of field elements, and the receiver re-derives `id` from the authenticated envelope sender and
/// `degree` from its own threshold. This test measures both encodings side by side, because the
/// 17-to-1 drop is what moved [`OpeningPolicy`]'s crossover: at 17 bytes per share the direct
/// path cost `34` bytes per multiplication and lost to batching above `w ~ 4`; at one byte it
/// costs `2` and wins on bytes *and* rounds at every width up to `w ~ 116` at `t = 4`.
#[test]
fn share_encoding_itemised() {
    // GF: 1 byte of field, 8 of `id`, 8 of `degree`.
    let elem = bincode::serialize(&K::zero()).unwrap().len();
    let idx = bincode::serialize(&0usize).unwrap().len();
    let share = bincode::serialize(&GfShare::new(K::zero(), 3, 2))
        .unwrap()
        .len();
    println!(
        "MODEL cfg=share_gf total={share} = element {elem} + id {idx} + degree {idx}; \
         secret_bytes={elem} redundant_bytes={}",
        share - elem
    );
    assert_eq!(elem, 1, "Gf256 is one byte");
    assert_eq!(share, 17);
    assert_eq!(share, elem + idx + idx);

    // A whole vector of them, to confirm there is no per-element saving from the container.
    let v: Vec<GfShare<K>> = (0..100).map(|i| GfShare::new(K::zero(), i, 1)).collect();
    let vlen = bincode::serialize(&v).unwrap().len();
    println!(
        "MODEL cfg=share_gf_vec len=100 bytes={vlen} per_share={}",
        (vlen - 8) / 100
    );
    assert_eq!(vlen, 8 + 100 * 17);

    // `F`: ark's CanonicalSerialize, so a Goldilocks element plus the same two `usize`s.
    let mut one = Vec::new();
    ark_serialize::CanonicalSerialize::serialize_compressed(&F::from(1u64), &mut one).unwrap();
    let mut sh = Vec::new();
    let rs: RobustShare<F> = RobustShare::new(F::from(1u64), 3, 2);
    ark_serialize::CanonicalSerialize::serialize_compressed(&rs, &mut sh).unwrap();
    println!(
        "MODEL cfg=share_f total={} = element {} + id 8 + degree 8; secret_bytes={} \
         redundant_bytes={}",
        sh.len(),
        one.len(),
        one.len(),
        sh.len() - one.len()
    );
    assert_eq!(one.len(), 8, "Goldilocks is 8 bytes compressed");
    assert_eq!(
        sh.len(),
        24,
        "8 element + 8 id + 8 degree; PhantomData is free"
    );

    // What the batch-recon path ships instead: bare elements, no envelope per value.
    let bare = bincode::serialize(&vec![K::zero(); 100]).unwrap().len();
    assert_eq!(bare, 8 + 100, "batched ships bare elements");

    // And what the direct path ships now: `GfShareWire`, which is the same bare run. The 16
    // redundant bytes are gone from the wire, so the two paths cost the same per secret and the
    // policy's choice is once again about the *pattern* (all-to-all in one round against two
    // rounds of `2n/(t+1)` packing) rather than about the container.
    let wire: Vec<GfShare<K>> = (0..100).map(|_| GfShare::new(K::zero(), 3, 2)).collect();
    let wired = bincode::serialize(&GfShareWire::encode(&wire, 3, 2).unwrap())
        .unwrap()
        .len();
    println!(
        "MODEL cfg=share_encoding_verdict gf_struct_per_secret={} gf_wire_per_secret={} \
         gf_batched_per_secret={} f_share=24 f_bare=8",
        share,
        (wired - 8) / 100,
        (bare - 8) / 100
    );
    assert_eq!(wired, 8 + 100, "the direct path ships bare elements too");
    assert_eq!((wired - 8) / 100, (bare - 8) / 100);
}

// ── one whole A2B conversion, end to end, under a chosen policy ──────────────

/// `p = 2^64 - 2^32 + 1`.
const P: u64 = 0xFFFF_FFFF_0000_0001;

/// Generous: a conversion is 7 AND layers plus an arithmetic opening over a shared `FakeNetwork`,
/// and a timeout that fires is indistinguishable from a protocol that never completes.
const A2B_TIMEOUT: Duration = Duration::from_secs(120);

/// Trusted-dealer stand-in for the edaBit pipeline: one full-range edaBit per conversion, with
/// `r` rejection-sampled below `p` exactly as the filter guarantees. Dealt locally, so none of it
/// is on the wire and the ledger holds the *online* cost alone.
fn deal_edabits(
    n_parties: usize,
    t: usize,
    count: usize,
    rng: &mut ark_std::rand::rngs::StdRng,
) -> Vec<Vec<EdaBit<F, K>>> {
    let width = field_bit_width::<F>();
    let mut per_party: Vec<Vec<EdaBit<F, K>>> = vec![Vec::new(); n_parties];
    for _ in 0..count {
        let r = loop {
            let candidate: u64 = ark_std::rand::Rng::gen(rng);
            if candidate < P {
                break candidate;
            }
        };
        let bits = canonical_bits::<F>(F::from(r), width).unwrap();
        let mut per_party_dabits: Vec<Vec<DaBit<F, K>>> = vec![Vec::new(); n_parties];
        for bit in bits {
            let arith =
                RobustShare::compute_shares(F::from(bit as u64), n_parties, t, None, rng).unwrap();
            let bin = GfShare::compute_shares(bit_to_binary::<K>(bit), n_parties, t, rng).unwrap();
            for party in 0..n_parties {
                per_party_dabits[party]
                    .push(DaBit::new(arith[party].clone(), bin[party].clone(), t).unwrap());
            }
        }
        for party in 0..n_parties {
            per_party[party]
                .push(EdaBit::compose_full_width(&per_party_dabits[party], false).unwrap());
        }
    }
    per_party
}

fn deal_gf_triples(
    n_parties: usize,
    t: usize,
    count: usize,
    rng: &mut ark_std::rand::rngs::StdRng,
) -> Vec<Vec<GfBeaverTriple<K>>> {
    let mut per_party: Vec<Vec<GfBeaverTriple<K>>> = vec![Vec::new(); n_parties];
    for _ in 0..count {
        let a = K::random(rng);
        let b = K::random(rng);
        let a_shares = GfShare::compute_shares(a, n_parties, t, rng).unwrap();
        let b_shares = GfShare::compute_shares(b, n_parties, t, rng).unwrap();
        let c_shares = GfShare::compute_shares(a * b, n_parties, t, rng).unwrap();
        for party in 0..n_parties {
            per_party[party].push(GfBeaverTriple::new(
                a_shares[party].clone(),
                b_shares[party].clone(),
                c_shares[party].clone(),
            ));
        }
    }
    per_party
}

fn deal_field(
    n_parties: usize,
    t: usize,
    values: &[F],
    rng: &mut ark_std::rand::rngs::StdRng,
) -> Vec<Vec<RobustShare<F>>> {
    let mut per_party: Vec<Vec<RobustShare<F>>> = vec![Vec::new(); n_parties];
    for value in values {
        let shares = RobustShare::compute_shares(*value, n_parties, t, None, rng).unwrap();
        for party in 0..n_parties {
            per_party[party].push(shares[party].clone());
        }
    }
    per_party
}

/// What one whole A2B conversion cost, per party, with broadcast charged to all `n`.
struct A2BCost {
    rows: BTreeMap<String, (u64, u64)>,
    bytes_per_party: f64,
    msgs_per_party: f64,
    /// One entry per AND-layer wave, in issue order.
    waves: Vec<WaveObs>,
    /// `MASK_OPENING_ROUNDS` + the rounds each wave took. Every wave here is one whole AND layer
    /// — the layers of a 64-bit conversion are far narrower than `128 * (t+1)`, so `mul_k` never
    /// splits one — which is what makes summing them the conversion's round count.
    rounds: usize,
}

/// Drives one real 64-bit A2B conversion under `policy` and books the wire.
///
/// Everything the conversion consumes — the input sharing, the edaBit, the GF triples — is dealt
/// locally, so what the ledger holds is the ONLINE cost and nothing else: one degree-`t` mask
/// opening (`BatchRecon`, always two rounds, never governed by the policy) and the AND layers.
async fn a2b_cost(n: usize, t: usize, policy: OpeningPolicy) -> A2BCost {
    use stoffelmpc_network::fake_network::FakeNetworkConfig;

    let mut rng = <ark_std::rand::rngs::StdRng as ark_std::rand::SeedableRng>::seed_from_u64(7);
    let value = F::from(0u64) - F::from(1u64);
    let values = [value];

    let config = FakeNetworkConfig::new(500);
    let (inner, mut receivers, _) = FakeInnerNetwork::new(n, None, config);
    let ledger = Arc::new(Ledger::default());
    let network: Vec<Arc<Booked<FakeNetwork>>> = (0..n)
        .map(|id| {
            Arc::new(Booked {
                inner: FakeNetwork::new(id, inner.clone()),
                ledger: Arc::clone(&ledger),
            })
        })
        .collect();

    let nodes: Vec<A2BNode<F, K>> = (0..n)
        .map(|id| A2BNode::<F, K>::new_with_opening_policy(id, n, t, policy).unwrap())
        .collect();

    let per_conversion = A2BNode::<F, K>::gf_triples_per_conversion().unwrap();
    let inputs = deal_field(n, t, &values, &mut rng);
    let edabits = deal_edabits(n, t, values.len(), &mut rng);
    let triples = deal_gf_triples(n, t, per_conversion * values.len(), &mut rng);

    let mut set = JoinSet::new();
    for id in 0..n {
        let mut a2b_node = nodes[id].clone();
        let net = network[id].clone();
        let inbox: Vec<(SenderId, Receiver<Vec<u8>>)> = std::mem::take(&mut receivers[id])
            .into_iter()
            .enumerate()
            .map(|(sender, rx)| (SenderId::Node(sender), rx))
            .collect();
        let mut merged = fan_in_inboxes(inbox);
        set.spawn(async move {
            while let Some((_sender, bytes)) = merged.recv().await {
                let wrapped: WrappedMessage = match bincode::deserialize(&bytes) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                match wrapped {
                    WrappedMessage::BatchRecon(msg) => {
                        let _ = a2b_node.open.process(msg, Arc::clone(&net)).await;
                        let _ = a2b_node.drain_open_output().await;
                    }
                    WrappedMessage::GfBatchRecon(msg) => {
                        let _ = a2b_node
                            .gf_mul
                            .batch_recon
                            .process(msg, Arc::clone(&net))
                            .await;
                        let _ = a2b_node.drain_gf_mul_output().await;
                    }
                    WrappedMessage::GfMult(msg) => {
                        let _ = a2b_node
                            .gf_mul
                            .process(msg.sender, msg.session_id, msg.payload)
                            .await;
                    }
                    other => panic!("unexpected traffic on an A2B mesh: {other:?}"),
                }
            }
        });
    }

    let session_id = SessionId::new(ProtocolType::A2B, SessionId::pack_slot(3, 0, 0), 1);
    let mut handles = Vec::with_capacity(n);
    for party in 0..n {
        let mut node = nodes[party].clone();
        let net = network[party].clone();
        let x = inputs[party].clone();
        let eda = edabits[party].clone();
        let tri = triples[party].clone();
        handles.push(tokio::spawn(async move {
            node.init(session_id, x, eda, tri, A2B_TIMEOUT, net)
                .await
                .unwrap_or_else(|e| panic!("A2B init failed on party {party}: {e:?}"));
            let bits = node
                .wait_for_result(session_id, A2B_TIMEOUT)
                .await
                .unwrap_or_else(|e| panic!("A2B result missing on party {party}: {e:?}"));
            node.clear_store(session_id).await;
            bits
        }));
    }
    // Every party must finish before the ledger is read, or a straggler that still owes its last
    // broadcast is booked short — the truncation that made the first end-to-end A2B figures
    // lower bounds.
    for h in handles {
        let bits = h.await.expect("A2B task panicked");
        assert_eq!(bits.len(), 1);
        assert_eq!(bits[0].len(), field_bit_width::<F>());
    }
    set.shutdown().await;

    let waves: Vec<WaveObs> = ledger.waves().into_values().collect();
    let rounds = 2 + waves.iter().map(|w| w.rounds()).sum::<usize>();
    A2BCost {
        rows: ledger.snapshot(),
        bytes_per_party: ledger.total_bytes.load(Ordering::Relaxed) as f64 / n as f64,
        msgs_per_party: ledger.total_msgs.load(Ordering::Relaxed) as f64 / n as f64,
        waves,
        rounds,
    }
}

/// The A2B online cost at one `(n, t)` under the policy it had, the policy it has, and the two
/// fixed controls.
///
/// `Batched` and `Direct` are not just controls here: **they are the old `Auto`**, which was
/// `Direct` at `t <= 1` and `Batched` above, so reading the right one of them off this table is
/// the before-figure for exactly this tree, measured rather than carried over from a tree with a
/// different share encoding.
async fn a2b_policy_comparison(n: usize, t: usize) {
    println!("MODEL cfg=a2b_begin n={n} t={t}");
    let mut totals = Vec::new();
    for policy in [
        OpeningPolicy::Batched,
        OpeningPolicy::Direct,
        OpeningPolicy::Auto,
        OpeningPolicy::Tuned { bytes_per_round: 0 },
        OpeningPolicy::Tuned {
            bytes_per_round: u32::MAX,
        },
    ] {
        let c = a2b_cost(n, t, policy).await;
        let detail: Vec<String> = c
            .rows
            .iter()
            .map(|(k, (b, m))| format!("{k}={}/{}", *b as f64 / n as f64, *m as f64 / n as f64))
            .collect();
        let widths: Vec<String> = c
            .waves
            .iter()
            .map(|w| match w.direct_width() {
                Some(x) => x.to_string(),
                None => "batched".to_string(),
            })
            .collect();
        println!(
            "MODEL cfg=a2b n={n} t={t} policy={policy:?} bytes_per_party={:.1} \
             kib_per_party={:.3} msgs_per_party={:.1} waves={} rounds={} widths[{}] rows[{}]",
            c.bytes_per_party,
            c.bytes_per_party / 1024.0,
            c.msgs_per_party,
            c.waves.len(),
            c.rounds,
            widths.join(","),
            detail.join(" ")
        );
        totals.push((policy, c.bytes_per_party, c.rounds));
    }
    let before = if t <= 1 { totals[1] } else { totals[0] };
    let after = totals[2];
    println!(
        "MODEL cfg=a2b_before_after n={n} t={t} old_auto={:?} old_bytes={:.1} old_rounds={} \
         new_bytes={:.1} new_rounds={} bytes_ratio={:.3}",
        before.0,
        before.1,
        before.2,
        after.1,
        after.2,
        after.1 / before.1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "stands up a mesh per policy; run explicitly with --ignored"]
async fn a2b_policy_comparison_n4() {
    a2b_policy_comparison(4, 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "stands up a mesh per policy; run explicitly with --ignored"]
async fn a2b_policy_comparison_n7() {
    a2b_policy_comparison(7, 2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "stands up a mesh per policy; run explicitly with --ignored"]
async fn a2b_policy_comparison_n10() {
    a2b_policy_comparison(10, 3).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "stands up a mesh per policy; run explicitly with --ignored"]
async fn a2b_policy_comparison_n13() {
    a2b_policy_comparison(13, 4).await;
}
