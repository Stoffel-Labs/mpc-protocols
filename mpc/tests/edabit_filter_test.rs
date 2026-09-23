//! End-to-end edaBit composition and the modulus-overflow (`r < p`) filter.
//!
//! `[r]_F = Σ 2^i [b_i]_F` is local and free, but it equals the *integer* `r` only while `r < p`.
//! The filter is the **only interactive certification left in the daBit stack** once PRSS daBits
//! made every share-type obligation free, so it is the one thing in `dabit/` whose 6 AND layers
//! and degree-`t` verdict opening actually have to be exercised over a network.
//!
//! Three properties, and all three matter:
//!
//! * a mask below `p` survives and composes to the right integer in **both** domains;
//! * a mask at or above `p` is **rejected**, together with all 64 of its daBits;
//! * the verdict is unanimous without any agreement round, because it was robustly opened at
//!   degree `t`.
//!
//! The daBits and the `GF(2^k)` double sharings are dealt: this is a test of the filter, not of
//! `PrssDaBitNode` (which `prss_dabit_test.rs` covers) or of `GfPrssDoubleShareSource`.
//!
//! The AND layers are **DN07 degree reductions** — one degree-`2t` opening per wave, no Beaver
//! triple — so what a party puts on the wire here is `GfBatchRecon` under `DaBitGfMul` and nothing
//! else. There is no `GfMult` arm any more: DN07 has no direct all-to-all opening path.

mod utils;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ark_std::rand::{rngs::StdRng, Rng, SeedableRng};
use stoffelcrypto::{
    common::{
        convert::{bit_to_binary, canonical_bits, field_bit_width},
        gf2k::{
            field::{BinaryField, Gf256},
            share::GfShare,
        },
        math::goldilocks::GoldilocksField,
        ProtocolSessionId, SecretSharingScheme,
    },
    honeybadger::{
        dabit::{edabit::EdaBitFilterNode, DaBit},
        gf_double_share::GfDoubleShamirShare,
        prss::{PrssAllocator, PrssExecSlot, PrssStream},
        robust_interpolate::robust_interpolate::RobustShare,
        ProtocolType, WrappedMessage,
    },
};
use stoffelmpc_network::fake_network::{FakeNetwork, SenderId};
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinSet;
use tracing::warn;

use crate::utils::test_utils::{fan_in_inboxes, setup_tracing, test_setup};

type F = GoldilocksField;
type K = Gf256;
type Node = EdaBitFilterNode<F, K>;

const PROTOCOL_TIMEOUT: Duration = Duration::from_secs(120);
const INSTANCE: u32 = 0x0EDA_B170;

/// One burned `exec_id` per party, each off that party's own fresh allocator, so all `n` land on
/// exec 0.
///
/// Mirrors production: every party's `PrssAllocator` starts at zero and claims in the same order,
/// so the parties agree on the exec with nothing sent. The filter derives **no PRSS position** —
/// it spends only the exec's `exec * 2^20 + wave` child-id block — so the key family stamped on
/// these allocators is irrelevant. What matters is that the exec comes off the `DaBitSeed` cursor,
/// the same one a daBit batch takes its parent exec from, which is what keeps the two drivers'
/// child blocks disjoint.
async fn exec_slots(n: usize) -> Vec<PrssExecSlot> {
    let mut out = Vec::with_capacity(n);
    for party in 0..n {
        let alloc = PrssAllocator::new(INSTANCE, [party as u8; 32]);
        out.push(
            alloc
                .claim_exec(PrssStream::DaBitSeed)
                .await
                .expect("burning an edaBit filter exec"),
        );
    }
    out
}

/// Deals one daBit per bit of `bits`, transposed per party.
fn deal_dabits(bits: &[bool], n: usize, t: usize, rng: &mut StdRng, out: &mut [Vec<DaBit<F, K>>]) {
    for bit in bits {
        let arith = RobustShare::compute_shares(F::from(*bit as u64), n, t, None, rng)
            .expect("dealing an arithmetic bit sharing failed");
        let bin = GfShare::compute_shares(bit_to_binary::<K>(*bit), n, t, rng)
            .expect("dealing a binary bit sharing failed");
        for party in 0..n {
            out[party].push(
                DaBit::new(arith[party].clone(), bin[party].clone(), t).expect("paired daBit"),
            );
        }
    }
}

/// `count` correct `GF(2^k)` double sharings `([r]_t, [r]_2t)`, transposed per party.
///
/// One uniform `r` shared twice, at degree `t` and at degree `2t`. That is the whole object DN07
/// consumes: the degree-`2t` half masks the local product for the opening, and the degree-`t` half
/// carries the same constant term back to degree `t` afterwards.
fn deal_gf_doubles(
    count: usize,
    n: usize,
    t: usize,
    rng: &mut StdRng,
) -> Vec<Vec<GfDoubleShamirShare<K>>> {
    let mut per_party: Vec<Vec<GfDoubleShamirShare<K>>> = vec![Vec::with_capacity(count); n];
    for _ in 0..count {
        let r = K::random(rng);
        let lo = GfShare::compute_shares(r, n, t, rng).unwrap();
        let hi = GfShare::compute_shares(r, n, 2 * t, rng).unwrap();
        for party in 0..n {
            per_party[party].push(GfDoubleShamirShare::new(
                lo[party].clone(),
                hi[party].clone(),
            ));
        }
    }
    per_party
}

/// Spawns one receiver task per party, demultiplexing exactly the arms the node dispatcher routes
/// to `conv.edabit`: `GfBatchRecon` under `DaBitGfMul` (the DN07 degree-`2t` opening) and under
/// `DaBitGfOpen` (the degree-`t` verdict), each `process` immediately followed by its drain.
fn spawn_receivers(
    receivers: Vec<Vec<Receiver<Vec<u8>>>>,
    nodes: &[Node],
    network: &[Arc<FakeNetwork>],
    off_protocol: &Arc<AtomicUsize>,
) -> JoinSet<()> {
    let mut set = JoinSet::new();

    for (party, inboxes) in receivers.into_iter().enumerate() {
        let mut node = nodes[party].clone();
        let net = Arc::clone(&network[party]);
        let off_protocol = Arc::clone(off_protocol);
        let inbox: Vec<(SenderId, Receiver<Vec<u8>>)> = inboxes
            .into_iter()
            .enumerate()
            .map(|(sender, rx)| (SenderId::Node(sender), rx))
            .collect();
        let mut merged = fan_in_inboxes(inbox);

        set.spawn(async move {
            while let Some((envelope, bytes)) = merged.recv().await {
                let SenderId::Node(_sender) = envelope else {
                    warn!("party {party} received a client message in a node-only test");
                    continue;
                };
                let wrapped: WrappedMessage = match bincode::deserialize(&bytes) {
                    Ok(w) => w,
                    Err(e) => {
                        warn!("party {party} could not deserialize a message: {e:?}");
                        continue;
                    }
                };
                match wrapped {
                    WrappedMessage::GfBatchRecon(msg) => match msg.session_id.calling_protocol() {
                        Some(ProtocolType::DaBitGfMul) => {
                            if let Err(e) = node
                                .gf_dn07
                                .batch_recon
                                .process(msg, Arc::clone(&net))
                                .await
                            {
                                warn!("party {party} DN07 batch-recon error: {e:?}");
                            }
                            if let Err(e) = node.drain_gf_dn07_output().await {
                                warn!("party {party} DN07 drain error: {e:?}");
                            }
                        }
                        Some(ProtocolType::DaBitGfOpen) => {
                            if let Err(e) = node.gf_open.process(msg, Arc::clone(&net)).await {
                                warn!("party {party} verdict open error: {e:?}");
                            }
                            if let Err(e) = node.drain_gf_open_output().await {
                                warn!("party {party} verdict open drain error: {e:?}");
                            }
                        }
                        other => {
                            off_protocol.fetch_add(1, Ordering::Relaxed);
                            warn!("party {party} saw a GfBatchRecon message tagged {other:?}")
                        }
                    },
                    // Counted, not merely warned about. A `GfMult` here would mean the AND layers
                    // had gone back to being Beaver multiplications: `GfMultiply` opens `d` and
                    // `e` directly all-to-all at `n = 4` under exactly this variant, while DN07
                    // puts nothing but a `GfBatchRecon` on the wire.
                    other => {
                        off_protocol.fetch_add(1, Ordering::Relaxed);
                        warn!("party {party} saw an unexpected message: {other:?}")
                    }
                }
            }
        });
    }

    set
}

/// Runs the filter over `masks`, one candidate per entry, and returns each party's surviving
/// edaBits.
async fn run_filter(n: usize, t: usize, masks: &[F], seed: u64) -> Vec<Vec<EdaBitOut>> {
    let width = field_bit_width::<F>();
    let mut rng = StdRng::seed_from_u64(seed);

    let nodes: Vec<Node> = (0..n)
        .map(|id| Node::new(id, n, t).expect("filter node"))
        .collect();

    let mut dabits: Vec<Vec<DaBit<F, K>>> = vec![Vec::new(); n];
    for mask in masks {
        let bits = canonical_bits(*mask, width).expect("mask fits the field");
        deal_dabits(&bits, n, t, &mut rng, &mut dabits);
    }

    let per_candidate = Node::gf_doubles_per_edabit().expect("filter AND count");
    let doubles = deal_gf_doubles(per_candidate * masks.len(), n, t, &mut rng);

    let (network, receivers, _, _) = test_setup(n, vec![]);
    let off_protocol = Arc::new(AtomicUsize::new(0));
    let mut pump = spawn_receivers(receivers, &nodes, &network, &off_protocol);

    let mut slots = exec_slots(n).await.into_iter();

    let mut set: JoinSet<(usize, Vec<EdaBitOut>)> = JoinSet::new();
    for (party, node) in nodes.iter().enumerate() {
        let mut node = node.clone();
        let net = Arc::clone(&network[party]);
        let my_dabits = dabits[party].clone();
        let my_doubles = doubles[party].clone();
        let slot = slots.next().expect("one exec slot per party");
        set.spawn(async move {
            let out = node
                .compose_edabits(slot, my_dabits, my_doubles, PROTOCOL_TIMEOUT, net)
                .await
                .unwrap_or_else(|e| panic!("party {party} edaBit filtering failed: {e:?}"));
            (
                party,
                out.into_iter()
                    .map(|e| EdaBitOut {
                        value: e.value,
                        bits: e.bits,
                    })
                    .collect(),
            )
        });
    }

    let mut per_party: Vec<Vec<EdaBitOut>> = (0..n).map(|_| Vec::new()).collect();
    while let Some(joined) = set.join_next().await {
        let (party, out) = joined.expect("edaBit filter task panicked");
        per_party[party] = out;
    }
    pump.abort_all();
    // The AND layers are DN07 degree reductions, so the only thing that went on the wire is
    // `GfBatchRecon` under the filter's own two tags. One `GfMult` — the direct all-to-all opening
    // a `GfMultiply` performs at `n = 4` — would mean the Beaver path had come back.
    assert_eq!(
        off_protocol.load(Ordering::Relaxed),
        0,
        "the filter put an off-protocol message on the wire"
    );
    per_party
}

/// The parts of an `EdaBit` this file reconstructs. A local struct so the test does not depend on
/// `EdaBit` being `Clone`-friendly across task boundaries in any particular way.
struct EdaBitOut {
    value: RobustShare<F>,
    bits: Vec<GfShare<K>>,
}

/// Reconstructs candidate `index` and returns `(value, bits)` in the clear.
fn recover(per_party: &[Vec<EdaBitOut>], index: usize, n: usize, t: usize) -> (F, Vec<bool>) {
    let value_shares: Vec<RobustShare<F>> =
        (0..n).map(|p| per_party[p][index].value.clone()).collect();
    let (_, value) =
        RobustShare::recover_secret(&value_shares, n, t).expect("value reconstruction");

    let width = per_party[0][index].bits.len();
    let bits = (0..width)
        .map(|i| {
            let shares: Vec<GfShare<K>> = (0..n)
                .map(|p| per_party[p][index].bits[i].clone())
                .collect();
            let (_, b) = GfShare::recover_secret(&shares, n, t).expect("bit reconstruction");
            assert!(b.is_bit(), "edaBit bit {i} is not a bit");
            b != K::zero()
        })
        .collect();
    (value, bits)
}

/// A mask below `p` survives, and both halves describe the same integer.
#[tokio::test(flavor = "multi_thread")]
async fn a_mask_below_the_modulus_composes_in_both_domains() {
    setup_tracing();
    let (n, t) = (4usize, 1usize);
    let masks = [F::from(0u64), F::from(1u64), F::from(0xDEAD_BEEF_u64)];

    let per_party = run_filter(n, t, &masks, 0x0EDA_0001).await;
    for p in &per_party {
        assert_eq!(p.len(), masks.len(), "a candidate below p was rejected");
    }

    for (index, expected) in masks.iter().enumerate() {
        let (value, bits) = recover(&per_party, index, n, t);
        assert_eq!(value, *expected, "candidate {index} value");
        let want = canonical_bits(*expected, field_bit_width::<F>()).unwrap();
        assert_eq!(bits, want, "candidate {index} bits");
    }
}

/// A mask at or above `p` is rejected, and its 64 daBits go with it.
///
/// `p = 2^64 - 2^32 + 1` on Goldilocks, so any 64-bit pattern in `[p, 2^64)` wraps. The bits are
/// dealt directly rather than derived from a field element, because a field element *cannot*
/// represent `r >= p` — which is precisely the condition the filter exists to catch.
#[tokio::test(flavor = "multi_thread")]
async fn a_mask_at_or_above_the_modulus_is_rejected_with_all_of_its_dabits() {
    setup_tracing();
    let (n, t) = (4usize, 1usize);
    let width = field_bit_width::<F>();
    let mut rng = StdRng::seed_from_u64(0x0EDA_0002);

    let nodes: Vec<Node> = (0..n).map(|id| Node::new(id, n, t).unwrap()).collect();

    // Candidate 0: r = 2^64 - 1, comfortably above p. Candidate 1: r = 5, comfortably below.
    let overflow_bits = vec![true; width];
    let ok_bits: Vec<bool> = canonical_bits(F::from(5u64), width).unwrap();

    let mut dabits: Vec<Vec<DaBit<F, K>>> = vec![Vec::new(); n];
    deal_dabits(&overflow_bits, n, t, &mut rng, &mut dabits);
    deal_dabits(&ok_bits, n, t, &mut rng, &mut dabits);

    let per_candidate = Node::gf_doubles_per_edabit().unwrap();
    let doubles = deal_gf_doubles(per_candidate * 2, n, t, &mut rng);

    let (network, receivers, _, _) = test_setup(n, vec![]);
    let off_protocol = Arc::new(AtomicUsize::new(0));
    let mut pump = spawn_receivers(receivers, &nodes, &network, &off_protocol);

    let mut slots = exec_slots(n).await.into_iter();

    let mut set: JoinSet<(usize, usize)> = JoinSet::new();
    for (party, node) in nodes.iter().enumerate() {
        let mut node = node.clone();
        let net = Arc::clone(&network[party]);
        let my_dabits = dabits[party].clone();
        let my_doubles = doubles[party].clone();
        let slot = slots.next().expect("one exec slot per party");
        set.spawn(async move {
            let out = node
                .compose_edabits(slot, my_dabits, my_doubles, PROTOCOL_TIMEOUT, net)
                .await
                .unwrap_or_else(|e| panic!("party {party} edaBit filtering failed: {e:?}"));
            (party, out.len())
        });
    }

    let mut survivors = vec![usize::MAX; n];
    while let Some(joined) = set.join_next().await {
        let (party, len) = joined.expect("edaBit filter task panicked");
        survivors[party] = len;
    }
    pump.abort_all();
    // The AND layers are DN07 degree reductions, so the only thing that went on the wire is
    // `GfBatchRecon` under the filter's own two tags. One `GfMult` — the direct all-to-all opening
    // a `GfMultiply` performs at `n = 4` — would mean the Beaver path had come back.
    assert_eq!(
        off_protocol.load(Ordering::Relaxed),
        0,
        "the filter put an off-protocol message on the wire"
    );

    // The verdict was robustly opened at degree `t`, so every honest party must have dropped the
    // *same* candidate with no agreement round. A split here would mean two parties disagree on
    // which pads exist.
    for (party, len) in survivors.iter().enumerate() {
        assert_eq!(
            *len, 1,
            "party {party} kept {len} candidates; exactly the wrapping one must be dropped"
        );
    }
}

/// `p` itself is the boundary case: `r = p` wraps to zero in `F`, so it must be rejected too.
#[tokio::test(flavor = "multi_thread")]
async fn the_modulus_itself_is_rejected() {
    setup_tracing();
    let (n, t) = (4usize, 1usize);
    let width = field_bit_width::<F>();
    let mut rng = StdRng::seed_from_u64(0x0EDA_0003);

    let nodes: Vec<Node> = (0..n).map(|id| Node::new(id, n, t).unwrap()).collect();

    // p = 2^64 - 2^32 + 1: bit 0 set, bits 32..63 set.
    let mut p_bits = vec![false; width];
    p_bits[0] = true;
    for bit in p_bits.iter_mut().take(width).skip(32) {
        *bit = true;
    }

    let mut dabits: Vec<Vec<DaBit<F, K>>> = vec![Vec::new(); n];
    deal_dabits(&p_bits, n, t, &mut rng, &mut dabits);

    let per_candidate = Node::gf_doubles_per_edabit().unwrap();
    let doubles = deal_gf_doubles(per_candidate, n, t, &mut rng);

    let (network, receivers, _, _) = test_setup(n, vec![]);
    let off_protocol = Arc::new(AtomicUsize::new(0));
    let mut pump = spawn_receivers(receivers, &nodes, &network, &off_protocol);

    let mut slots = exec_slots(n).await.into_iter();

    let mut set: JoinSet<usize> = JoinSet::new();
    for (party, node) in nodes.iter().enumerate() {
        let mut node = node.clone();
        let net = Arc::clone(&network[party]);
        let my_dabits = dabits[party].clone();
        let my_doubles = doubles[party].clone();
        let slot = slots.next().expect("one exec slot per party");
        set.spawn(async move {
            node.compose_edabits(slot, my_dabits, my_doubles, PROTOCOL_TIMEOUT, net)
                .await
                .unwrap_or_else(|e| panic!("party {party} edaBit filtering failed: {e:?}"))
                .len()
        });
    }
    while let Some(joined) = set.join_next().await {
        assert_eq!(joined.unwrap(), 0, "r = p must be rejected");
    }
    pump.abort_all();
    // The AND layers are DN07 degree reductions, so the only thing that went on the wire is
    // `GfBatchRecon` under the filter's own two tags. One `GfMult` — the direct all-to-all opening
    // a `GfMultiply` performs at `n = 4` — would mean the Beaver path had come back.
    assert_eq!(
        off_protocol.load(Ordering::Relaxed),
        0,
        "the filter put an off-protocol message on the wire"
    );
}

/// Every party's session state — the filter's own store, its `GfDn07MulNode`, that node's own
/// batch-reconstruction child, and the verdict opener — must be empty when the run returns.
///
/// `GfDn07MulNode` never retires a session itself: `clear_store` is the caller's obligation,
/// exactly as on the `F` twin, and `mul_k` is the caller. An un-retired child counts against a
/// peer's per-peer admission quota forever, and
/// `dn07::gf_dn07::tests::a_session_left_uncleared_costs_the_next_one_its_admission_slot` prices
/// that: at the quota's edge the next session this node issues to itself is refused outright.
///
/// The `gf_dn07.batch_recon` assertion is the one that distinguishes "the caller called
/// `clear_store`" from "the caller retired the parent entry": `GfDn07MulNode::clear_store` retires
/// both, and nothing else retires the child at all.
#[tokio::test(flavor = "multi_thread")]
async fn every_session_is_retired_when_the_run_returns() {
    setup_tracing();
    let (n, t) = (4usize, 1usize);
    let width = field_bit_width::<F>();
    let mut rng = StdRng::seed_from_u64(0x0EDA_0004);

    let nodes: Vec<Node> = (0..n).map(|id| Node::new(id, n, t).unwrap()).collect();
    let bits = canonical_bits(F::from(rng.gen::<u32>() as u64), width).unwrap();
    let mut dabits: Vec<Vec<DaBit<F, K>>> = vec![Vec::new(); n];
    deal_dabits(&bits, n, t, &mut rng, &mut dabits);
    let doubles = deal_gf_doubles(Node::gf_doubles_per_edabit().unwrap(), n, t, &mut rng);

    let (network, receivers, _, _) = test_setup(n, vec![]);
    let off_protocol = Arc::new(AtomicUsize::new(0));
    let mut pump = spawn_receivers(receivers, &nodes, &network, &off_protocol);
    let mut slots = exec_slots(n).await.into_iter();

    let mut set: JoinSet<()> = JoinSet::new();
    for (party, node) in nodes.iter().enumerate() {
        let mut node = node.clone();
        let net = Arc::clone(&network[party]);
        let my_dabits = dabits[party].clone();
        let my_doubles = doubles[party].clone();
        let slot = slots.next().expect("one exec slot per party");
        set.spawn(async move {
            node.compose_edabits(slot, my_dabits, my_doubles, PROTOCOL_TIMEOUT, net)
                .await
                .unwrap_or_else(|e| panic!("party {party} edaBit filtering failed: {e:?}"));
        });
    }
    while let Some(joined) = set.join_next().await {
        joined.expect("edaBit filter task panicked");
    }
    pump.abort_all();
    // The AND layers are DN07 degree reductions, so the only thing that went on the wire is
    // `GfBatchRecon` under the filter's own two tags. One `GfMult` — the direct all-to-all opening
    // a `GfMultiply` performs at `n = 4` — would mean the Beaver path had come back.
    assert_eq!(
        off_protocol.load(Ordering::Relaxed),
        0,
        "the filter put an off-protocol message on the wire"
    );

    for (party, node) in nodes.iter().enumerate() {
        assert_eq!(node.store_len().await, 0, "party {party} filter store");
        assert_eq!(
            node.gf_dn07.store_len().await,
            0,
            "party {party} gf_dn07 store"
        );
        assert_eq!(
            node.gf_dn07.batch_recon.store_len().await,
            0,
            "party {party} gf_dn07 batch-reconstruction child"
        );
        assert_eq!(
            node.gf_open.store_len().await,
            0,
            "party {party} gf_open store"
        );
    }
}
