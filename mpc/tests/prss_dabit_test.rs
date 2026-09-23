//! End-to-end PRSS daBit generation over a `FakeNetwork`.
//!
//! What a run has to establish is the primitive's defining property: every output daBit is a
//! sharing of **the same bit in both domains**, at degree `t` and indexed by the holder's own
//! party index, and the batch's bits are uniform rather than constant.
//!
//! # Why this replaces `dabit_test.rs`
//!
//! The dealt protocol needed a batch of 1024 outputs to reach its bucketing soundness floor —
//! 5 120 candidates, 51 200 dealt masks per domain per party, and every phase of a four-phase
//! protocol. PRSS daBits have **soundness error 0 and no bucket**, so a batch of 64 is exactly as
//! sound as a batch of 1024 and the whole protocol is two local derivations plus one degree-`t`
//! opening. The batch sizes here are chosen for a meaningful uniformity sample, not for soundness.
//!
//! # What is dealt, and what is not
//!
//! The **PRSS key family** is dealt here rather than established by running RISS over the network:
//! `setup_prss_keys` is `PRandIntNode`'s protocol, not this one, and running it underneath would
//! make this a RISS test. What matters is only that each party holds the key for every set it is
//! outside of — which is what the one-time setup produces.
//!
//! The **`RandBit`s** are likewise dealt. `RandBit` rides `MulPub`'s degree-`2t` opening, which is
//! a preprocessing primitive with its own tests; what this file needs from it is `1 + k` degree-`t`
//! sharings of genuine bits per daBit.
//!
//! Everything the daBit protocol itself does — both PRSS conversions, the mask assembly, the Mod2
//! opening and the public-affine step — is real, and the opening runs over a real network through
//! the same `BatchRecon` message path the node dispatcher routes.

mod utils;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{rngs::StdRng, Rng, SeedableRng};
use stoffelcrypto::{
    common::{
        gf2k::{
            field::{BinaryField, Gf256},
            share::GfShare,
        },
        math::goldilocks::GoldilocksField,
        ProtocolSessionId, SecretSharingScheme,
    },
    honeybadger::{
        batch_recon::{BatchReconMsg, BatchReconMsgType},
        dabit::{
            prss_dabit::{DaBitLeakBudget, PrssDaBitKeys, PrssDaBitNode, PSI_SUB_ID},
            DaBit,
        },
        gf_prss::gf_prss::GfPrssKeys,
        prss::{
            prss::{
                all_tsets, derive_ints_at, derive_ints_at_domain, held_ranks, PrssDomain, PrssKeys,
            },
            PrssAllocator, PRSS_KEY_LEN,
        },
        robust_interpolate::robust_interpolate::RobustShare,
        ProtocolType, SessionId, WrappedMessage, MIN_STATISTICAL_SECURITY,
    },
};
use stoffelmpc_network::fake_network::{FakeNetwork, SenderId};
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinSet;
use tracing::warn;

use crate::utils::test_utils::{fan_in_inboxes, setup_tracing, test_setup};

type F = GoldilocksField;
type K = Gf256;
type Node = PrssDaBitNode<F, K>;

/// Generous: an in-process network in a debug build.
const PROTOCOL_TIMEOUT: Duration = Duration::from_secs(120);

const INSTANCE: u32 = 0x0D_AB_17;

/// How many opening contributions the corrupt-opener run actually rewrote.
///
/// Without this a transform that silently stopped matching — a payload shape that no longer
/// deserializes, say — would turn the adversarial test into an expensive assertion that the
/// honest path still works.
static TAMPERED: AtomicUsize = AtomicUsize::new(0);

// ---------------------------------------------------------------------------------------------
// Trusted dealers for the two things this file does not test
// ---------------------------------------------------------------------------------------------

/// One key per maximal unqualified set, handed to every party outside that set — the shape
/// `setup_prss_keys` establishes over the network.
fn deal_prss_keys(n: usize, t: usize, rng: &mut StdRng) -> Vec<Vec<(usize, [u8; PRSS_KEY_LEN])>> {
    let all: Vec<[u8; PRSS_KEY_LEN]> = (0..all_tsets(n, t).len()).map(|_| rng.gen()).collect();
    (0..n)
        .map(|id| {
            held_ranks(n, t, id)
                .into_iter()
                .map(|rank| (rank, all[rank]))
                .collect()
        })
        .collect()
}

/// `count` degree-`t` sharings of genuine random bits, transposed per party.
///
/// `bits[party][i]` is party `party`'s share of the `i`-th bit. The plaintext bits are returned
/// too so that a test can check the extracted daBit against the arithmetic it should satisfy.
fn deal_rand_bits(
    count: usize,
    n: usize,
    t: usize,
    rng: &mut StdRng,
) -> (Vec<Vec<RobustShare<F>>>, Vec<u64>) {
    let mut per_party: Vec<Vec<RobustShare<F>>> = vec![Vec::with_capacity(count); n];
    let mut clear = Vec::with_capacity(count);
    for _ in 0..count {
        let b: u64 = rng.gen::<bool>() as u64;
        clear.push(b);
        let shares = RobustShare::compute_shares(F::from(b), n, t, None, rng)
            .expect("dealing a RandBit sharing failed");
        for (party, share) in shares.into_iter().enumerate() {
            per_party[party].push(share);
        }
    }
    (per_party, clear)
}

fn build_nodes(
    n: usize,
    t: usize,
    topup: Option<usize>,
    rng: &mut StdRng,
) -> (Vec<Node>, Vec<PrssAllocator>) {
    let dealt = deal_prss_keys(n, t, rng);
    let mut allocs = Vec::with_capacity(n);
    let nodes = (0..n)
        .map(|id| {
            let mut node =
                Node::new(id, n, t, MIN_STATISTICAL_SECURITY, topup).expect("node construction");
            let prss = PrssKeys::<F>::new(id, n, t, &dealt[id]).expect("F PRSS store");
            let gf_prss = GfPrssKeys::<K>::new(id, n, t, &dealt[id]).expect("K PRSS store");
            // One allocator per party, stamped with that party's key family, exactly as
            // `setup_prss_keys` builds the node's single one. All start at zero and all claim in
            // the same order, so the exec a batch lands on agrees across parties with no round.
            allocs.push(PrssAllocator::new(INSTANCE, prss.key_family_id()));
            node.install_keys(PrssDaBitKeys::new(id, t, prss, gf_prss).expect("paired key stores"));
            node
        })
        .collect();
    (nodes, allocs)
}

// ---------------------------------------------------------------------------------------------
// The message pump
// ---------------------------------------------------------------------------------------------

/// A wrong but well-formed field element, for a corrupt opener.
fn wrong_f(value: F) -> F {
    value + F::from(1u64)
}

/// Rewrites an opening contribution in whichever `BatchRecon` shape it arrived.
///
/// Both rounds are corrupted, not just the first: batch reconstruction has a party reconstruct
/// `y_j` from the `Eval`s addressed to it and then broadcast it, so corrupting only `Eval` would
/// leave the final degree-`t` interpolation unexercised.
fn corrupt_opening(raw: &[u8]) -> Option<Vec<u8>> {
    let wrapped: WrappedMessage = bincode::deserialize(raw).ok()?;
    let WrappedMessage::BatchRecon(msg) = wrapped else {
        return None;
    };
    let payload = match msg.msg_type {
        BatchReconMsgType::Eval | BatchReconMsgType::Reveal => {
            let value = F::deserialize_compressed(msg.payload.as_slice()).ok()?;
            let mut out = Vec::new();
            wrong_f(value).serialize_compressed(&mut out).ok()?;
            out
        }
        BatchReconMsgType::EvalBatch | BatchReconMsgType::RevealBatch => {
            let values = Vec::<F>::deserialize_compressed(msg.payload.as_slice()).ok()?;
            let values: Vec<F> = values.into_iter().map(wrong_f).collect();
            let mut out = Vec::new();
            values.serialize_compressed(&mut out).ok()?;
            out
        }
    };
    bincode::serialize(&WrappedMessage::BatchRecon(BatchReconMsg::new(
        msg.sender_id,
        msg.session_id,
        msg.msg_type,
        payload,
    )))
    .ok()
}

/// Spawns one receiver task per party, demultiplexing exactly the arm the node dispatcher routes
/// to `conv.dabit_gen`: `BatchRecon` under `ProtocolType::DaBitOpen`, each `process` immediately
/// followed by its drain.
///
/// `corrupt` names a *sender*: every message leaving that party is rewritten on its way into every
/// other party's `process`, which is what that party sending a different byte string looks like. A
/// corrupt party never lies to itself.
///
/// Errors are logged rather than unwrapped. Late arrivals for a session a peer has already
/// finished and retired are normal asynchronously, and an honest party must not be abortable by
/// one.
fn spawn_receivers(
    receivers: Vec<Vec<Receiver<Vec<u8>>>>,
    nodes: &[Node],
    network: &[Arc<FakeNetwork>],
    corrupt: Option<usize>,
) -> JoinSet<()> {
    let mut set = JoinSet::new();

    for (party, inboxes) in receivers.into_iter().enumerate() {
        let mut node = nodes[party].clone();
        let net = Arc::clone(&network[party]);
        let inbox: Vec<(SenderId, Receiver<Vec<u8>>)> = inboxes
            .into_iter()
            .enumerate()
            .map(|(sender, rx)| (SenderId::Node(sender), rx))
            .collect();
        let mut merged = fan_in_inboxes(inbox);

        set.spawn(async move {
            while let Some((envelope, bytes)) = merged.recv().await {
                let SenderId::Node(sender) = envelope else {
                    warn!("party {party} received a client message in a node-only test");
                    continue;
                };
                let bytes = if corrupt == Some(sender) && sender != party {
                    match corrupt_opening(&bytes) {
                        Some(tampered) => {
                            TAMPERED.fetch_add(1, Ordering::Relaxed);
                            tampered
                        }
                        None => bytes,
                    }
                } else {
                    bytes
                };
                let wrapped: WrappedMessage = match bincode::deserialize(&bytes) {
                    Ok(w) => w,
                    Err(e) => {
                        warn!("party {party} could not deserialize a message: {e:?}");
                        continue;
                    }
                };
                match wrapped {
                    WrappedMessage::BatchRecon(msg) => match msg.session_id.calling_protocol() {
                        Some(ProtocolType::DaBitOpen) => {
                            if let Err(e) = node.mod2.open.process(msg, Arc::clone(&net)).await {
                                warn!("party {party} Mod2 open error: {e:?}");
                            }
                            if let Err(e) = node.drain_open_output().await {
                                warn!("party {party} Mod2 drain error: {e:?}");
                            }
                        }
                        other => warn!("party {party} saw a BatchRecon message tagged {other:?}"),
                    },
                    other => warn!("party {party} saw an unexpected message: {other:?}"),
                }
            }
        });
    }

    set
}

// ---------------------------------------------------------------------------------------------
// Assertions
// ---------------------------------------------------------------------------------------------

/// Reconstructs every daBit in both domains and checks the primitive's whole contract.
///
/// `per_party[party][nu]` is party `party`'s `nu`-th daBit.
fn assert_dabits_are_consistent(per_party: &[Vec<DaBit<F, K>>], n: usize, t: usize) -> Vec<u64> {
    let count = per_party[0].len();
    for (party, dabits) in per_party.iter().enumerate() {
        assert_eq!(dabits.len(), count, "party {party} produced a short batch");
        for (nu, dabit) in dabits.iter().enumerate() {
            // Both halves carry this party's own index and the protocol degree. `DaBit::new`
            // enforces it, so a failure here means something bypassed the constructor.
            assert_eq!(dabit.arith.id, party, "party {party} daBit {nu} arith id");
            assert_eq!(dabit.bin.id, party, "party {party} daBit {nu} bin id");
            assert_eq!(
                dabit.arith.degree, t,
                "party {party} daBit {nu} arith degree"
            );
            assert_eq!(dabit.bin.degree, t, "party {party} daBit {nu} bin degree");
        }
    }

    let mut bits = Vec::with_capacity(count);
    for nu in 0..count {
        let arith: Vec<RobustShare<F>> = (0..n).map(|p| per_party[p][nu].arith.clone()).collect();
        let bin: Vec<GfShare<K>> = (0..n).map(|p| per_party[p][nu].bin.clone()).collect();

        let (coeffs, a) = RobustShare::recover_secret(&arith, n, t)
            .unwrap_or_else(|e| panic!("daBit {nu} arithmetic reconstruction failed: {e:?}"));
        assert!(
            coeffs.len() <= t + 1,
            "daBit {nu} arithmetic half is not degree t"
        );
        let (_, b) = GfShare::recover_secret(&bin, n, t)
            .unwrap_or_else(|e| panic!("daBit {nu} binary reconstruction failed: {e:?}"));

        // T3 in `F`: the secret is 0 or 1, by provenance rather than by a check.
        let a_bit = if a == F::from(0u64) {
            0u64
        } else if a == F::from(1u64) {
            1u64
        } else {
            panic!("daBit {nu} arithmetic half reconstructed to {a:?}, which is not a bit");
        };
        // T3 in `K`: structural — a sum of `GF(2)` elements in characteristic 2.
        assert!(
            b.is_bit(),
            "daBit {nu} binary half reconstructed to {b:?}, which is not a bit"
        );
        let b_bit = if b == K::zero() { 0u64 } else { 1u64 };

        // The whole point of the primitive.
        assert_eq!(
            a_bit, b_bit,
            "daBit {nu} is {a_bit} in F but {b_bit} in K: the two halves are not the same bit"
        );
        bits.push(a_bit);
    }
    bits
}

/// A batch that came out all-zero or all-one would satisfy every consistency check above while
/// being useless as a one-time pad, so the sample is checked for both values.
fn assert_bits_are_not_constant(bits: &[u64]) {
    let ones = bits.iter().filter(|b| **b == 1).count();
    assert!(
        ones > 0 && ones < bits.len(),
        "the batch's {} bits were constant ({ones} ones)",
        bits.len()
    );
}

// ---------------------------------------------------------------------------------------------
// Runs
// ---------------------------------------------------------------------------------------------

async fn run_batch(
    n: usize,
    t: usize,
    topup: Option<usize>,
    count: usize,
    seed: u64,
    corrupt: Option<usize>,
) -> Vec<Vec<DaBit<F, K>>> {
    let mut rng = StdRng::seed_from_u64(seed);
    let (nodes, allocs) = build_nodes(n, t, topup, &mut rng);
    let per_dabit = nodes[0].rand_bits_per_dabit();
    let (rand_bits, _) = deal_rand_bits(count * per_dabit, n, t, &mut rng);

    let (network, receivers, _, _) = test_setup(n, vec![]);
    let mut pump = spawn_receivers(receivers, &nodes, &network, corrupt);

    let mut set: JoinSet<(usize, Vec<DaBit<F, K>>)> = JoinSet::new();
    for (party, node) in nodes.iter().enumerate() {
        let mut node = node.clone();
        let net = Arc::clone(&network[party]);
        let bits = rand_bits[party].clone();
        // The exec is the allocator's to mint, not this driver's: `beta` and `psi` come out of
        // one `claim_dabit_batch` on the `DaBitSeed` cursor.
        let windows = allocs[party]
            .claim_dabit_batch(count, node.mask_bits())
            .await
            .expect("claiming a daBit batch");
        set.spawn(async move {
            let out = node
                .generate(windows, bits, PROTOCOL_TIMEOUT, net)
                .await
                .unwrap_or_else(|e| panic!("party {party} daBit generation failed: {e:?}"));
            (party, out)
        });
    }

    let mut per_party: Vec<Vec<DaBit<F, K>>> = vec![Vec::new(); n];
    while let Some(joined) = set.join_next().await {
        let (party, out) = joined.expect("daBit generation task panicked");
        per_party[party] = out;
    }
    pump.abort_all();
    per_party
}

#[tokio::test(flavor = "multi_thread")]
async fn prss_dabit_e2e_n4_t1() {
    setup_tracing();
    // `C(4,1) = 4`, so the production default top-up is `k = 0`: one RandBit per daBit.
    let per_party = run_batch(4, 1, None, 128, 0x0DAB1704, None).await;
    let bits = assert_dabits_are_consistent(&per_party, 4, 1);
    assert_bits_are_not_constant(&bits);
}

#[tokio::test(flavor = "multi_thread")]
async fn prss_dabit_e2e_n7_t2() {
    setup_tracing();
    // `C(7,2) = 21`, ceil = 5, default `k = 2`: three RandBits per daBit.
    let per_party = run_batch(7, 2, None, 96, 0x0DAB1707, None).await;
    let bits = assert_dabits_are_consistent(&per_party, 7, 2);
    assert_bits_are_not_constant(&bits);
}

#[tokio::test(flavor = "multi_thread")]
async fn prss_dabit_e2e_n10_t3() {
    setup_tracing();
    // `C(10,3) = 120`, ceil = 7, default `k = 4`: five RandBits per daBit.
    let per_party = run_batch(10, 3, None, 64, 0x0DAB1710, None).await;
    let bits = assert_dabits_are_consistent(&per_party, 10, 3);
    assert_bits_are_not_constant(&bits);
}

/// `k = 0` is the minimum-cost setting and has to produce the same daBits, only with a smaller
/// lifetime budget. A `k` that changed the *output* rather than the *leak* would be a correctness
/// bug hiding behind a privacy knob.
#[tokio::test(flavor = "multi_thread")]
async fn the_topup_knob_changes_the_budget_and_not_the_output() {
    setup_tracing();
    let (n, t) = (7usize, 2usize);
    let with_topup = run_batch(n, t, None, 48, 0x0DAB1720, None).await;
    let without = run_batch(n, t, Some(0), 48, 0x0DAB1720, None).await;

    let a = assert_dabits_are_consistent(&with_topup, n, t);
    let b = assert_dabits_are_consistent(&without, n, t);
    // Same PRSS keys (same seed) and the same `beta` positions, so the *bits* must agree: the
    // top-up only widens the mask that hides them.
    assert_eq!(a, b, "the RandBit top-up changed the generated bits");

    let wide = DaBitLeakBudget::new::<F>(n, t, MIN_STATISTICAL_SECURITY, None).unwrap();
    let narrow = DaBitLeakBudget::new::<F>(n, t, MIN_STATISTICAL_SECURITY, Some(0)).unwrap();
    assert!(
        wide.max_dabits > narrow.max_dabits,
        "the top-up must buy lifetime budget"
    );
    assert_eq!(wide.mask_bits, narrow.mask_bits);
}

/// The Mod2 opening is degree-`t` and **robust**: a corrupt party feeding a wrong share into every
/// round of it must not change the answer, stall the protocol, or make two honest parties disagree.
///
/// This is the property that lets daBit generation run with no abort path of its own. If it ever
/// fails, something has moved the opening off degree `t`.
#[tokio::test(flavor = "multi_thread")]
async fn a_corrupt_opener_cannot_change_or_stall_the_batch() {
    setup_tracing();
    let (n, t) = (10usize, 3usize);
    let honest = run_batch(n, t, Some(0), 32, 0x0DAB17C1, None).await;
    TAMPERED.store(0, Ordering::Relaxed);
    let attacked = run_batch(n, t, Some(0), 32, 0x0DAB17C1, Some(0)).await;
    assert!(
        TAMPERED.load(Ordering::Relaxed) > 0,
        "the corrupt opener rewrote nothing: this test would pass vacuously"
    );

    let expected = assert_dabits_are_consistent(&honest, n, t);
    let got = assert_dabits_are_consistent(&attacked, n, t);
    assert_eq!(
        expected, got,
        "a corrupt opener changed the batch: the Mod2 opening is not robust"
    );

    // The honest parties' shares must be identical too, not merely reconstruct to the same bits —
    // a divergence there would mean two honest parties hold different pads for the same daBit.
    for party in 1..n {
        assert_eq!(
            honest[party].len(),
            attacked[party].len(),
            "party {party} produced a different batch size under attack"
        );
        for nu in 0..honest[party].len() {
            assert_eq!(
                honest[party][nu].arith.share[0], attacked[party][nu].arith.share[0],
                "party {party} daBit {nu} arithmetic share diverged under attack"
            );
            assert_eq!(
                honest[party][nu].bin.share, attacked[party][nu].bin.share,
                "party {party} daBit {nu} binary share diverged under attack"
            );
        }
    }
}

/// §6.5's second silent error: if the daBit seeds `beta` and the Mod2 mask `psi` were drawn from
/// the same `(key, context, position)`, `psi_A`'s low bit would equal `beta_A` and `V mod 4` would
/// reveal the daBit with probability ~3/4.
///
/// The separation is **two** bytes of the PRF context — `ctx[13] = PSI_SUB_ID` and
/// `ctx[15] = PrssDomain::DaBitPsi` — it is invisible to every functional test, and nothing
/// downstream would ever notice. So it is asserted here at the level of the actual derived bytes
/// rather than trusted from the session-id arithmetic, and each byte is additionally shown to be
/// *independently* sufficient: losing either one still leaves the streams apart.
#[test]
fn the_dabit_seeds_and_the_mod2_mask_are_different_keystreams() {
    let key = [0x5au8; PRSS_KEY_LEN];
    let parent = SessionId::new(
        ProtocolType::DaBit,
        SessionId::pack_slot(31, 0, 0),
        INSTANCE,
    );
    let psi = SessionId::new(
        ProtocolType::DaBit,
        SessionId::pack_slot(31, PSI_SUB_ID, 0),
        INSTANCE,
    );
    assert_ne!(parent.sub_id(), psi.sub_id());

    // What `PrssDaBitNode::generate` actually derives, at equal width so that this compares the
    // streams rather than two slicings of one.
    let beta_stream = derive_ints_at(&key, parent, 0, 64, 55);
    let psi_stream = derive_ints_at_domain(&key, psi, PrssDomain::DaBitPsi, 0, 64, 55);
    assert_ne!(
        beta_stream, psi_stream,
        "beta and psi derive from the same keystream: V mod 4 would reveal the daBit"
    );

    // Each separator on its own. `sub_id` alone, with the domain byte collapsed to beta's:
    assert_ne!(
        beta_stream,
        derive_ints_at(&key, psi, 0, 64, 55),
        "ctx[13] alone does not separate the two keystreams"
    );
    // and the domain byte alone, with `sub_id` collapsed to beta's:
    assert_ne!(
        beta_stream,
        derive_ints_at_domain(&key, parent, PrssDomain::DaBitPsi, 0, 64, 55),
        "ctx[15] alone does not separate the two keystreams"
    );

    // And the specific collision that breaks the daBit: the mask's low bit must not track the
    // seed's value at the same position.
    let beta_bits = derive_ints_at(&key, parent, 0, 256, 1);
    let psi_wide = derive_ints_at_domain(&key, psi, PrssDomain::DaBitPsi, 0, 256, 55);
    let agreeing = beta_bits
        .iter()
        .zip(&psi_wide)
        .filter(|(b, p)| (*b % 2u8) == (*p % 2u8))
        .count();
    assert!(
        agreeing > 64 && agreeing < 192,
        "psi's low bit tracks beta at {agreeing}/256 positions, which is not independent"
    );
}
