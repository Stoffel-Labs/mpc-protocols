//! Adversarial and asynchronous-network coverage for A2B / B2A share conversion, driven through
//! `HoneyBadgerMPCNode::process`'s own dispatch.
//!
//! Everything in this file is a case that an all-honest, zero-latency run **cannot** reach:
//!
//! * a party feeding a **wrong share into an opening** — the F-side `BatchRecon` that opens A2B's
//!   mask, the K-side `GfBatchRecon` behind B2A, and the K-side opening behind every A2B AND
//!   layer, in whichever of its two shapes the deployment's
//!   [`OpeningPolicy`](stoffelcrypto::honeybadger::gf_mul::OpeningPolicy) selects — `GfBatchRecon`
//!   when the layer is batched, `GfMult` when it is opened directly all-to-all, which is the
//!   default at the `n = 4` these tests run at;
//! * **message reordering and delay**, both from turmoil's randomised per-link latency and from an
//!   explicit intra-sender reorder that TCP's own FIFO ordering would never produce;
//! * **duplicated and replayed** messages, including replay into a session that has already been
//!   retired, for the online conversions and for a preprocessing batch;
//! * a **preprocessing** fault, which is held to a different standard from an online one (below);
//! * the **phase boundary** itself, structurally and under attack: that no online session id can
//!   be turned into a [`PreprocessingSessionId`](stoffelcrypto::honeybadger::dn07::PreprocessingSessionId)
//!   and therefore none can reach a degree-`2t` opening; that the session ids the conversions
//!   really emit are on the right side of that; that a corrupt party lying into an online opening
//!   changes neither the answer nor the phase; and that a peer claiming degree `2t` on the wire —
//!   a lie no Rust type can reach, because a peer's messages are bytes — is refused at the door
//!   without costing liveness.
//!
//! # The two phases are not held to the same standard
//!
//! **Online** — A2B and B2A themselves — is asynchronous and robust with guaranteed output
//! delivery at `t < n/3`. Every opening is degree-`t`, there is no timeout, no broadcast beyond
//! RBC and **no abort**: a lying party must cost accuracy of nothing and liveness of nothing, and
//! every honest party must still return. That is what the corrupt-opener tests assert, and it is
//! why they assert a returned *value* rather than a reported error.
//!
//! **Preprocessing** is synchronous, may be timed out, and **may abort**. Degree-`2t` openings are
//! legal there and are used because they are cheaper per secret. What survives the relaxation is
//! *detection*: a corrupt party may kill a batch, never make one come out wrong. The tests at the
//! bottom of this file assert the abort happened *and* that no honest party accepted anything —
//! two different failures, only one of which is loud.
//!
//! Which leaves the error that would be silent in both directions: a degree-`2t` opening reaching
//! the online path. At `n = 3t+1` it reconstructs perfectly when everyone is honest, so no
//! functional test can see it; it only shows up later as a liveness break under attack.
//! `a2b_puts_only_online_sessions_on_the_wire` and its B2A twin audit for it directly, by taping
//! the wire and classifying every session through `dn07::phase_of` —
//! and `conversion_preprocessing_puts_only_preprocessing_sessions_on_the_wire` asks the same
//! function for the opposite answer, so the audit cannot pass by having become a tautology.
//!
//! The tampering is applied to the serialized bytes on their way into `process`, not to any node's
//! internal state, and it is deterministic on those bytes — so every honest receiver sees the
//! *same* lie. A consistent, non-equivocating corrupt party is the harder case here: an
//! equivocating one is caught by quorum bookkeeping, while a consistent one is only caught by the
//! error-correcting decode itself.
//!
//! **What is deliberately not here, and why the list shrank.** This file used to carry four
//! dealer-side daBit cases — a corrupt opener inside daBit generation, corrupted mask shares fed
//! to a dealer, churn against a dealt batch, and replay of a retired daBit session. There is no
//! dealer left to attack: `PrssDaBitNode` derives both halves of every daBit from PRSS keys, so a
//! party's only remaining freedom is to lie at the single Mod2 opening. That one surviving attack
//! is covered, closer to the code, by `prss_dabit_test::a_corrupt_opener_cannot_change_or_stall_the_batch`;
//! the dealt-material attacks have no analogue because the material no longer exists. What stays
//! here is the *consuming* end — `an_inconsistent_dabit_silently_flips_a_b2a_output_bit`, which
//! hand-deals a bad pad rather than asking a protocol to produce one — because it records what an
//! inconsistent daBit would cost downstream even though nothing can now produce one.

mod utils;

use crate::utils::{
    test_utils::{
        create_global_nodes, fan_in_inboxes, setup_tracing, test_setup, unused_precision,
    },
    turmoil::turmoil_setup_with_duration,
};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{rngs::StdRng, Rng, SeedableRng};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use stoffelcrypto::{
    common::{
        convert::{bit_to_binary, canonical_bits, field_bit_width},
        gf2k::{
            field::{BinaryField, Gf256},
            share::{GfShare, GfShareWire},
        },
        math::goldilocks::GoldilocksField,
        rbc::rbc::Avid,
        MPCProtocol, ProtocolSessionId, ProtocolTag, SecretSharingScheme, ShareConversionProtocol,
    },
    honeybadger::{
        a2b::a2b::A2BNode,
        batch_recon::{BatchReconMsg, BatchReconMsgType},
        dabit::{DaBit, EdaBit},
        dn07::{
            double_share::GfPrssDoubleShareSource, phase_of, Dn07Error, PreprocessingSessionId,
            ProtocolPhase,
        },
        gf_batch_recon::{GfBatchReconMsg, GfBatchReconMsgType},
        gf_mul::{GfMultMessage, GfMultReconstructionMessage},
        gf_prss::gf_prss::GfPrssKeys,
        gf_triple_gen::GfBeaverTriple,
        prss::{
            prss::{all_tsets, held_ranks},
            PRSS_KEY_LEN,
        },
        przs::gf_przs::GfPrzsKeys,
        robust_interpolate::robust_interpolate::RobustShare,
        HoneyBadgerMPCNode, ProtocolType, SessionId, WrappedMessage, MIN_STATISTICAL_SECURITY,
    },
};
use stoffelmpc_network::{
    fake_network::{FakeNetwork, SenderId},
    turmoil_network::TurmoilNetwork,
};
use stoffelnet::network_utils::Network;
use tokio::sync::mpsc::Receiver;

type F = GoldilocksField;
type K = Gf256;
type Node = HoneyBadgerMPCNode<F, Avid<SessionId>>;

// ---------------------------------------------------------------------------------------------
// The adversary
// ---------------------------------------------------------------------------------------------

/// What one corrupt party does to the traffic it emits, and what the network does to everybody's.
///
/// `corrupt` is a *sender* id: the transforms below are applied to messages **from** that party on
/// their way into every other party's `process`, which is exactly what that party sending a
/// different byte string would look like. A corrupt party never lies to itself, so nothing is
/// applied when `sender == receiver`.
#[derive(Clone, Copy, Debug)]
struct Adversary {
    corrupt: Option<usize>,
    /// Rewrite the corrupt party's contribution to every robust opening.
    openings: bool,
    /// Deliver every message twice, to every party.
    duplicate: bool,
    /// Hold one message back and deliver the next one first.
    reorder: bool,
    /// Re-encode the corrupt party's direct-opening shares in the retired 17-byte-per-share wire
    /// shape, *claiming* this degree and leaving every share value untouched. See
    /// [`relabel_degree`].
    relabel: Option<usize>,
    /// Rewrite the `sender` field of the corrupt party's direct-opening envelopes to this party
    /// id, leaving every share value untouched. See [`impersonate_sender`].
    impersonate: Option<usize>,
    /// Where this run tallies what it actually did.
    stats: &'static Stats,
    /// Where this run records the bytes each party put on the wire, for the phase audit.
    watch: Option<&'static Wire>,
    /// Where this run records the errors `process` raised, for the detection audit.
    faults: Option<&'static Faults>,
}

/// What an adversary *actually* managed to do, as opposed to what it was configured to do.
///
/// Without this a misconfigured transform — a payload shape that no longer deserializes, say —
/// turns every test below into an expensive assertion that the honest path still works. Each test
/// owns its own counters and asserts on them, so no test can pass vacuously.
#[derive(Debug)]
struct Stats {
    tampered: AtomicUsize,
    reordered: AtomicUsize,
    duplicated: AtomicUsize,
    relabelled: AtomicUsize,
    /// [`Stats::tampered`], split by the shape of the message that was rewritten: a two-round
    /// batch reconstruction (`BatchRecon` / `GfBatchRecon`) against a single-round direct
    /// all-to-all open (`GfMult`).
    ///
    /// The split exists because the aggregate is not assertable. A wave count is
    /// scheduling-dependent, so "how many messages did the adversary rewrite" has no stable
    /// floor; "did it rewrite anything of each shape" does, and it is the question the aggregate
    /// floor was a proxy for. See `a2b_tolerates_a_corrupt_opener`.
    tampered_batched: AtomicUsize,
    tampered_direct: AtomicUsize,
    impersonated: AtomicUsize,
}

/// Declares a zeroed [`Stats`] static. A `const` initializer would be an interior-mutable
/// constant, which is copied at each use rather than shared — exactly the bug clippy's
/// `declare_interior_mutable_const` exists to catch.
macro_rules! stats {
    ($name:ident) => {
        static $name: Stats = Stats {
            tampered: AtomicUsize::new(0),
            reordered: AtomicUsize::new(0),
            duplicated: AtomicUsize::new(0),
            relabelled: AtomicUsize::new(0),
            tampered_batched: AtomicUsize::new(0),
            tampered_direct: AtomicUsize::new(0),
            impersonated: AtomicUsize::new(0),
        };
    };
}

impl Stats {
    fn tampered(&self) -> usize {
        self.tampered.load(Ordering::Relaxed)
    }
    fn reordered(&self) -> usize {
        self.reordered.load(Ordering::Relaxed)
    }
    fn duplicated(&self) -> usize {
        self.duplicated.load(Ordering::Relaxed)
    }
    fn relabelled(&self) -> usize {
        self.relabelled.load(Ordering::Relaxed)
    }
    fn tampered_batched(&self) -> usize {
        self.tampered_batched.load(Ordering::Relaxed)
    }
    fn tampered_direct(&self) -> usize {
        self.tampered_direct.load(Ordering::Relaxed)
    }
    fn impersonated(&self) -> usize {
        self.impersonated.load(Ordering::Relaxed)
    }
}

// Counters for runs that make no claim about what the adversary achieved.
stats!(SINK);

/// Every byte string a party handed to the network during one run, in arrival order.
///
/// This exists for one assertion and it is the assertion the plan says is most likely to be got
/// wrong: the **online** path may open only at degree `t`, so nothing it puts on the wire may
/// belong to a session whose calling protocol is a preprocessing one. A smuggled degree-`2t`
/// opening — a `MulPub`, a `Dn07`, a `GfDn07` — is invisible to every functional test, because at
/// `n = 3t+1` with all parties honest a degree-`2t` opening reconstructs perfectly well. It only
/// shows up as a liveness or a correctness failure once someone lies, at which point it is a
/// guaranteed-output-delivery break rather than a bug.
#[derive(Debug)]
struct Wire {
    seen: StdMutex<Vec<Vec<u8>>>,
}

/// Declares a zeroed [`Wire`] static, for the same reason [`stats!`] exists: an interior-mutable
/// `const` is copied at each use instead of shared.
macro_rules! wire {
    ($name:ident) => {
        static $name: Wire = Wire {
            seen: StdMutex::new(Vec::new()),
        };
    };
}

impl Wire {
    fn len(&self) -> usize {
        self.seen.lock().unwrap().len()
    }

    /// The `(variant, calling protocol)` pair of every message recorded, deduplicated and sorted
    /// so an assertion failure prints a short, stable summary rather than a few hundred rows.
    fn callers(&self) -> Vec<(&'static str, Option<ProtocolType>)> {
        let mut seen: Vec<(&'static str, Option<ProtocolType>)> = self
            .seen
            .lock()
            .unwrap()
            .iter()
            .map(|raw| wire_caller(raw))
            .collect();
        seen.sort_by_key(|(name, caller)| (*name, caller.map(|c| c as u8)));
        seen.dedup();
        seen
    }
}

/// Every `process` error one run's receivers raised, as `{:?}` strings.
///
/// Preprocessing is allowed to abort, and the test that a corrupted degree-`2t` opening is
/// *detected* rather than silently accepted has to see the detection happen. The dispatcher's
/// typed errors are otherwise swallowed by [`deliver`], because an honest party must not be
/// abortable by one rejected forgery.
#[derive(Debug)]
struct Faults {
    seen: StdMutex<Vec<String>>,
}

/// Declares a zeroed [`Faults`] static; see [`stats!`] for why this is a macro and not a `const`.
macro_rules! faults {
    ($name:ident) => {
        static $name: Faults = Faults {
            seen: StdMutex::new(Vec::new()),
        };
    };
}

impl Faults {
    fn all(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
}

/// Decodes one wire message far enough to name its variant and the protocol that owns its session.
///
/// A variant that carries no session — or one that this file has never seen on a conversion's
/// wire — comes back with `None`, which the audit below treats as a failure rather than as a pass:
/// an unrecognised message on the online path is exactly as interesting as a mis-phased one.
fn wire_caller(raw: &[u8]) -> (&'static str, Option<ProtocolType>) {
    let Ok(wrapped) = bincode::deserialize::<WrappedMessage>(raw) else {
        return ("<undecodable>", None);
    };
    match wrapped {
        WrappedMessage::BatchRecon(m) => ("BatchRecon", m.session_id.calling_protocol()),
        WrappedMessage::GfBatchRecon(m) => ("GfBatchRecon", m.session_id.calling_protocol()),
        WrappedMessage::GfMult(m) => ("GfMult", m.session_id.calling_protocol()),
        WrappedMessage::RanDouSha(_) => ("RanDouSha", None),
        WrappedMessage::Rbc(_) => ("Rbc", None),
        WrappedMessage::Input(_) => ("Input", None),
        WrappedMessage::RanSha(_) => ("RanSha", None),
        WrappedMessage::Dousha(_) => ("Dousha", None),
        WrappedMessage::Output(_) => ("Output", None),
        WrappedMessage::PRandInt(_) => ("PRandInt", None),
        WrappedMessage::Mult(_) => ("Mult", None),
        WrappedMessage::Trunc(_) => ("Trunc", None),
        WrappedMessage::ZeroSha(_) => ("ZeroSha", None),
        WrappedMessage::GfRansha(_) => ("GfRansha", None),
        WrappedMessage::GfDousha(_) => ("GfDousha", None),
        WrappedMessage::GfRanDouSha(_) => ("GfRanDouSha", None),
        WrappedMessage::DaBit(_) => ("DaBit", None),
    }
}

/// Asserts that a replay tape actually carries the shapes the replay is supposed to exercise.
///
/// A tape is only ever checked for emptiness otherwise, which would let a replay test pass while
/// resending eight copies of one handshake. A conversion's traffic has more than one shape and
/// each is retired by different bookkeeping, so the test is worth only as much as the shapes it
/// managed to record.
fn assert_tape_carries(tape: &[(usize, Vec<u8>)], expect: &[&str]) {
    let mut got: Vec<&'static str> = tape.iter().map(|(_, raw)| wire_caller(raw).0).collect();
    got.sort_unstable();
    got.dedup();
    for want in expect {
        assert!(
            got.contains(want),
            "the tape carries no {want} message, so replaying it exercises nothing of that \
             shape; it carries {got:?}"
        );
    }
}

/// Asserts that every message `wire` recorded belongs to a session in phase `want`, and that the
/// protocols named are exactly `expect`.
///
/// Both halves are load-bearing. The phase check rules out a preprocessing opening having been
/// smuggled onto the online path — the plan's headline mistake. The exact-set check rules out the
/// opposite failure: a run that silently stopped exercising one of the shapes it is supposed to,
/// which is how `a2b_tolerates_a_corrupt_opener` came to pass while attacking nothing when the
/// direct-open policy landed.
///
/// It is called with `ProtocolPhase::Preprocessing` too, by the DN07 run at the bottom of this
/// file. That is not symmetry for its own sake: if `phase_of` ever collapsed to a constant, every
/// `Online` assertion here would pass vacuously and nothing else in the suite would notice.
fn assert_wire_phase(wire: &Wire, want: ProtocolPhase, expect: &[ProtocolType]) {
    assert!(
        wire.len() > 0,
        "the wire recorded nothing; the observer is not attached"
    );
    let callers = wire.callers();
    for (name, caller) in &callers {
        let Some(caller) = caller else {
            panic!("a {name} message carried no calling protocol: {callers:?}");
        };
        assert_eq!(
            phase_of(*caller),
            want,
            "a {name} message belongs to {caller:?}, which is {:?} and not the expected {want:?}. \
             On an online wire this means a degree-2t opening or a preprocessing round has been \
             smuggled onto a conversion. Observed: {callers:?}",
            phase_of(*caller),
        );
    }
    let mut got: Vec<ProtocolType> = callers.iter().filter_map(|(_, c)| *c).collect();
    got.sort_by_key(|c| *c as u8);
    got.dedup();
    let mut want = expect.to_vec();
    want.sort_by_key(|c| *c as u8);
    want.dedup();
    assert_eq!(
        got, want,
        "the conversion did not put the expected session mix on the wire: {callers:?}"
    );
}

impl Default for Adversary {
    fn default() -> Self {
        Self {
            corrupt: None,
            openings: false,
            duplicate: false,
            reorder: false,
            relabel: None,
            impersonate: None,
            stats: &SINK,
            watch: None,
            faults: None,
        }
    }
}

impl Adversary {
    fn corrupt_openings(party: usize, stats: &'static Stats) -> Self {
        Self {
            corrupt: Some(party),
            openings: true,
            stats,
            ..Self::default()
        }
    }

    /// A corrupt party that lies about nothing except the *phase* its shares belong to: every
    /// share value is the honest one, and only the `degree` label is rewritten to `degree`.
    ///
    /// This is the wire-side half of the phase boundary. [`PreprocessingSessionId`] stops one of
    /// *this crate's own* callers from opening at degree `2t` on an online session; it says
    /// nothing about a peer, whose messages arrive as bytes and are bound by no Rust type. The
    /// online direct opening therefore has to refuse a degree-`2t` label itself, which
    /// `GfMultiply::process` does by comparing against its own local `t` rather than trusting the
    /// sender's claim.
    fn relabelling_degree(party: usize, degree: usize, stats: &'static Stats) -> Self {
        Self {
            corrupt: Some(party),
            relabel: Some(degree),
            stats,
            ..Self::default()
        }
    }

    /// A corrupt party that lies about exactly one thing: **who it is**.
    ///
    /// Every share value in the direct-opening body is the honest one and the body is in the
    /// current encoding; only the envelope's `sender` field is rewritten to `victim`. See
    /// [`impersonate_sender`] for why this is the attack that the index derivation rests on.
    fn impersonating(party: usize, victim: usize, stats: &'static Stats) -> Self {
        Self {
            corrupt: Some(party),
            impersonate: Some(victim),
            stats,
            ..Self::default()
        }
    }

    fn churn(stats: &'static Stats) -> Self {
        Self {
            duplicate: true,
            reorder: true,
            stats,
            ..Self::default()
        }
    }

    fn with_churn(mut self) -> Self {
        self.duplicate = true;
        self.reorder = true;
        self
    }

    /// An adversary that does nothing but watch. Every byte any party emits is recorded on its
    /// way into a peer's `process`, which is the only place this file can see the wire.
    fn watching(wire: &'static Wire) -> Self {
        Self {
            watch: Some(wire),
            ..Self::default()
        }
    }

    fn with_watch(mut self, wire: &'static Wire) -> Self {
        self.watch = Some(wire);
        self
    }

    fn with_faults(mut self, faults: &'static Faults) -> Self {
        self.faults = Some(faults);
        self
    }
}

/// One wrong share in the `F` domain. `+ 1` rather than a random value so the lie is deterministic
/// on the bytes and therefore identical at every receiver.
fn wrong_f(value: F) -> F {
    value + F::from(1u64)
}

/// One wrong share in `GF(2^k)`. Addition is XOR here, so `+ one()` flips the low bit and is
/// guaranteed to change the value — unlike a multiplicative tweak, which fixes zero.
fn wrong_k(value: K) -> K {
    value + K::one()
}

/// Rewrites an opening contribution, in whichever message shape it arrived.
///
/// Both rounds of a batch reconstruction are corrupted, not just the first: `BatchRecon` has a
/// party reconstruct `y_j` from the `Eval`s addressed to it and then broadcast it, so corrupting
/// only `Eval` would leave the `Reveal` round untouched and the final degree-`t` interpolation
/// unexercised.
///
/// [`WrappedMessage::GfMult`] is the **direct all-to-all** opening shape, and covering it is not
/// optional. A wave of Beaver differences reaches the wire one of two ways
/// ([`OpeningPolicy`](stoffelcrypto::honeybadger::gf_mul::OpeningPolicy)), and at `n = 4` — the
/// party count `a2b_tolerates_a_corrupt_opener` runs at — the default picks the direct one, so
/// every AND layer's opening is a `GfMult` and *none* of them is a `GfBatchRecon`. An adversary
/// blind to this shape would leave all 7 AND layers running honestly and corrupt only the mask
/// opening, and the test would pass while proving nothing about the layers.
fn corrupt_opening(raw: &[u8]) -> Option<(&'static str, Vec<u8>)> {
    let wrapped: WrappedMessage = bincode::deserialize(raw).ok()?;
    let (shape, tampered) = match wrapped {
        WrappedMessage::BatchRecon(msg) => {
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
            (
                "batched",
                WrappedMessage::BatchRecon(BatchReconMsg::new(
                    msg.sender_id,
                    msg.session_id,
                    msg.msg_type,
                    payload,
                )),
            )
        }
        WrappedMessage::GfBatchRecon(msg) => {
            let payload = match msg.msg_type {
                GfBatchReconMsgType::Eval | GfBatchReconMsgType::Reveal => {
                    let value: K = bincode::deserialize(&msg.payload).ok()?;
                    bincode::serialize(&wrong_k(value)).ok()?
                }
                GfBatchReconMsgType::EvalBatch | GfBatchReconMsgType::RevealBatch => {
                    let values: Vec<K> = bincode::deserialize(&msg.payload).ok()?;
                    let values: Vec<K> = values.into_iter().map(wrong_k).collect();
                    bincode::serialize(&values).ok()?
                }
            };
            (
                "batched",
                WrappedMessage::GfBatchRecon(GfBatchReconMsg::new(
                    msg.sender_id,
                    msg.session_id,
                    msg.msg_type,
                    payload,
                )),
            )
        }
        WrappedMessage::GfMult(msg) => {
            // Every share value flipped. There is nothing else on the wire to touch: the payload
            // is `GfShareWire`, bare field elements, and the evaluation index and degree the old
            // encoding shipped are gone (the receiver derives both). What must be exercised is a
            // *well-formed* share carrying a wrong value: that is the error symbol OEC has to
            // correct, and correcting it is the whole reason a direct opening is allowed to stay
            // on the online path.
            let inner: GfMultReconstructionMessage<K> = bincode::deserialize(&msg.payload).ok()?;
            let inner = GfMultReconstructionMessage::<K> {
                a_sub_x: GfShareWire::from_elements(
                    inner
                        .a_sub_x
                        .elements()
                        .iter()
                        .copied()
                        .map(wrong_k)
                        .collect(),
                ),
                b_sub_y: GfShareWire::from_elements(
                    inner
                        .b_sub_y
                        .elements()
                        .iter()
                        .copied()
                        .map(wrong_k)
                        .collect(),
                ),
            };
            (
                "direct",
                WrappedMessage::GfMult(GfMultMessage::new(
                    msg.sender,
                    msg.session_id,
                    bincode::serialize(&inner).ok()?,
                )),
            )
        }
        _ => return None,
    };
    Some((shape, bincode::serialize(&tampered).ok()?))
}

/// The **pre-`GfShareWire`** on-the-wire shape of a share: field element, `id`, `degree`, 17
/// bytes for one byte of secret.
///
/// No code in the crate emits this any more — [`GfShareWire`] carries bare elements and the
/// receiver derives the index and the degree. It is retained *here*, inside the adversary,
/// because it is exactly the body a hostile peer (or a peer still on `main`'s wire format) can
/// still put on the network, and the point of [`relabel_degree`] is that the receiver refuses it
/// rather than reading a degree out of it.
#[derive(serde::Serialize, serde::Deserialize)]
struct LegacyGfShare {
    share: K,
    id: usize,
    degree: usize,
}

/// The pre-`GfShareWire` shape of a whole direct-opening payload.
#[derive(serde::Serialize, serde::Deserialize)]
struct LegacyGfMultReconstructionMessage {
    a_sub_x: Vec<LegacyGfShare>,
    b_sub_y: Vec<LegacyGfShare>,
}

/// Re-encodes a direct all-to-all opening in the retired 17-byte-per-share shape, **claiming**
/// `degree` on every share and leaving the share *values* exactly as the honest protocol computed
/// them.
///
/// The distinction from [`corrupt_opening`] is the whole point. That function produces a wrong
/// value in a well-formed body, which is an error symbol the online decode is *required* to
/// correct. This one produces honest values in a body that states a degree — a claim that a
/// degree-`2t` sharing belongs on the asynchronous robust path, which must never be honoured,
/// because at `n = 3t+1` a degree-`2t` opening has unique-decoding radius `floor(t/2) < t` and
/// admitting one would forfeit guaranteed output delivery.
///
/// **What changed, and why this is now a stronger property.** The claim used to be expressible:
/// `GfShare` shipped `degree`, and `GfMultiply::process` had to refuse a mismatching one at the
/// door, against its own local `t`. The wire no longer has the field, so the only way to state a
/// degree at all is to abandon the current encoding — which is what this does. The receiver has
/// no branch that reads a degree; the body simply fails to be a `GfShareWire` pair of the length
/// this node derived for itself, and is rejected. No `WrappedMessage` variant carries a degree
/// any more: `BatchReconMsg` and `GfBatchReconMsg` never did (their node is told its degree at
/// construction), and `GfMult` no longer does.
fn relabel_degree(raw: &[u8], degree: usize) -> Option<Vec<u8>> {
    let wrapped: WrappedMessage = bincode::deserialize(raw).ok()?;
    let WrappedMessage::GfMult(msg) = wrapped else {
        return None;
    };
    let inner: GfMultReconstructionMessage<K> = bincode::deserialize(&msg.payload).ok()?;
    let legacy = |w: &GfShareWire<K>| -> Vec<LegacyGfShare> {
        w.elements()
            .iter()
            .map(|&share| LegacyGfShare {
                share,
                id: msg.sender,
                degree,
            })
            .collect()
    };
    let forged = LegacyGfMultReconstructionMessage {
        a_sub_x: legacy(&inner.a_sub_x),
        b_sub_y: legacy(&inner.b_sub_y),
    };
    bincode::serialize(&WrappedMessage::GfMult(GfMultMessage::new(
        msg.sender,
        msg.session_id,
        bincode::serialize(&forged).ok()?,
    )))
    .ok()
}

/// Rewrites a direct-opening envelope's `sender` field to `victim`, leaving the body — honest
/// share values, current encoding — completely untouched.
///
/// # Why this is the attack the new encoding has to survive
///
/// `GfShareWire` removed `id` from the wire, so the receiver no longer reads a share's evaluation
/// index: `GfMultiply::process` *derives* it, stamping the `sender` it was handed onto every
/// element in the body. That is strictly stronger than the `share.id != sender` check it replaced
/// — but only for as long as the `sender` it is handed is the authenticated one.
///
/// This forges precisely that input. A corrupt party emits its own honest shares under an honest
/// party's id; if the value reaching `process` were the envelope's claim rather than the
/// transport's, the receiver would stamp index `victim` onto the impersonator's elements and
/// interpolate them at `victim`'s evaluation point. One corrupt party would then be supplying two
/// of the `2t+1` points a degree-`t` opening decodes from, which is a quorum forgery of exactly
/// the kind already fixed once in this repo's reliable broadcast — and, because the shares are
/// otherwise honest, an all-honest test would never see it.
///
/// What stops it is `HoneyBadgerMPCNode::process_message`'s `sender_id != mult_msg.sender` guard,
/// which is the *only* thing binding the derived index to the transport. Nothing else in the
/// suite pins that guard, which is why this exists: delete it and this test goes red, while every
/// correctness test still passes.
fn impersonate_sender(raw: &[u8], victim: usize) -> Option<Vec<u8>> {
    let WrappedMessage::GfMult(msg) = bincode::deserialize::<WrappedMessage>(raw).ok()? else {
        return None;
    };
    if msg.sender == victim {
        return None;
    }
    bincode::serialize(&WrappedMessage::GfMult(GfMultMessage::new(
        victim,
        msg.session_id,
        msg.payload,
    )))
    .ok()
}

/// The [`SessionId`] one wire message names, for the message shapes that carry one.
///
/// The companion to [`wire_caller`], which reports only the *tag*. The phase audit above is
/// satisfied by the tag; the structural audit at the bottom of this file is not, because what
/// `PreprocessingSessionId::new` classifies is a whole session id — tag, `sub_id` and `round_id`
/// together — and a test that only ever fed it synthetic ids would not be checking the sessions
/// the conversions really mint.
fn wire_session(raw: &[u8]) -> Option<SessionId> {
    match bincode::deserialize::<WrappedMessage>(raw).ok()? {
        WrappedMessage::BatchRecon(m) => Some(m.session_id),
        WrappedMessage::GfBatchRecon(m) => Some(m.session_id),
        WrappedMessage::GfMult(m) => Some(m.session_id),
        _ => None,
    }
}

/// What actually reaches `receiver`'s `process` for one message sent by `sender`.
fn deliveries(raw: Vec<u8>, sender: usize, receiver: usize, adv: Adversary) -> Vec<Vec<u8>> {
    // Recorded *before* tampering: the audit is about what the protocol emitted, not about what
    // the adversary turned it into.
    if let Some(wire) = adv.watch {
        wire.seen.lock().unwrap().push(raw.clone());
    }
    let mut bytes = raw;
    if adv.corrupt == Some(sender) && sender != receiver {
        if adv.openings {
            if let Some((shape, t)) = corrupt_opening(&bytes) {
                bytes = t;
                adv.stats.tampered.fetch_add(1, Ordering::Relaxed);
                let per_shape = match shape {
                    "direct" => &adv.stats.tampered_direct,
                    _ => &adv.stats.tampered_batched,
                };
                per_shape.fetch_add(1, Ordering::Relaxed);
            }
        }
        if let Some(degree) = adv.relabel {
            if let Some(t) = relabel_degree(&bytes, degree) {
                bytes = t;
                adv.stats.relabelled.fetch_add(1, Ordering::Relaxed);
            }
        }
        if let Some(victim) = adv.impersonate {
            if let Some(t) = impersonate_sender(&bytes, victim) {
                bytes = t;
                adv.stats.impersonated.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    if adv.duplicate {
        adv.stats.duplicated.fetch_add(1, Ordering::Relaxed);
        vec![bytes.clone(), bytes]
    } else {
        vec![bytes]
    }
}

// ---------------------------------------------------------------------------------------------
// Message pumps
// ---------------------------------------------------------------------------------------------

/// Feeds one message (possibly duplicated, possibly rewritten) into the node dispatcher.
///
/// A `process` error is logged, never propagated: a rejected forgery must not take the receiving
/// party's message loop down with it, which is the whole point of the typed errors on that path.
async fn deliver<N>(
    node: &mut Node,
    net: &Arc<N>,
    sender: usize,
    raw: Vec<u8>,
    me: usize,
    adv: Adversary,
) where
    N: Network + Send + Sync + 'static,
{
    for bytes in deliveries(raw, sender, me, adv) {
        if let Err(e) = node.process(sender, bytes, net.clone()).await {
            if let Some(faults) = adv.faults {
                faults.seen.lock().unwrap().push(format!("{e:?}"));
            }
            tracing::debug!("node {me} rejected a message from {sender}: {e:?}");
        }
    }
}

/// Bytes observed by a pump, kept so a test can replay them after the session has been retired.
type Tape = Arc<StdMutex<Vec<(usize, Vec<u8>)>>>;

/// Spawns one receiver task per party over `FakeNetwork`, applying `adv` on the way in.
///
/// Written out rather than reusing `test_utils::receive` because every test here needs to
/// intervene between the wire and `process`, which that helper deliberately does not allow.
fn pump_fake(
    receivers: Vec<Vec<Receiver<Vec<u8>>>>,
    nodes: Vec<Node>,
    net: Vec<Arc<FakeNetwork>>,
    adv: Adversary,
    tape: Option<Tape>,
) {
    assert_eq!(receivers.len(), nodes.len());
    for (me, (inbox_row, node)) in receivers.into_iter().zip(nodes.into_iter()).enumerate() {
        let labeled: Vec<(SenderId, Receiver<Vec<u8>>)> = inbox_row
            .into_iter()
            .enumerate()
            .map(|(idx, rx)| (SenderId::Node(idx), rx))
            .collect();
        let mut merged = fan_in_inboxes(labeled);
        let net_i = net[me].clone();
        let mut node = node;
        let tape = tape.clone();
        tokio::spawn(async move {
            // `held` is the reorder buffer: one message is kept back and released *after* the
            // next one, and the idle branch flushes it so the last message of a run can never be
            // stranded. One slot is enough — the property under test is that a handler tolerates
            // seeing a later message first, not how deep the shuffle goes.
            let mut held: Option<(usize, Vec<u8>)> = None;
            loop {
                let next = if adv.reorder {
                    tokio::select! {
                        m = merged.recv() => m,
                        _ = tokio::time::sleep(Duration::from_millis(5)) => {
                            if let Some((s, raw)) = held.take() {
                                deliver(&mut node, &net_i, s, raw, me, adv).await;
                            }
                            continue;
                        }
                    }
                } else {
                    merged.recv().await
                };
                let Some((sender, raw)) = next else {
                    if let Some((s, raw)) = held.take() {
                        deliver(&mut node, &net_i, s, raw, me, adv).await;
                    }
                    break;
                };
                let sender = match sender {
                    SenderId::Node(i) => i,
                    SenderId::Client(i) => i,
                };
                if let Some(tape) = &tape {
                    if me == 0 {
                        tape.lock().unwrap().push((sender, raw.clone()));
                    }
                }
                if adv.reorder {
                    match held.take() {
                        None => held = Some((sender, raw)),
                        Some((hs, hraw)) => {
                            adv.stats.reordered.fetch_add(1, Ordering::Relaxed);
                            deliver(&mut node, &net_i, sender, raw, me, adv).await;
                            deliver(&mut node, &net_i, hs, hraw, me, adv).await;
                        }
                    }
                } else {
                    deliver(&mut node, &net_i, sender, raw, me, adv).await;
                }
            }
        });
    }
}

// ---------------------------------------------------------------------------------------------
// Trusted-dealer preprocessing
// ---------------------------------------------------------------------------------------------
//
// Conversion *preprocessing* is dealt here rather than generated, for the reason `conv_node_test`
// gives: one real daBit batch at the shipped `B = 5, kappa = 40` cannot be smaller than 1024
// outputs. The daBit tests below do run generation for real, at the `B = 41, M = 2`
// parameterisation — which meets the identical `(B - 1) * log2(M) >= kappa` floor at 82 candidates
// instead of 10240, so it is a different point on the same curve and not a weakened one.

/// The bit [`deal_dabits`] puts at a given index. Named rather than inlined so a test that has to
/// know what a particular daBit carries cannot drift away from what was dealt.
fn dabit_bit_at(index: usize) -> bool {
    index % 3 != 0
}

fn deal_dabits(
    n_parties: usize,
    t: usize,
    count: usize,
    rng: &mut StdRng,
) -> Vec<Vec<DaBit<F, K>>> {
    let mut per_party: Vec<Vec<DaBit<F, K>>> = vec![Vec::new(); n_parties];
    for index in 0..count {
        let bit = dabit_bit_at(index);
        let arith =
            RobustShare::compute_shares(F::from(bit as u64), n_parties, t, None, rng).unwrap();
        let bin = GfShare::compute_shares(bit_to_binary::<K>(bit), n_parties, t, rng).unwrap();
        for party in 0..n_parties {
            per_party[party].push(DaBit::new(arith[party].clone(), bin[party].clone(), t).unwrap());
        }
    }
    per_party
}

/// `p = 2^64 - 2^32 + 1`.
const P: u64 = 0xFFFF_FFFF_0000_0001;

fn deal_edabits(
    n_parties: usize,
    t: usize,
    count: usize,
    rng: &mut StdRng,
) -> Vec<Vec<EdaBit<F, K>>> {
    let width = field_bit_width::<F>();
    let mut per_party: Vec<Vec<EdaBit<F, K>>> = vec![Vec::new(); n_parties];
    for _ in 0..count {
        // Rejection-sampled below `p`, which is exactly what the modulus-overflow filter
        // guarantees for a real edaBit: a bit vector is only a faithful integer encoding once
        // `r < p` has been established.
        let r = loop {
            let candidate: u64 = rng.gen();
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
    rng: &mut StdRng,
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
    rng: &mut StdRng,
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

fn nodes_for(n_parties: usize, t: usize, instance_id: u32) -> Vec<Node> {
    create_global_nodes::<F, Avid<SessionId>, RobustShare<F>, FakeNetwork>(
        n_parties,
        t,
        1,
        2,
        instance_id,
        0,
        0,
        unused_precision(),
        MIN_STATISTICAL_SECURITY,
        Duration::from_secs(60),
        vec![],
    )
}

/// The shares an adversary controlling `corrupt` never gets to touch: `2t + 1` honest ones, which
/// is the quorum a degree-`t` robust opening is entitled to assume and no more.
fn honest_quorum<S: Clone>(per_party: &[Vec<S>], index: usize, t: usize, corrupt: usize) -> Vec<S> {
    per_party
        .iter()
        .enumerate()
        .filter(|(party, _)| *party != corrupt)
        .map(|(_, shares)| shares[index].clone())
        .take(2 * t + 1)
        .collect()
}

// ---------------------------------------------------------------------------------------------
// B2A: wrong shares into the opening, and duplicate / reordered delivery
// ---------------------------------------------------------------------------------------------

async fn run_b2a(
    n_parties: usize,
    t: usize,
    instance_id: u32,
    widths: &[usize],
    adv: Adversary,
    tape: Option<Tape>,
) -> (Vec<Node>, Vec<F>, Vec<Vec<RobustShare<F>>>) {
    let total_bits: usize = widths.iter().sum();
    let (network, receivers, _, _) = test_setup(n_parties, vec![]);
    let mut nodes = nodes_for(n_parties, t, instance_id);

    let mut rng = StdRng::seed_from_u64(instance_id as u64);
    let dabits = deal_dabits(n_parties, t, total_bits, &mut rng);
    for (party, node) in nodes.iter_mut().enumerate() {
        node.conv_preprocessing_material
            .lock()
            .await
            .add(Some(dabits[party].clone()), None);
    }

    // Value `v` for width `w` is `2^w - 1`: every bit set, the largest the width can carry, and
    // the value a one-bit overshoot or undershoot gets wrong.
    let mut expected = Vec::new();
    let mut per_party_bits: Vec<Vec<Vec<GfShare<K>>>> = vec![Vec::new(); n_parties];
    for &width in widths {
        expected.push(F::from((1u128 << width) as u64 - 1));
        let mut columns: Vec<Vec<GfShare<K>>> = vec![Vec::new(); n_parties];
        for _ in 0..width {
            let shares = GfShare::compute_shares(K::one(), n_parties, t, &mut rng).unwrap();
            for party in 0..n_parties {
                columns[party].push(shares[party].clone());
            }
        }
        for party in 0..n_parties {
            per_party_bits[party].push(columns[party].clone());
        }
    }

    pump_fake(receivers, nodes.clone(), network.clone(), adv, tape);

    let mut handles = Vec::new();
    for pid in 0..n_parties {
        let mut node = nodes[pid].clone();
        let net = network[pid].clone();
        let bits = per_party_bits[pid].clone();
        handles.push(tokio::spawn(async move { node.b2a(bits, net).await }));
    }

    let mut per_party_results = Vec::with_capacity(n_parties);
    for (pid, handle) in handles.into_iter().enumerate() {
        let result = handle
            .await
            .unwrap()
            .unwrap_or_else(|e| panic!("b2a failed at party {pid}: {e:?}"));
        assert_eq!(result.len(), widths.len());
        per_party_results.push(result);
    }

    (nodes, expected, per_party_results)
}

/// A corrupt party feeds a wrong share into **both rounds** of every `GfBatchRecon` opening B2A
/// performs. At `n = 4, t = 1` that is the full error budget of the degree-`t` code, so every
/// honest party must still recover the right value rather than merely notice something is wrong.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b2a_tolerates_a_corrupt_opener() {
    setup_tracing();
    stats!(STATS);
    let (n_parties, t, corrupt) = (4usize, 1usize, 3usize);

    let (nodes, expected, results) = run_b2a(
        n_parties,
        t,
        231,
        &[1, 8, 32],
        Adversary::corrupt_openings(corrupt, &STATS),
        None,
    )
    .await;

    // Without this the test degenerates into an expensive re-run of the honest path.
    assert!(
        STATS.tampered() > 0,
        "no opening message was actually rewritten"
    );

    for (index, want) in expected.iter().enumerate() {
        let shares = honest_quorum(&results, index, t, corrupt);
        assert_eq!(shares.len(), 2 * t + 1);
        let (_, got) = RobustShare::recover_secret(&shares, n_parties, t).unwrap();
        assert_eq!(got, *want, "value {index} was not recovered");
    }
    // Containment: a corrupt *opener* must leave no residue. Every session it touched is retired.
    for node in &nodes {
        assert_eq!(node.conv.b2a.store_len().await, 0);
        assert_eq!(node.conv.b2a.gf_open.store_len().await, 0);
    }
}

/// Every message duplicated and every pair delivered in the wrong order. Handlers are supposed to
/// be idempotent and order-insensitive (C18), so the result must be bit-identical to a clean run.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b2a_survives_duplicated_and_reordered_delivery() {
    setup_tracing();
    stats!(STATS);
    let (n_parties, t) = (4usize, 1usize);

    let (nodes, expected, results) = run_b2a(
        n_parties,
        t,
        232,
        &[1, 8, 32],
        Adversary::churn(&STATS),
        None,
    )
    .await;

    assert!(STATS.duplicated() > 0 && STATS.reordered() > 0);

    for (index, want) in expected.iter().enumerate() {
        let shares: Vec<RobustShare<F>> = results[0..=2 * t]
            .iter()
            .map(|r| r[index].clone())
            .collect();
        let (_, got) = RobustShare::recover_secret(&shares, n_parties, t).unwrap();
        assert_eq!(got, *want, "value {index} was not recovered");
    }
    for node in &nodes {
        assert_eq!(node.conv.b2a.store_len().await, 0);
        assert_eq!(node.conv.b2a.gf_open.store_len().await, 0);
    }
}

/// Both at once: a corrupt opener *and* a network that duplicates and reorders everything.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b2a_tolerates_a_corrupt_opener_under_churn() {
    setup_tracing();
    stats!(STATS);
    let (n_parties, t, corrupt) = (4usize, 1usize, 3usize);

    let (_, expected, results) = run_b2a(
        n_parties,
        t,
        233,
        &[8],
        Adversary::corrupt_openings(corrupt, &STATS).with_churn(),
        None,
    )
    .await;

    assert!(STATS.tampered() > 0 && STATS.duplicated() > 0 && STATS.reordered() > 0);

    let shares = honest_quorum(&results, 0, t, corrupt);
    let (_, got) = RobustShare::recover_secret(&shares, n_parties, t).unwrap();
    assert_eq!(got, expected[0]);
}

/// Every message of a finished conversion, replayed into a party whose session is already retired.
///
/// A retired session must absorb the replay silently — neither resurrecting a store (which would
/// be an unbounded-memory hole a peer can drive) nor erroring out of the dispatcher (which would
/// let one straggler take down a party's whole message loop).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replayed_traffic_cannot_resurrect_a_retired_conversion() {
    setup_tracing();
    let (n_parties, t) = (4usize, 1usize);
    let tape: Tape = Arc::new(StdMutex::new(Vec::new()));

    let (nodes, _, _) = run_b2a(
        n_parties,
        t,
        234,
        &[8],
        Adversary::default(),
        Some(tape.clone()),
    )
    .await;

    let recorded = tape.lock().unwrap().clone();
    assert!(
        !recorded.is_empty(),
        "the tape must have captured the conversion's traffic"
    );
    assert_eq!(nodes[0].conv.b2a.store_len().await, 0);
    assert_eq!(nodes[0].conv.b2a.gf_open.store_len().await, 0);

    let (network, _receivers, _, _) = test_setup(n_parties, vec![]);
    let mut victim = nodes[0].clone();
    for (sender, bytes) in recorded {
        // Errors are fine and expected here; a panic or a resurrected store is not.
        let _ = victim.process(sender, bytes, network[0].clone()).await;
    }

    assert_eq!(
        victim.conv.b2a.store_len().await,
        0,
        "a replayed conversion re-admitted a retired session"
    );
    assert_eq!(
        victim.conv.b2a.gf_open.store_len().await,
        0,
        "a replayed opening re-admitted a retired batch-reconstruction session"
    );
}

// ---------------------------------------------------------------------------------------------
// A2B: wrong shares into the mask opening and into every AND layer
// ---------------------------------------------------------------------------------------------

async fn run_a2b(
    n_parties: usize,
    t: usize,
    instance_id: u32,
    values: &[F],
    adv: Adversary,
    tape: Option<Tape>,
) -> (Vec<Node>, Vec<Vec<Vec<GfShare<K>>>>) {
    let (network, receivers, _, _) = test_setup(n_parties, vec![]);
    let mut nodes = nodes_for(n_parties, t, instance_id);

    let mut rng = StdRng::seed_from_u64(instance_id as u64);
    let per_conversion = A2BNode::<F, K>::gf_triples_per_conversion().unwrap();
    let inputs = deal_field(n_parties, t, values, &mut rng);
    let edabits = deal_edabits(n_parties, t, values.len(), &mut rng);
    let gf_triples = deal_gf_triples(n_parties, t, per_conversion * values.len(), &mut rng);

    for (party, node) in nodes.iter_mut().enumerate() {
        node.conv_preprocessing_material
            .lock()
            .await
            .add(None, Some(edabits[party].clone()));
        node.gf_preprocessing_material
            .lock()
            .await
            .add(Some(gf_triples[party].clone()), None);
    }

    pump_fake(receivers, nodes.clone(), network.clone(), adv, tape);

    let mut handles = Vec::new();
    for pid in 0..n_parties {
        let mut node = nodes[pid].clone();
        let net = network[pid].clone();
        let x = inputs[pid].clone();
        handles.push(tokio::spawn(async move { node.a2b(x, net).await }));
    }

    let mut per_party_results = Vec::with_capacity(n_parties);
    for (pid, handle) in handles.into_iter().enumerate() {
        let result = handle
            .await
            .unwrap()
            .unwrap_or_else(|e| panic!("a2b failed at party {pid}: {e:?}"));
        assert_eq!(result.len(), values.len());
        per_party_results.push(result);
    }

    (nodes, per_party_results)
}

fn assert_a2b_bits(
    results: &[Vec<Vec<GfShare<K>>>],
    values: &[F],
    n_parties: usize,
    t: usize,
    corrupt: Option<usize>,
) {
    let width = field_bit_width::<F>();
    for (index, value) in values.iter().enumerate() {
        let want = canonical_bits::<F>(*value, width).unwrap();
        for bit in 0..width {
            let shares: Vec<GfShare<K>> = results
                .iter()
                .enumerate()
                .filter(|(party, _)| Some(*party) != corrupt)
                .map(|(_, r)| r[index][bit].clone())
                .take(2 * t + 1)
                .collect();
            let (_, got) = GfShare::recover_secret(&shares, n_parties, t).unwrap();
            assert_eq!(
                got,
                bit_to_binary::<K>(want[bit]),
                "value {index} bit {bit} mismatch"
            );
        }
    }
}

/// A corrupt party feeds a wrong share into A2B's degree-`t` mask opening **and** into all 7 AND
/// layers' GF openings.
///
/// `p - 1` is the case that matters most: it is the `c1 = 1` branch of the conditional reduction,
/// so a decode that quietly returned a wrong `y` would land on the wrong side of it. It is also
/// `-1`, which must come back as the canonical `0xFFFF_FFFF_0000_0000` and not a two's-complement
/// `u64::MAX`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a2b_tolerates_a_corrupt_opener() {
    setup_tracing();
    stats!(STATS);
    let (n_parties, t, corrupt) = (4usize, 1usize, 3usize);
    let values = [
        F::from(0u64),
        F::from(1u64 << 32),
        F::from(0u64) - F::from(1u64),
    ];

    let (nodes, results) = run_a2b(
        n_parties,
        t,
        235,
        &values,
        Adversary::corrupt_openings(corrupt, &STATS),
        None,
    )
    .await;

    // The tally is split by **shape**, and no aggregate floor is asserted, because the aggregate
    // is not a stable quantity. Measured over nine runs of this test on an idle machine, the
    // corrupt party's rewritten-message count ranged over {24, 33, 36, 39, 42} and the wire's
    // total `GfMult` count over 168..=192: how many waves the AND layers take is
    // scheduling-dependent, so any fixed floor either sits inside that distribution or rules out
    // nothing at all. The floor that used to stand here, 27, sat inside it — one run in nine
    // sampled 24 and failed — and because a panicking test aborts the whole binary it took every
    // test scheduled after it down with it rather than failing alone.
    //
    // This is not a race against messages still in flight: the tally is complete when it is read,
    // and a 1.5 s wait before reading it does not move it by one. It is nondeterminism in what
    // A2B emits.
    //
    // What the floor was *for* survives, and is now named rather than approximated. When the
    // direct-open policy landed, the adversary still knew `BatchRecon` and `GfBatchRecon` but not
    // `GfMult`: it corrupted the mask opening and *nothing else*, all 7 AND layers ran honestly,
    // and this test went on passing while attacking nothing that mattered. That failure is
    // exactly "no message of the direct shape was ever rewritten" — which the second assertion
    // below states in the terms the bug was in, and which, unlike a count, cannot be knocked over
    // by how many waves a layer happens to take.
    assert!(
        STATS.tampered_batched() > 0,
        "the two-round BatchRecon mask opening was never attacked"
    );
    assert!(
        STATS.tampered_direct() > 0,
        "no direct-open GfMult message was rewritten, so all 7 AND layers ran honestly and this \
         test attacked A2B's mask opening alone — the exact shape in which it passed vacuously \
         when OpeningPolicy::Direct landed"
    );
    assert_a2b_bits(&results, &values, n_parties, t, Some(corrupt));
    for node in &nodes {
        assert_eq!(node.conv.a2b.store_len().await, 0);
        assert_eq!(node.conv.a2b.open.store_len().await, 0);
        assert_eq!(node.conv.a2b.gf_mul.store_len().await, 0);
    }
}

/// 7 AND layers of duplicated, reordered traffic. Every layer's `GfMultiply` and its
/// batch-reconstruction children have to be idempotent for this to come out right.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a2b_survives_duplicated_and_reordered_delivery() {
    setup_tracing();
    stats!(STATS);
    let (n_parties, t) = (4usize, 1usize);
    let values = [F::from(1u64), F::from(0u64) - F::from(1u64)];

    let (nodes, results) =
        run_a2b(n_parties, t, 236, &values, Adversary::churn(&STATS), None).await;

    assert!(STATS.duplicated() > 0 && STATS.reordered() > 0);

    assert_a2b_bits(&results, &values, n_parties, t, None);
    for node in &nodes {
        assert_eq!(node.conv.a2b.store_len().await, 0);
        assert_eq!(node.conv.a2b.open.store_len().await, 0);
        assert_eq!(node.conv.a2b.gf_mul.store_len().await, 0);
    }
}

/// A daBit whose two halves carry *different* bits, fed straight into B2A.
///
/// B2A does not detect this and cannot: it opens `c_i = x_i XOR r_i.bin`, then rebuilds
/// `[x_i]_F` from `r_i.arith` — so a daBit with `arith != bin` silently produces the complement at
/// that bit position, with no error and nothing to notice. `b2a_checked` does not help either; it
/// certifies the *input* bits, not the pad.
///
/// That is why the *producing* end has to make cross-domain consistency unconditional, and this
/// test is here so that the cost of relaxing it is written down at the consuming end. Under PRSS
/// daBits the producing end discharges it by construction rather than by a check: `[S]_F` is the
/// integer sum and `[b]_K` the XOR of one and the same `derive_ints_at` draw, so `arith != bin` is
/// not a thing a party can cause. The attack staged below therefore has no producer left to stage
/// it from, which is the point — it survives only as a hand-dealt pad.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_inconsistent_dabit_silently_flips_a_b2a_output_bit() {
    setup_tracing();
    let (n_parties, t) = (4usize, 1usize);
    let width = 8usize;
    let bad_index = 3usize;

    let (network, receivers, _, _) = test_setup(n_parties, vec![]);
    let mut nodes = nodes_for(n_parties, t, 245);

    let mut rng = StdRng::seed_from_u64(245);
    let mut dabits = deal_dabits(n_parties, t, width, &mut rng);

    // Replace the binary half of one daBit with a sharing of the *complement* of the bit its
    // arithmetic half carries. Both halves are still perfectly good degree-`t` sharings of
    // perfectly good bits — which is exactly why the two exact-zero bit-ness checks cannot see
    // this, and why only the bucketed cross-domain check can.
    let dealt_bit = dabit_bit_at(bad_index);
    let flipped =
        GfShare::compute_shares(bit_to_binary::<K>(!dealt_bit), n_parties, t, &mut rng).unwrap();
    for party in 0..n_parties {
        let arith = dabits[party][bad_index].arith.clone();
        dabits[party][bad_index] = DaBit::new(arith, flipped[party].clone(), t).unwrap();
    }

    for (party, node) in nodes.iter_mut().enumerate() {
        node.conv_preprocessing_material
            .lock()
            .await
            .add(Some(dabits[party].clone()), None);
    }

    let mut per_party_bits: Vec<Vec<Vec<GfShare<K>>>> = vec![Vec::new(); n_parties];
    let mut column: Vec<Vec<GfShare<K>>> = vec![Vec::new(); n_parties];
    for _ in 0..width {
        let shares = GfShare::compute_shares(K::one(), n_parties, t, &mut rng).unwrap();
        for party in 0..n_parties {
            column[party].push(shares[party].clone());
        }
    }
    for party in 0..n_parties {
        per_party_bits[party].push(column[party].clone());
    }

    pump_fake(
        receivers,
        nodes.clone(),
        network.clone(),
        Adversary::default(),
        None,
    );

    let mut handles = Vec::new();
    for pid in 0..n_parties {
        let mut node = nodes[pid].clone();
        let net = network[pid].clone();
        let bits = per_party_bits[pid].clone();
        handles.push(tokio::spawn(async move { node.b2a(bits, net).await }));
    }

    let mut results = Vec::with_capacity(n_parties);
    for (pid, handle) in handles.into_iter().enumerate() {
        results.push(
            handle
                .await
                .unwrap()
                .unwrap_or_else(|e| panic!("b2a failed at party {pid}: {e:?}")),
        );
    }

    let shares: Vec<RobustShare<F>> = results[0..=2 * t].iter().map(|r| r[0].clone()).collect();
    let (_, got) = RobustShare::recover_secret(&shares, n_parties, t).unwrap();

    let honest = (1u64 << width) - 1;
    // The failure is silent, agreed across every party, and exactly one bit wide: the opened
    // `c = x XOR r.bin` says one thing while the reconstruction from `r.arith` assumes the other,
    // so bit `bad_index` — and only bit `bad_index` — comes back complemented. Every input bit
    // here is `1`, so the corrupted output is `honest` with that bit cleared.
    assert_ne!(
        got,
        F::from(honest),
        "an inconsistent daBit must be assumed to corrupt the output; if this now passes, \
         something downstream has started validating the pad and this test is stale"
    );
    assert_eq!(got, F::from(honest - (1u64 << bad_index)));
}

// ---------------------------------------------------------------------------------------------
// A2B: corrupt opener under churn, and replay into a retired conversion
// ---------------------------------------------------------------------------------------------

/// A corrupt opener *and* a network that duplicates and reorders every message, across A2B's
/// degree-`t` mask opening and all of its AND layers.
///
/// The B2A twin of this exists above; A2B is the harder case and was the one missing. B2A is a
/// single opening, so duplication and reordering have one session to confuse. A2B is a mask
/// opening followed by seven dependent AND layers, each its own session, each spending its own
/// Beaver triples in pool order — so a handler that was merely *tolerant* of a duplicate rather
/// than idempotent would consume a triple twice and desynchronise the parties' pools, and every
/// subsequent layer would then be computed against different material at different parties.
/// Nothing about that failure is detectable at the layer where it happens.
///
/// The run must still return at every honest party — no abort — and the bits must be right.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a2b_tolerates_a_corrupt_opener_under_churn() {
    setup_tracing();
    stats!(STATS);
    wire!(WIRE);
    let (n_parties, t, corrupt) = (4usize, 1usize, 3usize);
    // `0` and `p - 1` are the two ends of the conditional reduction: `0` never borrows, `p - 1`
    // always does, so the MUX selector is exercised in both positions inside one batch.
    let values = [F::from(0u64), F::from(0u64) - F::from(1u64)];

    let (nodes, results) = run_a2b(
        n_parties,
        t,
        237,
        &values,
        Adversary::corrupt_openings(corrupt, &STATS)
            .with_churn()
            .with_watch(&WIRE),
        None,
    )
    .await;

    assert!(
        STATS.tampered() > 0 && STATS.duplicated() > 0 && STATS.reordered() > 0,
        "tampered={} duplicated={} reordered={}",
        STATS.tampered(),
        STATS.duplicated(),
        STATS.reordered()
    );
    assert_a2b_bits(&results, &values, n_parties, t, Some(corrupt));
    // And the phase audit holds *under attack* as well: no amount of duplication, reordering or
    // forgery may push the conversion onto a preprocessing session.
    assert_wire_phase(
        &WIRE,
        ProtocolPhase::Online,
        &[ProtocolType::A2B, ProtocolType::A2BGfMul],
    );
    for node in &nodes {
        assert_eq!(node.conv.a2b.store_len().await, 0);
        assert_eq!(node.conv.a2b.open.store_len().await, 0);
        assert_eq!(node.conv.a2b.gf_mul.store_len().await, 0);
    }
}

/// Every message of a finished A2B, replayed into a party that has already retired the session.
///
/// The B2A twin above replays one opening. This replays a whole circuit: the mask `BatchRecon`,
/// and then one session per AND layer in whichever shape the deployment's
/// [`OpeningPolicy`](stoffelcrypto::honeybadger::gf_mul::OpeningPolicy) chose — at `n = 4` the
/// direct `GfMult` one, which is the shape whose per-sender slot a replay could plausibly refill.
///
/// Three stores have to stay empty afterwards, not one. A replay that re-admitted any of them
/// would be an unbounded-memory hole a peer can drive at will, since a conversion's traffic is
/// something every participant already holds a copy of and can resend forever.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replayed_traffic_cannot_resurrect_a_retired_a2b() {
    setup_tracing();
    let (n_parties, t) = (4usize, 1usize);
    let values = [F::from(0u64) - F::from(1u64)];
    let tape: Tape = Arc::new(StdMutex::new(Vec::new()));

    let (nodes, results) = run_a2b(
        n_parties,
        t,
        238,
        &values,
        Adversary::default(),
        Some(tape.clone()),
    )
    .await;
    assert_a2b_bits(&results, &values, n_parties, t, None);

    let recorded = tape.lock().unwrap().clone();
    // Both shapes, or the replay only exercises one kind of bookkeeping: `BatchRecon` is the mask
    // opening's two-round store, `GfMult` the direct all-to-all opener's one-slot-per-sender one,
    // and they are retired by different code.
    assert_tape_carries(&recorded, &["BatchRecon", "GfMult"]);
    assert_eq!(nodes[0].conv.a2b.store_len().await, 0);
    assert_eq!(nodes[0].conv.a2b.open.store_len().await, 0);
    assert_eq!(nodes[0].conv.a2b.gf_mul.store_len().await, 0);

    let (network, _receivers, _, _) = test_setup(n_parties, vec![]);
    let mut victim = nodes[0].clone();
    for (sender, bytes) in recorded {
        // Errors are fine and expected; a panic or a resurrected store is not.
        let _ = victim.process(sender, bytes, network[0].clone()).await;
    }

    assert_eq!(
        victim.conv.a2b.store_len().await,
        0,
        "a replayed conversion re-admitted a retired A2B session"
    );
    assert_eq!(
        victim.conv.a2b.open.store_len().await,
        0,
        "a replayed mask opening re-admitted a retired batch-reconstruction session"
    );
    assert_eq!(
        victim.conv.a2b.gf_mul.store_len().await,
        0,
        "a replayed AND layer re-admitted a retired multiplication session"
    );
}

// ---------------------------------------------------------------------------------------------
// Phase discipline: nothing from the preprocessing phase may appear on an online wire
// ---------------------------------------------------------------------------------------------

/// Every message an A2B puts on the wire belongs to an **online** session.
///
/// This is a structural audit rather than a behavioural one, and it is here because the failure
/// it looks for is silent by construction. `phase_of` classifies each session's calling protocol;
/// an online conversion that reached a `Dn07`, a `GfDn07`, a `RandBit` or any other
/// preprocessing-tagged session would have opened at degree `2t`, which at `n = 3t+1` has
/// unique-decoding radius `floor(t/2) < t` and is therefore not robust — but with every party
/// honest it reconstructs perfectly, so every functional test in this repo would still pass. The
/// property only becomes observable once someone lies, and then it is a guaranteed-output-delivery
/// break rather than a bug.
///
/// The expected set is asserted exactly, not merely bounded: `A2B` is the degree-`t` mask opening
/// and `A2BGfMul` the AND layers, and a run that had quietly stopped producing either would be a
/// test that no longer covers what it claims to.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a2b_puts_only_online_sessions_on_the_wire() {
    setup_tracing();
    wire!(WIRE);
    let (n_parties, t) = (4usize, 1usize);
    let values = [F::from(1u64 << 32), F::from(0u64) - F::from(1u64)];

    let (_, results) = run_a2b(n_parties, t, 239, &values, Adversary::watching(&WIRE), None).await;
    assert_a2b_bits(&results, &values, n_parties, t, None);

    assert_wire_phase(
        &WIRE,
        ProtocolPhase::Online,
        &[ProtocolType::A2B, ProtocolType::A2BGfMul],
    );
}

/// The B2A half of the same audit. One opening, one session, and it must be the online one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b2a_puts_only_online_sessions_on_the_wire() {
    setup_tracing();
    wire!(WIRE);
    let (n_parties, t) = (4usize, 1usize);

    let (_, expected, results) = run_b2a(
        n_parties,
        t,
        240,
        &[1, 8, 32],
        Adversary::watching(&WIRE),
        None,
    )
    .await;
    for (index, want) in expected.iter().enumerate() {
        let shares: Vec<RobustShare<F>> = results[0..=2 * t]
            .iter()
            .map(|r| r[index].clone())
            .collect();
        let (_, got) = RobustShare::recover_secret(&shares, n_parties, t).unwrap();
        assert_eq!(got, *want);
    }

    assert_wire_phase(&WIRE, ProtocolPhase::Online, &[ProtocolType::B2A]);
}

// ---------------------------------------------------------------------------------------------
// Turmoil: real delay and real cross-link reordering
// ---------------------------------------------------------------------------------------------

/// B2A end to end under turmoil's randomised 10-2000 ms per-link latency, with one party feeding
/// a wrong share into every opening.
///
/// The FakeNetwork tests above reorder deterministically; this one adds genuine asynchrony —
/// arbitrary interleavings across links, and a delay spread wide enough that a party regularly
/// starts a round before another has finished the previous one.
#[test]
fn b2a_e2e_turmoil_with_latency_and_a_corrupt_opener() {
    setup_tracing();

    let n_parties = 4;
    let t = 1;
    let corrupt = 3;
    let width = 8usize;
    stats!(STATS);
    let adv = Adversary::corrupt_openings(corrupt, &STATS);
    let expected = F::from((1u64 << width) - 1);

    let nodes = create_global_nodes::<F, Avid<SessionId>, RobustShare<F>, TurmoilNetwork>(
        n_parties,
        t,
        1,
        2,
        251,
        0,
        0,
        unused_precision(),
        MIN_STATISTICAL_SECURITY,
        Duration::from_secs(120),
        vec![],
    );

    let mut rng = StdRng::seed_from_u64(251);
    let dabits = deal_dabits(n_parties, t, width, &mut rng);
    let mut per_party_bits: Vec<Vec<Vec<GfShare<K>>>> = vec![Vec::new(); n_parties];
    {
        let mut column: Vec<Vec<GfShare<K>>> = vec![Vec::new(); n_parties];
        for _ in 0..width {
            let shares = GfShare::compute_shares(K::one(), n_parties, t, &mut rng).unwrap();
            for party in 0..n_parties {
                column[party].push(shares[party].clone());
            }
        }
        for party in 0..n_parties {
            per_party_bits[party].push(column[party].clone());
        }
    }

    tokio::runtime::Runtime::new().unwrap().block_on(async {
        for pid in 0..n_parties {
            nodes[pid]
                .conv_preprocessing_material
                .lock()
                .await
                .add(Some(dabits[pid].clone()), None);
        }
    });

    let (mut sim, inner) = turmoil_setup_with_duration(
        n_parties,
        vec![],
        Some((10, 2000)),
        Duration::from_secs(600),
    );
    let (tx, rx_done) = std::sync::mpsc::channel::<Result<(usize, Vec<RobustShare<F>>), String>>();
    let (done_tx, done_rx) = tokio::sync::broadcast::channel::<()>(n_parties);
    let barrier = Arc::new(tokio::sync::Barrier::new(n_parties));

    for id in 0..n_parties {
        let inner = inner.clone();
        let node = nodes[id].clone();
        let tx = tx.clone();
        let done_tx = done_tx.clone();
        let barrier = barrier.clone();
        let bits = per_party_bits[id].clone();

        sim.host(format!("node{}", id), move || {
            let inner = inner.clone();
            let mut node = node.clone();
            let tx = tx.clone();
            let done_tx = done_tx.clone();
            let barrier = barrier.clone();
            let bits = bits.clone();

            async move {
                let (network, mut rx) = TurmoilNetwork::new(SenderId::Node(id), inner).await;
                let net = Arc::new(network);
                barrier.wait().await;

                let mut worker = node.clone();
                let worker_net = net.clone();
                let handle = tokio::spawn(async move { worker.b2a(bits, worker_net).await });

                loop {
                    match rx.recv().await {
                        Some((sender, raw)) => {
                            let sender = match sender {
                                SenderId::Node(i) => i,
                                SenderId::Client(i) => i,
                            };
                            deliver(&mut node, &net, sender, raw, id, adv).await;
                        }
                        None => break,
                    }
                    tokio::task::yield_now().await;
                    if handle.is_finished() {
                        break;
                    }
                }

                match handle.await {
                    Ok(Ok(shares)) => {
                        let _ = tx.send(Ok((id, shares)));
                    }
                    Ok(Err(e)) => {
                        let _ = tx.send(Err(format!("node {id} b2a error: {e:?}")));
                    }
                    Err(e) => {
                        let _ = tx.send(Err(format!("node {id} join error: {e:?}")));
                    }
                }
                let _ = done_tx.send(());
                Ok(())
            }
        });
    }

    drop(tx);
    drop(done_tx);

    let mut done_rx = done_rx;
    sim.client("driver", async move {
        let mut count = 0;
        while count < n_parties {
            match done_rx.recv().await {
                Ok(()) => count += 1,
                Err(_) => break,
            }
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    });
    sim.run().unwrap();

    let results: Vec<_> = std::iter::from_fn(|| rx_done.try_recv().ok()).collect();
    assert_eq!(
        results.len(),
        n_parties,
        "not all nodes reported: got {}/{}",
        results.len(),
        n_parties
    );

    let mut by_party: Vec<Option<Vec<RobustShare<F>>>> = vec![None; n_parties];
    for r in results {
        match r {
            Err(e) => panic!("node failed: {e}"),
            Ok((id, shares)) => by_party[id] = Some(shares),
        }
    }
    let shares: Vec<RobustShare<F>> = (0..n_parties)
        .filter(|p| *p != corrupt)
        .map(|p| by_party[p].as_ref().expect("party reported")[0].clone())
        .take(2 * t + 1)
        .collect();
    let (_, got) = RobustShare::recover_secret(&shares, n_parties, t).unwrap();
    assert_eq!(got, expected);
    assert!(
        STATS.tampered() > 0,
        "no opening message was actually rewritten"
    );
}

/// A2B end to end under turmoil's randomised latency: a two-round degree-`t` mask opening
/// followed by 7 AND layers, each of which is its own round trip. At `n = 4` the default
/// `OpeningPolicy::Auto` opens those layers directly, one round apiece, so the conversion spans
/// `2 + 7 * 1 = 9` rounds of a network that delays every link independently — 16 is the figure
/// where the layers batch, and neither is the 8 that forgets the mask opening's second round.
#[test]
fn a2b_e2e_turmoil_with_latency() {
    setup_tracing();

    let n_parties = 4;
    let t = 1;
    let width = field_bit_width::<F>();
    // `p - 1` exercises the `c1 = 1` branch of the conditional reduction and pins the canonical
    // representative convention for a negative value.
    let value = F::from(0u64) - F::from(1u64);
    let adv = Adversary::default();

    let nodes = create_global_nodes::<F, Avid<SessionId>, RobustShare<F>, TurmoilNetwork>(
        n_parties,
        t,
        1,
        2,
        252,
        0,
        0,
        unused_precision(),
        MIN_STATISTICAL_SECURITY,
        Duration::from_secs(120),
        vec![],
    );

    let mut rng = StdRng::seed_from_u64(252);
    let per_conversion = A2BNode::<F, K>::gf_triples_per_conversion().unwrap();
    let inputs = deal_field(n_parties, t, &[value], &mut rng);
    let edabits = deal_edabits(n_parties, t, 1, &mut rng);
    let gf_triples = deal_gf_triples(n_parties, t, per_conversion, &mut rng);

    tokio::runtime::Runtime::new().unwrap().block_on(async {
        for pid in 0..n_parties {
            nodes[pid]
                .conv_preprocessing_material
                .lock()
                .await
                .add(None, Some(edabits[pid].clone()));
            nodes[pid]
                .gf_preprocessing_material
                .lock()
                .await
                .add(Some(gf_triples[pid].clone()), None);
        }
    });

    let (mut sim, inner) =
        turmoil_setup_with_duration(n_parties, vec![], Some((10, 200)), Duration::from_secs(900));
    let (tx, rx_done) = std::sync::mpsc::channel::<Result<(usize, Vec<Vec<GfShare<K>>>), String>>();
    let (done_tx, done_rx) = tokio::sync::broadcast::channel::<()>(n_parties);
    let barrier = Arc::new(tokio::sync::Barrier::new(n_parties));

    for id in 0..n_parties {
        let inner = inner.clone();
        let node = nodes[id].clone();
        let tx = tx.clone();
        let done_tx = done_tx.clone();
        let barrier = barrier.clone();
        let x = inputs[id].clone();

        sim.host(format!("node{}", id), move || {
            let inner = inner.clone();
            let mut node = node.clone();
            let tx = tx.clone();
            let done_tx = done_tx.clone();
            let barrier = barrier.clone();
            let x = x.clone();

            async move {
                let (network, mut rx) = TurmoilNetwork::new(SenderId::Node(id), inner).await;
                let net = Arc::new(network);
                barrier.wait().await;

                let mut worker = node.clone();
                let worker_net = net.clone();
                let handle = tokio::spawn(async move { worker.a2b(x, worker_net).await });

                loop {
                    match rx.recv().await {
                        Some((sender, raw)) => {
                            let sender = match sender {
                                SenderId::Node(i) => i,
                                SenderId::Client(i) => i,
                            };
                            deliver(&mut node, &net, sender, raw, id, adv).await;
                        }
                        None => break,
                    }
                    tokio::task::yield_now().await;
                    if handle.is_finished() {
                        break;
                    }
                }

                match handle.await {
                    Ok(Ok(bits)) => {
                        let _ = tx.send(Ok((id, bits)));
                    }
                    Ok(Err(e)) => {
                        let _ = tx.send(Err(format!("node {id} a2b error: {e:?}")));
                    }
                    Err(e) => {
                        let _ = tx.send(Err(format!("node {id} join error: {e:?}")));
                    }
                }
                let _ = done_tx.send(());
                Ok(())
            }
        });
    }

    drop(tx);
    drop(done_tx);

    let mut done_rx = done_rx;
    sim.client("driver", async move {
        let mut count = 0;
        while count < n_parties {
            match done_rx.recv().await {
                Ok(()) => count += 1,
                Err(_) => break,
            }
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    });
    sim.run().unwrap();

    let results: Vec<_> = std::iter::from_fn(|| rx_done.try_recv().ok()).collect();
    assert_eq!(
        results.len(),
        n_parties,
        "not all nodes reported: got {}/{}",
        results.len(),
        n_parties
    );

    let mut by_party: Vec<Option<Vec<Vec<GfShare<K>>>>> = vec![None; n_parties];
    for r in results {
        match r {
            Err(e) => panic!("node failed: {e}"),
            Ok((id, bits)) => by_party[id] = Some(bits),
        }
    }
    let want = canonical_bits::<F>(value, width).unwrap();
    for bit in 0..width {
        let shares: Vec<GfShare<K>> = (0..=2 * t)
            .map(|p| by_party[p].as_ref().expect("party reported")[0][bit].clone())
            .collect();
        let (_, got) = GfShare::recover_secret(&shares, n_parties, t).unwrap();
        assert_eq!(got, bit_to_binary::<K>(want[bit]), "bit {bit} mismatch");
    }
}

/// A2B end to end under turmoil's randomised per-link latency **and** a corrupt opener.
///
/// This is the strongest statement the file makes about the online phase, and it is the one the
/// threat model actually asks for: asynchronous, robust, guaranteed output delivery. The B2A twin
/// above is a single opening; here a party lies into the degree-`t` mask opening and into every
/// AND layer of a 7-deep circuit, while turmoil delivers each link with an independently drawn
/// 10-200 ms delay, so parties are routinely several rounds apart.
///
/// What must hold: every honest party **returns** — no abort, no timeout, no stall — and the bits
/// are right. At `n = 4, t = 1` one liar is the full error budget of the degree-`t` code, so this
/// is the boundary case rather than a comfortable one. Nothing here may be rescued by a retry or
/// by waiting for a synchronous round; if the decode were not re-attempted on each arrival, or if
/// any of these openings had been at degree `2t`, the run would hang instead of failing loudly.
#[test]
fn a2b_e2e_turmoil_with_latency_and_a_corrupt_opener() {
    setup_tracing();

    let n_parties = 4;
    let t = 1;
    let corrupt = 3;
    let width = field_bit_width::<F>();
    stats!(STATS);
    // `p - 1` exercises the borrow branch of the conditional reduction, which is where a quietly
    // wrong `y` would land on the wrong side of the MUX.
    let value = F::from(0u64) - F::from(1u64);
    let adv = Adversary::corrupt_openings(corrupt, &STATS);

    let nodes = create_global_nodes::<F, Avid<SessionId>, RobustShare<F>, TurmoilNetwork>(
        n_parties,
        t,
        1,
        2,
        253,
        0,
        0,
        unused_precision(),
        MIN_STATISTICAL_SECURITY,
        Duration::from_secs(120),
        vec![],
    );

    let mut rng = StdRng::seed_from_u64(253);
    let per_conversion = A2BNode::<F, K>::gf_triples_per_conversion().unwrap();
    let inputs = deal_field(n_parties, t, &[value], &mut rng);
    let edabits = deal_edabits(n_parties, t, 1, &mut rng);
    let gf_triples = deal_gf_triples(n_parties, t, per_conversion, &mut rng);

    tokio::runtime::Runtime::new().unwrap().block_on(async {
        for pid in 0..n_parties {
            nodes[pid]
                .conv_preprocessing_material
                .lock()
                .await
                .add(None, Some(edabits[pid].clone()));
            nodes[pid]
                .gf_preprocessing_material
                .lock()
                .await
                .add(Some(gf_triples[pid].clone()), None);
        }
    });

    let (mut sim, inner) =
        turmoil_setup_with_duration(n_parties, vec![], Some((10, 200)), Duration::from_secs(900));
    let (tx, rx_done) = std::sync::mpsc::channel::<Result<(usize, Vec<Vec<GfShare<K>>>), String>>();
    let (done_tx, done_rx) = tokio::sync::broadcast::channel::<()>(n_parties);
    let barrier = Arc::new(tokio::sync::Barrier::new(n_parties));

    for id in 0..n_parties {
        let inner = inner.clone();
        let node = nodes[id].clone();
        let tx = tx.clone();
        let done_tx = done_tx.clone();
        let barrier = barrier.clone();
        let x = inputs[id].clone();

        sim.host(format!("node{}", id), move || {
            let inner = inner.clone();
            let mut node = node.clone();
            let tx = tx.clone();
            let done_tx = done_tx.clone();
            let barrier = barrier.clone();
            let x = x.clone();

            async move {
                let (network, mut rx) = TurmoilNetwork::new(SenderId::Node(id), inner).await;
                let net = Arc::new(network);
                barrier.wait().await;

                let mut worker = node.clone();
                let worker_net = net.clone();
                let handle = tokio::spawn(async move { worker.a2b(x, worker_net).await });

                loop {
                    match rx.recv().await {
                        Some((sender, raw)) => {
                            let sender = match sender {
                                SenderId::Node(i) => i,
                                SenderId::Client(i) => i,
                            };
                            deliver(&mut node, &net, sender, raw, id, adv).await;
                        }
                        None => break,
                    }
                    tokio::task::yield_now().await;
                    if handle.is_finished() {
                        break;
                    }
                }

                match handle.await {
                    Ok(Ok(bits)) => {
                        let _ = tx.send(Ok((id, bits)));
                    }
                    Ok(Err(e)) => {
                        let _ = tx.send(Err(format!("node {id} a2b error: {e:?}")));
                    }
                    Err(e) => {
                        let _ = tx.send(Err(format!("node {id} join error: {e:?}")));
                    }
                }
                let _ = done_tx.send(());
                Ok(())
            }
        });
    }

    drop(tx);
    drop(done_tx);

    let mut done_rx = done_rx;
    sim.client("driver", async move {
        let mut count = 0;
        while count < n_parties {
            match done_rx.recv().await {
                Ok(()) => count += 1,
                Err(_) => break,
            }
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    });
    sim.run().unwrap();

    let results: Vec<_> = std::iter::from_fn(|| rx_done.try_recv().ok()).collect();
    assert_eq!(
        results.len(),
        n_parties,
        "not all nodes reported: got {}/{}",
        results.len(),
        n_parties
    );

    let mut by_party: Vec<Option<Vec<Vec<GfShare<K>>>>> = vec![None; n_parties];
    for r in results {
        match r {
            // A conversion that errored out is the failure this test exists to rule out: the
            // online phase has no abort, so a lying party must cost accuracy of nothing and
            // liveness of nothing.
            Err(e) => panic!("node failed: {e}"),
            Ok((id, bits)) => by_party[id] = Some(bits),
        }
    }
    let want = canonical_bits::<F>(value, width).unwrap();
    for bit in 0..width {
        let shares: Vec<GfShare<K>> = (0..n_parties)
            .filter(|p| *p != corrupt)
            .map(|p| by_party[p].as_ref().expect("party reported")[0][bit].clone())
            .take(2 * t + 1)
            .collect();
        let (_, got) = GfShare::recover_secret(&shares, n_parties, t).unwrap();
        assert_eq!(got, bit_to_binary::<K>(want[bit]), "bit {bit} mismatch");
    }
    assert!(
        STATS.tampered() > 0,
        "no opening message was actually rewritten"
    );
}

// ---------------------------------------------------------------------------------------------
// Preprocessing: abort is licensed, silence is not
// ---------------------------------------------------------------------------------------------
//
// Everything above this line runs in the **online** phase: asynchronous, robust, degree-`t` only,
// no abort under any adversarial behaviour. Everything below runs in **preprocessing**:
// synchronous, timeouts and abort permitted, degree-`2t` openings legal — and cheaper, which is
// why they are used there.
//
// The obligation that survives the relaxation is *detection*. A corrupt party may kill a
// preprocessing batch; it may not make one come out wrong. At `n = 3t+1` the degree-`2t`
// evaluation code is `[3t+1, 2t+1]` with minimum distance `n - 2t = t+1 > t`, so any deviation of
// weight at most `t` is a non-codeword: `batch_recover_secret` fails rather than returning a wrong
// value, with soundness error 0. `GfBatchReconNode`'s own arrival threshold is `degree + t + 1`,
// which at `degree = 2t` is exactly `n` — so every honest party waits for all `n` contributions
// and the detection is deterministic rather than a race with the corrupt party's arrival order.
//
// `dn07_test` covers this at the standalone-node level by corrupting a party's *mask* before it
// ever reaches the network. What is covered here instead is the node dispatcher: a Byzantine
// party that lies on the **wire**, whose forgery therefore has to survive admission, sender
// authentication and the drain before it can reach the decode at all.

/// The GF PRSS/PRZS double-sharing source behind `GfDn07MulNode`, dealt rather than established
/// by running RISS over the network — `setup_prss_keys` is `PRandIntNode`'s protocol, not this
/// one. What matters is only that each party holds the key for every maximal unqualified set it
/// is outside of, which is what the one-time setup produces.
fn deal_gf_doubles(n_parties: usize, t: usize, seed: u64) -> Vec<GfPrssDoubleShareSource<K>> {
    let mut rng = StdRng::seed_from_u64(seed);
    let family: Vec<[u8; PRSS_KEY_LEN]> = (0..all_tsets(n_parties, t).len())
        .map(|_| {
            let mut key = [0u8; PRSS_KEY_LEN];
            rng.fill(&mut key);
            key
        })
        .collect();
    (0..n_parties)
        .map(|id| {
            let keys: Vec<(usize, [u8; PRSS_KEY_LEN])> = held_ranks(n_parties, t, id)
                .into_iter()
                .map(|rank| (rank, family[rank]))
                .collect();
            GfPrssDoubleShareSource::new(
                GfPrssKeys::<K>::new(id, n_parties, t, &keys).unwrap(),
                GfPrzsKeys::<K>::new(id, n_parties, t, &keys).unwrap(),
            )
            .unwrap()
        })
        .collect()
}

/// One batch of DN07 multiplications over `Gf256`, driven end to end through
/// `HoneyBadgerMPCNode::process`.
///
/// This is the degree-`2t` engine under conversion preprocessing, and it is now **caller-driven
/// as well as dispatch-reachable**: `EdaBitFilterNode` runs every AND layer of the modulus-
/// overflow circuit through `GfDn07MulNode::init_mul` under `ProtocolType::DaBitGfMul`, in place
/// of the `GfMultiply` and the 63 GF(2^k) Beaver triples per candidate it used to spend. What
/// this harness drives is `gf_preprocess.gf_dn07` under `ProtocolType::GfDn07` — the same node
/// type on the node's own instance and dispatcher arm — so it exercises the primitive and the
/// routing directly rather than through the filter, which `edabit_filter_test.rs` covers.
///
/// No production caller uses `init_zero_check`: the bit-ness obligations it was meant to
/// discharge went away with the dealt daBit protocol, and PRSS daBits carry no dealt value to
/// certify. The exact-zero check is tested here and in `dn07_test.rs` and is unspent.
///
/// The batch is `2t + 1` wide because that is a degree-`2t` batch-reconstruction group: a partial
/// group would be padded and the test would be measuring the padding.
///
/// The session is **retired here, on both exit paths**, because retirement is the caller's
/// obligation for this node — `clear_store` is public and `run_dabit_batch` calls its `F`-side
/// twin before its own `?` for exactly this reason. Doing it in the harness is what lets the
/// tests below assert containment after an abort rather than only after a success.
///
/// Returns each party's outcome, `None` for an error, so a caller can distinguish "aborted" from
/// "accepted something" per party rather than in aggregate.
#[allow(clippy::type_complexity)]
async fn run_gf_dn07_mul(
    n_parties: usize,
    t: usize,
    instance_id: u32,
    adv: Adversary,
    tape: Option<Tape>,
) -> (Vec<Node>, Vec<K>, Vec<Option<Vec<GfShare<K>>>>) {
    let width = 2 * t + 1;
    let (network, receivers, _, _) = test_setup(n_parties, vec![]);
    let mut nodes = nodes_for(n_parties, t, instance_id);
    let sources = deal_gf_doubles(n_parties, t, instance_id as u64);

    let mut rng = StdRng::seed_from_u64(instance_id as u64 ^ 0x5A5A);
    let xs: Vec<K> = (0..width).map(|_| K::random(&mut rng)).collect();
    let ys: Vec<K> = (0..width).map(|_| K::random(&mut rng)).collect();
    let mut x_shares: Vec<Vec<GfShare<K>>> = vec![Vec::new(); n_parties];
    let mut y_shares: Vec<Vec<GfShare<K>>> = vec![Vec::new(); n_parties];
    for i in 0..width {
        let sx = GfShare::compute_shares(xs[i], n_parties, t, &mut rng).unwrap();
        let sy = GfShare::compute_shares(ys[i], n_parties, t, &mut rng).unwrap();
        for party in 0..n_parties {
            x_shares[party].push(sx[party].clone());
            y_shares[party].push(sy[party].clone());
        }
    }

    let session_id = SessionId::new(
        ProtocolType::GfDn07,
        SessionId::pack_slot(instance_id as u64, 0, 0),
        instance_id,
    );
    // The type, not a review note, is what keeps this opening off the online path: `init_mul`
    // accepts nothing but a `PreprocessingSessionId`, whose only constructor classifies the tag
    // through `phase_of` and rejects every online one.
    let pre = PreprocessingSessionId::new(session_id).unwrap();

    pump_fake(receivers, nodes.clone(), network.clone(), adv, tape);

    for (party, node) in nodes.iter_mut().enumerate() {
        let doubles = sources[party].double_shares_at(pre, 0, width).unwrap();
        node.gf_preprocess
            .gf_dn07
            .init_mul(
                pre,
                x_shares[party].clone(),
                y_shares[party].clone(),
                doubles,
                network[party].clone(),
            )
            .await
            .unwrap();
    }

    let mut outcomes = Vec::with_capacity(n_parties);
    for node in nodes.iter() {
        let handle = node.gf_preprocess.gf_dn07.clone();
        outcomes.push(
            handle
                .wait_for_products(session_id, Duration::from_secs(2))
                .await
                .ok(),
        );
        handle.clear_store(session_id).await;
    }

    let products: Vec<K> = xs.iter().zip(ys.iter()).map(|(x, y)| *x * *y).collect();
    (nodes, products, outcomes)
}

/// The honest control for the two tests below: a DN07 batch over `Gf256` really does produce
/// degree-`t` sharings of the products, routed through the node dispatcher's `GfDn07` arm.
///
/// Without this, the corrupt-party test could pass because the harness never worked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn conversion_preprocessing_multiplies_through_node_dispatch() {
    setup_tracing();
    let (n_parties, t) = (4usize, 1usize);

    let (nodes, want, outcomes) =
        run_gf_dn07_mul(n_parties, t, 241, Adversary::default(), None).await;

    for (party, outcome) in outcomes.iter().enumerate() {
        assert!(outcome.is_some(), "party {party} produced no products");
    }
    for (index, expected) in want.iter().enumerate() {
        let shares: Vec<GfShare<K>> = outcomes
            .iter()
            .map(|o| o.as_ref().unwrap()[index].clone())
            .collect();
        for share in &shares {
            assert_eq!(share.degree, t, "DN07 must hand back a degree-t sharing");
        }
        let (_, got) = GfShare::recover_secret(&shares, n_parties, t).unwrap();
        assert_eq!(got, *expected, "product {index} is wrong");
    }
    for node in &nodes {
        assert_eq!(
            node.gf_preprocess.gf_dn07.store_len().await,
            0,
            "a retired DN07 session left a store behind"
        );
    }
}

/// A corrupt party lies on the wire inside a degree-`2t` preprocessing opening.
///
/// **This must abort, and the abort must be visible.** The two failures being ruled out are very
/// different from each other and only one of them is loud:
///
/// * *silent acceptance* — an honest party returns a product built from the corrupted opening.
///   That is the catastrophic one: every Beaver triple derived from it is wrong, every AND gate
///   that spends one is wrong, and nothing downstream re-checks a triple. The assertion below is
///   therefore not "somebody errored" but "nobody accepted", checked per party.
/// * *silent stalling* — nothing is reported at all. Legal for liveness (preprocessing may be
///   timed out and retried) but it would let this test pass while the decode was never reached,
///   so a decoding-shaped error is required to have been raised.
///
/// Detection here is deterministic, not probabilistic: the corrupted evaluation vector differs
/// from a codeword of the `[3t+1, 2t+1]` code in one position, its minimum distance is
/// `t + 1 = 2 > 1`, and the arrival threshold `degree + t + 1` equals `n` at degree `2t` so no
/// honest party can decode from a subset that happens to exclude the liar.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_corrupt_share_in_conversion_preprocessing_is_detected_not_accepted() {
    setup_tracing();
    stats!(STATS);
    faults!(FAULTS);
    let (n_parties, t, corrupt) = (4usize, 1usize, 3usize);

    let (nodes, want, outcomes) = run_gf_dn07_mul(
        n_parties,
        t,
        242,
        Adversary::corrupt_openings(corrupt, &STATS).with_faults(&FAULTS),
        None,
    )
    .await;

    assert!(
        STATS.tampered() > 0,
        "no opening message was actually rewritten"
    );

    for (party, outcome) in outcomes.iter().enumerate() {
        if party == corrupt {
            continue;
        }
        assert!(
            outcome.is_none(),
            "party {party} accepted products from a corrupted degree-2t opening: {:?} (the \
             honest products would have been {want:?})",
            outcome.as_ref().map(|o| o.len()),
        );
    }

    let reported = FAULTS.all();
    assert!(
        reported.iter().any(|e| e.contains("Decoding")
            || e.contains("Interpolate")
            || e.contains("NotEnoughShares")
            || e.contains("Reconstruct")),
        "a corrupted degree-2t opening must be DETECTED, not merely stalled; the dispatcher \
         reported {reported:?}"
    );

    // Detected *and* contained: a batch that aborted must leave no store behind, or a peer could
    // drive memory by aborting batches forever.
    for node in &nodes {
        assert_eq!(
            node.gf_preprocess.gf_dn07.store_len().await,
            0,
            "an aborted DN07 session left a store behind; cleanup must run on the failure \
             path too, or a peer can drive memory by aborting batches forever"
        );
    }
}

/// The converse of the online audit: the opening that produces conversion material really is
/// tagged as preprocessing.
///
/// This exists so that the `ProtocolPhase::Online` assertions above cannot pass vacuously. If
/// `phase_of` ever collapsed to a constant — a `_ =>` arm added to its match, say — the online
/// audits would go on passing and nothing else in the suite would notice. Here the same function
/// is asked for the other answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn conversion_preprocessing_puts_only_preprocessing_sessions_on_the_wire() {
    setup_tracing();
    wire!(WIRE);
    let (n_parties, t) = (4usize, 1usize);

    let (_, _, outcomes) =
        run_gf_dn07_mul(n_parties, t, 243, Adversary::watching(&WIRE), None).await;
    assert!(outcomes.iter().all(|o| o.is_some()));

    assert_wire_phase(&WIRE, ProtocolPhase::Preprocessing, &[ProtocolType::GfDn07]);
}

/// A finished preprocessing batch's traffic, replayed into a party that has retired it.
///
/// Preprocessing may abort; it may not be made to leak memory. A degree-`2t` opening's messages
/// are held by every participant and can be resent forever, so a retired session must absorb the
/// replay without re-admitting a store — and without erroring the victim's whole message loop,
/// which asynchronously is indistinguishable from an honest straggler.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replayed_traffic_cannot_resurrect_a_retired_preprocessing_batch() {
    setup_tracing();
    let (n_parties, t) = (4usize, 1usize);
    let tape: Tape = Arc::new(StdMutex::new(Vec::new()));

    let (nodes, _, outcomes) =
        run_gf_dn07_mul(n_parties, t, 244, Adversary::default(), Some(tape.clone())).await;
    assert!(outcomes.iter().all(|o| o.is_some()));

    let recorded = tape.lock().unwrap().clone();
    assert_tape_carries(&recorded, &["GfBatchRecon"]);
    assert_eq!(nodes[0].gf_preprocess.gf_dn07.store_len().await, 0);

    let (network, _receivers, _, _) = test_setup(n_parties, vec![]);
    let mut victim = nodes[0].clone();
    for (sender, bytes) in recorded {
        let _ = victim.process(sender, bytes, network[0].clone()).await;
    }

    assert_eq!(
        victim.gf_preprocess.gf_dn07.store_len().await,
        0,
        "a replayed preprocessing batch re-admitted a retired degree-2t session"
    );
}

// ---------------------------------------------------------------------------------------------
// The phase boundary itself: as a type, as an observed fact, and under attack
// ---------------------------------------------------------------------------------------------
//
// Everything above tests the two phases *separately*: the online conversions are robust, the
// preprocessing batch aborts loudly. What is tested below is the line between them, which after
// the PRSS/PRZS rewiring carries more weight than it did.
//
// The rewiring moved `RandBit` off dealt `RanSha` + `ZeroSha` and onto PRSS + PRZS. That changes
// nothing about `RandBit`'s *phase* — it was preprocessing before and it is preprocessing now,
// and `phase_of` says so — but it changes what a phase violation would cost. A PRSS/PRZS position
// is derived, not dealt, and the whole family is addressed by `(session, position)`: a derivation
// reached from an online conversion would be reached at whatever position that conversion's
// caller happened to be at, with no interactive round to make the reuse visible. So "no online
// session may reach preprocessing machinery" stopped being only a degree-`2t` argument and became
// a position-reuse argument as well, and it is worth asserting rather than reasoning about.
//
// Three assertions, in increasing order of how much of the system they involve:
//
// 1. **The type.** No online session id can be turned into a `PreprocessingSessionId`, checked
//    over *every* `ProtocolType` the wire format can carry rather than over a list someone
//    remembered to update.
// 2. **The fact.** Every session id an A2B and a B2A really put on the wire is refused by that
//    same constructor. The type protects callers who are willing to be protected; this checks
//    that the sessions the conversions actually mint are on the right side of it.
// 3. **Under attack.** Both of the above, plus the online robustness claim, while a corrupt party
//    is lying — first about share *values*, then about their *degree*, which is the one lie that
//    is a phase claim rather than an arithmetic one.

/// No session belonging to an online protocol can be turned into a [`PreprocessingSessionId`],
/// and therefore none can reach `Dn07MulNode::init_mul` or its `Gf` twin.
///
/// **The enumeration is over `from_u8`, not over a hand-written list**, and that is the point of
/// the test. `phase_of`'s exhaustive match already forces the *author* of a new `ProtocolType` to
/// classify it; nothing forces them to come back here. Walking every byte the wire format can
/// decode means a variant added tomorrow is checked tomorrow, in whichever phase its author put
/// it, without this file being edited.
///
/// Each phase is checked for a *specific* error and not merely for failure, because the three
/// rejections mean different things and a test that accepted any of them would pass while the
/// interesting one had been lost:
///
/// * an online tag must fail with [`Dn07Error::OnlinePhaseForbidden`] — the error the module
///   exists to be able to return;
/// * a transport tag must fail with [`Dn07Error::MissingCallingProtocol`], because it names no
///   calling protocol at all and is malformed as a DN07 caller rather than mis-phased;
/// * a preprocessing tag must *succeed*, or the constructor is not a classification but a
///   blanket refusal and assertion (1) would be vacuous.
#[test]
fn no_online_session_id_can_construct_a_preprocessing_session_id() {
    const INSTANCE: u32 = 245;

    // Every tag the wire format can decode. `from_u8` is the wire contract, so this is exactly
    // the set a peer can put in a session id's caller byte.
    let tags: Vec<ProtocolType> = (0..=u8::MAX).filter_map(ProtocolType::from_u8).collect();
    assert!(
        tags.len() > 20,
        "the tag enumeration found only {} variants, so `from_u8` is not being walked",
        tags.len()
    );

    let root = |tag: ProtocolType| SessionId::new(tag, SessionId::pack_slot(7, 0, 0), INSTANCE);

    let mut online = Vec::new();
    let mut preprocessing = Vec::new();
    let mut transport = Vec::new();

    for tag in tags {
        let session = root(tag);
        match phase_of(tag) {
            ProtocolPhase::Online => {
                match PreprocessingSessionId::new(session) {
                    Err(Dn07Error::OnlinePhaseForbidden { tag: got, .. }) => {
                        assert_eq!(
                            got, tag as u8,
                            "the refusal named tag {got}, but the session carries {tag:?}"
                        );
                    }
                    other => panic!(
                        "{tag:?} is an ONLINE protocol, so a degree-2t opening on its session is \
                         unreconstructible at n = 3t+1 — `PreprocessingSessionId::new` must \
                         refuse it with OnlinePhaseForbidden, and instead gave {:?}",
                        other.map(|s| s.get())
                    ),
                }
                online.push(tag);
            }
            ProtocolPhase::Transport => {
                match PreprocessingSessionId::new(session) {
                    Err(Dn07Error::MissingCallingProtocol(_)) => {}
                    other => panic!(
                        "{tag:?} is a transport tag and names no calling protocol, so it is \
                         malformed as a DN07 caller rather than merely mis-phased; expected \
                         MissingCallingProtocol, got {:?}",
                        other.map(|s| s.get())
                    ),
                }
                transport.push(tag);
            }
            ProtocolPhase::Preprocessing => {
                let accepted = PreprocessingSessionId::new(session).unwrap_or_else(|e| {
                    panic!(
                        "{tag:?} is a PREPROCESSING protocol and must be accepted, or this \
                         constructor is a blanket refusal rather than a classification and every \
                         other assertion here is vacuous: {e:?}"
                    )
                });
                assert_eq!(
                    accepted.get(),
                    session,
                    "the wrapper altered the session id"
                );

                // The shape check is separate from the phase check and must not be able to
                // stand in for it. A preprocessing tag carried on a *child* session — one whose
                // sub/round bytes are already spent — is still refused, because those bytes are
                // the space DN07 mints its own batch-reconstruction child in.
                for dirty in [
                    SessionId::new(tag, SessionId::pack_slot(7, 1, 0), INSTANCE),
                    SessionId::new(tag, SessionId::pack_slot(7, 0, 1), INSTANCE),
                ] {
                    assert!(
                        matches!(
                            PreprocessingSessionId::new(dirty),
                            Err(Dn07Error::MalformedSessionId(_))
                        ),
                        "{tag:?} with a non-root sub/round must be refused as malformed"
                    );
                }
                preprocessing.push(tag);
            }
        }
    }

    // Non-vacuity, in both directions. Without these the test would pass if `phase_of` collapsed
    // to a constant, or if the three conversion tags were quietly reclassified.
    assert!(
        !online.is_empty() && !preprocessing.is_empty() && !transport.is_empty(),
        "one of the three phases was never observed: online={online:?} \
         preprocessing={preprocessing:?} transport={transport:?}"
    );
    for tag in [ProtocolType::A2B, ProtocolType::A2BGfMul, ProtocolType::B2A] {
        assert!(
            online.contains(&tag),
            "{tag:?} is a session an online conversion mints on its own wire and must be \
             classified Online; it was not, so DN07 is reachable from a conversion"
        );
    }
    for tag in [
        ProtocolType::Dn07,
        ProtocolType::GfDn07,
        // The rewiring's tag. `RandBit` is drawn from PRSS + PRZS now rather than from dealt
        // `RanSha` + `ZeroSha`, and is reachable from A2B by lazy top-up — but only ever as
        // preprocessing work scheduled *around* the conversion, never on the conversion's own
        // session. Its classification is what keeps that true.
        ProtocolType::RandBit,
    ] {
        assert!(
            preprocessing.contains(&tag),
            "{tag:?} must be classified Preprocessing"
        );
    }

    // A caller byte that decodes to no variant at all. This is not a hypothetical: a session id
    // arrives from the wire as 128 bits chosen by whoever sent it, and `calling_protocol`'s
    // `Option` return is the type admitting as much. It must be refused, not defaulted.
    let unknown: u8 = (0..=u8::MAX)
        .find(|b| ProtocolType::from_u8(*b).is_none())
        .expect("every byte decodes to a protocol, so there is no unknown-tag case to test");
    // SAFETY: `SessionId` is a plain `u128` newtype with no validity invariant — `from_u128` is
    // `unsafe` to mark "this bit pattern was not minted by `new`", which is precisely the case
    // under test. Nothing is dereferenced and no other invariant is asserted.
    let forged = unsafe {
        SessionId::from_u128(
            ((unknown as u128) << 112) | ((SessionId::pack_slot(7, 0, 0)) << 32) | INSTANCE as u128,
        )
    };
    assert_eq!(forged.calling_protocol(), None);
    assert!(
        matches!(
            PreprocessingSessionId::new(forged),
            Err(Dn07Error::MissingCallingProtocol(_))
        ),
        "a session id carrying an undecodable caller byte must be refused"
    );
}

/// Every session id an A2B and a B2A **actually emitted** is refused by the DN07 constructor.
///
/// The test above checks the classification; this one checks that the conversions live inside it.
/// Those are different claims, and only the second one would notice a conversion that started
/// minting its openings under some other tag — a `GfTriple`, say, or a bare `GfBatchRecon` — in
/// which case the type would go on refusing online tags correctly while the traffic that matters
/// had walked around it.
///
/// Each observed id is checked twice, and the second check is the one that cannot be satisfied by
/// accident. As it appeared on the wire, an id must be refused for *some* reason; then, re-minted
/// in the root shape `PreprocessingSessionId::new` is willing to consider at all — sub and round
/// bytes cleared — it must be refused specifically as [`Dn07Error::OnlinePhaseForbidden`].
/// Without the second, a run in which every observed id merely happened to be a child session
/// would pass on the shape check while the phase check was never reached.
///
/// As it turns out the ids these conversions emit are *already* root-shaped, so both checks bite
/// on the same ground and the fact is a little sharper than the test needs it to be: what A2B and
/// B2A put on the wire is exactly the shape `init_mul` would accept, and the only thing standing
/// between it and a degree-`2t` opening is its phase.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_session_the_online_conversions_emit_is_refused_by_dn07() {
    setup_tracing();
    wire!(A2B_WIRE);
    wire!(B2A_WIRE);
    let (n_parties, t) = (4usize, 1usize);

    let values = [F::from(1u64 << 32), F::from(0u64) - F::from(1u64)];
    let (_, a2b_results) = run_a2b(
        n_parties,
        t,
        246,
        &values,
        Adversary::watching(&A2B_WIRE),
        None,
    )
    .await;
    assert_a2b_bits(&a2b_results, &values, n_parties, t, None);

    let (_, expected, b2a_results) = run_b2a(
        n_parties,
        t,
        247,
        &[1, 8, 32],
        Adversary::watching(&B2A_WIRE),
        None,
    )
    .await;
    for (index, want) in expected.iter().enumerate() {
        let shares: Vec<RobustShare<F>> = b2a_results[0..=2 * t]
            .iter()
            .map(|r| r[index].clone())
            .collect();
        let (_, got) = RobustShare::recover_secret(&shares, n_parties, t).unwrap();
        assert_eq!(got, *want);
    }

    let mut checked = 0usize;
    let mut tags: Vec<ProtocolType> = Vec::new();
    for wire in [&A2B_WIRE, &B2A_WIRE] {
        let recorded = wire.seen.lock().unwrap().clone();
        assert!(!recorded.is_empty(), "the observer recorded nothing");
        for raw in recorded {
            let (name, _) = wire_caller(&raw);
            let Some(session) = wire_session(&raw) else {
                panic!(
                    "a {name} message on an online conversion's wire carries no session id, so \
                     it cannot be audited; every shape a conversion emits must be classifiable"
                );
            };
            assert!(
                PreprocessingSessionId::new(session).is_err(),
                "{session:?} (a {name} an online conversion put on the wire) can be turned into \
                 a PreprocessingSessionId, so it can be handed to a degree-2t opening"
            );

            let tag = session
                .calling_protocol()
                .unwrap_or_else(|| panic!("{session:?} ({name}) carries no calling protocol"));
            tags.push(tag);

            // The dangerous shape: the session re-minted as a root, which is the only form
            // `init_mul` would consider in the first place. Refusal here has to be the *phase*
            // refusal, not the shape one.
            let as_root = SessionId::new(
                tag,
                SessionId::pack_slot(session.exec_id(), 0, 0),
                session.instance_id(),
            );
            match PreprocessingSessionId::new(as_root) {
                Err(Dn07Error::OnlinePhaseForbidden { tag: got, .. }) => assert_eq!(got, tag as u8),
                other => panic!(
                    "{session:?} ({name}, tag {tag:?}) re-minted as the root session \
                     {as_root:?} was not refused as an online phase violation; got {:?}. A \
                     conversion whose root session is acceptable to DN07 is one AND layer away \
                     from a degree-2t opening on the asynchronous robust path.",
                    other.map(|s| s.get())
                ),
            }
            checked += 1;
        }
    }

    assert!(checked > 0, "no session id was audited");
    tags.sort_by_key(|tag| *tag as u8);
    tags.dedup();
    let mut want = vec![ProtocolType::A2B, ProtocolType::A2BGfMul, ProtocolType::B2A];
    want.sort_by_key(|tag| *tag as u8);
    assert_eq!(
        tags, want,
        "the two conversions did not put the expected session mix on the wire, so the audit \
         covered less than it claims"
    );
}

/// A2B's phase boundary **while a corrupt party is lying into every opening it can reach**.
///
/// `a2b_tolerates_a_corrupt_opener` asserts the output; `a2b_puts_only_online_sessions_on_the
/// _wire` asserts the phase. Neither rules out the combination, and the combination is where the
/// interesting failure lives: a party that cannot decode is a party looking for another way to
/// finish, and "another way" is exactly how a degree-`2t` opening — cheaper, and legal one phase
/// over — ends up on an asynchronous robust path. Robustness is not a licence to change phase.
///
/// So both are asserted of the same run: every honest party still returns the right bits, and
/// nothing that reached the wire while it did so belonged to a preprocessing session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a2b_holds_the_phase_boundary_under_a_corrupt_opener() {
    setup_tracing();
    stats!(STATS);
    wire!(WIRE);
    let (n_parties, t, corrupt) = (4usize, 1usize, 3usize);
    let values = [F::from(1u64 << 32), F::from(0u64) - F::from(1u64)];

    let (nodes, results) = run_a2b(
        n_parties,
        t,
        248,
        &values,
        Adversary::corrupt_openings(corrupt, &STATS).with_watch(&WIRE),
        None,
    )
    .await;

    // Both shapes, for the reason `a2b_tolerates_a_corrupt_opener` gives at length: the mask
    // opening and the AND layers travel in different message shapes, and an adversary that knew
    // only the first would leave every AND layer running honestly while this test reported a
    // healthy tally.
    assert!(
        STATS.tampered_batched() > 0 && STATS.tampered_direct() > 0,
        "the attack did not reach both opening shapes: batched={} direct={}",
        STATS.tampered_batched(),
        STATS.tampered_direct()
    );
    assert_a2b_bits(&results, &values, n_parties, t, Some(corrupt));
    assert_wire_phase(
        &WIRE,
        ProtocolPhase::Online,
        &[ProtocolType::A2B, ProtocolType::A2BGfMul],
    );
    for node in &nodes {
        assert_eq!(node.conv.a2b.store_len().await, 0);
        assert_eq!(node.conv.a2b.open.store_len().await, 0);
        assert_eq!(node.conv.a2b.gf_mul.store_len().await, 0);
    }
}

/// The B2A half of the same claim: one opening, still degree-`t`, still online, still right.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b2a_holds_the_phase_boundary_under_a_corrupt_opener() {
    setup_tracing();
    stats!(STATS);
    wire!(WIRE);
    let (n_parties, t, corrupt) = (4usize, 1usize, 3usize);

    let (nodes, expected, results) = run_b2a(
        n_parties,
        t,
        249,
        &[1, 8, 32],
        Adversary::corrupt_openings(corrupt, &STATS).with_watch(&WIRE),
        None,
    )
    .await;

    assert!(
        STATS.tampered() > 0,
        "no opening message was actually rewritten"
    );
    for (index, want) in expected.iter().enumerate() {
        let shares = honest_quorum(&results, index, t, corrupt);
        assert_eq!(shares.len(), 2 * t + 1);
        let (_, got) = RobustShare::recover_secret(&shares, n_parties, t).unwrap();
        assert_eq!(got, *want, "value {index} was not recovered");
    }
    assert_wire_phase(&WIRE, ProtocolPhase::Online, &[ProtocolType::B2A]);
    for node in &nodes {
        assert_eq!(node.conv.b2a.store_len().await, 0);
        assert_eq!(node.conv.b2a.gf_open.store_len().await, 0);
    }
}

/// A corrupt party claims degree `2t` on its direct-opening shares. The values are honest; only
/// the phase claim is a lie.
///
/// This is the attack the type system cannot reach. [`PreprocessingSessionId`] binds this crate's
/// own callers, and a peer is not one: its messages arrive as bytes and carry whatever the peer
/// chose to write. The online opening therefore has to make the same judgement the type makes.
///
/// **It now makes it in the encoding rather than at the door.** `GfShare` used to ship `degree`
/// (and `id`) on the wire and `GfMultiply::process` refused a mismatching one against its local
/// `t`. Since those fields moved off the wire — the receiver derives the index from the
/// authenticated sender and the degree from its own `threshold` — a peer has no way to state a
/// degree in the current encoding at all. [`relabel_degree`] therefore forges the **retired**
/// 17-byte-per-share body, which is the only remaining way to put the claim on the network, and
/// what this asserts is that such a body is refused rather than parsed.
///
/// Three things are asserted of the one run, and the middle one is the reason this is not just a
/// parser test:
///
/// * the degree-claiming bodies are **refused**, with a reported error;
/// * every honest party still returns the **right bits**. Refusing a share is not free — it makes
///   the liar silent, and a silent party still has to be inside the `t` budget. A refusal that
///   cost liveness would trade one guaranteed-output-delivery break for another;
/// * nothing preprocessing-tagged reached the wire while that happened.
///
/// The companion structural fact — that an *honest* direct-opening body has no room for a degree
/// or an index, being exactly two length prefixes plus one byte per share — is asserted from this
/// run's own recorded wire below, and unit-wise in `share_wire_encoding_test.rs`.
///
/// # This is also a cross-version compatibility guard, which the name does not say
///
/// The 17-byte-per-share body [`relabel_degree`] forges is not a shape invented for this test.
/// It is **exactly what a node on `main` emits**: `WrappedMessage::GfMult`'s payload was
/// `Vec<GfShare<K>>` there, and this branch already does not interoperate with `main` (reused
/// `ProtocolType` discriminants and no version tag — see the wire-format contract on
/// `WrappedMessage` in `honeybadger/mod.rs`). So this run also pins the rollout behaviour of that
/// break on this one path: an old-format body **fails closed**, refused rather than silently
/// misread as some other number of shares. Keep it passing for that reason as much as for the
/// adversarial one — if the direct-open payload shape is ever changed again, this is the test
/// that says whether the superseded shape still fails closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_online_opening_refuses_a_share_relabelled_to_degree_2t() {
    setup_tracing();
    stats!(STATS);
    faults!(FAULTS);
    wire!(WIRE);
    let (n_parties, t, corrupt) = (4usize, 1usize, 3usize);
    let values = [F::from(1u64 << 32), F::from(0u64) - F::from(1u64)];

    let (nodes, results) = run_a2b(
        n_parties,
        t,
        250,
        &values,
        Adversary::relabelling_degree(corrupt, 2 * t, &STATS)
            .with_faults(&FAULTS)
            .with_watch(&WIRE),
        None,
    )
    .await;

    assert!(
        STATS.relabelled() > 0,
        "no direct-opening share was actually relabelled; at n = {n_parties} the default \
         OpeningPolicy should route every AND layer through the direct GfMult path, so this \
         means the attack reached nothing"
    );

    let reported = FAULTS.all();
    assert!(
        !reported.is_empty(),
        "a body claiming degree {} on an ONLINE opening must be refused — at n = 3t+1 a \
         degree-2t opening has unique-decoding radius floor(t/2) < t and is not robust. The \
         dispatcher reported nothing, so the forged body was parsed",
        2 * t
    );

    // Refusing the liar makes it silent, and a silent party is still within the `t` budget — so
    // the conversion must complete, and correctly, for every honest party.
    assert_a2b_bits(&results, &values, n_parties, t, Some(corrupt));

    // And the structural half of the same claim, read off what this run actually emitted: an
    // honest direct-opening body is exactly two `u64` counts plus one byte per share. There is
    // no room in it for an index or a degree, which is what makes the forgery above have to
    // abandon the encoding to state one.
    let mut direct_bodies = 0usize;
    for raw in WIRE.seen.lock().unwrap().iter() {
        let Ok(WrappedMessage::GfMult(msg)) = bincode::deserialize::<WrappedMessage>(raw) else {
            continue;
        };
        let inner: GfMultReconstructionMessage<K> =
            bincode::deserialize(&msg.payload).expect("honest direct-open body");
        assert_eq!(
            msg.payload.len(),
            16 + inner.a_sub_x.len() + inner.b_sub_y.len(),
            "a direct-opening body must be two u64 counts plus one byte per share"
        );
        direct_bodies += 1;
    }
    assert!(
        direct_bodies > 0,
        "no direct-opening body reached the wire, so the structural check saw nothing"
    );

    assert_wire_phase(
        &WIRE,
        ProtocolPhase::Online,
        &[ProtocolType::A2B, ProtocolType::A2BGfMul],
    );
    for node in &nodes {
        assert_eq!(node.conv.a2b.store_len().await, 0);
        assert_eq!(node.conv.a2b.open.store_len().await, 0);
        assert_eq!(node.conv.a2b.gf_mul.store_len().await, 0);
    }
}

/// A corrupt party that signs its honest shares with an **honest party's id** is refused, and the
/// conversion still completes correctly for everyone else.
///
/// # Why this test exists
///
/// It is the companion to `an_online_opening_refuses_a_share_relabelled_to_degree_2t`, covering
/// the other half of what `GfShareWire` moved off the wire. That test covers `degree`; this one
/// covers `id`, and `id` is the half with a *correctness* consequence rather than a robustness
/// one.
///
/// Before `GfShareWire`, a direct-opening share carried its own evaluation index and
/// `GfMultiply::process` rejected it unless it equalled the authenticated sender. The index is no
/// longer on the wire: `process` now **derives** it, stamping the `sender` it is handed onto every
/// element of the body. That removes a forgeable field, but it also concentrates the entire
/// index-correctness argument onto one line — `HoneyBadgerMPCNode::process_message`'s
/// `sender_id != mult_msg.sender` check, which is what binds the derived index to the transport.
///
/// [`impersonate_sender`] attacks exactly that binding, and nothing else: honest share values, the
/// current encoding, only the envelope's `sender` rewritten. If the binding were absent, a
/// receiver would interpolate the impersonator's elements at the victim's evaluation point, giving
/// one corrupt party two of the `2t+1` points a degree-`t` opening decodes from — a quorum forgery
/// invisible to every all-honest test in this file, because the shares themselves are honest.
///
/// Three things are asserted, and the last is why this is not merely a parser test:
///
/// * the impersonation **actually reached** a receiver, so the run cannot pass vacuously;
/// * the forged envelopes are **refused**, with `InvalidPartyId` reported by name — not some other
///   error that happens to reject them for an unrelated reason;
/// * every honest party still returns the **right bits**. Refusing the liar silences it, and a
///   silent party still has to fit inside the `t` budget; a refusal that cost liveness would trade
///   a correctness break for a guaranteed-output-delivery break.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_online_opening_refuses_a_share_signed_with_another_partys_id() {
    setup_tracing();
    stats!(STATS);
    faults!(FAULTS);
    wire!(WIRE);
    let (n_parties, t, corrupt, victim) = (4usize, 1usize, 3usize, 0usize);
    let values = [F::from(1u64 << 32), F::from(0u64) - F::from(1u64)];

    let (nodes, results) = run_a2b(
        n_parties,
        t,
        252,
        &values,
        Adversary::impersonating(corrupt, victim, &STATS)
            .with_faults(&FAULTS)
            .with_watch(&WIRE),
        None,
    )
    .await;

    assert!(
        STATS.impersonated() > 0,
        "no direct-opening envelope was actually re-signed; at n = {n_parties} the default \
         OpeningPolicy should route every AND layer through the direct GfMult path, so this \
         means the attack reached nothing"
    );

    // Refused *by name*. `InvalidPartyId` is the dispatcher's sender-authentication error; any
    // other error here would mean the forgery was rejected for an incidental reason (a length
    // check, a session lookup) and that the binding under test is not what stopped it.
    let reported = FAULTS.all();
    assert!(
        reported.iter().any(|e| e.contains("InvalidPartyId")),
        "a GfMult envelope whose `sender` field disagrees with the transport sender must be \
         refused with InvalidPartyId — the derived share index is bound to the transport by \
         nothing else. Errors actually reported: {reported:?}"
    );

    // Silencing the liar must not cost liveness: `corrupt` is one party inside the `t` budget.
    assert_a2b_bits(&results, &values, n_parties, t, Some(corrupt));

    assert_wire_phase(
        &WIRE,
        ProtocolPhase::Online,
        &[ProtocolType::A2B, ProtocolType::A2BGfMul],
    );
    for node in &nodes {
        assert_eq!(node.conv.a2b.store_len().await, 0);
        assert_eq!(node.conv.a2b.open.store_len().await, 0);
        assert_eq!(node.conv.a2b.gf_mul.store_len().await, 0);
    }
}

/// The preprocessing side of the same boundary: a batch that **aborts** must abort *inside* its
/// own phase.
///
/// `a_corrupt_share_in_conversion_preprocessing_is_detected_not_accepted` asserts the abort is
/// detected; `conversion_preprocessing_puts_only_preprocessing_sessions_on_the_wire` asserts the
/// phase of a batch that succeeds. This run is the one neither covers: a batch under attack, on
/// the failure path, where a retry or a fallback would be minted if anything minted one. A
/// degree-`2t` opening that failed to decode is the single most plausible place for a caller to
/// reach for a degree-`t` retry, and a degree-`t` retry of a *preprocessing* opening on an online
/// tag would be invisible to every other test in this file.
///
/// Detection, containment and phase, asserted of one aborting run.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_aborted_preprocessing_batch_stays_inside_the_preprocessing_phase() {
    setup_tracing();
    stats!(STATS);
    faults!(FAULTS);
    wire!(WIRE);
    let (n_parties, t, corrupt) = (4usize, 1usize, 3usize);

    let (nodes, _, outcomes) = run_gf_dn07_mul(
        n_parties,
        t,
        251,
        Adversary::corrupt_openings(corrupt, &STATS)
            .with_faults(&FAULTS)
            .with_watch(&WIRE),
        None,
    )
    .await;

    assert!(
        STATS.tampered() > 0,
        "no opening message was actually rewritten"
    );
    for (party, outcome) in outcomes.iter().enumerate() {
        if party == corrupt {
            continue;
        }
        assert!(
            outcome.is_none(),
            "party {party} accepted products from a corrupted degree-2t opening"
        );
    }
    let reported = FAULTS.all();
    assert!(
        reported.iter().any(|e| e.contains("Decoding")
            || e.contains("Interpolate")
            || e.contains("NotEnoughShares")
            || e.contains("Reconstruct")),
        "the abort must be detected, not merely stalled; reported {reported:?}"
    );

    // The claim this test adds: nothing the aborting batch put on the wire belongs to an online
    // session. A preprocessing failure may cost the batch; it may not spill into the phase that
    // is not allowed to fail.
    assert_wire_phase(&WIRE, ProtocolPhase::Preprocessing, &[ProtocolType::GfDn07]);

    for node in &nodes {
        assert_eq!(
            node.gf_preprocess.gf_dn07.store_len().await,
            0,
            "an aborted DN07 session left a store behind"
        );
    }
}
