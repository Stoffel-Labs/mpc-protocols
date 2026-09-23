//! [`A2BNode`] — the driver for arithmetic-to-binary conversion.
//!
//! The protocol is two phases. First one degree-`t` opening of `[y] = [x] - [r]` per converted
//! value, batched into as few batch-reconstruction sessions as the chunking allows. Then the
//! binary adder and conditional reduction of [`FieldA2BCircuit`], evaluated AND layer by AND layer
//! with **every conversion in the batch sharing each layer's multiplication** — which is why the
//! round count is `2 + layers * rounds_per_wave` — 16 batched, 9 direct on Goldilocks — whatever
//! the batch size. See [`A2BNode::message_rounds`].
//!
//! See the module header of [`super`] for the algebra, the privacy argument and the output
//! convention.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Instant;

use ark_ff::PrimeField;
use stoffelnet::network_utils::{Network, PartyId};
use tokio::sync::{mpsc::Receiver, oneshot, Mutex};
use tokio::time::{timeout, Duration};
use tracing::{info, warn};

use crate::common::session_store::{Admission, SessionStore};
use crate::common::utils::deser_bounded_vec;
use crate::common::ProtocolSessionId;
use crate::{
    common::{
        convert::field_bit_width,
        gf2k::{field::BinaryField, share::GfShare},
    },
    honeybadger::{
        a2b::{A2BError, A2BState, A2BStore},
        batch_recon::batch_recon::{BatchReconNode, MAX_BATCH_RECON_SESSIONS},
        binary_circuits::{BinaryCircuit, FieldA2BCircuit, HasNetlist, WireStore},
        dabit::EdaBit,
        gf_mul::{gf_multiplication::GfMultiply, OpeningPolicy},
        gf_triple_gen::GfBeaverTriple,
        max_mul_pairs_per_session,
        robust_interpolate::robust_interpolate::RobustShare,
        ProtocolType, SessionId,
    },
};

/// Concurrent A2B sessions admitted node-wide.
///
/// A session's own footprint is one result channel plus its child-session list; the batch itself
/// lives on the driving call's stack. The cap therefore exists to bound the *child* sessions those
/// drivers can have in flight, not the store.
pub const MAX_A2B_SESSIONS: usize = 256;

/// Hard ceiling on the number of values one [`A2BNode::init`] call converts.
///
/// Each conversion carries its own netlist (the plan depends on that conversion's opened mask) and
/// its own wire arena — on Goldilocks roughly 180 KiB together — so a batch of 256 is about 45 MiB
/// of resident planner state. Larger batches buy nothing: the round count is already independent
/// of the batch size, and the per-layer multiplication is chunked and depth-capped regardless.
pub const MAX_A2B_CONVERSIONS: usize = 256;

/// Child session ids are `parent_exec * A2B_CHILD_STRIDE + wave`, giving every parent session a
/// disjoint block in each child protocol's own tag space.
///
/// Not `parent_exec + 1 + wave`: parent exec ids come from a counter that increments by one, so an
/// additive scheme aliases the *next* invocation's parent onto this invocation's later waves, and
/// `GfMultiply::init`'s `assert_eq!(sub_id(), 0)` would not catch it.
const A2B_CHILD_STRIDE: u64 = 1 << 20;

/// Batch-reconstruction payloads that arrived for a session nobody is waiting on yet. Bounded
/// because a quorum can complete this node's reconstruction of a session id *before* the local
/// opener registers for it.
const MAX_PARKED_OPEN_PAYLOADS: usize = 64;

/// Message rounds the arithmetic mask opening costs, whatever the AND layers do.
///
/// It is one degree-`t` [`BatchReconNode`] session — evaluations out, reveals back — and
/// [`OpeningPolicy`] governs the multiplier alone, never this. Quoting A2B at `1 + layers` rounds
/// silently drops this second round.
const MASK_OPENING_ROUNDS: usize = 2;

/// Maximum concurrent child batch-reconstruction sessions before a peer's *per-peer* quota in
/// `BatchReconNode::get_or_create_store` (`MAX_BATCH_RECON_SESSIONS / n`) starts rejecting its
/// `Eval` messages — at which point those openings silently never complete.
///
/// Capping depth rather than raising the existing quota also bounds the 200-slot `mpsc` backlog
/// inside `GfMultiply`, whose `send().await` runs inline on the single message-handling path: a
/// full channel stalls the whole node (C11). Identical to
/// [`crate::honeybadger::dabit::conv_pipeline_depth`], and deliberately so — the two
/// drivers compete for the same quota.
pub fn conv_pipeline_depth(n_parties: usize) -> usize {
    (MAX_BATCH_RECON_SESSIONS / n_parties.max(1)).max(1)
}

/// Values opened in one batch-reconstruction session. Same bound as the multiplication track's
/// per-session pair count: both produce one field element per slot in a single eval/reveal message
/// pair, so the same figure keeps both well inside `MAX_MESSAGE_SIZE`.
fn max_values_per_open(threshold: usize) -> usize {
    max_mul_pairs_per_session(threshold)
}

/// Which child protocol a minted session id belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ChildKind {
    Open,
    GfMul,
}

impl ChildKind {
    fn tag(self) -> ProtocolType {
        match self {
            ChildKind::Open => ProtocolType::A2B,
            ChildKind::GfMul => ProtocolType::A2BGfMul,
        }
    }
}

/// Deterministic child-session-id allocator for one batch.
///
/// Every honest party runs the same sequence of waves — the wave counts are functions of the batch
/// size and of the circuit plans, and the plans are functions of robustly-opened masks — so the ids
/// minted here agree across parties with no extra round. Ids are never derived from message data,
/// which is what keeps `GfMultiply::init`'s `assert_eq!` on `sub_id`/`round_id` unreachable from
/// the network (C12).
struct ChildIds {
    base: u64,
    instance_id: u32,
    waves: [u64; 2],
}

impl ChildIds {
    fn new(parent: SessionId) -> Result<Self, A2BError> {
        let base = parent
            .exec_id()
            .checked_mul(A2B_CHILD_STRIDE)
            .ok_or(A2BError::LimitError)?;
        Ok(Self {
            base,
            instance_id: parent.instance_id(),
            waves: [0; 2],
        })
    }

    fn next(&mut self, kind: ChildKind) -> Result<SessionId, A2BError> {
        let slot = kind as usize;
        let wave = self.waves[slot];
        if wave >= A2B_CHILD_STRIDE {
            return Err(A2BError::LimitError);
        }
        self.waves[slot] = wave + 1;
        let exec = self.base.checked_add(wave).ok_or(A2BError::LimitError)?;
        Ok(SessionId::new(
            kind.tag(),
            SessionId::pack_slot(exec, 0, 0),
            self.instance_id,
        ))
    }
}

/// Routes a completed batch-reconstruction payload back to the opener that asked for it.
///
/// Only this node's own openers ever `register`, so the waiter map cannot be grown by a peer. The
/// parked queue exists because a quorum can complete this node's reconstruction *before* the local
/// opener registers, and it is a bounded ring for exactly that reason.
#[derive(Debug, Default)]
struct OpenRegistry {
    waiters: HashMap<SessionId, oneshot::Sender<Vec<u8>>>,
    parked: VecDeque<(SessionId, Vec<u8>)>,
}

impl OpenRegistry {
    fn register(&mut self, session_id: SessionId) -> oneshot::Receiver<Vec<u8>> {
        let (tx, rx) = oneshot::channel();
        if let Some(pos) = self.parked.iter().position(|(id, _)| *id == session_id) {
            if let Some((_, bytes)) = self.parked.remove(pos) {
                let _ = tx.send(bytes);
                return rx;
            }
        }
        self.waiters.insert(session_id, tx);
        rx
    }

    fn deliver(&mut self, session_id: SessionId, bytes: Vec<u8>) {
        if let Some(tx) = self.waiters.remove(&session_id) {
            let _ = tx.send(bytes);
            return;
        }
        if self.parked.len() >= MAX_PARKED_OPEN_PAYLOADS {
            self.parked.pop_front();
        }
        self.parked.push_back((session_id, bytes));
    }

    fn cancel(&mut self, session_id: SessionId) {
        self.waiters.remove(&session_id);
        if let Some(pos) = self.parked.iter().position(|(id, _)| *id == session_id) {
            self.parked.remove(pos);
        }
    }
}

/// Node implementing arithmetic-to-binary conversion.
///
/// # No local-only rounds (C4)
///
/// This node introduces none. Every value it consumes is either a robust reconstruction it
/// performed itself or a product returned by `GfMultiply`, whose share ids and degrees
/// `absorb_layer` re-checks before touching a wire. The `sender == self.id` guard that
/// `GfMultiply` applies to its own batch-reconstruction round is inherited unchanged.
///
/// # One tag per owning instance (C17)
///
/// `GfMultiply::init` mints its batch-reconstruction children with the *parent's* tag, while the
/// node dispatcher demuxes `WrappedMessage::GfBatchRecon` on `calling_protocol()` alone. `open`
/// therefore carries [`ProtocolType::A2B`] and `gf_mul` carries [`ProtocolType::A2BGfMul`]; giving
/// them one tag would make both unroutable.
///
/// # Bound is `PrimeField`, not `FftField`
///
/// The circuit needs `F::MODULUS_BIT_SIZE` and `y.into_bigint()` to turn the opened mask into
/// public bits, neither of which `FftField` provides.
#[derive(Clone, Debug)]
pub struct A2BNode<F: PrimeField, K: BinaryField> {
    pub id: PartyId,
    pub n_parties: usize,
    pub threshold: usize,
    pub store: Arc<Mutex<SessionStore<SessionId, (usize, Instant, Arc<Mutex<A2BStore<F, K>>>)>>>,
    /// Degree-`t` opening of the arithmetic mask `y = x - r`. Tag: [`ProtocolType::A2B`].
    ///
    /// Degree `t`, never `2t`: at degree `2t` this repo's robust reconstruction needs
    /// `degree + t + 1 = n` agreeing evaluations, i.e. it tolerates zero faults.
    pub open: BatchReconNode<F>,
    pub open_output: Arc<Mutex<Receiver<SessionId>>>,
    /// One multiplication session per AND-layer chunk. Tag: [`ProtocolType::A2BGfMul`].
    pub gf_mul: GfMultiply<K>,
    open_registry: Arc<Mutex<OpenRegistry>>,
}

impl<F, K> A2BNode<F, K>
where
    F: PrimeField,
    K: BinaryField,
{
    pub fn new(id: PartyId, n_parties: usize, threshold: usize) -> Result<Self, A2BError> {
        Self::new_with_opening_policy(id, n_parties, threshold, OpeningPolicy::default())
    }

    /// [`A2BNode::new`] with an explicit [`OpeningPolicy`] for the AND layers.
    ///
    /// This is the ONLINE path, so the choice is constrained: both variants open at degree `t`
    /// and both are robust and asynchronous, and what the policy trades is bytes against rounds
    /// per layer. [`OpeningPolicy::Auto`] — the default — evaluates the measured byte model at
    /// each wave's own width; see [`OpeningPolicy`] for the model, its constants and the
    /// bytes-per-round assumption its default rests on.
    ///
    /// **The mask opening is not governed by this policy and is always two rounds.** It is a
    /// single degree-`t` [`BatchReconNode`] session — evaluations out, reveals back — so the
    /// node's total is `2 + 7 * 2 = 16` message rounds where the layers batch and
    /// `2 + 7 * 1 = 9` where they go direct, **not 8**. The plan's Point C quotes 8 because it
    /// also routes the mask opening directly; this node does not, so one round of that saving is
    /// unclaimed. `b2a`'s module docs make the same distinction ("one opening is not one round")
    /// and it is the same arithmetic here.
    ///
    /// A **public deployment parameter**: every party must pass the same value, exactly as with
    /// the prefix-adder topology. A split choice stalls rather than corrupts.
    pub fn new_with_opening_policy(
        id: PartyId,
        n_parties: usize,
        threshold: usize,
        policy: OpeningPolicy,
    ) -> Result<Self, A2BError> {
        if id >= n_parties {
            return Err(A2BError::InvalidPartyId);
        }
        // C5: the binary domain has only `K::MAX_DOMAIN_SIZE` distinct evaluation points, so a
        // party count above it cannot be shared in `K` at all. `Opts::new` already rejects
        // `n_parties > 255`, which coincides with `Gf256::MAX_DOMAIN_SIZE`; this makes the
        // coupling explicit rather than accidental.
        if n_parties > K::MAX_DOMAIN_SIZE {
            return Err(A2BError::InvalidPartyId);
        }

        let (open_sender, open_receiver) = tokio::sync::mpsc::channel(200);
        let open = BatchReconNode::<F>::new(id, n_parties, threshold, threshold, open_sender)?;

        Ok(Self {
            id,
            n_parties,
            threshold,
            store: Arc::new(Mutex::new(SessionStore::with_default_cap())),
            open,
            open_output: Arc::new(Mutex::new(open_receiver)),
            gf_mul: GfMultiply::<K>::new_with_policy(id, n_parties, threshold, policy)?,
            open_registry: Arc::new(Mutex::new(OpenRegistry::default())),
        })
    }

    /// The [`OpeningPolicy`] this node's AND layers run under.
    pub fn opening_policy(&self) -> OpeningPolicy {
        self.gf_mul.opening_policy()
    }

    /// Bits per converted value: `ceil(log2 p)`, 64 on Goldilocks. Also the width every edaBit
    /// handed to [`Self::init`] must have.
    pub fn bit_width() -> usize {
        field_bit_width::<F>()
    }

    /// `GF(2^k)` Beaver triples to reserve **per converted value**.
    ///
    /// This is the worst case over every admissible mask, because the exact gate count depends on
    /// the mask — a cleared bit of the public operand makes a whole sub-tree of the carry prefix
    /// statically zero, and the planner folds it away. **695 on Goldilocks**; a uniform mask
    /// averages about 642, and the surplus is simply not consumed.
    ///
    /// The blueprint quoted 626 here, for the *serial* `ADD64 -> ADD64 -> MUX` chain this node no
    /// longer runs. The parallel offset adder applies the mod-`p` offset to the public operand,
    /// so the two additions are independent: +11% on the sizing bound (626 -> 695) and +7% on the
    /// average (600 -> 642), for 6 fewer AND layers.
    ///
    /// Deviates from the blueprint's `-> usize` only in being fallible: building the worst-case
    /// plan can fail for a degenerate field width, and this crate does not panic on that.
    pub fn gf_triples_per_conversion() -> Result<usize, A2BError> {
        Ok(FieldA2BCircuit::<F>::max_and_count()?)
    }

    /// Upper bound on the AND layers, i.e. on the online multiplication *waves*. **7** on
    /// Goldilocks, down from the blueprint's 13.
    ///
    /// Message rounds are `2 + layers * (rounds per wave)`: the degree-`t` mask opening is a
    /// two-round [`BatchReconNode`] session, then one wave per layer. A batched wave is two
    /// rounds, giving **16**; a direct wave is one, giving **9** — not 8, because the policy
    /// governs the AND layers alone. [`A2BNode::message_rounds`] computes it; see also
    /// [`A2BNode::new_with_opening_policy`].
    ///
    /// Exposed as a function rather than the blueprint's `A2B_AND_LAYERS` constant because 7 is a
    /// property of Goldilocks, not of the protocol, and this node is generic over `F`.
    pub fn max_and_layers() -> Result<usize, A2BError> {
        Ok(FieldA2BCircuit::<F>::max_layers()?)
    }

    /// Message rounds one [`Self::init`] call costs, independent of how many values it converts.
    ///
    /// `MASK_OPENING_ROUNDS + layers * rounds_per_wave`: the two-round mask opening, then one
    /// multiplication wave per AND layer. A wave is two rounds when any part of it is opened
    /// through batch reconstruction and one when the whole wave goes direct, and which of those
    /// applies is a property of this node's [`OpeningPolicy`], its party count and the wave's
    /// **width** — so **16** on Goldilocks wherever the policy batches and **9** where it does
    /// not, never 8.
    ///
    /// An **upper bound** rather than an exact count, and the width is why. [`Self::mul_k`] cuts
    /// each AND layer into waves of at most `max_mul_pairs_per_session(t) = 128 * (t+1)`
    /// multiplications, so the widest wave this node can ever issue is that; this maximises the
    /// per-wave round count over every width up to it. A narrower wave can be cheaper —
    /// [`OpeningPolicy::Auto`] opens one directly, in one round, whenever the byte model says so
    /// — so a conversion that keeps its layers under the crossover finishes in fewer rounds than
    /// this returns. It never finishes in more.
    ///
    /// Measured, a real 64-bit conversion is **9 rounds at every `n`** — its layers are 89-118
    /// wide, far below the crossover, so every wave goes direct — while this returns 9 at
    /// `n = 4` and 16 at `n >= 7`, where the 512- and 640-wide waves the cap permits would batch.
    /// `conv_cost_measurement::measured_rounds_a2b_n*` reads 9.01 at all four party counts.
    pub fn message_rounds(&self) -> Result<usize, A2BError> {
        let rounds_per_wave = self.opening_policy().max_rounds_per_wave(
            self.n_parties,
            self.threshold,
            max_mul_pairs_per_session(self.threshold),
        );
        Ok(MASK_OPENING_ROUNDS + Self::max_and_layers()? * rounds_per_wave)
    }

    pub async fn store_len(&self) -> usize {
        self.store.lock().await.len()
    }

    async fn get_or_create_store(
        &self,
        session_id: SessionId,
        initiator_id: usize,
    ) -> Admission<Arc<Mutex<A2BStore<F, K>>>> {
        self.store.lock().await.get_or_admit(
            session_id,
            initiator_id,
            MAX_A2B_SESSIONS,
            // `.max(1)`: with `n > MAX_A2B_SESSIONS` the integer quotient is zero, which would
            // reject every session including this node's own.
            (MAX_A2B_SESSIONS / self.n_parties.max(1)).max(1),
            || Arc::new(Mutex::new(A2BStore::empty())),
        )
    }

    /// Retires the **exact** child session ids this batch recorded, on each child node, then the
    /// parent entry itself. Never re-derives ids: a re-derivation drifts the moment a chunk count
    /// changes, leaving orphaned child sessions squatting on their own caps (C7).
    pub async fn clear_store(&self, session_id: SessionId) -> bool {
        let children = {
            let store = self.store.lock().await;
            match store.get(&session_id) {
                Some((_, _, arc)) => arc.lock().await.child_sessions.clone(),
                None => Vec::new(),
            }
        };

        for child in children {
            match child.calling_protocol() {
                Some(ProtocolType::A2B) => {
                    self.open.clear_store(child).await;
                    self.open_registry.lock().await.cancel(child);
                }
                Some(ProtocolType::A2BGfMul) => {
                    self.gf_mul.clear_store(child).await;
                }
                _ => {}
            }
        }

        let mut store = self.store.lock().await;
        store.retire(session_id)
    }

    /// Collects the result of one A2B session: `[conversion][bit]`, LSB first, `bit_width()` long,
    /// degree `t`, indexed by this party.
    ///
    /// The bits are those of the **canonical representative in `[0, p)`**, not two's complement —
    /// see the module header.
    pub async fn wait_for_result(
        &self,
        session_id: SessionId,
        duration: Duration,
    ) -> Result<Vec<Vec<GfShare<K>>>, A2BError> {
        let output_receiver = {
            let storage = self.store.lock().await;
            let storage_bind = match storage.get(&session_id) {
                Some((_, _, arc)) => arc,
                None => return Err(A2BError::NoSuchSessionId(session_id)),
            };
            let mut storage = storage_bind.lock().await;
            storage
                .output_receiver
                .take()
                .ok_or(A2BError::ResultAlreadyReceived(session_id))?
        };

        match timeout(duration, output_receiver).await {
            Err(_) => Err(A2BError::Timeout(session_id)),
            Ok(Err(_)) => Err(A2BError::ReceiveError(session_id)),
            Ok(Ok(bits)) => Ok(bits),
        }
    }

    /// Routes completed mask openings back to the opener waiting on them.
    ///
    /// Call this immediately after every `self.open.process(..)` in the node dispatcher (C10).
    pub async fn drain_open_output(&mut self) -> Result<(), A2BError> {
        loop {
            let id = {
                let mut rx = self.open_output.lock().await;
                match rx.try_recv() {
                    Ok(id) => id,
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        return Err(A2BError::Abort);
                    }
                }
            };
            match self.open.get_store(id).await {
                Ok(bytes) => self.open_registry.lock().await.deliver(id, bytes),
                Err(e) => {
                    warn!(?id, ?e, "ignoring stale A2B mask-opening output");
                }
            }
        }
        Ok(())
    }

    /// Pumps the multiplication node's own batch-reconstruction outputs.
    ///
    /// Call this immediately after every `self.gf_mul.batch_recon.process(..)` in the node
    /// dispatcher (C10).
    pub async fn drain_gf_mul_output(&mut self) -> Result<(), A2BError> {
        Ok(self.gf_mul.drain_batch_recon_output().await?)
    }
}

// ---------------------------------------------------------------------------------------------
// Child-protocol drivers: chunked, depth-capped, and cleared on every exit path
// ---------------------------------------------------------------------------------------------

impl<F, K> A2BNode<F, K>
where
    F: PrimeField,
    K: BinaryField,
{
    async fn record_child(store: &Arc<Mutex<A2BStore<F, K>>>, session_id: SessionId) {
        store.lock().await.child_sessions.push(session_id);
    }

    /// Opens `values` at degree `t` and returns the opened scalars in input order.
    ///
    /// Chunked against [`max_values_per_open`] and pipelined at [`conv_pipeline_depth`], with each
    /// wave awaited and cleared before the next is issued — the two bounds that keep a wave from
    /// exhausting a peer's per-peer batch-reconstruction quota or filling the 200-slot channel
    /// inside the reconstruction path (C11).
    async fn open_f<N: Network + Send + Sync + 'static>(
        &mut self,
        values: &[RobustShare<F>],
        ids: &mut ChildIds,
        store: &Arc<Mutex<A2BStore<F, K>>>,
        duration: Duration,
        network: &Arc<N>,
    ) -> Result<Vec<F>, A2BError> {
        if values.is_empty() {
            return Ok(Vec::new());
        }
        let width = self.threshold + 1;
        let chunks: Vec<&[RobustShare<F>]> =
            values.chunks(max_values_per_open(self.threshold)).collect();
        let mut opened = Vec::with_capacity(values.len());

        for group in chunks.chunks(conv_pipeline_depth(self.n_parties)) {
            let mut first_err: Option<A2BError> = None;
            let mut issued = Vec::with_capacity(group.len());

            for chunk in group {
                let session_id = ids.next(ChildKind::Open)?;
                Self::record_child(store, session_id).await;
                // `init_batch_reconstruct_many` requires a non-empty multiple of `degree + 1`;
                // pad the tail exactly as `mul_pub` does.
                let mut padded = chunk.to_vec();
                while padded.len() % width != 0 {
                    padded.push(RobustShare::new(F::one(), self.id, self.threshold));
                }
                let rx = self.open_registry.lock().await.register(session_id);
                match self
                    .open
                    .init_batch_reconstruct_many(&padded, session_id, Arc::clone(network))
                    .await
                {
                    Ok(()) => issued.push((session_id, rx, chunk.len(), padded.len())),
                    Err(e) => {
                        self.open_registry.lock().await.cancel(session_id);
                        if first_err.is_none() {
                            first_err = Some(e.into());
                        }
                    }
                }
            }

            // Every issued session is cleared regardless of outcome: a timed-out session must not
            // be left dangling just because an earlier `?` would have skipped past it.
            for (session_id, rx, real_len, padded_len) in issued {
                let result = match timeout(duration, rx).await {
                    Ok(Ok(bytes)) => deser_bounded_vec::<F>(&mut bytes.as_slice(), padded_len)
                        .map_err(A2BError::ArkSerialization),
                    Ok(Err(_)) => Err(A2BError::ReceiveError(session_id)),
                    Err(_) => Err(A2BError::Timeout(session_id)),
                };
                self.open.clear_store(session_id).await;
                self.open_registry.lock().await.cancel(session_id);
                match result {
                    Ok(mut decoded) => {
                        if decoded.len() < real_len {
                            if first_err.is_none() {
                                first_err = Some(A2BError::MaterialLengthMismatch {
                                    what: "opened masks",
                                    expected: real_len,
                                    got: decoded.len(),
                                });
                            }
                        } else {
                            decoded.truncate(real_len);
                            opened.append(&mut decoded);
                        }
                    }
                    Err(e) if first_err.is_none() => first_err = Some(e),
                    Err(_) => {}
                }
            }

            if let Some(e) = first_err {
                return Err(e);
            }
        }
        Ok(opened)
    }

    /// Degree-`t` Beaver multiplication of `x[i] * y[i]` in `GF(2^k)`, chunked and depth-capped
    /// like the opener. The result is degree `t`, which is why no degree-`2t` primitive appears
    /// anywhere on this path.
    async fn mul_k<N: Network + Send + Sync + 'static>(
        &mut self,
        x: &[GfShare<K>],
        y: &[GfShare<K>],
        triples: &[GfBeaverTriple<K>],
        ids: &mut ChildIds,
        store: &Arc<Mutex<A2BStore<F, K>>>,
        duration: Duration,
        network: &Arc<N>,
    ) -> Result<Vec<GfShare<K>>, A2BError> {
        if x.len() != y.len() || x.len() != triples.len() {
            return Err(A2BError::MaterialLengthMismatch {
                what: "GF(2^k) multiplication operands",
                expected: x.len(),
                got: y.len().min(triples.len()),
            });
        }
        if x.is_empty() {
            return Ok(Vec::new());
        }

        let per_session = max_mul_pairs_per_session(self.threshold);
        let mut result = Vec::with_capacity(x.len());
        let mut offset = 0usize;

        while offset < x.len() {
            let wave_end =
                (offset + per_session * conv_pipeline_depth(self.n_parties)).min(x.len());
            let mut first_err: Option<A2BError> = None;
            let mut issued = Vec::new();

            let mut cursor = offset;
            while cursor < wave_end {
                let end = (cursor + per_session).min(wave_end);
                let session_id = ids.next(ChildKind::GfMul)?;
                Self::record_child(store, session_id).await;
                match self
                    .gf_mul
                    .init(
                        session_id,
                        x[cursor..end].to_vec(),
                        y[cursor..end].to_vec(),
                        triples[cursor..end].to_vec(),
                        Arc::clone(network),
                    )
                    .await
                {
                    Ok(()) => issued.push(session_id),
                    Err(e) if first_err.is_none() => first_err = Some(e.into()),
                    Err(_) => {}
                }
                cursor = end;
            }

            for session_id in issued {
                match self.gf_mul.wait_for_result(session_id, duration).await {
                    Ok(mut chunk) => result.append(&mut chunk),
                    Err(e) if first_err.is_none() => first_err = Some(e.into()),
                    Err(_) => {}
                }
                if !self.gf_mul.clear_store(session_id).await {
                    warn!(?session_id, "failed to clear A2B multiplication state");
                }
            }

            if let Some(e) = first_err {
                return Err(e);
            }
            offset = wave_end;
        }
        Ok(result)
    }
}

// ---------------------------------------------------------------------------------------------
// The protocol itself
// ---------------------------------------------------------------------------------------------

impl<F, K> A2BNode<F, K>
where
    F: PrimeField,
    K: BinaryField,
{
    /// Converts every `x[v]` to binary bit shares, consuming one full-range edaBit per value.
    ///
    /// This is a **long-running driver**: it awaits its own child sessions, so it must not be
    /// polled on the task that pumps the network — spawn it, exactly as `RandBit::init` and
    /// `PrssDaBitNode::generate` are spawned. The result is delivered through
    /// [`Self::wait_for_result`]; `init` itself returns once the batch is complete or has failed.
    ///
    /// # Preconditions, all checked
    ///
    /// * `x`, `edabits` the same non-empty length, at most [`MAX_A2B_CONVERSIONS`].
    /// * every edaBit full width and `r < p` (the caller gets the latter by construction: a
    ///   full-width edaBit can only be built through `EdaBit::compose_full_width`, which refuses
    ///   without the opened overflow bit).
    /// * `gf_triples.len() == gf_triples_per_conversion() * x.len()`. That budget is the worst
    ///   case over every mask; the surplus a given batch does not consume is discarded with the
    ///   session rather than returned to the pool, which costs about 4% of the triples and keeps
    ///   the pool strictly drain-only (C15).
    /// * every share — inputs, edaBit halves, triple components — carries this party's index and
    ///   degree `t` (C5).
    pub async fn init<N>(
        &mut self,
        session_id: SessionId,
        x: Vec<RobustShare<F>>,
        edabits: Vec<EdaBit<F, K>>,
        gf_triples: Vec<GfBeaverTriple<K>>,
        duration: Duration,
        network: Arc<N>,
    ) -> Result<(), A2BError>
    where
        N: Network + Send + Sync + 'static,
    {
        // ---- 0. Parameters -------------------------------------------------------------------
        if session_id.calling_protocol() != Some(ProtocolType::A2B)
            || session_id.sub_id() != 0
            || session_id.round_id() != 0
        {
            return Err(A2BError::SessionIdError(session_id));
        }

        // C13: an empty batch makes every length check below pass vacuously.
        if x.is_empty() {
            return Err(A2BError::EmptyBatch);
        }
        if x.len() > MAX_A2B_CONVERSIONS {
            return Err(A2BError::BatchTooLarge {
                requested: x.len(),
                max: MAX_A2B_CONVERSIONS,
            });
        }
        let conversions = x.len();
        let width = Self::bit_width();
        let budget = Self::gf_triples_per_conversion()?;

        // C13: exact lengths, never `>=`. A surplus edaBit silently dropped here is an edaBit the
        // caller hands to the next batch as well, i.e. one-time-pad reuse.
        if edabits.len() != conversions {
            return Err(A2BError::MaterialLengthMismatch {
                what: "edabits",
                expected: conversions,
                got: edabits.len(),
            });
        }
        let expected_triples = budget
            .checked_mul(conversions)
            .ok_or(A2BError::LimitError)?;
        if gf_triples.len() != expected_triples {
            return Err(A2BError::MaterialLengthMismatch {
                what: "GF(2^k) triples",
                expected: expected_triples,
                got: gf_triples.len(),
            });
        }

        for share in &x {
            self.check_arith_share(share)?;
        }
        for (index, edabit) in edabits.iter().enumerate() {
            // A2B masks the whole canonical range, so a short edaBit cannot mask it — and a short
            // one also means the `r < p` filter was never applied to it.
            if edabit.width != width || edabit.bits.len() != width {
                return Err(A2BError::EdaBitWidthMismatch {
                    index,
                    expected: width,
                    got: edabit.width.min(edabit.bits.len()),
                });
            }
            self.check_arith_share(&edabit.value)?;
            for bit in &edabit.bits {
                self.check_bin_share(bit)?;
            }
        }
        for triple in &gf_triples {
            self.check_bin_share(&triple.a)?;
            self.check_bin_share(&triple.b)?;
            self.check_bin_share(&triple.mult)?;
        }

        // ---- 1. Local state ------------------------------------------------------------------
        let store = match self.get_or_create_store(session_id, self.id).await {
            Admission::Got(arc) => arc,
            // Our own batch: a silent `Ok(())` would leave the caller waiting forever.
            Admission::Retired | Admission::Rejected => return Err(A2BError::LimitError),
        };
        {
            let mut guard = store.lock().await;
            if guard.state != A2BState::NotInitialized {
                return Err(A2BError::SessionIdError(session_id));
            }
            guard.state = A2BState::Masking;
            guard.conversions = conversions;
            guard.width = width;
        }

        let mut ids = ChildIds::new(session_id)?;
        let result = self
            .run(
                session_id, &store, &mut ids, x, edabits, gf_triples, budget, duration, &network,
            )
            .await;

        match result {
            Ok(bits) => {
                let mut guard = store.lock().await;
                guard.state = A2BState::Finished;
                // C18: taking the sender out makes finalisation idempotent by construction.
                if let Some(tx) = guard.output_sender.take() {
                    tx.send(bits).map_err(|_| A2BError::SendError(session_id))?;
                }
                info!(
                    party = self.id,
                    session_id = session_id.as_u128(),
                    conversions,
                    "A2B batch completed"
                );
                Ok(())
            }
            Err(e) => {
                // Drop the result channel so that a waiter on another task fails fast with
                // `ReceiveError` instead of blocking until its own timeout. The state is left
                // where it failed — there is no `Failed` phase, and inventing one would say
                // nothing `clear_store` does not already handle: it retires every recorded child
                // session on both child nodes regardless of how the batch ended (C7).
                let mut guard = store.lock().await;
                guard.output_sender.take();
                Err(e)
            }
        }
    }

    /// The batch itself, factored out so [`Self::init`] owns the state transitions and this owns
    /// nothing but the algebra.
    async fn run<N>(
        &mut self,
        session_id: SessionId,
        store: &Arc<Mutex<A2BStore<F, K>>>,
        ids: &mut ChildIds,
        x: Vec<RobustShare<F>>,
        edabits: Vec<EdaBit<F, K>>,
        gf_triples: Vec<GfBeaverTriple<K>>,
        budget: usize,
        duration: Duration,
        network: &Arc<N>,
    ) -> Result<Vec<Vec<GfShare<K>>>, A2BError>
    where
        N: Network + Send + Sync + 'static,
    {
        let conversions = x.len();

        // ---- 2. Mask and open ----------------------------------------------------------------
        // `[y] = [x] - [r]`, local. `r` is uniform on `[0, p)` and independent of `x`, so the
        // opened `y` is *exactly* uniform on `Z_p` — this is the whole privacy argument, and it
        // has no statistical parameter (C14). The subtraction is over `F`, so it wraps mod `p`;
        // the circuit's conditional reduction is what undoes that wrap over the integers.
        let mut masked = Vec::with_capacity(conversions);
        for (value, edabit) in x.iter().zip(edabits.iter()) {
            masked.push((value.clone() - edabit.value.clone())?);
        }
        let opened = self.open_f(&masked, ids, store, duration, network).await?;
        if opened.len() != conversions {
            return Err(A2BError::MaterialLengthMismatch {
                what: "opened masks",
                expected: conversions,
                got: opened.len(),
            });
        }

        // ---- 3. Plan the circuits ------------------------------------------------------------
        // The plan is a function of the opened mask alone, and the mask was *robustly* opened, so
        // every honest party builds the same plan, spends the same triples in the same order and
        // runs the same number of layers. No agreement sub-protocol is needed or used — the same
        // justification `truncpr`/`rand_bit` already rely on for their opened-value branches.
        let mut circuits = Vec::with_capacity(conversions);
        let mut wires: Vec<WireStore<K>> = Vec::with_capacity(conversions);
        let mut triple_base = Vec::with_capacity(conversions);
        let mut consumed = vec![0usize; conversions];

        for (index, (mask, edabit)) in opened.iter().zip(edabits.iter()).enumerate() {
            let circuit = FieldA2BCircuit::<F>::new(*mask)?;
            // Defensive, not decorative: the budget is an upper bound over every admissible mask,
            // so exceeding it is unreachable — but an unreachable overrun must be an error, never
            // an out-of-bounds slice (C12).
            let needed = circuit.and_count();
            if needed > budget {
                return Err(A2BError::TripleBudgetExceeded {
                    index,
                    needed,
                    budget,
                });
            }
            wires.push(circuit.init(&edabit.bits)?);
            circuits.push(circuit);
            triple_base.push(index * budget);
        }
        {
            let mut guard = store.lock().await;
            guard.state = A2BState::Circuit;
        }

        // ---- 4. Evaluate the AND layers ------------------------------------------------------
        // One multiplication wave per layer, shared by *every* conversion in the batch: that is
        // what keeps the round count at one wave per layer — `2 + layers * rounds_per_wave` in
        // all, the leading 2 being the mask opening — regardless of batch size. A conversion whose
        // plan is shorter (a sparse mask folds whole sub-trees away) simply contributes nothing to
        // the later layers.
        let layers = circuits.iter().map(|c| c.layers()).max().unwrap_or(0);
        for layer in 0..layers {
            let mut lhs: Vec<GfShare<K>> = Vec::new();
            let mut rhs: Vec<GfShare<K>> = Vec::new();
            let mut wave_triples: Vec<GfBeaverTriple<K>> = Vec::new();
            let mut spans: Vec<(usize, usize)> = Vec::new();

            for index in 0..conversions {
                if layer >= circuits[index].layers() {
                    continue;
                }
                let and_layer = circuits[index].build_layer(layer, &mut wires[index])?;
                let len = and_layer.len();
                let start = triple_base[index] + consumed[index];
                let end = start + len;
                // Same defensive reasoning as the budget check above.
                let slice = gf_triples
                    .get(start..end)
                    .ok_or(A2BError::TripleBudgetExceeded {
                        index,
                        needed: consumed[index] + len,
                        budget,
                    })?;
                wave_triples.extend_from_slice(slice);
                consumed[index] += len;
                spans.push((index, len));
                lhs.extend(and_layer.lhs);
                rhs.extend(and_layer.rhs);
            }

            let products = self
                .mul_k(&lhs, &rhs, &wave_triples, ids, store, duration, network)
                .await?;
            if products.len() != lhs.len() {
                return Err(A2BError::MaterialLengthMismatch {
                    what: "AND layer products",
                    expected: lhs.len(),
                    got: products.len(),
                });
            }

            // Split the wave back into per-conversion runs, in the same order they were gathered.
            let mut cursor = 0usize;
            for (index, len) in spans {
                let slice =
                    products
                        .get(cursor..cursor + len)
                        .ok_or(A2BError::MaterialLengthMismatch {
                            what: "AND layer products",
                            expected: cursor + len,
                            got: products.len(),
                        })?;
                circuits[index].absorb_layer(layer, slice.to_vec(), &mut wires[index])?;
                cursor += len;
            }
        }

        // ---- 5. Read off the bits ------------------------------------------------------------
        let mut out = Vec::with_capacity(conversions);
        for index in 0..conversions {
            let bits = circuits[index].outputs(&wires[index])?;
            if bits.len() != Self::bit_width() {
                return Err(A2BError::MaterialLengthMismatch {
                    what: "conversion outputs",
                    expected: Self::bit_width(),
                    got: bits.len(),
                });
            }
            out.push(bits);
        }
        info!(
            party = self.id,
            session_id = session_id.as_u128(),
            layers,
            "A2B circuits evaluated"
        );
        Ok(out)
    }

    /// C5: an arithmetic share must be this party's own, at the degree every consumer opens at.
    /// `RobustShare::id` indexes the FFT evaluation domain while `GfShare::id` indexes the powers
    /// of the `GF(2^k)` generator; only the *party index* crosses between the domains, never an
    /// x-coordinate, which is why the two checks are independent rather than shared.
    fn check_arith_share(&self, share: &RobustShare<F>) -> Result<(), A2BError> {
        if share.id != self.id {
            return Err(A2BError::IdMismatch {
                expected: self.id,
                got: share.id,
            });
        }
        if share.degree != self.threshold {
            return Err(A2BError::DegreeMismatch {
                expected: self.threshold,
                got: share.degree,
            });
        }
        Ok(())
    }

    /// C5: the binary-domain counterpart of [`Self::check_arith_share`].
    fn check_bin_share(&self, share: &GfShare<K>) -> Result<(), A2BError> {
        if share.id != self.id {
            return Err(A2BError::IdMismatch {
                expected: self.id,
                got: share.id,
            });
        }
        if share.degree != self.threshold {
            return Err(A2BError::DegreeMismatch {
                expected: self.threshold,
                got: share.degree,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::convert::{binary_to_bit, bit_to_binary, canonical_bits};
    use crate::common::gf2k::field::Gf256;
    use crate::common::math::goldilocks::GoldilocksField;
    use crate::common::SecretSharingScheme;
    use crate::honeybadger::dabit::DaBit;
    use crate::honeybadger::WrappedMessage;
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::{Rng, SeedableRng};
    use stoffelmpc_network::fake_network::{FakeInnerNetwork, FakeNetwork, FakeNetworkConfig};

    type F = GoldilocksField;
    type K = Gf256;
    type Node = A2BNode<F, K>;

    /// `p = 2^64 - 2^32 + 1`.
    const P: u64 = 0xFFFF_FFFF_0000_0001;

    fn parent(exec: u64) -> SessionId {
        SessionId::new(ProtocolType::A2B, SessionId::pack_slot(exec, 0, 0), 0)
    }

    fn net(n: usize) -> Arc<FakeNetwork> {
        let inner = FakeInnerNetwork::new(n, None, FakeNetworkConfig::new(10)).0;
        Arc::new(FakeNetwork::new(0, inner))
    }

    /// A full-width edaBit whose every share is the clear value itself, for the input-validation
    /// tests. It is never opened, so its degenerate sharing is irrelevant to what they check.
    fn dummy_edabit(id: usize, degree: usize) -> EdaBit<F, K> {
        let dabits: Vec<DaBit<F, K>> = (0..Node::bit_width())
            .map(|_| {
                DaBit::new(
                    RobustShare::new(F::from(0u64), id, degree),
                    GfShare::new(Gf256(0), id, degree),
                    degree,
                )
                .unwrap()
            })
            .collect();
        EdaBit::compose_full_width(&dabits, false).unwrap()
    }

    fn dummy_triples(count: usize, id: usize, degree: usize) -> Vec<GfBeaverTriple<K>> {
        (0..count)
            .map(|_| {
                GfBeaverTriple::new(
                    GfShare::new(Gf256(0), id, degree),
                    GfShare::new(Gf256(0), id, degree),
                    GfShare::new(Gf256(0), id, degree),
                )
            })
            .collect()
    }

    #[test]
    fn the_default_opening_policy_trades_bytes_for_rounds_only_where_the_model_says_to() {
        // ONLINE path. Every policy here opens at degree `t` and every one is robust and
        // asynchronous; what changes is rounds per AND layer against bytes on the wire. A
        // regression either way is invisible to every functional test in this crate — the
        // conversion still returns the right bits — so it is pinned here rather than left to the
        // e2e cases.
        //
        // What `Auto` decides is a function of the wave's **width**, not of `n` and not of `t`
        // alone. `message_rounds` is therefore an upper bound taken at the widest wave `mul_k`
        // can issue, `max_mul_pairs_per_session(t) = 128 * (t+1)`.
        let layers = Node::max_and_layers().unwrap();

        let small = Node::new(0, 4, 1).unwrap();
        assert_eq!(small.opening_policy(), OpeningPolicy::Auto);
        // At `t = 1` the two paths carry the same payload per multiplication — `2w` against
        // `4 * ceil(w/2)` — so the direct path wins on framing alone at every width, including
        // the widest wave this node can issue. The rule this replaced reached the same answer
        // here, from an unmeasured claim; this one reaches it from the byte model.
        assert_eq!(
            OpeningPolicy::Auto
                .plan(4, 1, max_mul_pairs_per_session(1))
                .direct,
            max_mul_pairs_per_session(1),
            "n=4 opens even its widest wave directly"
        );
        // The two-round mask opening + one single-round wave per layer. Reading it off the node
        // rather than off `layers` is what makes this an assertion about the policy: force
        // `Auto` to batch at `n = 4` and the left-hand side becomes 16.
        assert_eq!(
            small.message_rounds().unwrap(),
            MASK_OPENING_ROUNDS + layers
        );
        assert_eq!(small.message_rounds().unwrap(), 9);

        for (n, t) in [(7usize, 2usize), (10, 3), (13, 4)] {
            let node = Node::new(0, n, t).unwrap();
            assert_eq!(node.opening_policy(), OpeningPolicy::Auto);
            // A full-width wave is past the crossover at every `t >= 2`, so the bound stays 16 —
            // but by a different route than before: `Auto` batches it and pads the last group
            // instead of sending a sub-`t+1` remainder directly, which is where the 31% of
            // online bytes that used to go on 0.8% of the multiplications went. (That 31% was
            // measured when a direct share cost 17 bytes; with `GfShareWire` the same remainder
            // is ~8%, nearly all of it the 52-byte frame. The mechanism is unchanged.)
            //
            // 16 is a bound on the widest wave and NOT what a conversion costs: a real 64-bit
            // A2B issues 89-118-wide waves, every one of which goes direct, and measures
            // 9 rounds at every `n` (`conv_cost_measurement::measured_rounds_a2b_n*`).
            let widest = OpeningPolicy::Auto.plan(n, t, max_mul_pairs_per_session(t));
            assert_eq!(widest.direct, 0, "n={n} batches its widest wave");
            assert_eq!(widest.padded % (t + 1), 0, "n={n} pads to whole groups");
            assert_eq!(
                node.message_rounds().unwrap(),
                MASK_OPENING_ROUNDS + 2 * layers,
                "n={n} must stay at the batched round count"
            );
            assert_eq!(node.message_rounds().unwrap(), 16);

            // And the half of the new rule the old one could not express: a *narrow* layer at the
            // same `n` goes direct, for one round and fewer bytes. The old rule keyed on `t`
            // alone and batched this.
            assert_eq!(
                OpeningPolicy::Auto.plan(n, t, 64).direct,
                64,
                "n={n}: a 64-wide layer is below the crossover and opens directly"
            );
        }

        // An explicit choice overrides the default in both directions, and carries the round
        // count with it: the policy is what the round count is a function of, not `n`.
        let forced_direct = Node::new_with_opening_policy(0, 10, 3, OpeningPolicy::Direct).unwrap();
        assert_eq!(forced_direct.opening_policy(), OpeningPolicy::Direct);
        assert_eq!(forced_direct.message_rounds().unwrap(), 9);
        let forced_batched =
            Node::new_with_opening_policy(0, 4, 1, OpeningPolicy::Batched).unwrap();
        assert_eq!(forced_batched.opening_policy(), OpeningPolicy::Batched);
        assert_eq!(forced_batched.message_rounds().unwrap(), 16);

        // The deployment knob, at both ends. A budget of zero refuses to spend a byte for a
        // round, which moves the crossover down — at `n = 7` a 250-wide layer batches under it
        // and goes direct under the default — while an unbounded one minimises rounds
        // everywhere, including a wave `Auto` would have batched.
        //
        // Note what a zero budget does *not* change: `n = 4`. There the direct path is cheaper in
        // bytes at every width, so no exchange rate can make batching the better plan. That is
        // the difference between this rule and the one it replaced — the old rule's `t <= 1`
        // answer was right at `n = 4` by luck, and this one is right there for a reason that also
        // gets `n >= 7` right.
        let thrifty =
            Node::new_with_opening_policy(0, 7, 2, OpeningPolicy::Tuned { bytes_per_round: 0 })
                .unwrap();
        assert_eq!(thrifty.message_rounds().unwrap(), 16);
        assert_eq!(thrifty.opening_policy().plan(7, 2, 250).direct, 0);
        assert_eq!(OpeningPolicy::Auto.plan(7, 2, 250).direct, 250);
        assert_eq!(
            OpeningPolicy::Tuned { bytes_per_round: 0 }
                .plan(4, 1, max_mul_pairs_per_session(1))
                .direct,
            max_mul_pairs_per_session(1),
            "no budget makes batching cheaper at t = 1"
        );
        let hasty = Node::new_with_opening_policy(
            0,
            13,
            4,
            OpeningPolicy::Tuned {
                bytes_per_round: u32::MAX,
            },
        )
        .unwrap();
        assert_eq!(hasty.message_rounds().unwrap(), 9);
        assert_eq!(
            hasty
                .opening_policy()
                .plan(13, 4, max_mul_pairs_per_session(4))
                .direct,
            max_mul_pairs_per_session(4)
        );

        // And the mask opening is in every one of those figures: no policy can talk the total
        // down to `layers` alone, which is the error the module's own docs used to make.
        for node in [&small, &forced_direct, &forced_batched, &thrifty, &hasty] {
            assert!(node.message_rounds().unwrap() >= MASK_OPENING_ROUNDS + layers);
            assert_ne!(node.message_rounds().unwrap(), 1 + layers);
            assert_ne!(node.message_rounds().unwrap(), 1 + 2 * layers);
        }
    }

    #[test]
    fn triple_budget_and_depth_match_the_circuit() {
        // The sizing figures a caller draws its pool against must be the circuit's own, not a
        // number copied beside it that can drift.
        assert_eq!(
            Node::gf_triples_per_conversion().unwrap(),
            FieldA2BCircuit::<F>::max_and_count().unwrap()
        );
        assert_eq!(
            Node::max_and_layers().unwrap(),
            FieldA2BCircuit::<F>::max_layers().unwrap()
        );
        // Goldilocks: 695 ANDs over 7 AND layers, i.e. one two-round arithmetic mask opening + 7
        // two-round layers of multiplication = 2 + 7 * 2 = 16 message rounds, independent of
        // batch size. That is the batched worst case; a real conversion's layers go direct and
        // measure 9 at every n (`conv_cost_measurement::measured_rounds_a2b_n*`).
        //
        // The parallel offset adder applies the mod-p offset to the *public* operand so both
        // additions run concurrently, trading +11% worst-case ANDs (626 -> 695) for 6 fewer AND
        // layers (13 -> 7) and 12 fewer message rounds (2 + 13 * 2 = 28 -> 16).
        assert_eq!(Node::gf_triples_per_conversion().unwrap(), 695);
        assert_eq!(Node::max_and_layers().unwrap(), 7);
        assert_eq!(Node::bit_width(), 64);
    }

    #[test]
    fn realised_gate_counts_stay_inside_the_reserved_budget() {
        // The budget a caller draws its triple pool against is the worst case over every mask;
        // the plan actually run depends on the mask, because a cleared bit of the public operand
        // folds a whole sub-tree of the carry prefix away. The surplus is simply not consumed —
        // this pins that the reservation really is an upper bound, which is what keeps the
        // `TripleBudgetExceeded` guard in `run` unreachable.
        let budget = Node::gf_triples_per_conversion().unwrap();
        let depth = Node::max_and_layers().unwrap();
        let mut rng = StdRng::seed_from_u64(1);
        let mut total = 0usize;
        let samples = 256usize;
        for _ in 0..samples {
            let y = loop {
                let candidate: u64 = rng.gen();
                if candidate < P {
                    break candidate;
                }
            };
            let circuit = FieldA2BCircuit::<F>::new(F::from(y)).unwrap();
            assert!(circuit.and_count() <= budget);
            assert!(circuit.layers() <= depth);
            total += circuit.and_count();
        }
        let mean = total / samples;
        println!("mean A2B AND count over {samples} uniform masks: {mean} (budget {budget})");
        // Sanity band: a uniform mask clears about half its bits, so the realised count sits a
        // little under the all-ones bound rather than collapsing.
        assert!(mean > budget / 2 && mean <= budget);
    }

    #[test]
    fn new_rejects_degenerate_parameters() {
        assert!(matches!(Node::new(5, 5, 1), Err(A2BError::InvalidPartyId)));
        // More parties than the binary domain has evaluation points cannot be shared in `K`.
        assert!(matches!(
            Node::new(0, K::MAX_DOMAIN_SIZE + 1, 1),
            Err(A2BError::InvalidPartyId)
        ));
        let node = Node::new(2, 4, 1).unwrap();
        assert_eq!(
            node.open.degree, 1,
            "the mask is opened at degree t, not 2t"
        );
    }

    #[test]
    fn pipeline_depth_never_collapses_to_zero() {
        assert_eq!(conv_pipeline_depth(10), MAX_BATCH_RECON_SESSIONS / 10);
        // Beyond `MAX_BATCH_RECON_SESSIONS` parties the integer quotient is zero; a zero depth
        // would issue no sessions at all and hang.
        assert_eq!(conv_pipeline_depth(MAX_BATCH_RECON_SESSIONS + 1), 1);
        assert_eq!(conv_pipeline_depth(0), MAX_BATCH_RECON_SESSIONS);
    }

    #[test]
    fn child_session_ids_are_disjoint_across_parents_and_kinds() {
        let mut a = ChildIds::new(parent(0)).unwrap();
        let mut b = ChildIds::new(parent(1)).unwrap();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            for ids in [&mut a, &mut b] {
                for kind in [ChildKind::Open, ChildKind::GfMul] {
                    let id = ids.next(kind).unwrap();
                    // `GfMultiply::init` asserts both of these; minting them from a counter rather
                    // than from message data is what keeps those asserts unreachable (C12).
                    assert_eq!(id.sub_id(), 0);
                    assert_eq!(id.round_id(), 0);
                    assert_eq!(id.calling_protocol(), Some(kind.tag()));
                    assert!(seen.insert(id), "child session ids must not alias");
                }
            }
        }
    }

    #[tokio::test]
    async fn init_rejects_malformed_session_ids() {
        let mut node = Node::new(0, 4, 1).unwrap();
        let bad = [
            SessionId::new(ProtocolType::Mul, SessionId::pack_slot(0, 0, 0), 0),
            SessionId::new(ProtocolType::A2B, SessionId::pack_slot(0, 1, 0), 0),
            SessionId::new(ProtocolType::A2B, SessionId::pack_slot(0, 0, 1), 0),
        ];
        for session_id in bad {
            let result = node
                .init(
                    session_id,
                    vec![RobustShare::new(F::from(1u64), 0, 1)],
                    vec![dummy_edabit(0, 1)],
                    dummy_triples(626, 0, 1),
                    Duration::from_millis(50),
                    net(4),
                )
                .await;
            assert!(matches!(result, Err(A2BError::SessionIdError(_))));
        }
        assert_eq!(node.store_len().await, 0);
    }

    #[tokio::test]
    async fn init_rejects_empty_and_oversized_batches() {
        let mut node = Node::new(0, 4, 1).unwrap();
        // C13: an empty batch would make every length check below it pass vacuously.
        assert!(matches!(
            node.init(
                parent(0),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Duration::from_millis(50),
                net(4),
            )
            .await,
            Err(A2BError::EmptyBatch)
        ));

        let too_many = MAX_A2B_CONVERSIONS + 1;
        assert!(matches!(
            node.init(
                parent(1),
                vec![RobustShare::new(F::from(1u64), 0, 1); too_many],
                Vec::new(),
                Vec::new(),
                Duration::from_millis(50),
                net(4),
            )
            .await,
            Err(A2BError::BatchTooLarge { .. })
        ));
    }

    #[tokio::test]
    async fn init_checks_material_lengths_exactly() {
        let mut node = Node::new(0, 4, 1).unwrap();
        let budget = Node::gf_triples_per_conversion().unwrap();

        // One edaBit short.
        assert!(matches!(
            node.init(
                parent(0),
                vec![RobustShare::new(F::from(1u64), 0, 1); 2],
                vec![dummy_edabit(0, 1)],
                dummy_triples(2 * budget, 0, 1),
                Duration::from_millis(50),
                net(4),
            )
            .await,
            Err(A2BError::MaterialLengthMismatch {
                what: "edabits",
                ..
            })
        ));

        // One triple too many: a surplus triple is a triple the caller hands to the next batch
        // too, and a Beaver triple reused is a mask reused.
        assert!(matches!(
            node.init(
                parent(1),
                vec![RobustShare::new(F::from(1u64), 0, 1)],
                vec![dummy_edabit(0, 1)],
                dummy_triples(budget + 1, 0, 1),
                Duration::from_millis(50),
                net(4),
            )
            .await,
            Err(A2BError::MaterialLengthMismatch {
                what: "GF(2^k) triples",
                ..
            })
        ));
    }

    #[tokio::test]
    async fn init_rejects_short_edabits() {
        // A short edaBit cannot mask the whole canonical range — and a short one also means the
        // `r < p` filter was never applied, which is a correctness break, not a privacy one.
        let mut node = Node::new(0, 4, 1).unwrap();
        let budget = Node::gf_triples_per_conversion().unwrap();
        let dabits: Vec<DaBit<F, K>> = (0..8)
            .map(|_| {
                DaBit::new(
                    RobustShare::new(F::from(0u64), 0, 1),
                    GfShare::new(Gf256(0), 0, 1),
                    1,
                )
                .unwrap()
            })
            .collect();
        let short = EdaBit::compose(&dabits, 8).unwrap();
        assert!(matches!(
            node.init(
                parent(0),
                vec![RobustShare::new(F::from(1u64), 0, 1)],
                vec![short],
                dummy_triples(budget, 0, 1),
                Duration::from_millis(50),
                net(4),
            )
            .await,
            Err(A2BError::EdaBitWidthMismatch { index: 0, .. })
        ));
    }

    #[tokio::test]
    async fn init_rejects_foreign_share_ids_and_wrong_degrees() {
        // C5: a share carrying a foreign index would be interpolated at the wrong x-coordinate,
        // and a share at the wrong degree is undecodable at the degree every consumer opens at.
        let mut node = Node::new(2, 4, 1).unwrap();
        let budget = Node::gf_triples_per_conversion().unwrap();

        assert!(matches!(
            node.init(
                parent(0),
                vec![RobustShare::new(F::from(1u64), 3, 1)],
                vec![dummy_edabit(2, 1)],
                dummy_triples(budget, 2, 1),
                Duration::from_millis(50),
                net(4),
            )
            .await,
            Err(A2BError::IdMismatch {
                expected: 2,
                got: 3
            })
        ));

        assert!(matches!(
            node.init(
                parent(1),
                vec![RobustShare::new(F::from(1u64), 2, 1)],
                vec![dummy_edabit(2, 1)],
                dummy_triples(budget, 2, 2),
                Duration::from_millis(50),
                net(4),
            )
            .await,
            Err(A2BError::DegreeMismatch {
                expected: 1,
                got: 2
            })
        ));
        assert_eq!(
            node.store_len().await,
            0,
            "nothing is admitted on rejection"
        );
    }

    #[tokio::test]
    async fn clear_store_is_false_for_an_unknown_session() {
        let node = Node::new(0, 4, 1).unwrap();
        assert!(!node.clear_store(parent(7)).await);
    }

    #[tokio::test]
    async fn open_registry_parks_a_result_that_beats_its_own_opener() {
        // A quorum can complete this node's reconstruction before the local opener registers for
        // the session; the payload must survive that race, and the park must stay bounded.
        let mut registry = OpenRegistry::default();
        let session_id = parent(3);
        registry.deliver(session_id, vec![1, 2, 3]);
        let rx = registry.register(session_id);
        assert_eq!(rx.await.unwrap(), vec![1, 2, 3]);

        for exec in 0..(MAX_PARKED_OPEN_PAYLOADS as u64 * 2) {
            registry.deliver(parent(exec), vec![0]);
        }
        assert_eq!(registry.parked.len(), MAX_PARKED_OPEN_PAYLOADS);
    }

    // -----------------------------------------------------------------------------------------
    // End-to-end
    // -----------------------------------------------------------------------------------------

    /// Trusted-dealer stand-in for `PrssDaBitNode` + `EdaBit::compose_full_width`: one full-range
    /// edaBit per conversion, per party, with `r` drawn uniformly from `[0, p)` exactly as the
    /// `r < p` filter guarantees.
    fn deal_edabits(
        n_parties: usize,
        threshold: usize,
        count: usize,
        rng: &mut StdRng,
    ) -> Vec<Vec<EdaBit<F, K>>> {
        let width = Node::bit_width();
        let mut per_party: Vec<Vec<EdaBit<F, K>>> = vec![Vec::new(); n_parties];
        for _ in 0..count {
            // Rejection-sample `r < p`; this is what the ModulusOverflowCircuit filter does in
            // the real pipeline, at a rejection rate of `(2^32 - 1)/2^64`.
            let r = loop {
                let candidate: u64 = rng.gen();
                if candidate < P {
                    break candidate;
                }
            };
            let bits = canonical_bits::<F>(F::from(r), width).unwrap();
            let mut per_party_dabits: Vec<Vec<DaBit<F, K>>> = vec![Vec::new(); n_parties];
            for bit in bits {
                let arith = RobustShare::compute_shares(
                    F::from(bit as u64),
                    n_parties,
                    threshold,
                    None,
                    rng,
                )
                .unwrap();
                let bin =
                    GfShare::compute_shares(bit_to_binary::<K>(bit), n_parties, threshold, rng)
                        .unwrap();
                for party in 0..n_parties {
                    per_party_dabits[party].push(
                        DaBit::new(arith[party].clone(), bin[party].clone(), threshold).unwrap(),
                    );
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
        threshold: usize,
        count: usize,
        rng: &mut StdRng,
    ) -> Vec<Vec<GfBeaverTriple<K>>> {
        let mut per_party: Vec<Vec<GfBeaverTriple<K>>> = vec![Vec::new(); n_parties];
        for _ in 0..count {
            let a = K::random(rng);
            let b = K::random(rng);
            let a_shares = GfShare::compute_shares(a, n_parties, threshold, rng).unwrap();
            let b_shares = GfShare::compute_shares(b, n_parties, threshold, rng).unwrap();
            let c_shares = GfShare::compute_shares(a * b, n_parties, threshold, rng).unwrap();
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

    fn deal_inputs(
        n_parties: usize,
        threshold: usize,
        values: &[F],
        rng: &mut StdRng,
    ) -> Vec<Vec<RobustShare<F>>> {
        let mut per_party: Vec<Vec<RobustShare<F>>> = vec![Vec::new(); n_parties];
        for value in values {
            let shares =
                RobustShare::compute_shares(*value, n_parties, threshold, None, rng).unwrap();
            for party in 0..n_parties {
                per_party[party].push(shares[party].clone());
            }
        }
        per_party
    }

    /// Merges a party's per-sender inboxes into one stream of `(authenticated sender, bytes)`.
    fn fan_in(
        inboxes: Vec<tokio::sync::mpsc::Receiver<Vec<u8>>>,
    ) -> tokio::sync::mpsc::Receiver<(usize, Vec<u8>)> {
        let (tx, rx) = tokio::sync::mpsc::channel(8192);
        for (sender, mut inbox) in inboxes.into_iter().enumerate() {
            let tx = tx.clone();
            tokio::spawn(async move {
                while let Some(bytes) = inbox.recv().await {
                    if tx.send((sender, bytes)).await.is_err() {
                        break;
                    }
                }
            });
        }
        rx
    }

    /// Runs one A2B batch across `n_parties` and returns every party's output bit shares.
    async fn a2b_e2e(
        n_parties: usize,
        threshold: usize,
        values: &[F],
    ) -> Vec<Vec<Vec<GfShare<K>>>> {
        let mut rng = StdRng::seed_from_u64(7);
        let budget = Node::gf_triples_per_conversion().unwrap();
        let inputs = deal_inputs(n_parties, threshold, values, &mut rng);
        let edabits = deal_edabits(n_parties, threshold, values.len(), &mut rng);
        let triples = deal_gf_triples(n_parties, threshold, budget * values.len(), &mut rng);

        let config = FakeNetworkConfig::new(8192);
        let (inner, mut inboxes, _) = FakeInnerNetwork::new(n_parties, None, config);
        let networks: Vec<Arc<FakeNetwork>> = (0..n_parties)
            .map(|id| Arc::new(FakeNetwork::new(id, inner.clone())))
            .collect();

        let nodes: Vec<Node> = (0..n_parties)
            .map(|id| Node::new(id, n_parties, threshold).unwrap())
            .collect();

        // One receiver task per party, demuxing exactly as the node dispatcher will: every
        // `process` is immediately followed by its matching drain (C10). A2B contributes no
        // `WrappedMessage` variant of its own — everything below is a child protocol's traffic,
        // separated by `calling_protocol()` alone.
        for node in &nodes {
            let mut node = node.clone();
            let net = Arc::clone(&networks[node.id]);
            let mut merged = fan_in(std::mem::take(&mut inboxes[node.id]));
            tokio::spawn(async move {
                while let Some((_sender, bytes)) = merged.recv().await {
                    let wrapped: WrappedMessage = match bincode::deserialize(&bytes) {
                        Ok(m) => m,
                        Err(e) => {
                            warn!("undecodable message: {e:?}");
                            continue;
                        }
                    };
                    let outcome = match wrapped {
                        WrappedMessage::BatchRecon(msg) => {
                            match msg.session_id.calling_protocol() {
                                Some(ProtocolType::A2B) => {
                                    let _ = node.open.process(msg, Arc::clone(&net)).await;
                                    node.drain_open_output().await
                                }
                                other => panic!("unexpected batch-recon caller {other:?}"),
                            }
                        }
                        WrappedMessage::GfBatchRecon(msg) => {
                            match msg.session_id.calling_protocol() {
                                Some(ProtocolType::A2BGfMul) => {
                                    let _ = node
                                        .gf_mul
                                        .batch_recon
                                        .process(msg, Arc::clone(&net))
                                        .await;
                                    node.drain_gf_mul_output().await
                                }
                                other => panic!("unexpected GF batch-recon caller {other:?}"),
                            }
                        }
                        WrappedMessage::GfMult(msg) => node
                            .gf_mul
                            .process(msg.sender, msg.session_id, msg.payload)
                            .await
                            .map_err(A2BError::from),
                        other => panic!("unexpected message {other:?}"),
                    };
                    if let Err(e) = outcome {
                        warn!("processing error: {e:?}");
                    }
                }
            });
        }

        let session_id = parent(5);
        let mut set = tokio::task::JoinSet::new();
        for (index, node) in nodes.iter().enumerate() {
            let mut node = node.clone();
            let net = Arc::clone(&networks[index]);
            let x = inputs[index].clone();
            let eda = edabits[index].clone();
            let tri = triples[index].clone();
            set.spawn(async move {
                node.init(session_id, x, eda, tri, Duration::from_secs(60), net)
                    .await
                    .unwrap_or_else(|e| panic!("init failed at party {}: {e:?}", node.id));
                let bits = node
                    .wait_for_result(session_id, Duration::from_secs(60))
                    .await
                    .unwrap_or_else(|e| panic!("no result at party {}: {e:?}", node.id));
                // One mask-opening session plus at least one multiplication session per AND
                // layer: proof that the batch really went through the network rather than
                // short-circuiting into a locally-computable answer.
                let children = {
                    let store = node.store.lock().await;
                    let (_, _, arc) = store.get(&session_id).expect("session exists");
                    let inner = arc.lock().await;
                    inner.child_sessions.len()
                };
                assert!(
                    children > Node::max_and_layers().unwrap(),
                    "expected more than one child session per AND layer, got {children}"
                );
                assert!(node.clear_store(session_id).await);
                // C7: every child session is retired with the parent, on both child nodes.
                assert_eq!(node.open.store_len().await, 0);
                assert_eq!(node.gf_mul.store_len().await, 0);
                (node.id, bits)
            });
        }

        let mut by_party: Vec<Option<Vec<Vec<GfShare<K>>>>> =
            (0..n_parties).map(|_| None).collect();
        while let Some(joined) = set.join_next().await {
            let (id, bits) = joined.expect("party task panicked");
            by_party[id] = Some(bits);
        }
        by_party
            .into_iter()
            .map(|b| b.expect("every party produced an output"))
            .collect()
    }

    /// Reconstructs conversion `index` and returns it as a `u64`.
    fn recover(
        by_party: &[Vec<Vec<GfShare<K>>>],
        index: usize,
        n_parties: usize,
        threshold: usize,
    ) -> u64 {
        let width = Node::bit_width();
        let mut value = 0u64;
        for bit in 0..width {
            let shares: Vec<GfShare<K>> = by_party
                .iter()
                .map(|party| party[index][bit].clone())
                .collect();
            let (_, secret) = GfShare::recover_secret(&shares, n_parties, threshold).unwrap();
            let b = binary_to_bit::<K>(secret)
                .unwrap_or_else(|_| panic!("output bit {bit} of conversion {index} is not a bit"));
            if b {
                value |= 1u64 << bit;
            }
        }
        value
    }

    fn canonical_u64(x: F) -> u64 {
        let limbs = x.into_bigint().0;
        limbs[0]
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a2b_converts_the_boundary_vectors_and_a_random_value() {
        let (n, t) = (4usize, 1usize);
        let values: Vec<F> = [
            0u64,
            1,
            1u64 << 32,
            P - 1,
            P - (1u64 << 32),
            P - 1 - (1u64 << 32),
            0x0123_4567_89AB_CDEF,
        ]
        .iter()
        .map(|v| F::from(*v))
        .collect();

        let by_party = a2b_e2e(n, t, &values).await;
        for (party, out) in by_party.iter().enumerate() {
            assert_eq!(out.len(), values.len());
            for bits in out {
                assert_eq!(bits.len(), Node::bit_width());
                for bit in bits {
                    assert_eq!(bit.id, party);
                    // Degree `t`, never `2t`: the caller opens at `t`, where this repo's robust
                    // reconstruction actually corrects `t` errors.
                    assert_eq!(bit.degree, t);
                }
            }
        }
        for (index, value) in values.iter().enumerate() {
            assert_eq!(
                recover(&by_party, index, n, t),
                canonical_u64(*value),
                "conversion {index} disagrees with the canonical representative"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a2b_batch_that_is_a_multiple_of_the_recon_width_needs_no_padding() {
        // `init_batch_reconstruct_many` requires a non-empty multiple of `degree + 1`, so the
        // opener pads its tail. At `m = t + 1` the padding loop does not run at all, which is the
        // one batch shape the other end-to-end tests (m = 7 and m = 1, both padded) never take.
        let (n, t) = (4usize, 1usize);
        let values = [F::from(0u64), F::from(P - 1)];
        let by_party = a2b_e2e(n, t, &values).await;
        for (index, value) in values.iter().enumerate() {
            assert_eq!(recover(&by_party, index, n, t), canonical_u64(*value));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a2b_of_minus_one_is_canonical_not_twos_complement() {
        // `common/types` encodes `-|v|` as `p - |v|`, so A2B returns `p - 1` and NOT
        // `0xFFFF_FFFF_FFFF_FFFF`. A caller wanting a sign bit must shift by `2^(k-1)` first,
        // exactly as `truncpr.rs` does.
        let (n, t) = (4usize, 1usize);
        let minus_one = F::from(0u64) - F::from(1u64);
        let by_party = a2b_e2e(n, t, &[minus_one]).await;
        let recovered = recover(&by_party, 0, n, t);
        assert_eq!(recovered, P - 1);
        assert_eq!(recovered, 0xFFFF_FFFF_0000_0000);
        assert_ne!(recovered, u64::MAX);
    }
}
