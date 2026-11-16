//! edaBit composition and the modulus-overflow (`r < p`) filter.
//!
//! `[r]_F = Σ 2^i [b_i]_F` is local and free ([`EdaBit::compose`]), but it equals the *integer*
//! `r` only while `r < p`, and `p` is not a power of two. This node computes `r >= p` in the
//! binary domain — the carry out of a `w`-bit prefix adder, 402 ANDs over 8 layers on BLS12-381's
//! scalar field — and opens the one-bit verdict at degree `t`.
//!
//! Skipping the filter is **both** a correctness and a privacy break, at a rate of
//! `(2^w − p)/2^w` — about 9% on BLS12-381's scalar field and 24% on BN254's: `r mod p` for `r`
//! uniform on `[0, 2^w)` is that far from uniform, and the composed `[r]_F` would share
//! `r mod p` while the bits still spell `r`.
//!
//! # Phase: PREPROCESSING
//!
//! The filter is a *range* obligation on the composed edaBit rather than a share-type obligation
//! on any daBit.
//!
//! Its AND waves are **DN07 degree reductions**, which open at degree `2t` and may abort. That
//! is legal here and only here: preprocessing is synchronous, a silent party is timed out, and
//! abort is licensed. See [`crate::honeybadger::dn07`] for the whole argument, and note the
//! structural barrier: `GfDn07MulNode::init_mul` accepts only a `PreprocessingSessionId`, whose
//! constructor classifies this node's `DaBitGfMul` tag through `dn07::phase_of`'s exhaustive
//! match.
//!
//! Each AND consumes one dealt `GfRanDouSha` double sharing, so the filter is
//! information-theoretic end to end: its operands are daBit halves (locally derived, degree `t`
//! by construction) and earlier layers' outputs, and its masks are verified at dealing.
//!
//! The verdict opening at the end is degree-`t` and robust, which is what keeps "no agreement
//! round is needed" true.
//!
//! # The verdict needs no agreement round
//!
//! `bad` is robustly opened at degree `t`, so every honest party sees the same bit and drops the
//! same candidates — the same justification `rand_bit`'s "this square opened to zero, drop the
//! index" branch already relies on.
//!
//! A rejected candidate costs **all** `width` of its daBits, which are dropped rather than
//! returned to any pool: the opened verdict is a function of those bits, so reusing them would
//! hand a later protocol a mask the adversary already knows something about.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Instant;

use ark_ff::PrimeField;
use bincode::Options;
use serde::de::DeserializeOwned;
use stoffelnet::network_utils::{Network, PartyId};
use tokio::sync::{mpsc::Receiver, oneshot, Mutex};
use tokio::time::{timeout, Duration};
use tracing::{info, warn};

use crate::common::session_store::{Admission, SessionStore};
use crate::common::ProtocolSessionId;
use crate::{
    common::{
        convert::{field_bit_width, gf_to_bit},
        gf2k::{field::BinaryField, share::GfShare},
    },
    honeybadger::{
        binary_circuits::{BinaryCircuit, HasNetlist, ModulusOverflowCircuit, WireStore},
        dabit::{conv_pipeline_depth, max_values_per_open, DaBit, DaBitError, EdaBit},
        dn07::{gf_dn07::GfDn07MulNode, PreprocessingSessionId, MAX_DN07_SESSIONS},
        gf_batch_recon::gf_batch_recon::GfBatchReconNode,
        gf_double_share::GfDoubleShamirShare,
        max_mul_pairs_per_session, ProtocolType, SessionId,
    },
};

/// Concurrent edaBit-filter sessions admitted node-wide.
pub const MAX_EDABIT_SESSIONS: usize = 64;

/// Child session ids are `parent_exec * EDABIT_CHILD_STRIDE + wave`, which gives every parent
/// session a disjoint block in each child protocol's own tag space.
///
/// Not `parent_exec + 1 + wave`: parent exec ids come from a counter that increments by one, so an
/// additive scheme aliases the *next* invocation's parent onto this invocation's later waves, and
/// `GfMultiply::init`'s `assert_eq!(sub_id(), 0)` would not catch it.
const EDABIT_CHILD_STRIDE: u64 = 1 << 20;

/// Batch-recon payloads that arrived for a session nobody is waiting on yet. Bounded because a
/// peer can complete this node's reconstruction of a session id before the local opener registers
/// for it.
const MAX_PARKED_OPEN_PAYLOADS: usize = 64;

/// Deserializes `bytes` bounded by their own byte length. `with_fixint_encoding` is required, not
/// optional: `bincode::serialize` encodes length prefixes as fixints while `DefaultOptions`
/// defaults to varint, and the two are not wire-compatible.
fn deser_bounded<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, DaBitError> {
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(bytes.len() as u64)
        .deserialize(bytes)?)
}

/// Which child protocol a minted session id belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ChildKind {
    GfMul,
    GfOpen,
}

impl ChildKind {
    fn tag(self) -> ProtocolType {
        match self {
            ChildKind::GfMul => ProtocolType::DaBitGfMul,
            ChildKind::GfOpen => ProtocolType::DaBitGfOpen,
        }
    }
}

/// Deterministic child-session-id allocator for one filter run.
///
/// Every honest party runs the *same* sequence of waves — the wave counts are functions of
/// `(candidates, width)`, which are agreed — so the ids minted here agree across parties without
/// any extra round. Ids are never derived from message data, which is what keeps
/// `GfMultiply::init`'s `assert_eq!` on `sub_id`/`round_id` unreachable from the network.
struct ChildIds {
    base: u64,
    instance_id: u32,
    waves: [u64; 2],
}

impl ChildIds {
    /// `exec_id` is the parent session's exec id, minted by the node's daBit counter — the same
    /// monotone counter daBit generation draws its parents from, so the two drivers' parent
    /// sessions under [`ProtocolType::DaBit`] never collide.
    fn new(exec_id: u64, instance_id: u32) -> Result<Self, DaBitError> {
        let base = exec_id
            .checked_mul(EDABIT_CHILD_STRIDE)
            .ok_or(DaBitError::LimitError)?;
        Ok(Self {
            base,
            instance_id,
            waves: [0; 2],
        })
    }

    fn next(&mut self, kind: ChildKind) -> Result<SessionId, DaBitError> {
        let slot = kind as usize;
        let wave = self.waves[slot];
        if wave >= EDABIT_CHILD_STRIDE {
            return Err(DaBitError::LimitError);
        }
        self.waves[slot] = wave + 1;
        let exec = self.base.checked_add(wave).ok_or(DaBitError::LimitError)?;
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

/// Per-session state: only the child session ids this run minted, so `clear_store` retires exactly
/// those rather than re-deriving them. Re-derivation drifts as soon as a wave count changes.
#[derive(Debug, Default)]
pub struct EdaBitFilterStore {
    pub child_sessions: Vec<SessionId>,
}

/// Node composing full-range edaBits and filtering out the ones whose mask wraps `p`.
///
/// # One tag per owning node instance
///
/// `GfMultiply::init` mints its batch-reconstruction children with the *parent's* tag, while the
/// node dispatcher demuxes `WrappedMessage::GfBatchRecon` on `calling_protocol()` alone. A node
/// owning both a `GfMultiply<K>` and its own `GfBatchReconNode<K>` under one tag is therefore
/// unroutable, which is why `gf_mul` and `gf_open` carry distinct [`ProtocolType`]s.
#[derive(Clone, Debug)]
pub struct EdaBitFilterNode<F: PrimeField, K: BinaryField> {
    pub id: PartyId,
    pub n_parties: usize,
    pub threshold: usize,
    pub store: Arc<Mutex<SessionStore<SessionId, (usize, Instant, Arc<Mutex<EdaBitFilterStore>>)>>>,
    /// AND layers of the modulus-overflow circuit, as **DN07 degree reductions**. Tag:
    /// [`ProtocolType::DaBitGfMul`].
    ///
    /// **Phase: PREPROCESSING** — synchronous, abort permitted, and the abort is now load-bearing
    /// rather than incidental: this node opens at degree `2t`. That is licensed here and nowhere
    /// else, and the licence is enforced by the type — [`GfDn07MulNode::init_mul`] accepts only a
    /// [`PreprocessingSessionId`], whose constructor classifies `DaBitGfMul` through
    /// `dn07::phase_of`. See [`crate::honeybadger::dn07`] for why `n >= 4t+1` would be needed to
    /// put this opening on the online path, and therefore why it never goes there.
    ///
    /// Each AND spends one dealt `GfRanDouSha` double sharing and one degree-`2t` opening.
    pub gf_dn07: GfDn07MulNode<K>,
    /// Degree-`t` `K`-side opening of the overflow verdict. Tag: [`ProtocolType::DaBitGfOpen`].
    pub gf_open: GfBatchReconNode<K>,
    pub gf_open_output: Arc<Mutex<Receiver<SessionId>>>,
    gf_open_registry: Arc<Mutex<OpenRegistry>>,
    _field: std::marker::PhantomData<F>,
}

impl<F: PrimeField, K: BinaryField> EdaBitFilterNode<F, K> {
    pub fn new(id: PartyId, n_parties: usize, threshold: usize) -> Result<Self, DaBitError> {
        if id >= n_parties {
            return Err(DaBitError::InvalidPartyId);
        }
        if n_parties > K::MAX_DOMAIN_SIZE {
            return Err(DaBitError::InvalidPartyId);
        }
        let (gf_open_sender, gf_open_receiver) = tokio::sync::mpsc::channel(200);
        // degree = t, NOT 2t: the repo's robust reconstruction tolerates zero faults at degree
        // `2t` (`recover_secret` needs `degree + t + 1` agreeing evaluations, which is all `n`).
        let gf_open =
            GfBatchReconNode::<K>::new(id, n_parties, threshold, threshold, gf_open_sender)?;
        Ok(Self {
            id,
            n_parties,
            threshold,
            store: Arc::new(Mutex::new(SessionStore::with_default_cap())),
            gf_dn07: GfDn07MulNode::<K>::new(id, n_parties, threshold)?,
            gf_open,
            gf_open_output: Arc::new(Mutex::new(gf_open_receiver)),
            gf_open_registry: Arc::new(Mutex::new(OpenRegistry::default())),
            _field: std::marker::PhantomData,
        })
    }

    /// `([r]_t, [r]_2t)` double sharings one edaBit candidate's modulus-overflow filter consumes
    /// — one per AND.
    ///
    /// 402 on BLS12-381's scalar field, over 8 AND layers. Read off the circuit rather than written down beside
    /// it, so the two cannot drift.
    pub fn gf_doubles_per_edabit() -> Result<usize, DaBitError> {
        Ok(ModulusOverflowCircuit::<F>::new()?.and_count())
    }

    /// AND layers the modulus-overflow filter runs, i.e. its multiplication rounds.
    pub fn edabit_filter_layers() -> Result<usize, DaBitError> {
        Ok(ModulusOverflowCircuit::<F>::new()?.layers())
    }

    pub async fn store_len(&self) -> usize {
        self.store.lock().await.len()
    }

    async fn get_or_create_store(
        &self,
        session_id: SessionId,
        initiator_id: usize,
    ) -> Admission<Arc<Mutex<EdaBitFilterStore>>> {
        self.store.lock().await.get_or_admit(
            session_id,
            initiator_id,
            MAX_EDABIT_SESSIONS,
            (MAX_EDABIT_SESSIONS / self.n_parties).max(1),
            || Arc::new(Mutex::new(EdaBitFilterStore::default())),
        )
    }

    /// Retires this session and every child session it minted.
    ///
    /// The recorded ids are retired rather than re-derived: re-derivation drifts as soon as a wave
    /// count changes, and an un-retired child counts against a peer's per-peer admission quota
    /// forever.
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
                Some(ProtocolType::DaBitGfMul) => {
                    self.gf_dn07.clear_store(child).await;
                }
                Some(ProtocolType::DaBitGfOpen) => {
                    self.gf_open.clear_store(child).await;
                    self.gf_open_registry.lock().await.cancel(child);
                }
                _ => {}
            }
        }
        self.store.lock().await.retire(session_id)
    }

    /// Routes completed `K`-side openings back to the opener waiting on them.
    pub async fn drain_gf_open_output(&mut self) -> Result<(), DaBitError> {
        loop {
            let id = {
                let mut rx = self.gf_open_output.lock().await;
                match rx.try_recv() {
                    Ok(id) => id,
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        return Err(DaBitError::Abort);
                    }
                }
            };
            match self.gf_open.get_store(id).await {
                Ok(bytes) => self.gf_open_registry.lock().await.deliver(id, bytes),
                Err(e) => {
                    warn!(?id, ?e, "ignoring stale edaBit filter opening output");
                }
            }
        }
        Ok(())
    }

    /// Pumps the `K`-side DN07 node's own batch-reconstruction outputs.
    pub async fn drain_gf_dn07_output(&mut self) -> Result<(), DaBitError> {
        Ok(self.gf_dn07.drain_batch_recon_output().await?)
    }

    async fn record_child(store: &Arc<Mutex<EdaBitFilterStore>>, session_id: SessionId) {
        store.lock().await.child_sessions.push(session_id);
    }

    fn check_bin_share(&self, share: &GfShare<K>) -> Result<(), DaBitError> {
        if share.id != self.id {
            return Err(DaBitError::IdMismatch);
        }
        if share.degree != self.threshold {
            return Err(DaBitError::DegreeMismatch);
        }
        Ok(())
    }

    /// Composes full-range edaBits from `dabits`, taken `field_bit_width::<F>()` at a time, and
    /// **drops the candidates whose composed mask is not less than `p`**.
    ///
    /// This is a **driver**: it awaits its own child sessions, so it must not be polled on the
    /// task that pumps the network.
    ///
    /// # Session id
    ///
    /// `session_id` is a root [`ProtocolType::DaBit`] session whose exec id comes from the node's
    /// daBit counter. Children are minted as `exec * 2^20 + wave` under the filter's own tags.
    pub async fn compose_edabits<N>(
        &mut self,
        session_id: SessionId,
        dabits: Vec<DaBit<F, K>>,
        doubles: Vec<GfDoubleShamirShare<K>>,
        duration: Duration,
        network: Arc<N>,
    ) -> Result<Vec<EdaBit<F, K>>, DaBitError>
    where
        N: Network + Send + Sync + 'static,
    {
        if session_id.calling_protocol() != Some(ProtocolType::DaBit)
            || session_id.sub_id() != 0
            || session_id.round_id() != 0
        {
            return Err(DaBitError::SessionIdError(session_id));
        }

        let width = field_bit_width::<F>();
        if width == 0 {
            return Err(DaBitError::ZeroWidth);
        }
        // An empty batch makes every length check below pass vacuously.
        if dabits.is_empty() {
            return Err(DaBitError::NotEnoughMaterial("edabit dabits"));
        }
        // Exact, never `>=`. A surplus daBit silently dropped here is a daBit the caller believes
        // is still unused, i.e. one-time-pad reuse the next time it is handed out.
        if dabits.len() % width != 0 {
            return Err(DaBitError::MaterialLengthMismatch {
                what: "edabit dabits",
                expected: dabits.len().next_multiple_of(width),
                got: dabits.len(),
            });
        }
        let candidates = dabits.len() / width;

        let circuit = ModulusOverflowCircuit::<F>::new()?;
        let per_candidate = circuit.and_count();
        let expected_doubles = per_candidate
            .checked_mul(candidates)
            .ok_or(DaBitError::LimitError)?;
        if doubles.len() != expected_doubles {
            return Err(DaBitError::MaterialLengthMismatch {
                what: "edabit filter GF(2^k) double sharings",
                expected: expected_doubles,
                got: doubles.len(),
            });
        }

        // Index and degree checked in both domains independently. The two domains share only the
        // party index; their evaluation points are unrelated.
        for dabit in &dabits {
            if dabit.arith.id != self.id || dabit.arith.degree != self.threshold {
                return Err(DaBitError::IdMismatch);
            }
            self.check_bin_share(&dabit.bin)?;
        }
        // The degree-`t` half is checked exactly like every other degree-`t` share this node
        // handles. The degree-`2t` half is checked against `2t` explicitly rather than through
        // `check_bin_share`, and its *value* is all DN07 uses — `localise` substitutes the local
        // protocol constants for both labels — so this is a caller-hygiene check, not a security
        // one. What makes an honest `[r]` unforgeable is that it is derived, never dealt.
        for pair in &doubles {
            self.check_bin_share(&pair.degree_t)?;
            if pair.degree_2t.id != self.id {
                return Err(DaBitError::IdMismatch);
            }
            if pair.degree_2t.degree != 2 * self.threshold {
                return Err(DaBitError::DegreeMismatch);
            }
        }

        let store = match self.get_or_create_store(session_id, self.id).await {
            Admission::Got(arc) => arc,
            // Our own session: a silent `Ok` would hand the caller an empty pool instead.
            Admission::Retired | Admission::Rejected => return Err(DaBitError::LimitError),
        };
        let mut ids = ChildIds::new(session_id.exec_id(), session_id.instance_id())?;

        let result = self
            .run_edabit_filter(
                &circuit,
                &dabits,
                &doubles,
                candidates,
                width,
                per_candidate,
                &mut ids,
                &store,
                duration,
                &network,
            )
            .await;

        // Cleared on every exit path, before the `?`: a session abandoned mid-flight must not stay
        // resident just because an error would have skipped past the cleanup.
        if !self.clear_store(session_id).await {
            warn!(?session_id, "failed to clear edaBit filter state");
        }
        result
    }

    async fn run_edabit_filter<N: Network + Send + Sync + 'static>(
        &mut self,
        circuit: &ModulusOverflowCircuit<F>,
        dabits: &[DaBit<F, K>],
        doubles: &[GfDoubleShamirShare<K>],
        candidates: usize,
        width: usize,
        per_candidate: usize,
        ids: &mut ChildIds,
        store: &Arc<Mutex<EdaBitFilterStore>>,
        duration: Duration,
        network: &Arc<N>,
    ) -> Result<Vec<EdaBit<F, K>>, DaBitError> {
        let mut wires: Vec<WireStore<K>> = Vec::with_capacity(candidates);
        for index in 0..candidates {
            let bits: Vec<GfShare<K>> = dabits[index * width..(index + 1) * width]
                .iter()
                .map(|dabit| dabit.bin.clone())
                .collect();
            wires.push(circuit.init(&bits)?);
        }

        // One multiplication wave per AND layer, shared by every candidate in the batch: the
        // netlist is public and identical for all of them, so the round count is 6 regardless of
        // how many edaBits are being composed.
        let layers = circuit.layers();
        let mut consumed = vec![0usize; candidates];
        for layer in 0..layers {
            let mut lhs: Vec<GfShare<K>> = Vec::new();
            let mut rhs: Vec<GfShare<K>> = Vec::new();
            let mut wave_doubles: Vec<GfDoubleShamirShare<K>> = Vec::new();
            let mut spans: Vec<(usize, usize)> = Vec::new();

            for index in 0..candidates {
                let and_layer = circuit.build_layer(layer, &mut wires[index])?;
                let len = and_layer.len();
                let start = index * per_candidate + consumed[index];
                let end = start + len;
                // `get`, never a bare slice index: the budget above is the circuit's own figure,
                // but an out-of-bounds slice would be a panic rather than an error.
                let slice = doubles
                    .get(start..end)
                    .ok_or(DaBitError::MaterialLengthMismatch {
                        what: "edabit filter GF(2^k) double sharings",
                        expected: end,
                        got: doubles.len(),
                    })?;
                wave_doubles.extend_from_slice(slice);
                consumed[index] += len;
                spans.push((index, len));
                lhs.extend(and_layer.lhs);
                rhs.extend(and_layer.rhs);
            }

            let products = self
                .mul_k(&lhs, &rhs, &wave_doubles, ids, store, duration, network)
                .await?;
            if products.len() != lhs.len() {
                return Err(DaBitError::MaterialLengthMismatch {
                    what: "edabit filter AND layer products",
                    expected: lhs.len(),
                    got: products.len(),
                });
            }

            let mut cursor = 0usize;
            for (index, len) in spans {
                let slice = products.get(cursor..cursor + len).ok_or(
                    DaBitError::MaterialLengthMismatch {
                        what: "edabit filter AND layer products",
                        expected: cursor + len,
                        got: products.len(),
                    },
                )?;
                circuit.absorb_layer(layer, slice.to_vec(), &mut wires[index])?;
                cursor += len;
            }
        }

        let mut overflow_shares = Vec::with_capacity(candidates);
        for index in 0..candidates {
            let outputs = circuit.outputs(&wires[index])?;
            let bit = outputs
                .into_iter()
                .next()
                .ok_or(DaBitError::MaterialLengthMismatch {
                    what: "edabit filter overflow bit",
                    expected: 1,
                    got: 0,
                })?;
            overflow_shares.push(bit);
        }

        let opened = self
            .open_k(&overflow_shares, ids, store, duration, network)
            .await?;
        if opened.len() != candidates {
            return Err(DaBitError::MaterialLengthMismatch {
                what: "opened edabit overflow bits",
                expected: candidates,
                got: opened.len(),
            });
        }

        let mut edabits = Vec::with_capacity(candidates);
        let mut rejected = 0usize;
        for (index, value) in opened.into_iter().enumerate() {
            let overflow = gf_to_bit(value)?;
            match EdaBit::compose_full_width(&dabits[index * width..(index + 1) * width], overflow)
            {
                Ok(edabit) => edabits.push(edabit),
                // The expected, non-adversarial rejection. Every one of this candidate's daBits
                // goes with it — the opened verdict correlates with them.
                Err(DaBitError::ModulusOverflow) => rejected += 1,
                Err(e) => return Err(e),
            }
        }
        if rejected > 0 {
            info!(
                party = self.id,
                rejected, candidates, "discarded edaBit candidates whose mask was not below p"
            );
        }
        Ok(edabits)
    }

    /// Opens `values` at degree `t` and returns the opened scalars in input order.
    ///
    /// Chunked against [`max_values_per_open`] and pipelined at [`conv_pipeline_depth`], with each
    /// wave awaited and cleared before the next is issued — the two bounds that keep a wave from
    /// exhausting a peer's per-peer batch-reconstruction quota or filling the 200-slot channel
    /// inside the reconstruction path.
    async fn open_k<N: Network + Send + Sync + 'static>(
        &mut self,
        values: &[GfShare<K>],
        ids: &mut ChildIds,
        store: &Arc<Mutex<EdaBitFilterStore>>,
        duration: Duration,
        network: &Arc<N>,
    ) -> Result<Vec<K>, DaBitError> {
        if values.is_empty() {
            return Ok(Vec::new());
        }
        let width = self.threshold + 1;
        let chunks: Vec<&[GfShare<K>]> =
            values.chunks(max_values_per_open(self.threshold)).collect();
        let mut opened = Vec::with_capacity(values.len());

        for group in chunks.chunks(conv_pipeline_depth(self.n_parties)) {
            let mut first_err: Option<DaBitError> = None;
            let mut issued = Vec::with_capacity(group.len());

            for chunk in group {
                let session_id = ids.next(ChildKind::GfOpen)?;
                Self::record_child(store, session_id).await;
                let mut padded = chunk.to_vec();
                while padded.len() % width != 0 {
                    padded.push(GfShare::new(K::one(), self.id, self.threshold));
                }
                let rx = self.gf_open_registry.lock().await.register(session_id);
                match self
                    .gf_open
                    .init_batch_reconstruct_many(&padded, session_id, Arc::clone(network))
                    .await
                {
                    Ok(()) => issued.push((session_id, rx, chunk.len())),
                    Err(e) => {
                        self.gf_open_registry.lock().await.cancel(session_id);
                        if first_err.is_none() {
                            first_err = Some(e.into());
                        }
                    }
                }
            }

            for (session_id, rx, real_len) in issued {
                let result = match timeout(duration, rx).await {
                    Ok(Ok(bytes)) => deser_bounded::<Vec<K>>(&bytes),
                    Ok(Err(_)) => Err(DaBitError::ReceiveError(session_id)),
                    Err(_) => Err(DaBitError::Timeout(session_id)),
                };
                self.gf_open.clear_store(session_id).await;
                self.gf_open_registry.lock().await.cancel(session_id);
                match result {
                    Ok(mut decoded) => {
                        if decoded.len() < real_len {
                            if first_err.is_none() {
                                first_err = Some(DaBitError::MaterialLengthMismatch {
                                    what: "opened GF(2^k) values",
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

    /// DN07 degree reduction of `x[i] * y[i]`, chunked and depth-capped like the opener.
    ///
    /// **One degree-`2t` opening per wave, no Beaver triple, no degree-`t` opening.** The result
    /// is degree `t` — `[r]_t + d` with `d` public — which is why the circuit's next layer, and
    /// the verdict opening at the end, are unchanged by this being DN07 rather than Beaver.
    ///
    /// # Why a degree-`2t` opening is sound on these operands
    ///
    /// [`GfDn07MulNode::init_mul`] carries a warning that has teeth: a degree-`2t` opening at
    /// `n = 3t+1` imposes **no** codeword constraint on the honest sub-word, so an operand *dealt*
    /// at degree `t+1` is recoverable from the opening with no abort raised. Nothing on this path
    /// is a dealt Shamir sharing. `lhs`/`rhs` are either a daBit's binary half — computed locally
    /// by each party from set bits it has cross-checked with every other holder — or the output
    /// of an earlier layer of this same reduction, which is `[r]_t + d` on a `RanDouSha`-verified
    /// `[r]_t`. A corrupt party's only freedom is to lie at the
    /// opening, and the `[3t+1, 2t+1]` code's distance `t+1 > t` makes any such lie a non-codeword
    /// that `recover_secret` rejects: detection with probability 1, no sacrifice and no MAC.
    ///
    /// # Abort
    ///
    /// A wrong share aborts the batch. That is licensed: the whole node is preprocessing, it already aborts on `duration` expiry,
    /// and preprocessing may abort. It must not be moved: `a2b` reaches this code through
    /// `ensure_edabits`' lazy top-up, but it reaches it as *preprocessing that runs first*, never
    /// as a step of `A2BNode`, which holds no handle to any DN07 node.
    async fn mul_k<N: Network + Send + Sync + 'static>(
        &mut self,
        x: &[GfShare<K>],
        y: &[GfShare<K>],
        doubles: &[GfDoubleShamirShare<K>],
        ids: &mut ChildIds,
        store: &Arc<Mutex<EdaBitFilterStore>>,
        duration: Duration,
        network: &Arc<N>,
    ) -> Result<Vec<GfShare<K>>, DaBitError> {
        if x.len() != y.len() || x.len() != doubles.len() {
            return Err(DaBitError::MaterialLengthMismatch {
                what: "GF(2^k) multiplication operands",
                expected: x.len(),
                got: y.len().min(doubles.len()),
            });
        }
        if x.is_empty() {
            return Ok(Vec::new());
        }

        // Two ceilings, both real. `max_mul_pairs_per_session` is the child-session-space bound
        // this node has always chunked against and is the smaller of the two at every threshold
        // the repo admits; `max_batch_size` is DN07's own per-session group cap, and taking the
        // `min` means a future change to either constant cannot silently produce a `BatchTooLarge`
        // from inside the filter.
        let per_session =
            max_mul_pairs_per_session(self.threshold).min(self.gf_dn07.max_batch_size());
        let mut result = Vec::with_capacity(x.len());
        let mut offset = 0usize;

        // Sessions in flight at once. `conv_pipeline_depth` bounds the batch-reconstruction
        // child's own per-peer quota; `MAX_DN07_SESSIONS / n` bounds this node's. They happen to
        // be the same figure at every `n` — both are `256 / n` — but the `min` states the
        // dependency rather than relying on that, because a wave that exceeded either would be
        // rejected by the node's own admission control and the filter would stall on a session it
        // issued to itself.
        let depth = conv_pipeline_depth(self.n_parties)
            .min((MAX_DN07_SESSIONS / self.n_parties.max(1)).max(1));

        while offset < x.len() {
            let wave_end = (offset + per_session * depth).min(x.len());
            let mut first_err: Option<DaBitError> = None;
            let mut issued = Vec::new();

            let mut cursor = offset;
            while cursor < wave_end {
                let end = (cursor + per_session).min(wave_end);
                let session_id = ids.next(ChildKind::GfMul)?;
                Self::record_child(store, session_id).await;
                // The phase barrier, evaluated per session rather than hoisted: `DaBitGfMul` is
                // classified `Preprocessing` by `dn07::phase_of`'s exhaustive match, and this
                // call is what turns that classification into a value the node will accept.
                let pre_sid = match PreprocessingSessionId::new(session_id) {
                    Ok(sid) => sid,
                    Err(e) => {
                        if first_err.is_none() {
                            first_err = Some(e.into());
                        }
                        cursor = end;
                        continue;
                    }
                };
                match self
                    .gf_dn07
                    .init_mul(
                        pre_sid,
                        x[cursor..end].to_vec(),
                        y[cursor..end].to_vec(),
                        doubles[cursor..end].to_vec(),
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
                match self.gf_dn07.wait_for_products(session_id, duration).await {
                    Ok(mut chunk) => result.append(&mut chunk),
                    Err(e) if first_err.is_none() => first_err = Some(e.into()),
                    Err(_) => {}
                }
                if !self.gf_dn07.clear_store(session_id).await {
                    warn!(
                        ?session_id,
                        "failed to clear edaBit filter GF(2^k) DN07 multiplication state"
                    );
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::gf2k::field::Gf256;
    use ark_bls12_381::Fr as CurveField;

    type F = CurveField;
    type K = Gf256;
    type Node = EdaBitFilterNode<F, K>;

    fn sid(exec: u64) -> SessionId {
        SessionId::new(ProtocolType::DaBit, SessionId::pack_slot(exec, 0, 0), 7)
    }

    /// Read off the circuit, never written down beside it.
    #[test]
    fn the_filter_cost_is_the_overflow_circuit_s() {
        let circuit = ModulusOverflowCircuit::<F>::new().unwrap();
        assert_eq!(Node::gf_doubles_per_edabit().unwrap(), circuit.and_count());
        assert_eq!(Node::edabit_filter_layers().unwrap(), circuit.layers());
        // BLS12-381's scalar field has a general modulus, so the comparison is the carry out of a
        // 255-bit prefix adder.
        assert!(!circuit.is_specialised());
        assert_eq!(Node::gf_doubles_per_edabit().unwrap(), 402);
    }

    #[test]
    fn new_rejects_out_of_range_party_indices() {
        assert!(matches!(
            Node::new(10, 10, 3),
            Err(DaBitError::InvalidPartyId)
        ));
        assert!(matches!(
            Node::new(0, 256, 3),
            Err(DaBitError::InvalidPartyId)
        ));
        assert!(Node::new(0, 10, 3).is_ok());
    }

    /// The verdict opening is degree `t`, not `2t` — this whole module is on the robust path.
    #[test]
    fn the_verdict_opening_is_pinned_at_degree_t() {
        let node = Node::new(1, 13, 4).unwrap();
        assert_eq!(node.gf_open.degree, 4);
    }

    /// Child blocks of two different parents must not overlap, and the two kinds must not collide
    /// with each other.
    #[tokio::test]
    async fn child_session_ids_are_disjoint_across_parents_and_kinds() {
        let mut a = ChildIds::new(0, 7).unwrap();
        let mut b = ChildIds::new(1, 7).unwrap();
        let a0 = a.next(ChildKind::GfMul).unwrap();
        let a1 = a.next(ChildKind::GfMul).unwrap();
        let a_open = a.next(ChildKind::GfOpen).unwrap();
        let b0 = b.next(ChildKind::GfMul).unwrap();

        assert_ne!(a0, a1);
        assert_ne!(a0, a_open);
        assert_eq!(a0.calling_protocol(), Some(ProtocolType::DaBitGfMul));
        assert_eq!(a_open.calling_protocol(), Some(ProtocolType::DaBitGfOpen));
        // Parent 1's first wave must be far past parent 0's whole block.
        assert!(b0.exec_id() >= a0.exec_id() + EDABIT_CHILD_STRIDE);
        // Root sessions: the sub/round bytes are the child-minting space and must be free.
        for id in [a0, a1, a_open, b0] {
            assert_eq!(id.sub_id(), 0);
            assert_eq!(id.round_id(), 0);
        }
    }

    #[tokio::test]
    async fn compose_rejects_bad_sessions_and_bad_material_lengths() {
        use stoffelmpc_network::fake_network::{FakeInnerNetwork, FakeNetwork, FakeNetworkConfig};
        let (inner, _inboxes, _) = FakeInnerNetwork::new(10, None, FakeNetworkConfig::new(10));
        let network = Arc::new(FakeNetwork::new(0, inner));
        let mut node = Node::new(0, 10, 3).unwrap();

        // Not a root daBit session.
        let wrong = SessionId::new(ProtocolType::DaBit, SessionId::pack_slot(0, 1, 0), 7);
        assert!(matches!(
            node.compose_edabits(
                wrong,
                vec![],
                vec![],
                Duration::from_millis(5),
                network.clone()
            )
            .await,
            Err(DaBitError::SessionIdError(_))
        ));

        // Empty batch: refused rather than silently vacuous.
        assert!(matches!(
            node.compose_edabits(
                sid(1),
                vec![],
                vec![],
                Duration::from_millis(5),
                network.clone()
            )
            .await,
            Err(DaBitError::NotEnoughMaterial("edabit dabits"))
        ));

        // Not a whole number of candidates.
        let width = field_bit_width::<F>();
        let dabit = DaBit::<F, K>::new(
            crate::honeybadger::robust_interpolate::robust_interpolate::RobustShare::new(
                F::from(0u64),
                0,
                3,
            ),
            GfShare::new(Gf256(0), 0, 3),
            3,
        )
        .unwrap();
        assert!(matches!(
            node.compose_edabits(
                sid(2),
                vec![dabit.clone(); width - 1],
                vec![],
                Duration::from_millis(5),
                network.clone()
            )
            .await,
            Err(DaBitError::MaterialLengthMismatch {
                what: "edabit dabits",
                ..
            })
        ));

        // Right daBit count, wrong double-sharing count.
        assert!(matches!(
            node.compose_edabits(
                sid(3),
                vec![dabit; width],
                vec![],
                Duration::from_millis(5),
                network
            )
            .await,
            Err(DaBitError::MaterialLengthMismatch {
                what: "edabit filter GF(2^k) double sharings",
                expected: 402,
                got: 0
            })
        ));
    }
}
