//! Information-theoretic daBits from replicated one-time bits.
//!
//! A daBit is one secret bit `b` shared in both domains: `[b]_F` over the prime field and `[b]_K`
//! over GF(2^k). This generator uses **no PRF, no hash and no commitment** — every random value
//! in it is a fresh uniform bit drawn from the operating system's generator and used once.
//!
//! # The protocol
//!
//! Let `T` range over the `C(n,t)` maximal unqualified sets, and call `A_T` the `n - t` parties
//! outside `T`. For a batch of `m` daBits:
//!
//! ```text
//! 1. Deal    the lowest-indexed party of A_T samples m uniform bits β_T[0..m) and sends them to
//!            the other members of A_T.
//! 2. Echo    every member of A_T sends what it holds for T to every other member; any mismatch
//!            aborts.
//! 3. K side  [b]_K = Σ_{T ∌ i} β_T · f^K_T(x^K_i)            local; the secret is ⊕_T β_T
//! 4. F side  [β_T]_F = β_T · f_T(x_i)   (0 for i ∈ T)        local; one sharing per set
//!            [b]_F = XOR-fold of the C(n,t) sharings          C(n,t) - 1 multiplications
//! ```
//!
//! `f_T` is the degree-`t` polynomial with `f_T(0) = 1` that vanishes on `T`, so `β_T · f_T` is a
//! genuine degree-`t` sharing of `β_T` whose shares at `T` are zero — exactly the shares the
//! parties who must not learn `β_T` can compute without it. In characteristic 2 the sum over sets
//! is the XOR, so the `K` side is free. Over `F` the same sum would be the *integer* `Σ β_T`, so
//! the XOR is computed explicitly: `x ⊕ y = x + y - 2xy`, one multiplication per fold.
//!
//! Both halves are functions of the *same* `β_T`, so they agree by arithmetic and there is no
//! cross-domain consistency check to run.
//!
//! # Security
//!
//! **Privacy is perfect.** Some `T*` contains every corrupt party, so `A_{T*}` is all honest: its
//! dealer is honest, `β_{T*}` is uniform, and no corrupt party ever receives it. `b = ⊕_T β_T`
//! is therefore uniform given the adversary's view, provided the multiplications are private —
//! and they are degree-reduction multiplications masked by dealt `RanDouSha` double sharings,
//! which are themselves information-theoretic.
//!
//! **Correctness needs only the echo.** Every share an honest party holds is computed locally
//! from values it received, so the only way to produce an inconsistent sharing is for a corrupt
//! dealer to give two honest members of `A_T` different bits. Those two members echo to each
//! other and both abort. A corrupt party's remaining freedom is to lie at an opening, which the
//! degree-`2t` opening's exact check detects.
//!
//! **Bit-ness is structural.** The wire carries packed bits, so a dealt value cannot be anything
//! but 0 or 1; XOR of bits is a bit in both fields.
//!
//! # Phase: PREPROCESSING
//!
//! Synchronous and abort-permitted. A silent or cheating party stalls or aborts the batch; it
//! cannot bias it, learn it or corrupt it. The multiplications open at degree `2t` under
//! [`ProtocolType::DaBitMul`], which `dn07::phase_of` classifies as preprocessing.
//!
//! # Cost
//!
//! Per daBit: `C(n,t)` dealt bits, each sent to `n - t - 1` parties and echoed pairwise, plus
//! `C(n,t) - 1` multiplications in `⌈log2 C(n,t)⌉` rounds — 3 multiplications at `n = 4`, 34 at
//! `n = 7`, 119 at `n = 10`. The cost grows with `C(n,t)`, as every replicated construction does.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_std::rand::{rngs::OsRng, RngCore};
use itertools::Itertools;
use stoffelnet::network_utils::{Network, PartyId};
use tokio::sync::{oneshot, Mutex};
use tokio::time::{timeout, Duration};
use tracing::warn;

use crate::common::gf2k::field::BinaryField;
use crate::common::gf2k::get_or_create_gf2k_domain;
use crate::common::gf2k::share::GfShare;
use crate::common::session_store::{Admission, SessionStore};
use crate::common::ProtocolSessionId;
use crate::honeybadger::dabit::packing::{bit_at, clear_padding, is_canonical, packed_len};
use crate::honeybadger::dabit::{
    conv_pipeline_depth, DaBit, DaBitError, DaBitMessage, DaBitPayload,
};
use crate::honeybadger::dn07::{dn07::Dn07MulNode, PreprocessingSessionId, MAX_DN07_SESSIONS};
use crate::honeybadger::double_share::DoubleShamirShare;
use crate::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use crate::honeybadger::{max_mul_pairs_per_session, ProtocolType, SessionId, WrappedMessage};

/// Concurrent daBit-generation sessions admitted node-wide.
pub const MAX_DABIT_GEN_SESSIONS: usize = 64;

/// Largest batch one session may produce, before the per-message byte bound below is applied.
pub const MAX_DABIT_BATCH: usize = 4096;

/// Byte bound on one `Deal` or `Echo` message's packed bits. Sizes the batch and bounds what a
/// peer can make this node buffer for a session it has not initialised yet.
pub const MAX_DEAL_MESSAGE_BYTES: usize = 1 << 20;

/// Child session ids are `parent_exec * DABIT_CHILD_STRIDE + wave`, the same scheme the edaBit
/// filter uses under its own tags.
const DABIT_CHILD_STRIDE: u64 = 1 << 20;

/// Upper bound on `C(n, t)`, the number of unqualified sets this generator will enumerate. `n`
/// and `t` come from the deployment, never from the wire, so this guards against a configuration
/// that would allocate without bound rather than against a peer. It admits `C(16,5) = 4368` and
/// `C(19,6) = 27 132`.
pub const MAX_UNQUALIFIED_SETS: usize = 65_536;

/// `C(n, t)` when it is within [`MAX_UNQUALIFIED_SETS`], `None` when it overflows or exceeds it.
/// Called before [`all_tsets`], never after: the allocation is the thing being prevented.
fn bounded_set_count(n: usize, t: usize) -> Option<u128> {
    if t > n {
        return Some(0);
    }
    let k = t.min(n - t);
    let mut count: u128 = 1;
    for i in 0..k {
        count = count.checked_mul((n - i) as u128)?;
        count /= (i + 1) as u128;
    }
    (count <= MAX_UNQUALIFIED_SETS as u128).then_some(count)
}

/// All `t`-subsets of the parties, in the order every party must agree on: the rank of a set in
/// this list is how dealing and echo messages name it. Lexicographic over ascending indices.
///
/// Defined here rather than borrowed, so that nothing on the conversion path depends on the
/// pseudo-random sharing module.
fn all_tsets(n: usize, t: usize) -> Vec<Vec<usize>> {
    (0..n).combinations(t).collect()
}

/// One maximal unqualified set, from this party's point of view.
#[derive(Clone, Debug)]
struct SetEntry<F: PrimeField, K: BinaryField> {
    /// The parties that must not learn this set's bits, ascending.
    tset: Vec<usize>,
    /// The party that samples this set's bits: the lowest index outside `tset`.
    dealer: usize,
    /// Whether this party is outside `tset`, i.e. holds the set's bits.
    member: bool,
    /// `f_T(x_id)` over `F`. Zero when this party is in `tset`.
    coeff_f: F,
    /// `f^K_T(x^K_id)` over `K`. Zero when this party is in `tset`.
    coeff_k: K,
}

/// The `C(n,t)` unqualified sets in `all_tsets` order, with this party's conversion coefficients.
#[derive(Clone, Debug)]
pub struct SetTable<F: PrimeField, K: BinaryField> {
    id: usize,
    n: usize,
    entries: Vec<SetEntry<F, K>>,
}

impl<F: PrimeField, K: BinaryField> SetTable<F, K> {
    /// # Errors
    /// [`DaBitError::InvalidPartyId`], [`DaBitError::ThresholdOutOfRange`],
    /// [`DaBitError::TooManyUnqualifiedSets`], or a domain error for an `n` the fields cannot
    /// address.
    pub fn new(id: usize, n: usize, t: usize) -> Result<Self, DaBitError> {
        if id >= n || n > K::MAX_DOMAIN_SIZE {
            return Err(DaBitError::InvalidPartyId);
        }
        if t == 0 {
            return Err(DaBitError::DegenerateThreshold);
        }
        if n < 3 * t + 1 {
            return Err(DaBitError::ThresholdOutOfRange { n, t });
        }
        if bounded_set_count(n, t).is_none() {
            return Err(DaBitError::TooManyUnqualifiedSets {
                n,
                t,
                max: MAX_UNQUALIFIED_SETS as u128,
            });
        }

        let f_domain = GeneralEvaluationDomain::<F>::new(n)
            .ok_or(crate::common::share::ShareError::NoSuitableDomain(n))?;
        let k_domain = get_or_create_gf2k_domain::<K>(n)
            .map_err(|e| DaBitError::InvalidDealing(format!("GF(2^k) domain: {e:?}")))?;
        let x_f = f_domain.element(id);
        let x_k = k_domain.element(id);

        let mut entries = Vec::new();
        for tset in all_tsets(n, t) {
            let member = !tset.contains(&id);
            let dealer = (0..n)
                .find(|j| !tset.contains(j))
                .ok_or(DaBitError::ThresholdOutOfRange { n, t })?;
            // f_T(x) = Π_{j ∈ T} (x - x_j) / (0 - x_j): one at zero, zero on T, degree |T|.
            let mut coeff_f = F::one();
            let mut coeff_k = K::one();
            for j in &tset {
                let xj_f = f_domain.element(*j);
                let xj_k = k_domain.element(*j);
                let inv_f = (-xj_f).inverse().ok_or(DaBitError::InvalidPartyId)?;
                let inv_k = xj_k.inverse().ok_or(DaBitError::InvalidPartyId)?;
                coeff_f *= (x_f - xj_f) * inv_f;
                // Characteristic 2: `x - x_j` is `x + x_j` and `-x_j` is `x_j`.
                coeff_k = coeff_k * (x_k + xj_k) * inv_k;
            }
            entries.push(SetEntry {
                tset,
                dealer,
                member,
                coeff_f,
                coeff_k,
            });
        }
        Ok(Self { id, n, entries })
    }

    /// `C(n,t)`.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether `party` is outside set `rank`.
    fn holds(&self, rank: usize, party: usize) -> bool {
        self.entries
            .get(rank)
            .is_some_and(|e| party < self.n && !e.tset.contains(&party))
    }

    /// Ranks this party deals and `to` must receive.
    fn deal_ranks(&self, to: usize) -> Vec<usize> {
        (0..self.entries.len())
            .filter(|r| self.entries[*r].dealer == self.id && self.holds(*r, to))
            .collect()
    }

    /// Ranks both this party and `other` hold, i.e. what an echo between them covers.
    fn shared_ranks(&self, other: usize) -> Vec<usize> {
        (0..self.entries.len())
            .filter(|r| self.entries[*r].member && self.holds(*r, other))
            .collect()
    }

    /// Ranks this party holds.
    fn member_ranks(&self) -> Vec<usize> {
        (0..self.entries.len())
            .filter(|r| self.entries[*r].member)
            .collect()
    }

    /// This party's `K`-side share of daBit `index`: `Σ_T β_T · f^K_T(x^K_id)`.
    fn bin_share(&self, bits: &HashMap<usize, Vec<u8>>, index: usize) -> K {
        let mut acc = K::zero();
        for (rank, entry) in self.entries.iter().enumerate() {
            if entry.member && bits.get(&rank).is_some_and(|b| bit_at(b, index)) {
                acc = acc + entry.coeff_k;
            }
        }
        acc
    }

    /// This party's `F`-side shares of daBit `index`, one per set: `β_T · f_T(x_id)`, which is
    /// zero both when the bit is zero and when this party is inside `T`.
    fn arith_leaves(&self, bits: &HashMap<usize, Vec<u8>>, index: usize) -> Vec<F> {
        self.entries
            .iter()
            .enumerate()
            .map(|(rank, entry)| {
                if entry.member && bits.get(&rank).is_some_and(|b| bit_at(b, index)) {
                    entry.coeff_f
                } else {
                    F::zero()
                }
            })
            .collect()
    }
}

/// `count` uniform bits, packed LSB-first with the unused high bits of the last byte cleared.
///
/// Canonical packing matters: the echo compares bytes, so two honest holders must agree on the
/// padding as well as on the bits.
fn sample_bits(count: usize) -> Vec<u8> {
    let mut packed = vec![0u8; packed_len(count)];
    OsRng.fill_bytes(&mut packed);
    clear_padding(&mut packed, count);
    packed
}

/// Multiplications one daBit's XOR fold spends: `C(n,t) - 1`.
pub fn doubles_per_dabit(n: usize, t: usize) -> Result<usize, DaBitError> {
    let sets = bounded_set_count(n, t).ok_or(DaBitError::TooManyUnqualifiedSets {
        n,
        t,
        max: MAX_UNQUALIFIED_SETS as u128,
    })?;
    Ok((sets as usize).saturating_sub(1))
}

/// Per-session dealing state.
#[derive(Debug)]
pub struct DealStore {
    /// Batch size, known once this party has initialised the session.
    count: Option<usize>,
    /// Accepted packed bits per set rank.
    bits: HashMap<usize, Vec<u8>>,
    /// `Deal` payloads, at most one per sender, kept until `count` is known.
    deals: HashMap<PartyId, (u32, Vec<(u32, Vec<u8>)>)>,
    /// `Echo` payloads, at most one per sender, kept until this party holds all its own bits.
    echoes: HashMap<PartyId, (u32, Vec<(u32, Vec<u8>)>)>,
    echo_sent: bool,
    echo_ok: HashSet<PartyId>,
    finished: bool,
    done_tx: Option<oneshot::Sender<Result<(), DaBitError>>>,
    done_rx: Option<oneshot::Receiver<Result<(), DaBitError>>>,
    /// Multiplication sessions minted under this batch, for cleanup.
    child_sessions: Vec<SessionId>,
}

impl Default for DealStore {
    fn default() -> Self {
        let (done_tx, done_rx) = oneshot::channel();
        Self {
            count: None,
            bits: HashMap::new(),
            deals: HashMap::new(),
            echoes: HashMap::new(),
            echo_sent: false,
            echo_ok: HashSet::new(),
            finished: false,
            done_tx: Some(done_tx),
            done_rx: Some(done_rx),
            child_sessions: Vec::new(),
        }
    }
}

impl DealStore {
    fn finish(&mut self, outcome: Result<(), DaBitError>) {
        self.finished = true;
        if let Some(tx) = self.done_tx.take() {
            let _ = tx.send(outcome);
        }
    }
}

/// Generates daBits. Tags: [`ProtocolType::DaBit`] for the dealing and echo messages,
/// [`ProtocolType::DaBitMul`] for the `F`-side XOR fold's degree-`2t` openings.
#[derive(Clone, Debug)]
pub struct ReplicatedDaBitNode<F: PrimeField, K: BinaryField> {
    pub id: PartyId,
    pub n_parties: usize,
    pub threshold: usize,
    sets: Arc<SetTable<F, K>>,
    pub store: Arc<Mutex<SessionStore<SessionId, (usize, Instant, Arc<Mutex<DealStore>>)>>>,
    /// Degree-reduction multiplication for the XOR fold. **Preprocessing only.**
    pub dn07: Dn07MulNode<F>,
}

impl<F: PrimeField, K: BinaryField> ReplicatedDaBitNode<F, K> {
    pub fn new(id: PartyId, n_parties: usize, threshold: usize) -> Result<Self, DaBitError> {
        let sets = SetTable::new(id, n_parties, threshold)?;
        Ok(Self {
            id,
            n_parties,
            threshold,
            sets: Arc::new(sets),
            store: Arc::new(Mutex::new(SessionStore::with_default_cap())),
            dn07: Dn07MulNode::new(id, n_parties, threshold)?,
        })
    }

    /// Double sharings one daBit consumes.
    pub fn doubles_per_dabit(&self) -> usize {
        self.sets.len().saturating_sub(1)
    }

    /// Largest batch one session may produce: bounded by [`MAX_DABIT_BATCH`] and by keeping every
    /// `Deal`/`Echo` message's packed bits under [`MAX_DEAL_MESSAGE_BYTES`].
    pub fn max_batch_size(&self) -> usize {
        let sets = self.sets.len().max(1);
        (MAX_DEAL_MESSAGE_BYTES * 8 / sets).clamp(1, MAX_DABIT_BATCH)
    }

    pub async fn store_len(&self) -> usize {
        self.store.lock().await.len()
    }

    async fn get_or_create_store(
        &self,
        session_id: SessionId,
        initiator_id: usize,
    ) -> Admission<Arc<Mutex<DealStore>>> {
        self.store.lock().await.get_or_admit(
            session_id,
            initiator_id,
            MAX_DABIT_GEN_SESSIONS,
            (MAX_DABIT_GEN_SESSIONS / self.n_parties).max(1),
            || Arc::new(Mutex::new(DealStore::default())),
        )
    }

    /// Retires a session and every multiplication session minted under it. Idempotent.
    pub async fn clear_store(&self, session_id: SessionId) -> bool {
        let children = {
            let store = self.store.lock().await;
            match store.get(&session_id) {
                Some((_, _, arc)) => arc.lock().await.child_sessions.clone(),
                None => Vec::new(),
            }
        };
        for child in children {
            self.dn07.clear_store(child).await;
        }
        self.store.lock().await.retire(session_id)
    }

    /// Drains completed XOR-fold openings. Call after feeding a `BatchRecon` message tagged
    /// [`ProtocolType::DaBitMul`] to `self.dn07.batch_recon`.
    pub async fn drain_mul_output(&mut self) -> Result<(), DaBitError> {
        Ok(self.dn07.drain_batch_recon_output().await?)
    }

    fn check_session(session_id: SessionId) -> Result<(), DaBitError> {
        if session_id.calling_protocol() != Some(ProtocolType::DaBit)
            || session_id.sub_id() != 0
            || session_id.round_id() != 0
        {
            return Err(DaBitError::SessionIdError(session_id));
        }
        Ok(())
    }

    fn encode(&self, ranks: &[usize], bits: &HashMap<usize, Vec<u8>>) -> Vec<(u32, Vec<u8>)> {
        ranks
            .iter()
            .filter_map(|r| bits.get(r).map(|b| (*r as u32, b.clone())))
            .collect()
    }

    async fn send<N: Network + Send + Sync + 'static>(
        &self,
        to: PartyId,
        session_id: SessionId,
        payload: DaBitPayload,
        network: &Arc<N>,
    ) -> Result<(), DaBitError> {
        let msg = WrappedMessage::DaBit(DaBitMessage::new(self.id, session_id, payload));
        network.send(to, &bincode::serialize(&msg)?).await?;
        Ok(())
    }

    /// Handles a `Deal` or `Echo`. The caller has already bound `msg.sender_id` to the
    /// authenticated network sender.
    ///
    /// An invalid message fails the *session* — abort is permitted in preprocessing, and a peer
    /// that sends a malformed dealing could equally have sent nothing — but never the node.
    pub async fn process<N: Network + Send + Sync + 'static>(
        &mut self,
        msg: DaBitMessage,
        network: Arc<N>,
    ) -> Result<(), DaBitError> {
        Self::check_session(msg.session_id)?;
        if msg.sender_id >= self.n_parties || msg.sender_id == self.id {
            return Err(DaBitError::InvalidPartyId);
        }
        if msg.payload.byte_len() > MAX_DEAL_MESSAGE_BYTES {
            return Err(DaBitError::InvalidDealing("oversized payload".into()));
        }
        let store = match self
            .get_or_create_store(msg.session_id, msg.sender_id)
            .await
        {
            Admission::Got(arc) => arc,
            // A retired session's stragglers, or a peer over its quota: dropped.
            Admission::Retired | Admission::Rejected => return Ok(()),
        };
        {
            let mut s = store.lock().await;
            if s.finished {
                return Ok(());
            }
            let slot = match msg.payload {
                DaBitPayload::Deal { count, sets } => s.deals.insert(msg.sender_id, (count, sets)),
                DaBitPayload::Echo { count, sets } => s.echoes.insert(msg.sender_id, (count, sets)),
            };
            if slot.is_some() {
                s.finish(Err(DaBitError::InvalidDealing(format!(
                    "party {} sent the same dealing message twice",
                    msg.sender_id
                ))));
                return Ok(());
            }
        }
        self.advance(msg.session_id, &store, &network).await
    }

    /// Moves a session as far as the messages received so far allow.
    async fn advance<N: Network + Send + Sync + 'static>(
        &self,
        session_id: SessionId,
        store: &Arc<Mutex<DealStore>>,
        network: &Arc<N>,
    ) -> Result<(), DaBitError> {
        let mut echo_out: Vec<(PartyId, Vec<(u32, Vec<u8>)>)> = Vec::new();
        let count_on_wire: u32;
        {
            let mut s = store.lock().await;
            let count = match s.count {
                Some(count) if !s.finished => count,
                _ => return Ok(()),
            };
            count_on_wire = count as u32;

            // Deals: each set's bits are accepted from that set's dealer only, exactly once.
            let deals: Vec<(PartyId, (u32, Vec<(u32, Vec<u8>)>))> = s.deals.drain().collect();
            for (sender, (their_count, sets)) in deals {
                if their_count as usize != count {
                    s.finish(Err(DaBitError::InvalidDealing(format!(
                        "party {sender} is dealing a batch of {their_count}, this party {count}"
                    ))));
                    return Ok(());
                }
                for (rank, packed) in sets {
                    let rank = rank as usize;
                    let valid = self
                        .sets
                        .entries
                        .get(rank)
                        .is_some_and(|e| e.dealer == sender && e.member)
                        && is_canonical(&packed, count)
                        && !s.bits.contains_key(&rank);
                    if !valid {
                        s.finish(Err(DaBitError::InvalidDealing(format!(
                            "party {sender} dealt an invalid entry for set {rank}"
                        ))));
                        return Ok(());
                    }
                    s.bits.insert(rank, packed);
                }
            }

            let have_all = self
                .sets
                .member_ranks()
                .iter()
                .all(|r| s.bits.contains_key(r));
            if !have_all {
                return Ok(());
            }

            if !s.echo_sent {
                s.echo_sent = true;
                for other in (0..self.n_parties).filter(|p| *p != self.id) {
                    echo_out.push((other, self.encode(&self.sets.shared_ranks(other), &s.bits)));
                }
            }

            // Echoes: a co-holder must report exactly what this party holds, set for set. A
            // mismatch fails the session but does not return early: this party's own echoes,
            // queued above, still go out, so the other holders learn of the disagreement from a
            // message rather than from a timeout.
            let echoes: Vec<(PartyId, (u32, Vec<(u32, Vec<u8>)>))> = s.echoes.drain().collect();
            let mut mismatch = None;
            for (sender, (their_count, sets)) in echoes {
                let expected = self.encode(&self.sets.shared_ranks(sender), &s.bits);
                if their_count as usize != count || sets != expected {
                    mismatch.get_or_insert(sender);
                } else {
                    s.echo_ok.insert(sender);
                }
            }

            if let Some(with) = mismatch {
                s.finish(Err(DaBitError::DealingMismatch { with }));
            } else if s.echo_ok.len() == self.n_parties - 1 {
                s.finish(Ok(()));
            }
        }

        for (other, sets) in echo_out {
            let payload = DaBitPayload::Echo {
                count: count_on_wire,
                sets,
            };
            self.send(other, session_id, payload, network).await?;
        }
        Ok(())
    }

    /// Produces `count` daBits under `session_id`.
    ///
    /// `doubles` must hold exactly `count * doubles_per_dabit()` dealt double sharings. This is a
    /// **driver**: it awaits its own child sessions, so it must not be polled on the task that
    /// pumps the network.
    ///
    /// The session and every child are retired on every exit path.
    pub async fn generate<N>(
        &mut self,
        session_id: SessionId,
        count: usize,
        doubles: Vec<DoubleShamirShare<F>>,
        duration: Duration,
        network: Arc<N>,
    ) -> Result<Vec<DaBit<F, K>>, DaBitError>
    where
        N: Network + Send + Sync + 'static,
    {
        Self::check_session(session_id)?;
        if count == 0 {
            return Err(DaBitError::NotEnoughMaterial("dabit batch"));
        }
        if count > self.max_batch_size() {
            return Err(DaBitError::BatchTooLarge {
                requested: count,
                max: self.max_batch_size(),
            });
        }
        let expected = count
            .checked_mul(self.doubles_per_dabit())
            .ok_or(DaBitError::LimitError)?;
        // Exact, never `>=`: a surplus double sharing dropped here is one the caller believes is
        // unused, and a double sharing spent twice reveals the difference of two products.
        if doubles.len() != expected {
            return Err(DaBitError::MaterialLengthMismatch {
                what: "dabit double sharings",
                expected,
                got: doubles.len(),
            });
        }

        let store = match self.get_or_create_store(session_id, self.id).await {
            Admission::Got(arc) => arc,
            Admission::Retired | Admission::Rejected => return Err(DaBitError::LimitError),
        };
        let result = self
            .run(session_id, count, &doubles, &store, duration, &network)
            .await;
        if !self.clear_store(session_id).await {
            warn!(?session_id, "failed to clear daBit generation state");
        }
        result
    }

    async fn run<N: Network + Send + Sync + 'static>(
        &mut self,
        session_id: SessionId,
        count: usize,
        doubles: &[DoubleShamirShare<F>],
        store: &Arc<Mutex<DealStore>>,
        duration: Duration,
        network: &Arc<N>,
    ) -> Result<Vec<DaBit<F, K>>, DaBitError> {
        // Deal. Fresh operating-system randomness, sampled here and nowhere else.
        let done_rx = {
            let mut s = store.lock().await;
            if s.count.is_some() {
                return Err(DaBitError::SessionIdError(session_id));
            }
            s.count = Some(count);
            for (rank, entry) in self.sets.entries.iter().enumerate() {
                if entry.dealer == self.id {
                    s.bits.insert(rank, sample_bits(count));
                }
            }
            s.done_rx
                .take()
                .ok_or(DaBitError::ResultAlreadyReceived(session_id))?
        };
        for other in (0..self.n_parties).filter(|p| *p != self.id) {
            let ranks = self.sets.deal_ranks(other);
            if ranks.is_empty() {
                continue;
            }
            let sets = {
                let s = store.lock().await;
                self.encode(&ranks, &s.bits)
            };
            let payload = DaBitPayload::Deal {
                count: count as u32,
                sets,
            };
            self.send(other, session_id, payload, network).await?;
        }
        self.advance(session_id, store, network).await?;

        match timeout(duration, done_rx).await {
            Ok(Ok(outcome)) => outcome?,
            Ok(Err(_)) => return Err(DaBitError::ReceiveError(session_id)),
            Err(_) => return Err(DaBitError::Timeout(session_id)),
        }

        let bits = store.lock().await.bits.clone();

        // K side: free.
        let bin: Vec<GfShare<K>> = (0..count)
            .map(|j| GfShare::new(self.sets.bin_share(&bits, j), self.id, self.threshold))
            .collect();

        // F side: XOR-fold the per-set sharings, one multiplication wave per tree level.
        let mut level: Vec<Vec<F>> = (0..count)
            .map(|j| self.sets.arith_leaves(&bits, j))
            .collect();
        let mut width = self.sets.len();
        let mut spent = 0usize;
        let mut wave = 0u64;
        let two = F::from(2u64);
        while width > 1 {
            let pairs = width / 2;
            let mut x = Vec::with_capacity(count * pairs);
            let mut y = Vec::with_capacity(count * pairs);
            for row in &level {
                for p in 0..pairs {
                    x.push(RobustShare::new(row[2 * p], self.id, self.threshold));
                    y.push(RobustShare::new(row[2 * p + 1], self.id, self.threshold));
                }
            }
            let need = count * pairs;
            let slice =
                doubles
                    .get(spent..spent + need)
                    .ok_or(DaBitError::MaterialLengthMismatch {
                        what: "dabit double sharings",
                        expected: spent + need,
                        got: doubles.len(),
                    })?;
            spent += need;
            let products = self
                .mul_f(
                    session_id, &mut wave, &x, &y, slice, store, duration, network,
                )
                .await?;
            if products.len() != need {
                return Err(DaBitError::MaterialLengthMismatch {
                    what: "dabit XOR-fold products",
                    expected: need,
                    got: products.len(),
                });
            }
            for (j, row) in level.iter_mut().enumerate() {
                let mut next = Vec::with_capacity(pairs + width % 2);
                for p in 0..pairs {
                    let xy = products[j * pairs + p].share[0];
                    next.push(row[2 * p] + row[2 * p + 1] - two * xy);
                }
                if width % 2 == 1 {
                    next.push(row[width - 1]);
                }
                *row = next;
            }
            width = pairs + width % 2;
        }

        let mut dabits = Vec::with_capacity(count);
        for (row, bin) in level.into_iter().zip(bin) {
            let value = row
                .first()
                .copied()
                .ok_or(DaBitError::NotEnoughMaterial("dabit XOR fold"))?;
            let arith = RobustShare::new(value, self.id, self.threshold);
            dabits.push(DaBit::new(arith, bin, self.threshold)?);
        }
        Ok(dabits)
    }

    /// One wave of degree-reduction multiplications, chunked against the node's session limits.
    #[allow(clippy::too_many_arguments)]
    async fn mul_f<N: Network + Send + Sync + 'static>(
        &mut self,
        parent: SessionId,
        wave: &mut u64,
        x: &[RobustShare<F>],
        y: &[RobustShare<F>],
        doubles: &[DoubleShamirShare<F>],
        store: &Arc<Mutex<DealStore>>,
        duration: Duration,
        network: &Arc<N>,
    ) -> Result<Vec<RobustShare<F>>, DaBitError> {
        let base = parent
            .exec_id()
            .checked_mul(DABIT_CHILD_STRIDE)
            .ok_or(DaBitError::LimitError)?;
        let per_session = max_mul_pairs_per_session(self.threshold)
            .min(self.dn07.max_batch_size())
            .max(1);
        let depth = conv_pipeline_depth(self.n_parties)
            .min((MAX_DN07_SESSIONS / self.n_parties.max(1)).max(1));

        let mut result = Vec::with_capacity(x.len());
        let mut offset = 0usize;
        while offset < x.len() {
            let wave_end = (offset + per_session * depth).min(x.len());
            let mut first_err: Option<DaBitError> = None;
            let mut issued = Vec::new();

            let mut cursor = offset;
            while cursor < wave_end {
                let end = (cursor + per_session).min(wave_end);
                if *wave >= DABIT_CHILD_STRIDE {
                    return Err(DaBitError::LimitError);
                }
                let exec = base.checked_add(*wave).ok_or(DaBitError::LimitError)?;
                *wave += 1;
                let child = SessionId::new(
                    ProtocolType::DaBitMul,
                    SessionId::pack_slot(exec, 0, 0),
                    parent.instance_id(),
                );
                store.lock().await.child_sessions.push(child);
                let outcome = match PreprocessingSessionId::new(child) {
                    Ok(pre_sid) => {
                        self.dn07
                            .init_mul(
                                pre_sid,
                                x[cursor..end].to_vec(),
                                y[cursor..end].to_vec(),
                                doubles[cursor..end].to_vec(),
                                Arc::clone(network),
                            )
                            .await
                    }
                    Err(e) => Err(e),
                };
                match outcome {
                    Ok(()) => issued.push(child),
                    Err(e) if first_err.is_none() => first_err = Some(e.into()),
                    Err(_) => {}
                }
                cursor = end;
            }

            for child in issued {
                match self.dn07.wait_for_products(child, duration).await {
                    Ok(mut chunk) => result.append(&mut chunk),
                    Err(e) if first_err.is_none() => first_err = Some(e.into()),
                    Err(_) => {}
                }
                if !self.dn07.clear_store(child).await {
                    warn!(
                        ?child,
                        "failed to clear daBit XOR-fold multiplication state"
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
    use crate::common::SecretSharingScheme;
    use ark_bls12_381::Fr as Fq;
    use ark_ff::{One, Zero};

    fn tables(n: usize, t: usize) -> Vec<SetTable<Fq, Gf256>> {
        (0..n).map(|i| SetTable::new(i, n, t).unwrap()).collect()
    }

    /// Deals every set's bits the way the protocol does, without a network.
    fn deal(n: usize, t: usize, count: usize) -> (Vec<Vec<u8>>, Vec<HashMap<usize, Vec<u8>>>) {
        let tsets = all_tsets(n, t);
        let all: Vec<Vec<u8>> = tsets.iter().map(|_| sample_bits(count)).collect();
        let held = (0..n)
            .map(|i| {
                tsets
                    .iter()
                    .enumerate()
                    .filter(|(_, tset)| !tset.contains(&i))
                    .map(|(rank, _)| (rank, all[rank].clone()))
                    .collect()
            })
            .collect();
        (all, held)
    }

    #[test]
    fn the_dealer_is_the_lowest_party_outside_the_set() {
        for (n, t) in [(4, 1), (7, 2)] {
            let table = &tables(n, t)[0];
            for entry in &table.entries {
                assert!(!entry.tset.contains(&entry.dealer));
                assert!((0..entry.dealer).all(|j| entry.tset.contains(&j)));
            }
        }
    }

    #[test]
    fn a_party_inside_the_set_has_a_zero_coefficient_in_both_fields() {
        for (n, t) in [(4, 1), (7, 2)] {
            for table in tables(n, t) {
                for entry in &table.entries {
                    assert_eq!(entry.member, !entry.coeff_f.is_zero());
                    assert_eq!(entry.member, !entry.coeff_k.is_zero());
                }
            }
        }
    }

    /// The whole algebra: the `K` half reconstructs to the XOR of the set bits at degree `t`, and
    /// each `F` leaf reconstructs to its own set's bit at degree `t`.
    #[test]
    fn both_halves_are_degree_t_sharings_of_the_dealt_bits() {
        for (n, t) in [(4, 1), (7, 2), (10, 3)] {
            let count = 13;
            let tabs = tables(n, t);
            let (all, held) = deal(n, t, count);
            for j in 0..count {
                let xor = all.iter().fold(false, |acc, b| acc ^ bit_at(b, j));

                let bin: Vec<GfShare<Gf256>> = (0..n)
                    .map(|i| GfShare::new(tabs[i].bin_share(&held[i], j), i, t))
                    .collect();
                let (coeffs, secret) = GfShare::recover_secret(&bin, n, t).unwrap();
                assert!(coeffs.len() <= t + 1);
                let want = if xor { Gf256::one() } else { Gf256::zero() };
                assert_eq!(secret, want, "K half at n={n} index {j}");

                let leaves: Vec<Vec<Fq>> =
                    (0..n).map(|i| tabs[i].arith_leaves(&held[i], j)).collect();
                for rank in 0..tabs[0].len() {
                    let shares: Vec<RobustShare<Fq>> = (0..n)
                        .map(|i| RobustShare::new(leaves[i][rank], i, t))
                        .collect();
                    let (coeffs, secret) = RobustShare::recover_secret(&shares, n, t).unwrap();
                    assert!(coeffs.len() <= t + 1);
                    let want = if bit_at(&all[rank], j) {
                        Fq::one()
                    } else {
                        Fq::zero()
                    };
                    assert_eq!(secret, want, "F leaf {rank} at n={n} index {j}");
                }
            }
        }
    }

    #[test]
    fn deal_and_echo_cover_exactly_the_sets_both_parties_hold() {
        let (n, t) = (7, 2);
        let tabs = tables(n, t);
        for i in 0..n {
            for k in (0..n).filter(|k| *k != i) {
                assert_eq!(tabs[i].shared_ranks(k), tabs[k].shared_ranks(i));
                assert!(!tabs[i].shared_ranks(k).is_empty());
                for rank in tabs[i].deal_ranks(k) {
                    assert_eq!(tabs[k].entries[rank].dealer, i);
                    assert!(tabs[k].entries[rank].member);
                }
            }
        }
        // Every set is dealt by exactly one party to every other holder.
        for rank in 0..tabs[0].len() {
            let dealer = tabs[0].entries[rank].dealer;
            for k in (0..n).filter(|k| *k != dealer) {
                assert_eq!(
                    tabs[dealer].deal_ranks(k).contains(&rank),
                    tabs[k].entries[rank].member
                );
            }
        }
    }

    #[test]
    fn packing_is_canonical_and_rejects_dirty_padding() {
        for count in [1, 7, 8, 9, 64, 65] {
            let packed = sample_bits(count);
            assert!(is_canonical(&packed, count));
        }
        assert!(!is_canonical(&[0b1000_0000], 7));
        assert!(!is_canonical(&[0, 0], 8));
        assert!(is_canonical(&[0xFF], 8));
    }

    #[test]
    fn the_batch_bound_keeps_a_message_under_the_byte_limit() {
        for (n, t) in [(4, 1), (7, 2), (10, 3), (13, 4)] {
            let node = ReplicatedDaBitNode::<Fq, Gf256>::new(0, n, t).unwrap();
            let max = node.max_batch_size();
            assert!(max >= 1);
            assert!(node.sets.len() * packed_len(max) <= MAX_DEAL_MESSAGE_BYTES + node.sets.len());
            assert_eq!(node.doubles_per_dabit(), doubles_per_dabit(n, t).unwrap());
        }
    }

    #[test]
    fn degenerate_parameters_are_refused() {
        assert!(SetTable::<Fq, Gf256>::new(4, 4, 1).is_err());
        assert!(SetTable::<Fq, Gf256>::new(0, 4, 0).is_err());
        assert!(SetTable::<Fq, Gf256>::new(0, 6, 2).is_err());
    }
}
