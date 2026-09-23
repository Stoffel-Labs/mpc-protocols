//! The B2A node. See the [module header](super) for the protocol, the privacy argument and why
//! the width bound is a hard error.

use std::collections::{HashMap, VecDeque};
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Instant;

use ark_ff::PrimeField;
use bincode::Options;
use serde::de::DeserializeOwned;
use stoffelnet::network_utils::{Network, PartyId};
use tokio::sync::{mpsc::Receiver, oneshot, Mutex};
use tokio::time::{timeout, Duration};
use tracing::{info, warn};

use crate::common::convert::{binary_to_bit, field_bit_width};
use crate::common::session_store::{Admission, SessionStore};
use crate::common::ProtocolSessionId;
use crate::{
    common::{
        gf2k::{field::BinaryField, share::GfShare},
        share::ShareError,
    },
    honeybadger::{
        b2a::{B2AError, B2AState, B2AStore},
        dabit::{conv_pipeline_depth, DaBit},
        gf_batch_recon::gf_batch_recon::GfBatchReconNode,
        gf_triple_gen::GfBeaverTriple,
        max_mul_pairs_per_session,
        robust_interpolate::robust_interpolate::RobustShare,
        ProtocolType, SessionId,
    },
};

/// Concurrent B2A sessions admitted node-wide.
///
/// B2A owns no wire messages, so only *this* node can ever admit one of these — the cap bounds
/// a runaway local caller rather than a peer, and a session's own footprint is one result channel
/// plus a list of child ids.
pub const MAX_B2A_SESSIONS: usize = 256;

/// The width bound on **Goldilocks**: `2^63 - 1 < p <= 2^64 - 1`, so at width 64 the
/// recomposition `sum 2^i x_i` wraps mod `p` for the `2^32 - 1` payloads in `[p, 2^64)`.
///
/// The bound actually enforced is [`max_width`], which derives the same figure from `F` itself;
/// this constant is the quotable value for the field this crate ships, and a unit test pins the
/// two together.
pub const MAX_B2A_BITS: usize = 63;

/// Child `GfBatchRecon` session ids are `parent_exec * B2A_CHILD_STRIDE + wave`, which gives every
/// parent session a disjoint block.
///
/// Not `parent_exec + wave`: parent exec ids come from a counter that increments by one, so an
/// additive scheme aliases the *next* conversion's parent onto this one's later waves.
const B2A_CHILD_STRIDE: u64 = 1 << 20;

/// `round_id` of a child opening session.
///
/// B2A's children share their parent's `ProtocolType` — that is what makes them routable, since
/// the dispatcher demuxes `WrappedMessage::GfBatchRecon` on `calling_protocol()` alone — so the
/// stride above is not by itself enough to keep a child id off some *other* parent's id. The
/// round field separates the two spaces outright: parents are required to be `round_id == 0`,
/// children are always `round_id == 1`.
const B2A_OPEN_ROUND: u8 = 1;

/// Opened payloads that arrived for a session nobody has registered for yet. Bounded because a
/// quorum can complete this node's reconstruction before the local opener registers.
const MAX_PARKED_OPEN_PAYLOADS: usize = 64;

/// Largest width this node will convert over `F`: the largest `w` with `2^w - 1 < p` for every
/// input, i.e. `field_bit_width::<F>() - 1`.
///
/// `field_bit_width` is `F::MODULUS_BIT_SIZE`, so `2^(w) <= p` by definition of the bit size and
/// `2^w - 1 < p` holds for every prime field, not just Goldilocks. On Goldilocks it is
/// [`MAX_B2A_BITS`].
pub fn max_width<F: PrimeField>() -> usize {
    field_bit_width::<F>().saturating_sub(1)
}

/// Values opened in one batch-reconstruction session, matching the multiplication track's
/// per-session pair count: both produce one field element per slot in a single eval/reveal message
/// pair, so the same figure keeps both well inside `MAX_MESSAGE_SIZE`.
fn max_values_per_open(threshold: usize) -> usize {
    max_mul_pairs_per_session(threshold)
}

/// Deserializes `bytes` bounded by their own byte length. `with_fixint_encoding` is required, not
/// optional: `bincode::serialize` encodes length prefixes as fixints while `DefaultOptions`
/// defaults to varint, and the two are not wire-compatible.
fn deser_bounded<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, B2AError> {
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(bytes.len() as u64)
        .deserialize(bytes)?)
}

/// Routes a completed batch-reconstruction payload back to the opener that asked for it.
///
/// Only this node's own openers ever `register`, so the waiter map cannot be grown by a peer. The
/// parked queue exists because a quorum can complete this node's reconstruction *before* the local
/// opener registers, and it is a bounded ring for exactly that reason.
///
/// Structurally identical to the registry inside `dabit::edabit`, which is private to that module;
/// the duplication is deliberate rather than a shared helper, because the two nodes are separate
/// ports and sharing it would couple their session-id disciplines.
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

/// What separates the three public entry points: whether the input bits are certified, and how
/// wide a value they are allowed to encode.
///
/// Kept as one value rather than two parameters so the single shared driver stays readable — and
/// so a future variant adds a field here instead of another positional `usize` a call site can
/// transpose.
struct ConversionPlan<K: BinaryField> {
    /// `Some` for [`B2ANode::b2a_checked`]: one GF Beaver triple per input bit.
    gf_triples: Option<Vec<GfBeaverTriple<K>>>,
    /// Largest per-value width accepted. [`max_width`] everywhere except
    /// [`B2ANode::b2a_full_width_unchecked`].
    width_bound: usize,
}

/// Node implementing binary-to-arithmetic conversion.
///
/// # One tag, one child (C17)
///
/// The node owns a single child protocol — `gf_open`, a degree-`t` [`GfBatchReconNode`] — and a
/// single [`ProtocolType::B2A`] tag. It deliberately does **not** own a `GfMultiply<K>`: a
/// `GfMultiply` mints its own batch-reconstruction children with the *parent's* tag, so under one
/// tag its children would be indistinguishable from `gf_open`'s and the dispatcher, which demuxes
/// on `calling_protocol()` alone, could not route them. The checked variant's one AND layer is
/// therefore driven as a Beaver multiplication straight over `gf_open` — which is all
/// `GfMultiply` does internally anyway — keeping both variants on exactly one tag and one wire
/// message type.
///
/// # Local-only rounds (C4)
///
/// None. Every value consumed is either a caller-supplied share whose index and degree this node
/// re-checks, or a degree-`t` robust reconstruction it performed itself.
#[derive(Clone, Debug)]
pub struct B2ANode<F: PrimeField, K: BinaryField> {
    pub id: PartyId,
    pub n_parties: usize,
    pub threshold: usize,
    pub store: Arc<Mutex<SessionStore<SessionId, (usize, Instant, Arc<Mutex<B2AStore<F>>>)>>>,
    /// Degree-`t` `K`-side openings. Tag: [`ProtocolType::B2A`].
    pub gf_open: GfBatchReconNode<K>,
    pub gf_open_output: Arc<Mutex<Receiver<SessionId>>>,
    gf_open_registry: Arc<Mutex<OpenRegistry>>,
    _f: PhantomData<fn() -> F>,
}

impl<F, K> B2ANode<F, K>
where
    F: PrimeField,
    K: BinaryField,
{
    pub fn new(id: PartyId, n_parties: usize, threshold: usize) -> Result<Self, B2AError> {
        if id >= n_parties {
            return Err(B2AError::InvalidPartyId);
        }
        // C5: the binary domain has only `K::MAX_DOMAIN_SIZE` distinct evaluation points, so a
        // party count above it cannot be shared in `K` at all.
        if n_parties > K::MAX_DOMAIN_SIZE {
            return Err(B2AError::InvalidPartyId);
        }

        let (gf_open_sender, gf_open_receiver) = tokio::sync::mpsc::channel(200);
        // degree = t, NOT 2t: degree-`2t` robust reconstruction in this repo needs `degree+t+1`
        // agreeing evaluations, which at `n = 3t+1` is every single party — zero fault tolerance.
        let gf_open =
            GfBatchReconNode::<K>::new(id, n_parties, threshold, threshold, gf_open_sender)?;

        Ok(Self {
            id,
            n_parties,
            threshold,
            store: Arc::new(Mutex::new(SessionStore::with_default_cap())),
            gf_open,
            gf_open_output: Arc::new(Mutex::new(gf_open_receiver)),
            gf_open_registry: Arc::new(Mutex::new(OpenRegistry::default())),
            _f: PhantomData,
        })
    }

    /// GF(2^k) Beaver triples [`B2ANode::b2a_checked`] consumes for `total_bits` input bits: one
    /// per bit. [`B2ANode::b2a`] consumes none.
    pub fn gf_triples_per_check(total_bits: usize) -> usize {
        total_bits
    }

    pub async fn store_len(&self) -> usize {
        self.store.lock().await.len()
    }

    pub async fn get_or_create_store(
        &self,
        session_id: SessionId,
        initiator_id: usize,
    ) -> Admission<Arc<Mutex<B2AStore<F>>>> {
        self.store.lock().await.get_or_admit(
            session_id,
            initiator_id,
            MAX_B2A_SESSIONS,
            // `.max(1)`: with `n > MAX_B2A_SESSIONS` the integer quotient is zero, which would
            // reject every session including this node's own.
            (MAX_B2A_SESSIONS / self.n_parties.max(1)).max(1),
            || Arc::new(Mutex::new(B2AStore::empty())),
        )
    }

    /// Retires the **exact** child session ids this conversion recorded, then the parent entry.
    /// Never re-derives ids: a re-derivation drifts the moment a chunk count changes, leaving
    /// orphaned child sessions squatting on the batch-reconstruction cap (C7).
    pub async fn clear_store(&self, session_id: SessionId) -> bool {
        let children = {
            let store = self.store.lock().await;
            match store.get(&session_id) {
                Some((_, _, arc)) => arc.lock().await.child_sessions.clone(),
                None => Vec::new(),
            }
        };
        for child in children {
            self.gf_open.clear_store(child).await;
            self.gf_open_registry.lock().await.cancel(child);
        }
        let mut store = self.store.lock().await;
        store.retire(session_id)
    }

    /// Routes completed `K`-side openings back to the opener waiting on them.
    ///
    /// Must be called immediately after every `gf_open.process(..)` in the node dispatcher (C10):
    /// the opening driver is parked on the registry, and nothing else moves a finished
    /// reconstruction out of the batch-recon store.
    pub async fn drain_gf_open_output(&mut self) -> Result<(), B2AError> {
        loop {
            let id = {
                let mut rx = self.gf_open_output.lock().await;
                match rx.try_recv() {
                    Ok(id) => id,
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        return Err(B2AError::Abort);
                    }
                }
            };
            match self.gf_open.get_store(id).await {
                Ok(bytes) => self.gf_open_registry.lock().await.deliver(id, bytes),
                Err(e) => {
                    warn!(?id, ?e, "ignoring stale B2A opening output");
                }
            }
        }
        Ok(())
    }

    pub async fn wait_for_result(
        &self,
        session_id: SessionId,
        duration: Duration,
    ) -> Result<Vec<RobustShare<F>>, B2AError> {
        let output_receiver = {
            let storage = self.store.lock().await;
            let storage_bind = match storage.get(&session_id) {
                Some((_, _, arc)) => arc,
                None => return Err(B2AError::NoSuchSessionId(session_id)),
            };
            let mut storage = storage_bind.lock().await;
            storage
                .output_receiver
                .take()
                .ok_or(B2AError::ResultAlreadyReceived(session_id))?
        };

        match timeout(duration, output_receiver).await {
            Err(_) => Err(B2AError::Timeout(session_id)),
            Ok(Err(_)) => Err(B2AError::ReceiveError(session_id)),
            Ok(Ok(shares)) => Ok(shares),
        }
    }
}

// -------------------------------------------------------------------------------------------
// The protocol
// -------------------------------------------------------------------------------------------

impl<F, K> B2ANode<F, K>
where
    F: PrimeField,
    K: BinaryField,
{
    /// Converts binary sharings to arithmetic ones. **One GF opening, zero multiplications.**
    ///
    /// `bits[v]` holds the LSB-first degree-`t` binary sharings of value `v`; widths may differ
    /// between values. `dabits` supplies one daBit per bit, in the same order, flattened
    /// (`bits[0]`'s bits first, then `bits[1]`'s, ...). Every daBit is consumed exactly once.
    ///
    /// # Precondition (the "unchecked" in the name)
    ///
    /// The caller guarantees each `bits[v][i]` shares a value in `{0, 1}`. `GfShare` carries no
    /// bit-ness guarantee, and a non-bit input yields a wrong — not merely unverified —
    /// arithmetic result. This variant does *detect* the violation in practice, because the opened
    /// `c_i = x_i XOR r_i` then falls outside `GF(2)` and it returns
    /// [`B2AError::NonBooleanInput`]; but that detection leans on the daBit's binary half being a
    /// genuine bit, so it is a consequence of well-formed preprocessing rather than a proof about
    /// the input. [`B2ANode::b2a_checked`] proves it about the input directly, unconditionally,
    /// for one extra AND layer.
    ///
    /// This is the default because the bits a mixed circuit converts back normally came out of
    /// A2B, where bit-ness is structural.
    ///
    /// That detection is not quite free of information: for a non-bit `x_i` the opened `c_i`
    /// narrows `x_i` to the coset `{c_i, c_i + 1}`. No one-round protocol can avoid that — the
    /// pad has one bit of entropy — and it only happens on a caller bug that aborts the
    /// conversion anyway. For honest input, `c_i` is exactly uniform on `{0,1}` and perfectly
    /// hiding.
    ///
    /// # Width
    ///
    /// Every `bits[v].len()` must be at most [`max_width::<F>()`](max_width) — 63 on Goldilocks.
    /// Above it the recomposition wraps modulo `p` and returns the wrong value for an
    /// adversarially chosen payload; see [`B2AError::WidthTooLarge`].
    ///
    /// # Driving it
    ///
    /// This is a driver: it awaits its own child openings, so it must not be polled on the task
    /// that pumps the network. Spawn it, then take the result from
    /// [`B2ANode::wait_for_result`] (the result is also delivered there, so a caller may await it
    /// from a different task), and call [`B2ANode::clear_store`] on every exit path.
    pub async fn b2a<N>(
        &mut self,
        session_id: SessionId,
        bits: Vec<Vec<GfShare<K>>>,
        dabits: Vec<DaBit<F, K>>,
        duration: Duration,
        network: Arc<N>,
    ) -> Result<(), B2AError>
    where
        N: Network + Send + Sync + 'static,
    {
        self.run(
            session_id,
            bits,
            dabits,
            ConversionPlan {
                gf_triples: None,
                width_bound: max_width::<F>(),
            },
            duration,
            network,
        )
        .await
    }

    /// [`B2ANode::b2a`] plus one exact-zero AND layer certifying that every input share really is
    /// a bit.
    ///
    /// Costs one GF Beaver triple per bit ([`B2ANode::gf_triples_per_check`]) and one extra
    /// opening round: the Beaver masks `d_i = x_i - a_i` and `e_i = (x_i + 1) - b_i` ride in the
    /// *same* session as the `c_i`, and only the products `z_i = x_i (x_i + 1)` need a second
    /// round. A non-zero `z_i` is a proof that input bit `i` is not in `GF(2)`
    /// ([`B2AError::CertificationFailed`]).
    ///
    /// **Exact zero, never a random linear combination.** `z_i` is identically zero for a valid
    /// bit, so the check has soundness error `0` — batching the `z_i` under a random `GF(2^8)`
    /// coefficient would drop it to `2^-8` — and it names the offending index for free. It is also
    /// leak-free in the passing case: the adversary's `t` evaluations plus the known constant term
    /// `0` already determine the degree-`t` polynomial.
    ///
    /// **`x(x+1)`, never `x^2`.** Over `GF(2^k)` the Frobenius map `x -> x^2` is a *bijection*, so
    /// `x^2` determines `x` exactly — there is not even the sign ambiguity that makes the
    /// `F`-side square trick safe. And the product goes through a degree-`t` Beaver
    /// multiplication rather than a local `share_mul`, because an unrandomised degree-`2t` product
    /// sharing has the squares of `f`'s coefficients and square-rooting them recovers `f` and
    /// hence every party's share.
    pub async fn b2a_checked<N>(
        &mut self,
        session_id: SessionId,
        bits: Vec<Vec<GfShare<K>>>,
        dabits: Vec<DaBit<F, K>>,
        gf_triples: Vec<GfBeaverTriple<K>>,
        duration: Duration,
        network: Arc<N>,
    ) -> Result<(), B2AError>
    where
        N: Network + Send + Sync + 'static,
    {
        self.run(
            session_id,
            bits,
            dabits,
            ConversionPlan {
                gf_triples: Some(gf_triples),
                width_bound: max_width::<F>(),
            },
            duration,
            network,
        )
        .await
    }

    /// [`B2ANode::b2a`] at the **full** `field_bit_width::<F>()` — 64 on Goldilocks.
    ///
    /// # Safety of the arithmetic, which is the caller's to establish
    ///
    /// At full width the recomposition `sum_i 2^i x_i` is faithful only if that integer is less
    /// than `p`; otherwise this silently returns a sharing of `x mod p`. Nothing here can check
    /// it — the bits are secret — so the precondition is the caller's, and the explicit name is
    /// the only thing standing between a caller and a silent wrong answer for the `2^32 - 1`
    /// payloads in `[p, 2^64)`.
    ///
    /// The one caller that can discharge it is an A2B round trip: A2B emits the bits of the
    /// canonical representative in `[0, p)`, so
    /// `b2a_full_width_unchecked(a2b([x])) == [x]` for **every** `x in F`, exactly.
    pub async fn b2a_full_width_unchecked<N>(
        &mut self,
        session_id: SessionId,
        bits: Vec<Vec<GfShare<K>>>,
        dabits: Vec<DaBit<F, K>>,
        duration: Duration,
        network: Arc<N>,
    ) -> Result<(), B2AError>
    where
        N: Network + Send + Sync + 'static,
    {
        self.run(
            session_id,
            bits,
            dabits,
            ConversionPlan {
                gf_triples: None,
                width_bound: field_bit_width::<F>(),
            },
            duration,
            network,
        )
        .await
    }

    async fn run<N>(
        &mut self,
        session_id: SessionId,
        bits: Vec<Vec<GfShare<K>>>,
        dabits: Vec<DaBit<F, K>>,
        plan: ConversionPlan<K>,
        duration: Duration,
        network: Arc<N>,
    ) -> Result<(), B2AError>
    where
        N: Network + Send + Sync + 'static,
    {
        let ConversionPlan {
            gf_triples,
            width_bound,
        } = plan;
        // ---- 0. Session id ------------------------------------------------------------------
        // Parents are `round_id == 0`; children are minted at `B2A_OPEN_ROUND`. Enforcing it here
        // is what keeps the two id spaces disjoint under a shared protocol tag.
        if session_id.calling_protocol() != Some(ProtocolType::B2A)
            || session_id.sub_id() != 0
            || session_id.round_id() != 0
        {
            return Err(B2AError::SessionIdError(session_id));
        }

        // ---- 1. Shape ------------------------------------------------------------------------
        if bits.is_empty() {
            return Err(B2AError::NoValues);
        }
        let mut total = 0usize;
        for (value, value_bits) in bits.iter().enumerate() {
            let width = value_bits.len();
            // C13: an empty bit vector would make this value's recomposition loop vacuous and
            // return a sharing of zero rather than an error.
            if width == 0 {
                return Err(B2AError::ZeroWidth { value });
            }
            // The bound that keeps `sum 2^i x_i` from wrapping mod `p`. A hard error, never an
            // assertion and never a `warn!`: above it the conversion is silently wrong for
            // payloads the adversary chooses.
            if width > width_bound {
                return Err(B2AError::WidthTooLarge {
                    value,
                    width,
                    max: width_bound,
                });
            }
            total = total.checked_add(width).ok_or(B2AError::LimitError)?;
        }

        // C13: exact lengths, never `>=`. A surplus daBit here is a daBit the caller believes is
        // still unused — i.e. one-time-pad reuse on the next conversion.
        if dabits.len() != total {
            return Err(B2AError::MaterialLengthMismatch {
                what: "dabits",
                expected: total,
                got: dabits.len(),
            });
        }
        if let Some(triples) = gf_triples.as_ref() {
            if triples.len() != Self::gf_triples_per_check(total) {
                return Err(B2AError::MaterialLengthMismatch {
                    what: "gf triples",
                    expected: Self::gf_triples_per_check(total),
                    got: triples.len(),
                });
            }
        }

        // ---- 2. Index and degree, in both domains, independently (C5) ------------------------
        // A share carrying another party's index would silently pair this party's `F` half with
        // someone else's `K` half; a wrong degree would make one half undecodable at the degree
        // every opening here uses. The cross-domain correspondence is fixed by position in these
        // vectors and is never read out of a share.
        for value_bits in &bits {
            for share in value_bits {
                self.check_bin_share(share)?;
            }
        }
        for dabit in &dabits {
            self.check_bin_share(&dabit.bin)?;
            self.check_arith_share(&dabit.arith)?;
        }
        if let Some(triples) = gf_triples.as_ref() {
            for triple in triples {
                self.check_bin_share(&triple.a)?;
                self.check_bin_share(&triple.b)?;
                self.check_bin_share(&triple.mult)?;
            }
        }

        // ---- 3. Local state ------------------------------------------------------------------
        let store = match self.get_or_create_store(session_id, self.id).await {
            Admission::Got(arc) => arc,
            // Our own conversion: a silent `Ok(())` would leave the caller waiting forever on a
            // result channel nobody will ever fire.
            Admission::Retired | Admission::Rejected => return Err(B2AError::LimitError),
        };
        {
            let mut guard = store.lock().await;
            if guard.state != B2AState::NotInitialized {
                return Err(B2AError::SessionIdError(session_id));
            }
            guard.state = B2AState::Opening;
        }
        let mut wave = 0u64;

        // ---- 4. Mask the bits, and (checked only) the certification operands ------------------
        // `c_i = x_i XOR r_i` is free: characteristic 2, and `GfShare + GfShare` is share-wise.
        let mut to_open: Vec<GfShare<K>> = Vec::with_capacity(total.saturating_mul(3));
        let mut flat: Vec<&GfShare<K>> = Vec::with_capacity(total);
        for value_bits in &bits {
            for share in value_bits {
                flat.push(share);
            }
        }
        for (index, share) in flat.iter().enumerate() {
            to_open.push(((*share).clone() + dabits[index].bin.clone())?);
        }
        if let Some(triples) = gf_triples.as_ref() {
            // Beaver, done over this node's own opener rather than through a `GfMultiply`, so the
            // whole protocol keeps one tag: `x * y = [ab] + a*e + b*d + d*e` with `d = x - a`,
            // `e = y - b`. Both triple masks are uniform over all of `K`, so `(d, e)` is uniform
            // on `K^2` and independent of `x` — the operands being bits costs nothing here.
            for (index, share) in flat.iter().enumerate() {
                let one_plus_x = ((*share).clone() + K::one())?;
                to_open.push(((*share).clone() - triples[index].a.clone())?);
                to_open.push((one_plus_x - triples[index].b.clone())?);
            }
        }

        // ---- 5. One opening round -------------------------------------------------------------
        let opened = self
            .open_k(&to_open, session_id, &mut wave, &store, duration, &network)
            .await?;
        if opened.len() != to_open.len() {
            return Err(B2AError::MaterialLengthMismatch {
                what: "opened masks",
                expected: to_open.len(),
                got: opened.len(),
            });
        }

        // ---- 6. Certification, when asked for --------------------------------------------------
        if let Some(triples) = gf_triples.as_ref() {
            {
                let mut guard = store.lock().await;
                guard.state = B2AState::Certifying;
            }
            let mut products = Vec::with_capacity(total);
            for (index, triple) in triples.iter().enumerate() {
                let d = opened[total + 2 * index];
                let e = opened[total + 2 * index + 1];
                let ae = (triple.a.clone() * e)?;
                let bd = (triple.b.clone() * d)?;
                // `[ab] + a*e + b*d + d*e`, the last term a public constant. Degree `t`
                // throughout — the Beaver re-randomisation is what makes the opening below safe.
                products.push((((triple.mult.clone() + ae)? + bd)? + (d * e))?);
            }
            let certified = self
                .open_k(&products, session_id, &mut wave, &store, duration, &network)
                .await?;
            if certified.len() != total {
                return Err(B2AError::MaterialLengthMismatch {
                    what: "certification openings",
                    expected: total,
                    got: certified.len(),
                });
            }
            let mut index = 0usize;
            for (value, value_bits) in bits.iter().enumerate() {
                for offset in 0..value_bits.len() {
                    // Exact zero. `x(x+1) = 0` in a field iff `x in {0, 1}`, which is precisely
                    // `BinaryField::is_bit`. Every honest party sees the same opened value, so
                    // this verdict needs no agreement sub-protocol.
                    if !certified[index].is_zero() {
                        return Err(B2AError::CertificationFailed {
                            value,
                            index: offset,
                        });
                    }
                    index += 1;
                }
            }
        }

        // ---- 7. Recompose, entirely locally ----------------------------------------------------
        let two = F::one() + F::one();
        let mut results = Vec::with_capacity(bits.len());
        let mut index = 0usize;
        for (value, value_bits) in bits.iter().enumerate() {
            let mut acc = RobustShare::new(F::zero(), self.id, self.threshold);
            let mut weight = F::one();
            for offset in 0..value_bits.len() {
                // `c_i` was robustly opened, so a non-boolean value is an *agreed* condition and
                // can only mean the caller supplied a non-bit share — a typed error, never a
                // panic and never an adversary-attributable abort.
                let gamma =
                    binary_to_bit::<K>(opened[index]).map_err(|_| B2AError::NonBooleanInput {
                        value,
                        index: offset,
                    })?;
                // `x_i = c_i XOR r_i`: `[r_i]` when the mask opened to 0, `1 - [r_i]` when it
                // opened to 1. `from_scalar_sub` preserves the index and the degree.
                let bit_share = if gamma {
                    RobustShare::from_scalar_sub(F::one(), &dabits[index].arith)
                } else {
                    dabits[index].arith.clone()
                };
                acc = (acc + (bit_share * weight)?)?;
                weight *= two;
                index += 1;
            }
            results.push(acc);
        }

        // ---- 8. Finish --------------------------------------------------------------------------
        let mut guard = store.lock().await;
        guard.state = B2AState::Finished;
        // Taking the sender makes finalisation idempotent by construction (C18).
        if let Some(tx) = guard.output_sender.take() {
            let _ = tx.send(results);
        }
        info!(
            session_id = session_id.as_u128(),
            party = self.id,
            values = bits.len(),
            bits = total,
            "B2A conversion complete"
        );
        Ok(())
    }

    /// Opens `values` at degree `t` and returns the opened scalars in input order.
    ///
    /// Chunked against [`max_values_per_open`] and pipelined at
    /// [`conv_pipeline_depth`](crate::honeybadger::dabit::conv_pipeline_depth), with
    /// each wave awaited and cleared before the next is issued. Those two bounds are what keep a
    /// conversion from exhausting a peer's *per-peer* batch-reconstruction quota — beyond it that
    /// peer's `Eval` messages are rejected and the opening silently never completes — and from
    /// filling the 200-slot channel whose `send().await` runs inline on the single
    /// message-handling path (C11).
    ///
    /// A batch of up to `max_values_per_open(t) * conv_pipeline_depth(n)` values is a single
    /// wave, i.e. the one *opening* B2A advertises — two message rounds, since `GfBatchRecon`
    /// sends evaluations to the kings and reveals back. Larger batches cost one further wave, and
    /// so two further rounds, each.
    async fn open_k<N: Network + Send + Sync + 'static>(
        &mut self,
        values: &[GfShare<K>],
        parent: SessionId,
        wave: &mut u64,
        store: &Arc<Mutex<B2AStore<F>>>,
        duration: Duration,
        network: &Arc<N>,
    ) -> Result<Vec<K>, B2AError> {
        if values.is_empty() {
            return Ok(Vec::new());
        }
        let width = self.threshold + 1;
        let chunks: Vec<&[GfShare<K>]> =
            values.chunks(max_values_per_open(self.threshold)).collect();
        let mut opened = Vec::with_capacity(values.len());

        for group in chunks.chunks(conv_pipeline_depth(self.n_parties)) {
            let mut first_err: Option<B2AError> = None;
            let mut issued = Vec::with_capacity(group.len());

            for chunk in group {
                let session_id = self.child_session_id(parent, *wave)?;
                *wave += 1;
                store.lock().await.child_sessions.push(session_id);
                // `init_batch_reconstruct_many` requires a non-empty multiple of `degree + 1`;
                // pad the tail with a public constant, exactly as `mul_pub` does.
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

            // Every issued session is cleared regardless of outcome: a timed-out session must not
            // be left dangling just because an earlier `?` would have skipped past it (C7).
            for (session_id, rx, real_len) in issued {
                let result = match timeout(duration, rx).await {
                    Ok(Ok(bytes)) => deser_bounded::<Vec<K>>(&bytes),
                    Ok(Err(_)) => Err(B2AError::ReceiveError(session_id)),
                    Err(_) => Err(B2AError::Timeout(session_id)),
                };
                self.gf_open.clear_store(session_id).await;
                self.gf_open_registry.lock().await.cancel(session_id);
                match result {
                    Ok(mut decoded) => {
                        if decoded.len() < real_len {
                            if first_err.is_none() {
                                first_err = Some(B2AError::MaterialLengthMismatch {
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

    /// Child opening session `wave` of `parent`.
    ///
    /// Deterministic and derived only from the parent id and a local counter, never from message
    /// data — the same discipline `dabit::edabit` uses, and the reason the hard `assert_eq!` on
    /// `sub_id`/`round_id` inside the multiplication nodes is unreachable from the network (C12).
    fn child_session_id(&self, parent: SessionId, wave: u64) -> Result<SessionId, B2AError> {
        if wave >= B2A_CHILD_STRIDE {
            return Err(B2AError::LimitError);
        }
        let exec = parent
            .exec_id()
            .checked_mul(B2A_CHILD_STRIDE)
            .and_then(|base| base.checked_add(wave))
            .ok_or(B2AError::LimitError)?;
        Ok(SessionId::new(
            ProtocolType::B2A,
            SessionId::pack_slot(exec, 0, B2A_OPEN_ROUND),
            parent.instance_id(),
        ))
    }

    fn check_bin_share(&self, share: &GfShare<K>) -> Result<(), B2AError> {
        if share.id != self.id {
            return Err(ShareError::IdMismatch.into());
        }
        if share.degree != self.threshold {
            return Err(ShareError::DegreeMismatch.into());
        }
        Ok(())
    }

    fn check_arith_share(&self, share: &RobustShare<F>) -> Result<(), B2AError> {
        if share.id != self.id {
            return Err(ShareError::IdMismatch.into());
        }
        if share.degree != self.threshold {
            return Err(ShareError::DegreeMismatch.into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::convert::{bit_to_binary, bit_to_field};
    use crate::common::gf2k::field::Gf256;
    use crate::common::math::goldilocks::GoldilocksField;
    use crate::common::SecretSharingScheme;
    use crate::honeybadger::WrappedMessage;
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::{Rng, SeedableRng};
    use stoffelmpc_network::fake_network::{FakeInnerNetwork, FakeNetwork, FakeNetworkConfig};

    type F = GoldilocksField;
    type K = Gf256;
    type Node = B2ANode<F, K>;

    fn node(id: usize, n: usize, t: usize) -> Node {
        Node::new(id, n, t).unwrap()
    }

    fn net(n: usize) -> Arc<FakeNetwork> {
        let inner = FakeInnerNetwork::new(n, None, FakeNetworkConfig::new(10)).0;
        Arc::new(FakeNetwork::new(0, inner))
    }

    /// Per-party inboxes, one receiver per sending party.
    type Inboxes = Vec<Vec<tokio::sync::mpsc::Receiver<Vec<u8>>>>;

    /// A network whose inboxes stay alive but are never drained: sends succeed and no peer ever
    /// answers, which is how a test reaches the opening driver's timeout path rather than a
    /// `SendError` from a dropped receiver.
    fn silent_net(n: usize) -> (Arc<FakeNetwork>, Inboxes) {
        let (inner, inboxes, _) = FakeInnerNetwork::new(n, None, FakeNetworkConfig::new(64));
        (Arc::new(FakeNetwork::new(0, inner)), inboxes)
    }

    fn parent(exec: u64) -> SessionId {
        SessionId::new(ProtocolType::B2A, SessionId::pack_slot(exec, 0, 0), 0)
    }

    fn bin(value: u8, id: usize, degree: usize) -> GfShare<K> {
        GfShare::new(Gf256(value), id, degree)
    }

    fn dabit(bit: bool, id: usize, degree: usize) -> DaBit<F, K> {
        DaBit::new(
            RobustShare::new(bit_to_field::<F>(bit), id, degree),
            GfShare::new(bit_to_binary::<K>(bit), id, degree),
            degree,
        )
        .unwrap()
    }

    // -----------------------------------------------------------------------------------------
    // Parameters and ids
    // -----------------------------------------------------------------------------------------

    #[test]
    fn the_width_bound_on_goldilocks_is_63() {
        // `2^63 - 1 < p <= 2^64 - 1`. At 64 the recomposition wraps mod `p` for the `2^32 - 1`
        // payloads in `[p, 2^64)`, and the payload is the adversary's to choose.
        assert_eq!(max_width::<F>(), MAX_B2A_BITS);
        assert_eq!(field_bit_width::<F>(), 64);
        // The bound is derived from `F`, so it stays correct for any prime field: `2^w - 1 < p`
        // where `w = MODULUS_BIT_SIZE - 1`.
        let p: num_bigint::BigUint = F::MODULUS.into();
        let largest =
            (num_bigint::BigUint::from(1u8) << max_width::<F>()) - num_bigint::BigUint::from(1u8);
        assert!(largest < p);
    }

    #[test]
    fn new_rejects_degenerate_parameters() {
        assert!(matches!(Node::new(5, 5, 1), Err(B2AError::InvalidPartyId)));
        // More parties than the binary domain has evaluation points cannot be shared in `K`.
        assert!(matches!(
            Node::new(0, K::MAX_DOMAIN_SIZE + 1, 1),
            Err(B2AError::InvalidPartyId)
        ));
    }

    #[test]
    fn child_ids_are_disjoint_from_every_parent_and_from_each_other() {
        let node = node(0, 4, 1);
        let mut seen = std::collections::HashSet::new();
        for exec in 0..32u64 {
            // Parents live at round 0; children at `B2A_OPEN_ROUND`. Without that separation a
            // child of parent `1` could land exactly on the id of parent `B2A_CHILD_STRIDE`,
            // since both share the `B2A` tag.
            assert!(seen.insert(parent(exec).as_u128()));
        }
        for exec in [0u64, 1, 31, 1 << 20] {
            for wave in 0..32u64 {
                let child = node.child_session_id(parent(exec), wave).unwrap();
                assert_eq!(child.round_id(), B2A_OPEN_ROUND);
                assert_eq!(child.sub_id(), 0);
                assert_eq!(child.calling_protocol(), Some(ProtocolType::B2A));
                assert!(seen.insert(child.as_u128()), "child id collision");
            }
        }
    }

    #[test]
    fn child_id_allocation_refuses_to_wrap() {
        let node = node(0, 4, 1);
        let huge = SessionId::new(ProtocolType::B2A, SessionId::pack_slot(u64::MAX, 0, 0), 0);
        assert!(matches!(
            node.child_session_id(huge, 0),
            Err(B2AError::LimitError)
        ));
        assert!(matches!(
            node.child_session_id(parent(0), B2A_CHILD_STRIDE),
            Err(B2AError::LimitError)
        ));
    }

    // -----------------------------------------------------------------------------------------
    // Input validation — all of it happens before a single byte hits the network
    // -----------------------------------------------------------------------------------------

    #[tokio::test]
    async fn rejects_a_width_above_the_bound_rather_than_wrapping() {
        let mut node = node(0, 4, 1);
        let bits = vec![vec![bin(1, 0, 1); MAX_B2A_BITS + 1]];
        let dabits = vec![dabit(false, 0, 1); MAX_B2A_BITS + 1];
        let err = node
            .b2a(parent(0), bits, dabits, Duration::from_millis(50), net(4))
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            B2AError::WidthTooLarge {
                value: 0,
                width: 64,
                max: 63
            }
        ));
        // Nothing was admitted: the width check runs before any state exists.
        assert_eq!(node.store_len().await, 0);
    }

    #[tokio::test]
    async fn full_width_is_reachable_only_through_the_explicitly_named_entry_point() {
        let mut node = node(0, 4, 1);
        let bits = vec![vec![bin(0, 0, 1); 64]];
        let dabits = vec![dabit(false, 0, 1); 64];
        // Same inputs, different door: `b2a` refuses 64 bits outright...
        assert!(matches!(
            node.b2a(
                parent(0),
                bits.clone(),
                dabits.clone(),
                Duration::from_millis(20),
                net(4)
            )
            .await,
            Err(B2AError::WidthTooLarge { .. })
        ));
        // ...while the opt-in accepts them and gets as far as the network (which no peer is
        // answering here, so it times out rather than being rejected on width).
        let (network, _inboxes) = silent_net(4);
        let err = node
            .b2a_full_width_unchecked(parent(1), bits, dabits, Duration::from_millis(20), network)
            .await
            .unwrap_err();
        assert!(
            matches!(err, B2AError::Timeout(_)),
            "expected a timeout, got {err:?}"
        );
    }

    #[tokio::test]
    async fn rejects_empty_and_zero_width_batches() {
        let mut node = node(0, 4, 1);
        assert!(matches!(
            node.b2a(
                parent(0),
                Vec::new(),
                Vec::new(),
                Duration::from_millis(50),
                net(4)
            )
            .await,
            Err(B2AError::NoValues)
        ));
        // A zero-width value would recompose to a sharing of zero and look like a success.
        assert!(matches!(
            node.b2a(
                parent(1),
                vec![vec![bin(1, 0, 1)], Vec::new()],
                vec![dabit(true, 0, 1)],
                Duration::from_millis(50),
                net(4)
            )
            .await,
            Err(B2AError::ZeroWidth { value: 1 })
        ));
    }

    #[tokio::test]
    async fn rejects_material_lengths_that_are_not_exactly_right() {
        let mut node = node(0, 4, 1);
        // One daBit too many is one daBit the caller still believes is unused — i.e. pad reuse on
        // the next conversion, which turns two openings into `c XOR c' = x XOR x'`.
        let err = node
            .b2a(
                parent(0),
                vec![vec![bin(1, 0, 1); 3]],
                vec![dabit(false, 0, 1); 4],
                Duration::from_millis(50),
                net(4),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            B2AError::MaterialLengthMismatch {
                what: "dabits",
                expected: 3,
                got: 4
            }
        ));

        let err = node
            .b2a_checked(
                parent(1),
                vec![vec![bin(1, 0, 1); 3]],
                vec![dabit(false, 0, 1); 3],
                Vec::new(),
                Duration::from_millis(50),
                net(4),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            B2AError::MaterialLengthMismatch {
                what: "gf triples",
                expected: 3,
                got: 0
            }
        ));
    }

    #[tokio::test]
    async fn rejects_shares_indexed_or_graded_for_someone_else() {
        let mut node = node(0, 4, 1);
        // A share carrying another party's index would pair this party's `F` half with someone
        // else's `K` half; the two domains index unrelated point sets, so only the party index
        // may cross and it must match exactly.
        assert!(matches!(
            node.b2a(
                parent(0),
                vec![vec![bin(1, 2, 1)]],
                vec![dabit(false, 0, 1)],
                Duration::from_millis(50),
                net(4)
            )
            .await,
            Err(B2AError::ShareError(ShareError::IdMismatch))
        ));
        assert!(matches!(
            node.b2a(
                parent(1),
                vec![vec![bin(1, 0, 2)]],
                vec![dabit(false, 0, 1)],
                Duration::from_millis(50),
                net(4)
            )
            .await,
            Err(B2AError::ShareError(ShareError::DegreeMismatch))
        ));
        // The arithmetic half is checked independently of the binary one.
        let mixed = DaBit::new(
            RobustShare::new(F::from(0u64), 3, 1),
            GfShare::new(Gf256(0), 3, 1),
            1,
        )
        .unwrap();
        assert!(matches!(
            node.b2a(
                parent(2),
                vec![vec![bin(1, 0, 1)]],
                vec![mixed],
                Duration::from_millis(50),
                net(4)
            )
            .await,
            Err(B2AError::ShareError(ShareError::IdMismatch))
        ));
    }

    #[tokio::test]
    async fn rejects_a_session_id_that_is_not_a_b2a_parent() {
        let mut node = node(0, 4, 1);
        let bits = || vec![vec![bin(1, 0, 1)]];
        let dabits = || vec![dabit(false, 0, 1)];
        for bad in [
            SessionId::new(ProtocolType::Mul, SessionId::pack_slot(0, 0, 0), 0),
            // A child id: `round_id == B2A_OPEN_ROUND` is reserved for openings, and accepting one
            // as a parent would let a conversion mint children on top of another's ids.
            SessionId::new(
                ProtocolType::B2A,
                SessionId::pack_slot(0, 0, B2A_OPEN_ROUND),
                0,
            ),
            SessionId::new(ProtocolType::B2A, SessionId::pack_slot(0, 1, 0), 0),
        ] {
            assert!(matches!(
                node.b2a(bad, bits(), dabits(), Duration::from_millis(50), net(4))
                    .await,
                Err(B2AError::SessionIdError(_))
            ));
        }
    }

    #[tokio::test]
    async fn a_second_conversion_in_the_same_session_is_refused() {
        let mut node = node(0, 4, 1);
        let session_id = parent(0);
        let (network, _inboxes) = silent_net(4);
        // Drive one attempt far enough to mark the store `Opening`, then re-enter.
        let first = node
            .b2a(
                session_id,
                vec![vec![bin(0, 0, 1)]],
                vec![dabit(false, 0, 1)],
                Duration::from_millis(20),
                Arc::clone(&network),
            )
            .await;
        assert!(matches!(first, Err(B2AError::Timeout(_))));
        assert!(matches!(
            node.b2a(
                session_id,
                vec![vec![bin(0, 0, 1)]],
                vec![dabit(false, 0, 1)],
                Duration::from_millis(20),
                network
            )
            .await,
            Err(B2AError::SessionIdError(_))
        ));
        // And the child sessions the first attempt issued are retired with the parent.
        assert!(node.clear_store(session_id).await);
        assert_eq!(node.store_len().await, 0);
        assert_eq!(node.gf_open.store_len().await, 0);
    }

    #[tokio::test]
    async fn wait_for_result_is_single_shot_and_knows_an_unknown_session() {
        let node = node(0, 4, 1);
        assert!(matches!(
            node.wait_for_result(parent(9), Duration::from_millis(10))
                .await,
            Err(B2AError::NoSuchSessionId(_))
        ));
    }

    #[tokio::test]
    async fn the_open_registry_parks_a_result_that_beats_its_own_opener() {
        // A quorum can complete this node's reconstruction before the local opener registers for
        // the session; the payload must survive that race, and the park must stay bounded.
        let mut registry = OpenRegistry::default();
        registry.deliver(parent(3), vec![1, 2, 3]);
        let rx = registry.register(parent(3));
        assert_eq!(rx.await.unwrap(), vec![1, 2, 3]);

        for exec in 0..(MAX_PARKED_OPEN_PAYLOADS as u64 * 2) {
            registry.deliver(parent(exec), vec![0]);
        }
        assert_eq!(registry.parked.len(), MAX_PARKED_OPEN_PAYLOADS);
    }

    // -----------------------------------------------------------------------------------------
    // End-to-end
    // -----------------------------------------------------------------------------------------

    /// Trusted-dealer stand-in for the daBit pool: `total` daBits of uniformly random bits,
    /// dealt at degree `t` in both domains.
    fn deal_dabits(n: usize, t: usize, total: usize, rng: &mut StdRng) -> Vec<Vec<DaBit<F, K>>> {
        let mut out: Vec<Vec<DaBit<F, K>>> = (0..n).map(|_| Vec::with_capacity(total)).collect();
        for _ in 0..total {
            let b: bool = rng.gen();
            let arith = RobustShare::compute_shares(bit_to_field::<F>(b), n, t, None, rng).unwrap();
            let binr = GfShare::compute_shares(bit_to_binary::<K>(b), n, t, rng).unwrap();
            for party in 0..n {
                out[party].push(DaBit::new(arith[party].clone(), binr[party].clone(), t).unwrap());
            }
        }
        out
    }

    /// Deals the input bits. `tamper` replaces one bit's *secret* with an arbitrary `K` element,
    /// which is the only way to build the non-bit input a `GfShare` cannot otherwise express.
    fn deal_bits(
        n: usize,
        t: usize,
        values: &[Vec<bool>],
        tamper: Option<(usize, usize, K)>,
        rng: &mut StdRng,
    ) -> Vec<Vec<Vec<GfShare<K>>>> {
        let mut out: Vec<Vec<Vec<GfShare<K>>>> =
            (0..n).map(|_| Vec::with_capacity(values.len())).collect();
        for (v, value) in values.iter().enumerate() {
            for party in out.iter_mut() {
                party.push(Vec::with_capacity(value.len()));
            }
            for (i, bit) in value.iter().enumerate() {
                let secret = match tamper {
                    Some((tv, ti, k)) if tv == v && ti == i => k,
                    _ => bit_to_binary::<K>(*bit),
                };
                let shares = GfShare::compute_shares(secret, n, t, rng).unwrap();
                for (party, share) in shares.into_iter().enumerate() {
                    out[party][v].push(share);
                }
            }
        }
        out
    }

    fn deal_gf_triples(
        n: usize,
        t: usize,
        total: usize,
        rng: &mut StdRng,
    ) -> Vec<Vec<GfBeaverTriple<K>>> {
        let mut out: Vec<Vec<GfBeaverTriple<K>>> = (0..n).map(|_| Vec::new()).collect();
        for _ in 0..total {
            let a = K::random(rng);
            let b = K::random(rng);
            let a_shares = GfShare::compute_shares(a, n, t, rng).unwrap();
            let b_shares = GfShare::compute_shares(b, n, t, rng).unwrap();
            let c_shares = GfShare::compute_shares(a * b, n, t, rng).unwrap();
            for party in 0..n {
                out[party].push(GfBeaverTriple::new(
                    a_shares[party].clone(),
                    b_shares[party].clone(),
                    c_shares[party].clone(),
                ));
            }
        }
        out
    }

    /// Merges a party's per-sender inboxes into one stream of `(authenticated sender, bytes)`.
    fn fan_in(
        inboxes: Vec<tokio::sync::mpsc::Receiver<Vec<u8>>>,
    ) -> tokio::sync::mpsc::Receiver<(usize, Vec<u8>)> {
        let (tx, rx) = tokio::sync::mpsc::channel(4096);
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

    #[derive(Clone, Copy)]
    enum Variant {
        Unchecked,
        Checked,
        FullWidth,
    }

    /// Runs one conversion across `n` parties and returns the result of each of the
    /// `n - silent` participating ones, in party order.
    ///
    /// `silent` parties are never started at all — neither their receiver task nor their driver —
    /// which is the cheapest way to stage `silent` crash faults in a fake network.
    async fn b2a_e2e(
        n: usize,
        t: usize,
        values: &[Vec<bool>],
        variant: Variant,
        tamper: Option<(usize, usize, K)>,
        silent: usize,
    ) -> Vec<Result<Vec<RobustShare<F>>, B2AError>> {
        let active = n - silent;
        let mut rng = StdRng::seed_from_u64(7);
        let total: usize = values.iter().map(Vec::len).sum();
        let bits = deal_bits(n, t, values, tamper, &mut rng);
        let dabits = deal_dabits(n, t, total, &mut rng);
        let triples = match variant {
            Variant::Checked => Some(deal_gf_triples(n, t, total, &mut rng)),
            _ => None,
        };

        let config = FakeNetworkConfig::new(4096);
        let (inner, mut inboxes, _) = FakeInnerNetwork::new(n, None, config);
        let networks: Vec<Arc<FakeNetwork>> = (0..n)
            .map(|id| Arc::new(FakeNetwork::new(id, inner.clone())))
            .collect();
        let nodes: Vec<Node> = (0..n).map(|id| Node::new(id, n, t).unwrap()).collect();

        // One receiver task per party, demuxing exactly as the node dispatcher does: B2A owns no
        // message type of its own, so every arm here is `GfBatchRecon` routed on
        // `calling_protocol()` alone, and every `process` is followed by its matching drain (C10).
        for node in nodes.iter().take(active) {
            let mut node = node.clone();
            let net = Arc::clone(&networks[node.id]);
            let mut merged = fan_in(std::mem::take(&mut inboxes[node.id]));
            tokio::spawn(async move {
                while let Some((sender, bytes)) = merged.recv().await {
                    let wrapped: WrappedMessage = match bincode::deserialize(&bytes) {
                        Ok(m) => m,
                        Err(e) => {
                            warn!("undecodable message: {e:?}");
                            continue;
                        }
                    };
                    match wrapped {
                        WrappedMessage::GfBatchRecon(msg) => {
                            // The claim inside the payload must match the authenticated envelope
                            // id — the dispatcher's job, replicated here so the harness cannot
                            // accidentally be more permissive than production.
                            if msg.sender_id != sender {
                                warn!("forged sender id, dropping");
                                continue;
                            }
                            assert_eq!(msg.session_id.calling_protocol(), Some(ProtocolType::B2A));
                            let _ = node.gf_open.process(msg, Arc::clone(&net)).await;
                            if let Err(e) = node.drain_gf_open_output().await {
                                warn!("drain failed: {e:?}");
                            }
                        }
                        other => panic!("unexpected message {other:?}"),
                    }
                }
            });
        }

        let session_id = parent(5);
        let mut set = tokio::task::JoinSet::new();
        for (index, node) in nodes.iter().enumerate().take(active) {
            let mut node = node.clone();
            let net = Arc::clone(&networks[index]);
            let bits = bits[index].clone();
            let dabits = dabits[index].clone();
            let triples = triples.as_ref().map(|t| t[index].clone());
            set.spawn(async move {
                let started = match triples {
                    Some(triples) => {
                        node.b2a_checked(
                            session_id,
                            bits,
                            dabits,
                            triples,
                            Duration::from_secs(30),
                            net,
                        )
                        .await
                    }
                    None => match variant {
                        Variant::FullWidth => {
                            node.b2a_full_width_unchecked(
                                session_id,
                                bits,
                                dabits,
                                Duration::from_secs(30),
                                net,
                            )
                            .await
                        }
                        _ => {
                            node.b2a(session_id, bits, dabits, Duration::from_secs(30), net)
                                .await
                        }
                    },
                };
                let result = match started {
                    Ok(()) => {
                        node.wait_for_result(session_id, Duration::from_secs(30))
                            .await
                    }
                    Err(e) => Err(e),
                };
                assert!(node.clear_store(session_id).await);
                // Cleanup is complete on the failure path too, not only the happy one.
                assert_eq!(node.store_len().await, 0);
                assert_eq!(node.gf_open.store_len().await, 0);
                (node.id, result)
            });
        }

        let mut by_party: Vec<Option<Result<Vec<RobustShare<F>>, B2AError>>> =
            (0..active).map(|_| None).collect();
        while let Some(joined) = set.join_next().await {
            let (id, result) = joined.expect("party task panicked");
            by_party[id] = Some(result);
        }
        by_party
            .into_iter()
            .map(|r| r.expect("every party reported"))
            .collect()
    }

    /// Reconstructs value `v` from a deliberately minimal quorum of `2t + 1` shares.
    fn recover(
        results: &[Result<Vec<RobustShare<F>>, B2AError>],
        v: usize,
        n: usize,
        t: usize,
    ) -> F {
        let shares: Vec<RobustShare<F>> = results
            .iter()
            .take(2 * t + 1)
            .map(|r| r.as_ref().expect("party failed")[v].clone())
            .collect();
        RobustShare::recover_secret(&shares, n, t).unwrap().1
    }

    fn as_integer(value: &[bool]) -> u128 {
        value
            .iter()
            .enumerate()
            .filter(|(_, b)| **b)
            .map(|(i, _)| 1u128 << i)
            .sum()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn b2a_reconstructs_the_integer_the_bits_encode() {
        let (n, t) = (4usize, 1usize);
        // Widths 1, 8, 32 and the maximum 63, plus the all-ones pattern at each width, which is
        // where an off-by-one in the weighting or the bound would show up.
        let values = vec![
            vec![true],
            vec![false],
            (0..8).map(|i| i % 3 == 0).collect::<Vec<_>>(),
            vec![true; 32],
            vec![true; MAX_B2A_BITS],
            (0..MAX_B2A_BITS).map(|i| i % 2 == 1).collect::<Vec<_>>(),
        ];
        let results = b2a_e2e(n, t, &values, Variant::Unchecked, None, 0).await;
        for (v, value) in values.iter().enumerate() {
            let expected = F::from(as_integer(value));
            assert_eq!(recover(&results, v, n, t), expected, "value {v}");
        }
        // Every party's share is its own, at the right degree — the output is directly usable as
        // an operand of the arithmetic protocols.
        for (party, result) in results.iter().enumerate() {
            for share in result.as_ref().unwrap() {
                assert_eq!(share.id, party);
                assert_eq!(share.degree, t);
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn b2a_full_width_unchecked_is_exact_when_the_value_is_below_the_modulus() {
        let (n, t) = (4usize, 1usize);
        // `2^63`, `2^32` and `p - 1 = 0xFFFF_FFFF_0000_0000` — the last being exactly what an A2B
        // of `-1` emits, i.e. the round trip this entry point exists for.
        let mut two_pow_63 = vec![false; 64];
        two_pow_63[63] = true;
        let mut two_pow_32 = vec![false; 64];
        two_pow_32[32] = true;
        let p_minus_one: Vec<bool> = (0..64).map(|i| i >= 32).collect();
        let values = vec![two_pow_63, two_pow_32, p_minus_one];
        let results = b2a_e2e(n, t, &values, Variant::FullWidth, None, 0).await;
        assert_eq!(recover(&results, 0, n, t), F::from(1u128 << 63));
        assert_eq!(recover(&results, 1, n, t), F::from(1u128 << 32));
        assert_eq!(recover(&results, 2, n, t), F::from(0u64) - F::from(1u64));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn b2a_checked_agrees_with_the_unchecked_path_on_honest_input() {
        let (n, t) = (4usize, 1usize);
        let values = vec![vec![true, false, true, true], vec![false, true]];
        let checked = b2a_e2e(n, t, &values, Variant::Checked, None, 0).await;
        for (v, value) in values.iter().enumerate() {
            assert_eq!(recover(&checked, v, n, t), F::from(as_integer(value)));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_non_bit_input_is_rejected_identically_at_every_party() {
        let (n, t) = (4usize, 1usize);
        let values = vec![vec![true, false, true]];
        // `Gf256(3)` is outside the `GF(2)` subfield, so `c = x XOR r` lands outside it too. The
        // value was robustly opened, so the verdict is agreed with no extra round.
        let results = b2a_e2e(n, t, &values, Variant::Unchecked, Some((0, 1, Gf256(3))), 0).await;
        for (party, result) in results.iter().enumerate() {
            match result {
                Err(B2AError::NonBooleanInput { value, index }) => {
                    assert_eq!((*value, *index), (0, 1), "party {party}");
                }
                other => panic!("party {party} did not reject the non-bit: {other:?}"),
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn b2a_checked_proves_a_non_bit_input_rather_than_inferring_it() {
        let (n, t) = (4usize, 1usize);
        let values = vec![vec![true, true, false, true]];
        // The certification layer opens `x(x+1)`, which is identically zero for a bit and depends
        // on nothing but the input — unlike the `c_i.is_bit()` inference, it does not rely on the
        // daBit's binary half being well formed.
        let results = b2a_e2e(n, t, &values, Variant::Checked, Some((0, 2, Gf256(7))), 0).await;
        for (party, result) in results.iter().enumerate() {
            match result {
                Err(B2AError::CertificationFailed { value, index }) => {
                    assert_eq!((*value, *index), (0, 2), "party {party}");
                }
                other => panic!("party {party} did not certify-reject: {other:?}"),
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn conversion_completes_with_t_parties_silent() {
        // Every opening here is degree `t`, where robust reconstruction decodes an `[n, t+1]` code
        // with `d = 2t+1`: `degree + t + 1 = 2t + 1` evaluations suffice, and `n - t = 2t + 1`
        // parties are still speaking. (At degree `2t` the same guard would demand all `n`, which
        // is the pre-existing gap this protocol deliberately stays off.) `n = 7, t = 2` leaves
        // exactly the minimum quorum, so this also pins that the opener does not quietly need
        // more than it should.
        let (n, t) = (7usize, 2usize);
        let values = vec![vec![true, false, true, true, false]];
        let results = b2a_e2e(n, t, &values, Variant::Unchecked, None, t).await;
        assert_eq!(results.len(), n - t);
        assert_eq!(recover(&results, 0, n, t), F::from(as_integer(&values[0])));
    }
}
