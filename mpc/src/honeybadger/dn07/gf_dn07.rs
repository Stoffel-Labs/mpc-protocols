//! GF(2^k) equivalent of [`dn07`](super::dn07) — a direct structural port.
//!
//! Everything about the arithmetic twin carries over unchanged except the field: one degree-`2t`
//! batched opening per batch, one [`GfDoubleShamirShare`] per multiplication or per exact-zero
//! check, and no Beaver triple. Keep the two files in step; where they diverge, the divergence is
//! commented.
//!
//! **Phase: PREPROCESSING only** — synchronous, abort permitted. The `GfBatchReconNode` this node
//! owns is pinned at `degree = 2t`, which is unreconstructible on the asynchronous robust online
//! path at `n = 3t+1`. See the [module docs](super).
//!
//! # Two divergences from the `F` twin, both in characteristic 2
//!
//! * **The exact-zero check's second operand is `[W] + 1`, never `[W]`.** `W(W+1) = W² + W`
//!   vanishes exactly on `{0,1} = GF(2) ⊂ GF(2^k)`, which is what bit-ness means here. Checking
//!   `W · W` instead would be worse than useless: Frobenius is a bijection on `GF(2^k)`, so `W²`
//!   determines `W`, and opening it reveals the value exactly rather than up to a sign.
//! * **Addition is XOR, so `+` and `−` are the same operation.** The mask is still written as the
//!   difference `[r]_2t − [r]_t` to keep the port line-for-line with the `F` side; in this field
//!   that is the same element as the sum.
//!
//! # Why this file is item 6's payoff
//!
//! A `Gf256` Beaver triple from `gf_triple_gen` fed by dealt `GfRanDouSha` double sharings costs
//! `2·P1_K + P3_K + O2 = 18.857` bytes of **payload** per party at `n = 10`. The same triple with
//! its double sharing from
//! [`GfPrssDoubleShareSource`](super::double_share::GfPrssDoubleShareSource) costs `O2 = 2.857`,
//! because PRSS and PRZS put nothing at all on the wire — a **6.6x** payload cut. Nothing about
//! the opening changes; only where the randomness came from.
//!
//! Two corrections to that headline, both from measurement, both spelled out in
//! [`the dn07 module docs`](super): the 6.6x is against a *fully dealt* baseline this tree had
//! already left (what the change actually replaced is `2·P1_K + O2`, i.e. **3.25x / 3.62x /
//! 3.80x / 3.91x** at `n = 4/7/10/13`) and which does not complete above `n = 4` at all; and
//! `2.857` is a **marginal** cost — the measured wire bill for a batch is
//! `2n * 48 + O2 * triples`, the fixed part being the per-message frame the element-counting
//! model has no term for.

use std::sync::Arc;
use std::time::Instant;

use bincode::Options;
use serde::de::DeserializeOwned;
use stoffelnet::network_utils::Network;
use tokio::sync::mpsc::Receiver;
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};
use tracing::warn;

use crate::common::gf2k::field::BinaryField;
use crate::common::gf2k::share::GfShare;
use crate::common::session_store::{Admission, SessionStore};
use crate::honeybadger::dn07::{
    Dn07Error, Dn07Outcome, Dn07State, Dn07Store, Dn07Task, PreprocessingSessionId,
    MAX_DN07_GROUPS, MAX_DN07_SESSIONS,
};
use crate::honeybadger::gf_batch_recon::gf_batch_recon::GfBatchReconNode;
use crate::honeybadger::gf_double_share::GfDoubleShamirShare;
use crate::honeybadger::SessionId;

/// Bounded by the payload's own byte length, matching `bincode::serialize`'s fixint encoding —
/// see `gf_share_gen::gf_share_gen::deser_bounded` for why `with_fixint_encoding` is required and
/// not optional. Identical to the helper `gf_triple_generation.rs` carries, and deliberately a
/// local copy for the same reason that one is: the bound is the *received byte length*, which is
/// only meaningful at the call site that received it.
fn deser_bounded<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Dn07Error> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(bytes.len() as u64)
        .deserialize(bytes)
        .map_err(|e| Dn07Error::Deserialization(format!("{e:?}")))
}

/// GF(2^k) preprocessing multiplication node. See [`Dn07MulNode`](super::dn07::Dn07MulNode).
///
/// # Phase
///
/// **PREPROCESSING.** `init_mul` and `init_zero_check` accept only a [`PreprocessingSessionId`],
/// and [`GfBatchReconNode`] is pinned at `degree = 2 * threshold` in [`GfDn07MulNode::new`].
#[derive(Clone, Debug)]
pub struct GfDn07MulNode<K: BinaryField> {
    pub id: usize,
    pub n_parties: usize,
    pub threshold: usize,
    pub store:
        Arc<Mutex<SessionStore<SessionId, (usize, Instant, Arc<Mutex<Dn07Store<GfShare<K>>>>)>>>,
    /// Pinned at `degree = 2t`. The single reason this whole module is preprocessing-only.
    pub batch_recon: GfBatchReconNode<K>,
    pub batch_output: Arc<Mutex<Receiver<SessionId>>>,
}

impl<K: BinaryField> GfDn07MulNode<K> {
    /// # Errors
    /// - [`Dn07Error::DegenerateThreshold`] for `t == 0`.
    /// - [`Dn07Error::PartyCountTooSmall`] for `n < 3t+1`.
    ///
    /// Both for the reasons given on the arithmetic twin: below the Byzantine bound the
    /// `t+1`-minimum-distance argument that licenses a degree-`2t` opening does not hold.
    pub fn new(id: usize, n_parties: usize, threshold: usize) -> Result<Self, Dn07Error> {
        if threshold == 0 {
            return Err(Dn07Error::DegenerateThreshold);
        }
        if n_parties < 3 * threshold + 1 {
            return Err(Dn07Error::PartyCountTooSmall {
                n: n_parties,
                bound: 3 * threshold + 1,
            });
        }
        let (batch_sender, batch_receiver) = tokio::sync::mpsc::channel(200);
        let batch_recon =
            GfBatchReconNode::new(id, n_parties, threshold, 2 * threshold, batch_sender)?;
        Ok(Self {
            id,
            n_parties,
            threshold,
            store: Arc::new(Mutex::new(SessionStore::with_default_cap())),
            batch_recon,
            batch_output: Arc::new(Mutex::new(batch_receiver)),
        })
    }

    /// Largest `k` a single `init_*` call may open, in secrets.
    pub fn max_batch_size(&self) -> usize {
        MAX_DN07_GROUPS * (2 * self.threshold + 1)
    }

    pub async fn store_len(&self) -> usize {
        self.store.lock().await.len()
    }

    /// Retires this session here and in the batch-reconstruction child. Call it on the failure
    /// path too — an aborted check still holds two store entries.
    pub async fn clear_store(&self, session_id: SessionId) -> bool {
        self.batch_recon.clear_store(session_id).await;
        self.store.lock().await.retire(session_id)
    }

    pub async fn get_or_create_store(
        &self,
        session_id: SessionId,
        initiator_id: usize,
        k: usize,
    ) -> Option<Arc<Mutex<Dn07Store<GfShare<K>>>>> {
        match self.store.lock().await.get_or_admit(
            session_id,
            initiator_id,
            MAX_DN07_SESSIONS,
            (MAX_DN07_SESSIONS / self.n_parties).max(1),
            || Arc::new(Mutex::new(Dn07Store::new(k))),
        ) {
            Admission::Got(arc) => Some(arc),
            Admission::Retired => None,
            Admission::Rejected => {
                warn!("GF DN07 session limit reached");
                None
            }
        }
    }

    /// Rebuilds a supplied double sharing against this node's *local* degree constants. See the
    /// arithmetic twin for why the caller's `degree` field is discarded and its `id` is not.
    fn localise(
        &self,
        pairs: &[GfDoubleShamirShare<K>],
    ) -> Result<(Vec<GfShare<K>>, Vec<GfShare<K>>), Dn07Error> {
        let mut r_t = Vec::with_capacity(pairs.len());
        let mut r_2t = Vec::with_capacity(pairs.len());
        for (index, pair) in pairs.iter().enumerate() {
            if pair.degree_t.id != self.id || pair.degree_2t.id != self.id {
                return Err(Dn07Error::ShareIdMismatch {
                    index,
                    expected: self.id,
                    got: pair.degree_t.id,
                });
            }
            r_t.push(GfShare::new(pair.degree_t.share, self.id, self.threshold));
            r_2t.push(GfShare::new(
                pair.degree_2t.share,
                self.id,
                2 * self.threshold,
            ));
        }
        Ok((r_t, r_2t))
    }

    async fn open_2t<N: Network + Send + Sync + 'static>(
        &mut self,
        session_id: PreprocessingSessionId,
        masked: Vec<GfShare<K>>,
        task: Dn07Task<GfShare<K>>,
        network: Arc<N>,
    ) -> Result<(), Dn07Error> {
        let sid = session_id.get();
        let k = masked.len();

        let storage_bind = match self.get_or_create_store(sid, self.id, k).await {
            Some(s) => s,
            None => return Err(Dn07Error::LimitError),
        };

        let pending = {
            let mut store = storage_bind.lock().await;
            store.k = k;
            store.task = Some(task);
            store.pending_batch_recon_payload.take()
        };
        if let Some(payload) = pending {
            self.finish_from_payload(sid, storage_bind.clone(), payload)
                .await?;
            if storage_bind.lock().await.state == Dn07State::Finished {
                return Ok(());
            }
        }

        let group = 2 * self.threshold + 1;
        let groups = k.div_ceil(group);
        let mut all = masked;
        // Pad with zero: a zero check's padding must itself open to zero, and a multiplication's
        // padded positions are dropped.
        while all.len() < groups * group {
            all.push(GfShare::new(K::zero(), self.id, 2 * self.threshold));
        }

        self.batch_recon
            .init_batch_reconstruct_many(&all, sid, network)
            .await?;
        Ok(())
    }

    /// DN07 degree reduction over `Gf2k`: `[xy]_t` from `[x]_t`, `[y]_t` and one double sharing.
    ///
    /// **Phase: PREPROCESSING.** The dealt-input warning on
    /// [`Dn07MulNode::init_mul`](super::dn07::Dn07MulNode::init_mul) applies here verbatim: a
    /// degree-`2t` opening imposes no codeword constraint on the honest sub-word, so an operand
    /// dealt at degree `t+1` is recoverable from it without any abort being raised. Feed this node
    /// only shares that were derived rather than dealt, or certify dealt ones with a batch degree
    /// test first.
    pub async fn init_mul<N: Network + Send + Sync + 'static>(
        &mut self,
        session_id: PreprocessingSessionId,
        x: Vec<GfShare<K>>,
        y: Vec<GfShare<K>>,
        doubles: Vec<GfDoubleShamirShare<K>>,
        network: Arc<N>,
    ) -> Result<(), Dn07Error> {
        if x.len() != y.len() {
            return Err(Dn07Error::LengthMismatch {
                what: "operands x and y",
                expected: x.len(),
                got: y.len(),
            });
        }
        if x.len() != doubles.len() {
            return Err(Dn07Error::LengthMismatch {
                what: "double sharings",
                expected: x.len(),
                got: doubles.len(),
            });
        }
        if x.is_empty() {
            return Err(Dn07Error::EmptyInput);
        }
        if x.len() > self.max_batch_size() {
            return Err(Dn07Error::BatchTooLarge {
                requested: x.len(),
                max: self.max_batch_size(),
            });
        }

        let (r_t, r_2t) = self.localise(&doubles)?;

        let mut masked = Vec::with_capacity(x.len());
        for ((xi, yi), ri) in x.iter().zip(y.iter()).zip(r_2t.into_iter()) {
            let product = xi.share_mul(yi)?;
            let product = GfShare::new(product.share, self.id, 2 * self.threshold);
            masked.push((product - ri)?);
        }

        self.open_2t(session_id, masked, Dn07Task::Reduce { r_t }, network)
            .await
    }

    /// Exact-zero check over `Gf2k`: asserts `u_i · v_i == 0` for every `i`, soundness error **0**.
    ///
    /// **Phase: PREPROCESSING** — degree-`2t` opening, abort on failure.
    ///
    /// For bit-ness pass `v_i = u_i + 1`: `W(W+1) = 0` exactly on `GF(2) ⊂ GF(2^k)`. Never pass
    /// `v_i = u_i` — squaring is a bijection in characteristic 2, so opening `W²` reveals `W`.
    ///
    /// The mask is the double sharing's own difference `[r]_2t − [r]_t`, a uniform element of
    /// `{h : deg h <= 2t, h(0) = 0}`.
    pub async fn init_zero_check<N: Network + Send + Sync + 'static>(
        &mut self,
        session_id: PreprocessingSessionId,
        u: Vec<GfShare<K>>,
        v: Vec<GfShare<K>>,
        doubles: Vec<GfDoubleShamirShare<K>>,
        network: Arc<N>,
    ) -> Result<(), Dn07Error> {
        if u.len() != v.len() {
            return Err(Dn07Error::LengthMismatch {
                what: "operands u and v",
                expected: u.len(),
                got: v.len(),
            });
        }
        if u.len() != doubles.len() {
            return Err(Dn07Error::LengthMismatch {
                what: "double sharings",
                expected: u.len(),
                got: doubles.len(),
            });
        }
        if u.is_empty() {
            return Err(Dn07Error::EmptyInput);
        }
        if u.len() > self.max_batch_size() {
            return Err(Dn07Error::BatchTooLarge {
                requested: u.len(),
                max: self.max_batch_size(),
            });
        }

        let (r_t, r_2t) = self.localise(&doubles)?;

        let mut masked = Vec::with_capacity(u.len());
        for ((ui, vi), (rt, r2t)) in u
            .iter()
            .zip(v.iter())
            .zip(r_t.into_iter().zip(r_2t.into_iter()))
        {
            let product = ui.share_mul(vi)?;
            let product = GfShare::new(product.share, self.id, 2 * self.threshold);
            let rt_lifted = GfShare::new(rt.share, self.id, 2 * self.threshold);
            let mask = (r2t - rt_lifted)?;
            masked.push((product + mask)?);
        }

        self.open_2t(session_id, masked, Dn07Task::ZeroCheck, network)
            .await
    }

    pub async fn drain_batch_recon_output(&mut self) -> Result<(), Dn07Error> {
        loop {
            let sid = {
                let mut rx = self.batch_output.lock().await;
                match rx.try_recv() {
                    Ok(id) => id,
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        return Err(Dn07Error::Abort)
                    }
                }
            };

            let storage_bind = match self.get_or_create_store(sid, self.id, 0).await {
                Some(b) => b,
                None => continue,
            };
            let payload = self.batch_recon.get_store(sid).await?;
            self.finish_from_payload(sid, storage_bind, payload).await?;
        }
        Ok(())
    }

    async fn finish_from_payload(
        &self,
        session_id: SessionId,
        storage_bind: Arc<Mutex<Dn07Store<GfShare<K>>>>,
        payload: Vec<u8>,
    ) -> Result<(), Dn07Error> {
        let mut store = storage_bind.lock().await;
        if store.state == Dn07State::Finished {
            return Ok(());
        }
        if store.k == 0 || store.task.is_none() {
            store.pending_batch_recon_payload = Some(payload);
            return Ok(());
        }

        let opened: Vec<K> = deser_bounded(&payload)?;
        let k = store.k;
        if opened.len() < k {
            warn!(?session_id, "GF DN07: short coefficient vector");
            return Ok(());
        }

        let outcome = match store.task.take() {
            Some(Dn07Task::Reduce { r_t }) => {
                if r_t.len() != k {
                    return Err(Dn07Error::LengthMismatch {
                        what: "parked degree-t shares",
                        expected: k,
                        got: r_t.len(),
                    });
                }
                let mut products = Vec::with_capacity(k);
                for (share, d) in r_t.into_iter().zip(opened.iter().take(k)) {
                    products.push((share + *d)?);
                }
                Dn07Outcome::Products(products)
            }
            Some(Dn07Task::ZeroCheck) => {
                let zero = K::zero();
                let violations = opened
                    .iter()
                    .take(k)
                    .enumerate()
                    .filter_map(|(i, v)| (*v != zero).then_some(i))
                    .collect();
                Dn07Outcome::ZeroCheckViolations(violations)
            }
            None => {
                store.pending_batch_recon_payload = Some(payload);
                return Ok(());
            }
        };

        store.state = Dn07State::Finished;
        if let Some(tx) = store.output_sender.take() {
            tx.send(outcome)
                .map_err(|_| Dn07Error::SendError(session_id))?;
        }
        Ok(())
    }

    /// Awaits this session's outcome. The `duration` is a local liveness bound on a **synchronous
    /// preprocessing** round, not an online-path timeout.
    pub async fn wait_for_result(
        &self,
        session_id: SessionId,
        duration: Duration,
    ) -> Result<Dn07Outcome<GfShare<K>>, Dn07Error> {
        let rx = {
            let storage = self.store.lock().await;
            let (_, _, bind) = storage
                .get(&session_id)
                .ok_or(Dn07Error::NoSuchSession(session_id))?;
            let mut store = bind.lock().await;
            store
                .output_receiver
                .take()
                .ok_or(Dn07Error::ResultAlreadyReceived(session_id))?
        };
        match timeout(duration, rx).await {
            Err(_) => Err(Dn07Error::Timeout(session_id)),
            Ok(Err(_)) => Err(Dn07Error::ReceiveError(session_id)),
            Ok(Ok(outcome)) => Ok(outcome),
        }
    }

    pub async fn wait_for_products(
        &self,
        session_id: SessionId,
        duration: Duration,
    ) -> Result<Vec<GfShare<K>>, Dn07Error> {
        match self.wait_for_result(session_id, duration).await? {
            Dn07Outcome::Products(p) => Ok(p),
            Dn07Outcome::ZeroCheckViolations(_) => {
                Err(Dn07Error::WrongTask(session_id, "zero-check"))
            }
        }
    }

    /// Pass/fail form of [`Self::wait_for_result`]. A failure is an **abort** and a proof of
    /// misbehaviour: this check has soundness error 0.
    pub async fn wait_for_zero_check(
        &self,
        session_id: SessionId,
        duration: Duration,
    ) -> Result<(), Dn07Error> {
        match self.wait_for_result(session_id, duration).await? {
            Dn07Outcome::ZeroCheckViolations(v) => match v.first() {
                None => Ok(()),
                Some(index) => Err(Dn07Error::ZeroCheckFailed { index: *index }),
            },
            Dn07Outcome::Products(_) => Err(Dn07Error::WrongTask(session_id, "multiplication")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::gf2k::field::Gf256;
    use crate::common::ProtocolSessionId;
    use crate::honeybadger::ProtocolType;
    use stoffelmpc_network::fake_network::{FakeInnerNetwork, FakeNetwork, FakeNetworkConfig};

    fn pre_sid(tag: ProtocolType) -> PreprocessingSessionId {
        PreprocessingSessionId::new(SessionId::new(tag, SessionId::pack_slot(3, 0, 0), 42)).unwrap()
    }

    fn double(v_t: u8, v_2t: u8, id: usize) -> GfDoubleShamirShare<Gf256> {
        // Wrong degrees on the wire object on purpose: `localise` must overwrite them.
        GfDoubleShamirShare::new(
            GfShare::new(Gf256::from(v_t), id, 999),
            GfShare::new(Gf256::from(v_2t), id, 999),
        )
    }

    /// The inboxes are returned alongside the network and must be kept alive by the caller: a
    /// `FakeNetwork` whose receivers have been dropped fails every `send` with `SendError`, which
    /// would make these tests pass or fail for the wrong reason.
    type Inboxes = Vec<Vec<tokio::sync::mpsc::Receiver<Vec<u8>>>>;

    fn net() -> (Arc<FakeNetwork>, Inboxes) {
        let (inner, inboxes, _) = FakeInnerNetwork::new(5, None, FakeNetworkConfig::new(10));
        (Arc::new(FakeNetwork::new(0, inner)), inboxes)
    }

    fn payload_of(values: &[Gf256]) -> Vec<u8> {
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .serialize(&values.to_vec())
            .unwrap()
    }

    #[test]
    fn refuses_degenerate_threshold_and_small_party_counts() {
        assert!(matches!(
            GfDn07MulNode::<Gf256>::new(0, 5, 0).unwrap_err(),
            Dn07Error::DegenerateThreshold
        ));
        assert!(matches!(
            GfDn07MulNode::<Gf256>::new(0, 3, 1).unwrap_err(),
            Dn07Error::PartyCountTooSmall { n: 3, bound: 4 }
        ));
        assert!(GfDn07MulNode::<Gf256>::new(0, 4, 1).is_ok());
    }

    #[test]
    fn batch_recon_child_is_pinned_at_degree_2t() {
        let node = GfDn07MulNode::<Gf256>::new(0, 10, 3).unwrap();
        assert_eq!(node.batch_recon.degree, 6);
        assert_eq!(node.max_batch_size(), MAX_DN07_GROUPS * 7);
    }

    #[test]
    fn localise_overwrites_caller_written_degrees_and_checks_the_id() {
        let node = GfDn07MulNode::<Gf256>::new(2, 10, 3).unwrap();
        let (r_t, r_2t) = node.localise(&[double(0x11, 0x22, 2)]).unwrap();
        assert_eq!(r_t[0].degree, 3);
        assert_eq!(r_2t[0].degree, 6);
        assert!(matches!(
            node.localise(&[double(1, 2, 5)]).unwrap_err(),
            Dn07Error::ShareIdMismatch {
                index: 0,
                expected: 2,
                got: 5
            }
        ));
    }

    #[tokio::test]
    async fn buffers_a_reconstruction_that_finishes_before_local_init() {
        let (network, _inboxes) = net();
        let mut node = GfDn07MulNode::<Gf256>::new(0, 5, 1).unwrap();
        let sid = pre_sid(ProtocolType::GfTriple);
        let opened = vec![
            Gf256::from(0x10_u8),
            Gf256::from(0x20_u8),
            Gf256::from(0x30_u8),
        ];
        let payload = payload_of(&opened);

        let bind = node.get_or_create_store(sid.get(), 0, 0).await.unwrap();
        node.finish_from_payload(sid.get(), bind.clone(), payload.clone())
            .await
            .unwrap();
        assert_eq!(bind.lock().await.state, Dn07State::Running);

        let x = vec![GfShare::new(Gf256::from(2_u8), 0, 1); 3];
        node.init_mul(sid, x.clone(), x, vec![double(5, 7, 0); 3], network.clone())
            .await
            .unwrap();

        let products = node
            .wait_for_products(sid.get(), Duration::from_secs(1))
            .await
            .unwrap();
        // [xy]_t = [r]_t + d, and `+` is XOR here.
        let expected: Vec<Gf256> = opened.iter().map(|d| Gf256::from(5_u8) + *d).collect();
        assert_eq!(
            products.iter().map(|p| p.share).collect::<Vec<_>>(),
            expected
        );
        assert_eq!(products[0].degree, 1);
    }

    #[tokio::test]
    async fn zero_check_names_the_failing_index() {
        let (network, _inboxes) = net();
        let mut node = GfDn07MulNode::<Gf256>::new(0, 5, 1).unwrap();
        let sid = pre_sid(ProtocolType::GfDn07);
        let payload = payload_of(&[Gf256::from(0_u8), Gf256::from(0_u8), Gf256::from(7_u8)]);

        let u = vec![GfShare::new(Gf256::from(1_u8), 0, 1); 3];
        let v: Vec<GfShare<Gf256>> = u
            .iter()
            .map(|s| (s.clone() + Gf256::from(1_u8)).unwrap())
            .collect();
        node.init_zero_check(sid, u, v, vec![double(4, 4, 0); 3], network.clone())
            .await
            .unwrap();
        let bind = node.get_or_create_store(sid.get(), 0, 3).await.unwrap();
        node.finish_from_payload(sid.get(), bind, payload)
            .await
            .unwrap();

        assert!(matches!(
            node.wait_for_zero_check(sid.get(), Duration::from_secs(1))
                .await
                .unwrap_err(),
            Dn07Error::ZeroCheckFailed { index: 2 }
        ));
    }

    #[tokio::test]
    async fn online_sessions_cannot_even_be_named() {
        // `init_*` takes a `PreprocessingSessionId`, so this is the only place the attempt can be
        // made at all — and it fails before any share is touched.
        let err = PreprocessingSessionId::new(SessionId::new(
            ProtocolType::A2BGfMul,
            SessionId::pack_slot(1, 0, 0),
            42,
        ))
        .unwrap_err();
        assert!(matches!(err, Dn07Error::OnlinePhaseForbidden { .. }));
    }

    /// The `Gf2k` twin of `dn07::tests::a_session_left_uncleared_costs_the_next_one_its_admission_slot`,
    /// and the one that guards a live production caller: `EdaBitFilterNode::mul_k` issues a wave
    /// of these per AND layer and is the only thing that retires them.
    ///
    /// `n = 255` rather than 256 — `Gf256` has 255 distinct nonzero evaluation points — which
    /// still puts the per-peer quota `MAX_DN07_SESSIONS / n` at exactly one.
    #[tokio::test]
    async fn a_session_left_uncleared_costs_the_next_one_its_admission_slot() {
        let node = GfDn07MulNode::<Gf256>::new(0, Gf256::MAX_DOMAIN_SIZE, 1).unwrap();
        assert_eq!((MAX_DN07_SESSIONS / Gf256::MAX_DOMAIN_SIZE).max(1), 1);
        let first = PreprocessingSessionId::new(SessionId::new(
            ProtocolType::DaBitGfMul,
            SessionId::pack_slot(1, 0, 0),
            42,
        ))
        .unwrap()
        .get();
        let second = PreprocessingSessionId::new(SessionId::new(
            ProtocolType::DaBitGfMul,
            SessionId::pack_slot(2, 0, 0),
            42,
        ))
        .unwrap()
        .get();

        assert!(node.get_or_create_store(first, 0, 3).await.is_some());
        assert!(
            node.get_or_create_store(second, 0, 3).await.is_none(),
            "the uncleared first session must still be holding the only slot"
        );
        assert!(node.clear_store(first).await);
        assert!(
            node.get_or_create_store(second, 0, 3).await.is_some(),
            "clearing the first session must hand the slot back"
        );
        assert_eq!(node.store_len().await, 1, "one live session, not two");
    }

    #[tokio::test]
    async fn clearing_a_session_retires_the_batch_recon_child_too() {
        let (network, _inboxes) = net();
        let mut node = GfDn07MulNode::<Gf256>::new(0, 5, 1).unwrap();
        let sid = pre_sid(ProtocolType::GfDn07);
        let x = vec![GfShare::new(Gf256::from(2_u8), 0, 1); 3];
        node.init_mul(sid, x.clone(), x, vec![double(1, 1, 0); 3], network.clone())
            .await
            .unwrap();
        assert_eq!(node.store_len().await, 1);
        assert!(node.clear_store(sid.get()).await);
        assert_eq!(node.store_len().await, 0);
        assert_eq!(node.batch_recon.store_len().await, 0);
        assert!(node.get_or_create_store(sid.get(), 0, 3).await.is_none());
    }
}
