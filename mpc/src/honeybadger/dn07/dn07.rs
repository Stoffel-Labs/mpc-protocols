//! DN07 degree-reduction multiplication and exact-zero check over the arithmetic field `F`.
//!
//! **Phase: PREPROCESSING only** — synchronous, abort permitted. Every opening this node performs
//! is at degree `2t` and is therefore illegal on the asynchronous robust online path. See the
//! [module docs](super) for the full argument and for the four structural barriers that keep it
//! off that path.
//!
//! The `Gf2k` twin is [`gf_dn07`](super::gf_dn07) and is a line-for-line port; keep the two in
//! step.

use std::sync::Arc;
use std::time::Instant;

use ark_ff::FftField;
use stoffelnet::network_utils::{Network, PartyId};
use tokio::sync::mpsc::Receiver;
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};
use tracing::warn;

use crate::common::session_store::{Admission, SessionStore};
use crate::common::utils::deser_bounded_vec;
use crate::honeybadger::batch_recon::batch_recon::BatchReconNode;
use crate::honeybadger::dn07::{
    Dn07Error, Dn07Outcome, Dn07State, Dn07Store, Dn07Task, PreprocessingSessionId,
    MAX_DN07_GROUPS, MAX_DN07_SESSIONS,
};
use crate::honeybadger::double_share::DoubleShamirShare;
use crate::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use crate::honeybadger::SessionId;

/// A preprocessing multiplication node: one degree-`2t` batched opening per batch, no Beaver
/// triple, one random double sharing per multiplication or per exact-zero check.
///
/// # Phase
///
/// **PREPROCESSING.** `init_mul` and `init_zero_check` accept only a [`PreprocessingSessionId`],
/// and the one [`BatchReconNode`] this node owns is pinned at `degree = 2 * threshold` in
/// [`Dn07MulNode::new`] and is never reconfigured.
#[derive(Clone, Debug)]
pub struct Dn07MulNode<F: FftField> {
    pub id: PartyId,
    pub n_parties: usize,
    pub threshold: usize,
    pub store: Arc<
        Mutex<SessionStore<SessionId, (usize, Instant, Arc<Mutex<Dn07Store<RobustShare<F>>>>)>>,
    >,
    /// Pinned at `degree = 2t`. The single reason this whole module is preprocessing-only.
    pub batch_recon: BatchReconNode<F>,
    pub batch_output: Arc<Mutex<Receiver<SessionId>>>,
}

impl<F: FftField> Dn07MulNode<F> {
    /// # Errors
    /// - [`Dn07Error::DegenerateThreshold`] for `t == 0`: a degree-`0` "mask" is a constant and
    ///   hides nothing. A `warn!` here would be the `l`/`kappa` misconfiguration class the repo has
    ///   already shipped once; it is a hard error.
    /// - [`Dn07Error::PartyCountTooSmall`] for `n < 3t+1`: below the Byzantine bound a degree-`2t`
    ///   sharing has fewer than `2t+1` honest points and the `t+1` minimum distance that gives
    ///   detect-with-probability-1 is gone, so the opening would be neither reconstructible nor
    ///   sound. Refusing to construct the node is cheaper than discovering that at an opening.
    pub fn new(id: PartyId, n_parties: usize, threshold: usize) -> Result<Self, Dn07Error> {
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
            BatchReconNode::new(id, n_parties, threshold, 2 * threshold, batch_sender)?;
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
    ///
    /// Callers chunk against this rather than reimplementing the `2t+1` group arithmetic.
    pub fn max_batch_size(&self) -> usize {
        MAX_DN07_GROUPS * (2 * self.threshold + 1)
    }

    /// Number of live DN07 sessions. Used by the node's preprocessing trace.
    pub async fn store_len(&self) -> usize {
        self.store.lock().await.len()
    }

    /// Retires this session here and in the batch-reconstruction child.
    ///
    /// Call it on the **failure** path as well as on success: an aborted zero check still holds a
    /// store entry and a batch-recon store entry, and both count against the admission caps.
    pub async fn clear_store(&self, session_id: SessionId) -> bool {
        self.batch_recon.clear_store(session_id).await;
        self.store.lock().await.retire(session_id)
    }

    pub async fn get_or_create_store(
        &self,
        session_id: SessionId,
        initiator_id: usize,
        k: usize,
    ) -> Option<Arc<Mutex<Dn07Store<RobustShare<F>>>>> {
        match self.store.lock().await.get_or_admit(
            session_id,
            initiator_id,
            MAX_DN07_SESSIONS,
            // `.max(1)`: with `n > MAX_DN07_SESSIONS` the integer quotient is zero, which would
            // reject every session including this node's own.
            (MAX_DN07_SESSIONS / self.n_parties).max(1),
            || Arc::new(Mutex::new(Dn07Store::new(k))),
        ) {
            Admission::Got(arc) => Some(arc),
            Admission::Retired => None,
            Admission::Rejected => {
                warn!("DN07 session limit reached");
                None
            }
        }
    }

    /// Rebuilds a supplied double sharing against this node's *local* constants.
    ///
    /// `ShamirShare::degree` is caller-written metadata that proves nothing about the polynomial
    /// the share lies on, so trusting it would be a T2 (form) error. The value is taken and the
    /// labels `t` and `2t` are substituted, exactly as `batch_recon.rs:250` does with a
    /// reconstruction's claimed degree. The share `id` is the one label that *is* checked rather
    /// than overwritten: it is the evaluation point, and there is no local constant to put in its
    /// place — a wrong one would silently produce a share of a different polynomial.
    fn localise(
        &self,
        pairs: &[DoubleShamirShare<F>],
    ) -> Result<(Vec<RobustShare<F>>, Vec<RobustShare<F>>), Dn07Error> {
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
            r_t.push(RobustShare::new(
                pair.degree_t.share[0],
                self.id,
                self.threshold,
            ));
            r_2t.push(RobustShare::new(
                pair.degree_2t.share[0],
                self.id,
                2 * self.threshold,
            ));
        }
        Ok((r_t, r_2t))
    }

    /// Common tail: park the task, claim any early reconstruction, and open at degree `2t`.
    async fn open_2t<N: Network + Send + Sync + 'static>(
        &mut self,
        session_id: PreprocessingSessionId,
        masked: Vec<RobustShare<F>>,
        task: Dn07Task<RobustShare<F>>,
        network: Arc<N>,
    ) -> Result<(), Dn07Error> {
        let sid = session_id.get();
        let k = masked.len();

        let storage_bind = match self.get_or_create_store(sid, self.id, k).await {
            Some(s) => s,
            None => return Err(Dn07Error::LimitError),
        };

        // Set `k` and the task, and atomically claim a reconstruction result that arrived before
        // this call — a `2t+1` quorum can finish this node's own reconstruction before it reaches
        // `init_*`.
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
                // Already have the result — skip the redundant network round.
                return Ok(());
            }
        }

        let group = 2 * self.threshold + 1;
        let groups = k.div_ceil(group);
        let mut all = masked;
        // Pad with zero, not one: for a zero check the padding must itself open to zero, and for
        // a multiplication the padded positions are dropped, so zero is correct for both.
        while all.len() < groups * group {
            all.push(RobustShare::new(F::zero(), self.id, 2 * self.threshold));
        }

        self.batch_recon
            .init_batch_reconstruct_many(&all, sid, network)
            .await?;
        Ok(())
    }

    /// DN07 degree reduction: `[xy]_t` from `[x]_t`, `[y]_t` and one double sharing each.
    ///
    /// **Phase: PREPROCESSING.** One degree-`2t` batched opening for the whole batch, no Beaver
    /// triple, no degree-`t` opening.
    ///
    /// `x` and `y` are consumed by value only through `share_mul`, so their own degree labels are
    /// irrelevant to correctness here — what matters is that they really are degree-`t` sharings,
    /// which is the caller's obligation and which PRSS-sourced material discharges by
    /// construction. If either is degree `> t` the product exceeds degree `2t` and the opening
    /// fails to decode, which is a detected abort rather than a wrong value, **except** when the
    /// input was *dealt*: see the warning below.
    ///
    /// # Dealt inputs need a degree test first
    ///
    /// A degree-`2t` opening at `n = 3t+1` imposes *no* codeword constraint on the honest
    /// sub-word: the `2t+1` honest evaluations extend to a unique degree-`2t` polynomial whatever
    /// they are, and the `t` corrupt parties simply send that polynomial's values. So a dealer
    /// that deals `x` at degree `t+1` makes `phi_x·phi_y` degree `2t+1`, a unique degree-`2t`
    /// polynomial agrees with it on all `2t+1` honest points, the opening **succeeds**, no abort
    /// is raised, and the dealer recovers the honest operand `y` in the clear. A degree-`t` Beaver
    /// opening does not have this weakness.
    ///
    /// **Therefore: never feed this node an input that was dealt without a degree-validity
    /// mechanism** — masked dealing, or a batch random-linear-combination degree test (one robust
    /// degree-`t` opening of `sum chi_nu [u_nu] + [mask]` per dealer per batch, assert `deg = t`;
    /// soundness `1/p`). PRSS-sourced and protocol-derived shares are immune because nothing is
    /// dealt: a PRSS share is a deterministic function of keys held by `n − t >= 2t+1` parties and
    /// a corrupt party's only freedom is to lie at an opening, which the code distance catches.
    ///
    /// # Errors
    /// - [`Dn07Error::LengthMismatch`], [`Dn07Error::EmptyInput`], [`Dn07Error::BatchTooLarge`]
    /// - [`Dn07Error::ShareIdMismatch`] if a double sharing is not this party's
    /// - [`Dn07Error::LimitError`] if the session admission cap is reached
    pub async fn init_mul<N: Network + Send + Sync + 'static>(
        &mut self,
        session_id: PreprocessingSessionId,
        x: Vec<RobustShare<F>>,
        y: Vec<RobustShare<F>>,
        doubles: Vec<DoubleShamirShare<F>>,
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

        // [d]_2t = [x]·[y] − [r]_2t
        let mut masked = Vec::with_capacity(x.len());
        for ((xi, yi), ri) in x.iter().zip(y.iter()).zip(r_2t.into_iter()) {
            let product = xi.share_mul(yi)?;
            // `share_mul` labels the product `x.degree + y.degree`; substitute the local constant
            // so the subtraction's degree check compares two protocol constants rather than two
            // pieces of caller metadata.
            let product = RobustShare::new(product.share[0], self.id, 2 * self.threshold);
            masked.push((product - ri)?);
        }

        self.open_2t(session_id, masked, Dn07Task::Reduce { r_t }, network)
            .await
    }

    /// Exact-zero check: asserts `u_i · v_i == 0` for every `i`, with soundness error **0**.
    ///
    /// **Phase: PREPROCESSING** — it opens at degree `2t` and it *aborts* on failure, both of
    /// which are licensed only here.
    ///
    /// The mask is the supplied double sharing's own difference `[r]_2t − [r]_t`, which is a
    /// uniform element of `{h : deg h <= 2t, h(0) = 0}` — the exact space the opening must be
    /// randomised over, and zero at the origin so it does not disturb the value being checked. See
    /// the [module docs](super) for why this is one object rather than a second PRZS draw.
    ///
    /// Typical uses: `v_i = u_i − 1` certifies `u_i ∈ {0,1}` over `F`. Over `Gf2k` the twin uses
    /// `v_i = u_i + 1`; never `u_i · u_i`, because squaring is a bijection in characteristic 2 and
    /// opening `W²` reveals `W` exactly.
    ///
    /// The same dealt-input hazard as [`Self::init_mul`] applies verbatim: a value dealt at degree
    /// `t+1` is recoverable from this opening. Certify dealt inputs before checking them.
    pub async fn init_zero_check<N: Network + Send + Sync + 'static>(
        &mut self,
        session_id: PreprocessingSessionId,
        u: Vec<RobustShare<F>>,
        v: Vec<RobustShare<F>>,
        doubles: Vec<DoubleShamirShare<F>>,
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
            let product = RobustShare::new(product.share[0], self.id, 2 * self.threshold);
            // h = [r]_2t − [r]_t, a degree-2t sharing of zero. `rt` is relabelled to 2t for the
            // subtraction; the *value* is a degree-t evaluation, which is the point — the
            // difference of the two polynomials is what has degree 2t and vanishes at 0.
            let rt_lifted = RobustShare::new(rt.share[0], self.id, 2 * self.threshold);
            let mask = (r2t - rt_lifted)?;
            masked.push((product + mask)?);
        }

        self.open_2t(session_id, masked, Dn07Task::ZeroCheck, network)
            .await
    }

    /// Drains completed batch reconstructions. Call after feeding a `BatchRecon` message whose
    /// session's calling protocol routes here.
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

            // A faster quorum can finish this node's reconstruction before it reaches `init_*`.
            // `k = 0` is never a legal batch size, so it is a safe "not initialised" sentinel.
            let storage_bind = match self.get_or_create_store(sid, self.id, 0).await {
                Some(b) => b,
                None => continue,
            };
            let payload = self.batch_recon.get_store(sid).await?;
            self.finish_from_payload(sid, storage_bind, payload).await?;
        }
        Ok(())
    }

    /// Decodes a completed batch-reconstruction payload and finishes the session, or parks the
    /// raw bytes if `init_*` has not set `k` and the task locally yet.
    async fn finish_from_payload(
        &self,
        session_id: SessionId,
        storage_bind: Arc<Mutex<Dn07Store<RobustShare<F>>>>,
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

        let group = 2 * self.threshold + 1;
        let groups = store.k.div_ceil(group);
        // Bounded by a locally derived expected size, never by a length read off the wire.
        let opened: Vec<F> = deser_bounded_vec(&mut payload.as_slice(), groups * group)?;
        if opened.len() < store.k {
            warn!(?session_id, "DN07: short coefficient vector");
            return Ok(());
        }

        let k = store.k;
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
                let violations = opened
                    .iter()
                    .take(k)
                    .enumerate()
                    .filter_map(|(i, v)| (!v.is_zero()).then_some(i))
                    .collect();
                Dn07Outcome::ZeroCheckViolations(violations)
            }
            // Unreachable: guarded above. Parking rather than panicking keeps an unexpected
            // ordering from taking the node down on an attacker-reachable path.
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

    /// Awaits this session's outcome.
    ///
    /// The `duration` timeout is a **local liveness bound on a synchronous preprocessing round**,
    /// not an online-path timeout: preprocessing is allowed to time a silent party out and abort.
    pub async fn wait_for_result(
        &self,
        session_id: SessionId,
        duration: Duration,
    ) -> Result<Dn07Outcome<RobustShare<F>>, Dn07Error> {
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

    /// [`Self::wait_for_result`] for a session started by [`Self::init_mul`].
    pub async fn wait_for_products(
        &self,
        session_id: SessionId,
        duration: Duration,
    ) -> Result<Vec<RobustShare<F>>, Dn07Error> {
        match self.wait_for_result(session_id, duration).await? {
            Dn07Outcome::Products(p) => Ok(p),
            Dn07Outcome::ZeroCheckViolations(_) => {
                Err(Dn07Error::WrongTask(session_id, "zero-check"))
            }
        }
    }

    /// [`Self::wait_for_result`] for a session started by [`Self::init_zero_check`], collapsed to
    /// pass/fail.
    ///
    /// A failure is an **abort**, and it is a proof of misbehaviour rather than a false positive:
    /// the check has soundness error 0.
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
    use crate::common::share::shamir::NonRobustShare;
    use crate::common::ProtocolSessionId;
    use crate::honeybadger::ProtocolType;
    use ark_bls12_381::Fr;
    use ark_serialize::CanonicalSerialize;
    use stoffelmpc_network::fake_network::{FakeInnerNetwork, FakeNetwork, FakeNetworkConfig};

    fn pre_sid(tag: ProtocolType) -> PreprocessingSessionId {
        pre_sid_at(tag, 7)
    }

    fn pre_sid_at(tag: ProtocolType, exec: u64) -> PreprocessingSessionId {
        PreprocessingSessionId::new(SessionId::new(tag, SessionId::pack_slot(exec, 0, 0), 42))
            .unwrap()
    }

    fn double(v_t: u64, v_2t: u64, id: usize) -> DoubleShamirShare<Fr> {
        // Degrees deliberately wrong on the wire object: `localise` must overwrite them.
        DoubleShamirShare::new(
            NonRobustShare::new(Fr::from(v_t), id, 999),
            NonRobustShare::new(Fr::from(v_2t), id, 999),
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

    #[test]
    fn refuses_degenerate_threshold_and_small_party_counts() {
        assert!(matches!(
            Dn07MulNode::<Fr>::new(0, 5, 0).unwrap_err(),
            Dn07Error::DegenerateThreshold
        ));
        // n = 3 with t = 1 is below 3t+1 = 4.
        assert!(matches!(
            Dn07MulNode::<Fr>::new(0, 3, 1).unwrap_err(),
            Dn07Error::PartyCountTooSmall { n: 3, bound: 4 }
        ));
        assert!(Dn07MulNode::<Fr>::new(0, 4, 1).is_ok());
    }

    #[test]
    fn batch_recon_child_is_pinned_at_degree_2t() {
        let node = Dn07MulNode::<Fr>::new(0, 10, 3).unwrap();
        assert_eq!(
            node.batch_recon.degree, 6,
            "the opening degree is the whole security precondition; it must be 2t"
        );
        assert_eq!(node.max_batch_size(), MAX_DN07_GROUPS * 7);
    }

    #[test]
    fn localise_overwrites_caller_written_degrees() {
        let node = Dn07MulNode::<Fr>::new(3, 10, 3).unwrap();
        let (r_t, r_2t) = node.localise(&[double(11, 22, 3)]).unwrap();
        assert_eq!(
            r_t[0].degree, 3,
            "degree-t label must be the local constant"
        );
        assert_eq!(
            r_2t[0].degree, 6,
            "degree-2t label must be the local constant"
        );
        assert_eq!(r_t[0].share[0], Fr::from(11_u64));
        assert_eq!(r_2t[0].share[0], Fr::from(22_u64));
    }

    #[test]
    fn localise_rejects_a_share_belonging_to_another_party() {
        let node = Dn07MulNode::<Fr>::new(3, 10, 3).unwrap();
        assert!(matches!(
            node.localise(&[double(1, 2, 4)]).unwrap_err(),
            Dn07Error::ShareIdMismatch {
                index: 0,
                expected: 3,
                got: 4
            }
        ));
    }

    #[tokio::test]
    async fn init_mul_rejects_mismatched_and_oversized_input() {
        let (network, _inboxes) = net();
        let mut node = Dn07MulNode::<Fr>::new(0, 5, 1).unwrap();
        let sid = pre_sid(ProtocolType::Dn07);
        let one = vec![RobustShare::new(Fr::from(1_u64), 0, 1)];

        assert!(matches!(
            node.init_mul(
                sid,
                one.clone(),
                vec![],
                vec![double(1, 1, 0)],
                network.clone()
            )
            .await
            .unwrap_err(),
            Dn07Error::LengthMismatch { .. }
        ));
        assert!(matches!(
            node.init_mul(sid, one.clone(), one.clone(), vec![], network.clone())
                .await
                .unwrap_err(),
            Dn07Error::LengthMismatch { .. }
        ));
        assert!(matches!(
            node.init_mul(sid, vec![], vec![], vec![], network.clone())
                .await
                .unwrap_err(),
            Dn07Error::EmptyInput
        ));

        let big = node.max_batch_size() + 1;
        let xs = vec![RobustShare::new(Fr::from(1_u64), 0, 1); big];
        let ds = vec![double(1, 1, 0); big];
        assert!(matches!(
            node.init_mul(sid, xs.clone(), xs, ds, network.clone())
                .await
                .unwrap_err(),
            Dn07Error::BatchTooLarge { .. }
        ));
    }

    /// The early-reconstruction race: a `2t+1` quorum finishes this node's own reconstruction
    /// before it reaches `init_mul`. Without the parking path the payload would be decoded
    /// against `k = 0` and silently dropped, and `wait_for_products` would time out on a value
    /// that had already been correctly reconstructed.
    #[tokio::test]
    async fn buffers_a_reconstruction_that_finishes_before_local_init() {
        let (network, _inboxes) = net();
        let mut node = Dn07MulNode::<Fr>::new(0, 5, 1).unwrap();
        let sid = pre_sid(ProtocolType::Triple);

        // t = 1, so the group is 2t+1 = 3.
        let opened = vec![Fr::from(10_u64), Fr::from(20_u64), Fr::from(30_u64)];
        let mut payload = Vec::new();
        opened.serialize_compressed(&mut payload).unwrap();

        let bind = node.get_or_create_store(sid.get(), 0, 0).await.unwrap();
        node.finish_from_payload(sid.get(), bind.clone(), payload.clone())
            .await
            .unwrap();
        {
            let store = bind.lock().await;
            assert_eq!(store.state, Dn07State::Running);
            assert_eq!(
                store.pending_batch_recon_payload.as_deref(),
                Some(payload.as_slice())
            );
        }

        let x = vec![RobustShare::new(Fr::from(2_u64), 0, 1); 3];
        let doubles = vec![double(5, 7, 0); 3];
        node.init_mul(sid, x.clone(), x, doubles, network.clone())
            .await
            .unwrap();

        let products = node
            .wait_for_products(sid.get(), Duration::from_secs(1))
            .await
            .unwrap();
        // [xy]_t = [r]_t + d, with [r]_t = 5 and d = 10 / 20 / 30.
        assert_eq!(
            products.iter().map(|p| p.share[0]).collect::<Vec<_>>(),
            vec![Fr::from(15_u64), Fr::from(25_u64), Fr::from(35_u64)]
        );
        assert_eq!(
            products[0].degree, 1,
            "the product must be labelled degree t"
        );
        assert!(bind.lock().await.pending_batch_recon_payload.is_none());
    }

    #[tokio::test]
    async fn zero_check_passes_on_zeroes_and_names_the_failing_index() {
        let (network, _inboxes) = net();
        let mut node = Dn07MulNode::<Fr>::new(0, 5, 1).unwrap();

        for (exec, opened, expected) in [
            (100u64, vec![Fr::from(0_u64); 3], None),
            (
                101u64,
                vec![Fr::from(0_u64), Fr::from(9_u64), Fr::from(0_u64)],
                Some(1usize),
            ),
        ] {
            // A distinct exec id per iteration: `clear_store` *retires* a session, and a retired
            // session is refused on re-admission — which is the anti-replay behaviour we want, so
            // the test works around it rather than weakening it.
            let sid = pre_sid_at(ProtocolType::DaBitMul, exec);
            let mut payload = Vec::new();
            opened.serialize_compressed(&mut payload).unwrap();

            let u = vec![RobustShare::new(Fr::from(1_u64), 0, 1); 3];
            let v = vec![RobustShare::new(Fr::from(0_u64), 0, 1); 3];
            node.init_zero_check(sid, u, v, vec![double(4, 4, 0); 3], network.clone())
                .await
                .unwrap();

            let bind = node.get_or_create_store(sid.get(), 0, 3).await.unwrap();
            node.finish_from_payload(sid.get(), bind, payload)
                .await
                .unwrap();

            let outcome = node
                .wait_for_zero_check(sid.get(), Duration::from_secs(1))
                .await;
            match expected {
                None => assert!(outcome.is_ok(), "all-zero opening must pass"),
                Some(i) => assert!(
                    matches!(outcome, Err(Dn07Error::ZeroCheckFailed { index }) if index == i),
                    "expected a failure at index {i}, got {outcome:?}"
                ),
            }
            node.clear_store(sid.get()).await;
        }
    }

    #[tokio::test]
    async fn the_two_tasks_do_not_answer_each_other() {
        let (network, _inboxes) = net();
        let mut node = Dn07MulNode::<Fr>::new(0, 5, 1).unwrap();
        let sid = pre_sid(ProtocolType::Dn07);
        let mut payload = Vec::new();
        vec![Fr::from(0_u64); 3]
            .serialize_compressed(&mut payload)
            .unwrap();

        let u = vec![RobustShare::new(Fr::from(1_u64), 0, 1); 3];
        node.init_zero_check(sid, u.clone(), u, vec![double(4, 4, 0); 3], network.clone())
            .await
            .unwrap();
        let bind = node.get_or_create_store(sid.get(), 0, 3).await.unwrap();
        node.finish_from_payload(sid.get(), bind, payload)
            .await
            .unwrap();

        assert!(matches!(
            node.wait_for_products(sid.get(), Duration::from_secs(1))
                .await
                .unwrap_err(),
            Dn07Error::WrongTask(_, "zero-check")
        ));
    }

    #[tokio::test]
    async fn zero_check_mask_is_the_double_sharings_own_difference() {
        // The masked share opened at 2t is share_mul(u, v) + ([r]_2t − [r]_t); with u·v = 6 and
        // (r_t, r_2t) = (5, 7) this node's contribution is 6 + (7 − 5) = 8. The test reaches into
        // the algebra rather than the wire, because the property that matters is that the mask is
        // a *difference* and therefore vanishes at the origin — a second, independent draw would
        // not.
        let node = Dn07MulNode::<Fr>::new(0, 5, 1).unwrap();
        let (r_t, r_2t) = node.localise(&[double(5, 7, 0)]).unwrap();
        let u = RobustShare::new(Fr::from(2_u64), 0, 1);
        let v = RobustShare::new(Fr::from(3_u64), 0, 1);
        let product = u.share_mul(&v).unwrap();
        let product = RobustShare::new(product.share[0], 0, 2);
        let lifted = RobustShare::new(r_t[0].share[0], 0, 2);
        let masked = (product + (r_2t[0].clone() - lifted).unwrap()).unwrap();
        assert_eq!(masked.share[0], Fr::from(8_u64));
        assert_eq!(masked.degree, 2);
    }

    /// What forgetting [`Dn07MulNode::clear_store`] actually costs, in the units the node
    /// measures: one admission slot, permanently.
    ///
    /// `clear_store` is the **caller's** obligation — the node never retires a session on its own,
    /// not on success and not on timeout — so the only thing standing between a forgetful caller
    /// and a wedged node is a test that notices. This is that test, written at the quota rather
    /// than at the store length, because the quota is the consequence: `MAX_DN07_SESSIONS / n`
    /// sessions per initiator, which at `n = 256` is exactly one. A completed-but-uncleared
    /// session holds it forever (the TTL sweep reclaims it only after `session_ttl()`, and a
    /// caller in a loop does not wait that long), so the *next* session this node issues to
    /// itself is refused and its `wait_for_products` then blocks until timeout.
    ///
    /// The production callers — `HoneyBadgerMPCNode::generate_triples_via_dn07` and
    /// `EdaBitFilterNode::mul_k` — both clear on every exit path including the failure one, and
    /// `beaver_triples_leave_no_dn07_session_resident` / the edaBit filter's
    /// `every_session_is_retired_when_the_run_returns` check the end state of each. This checks
    /// the mechanism they depend on.
    #[tokio::test]
    async fn a_session_left_uncleared_costs_the_next_one_its_admission_slot() {
        // Per-peer quota = MAX_DN07_SESSIONS / n = 256 / 256 = 1.
        let node = Dn07MulNode::<Fr>::new(0, MAX_DN07_SESSIONS, 1).unwrap();
        let first = pre_sid_at(ProtocolType::Dn07, 1).get();
        let second = pre_sid_at(ProtocolType::Dn07, 2).get();

        assert!(node.get_or_create_store(first, 0, 3).await.is_some());
        assert!(
            node.get_or_create_store(second, 0, 3).await.is_none(),
            "the uncleared first session must still be holding the only slot"
        );
        assert_eq!(node.store_len().await, 1);

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
        let mut node = Dn07MulNode::<Fr>::new(0, 5, 1).unwrap();
        let sid = pre_sid(ProtocolType::Dn07);
        let x = vec![RobustShare::new(Fr::from(2_u64), 0, 1); 3];
        node.init_mul(sid, x.clone(), x, vec![double(1, 1, 0); 3], network.clone())
            .await
            .unwrap();
        assert_eq!(node.store_len().await, 1);
        assert!(node.clear_store(sid.get()).await);
        assert_eq!(node.store_len().await, 0);
        assert_eq!(node.batch_recon.store_len().await, 0);
        // Retirement is sticky: a cleared session is refused on re-admission rather than
        // resurrected, so a late or replayed message cannot reopen it.
        assert!(node.get_or_create_store(sid.get(), 0, 3).await.is_none());
    }
}
