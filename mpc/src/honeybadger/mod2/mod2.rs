//! One batched degree-`t` opening plus local affine work. See the [module docs](super).

use std::sync::Arc;
use std::time::Instant;

use ark_ff::{BigInteger, PrimeField};
use stoffelnet::network_utils::{Network, PartyId};
use tokio::sync::mpsc::Receiver;
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};
use tracing::warn;

use crate::common::session_store::{Admission, SessionStore};
use crate::common::utils::deser_bounded_vec;
use crate::common::ProtocolSessionId;
use crate::honeybadger::batch_recon::batch_recon::BatchReconNode;
use crate::honeybadger::mod2::{
    Mod2Error, Mod2State, Mod2Store, MAX_MOD2_GROUPS, MAX_MOD2_SESSIONS,
};
use crate::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use crate::honeybadger::SessionId;

/// Parity extraction: one degree-`t` batched opening, zero multiplications, soundness error 0.
///
/// # Phase
///
/// Phase-agnostic by construction: the one [`BatchReconNode`] this node owns is pinned at
/// `degree = threshold` in [`Mod2Node::new`] and never reconfigured, so nothing here can put a
/// degree-`2t` opening on any path. Its consumer carries the phase; today that consumer is
/// PREPROCESSING (PRSS daBit generation).
#[derive(Clone, Debug)]
pub struct Mod2Node<F: PrimeField> {
    pub id: PartyId,
    pub n_parties: usize,
    pub threshold: usize,
    pub store: Arc<Mutex<SessionStore<SessionId, (usize, Instant, Arc<Mutex<Mod2Store<F>>>)>>>,
    /// Pinned at `degree = t`. Robust, asynchronous, no abort.
    pub open: BatchReconNode<F>,
    pub open_output: Arc<Mutex<Receiver<SessionId>>>,
}

impl<F: PrimeField> Mod2Node<F> {
    /// # Errors
    /// - [`Mod2Error::DegenerateThreshold`] for `t == 0`: a degree-`0` sharing is a constant, so
    ///   the opening would reveal `S`, `r''` and `r'_0` outright. A `warn!` here would be the
    ///   `l`/`kappa` misconfiguration class this repo has already shipped once; it is a hard
    ///   error.
    /// - [`Mod2Error::PartyCountTooSmall`] for `n < 3t+1`: below the Byzantine bound the degree-
    ///   `t` opening's error correction (`degree + t + 1 + r <= n`) is no longer reachable for
    ///   `r <= t`, so the opening stops being robust and the "no agreement round is needed"
    ///   argument for the public branch on `c_0` fails with it.
    pub fn new(id: PartyId, n_parties: usize, threshold: usize) -> Result<Self, Mod2Error> {
        if threshold == 0 {
            return Err(Mod2Error::DegenerateThreshold);
        }
        if n_parties < 3 * threshold + 1 {
            return Err(Mod2Error::PartyCountTooSmall {
                n: n_parties,
                bound: 3 * threshold + 1,
            });
        }
        let (open_sender, open_receiver) = tokio::sync::mpsc::channel(200);
        // degree = t, NOT 2t. The single line this module's whole robustness argument rests on.
        let open = BatchReconNode::new(id, n_parties, threshold, threshold, open_sender)?;
        Ok(Self {
            id,
            n_parties,
            threshold,
            store: Arc::new(Mutex::new(SessionStore::with_default_cap())),
            open,
            open_output: Arc::new(Mutex::new(open_receiver)),
        })
    }

    /// Largest number of secrets one [`Self::init`] call may open.
    ///
    /// Callers chunk against this rather than reimplementing the `t+1` group arithmetic.
    pub fn max_batch_size(&self) -> usize {
        MAX_MOD2_GROUPS * (self.threshold + 1)
    }

    /// Number of live Mod2 sessions. Used by the node's preprocessing trace.
    pub async fn store_len(&self) -> usize {
        self.store.lock().await.len()
    }

    /// Retires this session here and in the batch-reconstruction child.
    ///
    /// Call it on the **failure** path as well as on success: a timed-out session still holds a
    /// store entry and a batch-recon store entry, and both count against the admission caps.
    pub async fn clear_store(&self, session_id: SessionId) -> bool {
        self.open.clear_store(session_id).await;
        self.store.lock().await.retire(session_id)
    }

    pub async fn get_or_create_store(
        &self,
        session_id: SessionId,
        initiator_id: usize,
        k: usize,
    ) -> Option<Arc<Mutex<Mod2Store<F>>>> {
        match self.store.lock().await.get_or_admit(
            session_id,
            initiator_id,
            MAX_MOD2_SESSIONS,
            // `.max(1)`: with `n > MAX_MOD2_SESSIONS` the integer quotient is zero, which would
            // reject every session including this node's own.
            (MAX_MOD2_SESSIONS / self.n_parties).max(1),
            || Arc::new(Mutex::new(Mod2Store::new(k))),
        ) {
            Admission::Got(arc) => Some(arc),
            Admission::Retired => None,
            Admission::Rejected => {
                warn!("Mod2 session limit reached");
                None
            }
        }
    }

    /// Rebuilds a supplied share against this node's *local* degree constant, checking only the
    /// one label there is no constant to substitute for.
    fn localise(&self, shares: &[RobustShare<F>]) -> Result<Vec<RobustShare<F>>, Mod2Error> {
        let mut out = Vec::with_capacity(shares.len());
        for (index, share) in shares.iter().enumerate() {
            if share.id != self.id {
                return Err(Mod2Error::ShareIdMismatch {
                    index,
                    expected: self.id,
                    got: share.id,
                });
            }
            out.push(RobustShare::new(share.share[0], self.id, self.threshold));
        }
        Ok(out)
    }

    /// Starts one parity extraction over `count = value.len()` secrets.
    ///
    /// * `value` — `[S]_F`, degree-`t` sharings of small non-negative **integers**.
    /// * `mask` — `[r'']_F`, the statistical mask. It is doubled here, so the caller sizes it
    ///   against `2·r''` and owns the no-wrap inequality.
    /// * `rand_bits` — `[r'_0]_F`, one certified random bit per secret. Parked for the
    ///   public-affine step, and **never** used as anything else.
    ///
    /// The opened `c` is `S + 2r'' + r'_0`. Its parity is the answer only while that sum does not
    /// wrap `p`: `p` is odd, so a single wrap flips the extracted bit. Enforcing that is the
    /// caller's obligation and it cannot be checked here — a wrapped `c` is an ordinary field
    /// element with nothing wrong with it.
    ///
    /// # Errors
    /// - [`Mod2Error::LengthMismatch`], [`Mod2Error::EmptyInput`], [`Mod2Error::BatchTooLarge`]
    /// - [`Mod2Error::ShareIdMismatch`] if any share is not this party's
    /// - [`Mod2Error::MissingCallingProtocol`] / [`Mod2Error::MalformedSessionId`]
    /// - [`Mod2Error::LimitError`] if the session admission cap is reached
    pub async fn init<N: Network + Send + Sync + 'static>(
        &mut self,
        session_id: SessionId,
        value: Vec<RobustShare<F>>,
        mask: Vec<RobustShare<F>>,
        rand_bits: Vec<RobustShare<F>>,
        network: Arc<N>,
    ) -> Result<(), Mod2Error> {
        if session_id.calling_protocol().is_none() {
            return Err(Mod2Error::MissingCallingProtocol(session_id));
        }
        if session_id.sub_id() != 0 || session_id.round_id() != 0 {
            return Err(Mod2Error::MalformedSessionId(session_id));
        }
        if value.is_empty() {
            return Err(Mod2Error::EmptyInput);
        }
        if mask.len() != value.len() {
            return Err(Mod2Error::LengthMismatch {
                what: "statistical masks",
                expected: value.len(),
                got: mask.len(),
            });
        }
        if rand_bits.len() != value.len() {
            return Err(Mod2Error::LengthMismatch {
                what: "random bits",
                expected: value.len(),
                got: rand_bits.len(),
            });
        }
        if value.len() > self.max_batch_size() {
            return Err(Mod2Error::BatchTooLarge {
                requested: value.len(),
                max: self.max_batch_size(),
            });
        }

        let value = self.localise(&value)?;
        let mask = self.localise(&mask)?;
        let rand_bits = self.localise(&rand_bits)?;

        // [c] = [S] + 2·[r''] + [r'_0]. Purely local; no multiplication, no round.
        let two = F::one() + F::one();
        let mut masked = Vec::with_capacity(value.len());
        for ((s, m), r0) in value.into_iter().zip(mask).zip(rand_bits.iter()) {
            let doubled = (m * two)?;
            masked.push(((s + doubled)? + r0.clone())?);
        }

        let k = masked.len();
        let storage_bind = match self.get_or_create_store(session_id, self.id, k).await {
            Some(s) => s,
            None => return Err(Mod2Error::LimitError),
        };

        // Set `k` and park the bits, then atomically claim a reconstruction result that arrived
        // before this call — a `t+1` quorum can finish this node's own reconstruction before it
        // reaches `init`.
        let pending = {
            let mut store = storage_bind.lock().await;
            store.k = k;
            store.rand_bits = Some(rand_bits);
            store.pending_batch_recon_payload.take()
        };
        if let Some(payload) = pending {
            self.finish_from_payload(session_id, storage_bind.clone(), payload)
                .await?;
            if storage_bind.lock().await.state == Mod2State::Finished {
                // Already have the result — skip the redundant network round.
                return Ok(());
            }
        }

        let group = self.threshold + 1;
        let groups = k.div_ceil(group);
        let mut all = masked;
        // Pad with the constant-zero degree-`t` sharing: every party contributes `0`, so the
        // padded positions open to `0` and are dropped below.
        while all.len() < groups * group {
            all.push(RobustShare::new(F::zero(), self.id, self.threshold));
        }

        self.open
            .init_batch_reconstruct_many(&all, session_id, network)
            .await?;
        Ok(())
    }

    /// Drains completed batch reconstructions. Call after feeding a `BatchRecon` message whose
    /// session's calling protocol routes here.
    pub async fn drain_open_output(&mut self) -> Result<(), Mod2Error> {
        loop {
            let sid = {
                let mut rx = self.open_output.lock().await;
                match rx.try_recv() {
                    Ok(id) => id,
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        return Err(Mod2Error::Abort)
                    }
                }
            };

            // A faster quorum can finish this node's reconstruction before it reaches `init`.
            // `k = 0` is never a legal batch size, so it is a safe "not initialised" sentinel.
            let storage_bind = match self.get_or_create_store(sid, self.id, 0).await {
                Some(b) => b,
                None => continue,
            };
            let payload = self.open.get_store(sid).await?;
            self.finish_from_payload(sid, storage_bind, payload).await?;
        }
        Ok(())
    }

    /// Decodes a completed opening and applies the public-affine step, or parks the raw bytes if
    /// `init` has not set `k` and the bits locally yet.
    async fn finish_from_payload(
        &self,
        session_id: SessionId,
        storage_bind: Arc<Mutex<Mod2Store<F>>>,
        payload: Vec<u8>,
    ) -> Result<(), Mod2Error> {
        let mut store = storage_bind.lock().await;
        if store.state == Mod2State::Finished {
            return Ok(());
        }
        if store.k == 0 || store.rand_bits.is_none() {
            store.pending_batch_recon_payload = Some(payload);
            return Ok(());
        }

        let group = self.threshold + 1;
        let groups = store.k.div_ceil(group);
        // Bounded by a locally derived expected size, never by a length read off the wire.
        let opened: Vec<F> = deser_bounded_vec(&mut payload.as_slice(), groups * group)?;
        if opened.len() < store.k {
            warn!(?session_id, "Mod2: short coefficient vector");
            return Ok(());
        }

        let k = store.k;
        // `take`, so a duplicate delivery cannot consume the same bits twice.
        let rand_bits = match store.rand_bits.take() {
            Some(bits) => bits,
            // Unreachable: guarded above. Parking rather than panicking keeps an unexpected
            // ordering from taking the node down on an attacker-reachable path.
            None => {
                store.pending_batch_recon_payload = Some(payload);
                return Ok(());
            }
        };
        if rand_bits.len() != k {
            return Err(Mod2Error::LengthMismatch {
                what: "parked random bits",
                expected: k,
                got: rand_bits.len(),
            });
        }

        let mut bits = Vec::with_capacity(k);
        for (r0, c) in rand_bits.into_iter().zip(opened.iter().take(k)) {
            // `c_0 = c mod 2` on the canonical representative in `[0, p)`.
            //
            // `into_bigint` is the representative, not the Montgomery limb: taking the parity of
            // the internal representation instead would be a silent, field-dependent wrong
            // answer that every all-honest test still passes.
            let c0 = c.into_bigint().is_odd();
            // `c_0 + (1 − 2c_0)·[r'_0]`, i.e. `c_0 XOR r'_0`. Public-affine, so the result is a
            // genuine degree-`t` sharing of a genuine bit by provenance: `from_scalar_sub`
            // preserves `id` and `degree`, and `r'_0`'s bit-ness came free from `RandBit`.
            bits.push(if c0 {
                RobustShare::from_scalar_sub(F::one(), &r0)
            } else {
                r0
            });
        }

        store.state = Mod2State::Finished;
        if let Some(tx) = store.output_sender.take() {
            tx.send(bits)
                .map_err(|_| Mod2Error::SendError(session_id))?;
        }
        Ok(())
    }

    /// Awaits this session's extracted bits, in input order.
    ///
    /// `duration` is the **caller's** liveness bound. This node's opening is robust and
    /// asynchronous — it cannot be aborted by a peer — so a timeout here means the local message
    /// pump is not running, not that the protocol failed.
    pub async fn wait_for_bits(
        &self,
        session_id: SessionId,
        duration: Duration,
    ) -> Result<Vec<RobustShare<F>>, Mod2Error> {
        let rx = {
            let storage = self.store.lock().await;
            let (_, _, bind) = storage
                .get(&session_id)
                .ok_or(Mod2Error::NoSuchSession(session_id))?;
            let mut store = bind.lock().await;
            store
                .output_receiver
                .take()
                .ok_or(Mod2Error::ResultAlreadyReceived(session_id))?
        };
        match timeout(duration, rx).await {
            Err(_) => Err(Mod2Error::Timeout(session_id)),
            Ok(Err(_)) => Err(Mod2Error::ReceiveError(session_id)),
            Ok(Ok(bits)) => Ok(bits),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::math::goldilocks::GoldilocksField;
    use crate::common::SecretSharingScheme;
    use crate::honeybadger::ProtocolType;
    use ark_ff::{One, Zero};
    use ark_serialize::CanonicalSerialize;
    use stoffelmpc_network::fake_network::{FakeInnerNetwork, FakeNetwork, FakeNetworkConfig};

    type F = GoldilocksField;

    fn sid(exec: u64) -> SessionId {
        SessionId::new(
            ProtocolType::DaBitOpen,
            SessionId::pack_slot(exec, 0, 0),
            42,
        )
    }

    /// The inboxes are returned alongside the network and must be kept alive by the caller: a
    /// `FakeNetwork` whose receivers have been dropped fails every `send` with `SendError`.
    type Inboxes = Vec<Vec<tokio::sync::mpsc::Receiver<Vec<u8>>>>;

    fn net(n: usize) -> (Arc<FakeNetwork>, Inboxes) {
        let (inner, inboxes, _) = FakeInnerNetwork::new(n, None, FakeNetworkConfig::new(10));
        (Arc::new(FakeNetwork::new(0, inner)), inboxes)
    }

    fn share(v: u64, id: usize, degree: usize) -> RobustShare<F> {
        RobustShare::new(F::from(v), id, degree)
    }

    #[test]
    fn refuses_degenerate_threshold_and_small_party_counts() {
        assert!(matches!(
            Mod2Node::<F>::new(0, 10, 0),
            Err(Mod2Error::DegenerateThreshold)
        ));
        assert!(matches!(
            Mod2Node::<F>::new(0, 9, 3),
            Err(Mod2Error::PartyCountTooSmall { n: 9, bound: 10 })
        ));
        assert!(Mod2Node::<F>::new(0, 10, 3).is_ok());
    }

    /// The child is pinned at degree `t` at construction. If this ever reads `2 * threshold` the
    /// module's whole robustness argument is void, so it is pinned by a test rather than by a
    /// comment.
    #[test]
    fn the_opening_child_is_pinned_at_degree_t() {
        let node = Mod2Node::<F>::new(1, 13, 4).unwrap();
        assert_eq!(node.open.degree, 4);
        assert_eq!(node.open.t, 4);
    }

    #[tokio::test]
    async fn init_rejects_mismatched_lengths_and_foreign_share_ids() {
        let (network, _inboxes) = net(10);
        let mut node = Mod2Node::<F>::new(0, 10, 3).unwrap();

        assert!(matches!(
            node.init(sid(1), vec![], vec![], vec![], network.clone())
                .await,
            Err(Mod2Error::EmptyInput)
        ));
        assert!(matches!(
            node.init(
                sid(2),
                vec![share(1, 0, 3)],
                vec![],
                vec![share(0, 0, 3)],
                network.clone()
            )
            .await,
            Err(Mod2Error::LengthMismatch {
                what: "statistical masks",
                ..
            })
        ));
        assert!(matches!(
            node.init(
                sid(3),
                vec![share(1, 0, 3)],
                vec![share(0, 0, 3)],
                vec![],
                network.clone()
            )
            .await,
            Err(Mod2Error::LengthMismatch {
                what: "random bits",
                ..
            })
        ));
        // A share carrying someone else's evaluation point is the one label with no local
        // constant to substitute, so it is rejected rather than overwritten.
        assert!(matches!(
            node.init(
                sid(4),
                vec![share(1, 7, 3)],
                vec![share(0, 0, 3)],
                vec![share(0, 0, 3)],
                network.clone()
            )
            .await,
            Err(Mod2Error::ShareIdMismatch {
                index: 0,
                expected: 0,
                got: 7
            })
        ));
    }

    #[tokio::test]
    async fn init_rejects_a_non_root_session_id() {
        let (network, _inboxes) = net(10);
        let mut node = Mod2Node::<F>::new(0, 10, 3).unwrap();
        let child = SessionId::new(ProtocolType::DaBitOpen, SessionId::pack_slot(1, 1, 0), 42);
        assert!(matches!(
            node.init(
                child,
                vec![share(1, 0, 3)],
                vec![share(0, 0, 3)],
                vec![share(0, 0, 3)],
                network
            )
            .await,
            Err(Mod2Error::MalformedSessionId(_))
        ));
    }

    #[tokio::test]
    async fn a_batch_above_the_session_ceiling_is_refused() {
        let (network, _inboxes) = net(10);
        let mut node = Mod2Node::<F>::new(0, 10, 3).unwrap();
        let over = node.max_batch_size() + 1;
        let v = vec![share(0, 0, 3); over];
        assert!(matches!(
            node.init(sid(5), v.clone(), v.clone(), v, network).await,
            Err(Mod2Error::BatchTooLarge { .. })
        ));
    }

    /// The public-affine step, end to end, on a locally faked opening.
    ///
    /// Drives the node's own decode path with a hand-built batch-reconstruction payload so the
    /// `c_0 = c mod 2` and `c_0 XOR r'_0` arithmetic is exercised without a network. `n = 1`
    /// "shares" are the clear values themselves, so the share arithmetic *is* the secret
    /// arithmetic.
    #[tokio::test]
    async fn parity_extraction_is_c0_xor_r0() {
        let node = Mod2Node::<F>::new(0, 10, 3).unwrap();

        // A retired session id is never re-admitted, so each case gets its own.
        for (case, (c, r0, expected)) in [
            (4u64, 0u64, 0u64), // c_0 = 0 -> b = r'_0 = 0
            (4, 1, 1),          // c_0 = 0 -> b = r'_0 = 1
            (5, 0, 1),          // c_0 = 1 -> b = 1 - 0 = 1
            (5, 1, 0),          // c_0 = 1 -> b = 1 - 1 = 0
        ]
        .into_iter()
        .enumerate()
        {
            let session_id = sid(100 + case as u64);
            let bind = node
                .get_or_create_store(session_id, 0, 1)
                .await
                .expect("admitted");
            {
                let mut store = bind.lock().await;
                store.k = 1;
                store.rand_bits = Some(vec![share(r0, 0, 3)]);
            }

            let group = node.threshold + 1;
            let mut opened = vec![F::from(c)];
            opened.resize(group, F::zero());
            let mut payload = Vec::new();
            opened.serialize_compressed(&mut payload).unwrap();

            node.finish_from_payload(session_id, bind, payload)
                .await
                .unwrap();
            let bits = node
                .wait_for_bits(session_id, Duration::from_millis(50))
                .await
                .unwrap();
            assert_eq!(bits.len(), 1);
            assert_eq!(bits[0].share[0], F::from(expected), "c={c} r0={r0}");
            assert_eq!(bits[0].degree, 3);
            assert_eq!(bits[0].id, 0);
            assert!(node.clear_store(session_id).await);
        }
    }

    /// A `t+1` quorum can finish this node's own reconstruction *before* it reaches `init`, so a
    /// payload that arrives early is parked and claimed atomically by `init`.
    ///
    /// Without that claim the result is delivered into a store whose `rand_bits` are not set yet,
    /// the session never completes, and `wait_for_bits` times out — a liveness failure a peer can
    /// cause simply by being fast.
    #[tokio::test]
    async fn a_reconstruction_that_arrives_before_init_is_claimed_not_lost() {
        let (network, _inboxes) = net(10);
        let mut node = Mod2Node::<F>::new(0, 10, 3).unwrap();
        let session_id = sid(200);

        // A peer's traffic reaches the store before this node has called `init`.
        let bind = node
            .get_or_create_store(session_id, 0, 0)
            .await
            .expect("admitted");
        let group = node.threshold + 1;
        let mut opened = vec![F::from(5u64)];
        opened.resize(group, F::zero());
        let mut payload = Vec::new();
        opened.serialize_compressed(&mut payload).unwrap();
        node.finish_from_payload(session_id, bind.clone(), payload)
            .await
            .unwrap();
        // Parked, not applied: `k` is still the "not initialised here" sentinel.
        assert!(bind.lock().await.pending_batch_recon_payload.is_some());
        assert_eq!(bind.lock().await.state, Mod2State::Running);

        node.init(
            session_id,
            vec![share(0, 0, 3)],
            vec![share(0, 0, 3)],
            vec![share(1, 0, 3)],
            network,
        )
        .await
        .unwrap();

        // `c = 5` is odd, so `b = 1 - r'_0 = 0`, and it is available with no network round.
        assert_eq!(bind.lock().await.state, Mod2State::Finished);
        let bits = node
            .wait_for_bits(session_id, Duration::from_millis(50))
            .await
            .unwrap();
        assert_eq!(bits.len(), 1);
        assert_eq!(bits[0].share[0], F::zero());
    }

    /// The whole primitive at `n = 10, t = 3`, with real Shamir sharings and a real
    /// reconstruction, but the opening done locally. `S` is the integer sum a PRSS draw would
    /// give; the extracted bit must be `S mod 2` for both parities of `S` and both values of
    /// `r'_0`.
    #[tokio::test]
    async fn extracted_bit_reconstructs_to_the_parity_of_the_value() {
        let (n, t) = (10usize, 3usize);
        let mut rng = ark_std::test_rng();

        for s in [0u64, 1, 6, 7, 120, 121] {
            for r0 in [0u64, 1] {
                // Fresh degree-`t` sharings of S, of a mask, and of the bit.
                let s_shares =
                    RobustShare::<F>::compute_shares(F::from(s), n, t, None, &mut rng).unwrap();
                let mask = RobustShare::<F>::compute_shares(F::from(1234u64), n, t, None, &mut rng)
                    .unwrap();
                let r0_shares =
                    RobustShare::<F>::compute_shares(F::from(r0), n, t, None, &mut rng).unwrap();

                // Each party's local [c]; open by reconstruction rather than over a network.
                let two: F = F::one() + F::one();
                let c_shares: Vec<RobustShare<F>> = (0..n)
                    .map(|i| {
                        let doubled: RobustShare<F> = (mask[i].clone() * two).unwrap();
                        ((s_shares[i].clone() + doubled).unwrap() + r0_shares[i].clone()).unwrap()
                    })
                    .collect();
                let (_, c) = RobustShare::<F>::recover_secret(&c_shares, n, t).unwrap();
                let c0 = c.into_bigint().is_odd();

                // The public-affine step, at every party.
                let bits: Vec<RobustShare<F>> = (0..n)
                    .map(|i| {
                        if c0 {
                            RobustShare::from_scalar_sub(F::one(), &r0_shares[i])
                        } else {
                            r0_shares[i].clone()
                        }
                    })
                    .collect();
                let (_, b) = RobustShare::<F>::recover_secret(&bits, n, t).unwrap();
                assert_eq!(
                    b,
                    F::from(s % 2),
                    "S={s} r0={r0}: extracted bit is not the parity"
                );
            }
        }
    }
}
