use crate::{
    common::{
        session_store::{Admission, SessionStore},
        share::ShareError,
        ProtocolSessionId, RBC,
    },
    honeybadger::{
        fpmul::{
            build_all_f_polys, PRandIntCommitMessage, PRandIntError, PRandIntMessage,
            PRandIntStore, PrandState, PRANDINT_COMMIT_LEN, PRANDINT_NONCE_LEN,
        },
        prss::{
            prss::{all_tsets, derive_key_from_riss, PrssKeys},
            PRSS_KEY_LEN,
        },
        robust_interpolate::robust_interpolate::RobustShare,
        ProtocolType, SessionId, WrappedMessage, MAX_MESSAGE_SIZE,
    },
};
use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain, Polynomial};
use ark_std::rand::{Rng, SeedableRng};
use bincode::Options;
use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Arc, time::Instant};
use stoffelnet::network_utils::Network;
use tokio::{
    sync::Mutex,
    time::{timeout, Duration},
};
use tracing::{info, warn};

/// Generates PRandInt shares: a random field element replicated-secret-shared (RISS) over the
/// maximal unqualified sets, following the distributed generation protocol.
///
/// `G` is the field the generated shares live in.
#[derive(Debug, Clone)]
pub struct PRandIntNode<G: PrimeField, R: RBC> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    pub store: Arc<Mutex<SessionStore<SessionId, (usize, Instant, Arc<Mutex<PRandIntStore<G>>>)>>>,
    /// PRSS key material. When present, `generate_prss` derives masks locally and the whole RISS
    /// message path below goes unused. Absent until a key setup has run.
    prss: Option<PrssKeys<G>>,
    /// Rank of each unqualified set in `all_tsets(n, t)`, built once at construction.
    /// `Arc` because the node is cloned per message task; the map itself is immutable.
    tset_ranks: Arc<HashMap<Vec<usize>, usize>>,
    pub rbc: R,
    pub rbc_output: Arc<Mutex<tokio::sync::mpsc::Receiver<SessionId>>>,
}

const MAX_PRAND_SESSIONS: usize = 512;

impl<G, R> PRandIntNode<G, R>
where
    G: PrimeField,
    R: RBC<Id = SessionId>,
{
    /// Creates a new PRandIntNode with empty shares.
    pub fn new(id: usize, n: usize, t: usize, k: usize) -> Result<Self, PRandIntError> {
        let (rbc_sender, rbc_receiver) = tokio::sync::mpsc::channel(200);
        let rbc = R::new(id, n, t, k, rbc_sender, Arc::new(WrappedMessage::rbc_wrap))?;
        let tset_ranks = all_tsets(n, t)
            .into_iter()
            .enumerate()
            .map(|(rank, tset)| (tset, rank))
            .collect();
        Ok(Self {
            id,
            n,
            t,
            store: Arc::new(Mutex::new(SessionStore::with_default_cap())),
            prss: None,
            rbc,
            rbc_output: Arc::new(Mutex::new(rbc_receiver)),
            tset_ranks: Arc::new(tset_ranks),
        })
    }

    /// Installs PRSS key material, switching mask generation from RISS to local derivation.
    pub fn install_prss_keys(&mut self, keys: PrssKeys<G>) {
        self.prss = Some(keys);
    }

    pub fn has_prss_keys(&self) -> bool {
        self.prss.is_some()
    }

    /// Position of `tset` in `all_tsets(n, t)`. Rejects anything that is not a real unqualified
    /// set, which is what keeps a peer from addressing a commitment slot that does not exist.
    fn rank_of(&self, tset: &[usize]) -> Result<usize, PRandIntError> {
        self.tset_ranks.get(tset).copied().ok_or_else(|| {
            PRandIntError::InvalidMessage(format!("unrecognised unqualified set {tset:?}"))
        })
    }

    /// Largest mask width this node can derive without the summed value wrapping the field.
    ///
    /// The secret is the sum over **all** `C(n,t)` sets, so it reaches `C(n,t) · 2^bits` — the
    /// per-set width alone is not the bound. Note there is no factor of `n` here as there is on
    /// the RISS path, where each `r_T` was itself a sum of `n` party contributions.
    pub fn max_mask_bits(&self) -> usize {
        let headroom = log2_tsets_ceil(self.n, self.t) + 1;
        (G::MODULUS_BIT_SIZE as usize).saturating_sub(headroom)
    }

    /// Derives the mask shares at absolute positions `start .. start + count`. No network, no
    /// session state.
    ///
    /// `start` is the party's current pool depth, so a node topping up a half-filled pool derives
    /// exactly the suffix the others already hold. Masks are addressed by position rather than by
    /// a per-invocation counter precisely so that restarts, retries and pool-level skew cannot
    /// silently repoint the derivation: with a local counter in the PRF input, two parties out of
    /// step by one produce shares of entirely different secrets and no message exchange remains
    /// to notice.
    ///
    /// Parties must still agree on `bits` and on the pool position they are filling.
    pub fn generate_prss_at(
        &self,
        instance_id: u32,
        start: usize,
        count: usize,
        bits: usize,
    ) -> Result<Vec<RobustShare<G>>, PRandIntError> {
        let keys = self.prss.as_ref().ok_or(PRandIntError::NoPrssKeys)?;
        if bits > self.max_mask_bits() {
            return Err(PRandIntError::SurpassedFieldCapacity);
        }

        let session_id = SessionId::new(
            ProtocolType::PRandInt,
            SessionId::pack_slot(0, 0, 0),
            instance_id,
        );

        Ok(keys.shares_at(session_id, start, count, bits)?)
    }

    /// Turns a completed RISS session's folded `r_T` values into PRSS key material.
    ///
    /// RISS already establishes exactly what a key setup needs: an agreed `r_T` per unqualified
    /// set, held by the `n-t` parties outside it and unknown to those inside — range-checked and
    /// echo-verified on the way in. Run once at startup, its output is stored as keys instead of
    /// being converted to Shamir shares, and every mask thereafter is derived locally.
    ///
    /// Must be called before `clear_store` retires the session.
    pub async fn take_riss_keys(
        &self,
        session_id: SessionId,
    ) -> Result<Vec<(usize, [u8; PRSS_KEY_LEN])>, PRandIntError> {
        let binding = {
            let store = self.store.lock().await;
            store
                .get(&session_id)
                .map(|(_, _, arc)| arc.clone())
                .ok_or(PRandIntError::NoSuchSessionId(session_id))?
        };
        let store = binding.lock().await;

        let expected = self
            .tset_ranks
            .keys()
            .filter(|ts| !ts.contains(&self.id))
            .count();
        if store.r_t.len() != expected {
            return Err(PRandIntError::NotSet(format!(
                "RISS folded {} of {expected} unqualified sets; key setup needs all of them",
                store.r_t.len()
            )));
        }

        let mut keys = Vec::with_capacity(store.r_t.len());
        for (tset, values) in store.r_t.iter() {
            let rank = self.rank_of(tset)?;
            keys.push((rank, derive_key_from_riss(rank, values)));
        }
        keys.sort_by_key(|(rank, _)| *rank);
        Ok(keys)
    }

    /// Pulls RBC-completed commitment broadcasts and replays the openings that were waiting on
    /// them.
    ///
    pub async fn drain_rbc_output<N: Network + Send + Sync>(
        &mut self,
        network: Arc<N>,
    ) -> Result<(), PRandIntError> {
        loop {
            let id = {
                let mut rx = self.rbc_output.lock().await;
                match rx.try_recv() {
                    Ok(id) => id,
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        return Err(PRandIntError::Abort);
                    }
                }
            };

            let output = self.rbc.get_store(id).await?;
            let msg: PRandIntCommitMessage = bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .allow_trailing_bytes()
                .with_limit(MAX_MESSAGE_SIZE)
                .deserialize(&output)?;

            let authenticated_sender = id.sub_id() as usize;
            if msg.sender_id != authenticated_sender || authenticated_sender >= self.n {
                warn!("Dropping PRandInt commitment: sender mismatch");
                continue;
            }
            if msg.session_id != id {
                warn!("Dropping PRandInt commitment: session_id mismatch");
                continue;
            }

            let expected_sets = self.tset_ranks.len();
            if msg.commitments.len() != expected_sets {
                warn!(
                    sender = authenticated_sender,
                    got = msg.commitments.len(),
                    expected_sets,
                    "Dropping PRandInt commitment: wrong number of unqualified sets"
                );
                continue;
            }

            // Openings are addressed to the originating session, whose sub_id is 0; the broadcast
            // carries the dealer in sub_id so the RBC layer can bind it.
            let session_id = SessionId::new(
                ProtocolType::PRandInt,
                SessionId::pack_slot(id.exec_id(), 0, id.round_id()),
                id.instance_id(),
            );

            let replay = {
                let binding = match self
                    .get_or_create_store(session_id, authenticated_sender)
                    .await
                {
                    Some(s) => s,
                    None => continue,
                };
                let mut store = binding.lock().await;
                if store
                    .commitments
                    .insert(authenticated_sender, msg.commitments)
                    .is_some()
                {
                    warn!(
                        sender = authenticated_sender,
                        "duplicate PRandInt commitment broadcast"
                    );
                    continue;
                }
                // Only the openings this commitment unblocks; everything else stays parked.
                let (ready, still_pending) = std::mem::take(&mut store.pending_riss_messages)
                    .into_iter()
                    .partition::<Vec<_>, _>(|m| m.sender_id == authenticated_sender);
                store.pending_riss_messages = still_pending;
                ready
            };

            for opening in replay {
                match self.process(opening).await {
                    Ok(()) => {}
                    Err(PRandIntError::InvalidMessage(_)) | Err(PRandIntError::Duplicate(_)) => {
                        warn!("dropping invalid parked RISS opening");
                    }
                    Err(e) => return Err(e),
                }
            }

            // This may have been the commitment that completed the set, in which case our own
            // openings are now clear to go out.
            self.try_release_openings(session_id, network.clone())
                .await?;
        }
        Ok(())
    }

    pub async fn clear_store(&self, session_id: SessionId) -> bool {
        let mut store = self.store.lock().await;
        store.retire(session_id)
    }

    pub async fn store_len(&self) -> usize {
        self.store.lock().await.len()
    }

    pub async fn wait_for_int_result(
        &self,
        session_id: SessionId,
        duration: Duration,
    ) -> Result<Vec<RobustShare<G>>, PRandIntError> {
        let output_receiver = {
            let storage = self.store.lock().await;
            let storage_bind = match storage.get(&session_id) {
                Some((_, _, arc)) => arc,
                None => return Err(PRandIntError::NoSuchSessionId(session_id)),
            };
            let mut storage = storage_bind.lock().await;

            storage
                .output_int_receiver
                .take()
                .ok_or(PRandIntError::ResultAlreadyReceived(session_id))?
        };

        match timeout(duration, output_receiver).await {
            Err(_) => {
                // A stalled session is nearly always a party that never committed, and the store
                // already knows which. Reporting it turns "PRandInt timed out" into a named
                // suspect: RBC totality means every honest party computes the same set here, so
                // the accusation is consistent across the network rather than one node's guess.
                let missing = self.missing_committers(session_id).await;
                if !missing.is_empty() {
                    warn!(
                        node_id = self.id,
                        ?session_id,
                        ?missing,
                        "PRandInt timed out waiting for commitments; these parties never broadcast"
                    );
                }
                Err(PRandIntError::Timeout(session_id))
            }
            Ok(Err(_)) => Err(PRandIntError::ReceiveError(session_id)),
            Ok(Ok(shares)) => Ok(shares),
        }
    }

    /// Parties whose commitment vector has not been RBC-delivered for this session.
    ///
    /// Empty once the barrier has fired, so a non-empty result on a stalled session is the direct
    /// cause rather than a symptom.
    pub async fn missing_committers(&self, session_id: SessionId) -> Vec<usize> {
        let binding = {
            let store = self.store.lock().await;
            match store.get(&session_id) {
                Some((_, _, arc)) => arc.clone(),
                None => return Vec::new(),
            }
        };
        let store = binding.lock().await;
        (0..self.n)
            .filter(|id| !store.commitments.contains_key(id))
            .collect()
    }

    async fn try_advance_from_riss(
        &mut self,
        session_id: SessionId,
    ) -> Result<bool, PRandIntError> {
        // Phase 0: Terminal fast-path
        {
            let binding = match self.get_or_create_store(session_id, self.id).await {
                Some(s) => s,
                None => return Ok(false),
            };
            let store = binding.lock().await;

            if store.state == PrandState::IntFinished {
                return Ok(true);
            }
        }

        // Phase 1: Check readiness + decide what must be done
        let (batch_size, r_t_map, need_compute) = {
            let binding = match self.get_or_create_store(session_id, self.id).await {
                Some(s) => s,
                None => return Ok(false),
            };
            let store = binding.lock().await;

            let Some(batch_size) = store.batch_size else {
                return Ok(false);
            };
            let Some(total_tsets) = store.no_of_tsets else {
                return Ok(false);
            };

            if store.r_t.len() != total_tsets {
                return Ok(false);
            }
            // validate stored r_t lengths before indexing
            for r_t in store.r_t.values() {
                if r_t.len() != batch_size {
                    return Err(PRandIntError::InvalidMessage(format!(
                        "stored r_t has length {} but batch_size is {}",
                        r_t.len(),
                        batch_size
                    )));
                }
            }

            let need_compute = store.share_r_p.is_none();

            (batch_size, store.r_t.clone(), need_compute)
        };

        // ============================================================
        // Phase 2: Heavy compute ONLY if needed
        // ============================================================
        let share_p = if need_compute {
            let tsets: Vec<Vec<usize>> = r_t_map.keys().cloned().collect();

            let poly_fp = build_all_f_polys::<G>(self.n, tsets.clone())?;

            let domain_g = GeneralEvaluationDomain::<G>::new(self.n)
                .ok_or_else(|| ShareError::NoSuitableDomain(self.n))?;

            let xi_p = domain_g.element(self.id);

            let mut share_p = vec![RobustShare::new(G::zero(), self.id, self.t); batch_size];

            for (tset, r_t) in r_t_map.iter() {
                let poly_p = &poly_fp[tset];
                let coeff_p = poly_p.evaluate(&xi_p);

                for i in 0..batch_size {
                    let r_p = G::from(r_t[i].clone());
                    share_p[i].share[0] += r_p * coeff_p;
                }
            }

            Some(share_p)
        } else {
            None
        };

        // ============================================================
        // Phase 3: Commit derived share + output once
        // ============================================================
        let binding = match self.get_or_create_store(session_id, self.id).await {
            Some(s) => s,
            None => return Ok(false),
        };

        let (sender, out) = {
            let mut store = binding.lock().await;

            // Commit the share exactly once
            if let Some(ref p) = share_p {
                if store.share_r_p.is_none() {
                    store.share_r_p = Some(p.clone());
                }
            }

            // Output once and stop
            if store.state != PrandState::IntFinished {
                store.state = PrandState::IntFinished;

                let out = store
                    .share_r_p
                    .clone()
                    .ok_or_else(|| PRandIntError::NotSet("share_r_p not set".into()))?;

                let sender = store
                    .output_int_sender
                    .take()
                    .ok_or(PRandIntError::SendError(session_id))?;

                (Some(sender), Some(out))
            } else {
                (None, None)
            }
        };

        if let (Some(sender), Some(out)) = (sender, out) {
            sender
                .send(out)
                .map_err(|_| PRandIntError::SendError(session_id))?;
        }

        Ok(true)
    }

    /// Distributed RISS generation of PRandInt shares.
    /// Generates shares in multiples of (t+1).
    pub async fn generate_riss<N: Network + Send + Sync>(
        &mut self,
        session_id: SessionId,
        mask_bits: usize,
        batch_size: usize,
        network: Arc<N>,
    ) -> Result<(), PRandIntError> {
        info!(node_id = self.id, "RISS started");

        assert_eq!(session_id.sub_id(), 0);
        assert_eq!(session_id.round_id(), 0);

        // Step 1: compute all maximal unqualified sets
        let tsets = all_tsets(self.n, self.t);

        let binding = match self.get_or_create_store(session_id, self.id).await {
            Some(s) => s,
            None => return Ok(()),
        };
        let mut store = binding.lock().await;
        let my_tsets: Vec<Vec<usize>> = tsets
            .clone()
            .into_iter()
            .filter(|ts| !ts.contains(&self.id))
            .collect();
        store.no_of_tsets = Some(my_tsets.len());
        store.batch_size = Some(batch_size);
        store.state = PrandState::Initialized;
        drop(store);
        self.try_advance_from_riss(session_id).await?;

        // Step 2: P_i samples randomness and sends.
        //
        // Each party draws an `r_T^i` in `[0, 2^mask_bits)` for every one of the `C(n,t)`
        // unqualified sets; `r_T` is the sum of all `n` of those, and the secret is the sum of
        // every `r_T`. The integer that must not wrap the modulus is therefore
        // `C(n,t) * n * 2^mask_bits` — Damgard-Thorbek Sec. 3.1's "choose p such that p > r".
        //
        // Counting only the `n` contributions per set under-reports that by `log2 C(n,t)`: two
        // bits at n=4 but thirteen at n=16, growing with n, so the check was loosest exactly
        // where wrapping first becomes reachable. It wraps silently — TruncPr's opened value is
        // then not `b + r` over the integers and the truncation takes the wrong bits — which is
        // why this is a hard error rather than a warning.
        const B_MARGIN: usize = 2; // `b` itself, plus a bit of slack
        let n_margin = (self.n as f64).log2().ceil() as usize;
        let tset_margin = log2_tsets_ceil(self.n, self.t);
        let required_bits = mask_bits + B_MARGIN + n_margin + tset_margin;
        let max_field_cap = G::MODULUS_BIT_SIZE;
        if required_bits as u32 >= max_field_cap {
            return Err(PRandIntError::SurpassedFieldCapacity);
        }
        let bound = BigUint::from(2 as u32).pow(mask_bits as u32);
        let pending = {
            let binding = match self.get_or_create_store(session_id, self.id).await {
                Some(s) => s,
                None => return Ok(()),
            };
            let mut store = binding.lock().await;
            store.r_t_bound = Some(bound.clone());
            std::mem::take(&mut store.pending_riss_messages)
        };
        for pending_msg in pending {
            match self.process(pending_msg).await {
                Ok(()) => {}
                Err(PRandIntError::InvalidMessage(_)) | Err(PRandIntError::Duplicate(_)) => {
                    warn!("dropping invalid pending RISS message from Byzantine peer");
                }
                Err(e) => return Err(e),
            }
        }

        // Step 3: commit to every contribution and reliably broadcast the commitments. The values
        // themselves are held back until *every* party has committed — see `try_release_openings`.

        let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
        let mut openings: Vec<(Vec<usize>, Vec<BigUint>, [u8; PRANDINT_NONCE_LEN])> =
            Vec::with_capacity(tsets.len());
        let mut commitments = Vec::with_capacity(tsets.len());

        for tset in &tsets {
            let r_t_i: Vec<BigUint> = (0..batch_size)
                .map(|_| gen_big_uint_range(&mut rng, &bound))
                .collect();
            let mut nonce = [0u8; PRANDINT_NONCE_LEN];
            rng.fill(&mut nonce);
            commitments.push(commit_contribution(tset, &r_t_i, &nonce));
            openings.push((tset.clone(), r_t_i, nonce));
        }

        // `sub_id` carries our own party id so the RBC's dealer check binds the broadcast to us
        let commit_session = SessionId::new(
            ProtocolType::PRandInt,
            SessionId::pack_slot(session_id.exec_id(), self.id as u8, session_id.round_id()),
            session_id.instance_id(),
        );
        let commit_msg =
            PRandIntCommitMessage::new(self.id, commit_session, std::mem::take(&mut commitments));
        {
            let binding = match self.get_or_create_store(session_id, self.id).await {
                Some(s) => s,
                None => return Ok(()),
            };
            let mut store = binding.lock().await;
            store.my_openings = openings;
        }

        self.rbc
            .init(
                bincode::serialize(&commit_msg)?,
                commit_session,
                network.clone(),
            )
            .await?;

        // Our own broadcast may already have come back to us, so try the barrier here as well as
        // from the drain — whichever call sees the last commitment arrive is the one that fires.
        self.try_release_openings(session_id, network).await
    }

    /// Sends this party's openings once every party's commitments have been delivered, and not
    /// before.
    ///
    /// This is the anti-rushing barrier. Without it a corrupt party can withhold its own broadcast,
    /// watch the honest openings arrive, pick its `r_T` to drive the sum wherever it likes, and
    /// only then commit — a commitment made after seeing the inputs binds it to nothing. Holding
    /// every opening until all `n` vectors are in means each contribution is fixed before its
    /// sender has seen any other.
    ///
    /// The cost is a liveness coupling: a party that never broadcasts stalls the session. That is
    /// the intended trade, and it is a *clean* stall — RBC totality means either every honest party
    /// delivers a given vector or none does, so all of them reach the same conclusion about who is
    /// missing rather than each timing out on a different peer.
    ///
    /// What this does not stop is abort-steering: having committed, an adversary can still watch
    /// the honest openings and decline to send its own. Nothing in a commit-then-open structure
    /// prevents walking away.
    async fn try_release_openings<N: Network + Send + Sync>(
        &mut self,
        session_id: SessionId,
        network: Arc<N>,
    ) -> Result<(), PRandIntError> {
        let openings = {
            let binding = match self.get_or_create_store(session_id, self.id).await {
                Some(s) => s,
                None => return Ok(()),
            };
            let mut store = binding.lock().await;

            if store.openings_sent
                || store.my_openings.is_empty()
                || store.commitments.len() < self.n
            {
                return Ok(());
            }
            // Set before releasing the lock: `drain_rbc_output` can re-enter here.
            store.openings_sent = true;
            std::mem::take(&mut store.my_openings)
        };

        info!(
            node_id = self.id,
            "all parties committed, releasing openings"
        );
        for (tset, r_t_i, nonce) in openings {
            for j in 0..self.n {
                if !tset.contains(&j) {
                    let msg = WrappedMessage::PRandInt(PRandIntMessage::new(
                        self.id,
                        session_id,
                        tset.clone(),
                        r_t_i.clone(),
                        nonce,
                    ));
                    let bytes_msg = bincode::serialize(&msg)?;
                    network.send(j, &bytes_msg).await?;
                }
            }
        }
        Ok(())
    }

    pub async fn process(&mut self, msg: PRandIntMessage) -> Result<(), PRandIntError> {
        info!(node_id = self.id, sender = msg.sender_id, "At RISS handler");

        if msg.session_id.calling_protocol().is_none() {
            return Err(PRandIntError::SessionIdError(msg.session_id));
        }

        let binding = match self
            .get_or_create_store(msg.session_id, msg.sender_id)
            .await
        {
            Some(s) => s,
            None => return Ok(()),
        };
        let mut store = binding.lock().await;

        if msg.tset.contains(&self.id) {
            return Err(PRandIntError::InvalidMessage(format!(
                "node {} received message for tset that contains itself: {:?}",
                self.id, msg.tset
            )));
        }

        if msg.tset.len() != self.t {
            return Err(PRandIntError::InvalidMessage(format!(
                "tset length {} != threshold {}",
                msg.tset.len(),
                self.t
            )));
        }
        if msg.tset.iter().any(|&id| id >= self.n) {
            return Err(PRandIntError::InvalidMessage(
                "tset contains out-of-range party ID".into(),
            ));
        }
        let mut seen = std::collections::HashSet::new();
        if msg.tset.iter().any(|id| !seen.insert(id)) {
            return Err(PRandIntError::InvalidMessage(
                "tset contains duplicate IDs".into(),
            ));
        }

        // If bounds are not yet set, queue the message for retroactive validation
        // once generate_riss() initialises the session.
        if store.batch_size.is_none() || store.r_t_bound.is_none() {
            const MAX_PENDING_RISS: usize = 4096;
            if store.pending_riss_messages.len() >= MAX_PENDING_RISS {
                return Err(PRandIntError::InvalidMessage(
                    "too many pending messages for uninitialized session".into(),
                ));
            }
            if store
                .pending_riss_messages
                .iter()
                .any(|m| m.sender_id == msg.sender_id && m.tset == msg.tset)
            {
                return Err(PRandIntError::Duplicate(format!(
                    "Already queued from {} for tset {:?}",
                    msg.sender_id, msg.tset
                )));
            }
            store.pending_riss_messages.push(msg);
            return Ok(());
        }

        let maybe_batch_size = store.batch_size;

        if let Some(batch_size) = maybe_batch_size {
            if msg.r_t.len() != batch_size {
                return Err(PRandIntError::InvalidMessage(format!(
                    "r_t length {} does not match batch_size {}",
                    msg.r_t.len(),
                    batch_size
                )));
            }
        }

        if let Some(ref bound) = store.r_t_bound {
            // `>=`: the range is half-open, so `bound` itself is out of range. Accepting it let a
            // peer contribute an `L+1`-bit value under an `L`-bit declaration -- the one input the
            // width accounting in `generate_riss` does not cover.
            for val in &msg.r_t {
                if val >= bound {
                    return Err(PRandIntError::InvalidMessage(format!(
                        "r_t value from sender {} is at or above the maximum allowed bound",
                        msg.sender_id
                    )));
                }
            }
        }

        // The commitment may not have been RBC-delivered yet — openings and broadcasts race. Park
        // the opening and let `drain_rbc_output` replay it when the commitment lands.
        let Some(sender_commitments) = store.commitments.get(&msg.sender_id).cloned() else {
            const MAX_PENDING_RISS: usize = 4096;
            if store.pending_riss_messages.len() >= MAX_PENDING_RISS {
                return Err(PRandIntError::InvalidMessage(
                    "too many openings pending a commitment".into(),
                ));
            }
            if store
                .pending_riss_messages
                .iter()
                .any(|m| m.sender_id == msg.sender_id && m.tset == msg.tset)
            {
                return Err(PRandIntError::Duplicate(format!(
                    "Already queued from {} for tset {:?}",
                    msg.sender_id, msg.tset
                )));
            }
            store.pending_riss_messages.push(msg);
            return Ok(());
        };
        drop(store);

        self.verify_and_insert(msg, &sender_commitments).await
    }

    /// Checks one opening against its sender's RBC-delivered commitment vector, accepts it, and
    /// folds `r_T` once every contributor for that unqualified set has been accepted.
    ///
    /// A mismatch here is unambiguous. The commitment vector came from RBC, so every honest party
    /// holds the identical one, and only the sender could have produced an opening for it — there
    /// is no third party whose word is being taken. That is what makes aborting on this sound,
    async fn verify_and_insert(
        &mut self,
        msg: PRandIntMessage,
        sender_commitments: &[[u8; PRANDINT_COMMIT_LEN]],
    ) -> Result<(), PRandIntError> {
        let session_id = msg.session_id;
        let tset = msg.tset;
        let original_sender = msg.sender_id;

        let rank = self.rank_of(&tset)?;

        let expected = sender_commitments.get(rank).ok_or_else(|| {
            PRandIntError::InvalidMessage(format!(
                "sender {original_sender} committed to {} sets, no entry at rank {rank}",
                sender_commitments.len()
            ))
        })?;

        if &commit_contribution(&tset, &msg.r_t, &msg.nonce) != expected {
            warn!(
                node_id = self.id,
                original_sender, "RISS opening does not match committed value"
            );
            return Err(PRandIntError::EquivocationDetected(original_sender, tset));
        }

        let binding = match self.get_or_create_store(session_id, self.id).await {
            Some(s) => s,
            None => return Ok(()),
        };

        let should_advance = {
            let mut store = binding.lock().await;

            // Guard against duplicate insertion (e.g. a replayed opening)
            if store
                .riss_shares
                .get(&tset)
                .map(|m| m.contains_key(&original_sender))
                .unwrap_or(false)
            {
                return Ok(());
            }

            // Insert verified contribution into riss_shares
            {
                let entry = store
                    .riss_shares
                    .entry(tset.clone())
                    .or_insert_with(HashMap::new);
                entry.insert(original_sender, msg.r_t);
            }

            // Fold into r_t when all n contributors for this tset have been verified
            let tset_len = store.riss_shares[&tset].len();
            if tset_len == self.n {
                let batch_size = store.batch_size.ok_or_else(|| {
                    PRandIntError::NotSet("batch_size not set when folding r_t".into())
                })?;
                let sum = {
                    store.riss_shares[&tset].values().fold(
                        vec![BigUint::ZERO; batch_size],
                        |mut acc, v| {
                            for (a, x) in acc.iter_mut().zip(v) {
                                *a += x;
                            }
                            acc
                        },
                    )
                };
                store.r_t.insert(tset.clone(), sum);
                true
            } else {
                false
            }
        };

        if should_advance {
            self.try_advance_from_riss(session_id).await?;
        }

        Ok(())
    }

    pub async fn get_or_create_store(
        &mut self,
        session_id: SessionId,
        initiator_id: usize,
    ) -> Option<Arc<Mutex<PRandIntStore<G>>>> {
        match self.store.lock().await.get_or_admit(
            session_id,
            initiator_id,
            MAX_PRAND_SESSIONS,
            MAX_PRAND_SESSIONS / self.n,
            || Arc::new(Mutex::new(PRandIntStore::empty())),
        ) {
            Admission::Got(arc) => Some(arc),
            Admission::Retired => None,
            Admission::Rejected => {
                warn!("PRandInt session limit reached");
                None
            }
        }
    }
}

/// Binding, hiding commitment to one party's contribution for one unqualified set.
/// Lengths are hashed alongside the values because `BigUint` byte encodings are variable-width:
/// without them, two different `r_T` vectors could serialise to the same concatenated bytes and
/// the commitment would not bind.
fn commit_contribution(
    tset: &[usize],
    values: &[BigUint],
    nonce: &[u8; PRANDINT_NONCE_LEN],
) -> [u8; PRANDINT_COMMIT_LEN] {
    let mut h = Sha256::new();
    h.update(b"STOFFEL-RISS-COMMIT-v1");
    h.update((tset.len() as u64).to_le_bytes());
    for party in tset {
        h.update((*party as u64).to_le_bytes());
    }
    h.update((values.len() as u64).to_le_bytes());
    for value in values {
        let bytes = value.to_bytes_le();
        h.update((bytes.len() as u64).to_le_bytes());
        h.update(&bytes);
    }
    h.update(nonce);
    h.finalize().into()
}

/// `ceil(log2(C(n, t)))` — the width a sum gains from ranging over every unqualified set.
///
/// Summed logs rather than `binomial(n, t)`: `n` is only bounded by 255 here and `C(255, 84)`
/// overflows `u64`, so computing the binomial to size a capacity check would wrap silently on the
/// very inputs the check exists for. The combinatorics make those party counts unreachable long
/// before the arithmetic matters — every RISS and PRSS structure here is `C(n, t)`-sized — but the
/// bound guarding correctness does not get to be the part that overflows.
fn log2_tsets_ceil(n: usize, t: usize) -> usize {
    let t = t.min(n);
    (1..=t)
        .map(|i| (((n - t + i) as f64) / (i as f64)).log2())
        .sum::<f64>()
        .ceil() as usize
}

/// Uniform on the half-open range `[0, bound)`.
///
/// Half-open so that a `bound` of `2^L` yields exactly `L`-bit values. An inclusive range makes
/// `2^L` itself a legal draw, and the one extra value costs an entire bit of declared width: the
/// capacity bound in `generate_riss` would have to carry slack for a case that occurs with
/// probability `2^-L`, instead of being exact.
fn gen_big_uint_range<R>(rng: &mut R, bound: &BigUint) -> BigUint
where
    R: Rng,
{
    assert!(bound > &BigUint::ZERO, "empty range");

    // Width of the largest *legal* value, not of `bound` itself. Sizing from `bound` would draw a
    // bit too many for the only shape this is ever called with -- `bound = 2^mask_bits`, where the
    // legal values are exactly `mask_bits` wide -- and reject half of every draw for nothing.
    let n_bits = (bound - BigUint::from(1u32)).bits() as usize;
    let n_bytes = n_bits.div_ceil(8);
    let excess_bits = n_bytes * 8 - n_bits;

    // Rejection sampling: uniform on `[0, 2^n_bits)`, retried until it lands below `bound`. For a
    // power-of-two bound the two coincide and nothing is ever rejected.
    loop {
        let bytes: Vec<u8> = (0..n_bytes).map(|_| rng.gen()).collect();
        let candidate = BigUint::from_bytes_le(&bytes) >> excess_bits;
        if candidate < *bound {
            return candidate;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{gen_big_uint_range, log2_tsets_ceil};
    use ark_std::rand::SeedableRng;
    use num_bigint::BigUint;

    /// The sampler must never return `bound`. A single draw of `2^L` under an `L`-bit declaration
    /// is what the peer-side range check is written to reject, so the two have to agree on which
    /// end is open -- otherwise honest parties trip each other's validation.
    #[test]
    fn gen_big_uint_range_is_half_open_and_covers_the_range() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(7);
        let bound = BigUint::from(4u32);

        let mut seen = [false; 4];
        for _ in 0..512 {
            let v = gen_big_uint_range(&mut rng, &bound);
            assert!(
                v < bound,
                "sampler returned {v}, which is not below {bound}"
            );
            seen[u32::try_from(v).unwrap() as usize] = true;
        }
        // Every value below the bound is reachable: a half-open range must not be produced by
        // clamping or by dropping the top value's probability mass.
        assert!(seen.iter().all(|&hit| hit), "sampler did not cover 0..4");

        // A non-power-of-two bound still has to reject rather than fold the excess back in.
        let bound = BigUint::from(5u32);
        let mut counts = [0usize; 5];
        for _ in 0..5_000 {
            let v = gen_big_uint_range(&mut rng, &bound);
            assert!(v < bound);
            counts[u32::try_from(v).unwrap() as usize] += 1;
        }
        // Folding the 3 excess values of a 3-bit draw onto 0..3 would roughly double their share;
        // this only has to be tight enough to catch that, not to be a statistical test.
        assert!(
            counts.iter().all(|&c| (700..=1300).contains(&c)),
            "draws are not close to uniform over 0..5: {counts:?}"
        );
    }

    /// Exact against `C(n, t)` wherever the binomial is computable, and still finite where it is
    /// not — the two properties the summed-log form is there to provide.
    #[test]
    fn log2_tsets_matches_the_binomial_and_survives_past_u64() {
        fn exact_ceil(n: u32, t: u32) -> usize {
            let mut c: u128 = 1;
            for i in 0..t as u128 {
                c = c * (n as u128 - i) / (i + 1);
            }
            (128 - (c - 1).leading_zeros()) as usize
        }

        for &(n, t) in &[(4, 1), (5, 1), (7, 2), (10, 3), (16, 5), (31, 10)] {
            assert_eq!(
                log2_tsets_ceil(n, t),
                exact_ceil(n as u32, t as u32),
                "C({n},{t})"
            );
        }

        // C(255, 84) is a 229-bit number: `binomial` over `u64` wrapped here, which would have
        // handed the capacity check a headroom smaller than the real one.
        assert_eq!(log2_tsets_ceil(255, 84), 229);

        // Degenerate shapes: C(n, 0) = C(n, n) = 1 costs no headroom at all.
        assert_eq!(log2_tsets_ceil(7, 0), 0);
        assert_eq!(log2_tsets_ceil(7, 7), 0);
    }
}
