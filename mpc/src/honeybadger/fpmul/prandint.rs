use crate::{
    common::{
        session_store::{Admission, SessionStore},
        share::ShareError,
        ProtocolSessionId,
    },
    honeybadger::{
        fpmul::{
            build_all_f_polys, PRandIntEchoMessage, PRandIntError, PRandIntMessage, PRandIntStore,
            PrandState,
        },
        prss::{
            prss::{all_tsets, derive_key_from_riss, PrssKeys},
            PRSS_KEY_LEN,
        },
        robust_interpolate::robust_interpolate::RobustShare,
        ProtocolType, SessionId, WrappedMessage,
    },
};
use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain, Polynomial};
use ark_std::rand::{Rng, SeedableRng};
use itertools::Itertools;
use num_bigint::BigUint;
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
pub struct PRandIntNode<G: PrimeField> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    pub store: Arc<Mutex<SessionStore<SessionId, (usize, Instant, Arc<Mutex<PRandIntStore<G>>>)>>>,
    /// PRSS key material. When present, `generate_prss` derives masks locally and the whole RISS
    /// message path below goes unused. Absent until a key setup has run.
    prss: Option<PrssKeys<G>>,
}

const MAX_PRAND_SESSIONS: usize = 512;

impl<G: PrimeField> PRandIntNode<G> {
    /// Creates a new PRandIntNode with empty shares.
    pub fn new(id: usize, n: usize, t: usize) -> Result<Self, PRandIntError> {
        Ok(Self {
            id,
            n,
            t,
            store: Arc::new(Mutex::new(SessionStore::with_default_cap())),
            prss: None,
        })
    }

    /// Installs PRSS key material, switching mask generation from RISS to local derivation.
    pub fn install_prss_keys(&mut self, keys: PrssKeys<G>) {
        self.prss = Some(keys);
    }

    pub fn has_prss_keys(&self) -> bool {
        self.prss.is_some()
    }

    /// Largest mask width this node can derive without the summed value wrapping the field.
    ///
    /// The secret is the sum over **all** `C(n,t)` sets, so it reaches `C(n,t) · 2^bits` — the
    /// per-set width alone is not the bound. Note there is no factor of `n` here as there is on
    /// the RISS path, where each `r_T` was itself a sum of `n` party contributions.
    pub fn max_mask_bits(&self) -> usize {
        let n_tsets = num_integer::binomial(self.n as u64, self.t as u64);
        let headroom = (n_tsets as f64).log2().ceil() as usize + 1;
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

        let expected = all_tsets(self.n, self.t)
            .iter()
            .filter(|ts| !ts.contains(&self.id))
            .count();
        if store.r_t.len() != expected {
            return Err(PRandIntError::NotSet(format!(
                "RISS folded {} of {expected} unqualified sets; key setup needs all of them",
                store.r_t.len()
            )));
        }

        let tsets = all_tsets(self.n, self.t);
        let mut keys = Vec::with_capacity(store.r_t.len());
        for (tset, values) in store.r_t.iter() {
            let rank = tsets
                .iter()
                .position(|candidate| candidate == tset)
                .ok_or_else(|| {
                    PRandIntError::InvalidMessage(format!("unrecognised unqualified set {tset:?}"))
                })?;
            keys.push((rank, derive_key_from_riss(rank, values)));
        }
        keys.sort_by_key(|(rank, _)| *rank);
        Ok(keys)
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
            Err(_) => Err(PRandIntError::Timeout(session_id)),
            Ok(Err(_)) => Err(PRandIntError::ReceiveError(session_id)),
            Ok(Ok(shares)) => Ok(shares),
        }
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
        l: usize,
        k: usize,
        batch_size: usize,
        network: Arc<N>,
    ) -> Result<(), PRandIntError> {
        info!(node_id = self.id, "RISS started");

        assert_eq!(session_id.sub_id(), 0);
        assert_eq!(session_id.round_id(), 0);

        // Step 1: compute all maximal unqualified sets
        let tsets: Vec<Vec<usize>> = (0..self.n).combinations(self.t).collect();

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

        // Step 2: P_i samples randomness and sends
        // Random integer range: [0, 2^(l+k)]
        // Check that k + l + (2 bits for b) + ceil(log2(n)) fit the modulus.
        // The ceil(log2(n)) accounts for summing n individual shares without overflow.
        const B_MARGIN: usize = 2;
        let n_margin = (self.n as f64).log2().ceil() as usize;
        let required_bits = k + l + B_MARGIN + n_margin;
        let max_field_cap = G::MODULUS_BIT_SIZE;
        if required_bits as u32 >= max_field_cap {
            return Err(PRandIntError::SurpassedFieldCapacity);
        }
        let bound = BigUint::from(2 as u32).pow((k + l) as u32);
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
            match self.process(pending_msg, network.clone()).await {
                Ok(()) => {}
                Err(PRandIntError::InvalidMessage(_)) | Err(PRandIntError::Duplicate(_)) => {
                    warn!("dropping invalid pending RISS message from Byzantine peer");
                }
                Err(e) => return Err(e),
            }
        }

        // Reprocess echo messages that arrived before this session was initialized
        let pending_echoes = {
            let binding = match self.get_or_create_store(session_id, self.id).await {
                Some(s) => s,
                None => return Ok(()),
            };
            let mut store = binding.lock().await;
            std::mem::take(&mut store.pending_echo_messages)
        };
        for echo_msg in pending_echoes {
            match self.process_echo(echo_msg).await {
                Ok(()) => {}
                Err(PRandIntError::InvalidMessage(_)) | Err(PRandIntError::Duplicate(_)) => {
                    warn!("dropping invalid pending echo message from Byzantine peer");
                }
                Err(e) => return Err(e),
            }
        }

        let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
        for tset in tsets {
            let r_t_i: Vec<BigUint> = (0..batch_size)
                .map(|_| gen_big_uint_range(&mut rng, &bound))
                .collect();

            // Send to all players not in T
            for j in 0..self.n {
                if !tset.contains(&j) {
                    let msg = WrappedMessage::PRandInt(PRandIntMessage::new(
                        self.id,
                        session_id,
                        tset.clone(),
                        r_t_i.clone(),
                    ));
                    let bytes_msg = bincode::serialize(&msg)?;
                    network.send(j, &bytes_msg).await?;
                }
            }
        }
        Ok(())
    }

    pub async fn process<N: Network + Send + Sync>(
        &mut self,
        msg: PRandIntMessage,
        network: Arc<N>,
    ) -> Result<(), PRandIntError> {
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
            for val in &msg.r_t {
                if val > bound {
                    return Err(PRandIntError::InvalidMessage(format!(
                        "r_t value from sender {} exceeds maximum allowed bound",
                        msg.sender_id
                    )));
                }
            }
        }

        // Deduplicate per (sender, tset) against the direct-receive buffer
        let key = (msg.tset.clone(), msg.sender_id);
        if store.riss_direct.contains_key(&key) {
            return Err(PRandIntError::Duplicate(format!(
                "PRandInt: Already received from {} for tset {:?}",
                msg.sender_id, msg.tset
            )));
        }

        // Park value pending echo verification — do NOT insert into riss_shares yet
        store.riss_direct.insert(key, msg.r_t.clone());
        drop(store);

        // Echo the received value to all other non-T parties
        let non_t_others: Vec<usize> = (0..self.n)
            .filter(|&j| !msg.tset.contains(&j) && j != self.id)
            .collect();
        let echo = WrappedMessage::PRandIntEcho(PRandIntEchoMessage::new(
            self.id,
            msg.sender_id,
            msg.session_id,
            msg.tset.clone(),
            msg.r_t,
        ));
        let echo_bytes = bincode::serialize(&echo)?;
        for &j in &non_t_others {
            network.send(j, &echo_bytes).await?;
        }

        self.try_maybe_verify_and_insert(msg.session_id, msg.tset, msg.sender_id)
            .await
    }

    /// Verifies echo consistency for a single (tset, original_sender) contribution and,
    /// if all n-t-1 echoes have arrived and agree with the directly received value,
    /// inserts the verified contribution into riss_shares and folds r_t when complete.
    async fn try_maybe_verify_and_insert(
        &mut self,
        session_id: SessionId,
        tset: Vec<usize>,
        original_sender: usize,
    ) -> Result<(), PRandIntError> {
        let key = (tset.clone(), original_sender);
        // All non-T parties except self must send an echo: n - t - 1
        let expected_echoes = self.n.saturating_sub(self.t + 1);

        let binding = match self.get_or_create_store(session_id, self.id).await {
            Some(s) => s,
            None => return Ok(()),
        };

        let should_advance = {
            let mut store = binding.lock().await;

            // Wait until the direct message has arrived
            let direct_val = match store.riss_direct.get(&key) {
                Some(v) => v.clone(),
                None => return Ok(()),
            };

            // Wait until all expected echoes have arrived
            let echo_count = store.riss_echoes.get(&key).map(|m| m.len()).unwrap_or(0);
            if echo_count < expected_echoes {
                return Ok(());
            }

            // Verify every echo matches what we received directly
            if let Some(echoes) = store.riss_echoes.get(&key) {
                for (&echoer, echo_val) in echoes {
                    if echo_val != &direct_val {
                        warn!(
                            node_id = self.id,
                            original_sender, echoer, "RISS equivocation detected"
                        );
                        return Err(PRandIntError::EquivocationDetected(
                            original_sender,
                            tset.clone(),
                        ));
                    }
                }
            }

            // Guard against duplicate insertion (e.g. called twice)
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
                entry.insert(original_sender, direct_val);
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

    /// Handles an incoming RISS echo message.
    /// Stores the echo and triggers verification once all echoes for a contribution arrive.
    pub async fn process_echo(&mut self, msg: PRandIntEchoMessage) -> Result<(), PRandIntError> {
        if msg.tset.contains(&self.id) {
            return Err(PRandIntError::InvalidMessage(format!(
                "echo: node {} received echo for tset containing itself: {:?}",
                self.id, msg.tset
            )));
        }
        if msg.tset.len() != self.t {
            return Err(PRandIntError::InvalidMessage(format!(
                "echo: tset length {} != threshold {}",
                msg.tset.len(),
                self.t
            )));
        }
        if msg.tset.iter().any(|&id| id >= self.n) {
            return Err(PRandIntError::InvalidMessage(
                "echo: tset contains out-of-range party ID".into(),
            ));
        }
        {
            let mut seen = std::collections::HashSet::new();
            if msg.tset.iter().any(|id| !seen.insert(id)) {
                return Err(PRandIntError::InvalidMessage(
                    "echo: tset contains duplicate IDs".into(),
                ));
            }
        }
        if msg.tset.contains(&msg.echoer_id) {
            return Err(PRandIntError::InvalidMessage(format!(
                "echo: echoer {} is in the tset {:?}",
                msg.echoer_id, msg.tset
            )));
        }
        if msg.echoer_id == self.id {
            return Err(PRandIntError::InvalidMessage(
                "echo: received own echo".to_string(),
            ));
        }
        if msg.original_sender >= self.n || msg.echoer_id >= self.n {
            return Err(PRandIntError::InvalidMessage(
                "echo: party ID out of range".to_string(),
            ));
        }

        if msg.session_id.calling_protocol().is_none() {
            return Err(PRandIntError::SessionIdError(msg.session_id));
        }

        let binding = match self
            .get_or_create_store(msg.session_id, msg.original_sender)
            .await
        {
            Some(s) => s,
            None => return Ok(()),
        };

        {
            let mut store = binding.lock().await;

            // Queue if session not yet initialized
            if store.batch_size.is_none() || store.r_t_bound.is_none() {
                const MAX_PENDING_ECHO: usize = 4096;
                if store.pending_echo_messages.len() >= MAX_PENDING_ECHO {
                    return Err(PRandIntError::InvalidMessage(
                        "pending echo queue full".to_string(),
                    ));
                }
                store.pending_echo_messages.push(msg);
                return Ok(());
            }

            if let Some(batch_size) = store.batch_size {
                if msg.r_t.len() != batch_size {
                    return Err(PRandIntError::InvalidMessage(format!(
                        "echo: r_t length {} != batch_size {}",
                        msg.r_t.len(),
                        batch_size
                    )));
                }
            }
            if let Some(ref bound) = store.r_t_bound {
                for val in &msg.r_t {
                    if val > bound {
                        return Err(PRandIntError::InvalidMessage(format!(
                            "echo: r_t value from echoer {} exceeds bound",
                            msg.echoer_id
                        )));
                    }
                }
            }

            let key = (msg.tset.clone(), msg.original_sender);
            let echo_map = store.riss_echoes.entry(key).or_insert_with(HashMap::new);

            if echo_map.contains_key(&msg.echoer_id) {
                return Err(PRandIntError::Duplicate(format!(
                    "PRandInt: Already received echo from {} for (sender={}, tset={:?})",
                    msg.echoer_id, msg.original_sender, msg.tset
                )));
            }

            echo_map.insert(msg.echoer_id, msg.r_t);
        }

        self.try_maybe_verify_and_insert(msg.session_id, msg.tset, msg.original_sender)
            .await
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

/// Generates a random number in the range [0, bound] via rejection sampling.
fn gen_big_uint_range<R>(rng: &mut R, bound: &BigUint) -> BigUint
where
    R: Rng,
{
    // To generate the random element including `bound`.
    let bound = bound + BigUint::from(1 as usize);
    let n_bytes = bound.to_bytes_le().len();
    let n_bits = bound.bits();
    let excess_bits = (8 - n_bits % 8) % 8;

    // Rejection sampling.
    loop {
        let bytes: Vec<u8> = (0..n_bytes).map(|_| rng.gen()).collect();
        let candidate = BigUint::from_bytes_le(&bytes) >> excess_bits;
        if candidate < bound {
            return candidate;
        }
    }
}
