//! Mod2 — Protocol 3.4 (Catrina & de Hoogh 2010).
//!
//! Computes [a mod 2] given [a] and PRandM(k, 1) preprocessing.
//!
//! Protocol steps:
//!   1. c  ← Open(2^{k-1} + [a] + 2*[r''] + [r0'])
//!   2. c0 ← c mod 2  (public parity)
//!   3. [a0] ← c0 + [r0'] - 2*c0*[r0']  = XOR(c0, [r0'])  (local)
//!
//! Each party sends its share of c to every peer as a plain point-to-point
//! `Mod2Message` broadcast — no RBC; robust interpolation already tolerates
//! t wrong shares, so echo/ready amplification buys nothing here.
//! Wire session IDs: calling_protocol = outer, sub_id = party_id,
//! round_id = 0 (single-value) or 1 (batch).
//! Reconstruction is first attempted at 2t+1 received shares and retried as
//! more arrive (see `try_finalize` on why a bad share defers decoding).
//!
//! Session routing (add to HoneyBadgerMPCNode.process):
//!   WrappedMessage::Mod2 → owning sub-protocol's mod2_node.process
//!
//! # Batched variant
//!
//! `init_batch`/`wait_for_batch_result` reveal m independent values in a
//! single broadcast per party (round_id = 1) instead of m separate
//! sessions sharing one exec_id — the latter doesn't work because
//! `process` reconstructs the single-value store key as
//! `(exec_id, sub_id=0, round_id=0)` unconditionally, so m single-value calls
//! under one exec_id would all collide on that same key. Batching sidesteps
//! this: there is exactly one store per batched session, keyed the same way
//! `init_batch`'s caller-supplied session already is.

use crate::common::wire_format;
use crate::{
    common::{
        session_store::{Admission, SessionStore},
        utils::deser_bounded_vec,
        ProtocolSessionId, SecretSharingScheme,
    },
    honeybadger::{
        bitwise::{pre_mulc::PhaseState, Mod2Error, Mod2Message, PRandMPrep},
        robust_interpolate::{robust_interpolate::RobustShare, InterpolateError},
        SessionId, WrappedMessage,
    },
};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::CanonicalSerialize;
use std::{collections::HashMap, sync::Arc, time::Instant};
use stoffelnet::network_utils::Network;
use tokio::{
    sync::Mutex,
    time::{timeout, Duration},
};
use tracing::warn;

const MAX_MOD2_SESSIONS: usize = 1024;

/// Per-session state for one single-value Mod2 reveal.
#[derive(Debug)]
pub struct Mod2Store<F: PrimeField> {
    /// Waiting until finalized; Finished once the output has been sent.
    pub state: PhaseState,
    /// This party's [r0'] from the PRandM bundle, needed to compute the
    /// output XOR after c is reconstructed. None until `init` stores it —
    /// shares can arrive first (see `process`).
    pub r_prime: Option<RobustShare<F>>,
    /// Received c-shares, party_id → share value; first message per sender wins.
    pub received_shares: HashMap<usize, F>,
    /// One-shot carrying the result [a0] from `try_finalize` to `wait_for_result`.
    pub output_sender: Option<tokio::sync::oneshot::Sender<RobustShare<F>>>,
    /// Taken (once) by `wait_for_result`.
    pub output_receiver: Option<tokio::sync::oneshot::Receiver<RobustShare<F>>>,
}

impl<F: PrimeField> Mod2Store<F> {
    pub fn new() -> Self {
        let (tx, rx) = tokio::sync::oneshot::channel();
        Self {
            state: PhaseState::Waiting,
            r_prime: None,
            received_shares: HashMap::new(),
            output_sender: Some(tx),
            output_receiver: Some(rx),
        }
    }
}

/// Per-session state for one batched Mod2 reveal of m values (see the
/// "Batched variant" module docs).
#[derive(Debug)]
pub struct Mod2BatchStore<F: PrimeField> {
    /// Waiting until finalized; Finished once the output has been sent.
    pub state: PhaseState,
    /// This party's m [r0'_i] values, in input order; their length is also
    /// the expected per-sender share count. None until `init_batch` stores it.
    pub r_primes: Option<Vec<RobustShare<F>>>,
    /// Received c-shares, party_id → its m c-shares; first message per sender wins.
    pub received_shares: HashMap<usize, Vec<F>>,
    /// One-shot carrying the m results from `try_finalize_batch` to
    /// `wait_for_batch_result`.
    pub output_sender: Option<tokio::sync::oneshot::Sender<Vec<RobustShare<F>>>>,
    /// Taken (once) by `wait_for_batch_result`.
    pub output_receiver: Option<tokio::sync::oneshot::Receiver<Vec<RobustShare<F>>>>,
}

impl<F: PrimeField> Mod2BatchStore<F> {
    pub fn new() -> Self {
        let (tx, rx) = tokio::sync::oneshot::channel();
        Self {
            state: PhaseState::Waiting,
            r_primes: None,
            received_shares: HashMap::new(),
            output_sender: Some(tx),
            output_receiver: Some(rx),
        }
    }
}

/// One party's Mod2 engine: runs the reveal/finalize state machine for any
/// number of concurrent sessions, single-value and batched.
#[derive(Clone, Debug)]
pub struct Mod2Node<F: PrimeField> {
    /// This party's index in [0, n).
    pub id: usize,
    /// Total number of parties.
    pub n: usize,
    /// Corruption threshold (n >= 3t + 1).
    pub t: usize,
    /// Single-value sessions (wire round_id = 0), admission-capped per peer.
    store: Arc<Mutex<SessionStore<SessionId, (usize, Instant, Arc<Mutex<Mod2Store<F>>>)>>>,
    /// Batched sessions (wire round_id = 1), admission-capped per peer.
    batch_store:
        Arc<Mutex<SessionStore<SessionId, (usize, Instant, Arc<Mutex<Mod2BatchStore<F>>>)>>>,
}

impl<F: PrimeField> Mod2Node<F> {
    pub fn new(id: usize, n: usize, t: usize) -> Result<Self, Mod2Error> {
        Ok(Self {
            id,
            n,
            t,
            store: Arc::new(Mutex::new(SessionStore::with_default_cap())),
            batch_store: Arc::new(Mutex::new(SessionStore::with_default_cap())),
        })
    }

    async fn get_or_create_store(
        &self,
        session: SessionId,
        initiator_id: usize,
    ) -> Option<Arc<Mutex<Mod2Store<F>>>> {
        match self.store.lock().await.get_or_admit(
            session,
            initiator_id,
            MAX_MOD2_SESSIONS,
            MAX_MOD2_SESSIONS / self.n,
            || Arc::new(Mutex::new(Mod2Store::new())),
        ) {
            Admission::Got(arc) => Some(arc),
            Admission::Retired => None,
            Admission::Rejected => {
                warn!("Mod2 session limit reached");
                None
            }
        }
    }

    async fn get_or_create_batch_store(
        &self,
        session: SessionId,
        initiator_id: usize,
    ) -> Option<Arc<Mutex<Mod2BatchStore<F>>>> {
        match self.batch_store.lock().await.get_or_admit(
            session,
            initiator_id,
            MAX_MOD2_SESSIONS,
            MAX_MOD2_SESSIONS / self.n,
            || Arc::new(Mutex::new(Mod2BatchStore::new())),
        ) {
            Admission::Got(arc) => Some(arc),
            Admission::Retired => None,
            Admission::Rejected => {
                warn!("Mod2 batch session limit reached");
                None
            }
        }
    }

    /// Clears state for `session` in whichever store (single or batch) it
    /// belongs to.
    pub async fn clear_store(&self, session: SessionId) -> Result<(), Mod2Error> {
        let removed_single = self.store.lock().await.retire(session);
        let removed_batch = self.batch_store.lock().await.retire(session);
        if removed_single || removed_batch {
            Ok(())
        } else {
            Err(Mod2Error::ClearStoreError(session))
        }
    }

    /// Blocks until `session`'s result [a mod 2] is ready or `duration`
    /// elapses. Call after `init`; single-consumer — a second call on the
    /// same session returns `ResultAlreadyReceived`.
    pub async fn wait_for_result(
        &self,
        session: SessionId,
        duration: Duration,
    ) -> Result<RobustShare<F>, Mod2Error> {
        let rx = {
            let map = self.store.lock().await;
            let (_, _, inner) = map
                .get(&session)
                .ok_or(Mod2Error::NoSuchSessionId(session))?;
            let inner = inner.clone();
            drop(map);
            let mut s = inner.lock().await;
            s.output_receiver
                .take()
                .ok_or(Mod2Error::ResultAlreadyReceived(session))?
        };
        match timeout(duration, rx).await {
            Err(_) => Err(Mod2Error::Timeout(session)),
            Ok(Err(_)) => Err(Mod2Error::ReceiveError(session)),
            Ok(Ok(v)) => Ok(v),
        }
    }

    /// Protocol 3.4 Mod2.
    ///
    /// Each party broadcasts its share of c = 2^{k-1} + [a] + 2*[r''] + [r0'].
    /// Keep routing incoming Mod2 messages to `process` until
    /// `wait_for_result` resolves.
    ///
    /// Requires `k >= 2`. The caller must also ensure the PRandInt draw behind
    /// `prep.r_double_prime` is wide enough for this `k` — see
    /// `check_mask_security` on the node, which enforces
    /// `k <= max_masked_width + 1` there (this node never sees the pool
    /// parameters).
    pub async fn init<N: Network + Send + Sync>(
        &mut self,
        a: RobustShare<F>,
        k: usize,
        prep: PRandMPrep<F>,
        session: SessionId,
        network: Arc<N>,
    ) -> Result<(), Mod2Error> {
        // k = 0 underflows the exponent below; k = 1 makes the offset 2^0 = 1
        // odd, which flips the parity of c and inverts the result.
        if k < 2 {
            return Err(Mod2Error::InvalidK(k));
        }
        let two = F::one() + F::one();
        let two_pow_k_minus_1 = two.pow([(k as u64) - 1]);

        // c = 2^{k-1} + [a] + 2*[r''] + [r0']
        let c_share =
            (((a + (prep.r_double_prime * two)?)? + prep.r_prime.clone())? + two_pow_k_minus_1)?;

        let calling_proto = session
            .calling_protocol()
            .ok_or(Mod2Error::SessionIdError(session))?;

        // Pre-create the store and save r_zero_prime before any async work.
        // Attributed to `self.id`: this party is the one creating the session.
        {
            let store = self
                .get_or_create_store(session, self.id)
                .await
                .ok_or(Mod2Error::LimitError)?;
            let mut s = store.lock().await;
            s.r_prime = Some(prep.r_prime);
        }

        // Broadcast this party's share of c directly, point-to-point.
        // sub_id = self.id identifies the broadcaster; round_id = 0 distinguishes
        // single-value sessions from batch sessions (round_id = 1, see init_batch).
        let wire_session = SessionId::new(
            calling_proto,
            SessionId::pack_slot(session.exec_id(), self.id as u8, 0),
            session.instance_id(),
        );

        let mut payload = Vec::new();
        c_share.share[0].serialize_compressed(&mut payload)?;

        let mod2_msg = Mod2Message::new(self.id, wire_session, payload);
        let wrapped = WrappedMessage::Mod2(mod2_msg);
        let bytes_wrapped = wire_format::serialize(&wrapped)?;
        network.broadcast(&bytes_wrapped).await?;
        // If 2t+1 shares already arrived before r_prime was stored, finalize now.
        {
            let store = self
                .get_or_create_store(session, self.id)
                .await
                .ok_or(Mod2Error::LimitError)?;
            let ready = {
                let s = store.lock().await;
                s.r_prime.is_some() && s.received_shares.len() >= 2 * self.t + 1
            };
            if ready {
                self.try_finalize(session, store).await?;
            }
        }
        Ok(())
    }

    /// Batched Mod2: reveals m independent values (each `2^{k-1} + [a_i] +
    /// 2*[r''_i] + [r0'_i]`) in a single broadcast per party, avoiding the
    /// session collisions that m separate `init` calls sharing one exec_id
    /// would hit (see module docs). `a_vec` and `preps` must have equal,
    /// non-zero length, and `k >= 2` as in `init`. Keep routing incoming Mod2
    /// messages to `process` until `wait_for_batch_result` resolves.
    pub async fn init_batch<N: Network + Send + Sync>(
        &mut self,
        a_vec: Vec<RobustShare<F>>,
        k: usize,
        preps: Vec<PRandMPrep<F>>,
        session: SessionId,
        network: Arc<N>,
    ) -> Result<(), Mod2Error> {
        if a_vec.is_empty() || a_vec.len() != preps.len() {
            return Err(Mod2Error::SessionIdError(session));
        }
        // Same bound as `init`: 2^{k-1} must be even to leave c's parity intact.
        if k < 2 {
            return Err(Mod2Error::InvalidK(k));
        }

        let two = F::one() + F::one();
        let two_pow_k_minus_1 = two.pow([(k as u64) - 1]);

        let mut c_shares: Vec<F> = Vec::with_capacity(a_vec.len());
        let mut r_primes: Vec<RobustShare<F>> = Vec::with_capacity(a_vec.len());
        for (a, prep) in a_vec.into_iter().zip(preps.into_iter()) {
            let c_share = (((a + (prep.r_double_prime * two)?)? + prep.r_prime.clone())?
                + two_pow_k_minus_1)?;
            c_shares.push(c_share.share[0]);
            r_primes.push(prep.r_prime);
        }

        let calling_proto = session
            .calling_protocol()
            .ok_or(Mod2Error::SessionIdError(session))?;

        // Pre-create the store and save r_primes before any async work.
        // Attributed to `self.id`: this party is the one creating the session.
        {
            let store = self
                .get_or_create_batch_store(session, self.id)
                .await
                .ok_or(Mod2Error::LimitError)?;
            let mut s = store.lock().await;
            s.r_primes = Some(r_primes);
        }

        // Broadcast this party's m c-shares in one message, directly point-to-point.
        // round_id = 1 distinguishes batch sessions from single-value ones (round_id = 0).
        let wire_session = SessionId::new(
            calling_proto,
            SessionId::pack_slot(session.exec_id(), self.id as u8, 1),
            session.instance_id(),
        );

        let mut payload = Vec::new();
        c_shares.serialize_compressed(&mut payload)?;

        let mod2_msg = Mod2Message::new(self.id, wire_session, payload);
        let wrapped = WrappedMessage::Mod2(mod2_msg);
        let bytes_wrapped = wire_format::serialize(&wrapped)?;
        network.broadcast(&bytes_wrapped).await?;
        // If 2t+1 shares already arrived before r_primes was stored, finalize now.
        {
            let store = self
                .get_or_create_batch_store(session, self.id)
                .await
                .ok_or(Mod2Error::LimitError)?;
            let ready = {
                let s = store.lock().await;
                s.r_primes.is_some() && s.received_shares.len() >= 2 * self.t + 1
            };
            if ready {
                self.try_finalize_batch(session, store).await?;
            }
        }
        Ok(())
    }

    /// Handles a directly-opened share of `c`, accumulates it, and attempts to
    /// finalise once 2t+1 shares have arrived (retrying on later shares if
    /// decoding fails). `msg.sender` must already be authenticated by the caller
    /// (network-layer sender == `msg.sender`) before this is invoked.
    pub async fn process(&self, msg: Mod2Message) -> Result<(), Mod2Error> {
        let id = msg.session_id;
        let sender = msg.sender;
        let payload = msg.payload;
        let calling_proto = id.calling_protocol().ok_or(Mod2Error::SessionIdError(id))?;
        let parent = SessionId::new(
            calling_proto,
            SessionId::pack_slot(id.exec_id(), 0, 0),
            id.instance_id(),
        );

        if id.round_id() == 1 {
            // Bounded by payload.len(): an adversarial length header can't
            // reserve more memory than the bytes actually sent.
            let share_vals: Vec<F> = deser_bounded_vec(&mut payload.as_slice(), payload.len())?;
            // Attributed to `sender`: whichever party's message happens to
            // create this entry (same heuristic as Bracha/Avid), so no
            // single sender can flood past its own per-peer share.
            let store = match self.get_or_create_batch_store(parent, sender).await {
                Some(s) => s,
                None => return Ok(()),
            };
            let ready = {
                let mut s = store.lock().await;
                if s.state == PhaseState::Finished {
                    return Ok(());
                }
                // A malicious sender can broadcast a batch of the wrong length; reject it
                // here when the expected length is already known, and defensively filter
                // again in try_finalize_batch for shares stored before r_primes was set.
                if let Some(expected) = s.r_primes.as_ref().map(|r| r.len()) {
                    if share_vals.len() != expected {
                        warn!(
                            "Mod2 batch {parent:?}: dropping share from party {sender} with length {} (expected {expected})",
                            share_vals.len()
                        );
                        return Ok(());
                    }
                }
                s.received_shares.entry(sender).or_insert(share_vals);
                s.received_shares.len() >= 2 * self.t + 1
            };
            if ready {
                self.try_finalize_batch(parent, store).await?;
            }
            return Ok(());
        }

        let share_val: F = F::deserialize_compressed(payload.as_slice())?;

        // Attributed to `sender` — see the batch branch above for why.
        let store = match self.get_or_create_store(parent, sender).await {
            Some(s) => s,
            None => return Ok(()),
        };
        let ready = {
            let mut s = store.lock().await;
            if s.state == PhaseState::Finished {
                return Ok(());
            }
            s.received_shares.entry(sender).or_insert(share_val);
            s.received_shares.len() >= 2 * self.t + 1
        };

        if ready {
            self.try_finalize(parent, store).await?;
        }
        Ok(())
    }

    async fn try_finalize(
        &self,
        parent: SessionId,
        store_mutex: Arc<Mutex<Mod2Store<F>>>,
    ) -> Result<(), Mod2Error> {
        let (shares, r_zero_prime) = {
            let s = store_mutex.lock().await;
            if s.state == PhaseState::Finished {
                return Ok(());
            }
            if s.received_shares.len() < 2 * self.t + 1 {
                return Ok(());
            }
            let Some(rzp) = s.r_prime.clone() else {
                return Ok(());
            };
            (s.received_shares.clone(), rzp)
        };

        let robust_shares: Vec<RobustShare<F>> = shares
            .iter()
            .map(|(&id, &val)| RobustShare::new(val, id, self.t))
            .collect();

        let c = match RobustShare::recover_secret(&robust_shares, self.n, self.t) {
            Ok((_, c)) => c,
            // OEC needs degree+t+2 shares before it can correct even one error, so a
            // bad share makes this fail routinely at the quorum. Wait for the rest.
            Err(InterpolateError::DecodingError(_)) if robust_shares.len() < self.n => {
                return Ok(())
            }
            Err(_) => return Err(Mod2Error::Abort),
        };

        let c0 = if c.into_bigint().is_odd() {
            F::one()
        } else {
            F::zero()
        };

        // [a0] = [r0'] * (1 - 2*c0) + c0  =  XOR(c0, [r0'])
        let two = F::one() + F::one();
        let coeff = F::one() - two * c0;
        let a0 = ((r_zero_prime * coeff)? + c0)?;

        let sender = {
            let mut s = store_mutex.lock().await;
            if s.state == PhaseState::Finished {
                return Ok(());
            }
            s.state = PhaseState::Finished;
            s.output_sender.take().ok_or(Mod2Error::SendError(parent))?
        };
        sender.send(a0).map_err(|_| Mod2Error::SendError(parent))?;
        Ok(())
    }

    async fn try_finalize_batch(
        &self,
        parent: SessionId,
        store_mutex: Arc<Mutex<Mod2BatchStore<F>>>,
    ) -> Result<(), Mod2Error> {
        let (shares, r_primes) = {
            let s = store_mutex.lock().await;
            if s.state == PhaseState::Finished {
                return Ok(());
            }
            if s.received_shares.len() < 2 * self.t + 1 {
                return Ok(());
            }
            let Some(r_primes) = s.r_primes.clone() else {
                return Ok(());
            };
            (s.received_shares.clone(), r_primes)
        };

        let m = r_primes.len();
        // Shares may have been stored before r_primes was known locally (see
        // `process`), so re-validate lengths here before indexing into them —
        // a malformed length must never reach `vals[j]` below.
        let shares: HashMap<usize, Vec<F>> = shares
            .into_iter()
            .filter(|(sender, vals)| {
                let ok = vals.len() == m;
                if !ok {
                    warn!(
                        "Mod2 batch {parent:?}: excluding share from party {sender} with length {} (expected {m})",
                        vals.len()
                    );
                }
                ok
            })
            .collect();
        if shares.len() < 2 * self.t + 1 {
            // Not enough correctly-sized shares yet; wait for more to arrive.
            return Ok(());
        }

        let two = F::one() + F::one();
        let mut results: Vec<RobustShare<F>> = Vec::with_capacity(m);
        for (j, r_zero_prime) in r_primes.into_iter().enumerate() {
            let robust_shares: Vec<RobustShare<F>> = shares
                .iter()
                .map(|(&id, vals)| RobustShare::new(vals[j], id, self.t))
                .collect();
            let c = match RobustShare::recover_secret(&robust_shares, self.n, self.t) {
                Ok((_, c)) => c,
                // OEC needs degree+t+2 shares before it can correct even one error, so a
                // bad share makes this fail routinely at the quorum. Drop the partial
                // batch and retry the whole thing once the rest land.
                Err(InterpolateError::DecodingError(_)) if robust_shares.len() < self.n => {
                    return Ok(())
                }
                Err(_) => return Err(Mod2Error::Abort),
            };
            let c0 = if c.into_bigint().is_odd() {
                F::one()
            } else {
                F::zero()
            };
            let coeff = F::one() - two * c0;
            let a0 = ((r_zero_prime * coeff)? + c0)?;
            results.push(a0);
        }

        let sender = {
            let mut s = store_mutex.lock().await;
            if s.state == PhaseState::Finished {
                return Ok(());
            }
            s.state = PhaseState::Finished;
            s.output_sender.take().ok_or(Mod2Error::SendError(parent))?
        };
        sender
            .send(results)
            .map_err(|_| Mod2Error::SendError(parent))?;
        Ok(())
    }

    /// Batch counterpart of `wait_for_result`: blocks until all m results of
    /// `session` are ready (in input order) or `duration` elapses. Call after
    /// `init_batch`; single-consumer like `wait_for_result`.
    pub async fn wait_for_batch_result(
        &self,
        session: SessionId,
        duration: Duration,
    ) -> Result<Vec<RobustShare<F>>, Mod2Error> {
        let rx = {
            let map = self.batch_store.lock().await;
            let (_, _, inner) = map
                .get(&session)
                .ok_or(Mod2Error::NoSuchSessionId(session))?;
            let inner = inner.clone();
            drop(map);
            let mut s = inner.lock().await;
            s.output_receiver
                .take()
                .ok_or(Mod2Error::ResultAlreadyReceived(session))?
        };
        match timeout(duration, rx).await {
            Err(_) => Err(Mod2Error::Timeout(session)),
            Ok(Err(_)) => Err(Mod2Error::ReceiveError(session)),
            Ok(Ok(v)) => Ok(v),
        }
    }
}
