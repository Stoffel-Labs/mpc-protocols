//! PreMod2m — Protocol 9 (Catrina 2018).
//!
//! Given a secret-shared value `[a]` known to lie in [0, 2^k), computes:
//!
//!   {[a mod 2^i]}_{i=1}^{m}
//!
//! That is, m secret shares where the i-th share is `[a mod 2^i]`.
//!
//! # Algorithm
//!
//! 1. PRandM preprocessing gives `[r'']`, `[r']`, `{[r'_j]}_{j=0}^{m-1}`.
//! 2. Each party broadcasts its share of `v = 2^{k-1} + [a] + 2^m * [r''] + [r']`
//!    via RBC.  After n-t shares arrive all parties reconstruct `c` (public).
//! 3. For each i ∈ [1,m]:
//!    * `c_i = c mod 2^i`                             (public, lower i bits of c)
//!    * `[s_i] = Σ_{j=0}^{i-1} 2^j [r'_j]`          (prefix sum of random bits)
//! 4. `{[u_i]}_{i=1}^{m}` ← PreBitLT(c_bits[0..m-1], {[r'_j]})
//!    where c_bits are the lower m bits of c and {[r'_j]} are the secret bits.
//! 5. For each i ∈ [1,m]:
//!    `[a'_i] = c_i - [s_i] + 2^i * [u_i]`  = `[a mod 2^i]`
//!
//! # Replacing D-variants
//!
//! PreBitLT already uses Beaver Mul instead of local degree-2t products.
//! No additional substitutions are needed in this protocol.

use crate::{
    common::{ProtocolSessionId, SecretSharingScheme, RBC},
    honeybadger::{
        bitwise::{
            pre_bitlt::PreBitLTNode, pre_mulc::PhaseState, PreMod2mError, PreMod2mPrep,
            PreMod2mStore,
        },
        robust_interpolate::robust_interpolate::RobustShare,
        ProtocolType, SessionId, WrappedMessage,
    },
};

use ark_ff::{BigInteger, FftField, PrimeField};
use std::{collections::HashMap, sync::Arc};
use stoffelnet::network_utils::Network;
use tokio::{
    sync::{mpsc::Receiver, Mutex},
    time::{timeout, Duration},
};

const MAX_PRE_MOD2M_SESSIONS: usize = 1024;

// ── Node ───────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct PreMod2mNode<F: PrimeField + FftField, R: RBC> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    // Tagged with the party attributed with creating each entry, so a single
    // party can't flood this store past its own per-peer share of the cap
    // (same heuristic as Bracha/Avid's own session stores).
    store: Arc<Mutex<HashMap<SessionId, (usize, Arc<Mutex<PreMod2mStore<F>>>)>>>,
    pub rbc: R,
    rbc_output: Arc<Mutex<Receiver<SessionId>>>,
    /// Owned so `try_finalize` can run Phase 3 (PreBitLT) directly, without
    /// every caller having to thread a shared instance through each call.
    pub pre_bitlt: PreBitLTNode<F, R>,
}

impl<F: PrimeField + FftField, R: RBC<Id = SessionId>> PreMod2mNode<F, R> {
    pub fn new(id: usize, n: usize, t: usize) -> Result<Self, PreMod2mError> {
        let (rbc_sender, rbc_receiver) = tokio::sync::mpsc::channel(200);
        let rbc = R::new(
            id,
            n,
            t,
            t + 1,
            rbc_sender,
            Arc::new(WrappedMessage::rbc_wrap),
        )?;
        Ok(Self {
            id,
            n,
            t,
            store: Arc::new(Mutex::new(HashMap::new())),
            rbc,
            rbc_output: Arc::new(Mutex::new(rbc_receiver)),
            pre_bitlt: PreBitLTNode::new(id, n, t)?,
        })
    }

    async fn get_or_create_store(
        &self,
        session: SessionId,
        initiator_id: usize,
    ) -> Result<Arc<Mutex<PreMod2mStore<F>>>, PreMod2mError> {
        let mut map = self.store.lock().await;
        if !map.contains_key(&session) {
            if map.len() >= MAX_PRE_MOD2M_SESSIONS {
                return Err(PreMod2mError::LimitError);
            }
            let per_peer_limit = MAX_PRE_MOD2M_SESSIONS / self.n;
            let peer_count = map.values().filter(|(id, _)| *id == initiator_id).count();
            if peer_count >= per_peer_limit {
                return Err(PreMod2mError::LimitError);
            }
        }
        Ok(map
            .entry(session)
            .or_insert_with(|| (initiator_id, Arc::new(Mutex::new(PreMod2mStore::new()))))
            .1
            .clone())
    }

    pub async fn clear_store(&self, session: SessionId) -> Result<(), PreMod2mError> {
        self.rbc.clear_store().await;
        let mut map = self.store.lock().await;
        map.remove(&session)
            .map(|_| ())
            .ok_or(PreMod2mError::ClearStoreError(session))
    }

    /// Drains completed RBC outputs, handing each one to `handle_reveal_share`.
    /// Purely local, like every other `drain_*_output` in this codebase —
    /// safe to call inline from a shared dispatch loop. The nested PreBitLT
    /// round-trip needed to finish this protocol is driven separately, by
    /// `init`, in whatever task called it.
    pub async fn drain_rbc_output(&mut self) -> Result<(), PreMod2mError> {
        loop {
            let id = {
                let mut rx = self.rbc_output.lock().await;
                match rx.try_recv() {
                    Ok(id) => id,
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        return Err(PreMod2mError::Abort)
                    }
                }
            };

            let payload = self.rbc.get_store(id).await?;
            let share_val: F = F::deserialize_compressed(payload.as_slice())?;
            let sender = id.sub_id() as usize;

            // Recover the parent session (sub_id=0, round_id=0) from this
            // broadcaster's RBC session (sub_id=party_id, round_id=0).
            let parent = SessionId::new(
                ProtocolType::FpDiv,
                SessionId::pack_slot(id.exec_id(), 0, 0),
                id.instance_id(),
            );

            self.handle_reveal_share(parent, sender, share_val).await?;
        }
        Ok(())
    }

    /// Records one party's share of v and, once n-t shares are in, calls
    /// `try_finalize` to complete Phase 1-2.
    async fn handle_reveal_share(
        &mut self,
        parent: SessionId,
        sender: usize,
        share_val: F,
    ) -> Result<(), PreMod2mError> {
        // Attributed to `sender` — whichever party's message happens to
        // create this entry, so no single sender can flood past its own
        // per-peer share of the cap.
        let store = self.get_or_create_store(parent, sender).await?;
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

    /// Reconstructs `c` once enough shares are in, then runs Phase 2 (local
    /// bit/prefix extraction) and gathers Phase 3's inputs, sending them
    /// through the store's oneshot. Entirely local — never touches the
    /// network, so it's safe to call inline from a shared dispatch loop.
    /// Called both from `init` (in case n-t shares already arrived before
    /// `init` completed) and from `drain_rbc_output` once a fresh share
    /// pushes the count over threshold.
    async fn try_finalize(
        &mut self,
        parent: SessionId,
        store_mutex: Arc<Mutex<PreMod2mStore<F>>>,
    ) -> Result<(), PreMod2mError> {
        let (m, shares) = {
            let s = store_mutex.lock().await;
            if s.state == PhaseState::Finished {
                return Ok(());
            }
            if s.received_shares.len() < 2 * self.t + 1 {
                return Ok(());
            }
            let Some(m) = s.m else {
                // init() hasn't set m yet: shares are buffered, can't finish.
                return Ok(());
            };
            (m, s.received_shares.clone())
        };

        let robust_shares: Vec<RobustShare<F>> = shares
            .iter()
            .map(|(&id, &val)| RobustShare::new(val, id, self.t))
            .collect();

        let (_, c) = RobustShare::recover_secret(&robust_shares, self.n, self.t)
            .map_err(|_| PreMod2mError::Abort)?;

        // Phase 2: extract bits and prefix values from public c.
        //
        // c mod 2^i = (a + r') mod 2^i  (the 2^{k-1} and 2^m terms vanish for i ≤ m).
        //
        // c_bits[j]        = j-th bit of c (0 = LSB).
        // c_prefix_vals[j] = c mod 2^{j+1}  (used as c_{j+1} in paper notation).
        // s_vals[j]        = [s_{j+1}] = Σ_{l=0}^{j} 2^l [r'_l].
        let c_bigint = c.into_bigint();

        let c_bits: Vec<F> = (0..m)
            .map(|j| {
                if c_bigint.get_bit(j) {
                    F::one()
                } else {
                    F::zero()
                }
            })
            .collect();

        let mut c_prefix_vals: Vec<F> = Vec::with_capacity(m);
        {
            let mut acc = F::zero();
            let mut pw = F::one();
            for j in 0..m {
                if c_bigint.get_bit(j) {
                    acc += pw;
                }
                c_prefix_vals.push(acc); // c mod 2^{j+1}
                pw = pw + pw;
            }
        }

        let (r_prime_bits, pre_bitlt_prep) = {
            let mut s = store_mutex.lock().await;
            if s.state == PhaseState::Finished {
                return Ok(());
            }
            let r_prime_bits = s
                .r_prime_bits
                .take()
                .ok_or(PreMod2mError::ResultAlreadyReceived(parent))?;
            let pre_bitlt_prep = s
                .pre_bitlt_prep
                .take()
                .ok_or(PreMod2mError::ResultAlreadyReceived(parent))?;
            (r_prime_bits, pre_bitlt_prep)
        };

        let two = F::one() + F::one();

        // s_vals[j] = s_{j+1}: cumulative prefix of the m random bit shares.
        let mut s_vals: Vec<RobustShare<F>> = Vec::with_capacity(m);
        {
            // s_1 = r'_0
            let mut s_prefix = r_prime_bits[0].clone();
            s_vals.push(s_prefix.clone());
            let mut pw = two; // starts at 2^1
            for j in 1..m {
                let term = (r_prime_bits[j].clone() * pw)?;
                s_prefix = (s_prefix + term)?;
                s_vals.push(s_prefix.clone());
                pw = pw + pw;
            }
        }

        let sender = {
            let mut s = store_mutex.lock().await;
            if s.state == PhaseState::Finished {
                return Ok(());
            }
            s.state = PhaseState::Finished;
            s.output_sender
                .take()
                .ok_or(PreMod2mError::SendError(parent))?
        };
        sender
            .send((c_bits, r_prime_bits, pre_bitlt_prep, c_prefix_vals, s_vals))
            .map_err(|_| PreMod2mError::SendError(parent))?;
        Ok(())
    }

    /// Runs Protocol 9 (PreMod2m) to completion: broadcasts this party's
    /// share of v via RBC, awaits the reveal (driven concurrently by the
    /// outer message loop's `drain_rbc_output`), then drives Phase 3 (nested
    /// PreBitLT) and Phase 4 (local assembly) itself before returning
    /// `[[a mod 2], [a mod 4], ..., [a mod 2^m]]`. Must be called from a
    /// dedicated driver task, never from the shared dispatch loop — it
    /// blocks through PreBitLT's own multi-round round-trip.
    ///
    /// Callers must call `clear_store` on `session` once they're done with
    /// the result — on every exit path, not just success (see module-level
    /// DoS note) — the same way callers already do for `Multiply`/`TruncPr`.
    ///
    /// # Arguments
    /// * `a`         – secret share of the value; must lie in [0, 2^k).
    /// * `k`         – declared bit length of a (k ≥ 2).
    /// * `m`         – number of prefix reductions (2 ≤ m < k, per the paper).
    /// * `prep`      – all preprocessing.
    /// * `session`   – caller session; `instance_id()` is inherited.
    /// * `network`   – network handle shared with the message loop.
    /// * `duration`  – timeout for the reveal and for PreBitLT's own rounds.
    pub async fn init<N: Network + Send + Sync + 'static>(
        &mut self,
        a: RobustShare<F>,
        k: usize,
        m: usize,
        prep: PreMod2mPrep<F>,
        session: SessionId,
        network: Arc<N>,
        duration: Duration,
    ) -> Result<Vec<RobustShare<F>>, PreMod2mError> {
        if k < 2 {
            return Err(PreMod2mError::InvalidInput(format!(
                "k must be ≥ 2 (got {k})"
            )));
        }
        // m < k strictly, per the paper: the 2^{k-1} reveal offset only
        // vanishes mod 2^i for i ≤ k-1, so the prefix at i = k would be
        // corrupted by the offset. Callers needing a mod 2^k already hold it:
        // for a ∈ [0, 2^k) it is [a] itself.
        if m < 2 || m >= k {
            return Err(PreMod2mError::InvalidInput(format!(
                "m must be in [2, k={k}) (got {m})"
            )));
        }
        if prep.prandm.r_prime_bits.len() != m {
            return Err(PreMod2mError::InvalidInput(format!(
                "r_prime_bits.len() ({}) != m ({m})",
                prep.prandm.r_prime_bits.len()
            )));
        }

        let two = F::one() + F::one();

        // ── Phase 1: broadcast share of v = 2^{k-1} + [a] + 2^m * [r''] + [r'] ─

        let two_k_minus_1 = two.pow([(k as u64) - 1]);
        let two_m = two.pow([m as u64]);

        let v_share = (((a + two_k_minus_1)? + (prep.prandm.r_double_prime.clone() * two_m)?)?
            + prep.prandm.r_prime.clone())?;

        // Pre-create the store and stash everything try_finalize needs after
        // the reveal — set before starting the RBC broadcast so a
        // fast-arriving share can never race ahead of this being in place.
        {
            let store = self.get_or_create_store(session, self.id).await?;
            let mut s = store.lock().await;
            s.m = Some(m);
            s.r_prime_bits = Some(prep.prandm.r_prime_bits);
            s.pre_bitlt_prep = Some(prep.pre_bitlt);
        }

        let calling_proto = session
            .calling_protocol()
            .ok_or(PreMod2mError::SessionIdError(session))?;

        let rbc_session = SessionId::new(
            calling_proto,
            SessionId::pack_slot(session.exec_id(), self.id as u8, 4),
            session.instance_id(),
        );
        let mut payload = Vec::new();
        v_share.share[0].serialize_compressed(&mut payload)?;
        self.rbc
            .init(payload, rbc_session, Arc::clone(&network))
            .await?;

        // If n-t shares already arrived during init, finalize immediately.
        {
            let store = self
                .store
                .lock()
                .await
                .get(&session)
                .map(|(_, s)| s.clone())
                .ok_or(PreMod2mError::NoSuchSessionId(session))?;
            let ready = {
                let s = store.lock().await;
                s.received_shares.len() >= 2 * self.t + 1
            };
            if ready {
                self.try_finalize(session, store).await?;
            }
        }

        // Await Phase 1-2's local-only result (resolved either by the
        // early-arrival check above, or concurrently by the outer message
        // loop's drain_rbc_output → try_finalize).
        let (c_bits, r_prime_bits, pre_bitlt_prep, c_prefix_vals, s_vals) = {
            let rx = {
                let store = self
                    .store
                    .lock()
                    .await
                    .get(&session)
                    .map(|(_, s)| s.clone())
                    .ok_or(PreMod2mError::NoSuchSessionId(session))?;
                let mut s = store.lock().await;
                s.output_receiver
                    .take()
                    .ok_or(PreMod2mError::ResultAlreadyReceived(session))?
            };
            match timeout(duration, rx).await {
                Err(_) => return Err(PreMod2mError::Timeout(session)),
                Ok(Err(_)) => return Err(PreMod2mError::ReceiveError(session)),
                Ok(Ok(intermediate)) => intermediate,
            }
        };

        // ── Phase 3: PreBitLT(c_bits, r_prime_bits) → {[u_j]} ────────────────
        //
        // Public input  = c_bits[0..m-1] (lower m bits of revealed c).
        // Secret input  = r'_bits[0..m-1] (the m random bits from PRandM).
        // u_j = (c'_j < r'_j) = carry-out of bit j when computing a + r'.
        //
        let bitlt_session = SessionId::new(
            calling_proto,
            SessionId::pack_slot(session.exec_id(), 0, 0),
            session.instance_id(),
        );
        let u_shares = self
            .pre_bitlt
            .init(
                c_bits,
                r_prime_bits,
                pre_bitlt_prep,
                bitlt_session,
                network,
                duration,
            )
            .await?;

        // ── Phase 4: [a'_{j+1}] = c_{j+1} - [s_{j+1}] + 2^{j+1} * [u_{j+1}] ─
        //
        // 0-indexed: c_prefix_vals[j] = c_{j+1}, s_vals[j] = s_{j+1},
        // u_shares[j] = u_{j+1}.
        //
        // Derivation: carries from PreBitLT correct for whether a + r' overflows
        // at each prefix position, recovering exactly a mod 2^{j+1}.
        let neg_one = -F::one();
        let mut results: Vec<RobustShare<F>> = Vec::with_capacity(m);
        let mut two_i = two; // 2^{j+1}: starts at 2^1 and doubles each iteration
        for j in 0..m {
            let neg_s = (s_vals[j].clone() * neg_one)?;
            let neg_s_plus_c = (neg_s + c_prefix_vals[j])?;
            let u_scaled = (u_shares[j].clone() * two_i)?;
            let a_prime = (neg_s_plus_c + u_scaled)?;
            results.push(a_prime);
            two_i = two_i + two_i;
        }

        Ok(results)
    }
}
