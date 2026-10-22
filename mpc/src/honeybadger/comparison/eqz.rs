//! EQZ — Protocol 3.7 (Catrina & de Hoogh 2010).
//!
//! Computes [a = 0] given [a] and PRandM(k, k) preprocessing.
//!
//! Protocol:
//!   1. ([r''], [r'], [r'_{k-1}], ..., [r'_0]) ← PRandM(k, k)
//!   2. c ← Open([a] + 2^k·[r''] + [r'])       (broadcast own share via RBC)
//!   3. (c_{k-1}, ..., c_0) ← Bits(c, k)        (extract low k bits; public)
//!   4. [d_i] ← c_i + [r'_i] − 2·c_i·[r'_i]   (= XOR(c_i, [r'_i]); local)
//!   5. [u] ← KOrCL([d_{k-1}], ..., [d_0])
//!   6. return 1 − [u]
//!
//! # No `2^{k-1}` reveal offset
//!
//! Sibling protocols in this family (Mod2m, and `PreMod2m` here) open
//! `2^{k-1} + [a] + ...` so the opened value is non-negative by construction.
//! That offset is invisible to them because they only ever consume `c mod 2^i`
//! for `i ≤ k-1`, and `2^{k-1} ≡ 0 (mod 2^i)` there — see the `m >= k` rejection
//! in `PreMod2mNode::init` for the same boundary stated from the other side.
//!
//! EQZ consumes all `k` low bits, and `2^{k-1} mod 2^k = 2^{k-1} ≠ 0`, so the
//! offset would *not* vanish: it flips bit `k-1` of `c`, making `d ≠ 0` even
//! when `a = 0`, and EQZ would answer 0 for a zero input. It is therefore
//! deliberately absent here.

use crate::common::wire_format;
use crate::{
    common::{
        session_store::{Admission, SessionStore},
        ProtocolSessionId, SecretSharingScheme,
    },
    honeybadger::{
        bitwise::{kor_cl::KOrCLNode, kor_cs::KOrCSPrep, pre_mulc::PhaseState, PRandMPrep},
        comparison::{EQZError, EqzMessage},
        robust_interpolate::{robust_interpolate::RobustShare, InterpolateError},
        SessionId, WrappedMessage,
    },
};
use ark_ff::{BigInteger, PrimeField};
use std::{collections::HashMap, sync::Arc, time::Instant};
use stoffelnet::network_utils::Network;
use tokio::{
    sync::Mutex,
    time::{timeout, Duration},
};
use tracing::warn;

const MAX_EQZ_SESSIONS: usize = 256;

// ── Store ──────────────────────────────────────────────────────────────────────
#[derive(Debug)]
struct EQZStore<F: PrimeField> {
    state: PhaseState,
    k: usize,
    r_prime_bits: Option<Vec<RobustShare<F>>>,
    received_shares: HashMap<usize, F>,
    output_sender: Option<tokio::sync::oneshot::Sender<Vec<RobustShare<F>>>>,
    output_receiver: Option<tokio::sync::oneshot::Receiver<Vec<RobustShare<F>>>>,
}

impl<F: PrimeField> EQZStore<F> {
    fn new() -> Self {
        let (tx, rx) = tokio::sync::oneshot::channel();
        Self {
            state: PhaseState::Waiting,
            k: 0,
            r_prime_bits: None,
            received_shares: HashMap::new(),
            output_sender: Some(tx),
            output_receiver: Some(rx),
        }
    }
}

// ── Node ───────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct EQZNode<F: PrimeField> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    store: Arc<Mutex<SessionStore<SessionId, (usize, Instant, Arc<Mutex<EQZStore<F>>>)>>>,
    pub kor_cl: KOrCLNode<F>,
}

impl<F: PrimeField> EQZNode<F> {
    pub fn new(id: usize, n: usize, t: usize) -> Result<Self, EQZError> {
        Ok(Self {
            id,
            n,
            t,
            store: Arc::new(Mutex::new(SessionStore::with_default_cap())),
            kor_cl: KOrCLNode::new(id, n, t)?,
        })
    }

    async fn get_or_create_store(
        &self,
        session: SessionId,
        initiator_id: usize,
    ) -> Option<Arc<Mutex<EQZStore<F>>>> {
        match self.store.lock().await.get_or_admit(
            session,
            initiator_id,
            MAX_EQZ_SESSIONS,
            MAX_EQZ_SESSIONS / self.n,
            || Arc::new(Mutex::new(EQZStore::new())),
        ) {
            Admission::Got(arc) => Some(arc),
            Admission::Retired => None,
            Admission::Rejected => {
                warn!("EQZ session limit reached");
                None
            }
        }
    }

    /// Clears this session's own store. `run` is itself responsible for
    /// clearing the inner `KOrCL` session it drives — see the end of `run`.
    pub async fn clear_store(&self, session: SessionId) -> bool {
        self.store.lock().await.retire(session)
    }

    /// Handles a directly-opened share of `c`. `msg.sender` must already be
    /// authenticated by the caller (network-layer sender == `msg.sender`)
    /// before this is invoked.
    pub async fn process(&mut self, msg: EqzMessage) -> Result<(), EQZError> {
        let id = msg.session_id;
        let share_val: F = F::deserialize_compressed(msg.payload.as_slice())?;
        let sender = msg.sender;

        let calling_proto = id.calling_protocol().ok_or(EQZError::SessionIdError(id))?;
        let parent = SessionId::new(
            calling_proto,
            SessionId::pack_slot(id.exec_id(), 0, 0),
            id.instance_id(),
        );

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

    async fn wait_for_d_bits(
        &self,
        session: SessionId,
        duration: Duration,
    ) -> Result<Vec<RobustShare<F>>, EQZError> {
        let rx = {
            let map = self.store.lock().await;
            let (_, _, inner) = map
                .get(&session)
                .ok_or(EQZError::NoSuchSessionId(session))?
                .clone();
            let mut s = inner.lock().await;
            s.output_receiver
                .take()
                .ok_or(EQZError::ResultAlreadyReceived(session))?
        };
        match timeout(duration, rx).await {
            Err(_) => Err(EQZError::Timeout(session)),
            Ok(Err(_)) => Err(EQZError::ReceiveError(session)),
            Ok(Ok(v)) => Ok(v),
        }
    }

    async fn try_finalize(
        &self,
        parent: SessionId,
        store_mutex: Arc<Mutex<EQZStore<F>>>,
    ) -> Result<(), EQZError> {
        let (shares, k, r_prime_bits) = {
            let s = store_mutex.lock().await;
            if s.state == PhaseState::Finished {
                return Ok(());
            }
            if s.received_shares.len() < 2 * self.t + 1 {
                return Ok(());
            }
            let Some(rb) = s.r_prime_bits.clone() else {
                return Ok(());
            };
            (s.received_shares.clone(), s.k, rb)
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
            Err(_) => return Err(EQZError::Abort),
        };

        let c_int = c.into_bigint();
        let two = F::one() + F::one();
        let mut d_bits: Vec<RobustShare<F>> = Vec::with_capacity(k);
        for i in 0..k {
            let c_i = if c_int.get_bit(i) {
                F::one()
            } else {
                F::zero()
            };
            // XOR(c_i, [r_i']) = c_i + [r_i'] - 2·c_i·[r_i']
            let coeff = F::one() - two * c_i;
            let d_i = ((r_prime_bits[i].clone() * coeff)? + c_i)?;
            d_bits.push(d_i);
        }

        let sender = {
            let mut s = store_mutex.lock().await;
            if s.state == PhaseState::Finished {
                return Ok(());
            }
            s.state = PhaseState::Finished;
            s.output_sender.take().ok_or(EQZError::SendError(parent))?
        };
        sender
            .send(d_bits)
            .map_err(|_| EQZError::SendError(parent))?;
        Ok(())
    }

    /// Protocol 3.7 EQZ.
    ///
    /// `a`: secret share of the value to test. Tested **modulo 2^k**, so signed
    ///   values in Z⟨k⟩ = [-2^{k-1}, 2^{k-1}) are accepted as well as unsigned
    ///   ones in [0, 2^k) — `(r' + a) mod 2^k = r'` iff `a ≡ 0 (mod 2^k)`, and
    ///   no value in either range other than 0 is ≡ 0. This is what `eqz_int`
    ///   relies on, since `SecretInt` carries signed values.
    ///
    ///   For negative `a` the opened `c = 2^k·[r''] + [r'] + [a]` stays
    ///   non-negative whenever `r'' ≥ 1` (as `2^k > |a|`); it can only wrap when
    ///   `r'' = 0` *and* `r' < |a|`, i.e. with probability ~2^-dp_bits — the
    ///   usual statistical-security bound, not a distinct failure mode. Unlike
    ///   Mod2m there is no `2^{k-1}` offset available to rule this out
    ///   deterministically (see the module docs for why).
    /// `k`: bit length of `a`.
    /// `prandm`: PRandM(k, k) for masking a.
    /// `kor_cl_prandm`: PRandM(k, m) for KOrCL (m = floor(log2(k))+1).
    /// `kor_cs_prep`: KOrCSPrep for KOrCS with m inputs.
    pub async fn run<N: Network + Send + Sync>(
        &mut self,
        a: RobustShare<F>,
        k: usize,
        prandm: PRandMPrep<F>,
        kor_cl_prandm: PRandMPrep<F>,
        kor_cs_prep: KOrCSPrep<F>,
        session: SessionId,
        network: Arc<N>,
        duration: Duration,
    ) -> Result<RobustShare<F>, EQZError> {
        if k == 0 {
            return Err(EQZError::LengthError);
        }
        // `try_finalize` indexes `r_prime_bits[0..k]`, and it runs on the
        // message-processing path — a short prep would panic the receive task
        // rather than surfacing here. Reject it while we can still return.
        if prandm.r_prime_bits.len() < k {
            return Err(EQZError::LengthError);
        }

        let calling_proto = session
            .calling_protocol()
            .ok_or(EQZError::SessionIdError(session))?;
        let two = F::one() + F::one();

        // c_share = [a] + 2^k·[r''] + [r']
        let two_pow_k = two.pow([k as u64]);
        let c_share = (((prandm.r_double_prime * two_pow_k)? + prandm.r_prime)? + a)?;

        {
            let store = self
                .get_or_create_store(session, self.id)
                .await
                .ok_or(EQZError::LimitError)?;
            let mut s = store.lock().await;
            s.k = k;
            s.r_prime_bits = Some(prandm.r_prime_bits);
        }

        // Broadcast this party's share of c directly, point-to-point.
        let wire_session = SessionId::new(
            calling_proto,
            SessionId::pack_slot(session.exec_id(), self.id as u8, 0),
            session.instance_id(),
        );
        let mut payload = Vec::new();
        c_share.share[0].serialize_compressed(&mut payload)?;
        let eqz_msg = EqzMessage::new(self.id, wire_session, payload);
        let wrapped = WrappedMessage::Eqz(eqz_msg);
        let bytes_wrapped = wire_format::serialize(&wrapped)?;
        network.broadcast(&bytes_wrapped).await?;

        {
            let store = self
                .get_or_create_store(session, self.id)
                .await
                .ok_or(EQZError::LimitError)?;
            let ready = {
                let s = store.lock().await;
                s.r_prime_bits.is_some() && s.received_shares.len() >= 2 * self.t + 1
            };
            if ready {
                self.try_finalize(session, store).await?;
            }
        }

        // Wait until `process` reconstructs c and computes d_bits.
        let d_bits_result = self.wait_for_d_bits(session, duration).await;
        // This party's own c_share-open phase is done either way; clear it
        // before propagating so a failure here doesn't leak the slot.
        self.clear_store(session).await;
        let d_bits = d_bits_result?;

        // KOrCL on the k d_bits, then negate. EQZ called it, so EQZ clears it
        // on every exit path, not just success.
        let u_result = self
            .kor_cl
            .run(
                d_bits,
                kor_cl_prandm,
                kor_cs_prep,
                session,
                network,
                duration,
            )
            .await;
        self.kor_cl.clear_store(session).await;
        let u = u_result?;

        // Return 1 − u.
        let neg_one = F::zero() - F::one();
        Ok(((u * neg_one)? + F::one())?)
    }
}
