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

use crate::{
    common::{ProtocolSessionId, SecretSharingScheme, RBC},
    honeybadger::{
        comparison::{
            kor_cl::KOrCLNode, kor_cs::KOrCSPrep, pre_mulc::PhaseState, EQZError, PRandMPrep,
        },
        robust_interpolate::robust_interpolate::RobustShare,
        SessionId, WrappedMessage,
    },
};
use ark_ff::{BigInteger, PrimeField};
use std::{collections::HashMap, sync::Arc};
use stoffelnet::network_utils::Network;
use tokio::{
    sync::{mpsc::Receiver, Mutex},
    time::{timeout, Duration},
};

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
pub struct EQZNode<F: PrimeField, R: RBC> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    store: Arc<Mutex<HashMap<SessionId, Arc<Mutex<EQZStore<F>>>>>>,
    pub rbc: R,
    pub rbc_output: Arc<Mutex<Receiver<SessionId>>>,
    pub kor_cl: KOrCLNode<F, R>,
}

impl<F: PrimeField, R: RBC<Id = SessionId>> EQZNode<F, R> {
    pub fn new(id: usize, n: usize, t: usize) -> Result<Self, EQZError> {
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
            kor_cl: KOrCLNode::new(id, n, t)?,
        })
    }

    async fn get_or_create_store(
        &self,
        session: SessionId,
    ) -> Result<Arc<Mutex<EQZStore<F>>>, EQZError> {
        let mut map = self.store.lock().await;
        if map.len() >= 256 && !map.contains_key(&session) {
            return Err(EQZError::LimitError);
        }
        Ok(map
            .entry(session)
            .or_insert_with(|| Arc::new(Mutex::new(EQZStore::new())))
            .clone())
    }

    pub async fn clear_store(&self, session: SessionId) -> Result<(), EQZError> {
        self.rbc.clear_store().await;
        let mut map = self.store.lock().await;
        map.remove(&session)
            .map(|_| ())
            .ok_or(EQZError::ClearStoreError(session))
    }

    /// Drive completions from self.rbc. Route Rbc round_id=3 messages here.
    pub async fn drain_rbc_output(&mut self) -> Result<(), EQZError> {
        loop {
            let id = {
                let mut rx = self.rbc_output.lock().await;
                match rx.try_recv() {
                    Ok(id) => id,
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        return Err(EQZError::Abort);
                    }
                }
            };

            let payload = self.rbc.get_store(id).await?;
            let share_val: F = F::deserialize_compressed(payload.as_slice())?;
            let sender = id.sub_id() as usize;

            let calling_proto = id.calling_protocol().ok_or(EQZError::SessionIdError(id))?;
            let parent = SessionId::new(
                calling_proto,
                SessionId::pack_slot24(id.exec_id(), 0, 0),
                id.instance_id(),
            );

            let store = self.get_or_create_store(parent).await?;
            let ready = {
                let mut s = store.lock().await;
                if s.state == PhaseState::Finished {
                    continue;
                }
                s.received_shares.entry(sender).or_insert(share_val);
                s.received_shares.len() >= 2 * self.t + 1
            };

            if ready {
                self.try_finalize(parent, store).await?;
            }
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
            let inner = map
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
        let (_, c) = RobustShare::recover_secret(&robust_shares, self.n, self.t)
            .map_err(|_| EQZError::Abort)?;

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
    /// `a`: secret share of the value to test.
    /// `k`: bit length of `a` (0 ≤ a < 2^k).
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

        let calling_proto = session
            .calling_protocol()
            .ok_or(EQZError::SessionIdError(session))?;
        let two = F::one() + F::one();

        // c_share = [a] + 2^k·[r''] + [r']
        let two_pow_k = two.pow([k as u64]);
        let c_share = (((prandm.r_double_prime * two_pow_k)? + prandm.r_prime)? + a)?;

        {
            let store = self.get_or_create_store(session).await?;
            let mut s = store.lock().await;
            s.k = k;
            s.r_prime_bits = Some(prandm.r_prime_bits);
        }

        let rbc_session = SessionId::new(
            calling_proto,
            SessionId::pack_slot24(session.exec_id(), self.id as u8, 0),
            session.instance_id(),
        );
        let mut payload = Vec::new();
        c_share.share[0].serialize_compressed(&mut payload)?;
        self.rbc
            .init(payload, rbc_session, Arc::clone(&network))
            .await?;

        {
            let store = self.get_or_create_store(session).await?;
            let ready = {
                let s = store.lock().await;
                s.r_prime_bits.is_some() && s.received_shares.len() >= 2 * self.t + 1
            };
            if ready {
                self.try_finalize(session, store).await?;
            }
        }

        // Wait until drain_rbc_output reconstructs c and computes d_bits.
        let d_bits = self.wait_for_d_bits(session, duration).await?;

        // KOrCL on the k d_bits, then negate.
        let u = self
            .kor_cl
            .run(
                d_bits,
                kor_cl_prandm,
                kor_cs_prep,
                session,
                network,
                duration,
            )
            .await?;

        // Return 1 − u.
        let neg_one = F::zero() - F::one();
        Ok(((u * neg_one)? + F::one())?)
    }
}
