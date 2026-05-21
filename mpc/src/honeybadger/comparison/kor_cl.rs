//! KOrCL — Protocol 4.3 (Catrina & de Hoogh 2010).
//!
//! k-ary OR with log-round reduction via PRandM masking then KOrCS.
//!
//! Protocol (k inputs each in {0,1}):
//!   m = floor(log2(k)) + 1   (ensures 2^m > k strictly; paper writes ⌈log(k)⌉)
//!   1. ([r''], [r'], [r'_{m-1}], ..., [r'_0]) ← PRandM(k, m)
//!   2. c ← Open(2^m·[r''] + [r'] + Σ[a_i])   (broadcast own share via RBC)
//!   3. (c_m, ..., c_1) ← Bits(c, m)            (extract low m bits of c; public)
//!   4. [d_i] ← c_i + [r'_i] − 2·c_i·[r'_i]   (= XOR(c_i, [r'_i]); local)
//!   5. [e] ← KOrCS([d_1], ..., [d_m])

use crate::{
    common::{ProtocolSessionId, SecretSharingScheme, RBC},
    honeybadger::{
        comparison::{
            kor_cs::{KOrCSNode, KOrCSPrep},
            pre_mulc::PhaseState,
            KOrCLError, PRandMPrep,
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
struct KOrCLStore<F: PrimeField> {
    state: PhaseState,
    m: usize,
    r_prime_bits: Option<Vec<RobustShare<F>>>,
    received_shares: HashMap<usize, F>,
    output_sender: Option<tokio::sync::oneshot::Sender<Vec<RobustShare<F>>>>,
    output_receiver: Option<tokio::sync::oneshot::Receiver<Vec<RobustShare<F>>>>,
}

impl<F: PrimeField> KOrCLStore<F> {
    fn new() -> Self {
        let (tx, rx) = tokio::sync::oneshot::channel();
        Self {
            state: PhaseState::Waiting,
            m: 0,
            r_prime_bits: None,
            received_shares: HashMap::new(),
            output_sender: Some(tx),
            output_receiver: Some(rx),
        }
    }
}

// ── Node ───────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct KOrCLNode<F: PrimeField, R: RBC> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    store: Arc<Mutex<HashMap<SessionId, Arc<Mutex<KOrCLStore<F>>>>>>,
    pub rbc: R,
    pub rbc_output: Arc<Mutex<Receiver<SessionId>>>,
    pub kor_cs: KOrCSNode<F, R>,
}

impl<F: PrimeField, R: RBC<Id = SessionId>> KOrCLNode<F, R> {
    pub fn new(id: usize, n: usize, t: usize) -> Result<Self, KOrCLError> {
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
            kor_cs: KOrCSNode::new(id, n, t)?,
        })
    }

    async fn get_or_create_store(
        &self,
        session: SessionId,
    ) -> Result<Arc<Mutex<KOrCLStore<F>>>, KOrCLError> {
        let mut map = self.store.lock().await;
        if map.len() >= 256 && !map.contains_key(&session) {
            return Err(KOrCLError::LimitError);
        }
        Ok(map
            .entry(session)
            .or_insert_with(|| Arc::new(Mutex::new(KOrCLStore::new())))
            .clone())
    }

    pub async fn clear_store(&self, session: SessionId) -> Result<(), KOrCLError> {
        self.rbc.clear_store().await;
        let mut map = self.store.lock().await;
        map.remove(&session)
            .map(|_| ())
            .ok_or(KOrCLError::ClearStoreError(session))
    }

    /// Drive completions from self.rbc. Route Rbc round_id=1 messages here.
    pub async fn drain_rbc_output(&mut self) -> Result<(), KOrCLError> {
        loop {
            let id = {
                let mut rx = self.rbc_output.lock().await;
                match rx.try_recv() {
                    Ok(id) => id,
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        return Err(KOrCLError::Abort);
                    }
                }
            };

            let payload = self.rbc.get_store(id).await?;
            let share_val: F = F::deserialize_compressed(payload.as_slice())?;
            let sender = id.sub_id() as usize;

            let calling_proto = id
                .calling_protocol()
                .ok_or(KOrCLError::SessionIdError(id))?;
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
    ) -> Result<Vec<RobustShare<F>>, KOrCLError> {
        let rx = {
            let map = self.store.lock().await;
            let inner = map
                .get(&session)
                .ok_or(KOrCLError::NoSuchSessionId(session))?
                .clone();
            let mut s = inner.lock().await;
            s.output_receiver
                .take()
                .ok_or(KOrCLError::ResultAlreadyReceived(session))?
        };
        match timeout(duration, rx).await {
            Err(_) => Err(KOrCLError::Timeout(session)),
            Ok(Err(_)) => Err(KOrCLError::ReceiveError(session)),
            Ok(Ok(v)) => Ok(v),
        }
    }

    async fn try_finalize(
        &self,
        parent: SessionId,
        store_mutex: Arc<Mutex<KOrCLStore<F>>>,
    ) -> Result<(), KOrCLError> {
        let (shares, m, r_prime_bits) = {
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
            (s.received_shares.clone(), s.m, rb)
        };

        let robust_shares: Vec<RobustShare<F>> = shares
            .iter()
            .map(|(&id, &val)| RobustShare::new(val, id, self.t))
            .collect();
        let (_, c) = RobustShare::recover_secret(&robust_shares, self.n, self.t)
            .map_err(|_| KOrCLError::Abort)?;

        let c_int = c.into_bigint();
        let two = F::one() + F::one();
        let mut d_bits: Vec<RobustShare<F>> = Vec::with_capacity(m);
        for i in 0..m {
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
            s.output_sender
                .take()
                .ok_or(KOrCLError::SendError(parent))?
        };
        sender
            .send(d_bits)
            .map_err(|_| KOrCLError::SendError(parent))?;
        Ok(())
    }

    /// Protocol 4.3 KOrCL.
    ///
    /// `a_bits`: secret shares of k input bits in {0,1}.
    /// `prandm`: PRandM(k, m) prep — r'' is k-bit, r_prime_bits has m bits (LSB first).
    /// `kor_cs_prep`: KOrCSPrep for KOrCS with m inputs.
    pub async fn run<N: Network + Send + Sync>(
        &mut self,
        a_bits: Vec<RobustShare<F>>,
        prandm: PRandMPrep<F>,
        kor_cs_prep: KOrCSPrep<F>,
        session: SessionId,
        network: Arc<N>,
        duration: Duration,
    ) -> Result<RobustShare<F>, KOrCLError> {
        let k = a_bits.len();
        if k == 0 {
            return Err(KOrCLError::LengthError);
        }

        // m = floor(log2(k)) + 1  →  2^m > k
        let m = (k as u32).ilog2() as usize + 1;

        let calling_proto = session
            .calling_protocol()
            .ok_or(KOrCLError::SessionIdError(session))?;
        let two = F::one() + F::one();

        // c_share = Σ [a_i] + 2^m·[r''] + [r']
        let mut sum = RobustShare::new(F::zero(), self.id, self.t);
        for bit in &a_bits {
            sum = (sum + bit.clone())?;
        }
        let two_pow_m = two.pow([m as u64]);
        let c_share = (((prandm.r_double_prime * two_pow_m)? + prandm.r_prime)? + sum)?;

        {
            let store = self.get_or_create_store(session).await?;
            let mut s = store.lock().await;
            s.m = m;
            s.r_prime_bits = Some(prandm.r_prime_bits);
        }

        // Broadcast via RBC with round_id=1 to avoid collision with KOrCS Mod2 (round_id=0).
        let rbc_session = SessionId::new(
            calling_proto,
            SessionId::pack_slot24(session.exec_id(), self.id as u8, 1),
            session.instance_id(),
        );
        let mut payload = Vec::new();
        c_share.share[0].serialize_compressed(&mut payload)?;
        self.rbc
            .init(payload, rbc_session, Arc::clone(&network))
            .await?;
        // Eagerly finalize if all RBC shares arrived before run() stored local state.
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

        // KOrCS on the m d_bits.
        self.kor_cs
            .run(d_bits, kor_cs_prep, session, network, duration)
            .await?;
        let e = self.kor_cs.wait_for_result(session, duration).await?;
        Ok(e)
    }
}
