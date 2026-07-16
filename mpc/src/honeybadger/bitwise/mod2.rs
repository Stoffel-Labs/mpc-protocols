//! Mod2 — Protocol 3.4 (Catrina & de Hoogh 2010).
//!
//! Computes [a mod 2] given [a] and PRandM(k, 1) preprocessing.
//!
//! Protocol steps:
//!   1. c  ← Open(2^{k-1} + [a] + 2*[r''] + [r0'])
//!   2. c0 ← c mod 2  (public parity)
//!   3. [a0] ← c0 + [r0'] - 2*c0*[r0']  = XOR(c0, [r0'])  (local)
//!
//! Each party broadcasts its share of c via one RBC instance.
//! RBC session IDs: calling_protocol = outer, sub_id = party_id, round_id = 0.
//! Reconstruction fires when n-t shares have been delivered.
//!
//! Session routing (add to HoneyBadgerMPCNode.process):
//!   Rbc (round_id=1): → mod2_node.rbc.process + mod2_node.drain_rbc_output
//!
//! # Batched variant
//!
//! `init_batch`/`wait_for_batch_result` reveal m independent values in a
//! single RBC broadcast per party (round_id = 1) instead of m separate
//! sessions sharing one exec_id — the latter doesn't work because
//! `drain_rbc_output` reconstructs the single-value store key as
//! `(exec_id, sub_id=0, round_id=0)` unconditionally, so m single-value calls
//! under one exec_id would all collide on that same key. Batching sidesteps
//! this: there is exactly one store per batched session, keyed the same way
//! `init_batch`'s caller-supplied session already is.

use crate::{
    common::{ProtocolSessionId, SecretSharingScheme, RBC},
    honeybadger::{
        bitwise::{pre_mulc::PhaseState, Mod2Error, PRandMPrep},
        robust_interpolate::robust_interpolate::RobustShare,
        SessionId, WrappedMessage,
    },
};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::{collections::HashMap, sync::Arc};
use stoffelnet::network_utils::Network;
use tokio::{
    sync::{mpsc::Receiver, Mutex},
    time::{timeout, Duration},
};

#[derive(Debug)]
pub struct Mod2Store<F: PrimeField> {
    pub state: PhaseState,
    pub r_prime: Option<RobustShare<F>>,
    pub received_shares: HashMap<usize, F>, // party_id → share value
    pub output_sender: Option<tokio::sync::oneshot::Sender<RobustShare<F>>>,
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

#[derive(Debug)]
pub struct Mod2BatchStore<F: PrimeField> {
    pub state: PhaseState,
    pub r_primes: Option<Vec<RobustShare<F>>>,
    pub received_shares: HashMap<usize, Vec<F>>, // party_id → its m c-shares
    pub output_sender: Option<tokio::sync::oneshot::Sender<Vec<RobustShare<F>>>>,
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

#[derive(Clone, Debug)]
pub struct Mod2Node<F: PrimeField, R: RBC> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    store: Arc<Mutex<HashMap<SessionId, Arc<Mutex<Mod2Store<F>>>>>>,
    batch_store: Arc<Mutex<HashMap<SessionId, Arc<Mutex<Mod2BatchStore<F>>>>>>,
    pub rbc: R,
    rbc_output: Arc<Mutex<Receiver<SessionId>>>,
}

impl<F: PrimeField, R: RBC<Id = SessionId>> Mod2Node<F, R> {
    pub fn new(id: usize, n: usize, t: usize) -> Result<Self, Mod2Error> {
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
            batch_store: Arc::new(Mutex::new(HashMap::new())),
            rbc,
            rbc_output: Arc::new(Mutex::new(rbc_receiver)),
        })
    }

    async fn get_or_create_store(
        &self,
        session: SessionId,
    ) -> Result<Arc<Mutex<Mod2Store<F>>>, Mod2Error> {
        let mut map = self.store.lock().await;
        if map.len() >= 256 && !map.contains_key(&session) {
            return Err(Mod2Error::LimitError);
        }
        Ok(map
            .entry(session)
            .or_insert_with(|| Arc::new(Mutex::new(Mod2Store::new())))
            .clone())
    }

    async fn get_or_create_batch_store(
        &self,
        session: SessionId,
    ) -> Result<Arc<Mutex<Mod2BatchStore<F>>>, Mod2Error> {
        let mut map = self.batch_store.lock().await;
        if map.len() >= 256 && !map.contains_key(&session) {
            return Err(Mod2Error::LimitError);
        }
        Ok(map
            .entry(session)
            .or_insert_with(|| Arc::new(Mutex::new(Mod2BatchStore::new())))
            .clone())
    }

    /// Clears state for `session` in whichever store (single or batch) it
    /// belongs to.
    pub async fn clear_store(&self, session: SessionId) -> Result<(), Mod2Error> {
        self.rbc.clear_store().await;
        let removed_single = self.store.lock().await.remove(&session).is_some();
        let removed_batch = self.batch_store.lock().await.remove(&session).is_some();
        if removed_single || removed_batch {
            Ok(())
        } else {
            Err(Mod2Error::ClearStoreError(session))
        }
    }

    pub async fn wait_for_result(
        &self,
        session: SessionId,
        duration: Duration,
    ) -> Result<RobustShare<F>, Mod2Error> {
        let rx = {
            let map = self.store.lock().await;
            let inner = map
                .get(&session)
                .ok_or(Mod2Error::NoSuchSessionId(session))?
                .clone();
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
    /// Drive `drain_rbc_output` until `wait_for_result` resolves.
    pub async fn init<N: Network + Send + Sync>(
        &mut self,
        a: RobustShare<F>,
        k: usize,
        prep: PRandMPrep<F>,
        session: SessionId,
        network: Arc<N>,
    ) -> Result<(), Mod2Error> {
        let two = F::one() + F::one();
        let two_pow_k_minus_1 = two.pow([(k as u64) - 1]);

        // c = 2^{k-1} + [a] + 2*[r''] + [r0']
        let c_share =
            (((a + (prep.r_double_prime * two)?)? + prep.r_prime.clone())? + two_pow_k_minus_1)?;

        let calling_proto = session
            .calling_protocol()
            .ok_or(Mod2Error::SessionIdError(session))?;

        // Pre-create the store and save r_zero_prime before any async work.
        {
            let store = self.get_or_create_store(session).await?;
            let mut s = store.lock().await;
            s.r_prime = Some(prep.r_prime);
        }

        // Broadcast this party's share of c.
        // sub_id = self.id identifies the broadcaster; round_id = 1 avoids colliding with
        // the outer session (sub_id=0, round_id=0).
        let rbc_session = SessionId::new(
            calling_proto,
            SessionId::pack_slot(session.exec_id(), self.id as u8, 0),
            session.instance_id(),
        );

        let mut payload = Vec::new();
        c_share.share[0].serialize_compressed(&mut payload)?;

        self.rbc.init(payload, rbc_session, network).await?;
        // If n-t shares already arrived before r_prime was stored, finalize now.
        {
            let store = self.get_or_create_store(session).await?;
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
    /// 2*[r''_i] + [r0'_i]`) in a single RBC broadcast per party, avoiding the
    /// session collisions that m separate `init` calls sharing one exec_id
    /// would hit (see module docs). `a_vec` and `preps` must have equal,
    /// non-zero length. Drive `drain_rbc_output` until `wait_for_batch_result`
    /// resolves.
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
        {
            let store = self.get_or_create_batch_store(session).await?;
            let mut s = store.lock().await;
            s.r_primes = Some(r_primes);
        }

        // Broadcast this party's m c-shares in one message.
        // round_id = 1 distinguishes batch sessions from single-value ones (round_id = 0).
        let rbc_session = SessionId::new(
            calling_proto,
            SessionId::pack_slot(session.exec_id(), self.id as u8, 1),
            session.instance_id(),
        );

        let mut payload = Vec::new();
        c_shares.serialize_compressed(&mut payload)?;

        self.rbc.init(payload, rbc_session, network).await?;
        // If n-t shares already arrived before r_primes was stored, finalize now.
        {
            let store = self.get_or_create_batch_store(session).await?;
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

    /// Drains completed RBC outputs, accumulates shares, and finalises once
    /// n-t shares have arrived (enough for robust reconstruction despite t faults).
    pub async fn drain_rbc_output(&mut self) -> Result<(), Mod2Error> {
        loop {
            let id = {
                let mut rx = self.rbc_output.lock().await;
                match rx.try_recv() {
                    Ok(id) => id,
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        return Err(Mod2Error::Abort)
                    }
                }
            };

            let payload = self.rbc.get_store(id).await?;
            let sender = id.sub_id() as usize;
            let calling_proto = id.calling_protocol().ok_or(Mod2Error::SessionIdError(id))?;
            let parent = SessionId::new(
                calling_proto,
                SessionId::pack_slot(id.exec_id(), 0, 0),
                id.instance_id(),
            );

            if id.round_id() == 1 {
                let share_vals: Vec<F> = CanonicalDeserialize::deserialize_compressed(
                    payload.as_slice(),
                )?;
                let store = self.get_or_create_batch_store(parent).await?;
                let ready = {
                    let mut s = store.lock().await;
                    if s.state == PhaseState::Finished {
                        continue;
                    }
                    s.received_shares.entry(sender).or_insert(share_vals);
                    s.received_shares.len() >= 2 * self.t + 1
                };
                if ready {
                    self.try_finalize_batch(parent, store).await?;
                }
                continue;
            }

            let share_val: F = F::deserialize_compressed(payload.as_slice())?;

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

        let (_, c) = RobustShare::recover_secret(&robust_shares, self.n, self.t)
            .map_err(|_| Mod2Error::Abort)?;

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

        let two = F::one() + F::one();
        let m = r_primes.len();
        let mut results: Vec<RobustShare<F>> = Vec::with_capacity(m);
        for (j, r_zero_prime) in r_primes.into_iter().enumerate() {
            let robust_shares: Vec<RobustShare<F>> = shares
                .iter()
                .map(|(&id, vals)| RobustShare::new(vals[j], id, self.t))
                .collect();
            let (_, c) = RobustShare::recover_secret(&robust_shares, self.n, self.t)
                .map_err(|_| Mod2Error::Abort)?;
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

    pub async fn wait_for_batch_result(
        &self,
        session: SessionId,
        duration: Duration,
    ) -> Result<Vec<RobustShare<F>>, Mod2Error> {
        let rx = {
            let map = self.batch_store.lock().await;
            let inner = map
                .get(&session)
                .ok_or(Mod2Error::NoSuchSessionId(session))?
                .clone();
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