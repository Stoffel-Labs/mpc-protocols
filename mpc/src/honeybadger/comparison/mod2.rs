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

use crate::{
    common::{ProtocolSessionId, SecretSharingScheme, RBC},
    honeybadger::{
        comparison::{pre_mulc::PhaseState, Mod2Error, PRandMPrep},
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

#[derive(Clone, Debug)]
pub struct Mod2Node<F: PrimeField, R: RBC> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    store: Arc<Mutex<HashMap<SessionId, Arc<Mutex<Mod2Store<F>>>>>>,
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

    pub async fn clear_store(&self, session: SessionId) -> Result<(), Mod2Error> {
        self.rbc.clear_store().await;
        let mut map = self.store.lock().await;
        map.remove(&session)
            .map(|_| ())
            .ok_or(Mod2Error::ClearStoreError(session))
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
            SessionId::pack_slot24(session.exec_id(), self.id as u8, 0),
            session.instance_id(),
        );

        let mut payload = Vec::new();
        c_share.share[0].serialize_compressed(&mut payload)?;

        self.rbc.init(payload, rbc_session, network).await?;
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
            let share_val: F = F::deserialize_compressed(payload.as_slice())?;
            let sender = id.sub_id() as usize;

            let calling_proto = id.calling_protocol().ok_or(Mod2Error::SessionIdError(id))?;
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
                s.received_shares.len() >= self.n - self.t
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
            if s.received_shares.len() < self.n - self.t {
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
}
