//! Mod2m — Protocol 3.2 (Catrina & de Hoogh 2010).
//!
//! Computes [a mod 2^m] given [a] and PRandM(k, m) preprocessing.
//!
//! Protocol steps:
//!   1. c   ← Open(2^{k-1} + [a] + 2^m*[r''] + [r'])
//!   2. c'  ← c mod 2^m   (public — bit-mask on opened integer)
//!   3. [u] ← BitLTC1(c', ([r'_{m-1}], ..., [r'_0]))
//!   4. [a'] ← c' - [r'] + 2^m*[u]   (local)
//!

use crate::{
    common::{ProtocolSessionId, SecretSharingScheme, RBC},
    honeybadger::{
        comparison::{
            bit_ltc1::BitLTC1Node, pre_mulc::PhaseState, Mod2mError, PRandMPrep, PreMulCPrep,
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

#[derive(Debug)]
pub struct Mod2mStore<F: PrimeField> {
    pub state: PhaseState,
    pub received_shares: HashMap<usize, F>,
    pub c_sender: Option<tokio::sync::oneshot::Sender<F>>,
    pub c_receiver: Option<tokio::sync::oneshot::Receiver<F>>,
}

impl<F: PrimeField> Mod2mStore<F> {
    pub fn new() -> Self {
        let (tx, rx) = tokio::sync::oneshot::channel();
        Self {
            state: PhaseState::Waiting,
            received_shares: HashMap::new(),
            c_sender: Some(tx),
            c_receiver: Some(rx),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Mod2mNode<F: PrimeField, R: RBC> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    pub bit_ltc1: BitLTC1Node<F, R>,
    pub rbc: R,
    rbc_output: Arc<Mutex<Receiver<SessionId>>>,
    store: Arc<Mutex<HashMap<SessionId, Arc<Mutex<Mod2mStore<F>>>>>>,
}

impl<F: PrimeField, R: RBC<Id = SessionId>> Mod2mNode<F, R> {
    pub fn new(id: usize, n: usize, t: usize) -> Result<Self, Mod2mError> {
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
            bit_ltc1: BitLTC1Node::new(id, n, t)?,
            rbc,
            rbc_output: Arc::new(Mutex::new(rbc_receiver)),
            store: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    async fn get_or_create_store(
        &self,
        session: SessionId,
    ) -> Result<Arc<Mutex<Mod2mStore<F>>>, Mod2mError> {
        let mut map = self.store.lock().await;
        if map.len() >= 256 && !map.contains_key(&session) {
            return Err(Mod2mError::LimitError);
        }
        Ok(map
            .entry(session)
            .or_insert_with(|| Arc::new(Mutex::new(Mod2mStore::new())))
            .clone())
    }

    async fn wait_for_c(&self, session: SessionId, duration: Duration) -> Result<F, Mod2mError> {
        let rx = {
            let map = self.store.lock().await;
            let inner = map
                .get(&session)
                .ok_or(Mod2mError::NoSuchSessionId(session))?
                .clone();
            let mut s = inner.lock().await;
            s.c_receiver
                .take()
                .ok_or(Mod2mError::ResultAlreadyReceived(session))?
        };
        match timeout(duration, rx).await {
            Err(_) => Err(Mod2mError::Timeout(session)),
            Ok(Err(_)) => Err(Mod2mError::ReceiveError(session)),
            Ok(Ok(v)) => Ok(v),
        }
    }

    pub async fn drain_rbc_output(&mut self) -> Result<(), Mod2mError> {
        loop {
            let id = {
                let mut rx = self.rbc_output.lock().await;
                match rx.try_recv() {
                    Ok(id) => id,
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        return Err(Mod2mError::Abort)
                    }
                }
            };

            let payload = self.rbc.get_store(id).await?;
            let share_val: F = F::deserialize_compressed(payload.as_slice())?;
            let sender_id = id.sub_id() as usize;

            let calling_proto = id
                .calling_protocol()
                .ok_or(Mod2mError::SessionIdError(id))?;
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
                s.received_shares.entry(sender_id).or_insert(share_val);
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
        store_mutex: Arc<Mutex<Mod2mStore<F>>>,
    ) -> Result<(), Mod2mError> {
        let shares = {
            let s = store_mutex.lock().await;
            if s.state == PhaseState::Finished {
                return Ok(());
            }
            if s.received_shares.len() < 2 * self.t + 1 {
                return Ok(());
            }
            s.received_shares.clone()
        };

        let robust_shares: Vec<RobustShare<F>> = shares
            .iter()
            .map(|(&id, &val)| RobustShare::new(val, id, self.t))
            .collect();

        let (_, c) = RobustShare::recover_secret(&robust_shares, self.n, self.t)
            .map_err(|_| Mod2mError::Abort)?;

        let sender = {
            let mut s = store_mutex.lock().await;
            if s.state == PhaseState::Finished {
                return Ok(());
            }
            s.state = PhaseState::Finished;
            s.c_sender.take().ok_or(Mod2mError::SendError(parent))?
        };
        sender.send(c).map_err(|_| Mod2mError::SendError(parent))?;
        Ok(())
    }

    /// Protocol 3.2 Mod2m.
    ///
    /// `a`:            [a] — value to reduce mod 2^m.
    /// `k`:            total bit length (m < k <= 64).
    /// `m`:            number of low bits to extract.
    /// `r_double_prime`: [r''] — random k-bit blinding from PRandM(k, m).
    /// `r_prime`:        [r'] — random m-bit value from PRandM(k, m).
    /// `r_prime_bits`:   [r'_0], ..., [r'_{m-1}] — bit shares of r', LSB first.
    /// `w`, `z`:         PreMulC preprocessing (premulc_k(m, t) elements each).
    /// `triples`:        Beaver triples for PreMulC inside BitLTC1.
    /// `r_dp_mod2`:      [r''] for the inner Mod2 call.
    /// `r_zp_mod2`:      [r0'] for the inner Mod2 call.
    ///
    /// Drive all nested drains concurrently until this returns.
    pub async fn run<N: Network + Send + Sync>(
        &mut self,
        a: RobustShare<F>,
        k: usize,
        m: usize,
        prandm_prep: PRandMPrep<F>,
        premulc_prep: PreMulCPrep<F>,
        mod2_prep: PRandMPrep<F>,
        session: SessionId,
        network: Arc<N>,
        duration: Duration,
    ) -> Result<RobustShare<F>, Mod2mError> {
        assert!(m > 0 && m < k && k <= 64, "require 0 < m < k <= 64");
        if prandm_prep.r_prime_bits.len() != m {
            return Err(Mod2mError::LengthError);
        }

        let two_m = F::from(2u64).pow([m as u64]);
        let two_k_minus_1 = F::from(2u64).pow([(k as u64) - 1]);

        // Pre-create the store so wait_for_c can find the receiver even before drain runs.
        self.get_or_create_store(session).await?;

        // ── Step 1: c = 2^{k-1} + [a] + 2^m*[r''] + [r'] ───────────────────
        let c_share = (((a + (prandm_prep.r_double_prime * two_m)?)?
            + prandm_prep.r_prime.clone())?
            + two_k_minus_1)?;

        let calling_proto = session
            .calling_protocol()
            .ok_or(Mod2mError::SessionIdError(session))?;
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

        let c = self.wait_for_c(session, duration).await?;

        // ── Step 2: c' = c mod 2^m  (low m bits of c as integer) ─────────────
        let bytes = c.into_bigint().to_bytes_le();
        let mut buf = [0u8; 8];
        let copy_len = bytes.len().min(8);
        buf[..copy_len].copy_from_slice(&bytes[..copy_len]);
        let c_low64 = u64::from_le_bytes(buf);
        let mask: u64 = if m >= 64 { u64::MAX } else { (1u64 << m) - 1 };
        let c_prime_int = c_low64 & mask;
        let c_prime = F::from(c_prime_int);

        // ── Step 3: [u] = BitLTC1(c', r'_bits) ───────────────────────────────
        let u = self
            .bit_ltc1
            .run(
                c_prime,
                prandm_prep.r_prime_bits,
                premulc_prep,
                mod2_prep,
                session,
                Arc::clone(&network),
                duration,
            )
            .await?;

        // ── Step 4: [a'] = c' - [r'] + 2^m*[u]  (local) ─────────────────────
        let a_prime = (((u * two_m)? + c_prime)? - prandm_prep.r_prime)?;

        Ok(a_prime)
    }
}
