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
//! Session routing (add to HoneyBadgerMPCNode.process):
//!   Mod2m BatchRecon   → mod2m_node.batch_recon + drain_batch_recon_output
//!   PreMulCOn BatchRecon → mod2m_node.bit_ltc1.pre_mul_c.batch_recon + drain
//!   PreMulCOn Mul BatchRecon/RBC → mod2m_node.bit_ltc1.pre_mul_c.mul.*
//!   Mod2 BatchRecon    → mod2m_node.bit_ltc1.mod2.batch_recon + drain

use crate::{
    common::{ProtocolSessionId, RBC},
    honeybadger::{
        batch_recon::batch_recon::BatchReconNode,
        comparison::{bit_ltc1::BitLTC1Node, pre_mulc::PhaseState, Mod2mError},
        robust_interpolate::robust_interpolate::RobustShare,
        triple_gen::ShamirBeaverTriple,
        SessionId,
    },
};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::CanonicalDeserialize;
use std::{collections::HashMap, sync::Arc};
use stoffelnet::network_utils::Network;
use tokio::{
    sync::{mpsc::Receiver, Mutex},
    time::{timeout, Duration},
};

#[derive(Debug)]
pub struct Mod2mStore<F: PrimeField> {
    pub state: PhaseState,
    pub c_sender: Option<tokio::sync::oneshot::Sender<F>>,
    pub c_receiver: Option<tokio::sync::oneshot::Receiver<F>>,
}

impl<F: PrimeField> Mod2mStore<F> {
    pub fn new() -> Self {
        let (tx, rx) = tokio::sync::oneshot::channel();
        Self {
            state: PhaseState::Waiting,
            c_sender: Some(tx),
            c_receiver: Some(rx),
        }
    }
}

pub struct Mod2mNode<F: PrimeField, R: RBC<Id = SessionId>> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    pub bit_ltc1: BitLTC1Node<F, R>,
    pub batch_recon: BatchReconNode<F>,
    batch_output: Arc<Mutex<Receiver<SessionId>>>,
    store: Arc<Mutex<HashMap<SessionId, Arc<Mutex<Mod2mStore<F>>>>>>,
}

impl<F: PrimeField, R: RBC<Id = SessionId>> Mod2mNode<F, R> {
    pub fn new(id: usize, n: usize, t: usize) -> Result<Self, Mod2mError> {
        let (batch_sender, batch_receiver) = tokio::sync::mpsc::channel(200);
        let batch_recon = BatchReconNode::new(id, n, t, t, batch_sender)?;
        Ok(Self {
            id,
            n,
            t,
            bit_ltc1: BitLTC1Node::new(id, n, t)?,
            batch_recon,
            batch_output: Arc::new(Mutex::new(batch_receiver)),
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

    /// Signals the waiting `wait_for_c` when Phase 1 batch recon completes.
    pub async fn drain_batch_recon_output(&mut self) -> Result<(), Mod2mError> {
        loop {
            let id = {
                let mut rx = self.batch_output.lock().await;
                match rx.try_recv() {
                    Ok(id) => id,
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        return Err(Mod2mError::Abort)
                    }
                }
            };

            let output = self.batch_recon.get_store(id).await?;
            let vals: Vec<F> = CanonicalDeserialize::deserialize_compressed(output.as_slice())?;
            if vals.is_empty() {
                return Err(Mod2mError::Abort);
            }
            let c = vals[0];

            let parent = SessionId::new(
                id.calling_protocol()
                    .ok_or(Mod2mError::SessionIdError(id))?,
                SessionId::pack_slot24(id.exec_id(), 0, 0),
                id.instance_id(),
            );

            let store = self.get_or_create_store(parent).await?;
            let sender = {
                let mut s = store.lock().await;
                if s.state == PhaseState::Finished {
                    continue;
                }
                s.state = PhaseState::Finished;
                s.c_sender.take().ok_or(Mod2mError::SendError(parent))?
            };
            sender.send(c).map_err(|_| Mod2mError::SendError(parent))?;
        }
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
    /// `session` must have calling_protocol = ProtocolType::Mod2m.
    /// Drive all nested drains concurrently until this returns.
    pub async fn run<N: Network + Send + Sync>(
        &mut self,
        a: RobustShare<F>,
        k: usize,
        m: usize,
        r_double_prime: RobustShare<F>,
        r_prime: RobustShare<F>,
        r_prime_bits: Vec<RobustShare<F>>,
        w: Vec<RobustShare<F>>,
        z: Vec<RobustShare<F>>,
        triples: Vec<ShamirBeaverTriple<F>>,
        r_dp_mod2: RobustShare<F>,
        r_zp_mod2: RobustShare<F>,
        session: SessionId,
        network: Arc<N>,
        duration: Duration,
    ) -> Result<RobustShare<F>, Mod2mError> {
        assert!(m > 0 && m < k && k <= 64, "require 0 < m < k <= 64");
        if r_prime_bits.len() != m {
            return Err(Mod2mError::LengthError);
        }

        let two_m = F::from(2u64).pow([m as u64]);
        let two_k_minus_1 = F::from(2u64).pow([(k as u64) - 1]);

        // Pre-create the store so wait_for_c can find the receiver even before drain runs.
        self.get_or_create_store(session).await?;

        // ── Step 1: c = 2^{k-1} + [a] + 2^m*[r''] + [r'] ───────────────────
        let c_share = (((a + (r_double_prime * two_m)?)? + r_prime.clone())? + two_k_minus_1)?;

        self.batch_recon
            .init_batch_reconstruct(&[c_share], session, Arc::clone(&network))
            .await?;

        // Wait for c to be opened (driven by drain_batch_recon_output concurrently).
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

        // Decompose c' into m bits, LSB = index 0.
        let c_prime_bits: Vec<F> = (0..m).map(|i| F::from((c_prime_int >> i) & 1)).collect();

        // ── Step 3: [u] = BitLTC1(c', r'_bits) ───────────────────────────────
        let u = self
            .bit_ltc1
            .run(
                c_prime_bits,
                r_prime_bits,
                w,
                z,
                triples,
                r_dp_mod2,
                r_zp_mod2,
                session,
                Arc::clone(&network),
                duration,
            )
            .await?;

        // ── Step 4: [a'] = c' - [r'] + 2^m*[u]  (local) ─────────────────────
        let a_prime = (((u * two_m)? + c_prime)? - r_prime)?;

        Ok(a_prime)
    }
}
