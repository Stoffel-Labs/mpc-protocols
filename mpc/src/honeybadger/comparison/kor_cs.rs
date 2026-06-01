//! KOrCS — k-ary OR, constant rounds (Catrina & de Hoogh 2010, Toft PhD §8.2.2).
//!
//! Computes [OR(b_1, ..., b_k)] given secret bit shares [b_i] ∈ {0,1}.
//!
//! Protocol:
//!   1. [a] = 1 + Σ [b_i]  (local; a ∈ {1,...,k+1}, non-zero)
//!   2. ([a^1],...,[a^k]) ← UnboundedFanInPowers([a], k)
//!   3. [p] = α_0 + Σ_{i=1}^k α_i·[a^i]  (local)
//!
//! UnboundedFanInPowers (Bar-Ilan & Beaver 1989):
//!   Round 1 (k−1 muls): [tmp_j] = [r_{j−1}^{-1}]·[a]  for j=2..k  (j=1 free: tmp_1=[a])
//!   Round 2 (k muls):   [d_j]   = [tmp_j]·[r_j]       for j=1..k
//!   Open (batch recon): c_j = open([d_j])              for j=1..k
//!   Local:              D_j = Π_{i=1}^j c_i;  [a^j] = D_j·[r_j^{-1}]
//!

use crate::{
    common::{ProtocolSessionId, RBC},
    honeybadger::{
        batch_recon::batch_recon::BatchReconNode,
        comparison::{pre_mulc::PhaseState, KOrCSError},
        mul::multiplication::Multiply,
        robust_interpolate::robust_interpolate::RobustShare,
        triple_gen::ShamirBeaverTriple,
        ProtocolType, SessionId,
    },
};
use ark_ff::{FftField, PrimeField};
use ark_serialize::CanonicalDeserialize;
use std::{collections::HashMap, sync::Arc};
use stoffelnet::network_utils::Network;
use tokio::{
    sync::{mpsc::Receiver, Mutex},
    time::{timeout, Duration},
};

/// Preprocessing for the KOrCS protocol with k input bits.
#[derive(Clone, Debug)]
pub struct KOrCSPrep<F: FftField> {
    /// k random invertible pairs ([r_j], [r_j^{-1}]) for j = 1..k.
    pub rand_inv_pairs: Vec<(RobustShare<F>, RobustShare<F>)>,
    /// k-1 Beaver triples for round-1 muls: [r_{j-1}^{-1}]·[a] for j=2..k.
    pub triples_round1: Vec<ShamirBeaverTriple<F>>,
    /// k Beaver triples for round-2 muls: [tmp_j]·[r_j] for j=1..k.
    pub triples_round2: Vec<ShamirBeaverTriple<F>>,
}

#[derive(Debug)]
struct KOrCSStore<F: PrimeField> {
    state: PhaseState,
    k: usize,
    n_chunks: usize,
    r_shares: Vec<RobustShare<F>>,
    alpha: Vec<F>,
    open: HashMap<u8, Vec<F>>,
    output_sender: Option<tokio::sync::oneshot::Sender<RobustShare<F>>>,
    output_receiver: Option<tokio::sync::oneshot::Receiver<RobustShare<F>>>,
}

impl<F: PrimeField> KOrCSStore<F> {
    fn new() -> Self {
        let (tx, rx) = tokio::sync::oneshot::channel();
        Self {
            state: PhaseState::Waiting,
            k: 0,
            n_chunks: 0,
            r_shares: Vec::new(),
            alpha: Vec::new(),
            open: HashMap::new(),
            output_sender: Some(tx),
            output_receiver: Some(rx),
        }
    }
}

#[derive(Clone, Debug)]
pub struct KOrCSNode<F: PrimeField, R: RBC> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    /// Single Multiply node for both sequential mul rounds (distinguished by session ID).
    pub mul: Multiply<F, R>,
    /// BatchRecon node for opening d_j values.
    pub batch_recon: BatchReconNode<F>,
    batch_output: Arc<Mutex<Receiver<SessionId>>>,
    store: Arc<Mutex<HashMap<SessionId, Arc<Mutex<KOrCSStore<F>>>>>>,
}

impl<F: PrimeField, R: RBC<Id = SessionId>> KOrCSNode<F, R> {
    pub fn new(id: usize, n: usize, t: usize) -> Result<Self, KOrCSError> {
        let (batch_sender, batch_receiver) = tokio::sync::mpsc::channel(200);
        let batch_recon = BatchReconNode::new(id, n, t, t, batch_sender)?;
        let mul = Multiply::new(id, n, t)?;
        Ok(Self {
            id,
            n,
            t,
            mul,
            batch_recon,
            batch_output: Arc::new(Mutex::new(batch_receiver)),
            store: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    async fn get_or_create_store(
        &self,
        session: SessionId,
    ) -> Result<Arc<Mutex<KOrCSStore<F>>>, KOrCSError> {
        let mut map = self.store.lock().await;
        if map.len() >= 256 && !map.contains_key(&session) {
            return Err(KOrCSError::LimitError);
        }
        Ok(map
            .entry(session)
            .or_insert_with(|| Arc::new(Mutex::new(KOrCSStore::new())))
            .clone())
    }

    /// Drive completed batch-recon chunks for the d_j opening step.
    /// Must be called by the external message loop after each BatchRecon round_id=0 message.
    pub async fn drain_batch_recon_output(&mut self) -> Result<(), KOrCSError> {
        loop {
            let id = {
                let mut rx = self.batch_output.lock().await;
                match rx.try_recv() {
                    Ok(id) => id,
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        return Err(KOrCSError::Abort)
                    }
                }
            };

            let output = self.batch_recon.get_store(id).await?;
            let vals: Vec<F> = CanonicalDeserialize::deserialize_compressed(output.as_slice())?;

            let calling_proto = id
                .calling_protocol()
                .ok_or(KOrCSError::SessionIdError(id))?;
            let parent = SessionId::new(
                calling_proto,
                SessionId::pack_slot24(id.exec_id(), 0, 0),
                id.instance_id(),
            );
            let chunk_idx = id.sub_id();
            self.handle_chunk(parent, chunk_idx, vals).await?;
        }
        Ok(())
    }

    async fn handle_chunk(
        &mut self,
        parent: SessionId,
        chunk_idx: u8,
        vals: Vec<F>,
    ) -> Result<(), KOrCSError> {
        let store = self.get_or_create_store(parent).await?;
        {
            let mut s = store.lock().await;
            if s.state == PhaseState::Finished {
                return Ok(());
            }
            s.open.insert(chunk_idx, vals);
        }
        self.try_finalize(parent, store).await
    }

    async fn try_finalize(
        &self,
        session: SessionId,
        store_mutex: Arc<Mutex<KOrCSStore<F>>>,
    ) -> Result<(), KOrCSError> {
        let (r_shares, alpha, open_map, n_chunks, k) = {
            let s = store_mutex.lock().await;
            if s.state == PhaseState::Finished {
                return Ok(());
            }
            if s.r_shares.is_empty() {
                return Ok(());
            }
            if s.open.len() < s.n_chunks {
                return Ok(());
            }
            (
                s.r_shares.clone(),
                s.alpha.clone(),
                s.open.clone(),
                s.n_chunks,
                s.k,
            )
        };

        // Assemble opened c_j values in chunk order.
        let mut c_vals: Vec<F> = Vec::new();
        for i in 0..n_chunks as u8 {
            let chunk = open_map.get(&i).ok_or(KOrCSError::Abort)?;
            c_vals.extend_from_slice(chunk);
        }
        // Trim to k (padded chunks may have extra values).
        let c_vals = &c_vals[..k];

        // Prefix products D_j = c_1 · c_2 · … · c_j.
        let mut prefix = Vec::with_capacity(k);
        let mut acc = F::one();
        for &c in c_vals {
            acc *= c;
            prefix.push(acc);
        }

        // [a^j] = D_j · [r_j^{-1}]  (local scalar multiplication).
        let mut powers: Vec<RobustShare<F>> = Vec::with_capacity(k);
        for (d_j, r_j) in prefix.into_iter().zip(r_shares.iter()) {
            powers.push((r_j.clone() * d_j)?);
        }

        // [p] = α_0 + Σ_{i=1}^k α_i · [a^i].
        let mut result = RobustShare::new(alpha[0], self.id, self.t);
        for (i, power) in powers.into_iter().enumerate() {
            result = (result + (power * alpha[i + 1])?)?;
        }

        let sender = {
            let mut s = store_mutex.lock().await;
            if s.state == PhaseState::Finished {
                return Ok(());
            }
            s.state = PhaseState::Finished;
            s.output_sender
                .take()
                .ok_or(KOrCSError::SendError(session))?
        };
        sender
            .send(result)
            .map_err(|_| KOrCSError::SendError(session))?;
        Ok(())
    }

    pub async fn wait_for_result(
        &self,
        session: SessionId,
        duration: Duration,
    ) -> Result<RobustShare<F>, KOrCSError> {
        let rx = {
            let map = self.store.lock().await;
            let inner = map
                .get(&session)
                .ok_or(KOrCSError::NoSuchSessionId(session))?
                .clone();
            let mut s = inner.lock().await;
            s.output_receiver
                .take()
                .ok_or(KOrCSError::ResultAlreadyReceived(session))?
        };
        match timeout(duration, rx).await {
            Err(_) => Err(KOrCSError::Timeout(session)),
            Ok(Err(_)) => Err(KOrCSError::ReceiveError(session)),
            Ok(Ok(v)) => Ok(v),
        }
    }

    /// Lagrange coefficients [α_0, ..., α_k] for the degree-k polynomial φ satisfying
    /// φ(1) = 0, φ(j) = 1 for j = 2..k+1.
    fn lagrange_coeffs(k: usize) -> Vec<F> {
        // Interpolation points: x_j = j+1 for j = 0..k.  Values: y_0=0, y_j=1 for j>0.
        // φ = Σ_{j=1}^k L_j  (the j=0 term has value 0 and is dropped).
        let points: Vec<F> = (1u64..=k as u64 + 1).map(F::from).collect();
        let mut coeffs = vec![F::zero(); k + 1];

        for j in 1..=k {
            let xj = points[j];
            let mut l_poly = vec![F::one()];
            let mut denom = F::one();
            for m in 0..=k {
                if m == j {
                    continue;
                }
                let xm = points[m];
                // l_poly *= (x - xm)
                let mut new_poly = vec![F::zero(); l_poly.len() + 1];
                for (i, &c) in l_poly.iter().enumerate() {
                    new_poly[i + 1] = new_poly[i + 1] + c;
                    new_poly[i] = new_poly[i] - c * xm;
                }
                l_poly = new_poly;
                denom = denom * (xj - xm);
            }
            let denom_inv = denom.inverse().expect("interpolation points are distinct");
            for (i, &c) in l_poly.iter().enumerate() {
                coeffs[i] = coeffs[i] + c * denom_inv;
            }
        }
        coeffs
    }

    /// KOrCS: k-ary OR in constant rounds.
    ///
    /// `b_bits`: secret shares of k input bits in {0,1}.
    /// `prep`:   KOrCSPrep with k random invertible pairs and 2k-1 Beaver triples.
    pub async fn run<N: Network + Send + Sync>(
        &mut self,
        b_bits: Vec<RobustShare<F>>,
        prep: KOrCSPrep<F>,
        session: SessionId,
        network: Arc<N>,
        duration: Duration,
    ) -> Result<(), KOrCSError> {
        let k = b_bits.len();
        if k == 0 {
            return Err(KOrCSError::LengthError);
        }
        if prep.rand_inv_pairs.len() != k
            || prep.triples_round1.len() != k.saturating_sub(1)
            || prep.triples_round2.len() != k
        {
            return Err(KOrCSError::LengthError);
        }

        // Step 1: [a] = 1 + Σ [b_i]  (local; a ∈ {1,...,k+1}).
        let mut a = RobustShare::new(F::one(), self.id, self.t);
        for bit in &b_bits {
            a = (a + bit.clone())?;
        }

        let sid1 = SessionId::new(
            ProtocolType::KOr1,
            SessionId::pack_slot24(session.exec_id(), 0, 0),
            session.instance_id(),
        );
        let sid2 = SessionId::new(
            ProtocolType::KOr2,
            SessionId::pack_slot24(session.exec_id(), 0, 0),
            session.instance_id(),
        );

        // Step 2a — Round 1 (k-1 muls): [tmp_j] = [r_{j-1}^{-1}] · [a] for j=2..k.
        // j=1 is free: tmp_1 = [a] (since r_0 = 1).
        let tmp: Vec<RobustShare<F>> = if k == 1 {
            vec![a.clone()]
        } else {
            let x: Vec<RobustShare<F>> = prep.rand_inv_pairs[..k - 1]
                .iter()
                .map(|(_, r_inv)| r_inv.clone())
                .collect();
            let y: Vec<RobustShare<F>> = (0..k - 1).map(|_| a.clone()).collect();
            self.mul
                .init(sid1, x, y, prep.triples_round1, Arc::clone(&network))
                .await?;
            let round1 = self.mul.wait_for_result(sid1, duration).await?;
            let mut tmp = vec![a.clone()];
            tmp.extend(round1);
            tmp
        };

        // Step 2b — Round 2 (k muls): [d_j] = [tmp_j] · [r_j] for j=1..k.
        let r_shares: Vec<RobustShare<F>> =
            prep.rand_inv_pairs.iter().map(|(r, _)| r.clone()).collect();
        // r_inv_shares are needed for the final [a^j] = D_j · [r_j^{-1}] step.
        let r_inv_shares: Vec<RobustShare<F>> = prep
            .rand_inv_pairs
            .iter()
            .map(|(_, r_inv)| r_inv.clone())
            .collect();
        self.mul
            .init(
                sid2,
                tmp,
                r_shares, // Round 2 still multiplies by r_j
                prep.triples_round2,
                Arc::clone(&network),
            )
            .await?;

        let d_shares = self.mul.wait_for_result(sid2, duration).await?;

        // Pad d_shares to the next multiple of (t+1) for batch reconstruction.
        let pk = ((k + self.t) / (self.t + 1)) * (self.t + 1);
        let one_share = RobustShare::new(F::one(), self.id, self.t);
        let mut padded_d = d_shares;
        while padded_d.len() < pk {
            padded_d.push(one_share.clone());
        }
        let n_chunks = pk / (self.t + 1);

        // Setup per-session store before initiating batch recon.
        let alpha = Self::lagrange_coeffs(k);
        {
            let store = self.get_or_create_store(session).await?;
            let mut s = store.lock().await;
            s.k = k;
            s.n_chunks = n_chunks;
            s.r_shares = r_inv_shares; // D_j · [r_j^{-1}] in try_finalize
            s.alpha = alpha;
        }

        // Step 2c — Open [d_j] via batch reconstruction (round_id=0).
        let calling_proto = session
            .calling_protocol()
            .ok_or(KOrCSError::SessionIdError(session))?;

        for (i, chunk) in padded_d.chunks(self.t + 1).enumerate() {
            let batch_session = SessionId::new(
                calling_proto,
                SessionId::pack_slot24(session.exec_id(), i as u8, 0),
                session.instance_id(),
            );
            self.batch_recon
                .init_batch_reconstruct(chunk, batch_session, Arc::clone(&network))
                .await?;
        }
        {
            let store = self.get_or_create_store(session).await?;
            let ready = {
                let s = store.lock().await;
                !s.r_shares.is_empty() && s.open.len() >= s.n_chunks
            };
            if ready {
                self.try_finalize(session, store).await?;
            }
        }

        // Step 3 — Polynomial evaluation and unmasking happen in try_finalize,
        // triggered by drain_batch_recon_output once all chunks arrive.
        Ok(())
    }
}
