//! RandInvPair — preprocessing for random invertible pairs ([r], [r⁻¹]).
//!
//! For each pair j ∈ 1..k:
//!   1. Random shares [r_j] and [r'_j] are given as preprocessing input.
//!   2. Compute [c_j] = [r_j] · [r'_j] via Beaver multiplication.
//!   3. Open c_j via batch reconstruction.
//!   4. If c_j = 0, abort (prob ≈ 1/|F|).
//!   5. [r_j⁻¹] = c_j⁻¹ · [r'_j]  (local scalar mult).
//!   Return Vec<([r_j], [r_j⁻¹])>.
//!
//! Session routing:
//!   BatchRecon round_id=0 → self.batch_recon  (product openings)
//!   BatchRecon round_id=1 → self.mul.batch_recon
//!   Rbc        round_id=2 → self.mul.rbc

use crate::{
    common::{ProtocolSessionId, RBC},
    honeybadger::{
        batch_recon::batch_recon::BatchReconNode,
        comparison::{pre_mulc::PhaseState, RandInvPairError},
        mul::multiplication::Multiply,
        robust_interpolate::robust_interpolate::RobustShare,
        triple_gen::ShamirBeaverTriple,
        SessionId,
    },
};
use ark_ff::PrimeField;
use ark_serialize::CanonicalDeserialize;
use std::{collections::HashMap, sync::Arc};
use stoffelnet::network_utils::Network;
use tokio::{
    sync::{mpsc::Receiver, Mutex},
    time::{timeout, Duration},
};

// ── Prep ───────────────────────────────────────────────────────────────────────

/// Preprocessing input for generating k random invertible pairs.
#[derive(Clone, Debug)]
pub struct RandInvPairPrep<F: PrimeField> {
    /// k independent random shares [r_j].
    pub r_shares: Vec<RobustShare<F>>,
    /// k independent random shares [r'_j], used to mask [r_j].
    pub r_prime_shares: Vec<RobustShare<F>>,
    /// k Beaver triples for computing [r_j] · [r'_j].
    pub triples: Vec<ShamirBeaverTriple<F>>,
}

// ── Store ──────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct RandInvPairStore<F: PrimeField> {
    state: PhaseState,
    r_shares: Vec<RobustShare<F>>,
    r_prime_shares: Vec<RobustShare<F>>,
    k: usize,
    n_chunks: usize,
    open: HashMap<u8, Vec<F>>,
    output_sender: Option<tokio::sync::oneshot::Sender<Vec<(RobustShare<F>, RobustShare<F>)>>>,
    pub output_receiver: Option<tokio::sync::oneshot::Receiver<Vec<(RobustShare<F>, RobustShare<F>)>>>,
}

impl<F: PrimeField> RandInvPairStore<F> {
    fn new() -> Self {
        let (tx, rx) = tokio::sync::oneshot::channel();
        Self {
            state: PhaseState::Waiting,
            r_shares: Vec::new(),
            r_prime_shares: Vec::new(),
            k: 0,
            n_chunks: 0,
            open: HashMap::new(),
            output_sender: Some(tx),
            output_receiver: Some(rx),
        }
    }
}

// ── Node ───────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct RandInvPairNode<F: PrimeField, R: RBC> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    pub mul: Multiply<F, R>,
    pub batch_recon: BatchReconNode<F>,
    batch_output: Arc<Mutex<Receiver<SessionId>>>,
    store: Arc<Mutex<HashMap<SessionId, Arc<Mutex<RandInvPairStore<F>>>>>>,
}

impl<F: PrimeField, R: RBC<Id = SessionId>> RandInvPairNode<F, R> {
    pub fn new(id: usize, n: usize, t: usize) -> Result<Self, RandInvPairError> {
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
    ) -> Result<Arc<Mutex<RandInvPairStore<F>>>, RandInvPairError> {
        let mut map = self.store.lock().await;
        if map.len() >= 256 && !map.contains_key(&session) {
            return Err(RandInvPairError::LimitError);
        }
        Ok(map
            .entry(session)
            .or_insert_with(|| Arc::new(Mutex::new(RandInvPairStore::new())))
            .clone())
    }

    /// Drive completed batch-recon chunks for the product opening step.
    /// Must be called by the external message loop after each BatchRecon round_id=0 message.
    pub async fn drain_batch_recon_output(&mut self) -> Result<(), RandInvPairError> {
        loop {
            let id = {
                let mut rx = self.batch_output.lock().await;
                match rx.try_recv() {
                    Ok(id) => id,
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        return Err(RandInvPairError::Abort);
                    }
                }
            };

            let output = self.batch_recon.get_store(id).await?;
            let vals: Vec<F> = CanonicalDeserialize::deserialize_compressed(output.as_slice())?;

            let calling_proto = id
                .calling_protocol()
                .ok_or(RandInvPairError::SessionIdError(id))?;
            let parent = SessionId::new(
                calling_proto,
                SessionId::pack_slot24(id.exec_id(), 0, 0),
                id.instance_id(),
            );
            let store = self.get_or_create_store(parent).await?;
            self.handle_chunk(parent, store, id.sub_id(), vals).await?;
        }
        Ok(())
    }

    async fn handle_chunk(
        &self,
        session: SessionId,
        store_mutex: Arc<Mutex<RandInvPairStore<F>>>,
        chunk_idx: u8,
        vals: Vec<F>,
    ) -> Result<(), RandInvPairError> {
        {
            let mut s = store_mutex.lock().await;
            if s.state == PhaseState::Finished {
                return Ok(());
            }
            s.open.insert(chunk_idx, vals);
        }
        self.try_finalize(session, store_mutex).await
    }
    async fn try_finalize(
        &self,
        session: SessionId,
        store_mutex: Arc<Mutex<RandInvPairStore<F>>>,
    ) -> Result<(), RandInvPairError> {
        let (r_shares, r_prime_shares, k, n_chunks, open_map) = {
            let s = store_mutex.lock().await;
            if s.state == PhaseState::Finished {
                return Ok(());
            }
            if s.r_shares.is_empty() || s.open.len() < s.n_chunks {
                return Ok(());
            }
            (
                s.r_shares.clone(),
                s.r_prime_shares.clone(),
                s.k,
                s.n_chunks,
                s.open.clone(),
            )
        };

        let mut c_vals: Vec<F> = Vec::new();
        for i in 0..n_chunks as u8 {
            let chunk = open_map.get(&i).ok_or(RandInvPairError::Abort)?;
            c_vals.extend_from_slice(chunk);
        }
        let c_vals = &c_vals[..k];

        let mut pairs: Vec<(RobustShare<F>, RobustShare<F>)> = Vec::with_capacity(k);
        for j in 0..k {
            if c_vals[j].is_zero() {
                return Err(RandInvPairError::Abort);
            }
            let c_inv = c_vals[j].inverse().ok_or(RandInvPairError::Abort)?;
            let r_inv = (r_prime_shares[j].clone() * c_inv)?;
            pairs.push((r_shares[j].clone(), r_inv));
        }

        let sender = {
            let mut s = store_mutex.lock().await;
            if s.state == PhaseState::Finished {
                return Ok(());
            }
            s.state = PhaseState::Finished;
            s.output_sender
                .take()
                .ok_or(RandInvPairError::SendError(session))?
        };
        sender
            .send(pairs)
            .map_err(|_| RandInvPairError::SendError(session))?;
        Ok(())
    }

    pub async fn wait_for_result(
        &self,
        session: SessionId,
        duration: Duration,
    ) -> Result<Vec<(RobustShare<F>, RobustShare<F>)>, RandInvPairError> {
        let rx = {
            let map = self.store.lock().await;
            let inner = map
                .get(&session)
                .ok_or(RandInvPairError::NoSuchSessionId(session))?
                .clone();
            let mut s = inner.lock().await;
            s.output_receiver
                .take()
                .ok_or(RandInvPairError::ResultAlreadyReceived(session))?
        };
        match timeout(duration, rx).await {
            Err(_) => Err(RandInvPairError::Timeout(session)),
            Ok(Err(_)) => Err(RandInvPairError::ReceiveError(session)),
            Ok(Ok(v)) => Ok(v),
        }
    }

    /// Generate k random invertible pairs ([r_j], [r_j⁻¹]).
    ///
    /// `prep.r_shares`, `prep.r_prime_shares`, and `prep.triples` must each have exactly k entries.
    pub async fn run<N: Network + Send + Sync>(
        &mut self,
        prep: RandInvPairPrep<F>,
        session: SessionId,
        network: Arc<N>,
        duration: Duration,
    ) -> Result<(), RandInvPairError> {
        let k = prep.r_shares.len();
        if k == 0 || prep.r_prime_shares.len() != k || prep.triples.len() != k {
            return Err(RandInvPairError::LengthError);
        }

        let calling_proto = session
            .calling_protocol()
            .ok_or(RandInvPairError::SessionIdError(session))?;

        // Batch-multiply [r_j] · [r'_j] for all j in a single Multiply::init call.
        let mul_session = SessionId::new(
            calling_proto,
            SessionId::pack_slot24(session.exec_id(), 0, 0),
            session.instance_id(),
        );
        self.mul
            .init(
                mul_session,
                prep.r_shares.clone(),
                prep.r_prime_shares.clone(),
                prep.triples,
                Arc::clone(&network),
            )
            .await?;
        let product_shares = self.mul.wait_for_result(mul_session, duration).await?;

        // Pad products to the next multiple of (t+1) for batch reconstruction.
        let chunk = self.t + 1;
        let pk = ((k + self.t) / chunk) * chunk;
        let one_share = RobustShare::new(F::one(), self.id, self.t);
        let mut padded = product_shares;
        while padded.len() < pk {
            padded.push(one_share.clone());
        }
        let n_chunks = pk / chunk;

        // Populate store before initiating batch recon so try_finalize can run.
        {
            let store = self.get_or_create_store(session).await?;
            let mut s = store.lock().await;
            s.r_shares = prep.r_shares;
            s.r_prime_shares = prep.r_prime_shares;
            s.k = k;
            s.n_chunks = n_chunks;
        }

        // Open all products via batch reconstruction (round_id=0).
        for (i, chunk_shares) in padded.chunks(self.t + 1).enumerate() {
            let batch_session = SessionId::new(
                calling_proto,
                SessionId::pack_slot24(session.exec_id(), i as u8, 0),
                session.instance_id(),
            );
            self.batch_recon
                .init_batch_reconstruct(chunk_shares, batch_session, Arc::clone(&network))
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
        Ok(())
    }
}
