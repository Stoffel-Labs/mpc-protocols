//! RandInvPair — preprocessing for random invertible pairs ([r], [r⁻¹]).
//!
//! For each pair j ∈ 0..k:
//!   1. Random shares [r_j] and [r'_j] are given as preprocessing input.
//!   2. Publicly reveal c_j = [r_j] · [r'_j] via MulPub.
//!   3. If c_j = 0, abort (prob ≈ 1/|F|).
//!   4. [r_j⁻¹] = c_j⁻¹ · [r'_j]  (local scalar mult).
//!   Return Vec<([r_j], [r_j⁻¹])>.
//!
//! Session routing:
//!   BatchRecon → self.mul_pub.batch_recon

use crate::honeybadger::{
    comparison::RandInvPairError, mul_pub::mul_pub::MulPubNode,
    robust_interpolate::robust_interpolate::RobustShare, SessionId,
};
use ark_ff::{FftField, PrimeField};
use std::{collections::HashMap, sync::Arc};
use stoffelnet::network_utils::Network;
use tokio::{
    sync::Mutex,
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
    /// degree-2t sharings of 0, one per multiplication
    pub zero_shares: Vec<RobustShare<F>>,
}

// ── Store ──────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct RandInvPairStore<F: PrimeField> {
    pub output_sender: Option<tokio::sync::oneshot::Sender<Vec<(RobustShare<F>, RobustShare<F>)>>>,
    pub output_receiver:
        Option<tokio::sync::oneshot::Receiver<Vec<(RobustShare<F>, RobustShare<F>)>>>,
}

impl<F: PrimeField> RandInvPairStore<F> {
    fn new() -> Self {
        let (tx, rx) = tokio::sync::oneshot::channel();
        Self {
            output_sender: Some(tx),
            output_receiver: Some(rx),
        }
    }
}

// ── Node ───────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct RandInvPairNode<F: PrimeField + FftField> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    pub mul_pub: MulPubNode<F>,
    store: Arc<Mutex<HashMap<SessionId, Arc<Mutex<RandInvPairStore<F>>>>>>,
}

impl<F: PrimeField + FftField> RandInvPairNode<F> {
    pub fn new(id: usize, n: usize, t: usize) -> Result<Self, RandInvPairError> {
        Ok(Self {
            id,
            n,
            t,
            mul_pub: MulPubNode::new(id, n, t)?,
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

    pub async fn clear_store(&self, session: SessionId) -> bool {
        self.mul_pub.clear_store(session).await;
        self.store.lock().await.remove(&session).is_some()
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
    /// Runs MulPub to publicly reveal [r_j]·[r'_j], then derives [r_j⁻¹] locally.
    pub async fn run<N: Network + Send + Sync + 'static>(
        &mut self,
        prep: RandInvPairPrep<F>,
        session: SessionId,
        network: Arc<N>,
        duration: Duration,
    ) -> Result<(), RandInvPairError> {
        let k = prep.r_shares.len();
        if k == 0 || prep.r_prime_shares.len() != k || prep.zero_shares.len() != k {
            return Err(RandInvPairError::LengthError);
        }

        self.get_or_create_store(session).await?;

        self.mul_pub
            .init(
                session,
                prep.r_shares.clone(),
                prep.r_prime_shares.clone(),
                prep.zero_shares,
                network,
            )
            .await?;
        // Blocks until all products are publicly reconstructed by the message loop.
        let c_vals = self
            .mul_pub
            .wait_for_result(session, duration)
            .await
            .map_err(RandInvPairError::MulPubError)?;

        let mut pairs = Vec::with_capacity(k);
        for j in 0..k {
            if c_vals[j].is_zero() {
                return Err(RandInvPairError::Abort);
            }
            let c_inv = c_vals[j].inverse().ok_or(RandInvPairError::Abort)?;
            let r_inv = (prep.r_prime_shares[j].clone() * c_inv)?;
            pairs.push((prep.r_shares[j].clone(), r_inv));
        }

        let store = self.get_or_create_store(session).await?;
        let sender = {
            let mut s = store.lock().await;
            s.output_sender
                .take()
                .ok_or(RandInvPairError::SendError(session))?
        };
        sender
            .send(pairs)
            .map_err(|_| RandInvPairError::SendError(session))?;
        Ok(())
    }
}
