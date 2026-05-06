//! PreMulC — Protocol 4.2 (Catrina & de Hoogh 2010).
//!
//! Session ID scheme (all sub-sessions derive from caller's session):
//!   PreMulCOff session:    pack_slot24(exec_id, 0, 0)  — preprocessing
//!   PreMulCOn session:     pack_slot24(exec_id, 0, 0)  — online
//!   Batch chunks:          pack_slot24(exec_id, chunk_i, 0)  in respective session
//!   Routing:               drain_batch_recon_output routes by calling_protocol()
//!
//! k must be a multiple of (t+1).
//! Caller asserts: session.sub_id() == 0 && session.round_id() == 0.

use crate::{
    common::{ProtocolSessionId, RBC},
    honeybadger::{
        batch_recon::batch_recon::BatchReconNode,
        comparison::{PreMulCError, PreMulCPrep},
        mul::multiplication::Multiply,
        robust_interpolate::robust_interpolate::RobustShare,
        triple_gen::ShamirBeaverTriple,
        ProtocolType, SessionId,
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
use tracing::warn;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhaseState {
    Waiting,
    Finished,
}

#[derive(Debug)]
pub struct PreMulCPrepStore<F: PrimeField> {
    pub state: PhaseState,
    pub r: Option<Vec<RobustShare<F>>>,
    pub s: Option<Vec<RobustShare<F>>>,
    pub chunks: usize,
    pub open: HashMap<u8, Vec<F>>,
    pub output_sender:
        Option<tokio::sync::oneshot::Sender<(Vec<RobustShare<F>>, Vec<RobustShare<F>>)>>,
    pub output_receiver:
        Option<tokio::sync::oneshot::Receiver<(Vec<RobustShare<F>>, Vec<RobustShare<F>>)>>,
}

impl<F: PrimeField> PreMulCPrepStore<F> {
    pub fn new() -> Self {
        let (tx, rx) = tokio::sync::oneshot::channel();
        Self {
            state: PhaseState::Waiting,
            r: None,
            s: None,
            chunks: 0,
            open: HashMap::new(),
            output_sender: Some(tx),
            output_receiver: Some(rx),
        }
    }
}

#[derive(Debug)]
pub struct PreMulCOnlineStore<F: PrimeField> {
    pub state: PhaseState,
    pub z_shares: Option<Vec<RobustShare<F>>>,
    pub chunks: usize,
    pub open: HashMap<u8, Vec<F>>,
    pub output_sender: Option<tokio::sync::oneshot::Sender<Vec<RobustShare<F>>>>,
    pub output_receiver: Option<tokio::sync::oneshot::Receiver<Vec<RobustShare<F>>>>,
}

impl<F: PrimeField> PreMulCOnlineStore<F> {
    pub fn new() -> Self {
        let (tx, rx) = tokio::sync::oneshot::channel();
        Self {
            state: PhaseState::Waiting,
            z_shares: None,
            chunks: 0,
            open: HashMap::new(),
            output_sender: Some(tx),
            output_receiver: Some(rx),
        }
    }
}
#[derive(Clone)]
pub struct PreMulCNode<F: PrimeField, R: RBC<Id = SessionId>> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    prep_store: Arc<Mutex<HashMap<SessionId, Arc<Mutex<PreMulCPrepStore<F>>>>>>,
    online_store: Arc<Mutex<HashMap<SessionId, Arc<Mutex<PreMulCOnlineStore<F>>>>>>,
    pub mul: Multiply<F, R>,
    pub batch_recon: BatchReconNode<F>,
    batch_output: Arc<Mutex<Receiver<SessionId>>>,
}

impl<F: PrimeField, R: RBC<Id = SessionId>> PreMulCNode<F, R> {
    pub fn new(id: usize, n: usize, t: usize) -> Result<Self, PreMulCError> {
        let (batch_sender, batch_receiver) = tokio::sync::mpsc::channel(200);
        let batch_recon = BatchReconNode::new(id, n, t, t, batch_sender)?;
        let mul = Multiply::new(id, n, t)?;
        Ok(Self {
            id,
            n,
            t,
            prep_store: Arc::new(Mutex::new(HashMap::new())),
            online_store: Arc::new(Mutex::new(HashMap::new())),
            mul,
            batch_recon,
            batch_output: Arc::new(Mutex::new(batch_receiver)),
        })
    }

    async fn get_or_create_prep(
        &self,
        session: SessionId,
    ) -> Result<Arc<Mutex<PreMulCPrepStore<F>>>, PreMulCError> {
        let mut map = self.prep_store.lock().await;
        if map.len() >= 256 && !map.contains_key(&session) {
            return Err(PreMulCError::LimitError);
        }
        Ok(map
            .entry(session)
            .or_insert_with(|| Arc::new(Mutex::new(PreMulCPrepStore::new())))
            .clone())
    }

    async fn get_or_create_online(
        &self,
        session: SessionId,
    ) -> Result<Arc<Mutex<PreMulCOnlineStore<F>>>, PreMulCError> {
        let mut map = self.online_store.lock().await;
        if map.len() >= 256 && !map.contains_key(&session) {
            return Err(PreMulCError::LimitError);
        }
        Ok(map
            .entry(session)
            .or_insert_with(|| Arc::new(Mutex::new(PreMulCOnlineStore::new())))
            .clone())
    }

    pub async fn clear_store(&self, session: SessionId) -> Result<(), PreMulCError> {
        self.batch_recon.clear_entire_store().await;
        self.mul.clear_store(session).await?;
        let mut pmap = self.prep_store.lock().await;
        let mut omap = self.online_store.lock().await;
        pmap.remove(&session);
        omap.remove(&session)
            .map(|_| ())
            .ok_or(PreMulCError::ClearStoreError(session))
    }

    pub async fn wait_for_preprocessing(
        &self,
        session: SessionId,
        duration: Duration,
    ) -> Result<(Vec<RobustShare<F>>, Vec<RobustShare<F>>), PreMulCError> {
        let rx = {
            let map = self.prep_store.lock().await;
            let inner = map
                .get(&session)
                .ok_or(PreMulCError::NoSuchSessionId(session))?
                .clone();
            let mut s = inner.lock().await;
            s.output_receiver
                .take()
                .ok_or(PreMulCError::ResultAlreadyReceived(session))?
        };
        match timeout(duration, rx).await {
            Err(_) => Err(PreMulCError::Timeout(session)),
            Ok(Err(_)) => Err(PreMulCError::ReceiveError(session)),
            Ok(Ok(v)) => Ok(v),
        }
    }

    pub async fn wait_for_result(
        &self,
        session: SessionId,
        duration: Duration,
    ) -> Result<Vec<RobustShare<F>>, PreMulCError> {
        let rx = {
            let map = self.online_store.lock().await;
            let inner = map
                .get(&session)
                .ok_or(PreMulCError::NoSuchSessionId(session))?
                .clone();
            let mut s = inner.lock().await;
            s.output_receiver
                .take()
                .ok_or(PreMulCError::ResultAlreadyReceived(session))?
        };
        match timeout(duration, rx).await {
            Err(_) => Err(PreMulCError::Timeout(session)),
            Ok(Err(_)) => Err(PreMulCError::ReceiveError(session)),
            Ok(Ok(v)) => Ok(v),
        }
    }

    pub async fn drain_batch_recon_output(&mut self) -> Result<(), PreMulCError> {
        loop {
            let id = {
                let mut rx = self.batch_output.lock().await;
                match rx.try_recv() {
                    Ok(id) => id,
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        return Err(PreMulCError::Abort)
                    }
                }
            };

            let output = self.batch_recon.get_store(id).await?;
            let vals: Vec<F> = CanonicalDeserialize::deserialize_compressed(output.as_slice())?;

            let calling_proto = id
                .calling_protocol()
                .ok_or(PreMulCError::SessionIdError(id))?;
            let parent = SessionId::new(
                calling_proto,
                SessionId::pack_slot24(id.exec_id(), 0, 0),
                id.instance_id(),
            );
            let chunk_idx = id.sub_id();

            match id.calling_protocol() {
                Some(ProtocolType::PreMulCOff) => {
                    self.handle_prep_batch(parent, chunk_idx, vals).await?
                }
                Some(_) => self.handle_online_batch(parent, chunk_idx, vals).await?,
                None => warn!("PreMulC: no calling_protocol in {:?}", id),
            }
        }
        Ok(())
    }

    // ── preprocessing ─────────────────────────────────────────────────────────

    /// Protocol 4.2 lines 1–8. k must be a multiple of (t+1).
    ///
    /// After calling this, drive `drain_batch_recon_output` until
    /// `wait_for_preprocessing` resolves to get ([w_1,…,w_k], [z_1,…,z_k]).
    pub async fn generate_preprocessing<N: Network + Send + Sync>(
        &mut self,
        r: Vec<RobustShare<F>>,
        s: Vec<RobustShare<F>>,
        triples: Vec<ShamirBeaverTriple<F>>,
        session: SessionId,
        network: Arc<N>,
        mul_duration: Duration,
    ) -> Result<(), PreMulCError> {
        let k = r.len();
        assert_eq!(s.len(), k);
        assert_eq!(k % (self.t + 1), 0, "k must be a multiple of t+1");

        let calling_proto = session
            .calling_protocol()
            .ok_or(PreMulCError::SessionIdError(session))?;

        self.mul
            .init(session, r.clone(), s.clone(), triples, Arc::clone(&network))
            .await?;
        let u_shares = self.mul.wait_for_result(session, mul_duration).await?;

        {
            let store = self.get_or_create_prep(session).await?;
            let mut st = store.lock().await;
            st.r = Some(r);
            st.s = Some(s);
            st.chunks = k / (self.t + 1);
        }

        // Open [u_i] via batch recon — protocol type PreMulCoff distinguishes from online.
        for (i, chunk) in u_shares.chunks(self.t + 1).enumerate() {
            let batch_session = SessionId::new(
                calling_proto,
                SessionId::pack_slot24(session.exec_id(), i as u8, 0),
                session.instance_id(),
            );
            self.batch_recon
                .init_batch_reconstruct(chunk, batch_session, Arc::clone(&network))
                .await?;
        }
        Ok(())
    }

    async fn handle_prep_batch(
        &mut self,
        parent: SessionId,
        chunk_idx: u8,
        vals: Vec<F>,
    ) -> Result<(), PreMulCError> {
        let store = self.get_or_create_prep(parent).await?;
        {
            let mut s = store.lock().await;
            if s.state == PhaseState::Finished {
                return Ok(());
            }
            s.open.insert(chunk_idx, vals);
        }
        self.try_finalize_prep(parent, store).await?;
        Ok(())
    }

    async fn try_finalize_prep(
        &self,
        session: SessionId,
        store_mutex: Arc<Mutex<PreMulCPrepStore<F>>>,
    ) -> Result<bool, PreMulCError> {
        let (r, s_vec, open_map, num_chunks) = {
            let s = store_mutex.lock().await;
            if s.state == PhaseState::Finished {
                return Ok(true);
            }
            if s.open.len() < s.chunks {
                return Ok(false);
            }
            let Some(r) = s.r.clone() else {
                return Ok(false);
            };
            let Some(sv) = s.s.clone() else {
                return Ok(false);
            };
            (r, sv, s.open.clone(), s.chunks)
        };

        // Assemble u_vals from chunks in order.
        let mut u_vals: Vec<F> = Vec::with_capacity(r.len());
        for i in 0..num_chunks as u8 {
            let chunk = open_map.get(&i).ok_or(PreMulCError::Abort)?;
            u_vals.extend_from_slice(chunk);
        }
        for u in &u_vals {
            if *u == F::zero() {
                return Err(PreMulCError::Abort); // repeat with new randomness
            }
        }

        let k = r.len();

        // Line 5: [v_i] = share_mul([r_{i+1}], [s_i])  for i = 0..k-2  (local).
        let mut v: Vec<RobustShare<F>> = Vec::with_capacity(k - 1);
        for i in 0..k - 1 {
            v.push(r[i + 1].share_mul(&s_vec[i])?);
        }

        // Lines 6–7: [w_1] = [r_0]; [w_i] = [v_{i-1}] * u_{i-1}^{-1}.
        let mut w: Vec<RobustShare<F>> = Vec::with_capacity(k);
        w.push(r[0].clone());
        for i in 1..k {
            let u_inv = u_vals[i - 1].inverse().expect("u != 0");
            w.push((v[i - 1].clone() * u_inv)?);
        }

        // Line 8: [z_i] = [s_i] * u_i^{-1}.
        let mut z: Vec<RobustShare<F>> = Vec::with_capacity(k);
        for i in 0..k {
            let u_inv = u_vals[i].inverse().expect("u != 0");
            z.push((s_vec[i].clone() * u_inv)?);
        }

        let sender = {
            let mut s = store_mutex.lock().await;
            if s.state == PhaseState::Finished {
                return Ok(true);
            }
            s.state = PhaseState::Finished;
            s.output_sender
                .take()
                .ok_or(PreMulCError::SendError(session))?
        };
        sender
            .send((w, z))
            .map_err(|_| PreMulCError::SendError(session))?;
        Ok(true)
    }

    // ── online ────────────────────────────────────────────────────────────────

    /// Protocol 4.2 lines 9–12. k must be a multiple of (t+1).
    ///
    /// Drive `drain_batch_recon_output` until `wait_for_result` resolves.
    pub async fn init<N: Network + Send + Sync>(
        &mut self,
        a: Vec<RobustShare<F>>,
        prep: PreMulCPrep<F>,
        session: SessionId,
        network: Arc<N>,
        mul_duration: Duration,
    ) -> Result<(), PreMulCError> {
        let k = a.len();
        if k == 0 {
            return Err(PreMulCError::EmptyInput);
        }
        assert_eq!(k % (self.t + 1), 0, "k must be a multiple of t+1");

        let calling_proto = session
            .calling_protocol()
            .ok_or(PreMulCError::SessionIdError(session))?;

        self.mul
            .init(session, prep.w, a, prep.triples, Arc::clone(&network))
            .await?;
        let m_shares = self.mul.wait_for_result(session, mul_duration).await?;

        {
            let store = self.get_or_create_online(session).await?;
            let mut s = store.lock().await;
            s.z_shares = Some(prep.z);
            s.chunks = k / (self.t + 1);
        }

        // Open [m_i] via batch recon (round_id = 0 for online).
        for (i, chunk) in m_shares.chunks(self.t + 1).enumerate() {
            let batch_session = SessionId::new(
                calling_proto,
                SessionId::pack_slot24(session.exec_id(), i as u8, 0),
                session.instance_id(),
            );
            self.batch_recon
                .init_batch_reconstruct(chunk, batch_session, Arc::clone(&network))
                .await?;
        }
        Ok(())
    }

    async fn handle_online_batch(
        &mut self,
        parent: SessionId,
        chunk_idx: u8,
        vals: Vec<F>,
    ) -> Result<(), PreMulCError> {
        let store = self.get_or_create_online(parent).await?;
        {
            let mut s = store.lock().await;
            if s.state == PhaseState::Finished {
                return Ok(());
            }
            s.open.insert(chunk_idx, vals);
        }
        self.try_finalize_online(parent, store).await?;
        Ok(())
    }

    async fn try_finalize_online(
        &self,
        session: SessionId,
        store_mutex: Arc<Mutex<PreMulCOnlineStore<F>>>,
    ) -> Result<bool, PreMulCError> {
        let (z_shares, open_map, num_chunks) = {
            let s = store_mutex.lock().await;
            if s.state == PhaseState::Finished {
                return Ok(true);
            }
            if s.open.len() < s.chunks {
                return Ok(false);
            }
            let Some(z) = s.z_shares.clone() else {
                return Ok(false);
            };
            (z, s.open.clone(), s.chunks)
        };

        // Assemble m_vals from chunks in order.
        let k = z_shares.len();
        let mut m_vals: Vec<F> = Vec::with_capacity(k);
        for i in 0..num_chunks as u8 {
            let chunk = open_map.get(&i).ok_or(PreMulCError::Abort)?;
            m_vals.extend_from_slice(chunk);
        }

        // Prefix products M_j = m_1 * … * m_j (public).
        let mut prefix_m = Vec::with_capacity(k);
        let mut acc = F::one();
        for m in &m_vals {
            acc *= m;
            prefix_m.push(acc);
        }

        // [p_j] = [z_j] * M_j  — holds for j=1 too: [z_1]*M_1 = [r_1^{-1}]*(r_1*a_1) = [a_1].
        let mut p_shares = Vec::with_capacity(k);
        for (z_j, m_j) in z_shares.into_iter().zip(prefix_m) {
            p_shares.push((z_j * m_j)?);
        }

        let sender = {
            let mut s = store_mutex.lock().await;
            if s.state == PhaseState::Finished {
                return Ok(true);
            }
            s.state = PhaseState::Finished;
            s.output_sender
                .take()
                .ok_or(PreMulCError::SendError(session))?
        };
        sender
            .send(p_shares)
            .map_err(|_| PreMulCError::SendError(session))?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::rbc::rbc::Avid;
    use ark_bls12_381::Fr;

    #[tokio::test]
    async fn test_premulc_session_limit() {
        let node = PreMulCNode::<Fr, Avid<SessionId>>::new(0, 5, 1).unwrap();
        for i in 0u8..=255 {
            let sid = SessionId::new(
                crate::honeybadger::ProtocolType::Trunc,
                SessionId::pack_slot24(i, 0, 0),
                111,
            );
            let _ = node.get_or_create_online(sid).await;
        }
        let sid = SessionId::new(
            crate::honeybadger::ProtocolType::Trunc,
            SessionId::pack_slot24(0, 1, 0),
            111,
        );
        assert!(matches!(
            node.get_or_create_online(sid).await,
            Err(PreMulCError::LimitError)
        ));
    }
}
