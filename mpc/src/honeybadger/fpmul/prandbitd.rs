use crate::{
    common::{share::ShareError, ProtocolSessionId},
    honeybadger::{
        batch_recon::batch_recon::BatchReconNode,
        deser_bounded_vec,
        fpmul::{
            build_all_f_polys,
            f256::{build_all_f_polys_2_8, Gf2568, Gf256Domain},
            PRandBitDMessage, PRandBitDStore, PRandError, PrandState,
        },
        mul::concat_sorted,
        robust_interpolate::robust_interpolate::RobustShare,
        ProtocolType, SessionId, WrappedMessage,
    },
};
use ark_ff::{BigInteger, PrimeField};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain, Polynomial};
use itertools::Itertools;
use rand::Rng;
use std::{collections::HashMap, sync::Arc, vec};
use stoffelnet::network_utils::Network;
use tokio::{
    sync::{mpsc::Receiver, Mutex},
    time::{timeout, Duration},
};
use tracing::{info, warn};

/// Represents the shares stored by a player
#[derive(Debug, Clone)]
pub struct PRandBitDNode<F: PrimeField, G: PrimeField> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    pub store: Arc<Mutex<HashMap<SessionId, Arc<Mutex<PRandBitDStore<F, G>>>>>>,
    pub batch_recon: BatchReconNode<F>,
    pub batch_output: Arc<Mutex<Receiver<SessionId>>>,
}

impl<F: PrimeField, G: PrimeField> PRandBitDNode<F, G> {
    /// Creates a new PRandBitDNode with empty shares.
    pub fn new(id: usize, n: usize, t: usize) -> Result<Self, PRandError> {
        let (batch_sender, batch_receiver) = tokio::sync::mpsc::channel(200);
        let batch_recon = BatchReconNode::new(id, n, t, t, batch_sender)?;
        Ok(Self {
            id,
            n,
            t,
            store: Arc::new(Mutex::new(HashMap::new())),
            batch_recon,
            batch_output: Arc::new(Mutex::new(batch_receiver)),
        })
    }

    pub async fn clear_store(&self, session_id: SessionId) -> Result<(), PRandError> {
        self.batch_recon.clear_entire_store().await;
        let mut store = self.store.lock().await;
        store
            .remove(&session_id)
            .map(|_| ())
            .ok_or(PRandError::ClearStoreError(session_id))
    }
    pub async fn drain_batch_recon_output(&mut self) -> Result<(), PRandError> {
        loop {
            let id = {
                let mut rx = self.batch_output.lock().await;
                match rx.try_recv() {
                    Ok(id) => id,
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        return Err(PRandError::Abort);
                    }
                }
            };

            let output = self.batch_recon.get_store(id).await?;
            match self.output_handler(id, output).await {
                Ok(()) => {}
                Err(e) => {
                    return Err(e);
                }
            }
        }
        Ok(())
    }
    pub async fn wait_for_bit_result(
        &self,
        session_id: SessionId,
        duration: Duration,
    ) -> Result<Vec<(RobustShare<G>, Gf2568)>, PRandError> {
        let output_receiver = {
            let storage = self.store.lock().await;
            let storage_bind = match storage.get(&session_id) {
                Some(value) => value,
                None => return Err(PRandError::NoSuchSessionId(session_id)),
            };
            let mut storage = storage_bind.lock().await;

            storage
                .output_bit_receiver
                .take()
                .ok_or(PRandError::ResultAlreadyReceived(session_id))?
        };

        match timeout(duration, output_receiver).await {
            Err(_) => Err(PRandError::Timeout(session_id)),
            Ok(Err(_)) => Err(PRandError::ReceiveError(session_id)),
            Ok(Ok(shares)) => Ok(shares),
        }
    }

    pub async fn wait_for_int_result(
        &self,
        session_id: SessionId,
        duration: Duration,
    ) -> Result<Vec<RobustShare<G>>, PRandError> {
        let output_receiver = {
            let storage = self.store.lock().await;
            let storage_bind = match storage.get(&session_id) {
                Some(value) => value,
                None => return Err(PRandError::NoSuchSessionId(session_id)),
            };
            let mut storage = storage_bind.lock().await;

            storage
                .output_int_receiver
                .take()
                .ok_or(PRandError::ResultAlreadyReceived(session_id))?
        };

        match timeout(duration, output_receiver).await {
            Err(_) => Err(PRandError::Timeout(session_id)),
            Ok(Err(_)) => Err(PRandError::ReceiveError(session_id)),
            Ok(Ok(shares)) => Ok(shares),
        }
    }

    async fn try_finalize_bit(
        &self,
        session_id: SessionId,
        store_mutex: Arc<Mutex<PRandBitDStore<F, G>>>,
    ) -> Result<bool, PRandError> {
        // -------- Phase 1: Check readiness + extract --------
        let (share_r_2, share_r_p, share_r_plus_b, batch_size) = {
            let s = store_mutex.lock().await;

            if s.state == PrandState::BitFinished {
                return Ok(true);
            }

            if s.batch_size.is_none() {
                return Ok(false);
            }

            let batch_size = s.batch_size.unwrap();
            let no_of_batches = batch_size / (self.t + 1);

            if s.output_open.len() != no_of_batches {
                return Ok(false);
            }

            if s.share_r_2.is_none() || s.share_r_p.is_none() {
                return Ok(false);
            }
            if s.share_b_2.len() == batch_size {
                return Ok(true);
            }
            let share_r_plus_b = concat_sorted(&s.output_open);

            (
                s.share_r_2.clone().unwrap(),
                s.share_r_p.clone().unwrap(),
                share_r_plus_b,
                batch_size,
            )
        };

        // -------- Phase 2: Compute outside lock --------
        let mut b2_vec = Vec::with_capacity(batch_size);
        let mut bp_vec = Vec::with_capacity(batch_size);
        let mut output = Vec::with_capacity(batch_size);

        for (i, v) in share_r_plus_b.iter().enumerate() {
            let repr = v.into_bigint();
            let lsb = repr.is_odd();
            let lsb_elem_2 = Gf2568::from(lsb as u8);

            let bytes = repr.to_bytes_le();
            let v_g = G::from_le_bytes_mod_order(&bytes);

            let my_b2_share = share_r_2[i] + lsb_elem_2;

            let my_b_p_share = RobustShare::new(
                v_g - share_r_p[i].share[0],
                share_r_p[i].id,
                share_r_p[i].degree,
            );
            b2_vec.push(my_b2_share);
            bp_vec.push(my_b_p_share.clone());
            output.push((my_b_p_share, my_b2_share));
        }

        // -------- Phase 3: Commit + send --------
        let sender = {
            let mut s = store_mutex.lock().await;

            if s.state == PrandState::BitFinished {
                return Ok(true);
            }

            s.share_b_2.extend_from_slice(&b2_vec);
            s.share_b_p.extend_from_slice(&bp_vec);

            s.state = PrandState::BitFinished;

            s.output_bit_sender
                .take()
                .ok_or(PRandError::SendError(session_id))?
        };

        sender
            .send(output)
            .map_err(|_| PRandError::SendError(session_id))?;

        Ok(true)
    }

    async fn try_advance_from_riss<N>(
        &mut self,
        session_id: SessionId,
        calling_proto: ProtocolType,
        network: Arc<N>,
    ) -> Result<bool, PRandError>
    where
        N: Network + Send + Sync,
    {
        // Phase 0: Terminal fast-path
        {
            let binding = self.get_or_create_store(session_id).await?;
            let store = binding.lock().await;

            match calling_proto {
                ProtocolType::PRandInt => {
                    if store.state == PrandState::IntFinished {
                        return Ok(true);
                    }
                }
                ProtocolType::PRandBit => {
                    if store.state == PrandState::BitFinished {
                        return Ok(true);
                    }
                }
                _ => {}
            }
        }

        // Phase 1: Check readiness + decide what must be done
        let (batch_size, r_t_map, share_b_q, need_compute, need_open_start) = {
            let binding = self.get_or_create_store(session_id).await?;
            let store = binding.lock().await;

            let Some(batch_size) = store.batch_size else {
                return Ok(false);
            };
            let Some(total_tsets) = store.no_of_tsets else {
                return Ok(false);
            };

            if store.r_t.len() != total_tsets {
                return Ok(false);
            }
            // validate stored r_t lengths before indexing
            for r_t in store.r_t.values() {
                if r_t.len() != batch_size {
                    return Err(PRandError::InvalidMessage(format!(
                        "stored r_t has length {} but batch_size is {}",
                        r_t.len(),
                        batch_size
                    )));
                }
            }

            let need_compute =
                store.share_r_q.is_none() || store.share_r_p.is_none() || store.share_r_2.is_none();

            let need_open_start = calling_proto == ProtocolType::PRandBit && !store.open_started;

            let share_b_q = if calling_proto == ProtocolType::PRandBit {
                store.share_b_q.clone()
            } else {
                None
            };

            (
                batch_size,
                store.r_t.clone(),
                share_b_q,
                need_compute,
                need_open_start,
            )
        };

        // ============================================================
        // Phase 2: Heavy compute ONLY if needed
        // ============================================================
        let (share_q, share_p, share_2) = if need_compute {
            let tsets: Vec<Vec<usize>> = r_t_map.keys().cloned().collect();

            let poly_fq = build_all_f_polys::<F>(self.n, tsets.clone())?;
            let poly_fp = build_all_f_polys::<G>(self.n, tsets.clone())?;
            let poly_f2 = build_all_f_polys_2_8(self.n, tsets.clone())?;

            let domain_f = GeneralEvaluationDomain::<F>::new(self.n)
                .ok_or_else(|| ShareError::NoSuitableDomain(self.n))?;
            let domain_g = GeneralEvaluationDomain::<G>::new(self.n)
                .ok_or_else(|| ShareError::NoSuitableDomain(self.n))?;
            let domain_2 = Gf256Domain::new(self.n)?;

            let xi_q = domain_f.element(self.id);
            let xi_p = domain_g.element(self.id);
            let xi_2 = domain_2.element(self.id);

            let mut share_q = vec![RobustShare::new(F::zero(), self.id, self.t); batch_size];
            let mut share_p = vec![RobustShare::new(G::zero(), self.id, self.t); batch_size];
            let mut share_2 = vec![Gf2568::zero(); batch_size];

            for (tset, r_t) in r_t_map.iter() {
                let poly_q = &poly_fq[tset];
                let poly_p = &poly_fp[tset];
                let poly_2 = &poly_f2[tset];

                let coeff_q = poly_q.evaluate(&xi_q);
                let coeff_p = poly_p.evaluate(&xi_p);
                let coeff_2 = poly_2.evaluate(xi_2);

                for i in 0..batch_size {
                    let r_q = F::from(r_t[i]);
                    let r_p = G::from(r_t[i]);
                    let r_2 = Gf2568::from((r_t[i] & 1) as u8);

                    share_q[i].share[0] += r_q * coeff_q;
                    share_p[i].share[0] += r_p * coeff_p;
                    share_2[i] = share_2[i] + (r_2 * coeff_2);
                }
            }

            (Some(share_q), Some(share_p), Some(share_2))
        } else {
            (None, None, None)
        };

        // ============================================================
        // Phase 3: Commit derived shares + PRandInt finish
        // ============================================================
        let binding = self.get_or_create_store(session_id).await?;

        let (int_sender, int_out) = {
            let mut store = binding.lock().await;

            // Commit shares exactly once
            if let Some(ref q) = share_q {
                if store.share_r_q.is_none() {
                    store.share_r_q = Some(q.clone());
                }
            }
            if let Some(ref p) = share_p {
                if store.share_r_p.is_none() {
                    store.share_r_p = Some(p.clone());
                }
            }
            if let Some(ref s2) = share_2 {
                if store.share_r_2.is_none() {
                    store.share_r_2 = Some(s2.clone());
                }
            }

            // PRandInt: output once and stop
            if calling_proto == ProtocolType::PRandInt {
                if store.state != PrandState::IntFinished {
                    store.state = PrandState::IntFinished;

                    let out = store
                        .share_r_p
                        .clone()
                        .ok_or_else(|| PRandError::NotSet("share_r_p not set".into()))?;

                    let sender = store
                        .output_int_sender
                        .take()
                        .ok_or(PRandError::SendError(session_id))?;

                    (Some(sender), Some(out))
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            }
        };

        if let (Some(sender), Some(out)) = (int_sender, int_out) {
            sender
                .send(out)
                .map_err(|_| PRandError::SendError(session_id))?;
            return Ok(true);
        }

        // Phase 4: PRandBit — start openings exactly once
        if calling_proto == ProtocolType::PRandBit {
            let share_b_q = share_b_q
                .ok_or_else(|| PRandError::NotSet("share_b_q missing for PRandBit".into()))?;

            if need_open_start {
                let share_r_q = {
                    let mut store = binding.lock().await;
                    store.open_started = true;
                    store
                        .share_r_q
                        .clone()
                        .ok_or_else(|| PRandError::NotSet("share_r_q missing".into()))?
                };

                let share_rplusb: Vec<RobustShare<F>> = share_r_q
                    .iter()
                    .zip(share_b_q.iter())
                    .map(|(x, y)| x.clone() + y.clone())
                    .collect::<Result<_, _>>()
                    .map_err(|_| PRandError::NotSet("r+b failed".into()))?;

                for (i, chunk) in share_rplusb.chunks(self.t + 1).enumerate() {
                    let session_id_batch = SessionId::new(
                        calling_proto,
                        SessionId::pack_slot24(session_id.exec_id(), i as u8, 0),
                        session_id.instance_id(),
                    );
                    self.batch_recon
                        .init_batch_reconstruct(chunk, session_id_batch, network.clone())
                        .await?;
                }
            }

            let _ = self.try_finalize_bit(session_id, binding.clone()).await?;
        }

        Ok(true)
    }
    /// Distributed RISS generation
    /// generates shares in multiples of (t+1)
    pub async fn generate_riss<N: Network + Send + Sync>(
        &mut self,
        session_id: SessionId,
        smallfield_bits: Vec<RobustShare<F>>,
        l: usize,
        k: usize,
        batch_size: usize,
        network: Arc<N>,
    ) -> Result<(), PRandError> {
        info!(node_id = self.id, "RISS started");

        assert_eq!(session_id.sub_id(), 0);
        assert_eq!(session_id.round_id(), 0);

        if batch_size % (self.t + 1) != 0
            && session_id.calling_protocol() == Some(ProtocolType::PRandBit)
        {
            return Err(PRandError::Incompatible);
        }

        // Step 1: compute all maximal unqualified sets
        let tsets: Vec<Vec<usize>> = (0..self.n).combinations(self.t).collect();

        let binding = self.get_or_create_store(session_id).await?;
        let mut store = binding.lock().await;
        let my_tsets: Vec<Vec<usize>> = tsets
            .clone()
            .into_iter()
            .filter(|ts| !ts.contains(&self.id))
            .collect();
        store.no_of_tsets = Some(my_tsets.len());
        if smallfield_bits.len() != batch_size
            && session_id.calling_protocol() == Some(ProtocolType::PRandBit)
        {
            return Err(PRandError::NotSet(
                "Not enough bits from the smaller field".to_string(),
            ));
        }
        store.share_b_q = Some(smallfield_bits);
        store.batch_size = Some(batch_size);
        store.state = PrandState::Initialized;
        drop(store);
        self.try_advance_from_riss(
            session_id,
            session_id.calling_protocol().unwrap(),
            network.clone(),
        )
        .await?;

        // Step 2: P_i samples randomness and sends
        // Random integer range: [0, 2^(l+k)]
        let bound: i64 = 1 << (l + k);
        for tset in tsets {
            let r_t_i: Vec<i64> = (0..batch_size)
                .map(|_| rand::thread_rng().gen_range(0, bound + 1))
                .collect();

            // send to all players not in T
            for j in 0..self.n {
                if !tset.contains(&j) {
                    let msg = WrappedMessage::PRandBitD(PRandBitDMessage::new(
                        self.id,
                        session_id,
                        tset.clone(),
                        r_t_i.clone(),
                        vec![],
                    ));
                    let bytes_msg = bincode::serialize(&msg)?;
                    network.send(j, &bytes_msg).await?;
                }
            }
        }
        Ok(())
    }

    pub async fn process<N: Network + Send + Sync>(
        &mut self,
        msg: PRandBitDMessage,
        network: Arc<N>,
    ) -> Result<(), PRandError> {
        info!(node_id = self.id, sender = msg.sender_id, "At RISS handler");

        let calling_proto = match msg.session_id.calling_protocol() {
            Some(proto) => proto,
            None => {
                return Err(PRandError::SessionIdError(msg.session_id));
            }
        };

        let binding = self.get_or_create_store(msg.session_id).await?;
        let mut store = binding.lock().await;

        if msg.tset.contains(&self.id) {
            return Err(PRandError::InvalidMessage(format!(
                "node {} received message for tset that contains itself: {:?}",
                self.id, msg.tset
            )));
        }

        let maybe_batch_size = store.batch_size;

        if let Some(batch_size) = maybe_batch_size {
            if msg.r_t.len() != batch_size {
                return Err(PRandError::InvalidMessage(format!(
                    "r_t length {} does not match batch_size {}",
                    msg.r_t.len(),
                    batch_size
                )));
            }
        }

        // Get or create entry for this tset
        let tset_entry = store
            .riss_shares
            .entry(msg.tset.clone())
            .or_insert_with(HashMap::new);

        // Deduplicate per (sender, tset)
        if tset_entry.contains_key(&msg.sender_id) {
            return Err(PRandError::Duplicate(format!(
                "Already received from {} for tset {:?}",
                msg.sender_id, msg.tset
            )));
        }

        // Insert sender’s contribution
        tset_entry.insert(msg.sender_id, msg.r_t);

        // Check if we have all expected contributors
        let r_t_sum = if tset_entry.len() == self.n {
            let batch_size = maybe_batch_size
                .ok_or_else(|| PRandError::NotSet("batch_size not set when folding r_t".into()))?;
            Some(
                tset_entry
                    .values()
                    .fold(vec![0i64; batch_size], |mut acc, v| {
                        for (a, x) in acc.iter_mut().zip(v) {
                            *a += *x;
                        }
                        acc
                    }),
            )
        } else {
            None
        };

        if let Some(sum) = r_t_sum {
            store.r_t.insert(msg.tset.clone(), sum);
        }
        drop(store);
        self.try_advance_from_riss(msg.session_id, calling_proto, network.clone())
            .await?;
        Ok(())
    }

    pub async fn output_handler(
        &mut self,
        sid: SessionId,
        payload: Vec<u8>,
    ) -> Result<(), PRandError> {
        info!(node_id = self.id, "At output handler");

        let calling_proto = match sid.calling_protocol() {
            Some(proto) => proto,
            None => {
                return Err(PRandError::SessionIdError(sid));
            }
        };

        let session_id = SessionId::new(
            calling_proto,
            SessionId::pack_slot24(sid.exec_id(), 0, 0),
            sid.instance_id(),
        );

        let binding = self.get_or_create_store(session_id).await?;
        let mut store = binding.lock().await;
        if store.state == PrandState::BitFinished {
            return Ok(());
        }

        // deserialize the field element from the payload
        let share_i_list: Vec<F> = deser_bounded_vec(&mut payload.as_slice(), self.n)?;
        let dealer_id = sid.sub_id();
        if store.output_open.contains_key(&dealer_id) {
            return Err(PRandError::Duplicate(format!(
                "Already received for {}",
                dealer_id
            )));
        }
        store.output_open.insert(dealer_id, share_i_list);
        drop(store);
        self.try_finalize_bit(session_id, binding.clone()).await?;
        return Ok(());
    }

    pub async fn get_or_create_store(
        &mut self,
        session_id: SessionId,
    ) -> Result<Arc<Mutex<PRandBitDStore<F, G>>>, PRandError> {
        let mut storage = self.store.lock().await;

        if storage.len() >= 256 && !storage.contains_key(&session_id) {
            warn!("PRandBitD session limit reached");
            return Err(PRandError::LimitError);
        }
        Ok(storage
            .entry(session_id)
            .or_insert(Arc::new(Mutex::new(PRandBitDStore::empty())))
            .clone())
    }
}
