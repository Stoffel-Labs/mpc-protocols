use crate::{
    common::share::ShareError,
    honeybadger::{
        batch_recon::batch_recon::BatchReconNode,
        fpmul::{
            build_all_f_polys,
            f256::{build_all_f_polys_2_8, F2_8Domain, F2_8},
            PRandBitDMessage, PRandBitDStore, PRandError, PRandMessageType,
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
use tokio::sync::{mpsc::Sender, Mutex};
use tracing::{debug, info};

/// Represents the shares stored by a player
#[derive(Debug, Clone)]
pub struct PRandBitNode<F: PrimeField, G: PrimeField> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    pub l: usize,
    pub k: usize,
    pub store: Arc<Mutex<HashMap<SessionId, Arc<Mutex<PRandBitDStore<F, G>>>>>>,
    pub output_bit_channel: Sender<SessionId>,
    pub output_int_channel: Sender<SessionId>,
    pub batch_recon: BatchReconNode<F>,
}

impl<F: PrimeField, G: PrimeField> PRandBitNode<F, G> {
    /// Creates a new PRandBitDNode with empty shares.
    pub fn new(
        id: usize,
        n: usize,
        t: usize,
        output_bit_channel: Sender<SessionId>,
        output_int_channel: Sender<SessionId>,
    ) -> Result<Self, PRandError> {
        let batch_recon = BatchReconNode::new(id, n, t)?;
        Ok(Self {
            id,
            n,
            t,
            l: 0,
            k: 0,
            store: Arc::new(Mutex::new(HashMap::new())),
            output_bit_channel,
            output_int_channel,
            batch_recon,
        })
    }

    pub async fn clear_store(&self) {
        let mut store = self.store.lock().await;
        self.batch_recon.clear_entire_store().await;
        store.clear();
    }

    /// Distributed RISS generation
    /// generates shares in multiples of (t+1)
    pub async fn generate_riss<N: Network>(
        &mut self,
        session_id: SessionId,
        smallfield_bits: Vec<RobustShare<F>>,
        l: usize,
        k: usize,
        batch_size: usize,
        network: Arc<N>,
    ) -> Result<(), PRandError> {
        info!(node_id = self.id, "RISS started");
        if batch_size % (self.t + 1) != 0
            && session_id.calling_protocol() == Some(ProtocolType::PRandBit)
        {
            return Err(PRandError::Incompatible);
        }
        self.l = l;
        self.k = k;
        // Step 1: compute all maximal unqualified sets
        let tsets: Vec<Vec<usize>> = (0..self.n).combinations(self.t).collect();

        let binding = self.get_or_create_store(session_id).await;
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
        drop(store);
        // Step 2: P_i samples randomness and sends
        // Random integer range: [0, 2^(l+k)]
        let bound: i64 = 1 << (self.l + self.k);
        for tset in tsets {
            let r_t_i: Vec<i64> = (0..batch_size)
                .map(|_| rand::thread_rng().gen_range(0, bound + 1))
                .collect();

            // send to all players not in T
            for j in 0..self.n {
                if !tset.contains(&j) {
                    let msg = WrappedMessage::PRandBit(PRandBitDMessage::new(
                        self.id,
                        PRandMessageType::RissMessage,
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

    pub async fn riss_handler<N: Network + Send + Sync>(
        &mut self,
        msg: PRandBitDMessage,
        network: Arc<N>,
    ) -> Result<(), PRandError> {
        info!(node_id = self.id, sender = msg.sender_id, "At RISS handler");

        let binding = self.get_or_create_store(msg.session_id).await;
        let mut store = binding.lock().await;

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
        if tset_entry.len() == self.n {
            // Compute r_T = sum of contributions
            let r_t_sum = tset_entry.values().fold(
                vec![0; tset_entry.values().next().unwrap().len()],
                |mut acc, v| {
                    for (a, x) in acc.iter_mut().zip(v) {
                        *a += *x;
                    }
                    acc
                },
            );
            store.r_t.insert(msg.tset.clone(), r_t_sum);
        }
        // Check if all tsets are done
        if store.batch_size.is_none() {
            debug!("Waiting for initiating");
            return Ok(());
        }
        let batch_size = store
            .batch_size
            .ok_or_else(|| PRandError::NotSet("Batch size not set at RISS handler".to_string()))?;
        let total_tsets = store.no_of_tsets.ok_or_else(|| {
            PRandError::NotSet(format!(
                "No of tsets not set {:?}",
                msg.session_id.calling_protocol().unwrap()
            ))
        })?;
        if store.r_t.len() == total_tsets {
            info!(node_id = self.id, "Constructing Polynomials");

            // Ready to do the conversions of shares
            let tsets: Vec<Vec<usize>> = store.r_t.keys().cloned().collect();
            let poly_fq = build_all_f_polys::<F>(self.n, tsets.clone())?;
            let poly_fp = build_all_f_polys::<G>(self.n, tsets.clone())?;
            //build f polys for Fq and F_2^8
            let poly_f2 = build_all_f_polys_2_8(self.n, tsets)?;

            // My evaluation points in each field
            let domain_f = GeneralEvaluationDomain::<F>::new(self.n)
                .ok_or_else(|| ShareError::NoSuitableDomain(self.n))?;
            let domain_g = GeneralEvaluationDomain::<G>::new(self.n)
                .ok_or_else(|| ShareError::NoSuitableDomain(self.n))?;
            let domain_2 = F2_8Domain::new(self.n)?;
            let xi_q = domain_f.element(self.id);
            let xi_p = domain_g.element(self.id);
            let xi_2 = domain_2.element(self.id);

            let mut share_q = vec![RobustShare::new(F::zero(), self.id, self.t); batch_size];
            let mut share_p = vec![RobustShare::new(G::zero(), self.id, self.t); batch_size];
            let mut share_2 = vec![F2_8::zero(); batch_size];

            for (tset, r_t) in store.r_t.clone() {
                let poly_q = &poly_fq[&tset];
                let poly_p = &poly_fp[&tset];
                let poly_2 = &poly_f2[&tset];

                // Evaluate polynomials at my xi
                let coeff_q = poly_q.evaluate(&xi_q);
                let coeff_p = poly_p.evaluate(&xi_p);
                let coeff_2 = poly_2.evaluate(xi_2);

                for i in 0..batch_size {
                    // Reduce r_T into each field
                    let r_q = F::from(r_t[i]);
                    let r_p = G::from(r_t[i]);
                    let r_2 = F2_8::from((r_t[i] & 1) as u8); // parity

                    // Accumulate
                    share_q[i].share[0] += r_q * coeff_q;
                    share_p[i].share[0] += r_p * coeff_p;
                    share_2[i] = share_2[i] + (r_2 * coeff_2);
                }
            }

            // Save Shamir shares
            store.share_r_q = Some(share_q.clone());
            store.share_r_p = Some(share_p);
            store.share_r_2 = Some(share_2);

            if msg.session_id.calling_protocol() == Some(ProtocolType::PRandInt) {
                //output the shared random integer,r_t that is converted to r_p
                //stored in share_r_p
                info!(node_id = self.id, "Output for PRandInt");
                self.output_int_channel.send(msg.session_id).await?;
                return Ok(());
            }

            //Compute
            let share_b_q = store
                .share_b_q
                .clone()
                .ok_or_else(|| PRandError::NotSet("Small field bits not set".to_string()))?;
            drop(store);
            
            // share of r + b
            let share_rplusb: Vec<RobustShare<F>> = share_q
                .iter()
                .zip(share_b_q.iter())
                .filter_map(|(x, y)| match x.clone() + y.clone() {
                    Ok(sum) => Some(sum),
                    Err(e) => {
                        eprintln!("Share addition failed: {:?}", e);
                        None
                    }
                })
                .collect();

            // Batch reconstruct r+b
            for (i, chunk) in share_rplusb.chunks(self.t + 1).enumerate() {
                let session_id_batch = SessionId::new(
                    msg.session_id.calling_protocol().unwrap(),
                    msg.session_id.exec_id(),
                    0,
                    i as u8,
                    msg.session_id.instance_id(),
                );
                self.batch_recon
                    .init_batch_reconstruct(chunk, session_id_batch, network.clone())
                    .await?;
            }
        }

        Ok(())
    }

    pub async fn output_handler(&mut self, msg: PRandBitDMessage) -> Result<(), PRandError> {
        info!(node_id = self.id, "At output handler");

        let session_id = SessionId::new(
            msg.session_id.calling_protocol().unwrap(),
            msg.session_id.exec_id(),
            0,
            0,
            msg.session_id.instance_id(),
        );

        let binding = self.get_or_create_store(session_id).await;
        let mut store = binding.lock().await;
        let batch_size = store
            .batch_size
            .ok_or_else(|| PRandError::NotSet("Batch size not set at RISS handler".to_string()))?;
        let no_of_batches = batch_size / (self.t + 1);

        // deserialize the field element from the payload
        let share_i_list: Vec<F> =
            ark_serialize::CanonicalDeserialize::deserialize_compressed(msg.payload.as_slice())?;
        let round_id = msg.session_id.round_id();
        if store.output_open.contains_key(&round_id) {
            return Err(PRandError::Duplicate(format!(
                "Already received from {}",
                msg.sender_id
            )));
        }
        store.output_open.insert(round_id, share_i_list);
        if store.output_open.len() != no_of_batches {
            debug!("Waiting for more openings");
            return Ok(());
        }

        let share_r_plus_b: Vec<F> = concat_sorted(&store.output_open);

        // Check if we have enough shares to reconstruct
        if store.share_b_2.len() != batch_size {
            for (i, v) in share_r_plus_b.iter().enumerate() {
                // Compute lsb(v)
                // BigInteger has is_odd() method.
                let repr = v.into_bigint();
                let lsb = repr.is_odd(); // boolean
                let lsb_elem_2 = F2_8::from(lsb as u8);

                let bytes = repr.to_bytes_le();
                let v_g = G::from_le_bytes_mod_order(&bytes); // reduction into G

                // Now finalize GF(2^8) share: b = r0 XOR lsb
                if store.share_r_2.is_none() {
                    debug!("Waiting for F_2^8 field share to be set");
                    return Ok(());
                }
                let my_r0_share_2 = store
                    .share_r_2
                    .clone()
                    .ok_or_else(|| PRandError::NotSet("F_2^8 share not set".to_string()))?;
                let my_r0_share_g = store
                    .share_r_p
                    .clone()
                    .ok_or_else(|| PRandError::NotSet("Big field share not set".to_string()))?;

                let my_b2_share = my_r0_share_2[i] + (lsb_elem_2);
                let my_b_p_share = RobustShare::new(
                    v_g - my_r0_share_g[i].share[0],
                    my_r0_share_g[i].id,
                    my_r0_share_g[i].degree,
                );

                info!(node_id = self.id, "Generated [b] shares");
                store.share_b_2.push(my_b2_share);
                store.share_b_p.push(my_b_p_share);
            }
            info!(id = self.id, "Prandbit finished");
            self.output_bit_channel.send(session_id).await?;
            return Ok(());
        }

        Ok(())
    }
    pub async fn process<N: Network + Send + Sync>(
        &mut self,
        msg: PRandBitDMessage,
        network: Arc<N>,
    ) -> Result<(), PRandError> {
        match msg.msg_type {
            PRandMessageType::RissMessage => self.riss_handler(msg, network).await?,
            PRandMessageType::OutputMessage => self.output_handler(msg).await?,
        }
        Ok(())
    }

    pub async fn get_or_create_store(
        &mut self,
        session_id: SessionId,
    ) -> Arc<Mutex<PRandBitDStore<F, G>>> {
        let mut storage = self.store.lock().await;
        storage
            .entry(session_id)
            .or_insert(Arc::new(Mutex::new(PRandBitDStore::empty())))
            .clone()
    }
}
