use crate::{
    common::{
        lagrange_interpolate,
        types::{
            f256::{lagrange_interpolate_f2_8, Poly, F2_8},
            MessageType, PRandBitDMessage, PRandBitDStore, PRandError,
        },
    },
    honeybadger::{ProtocolType, SessionId},
};
use ark_ff::{BigInteger, PrimeField};
use ark_poly::{univariate::DensePolynomial, Polynomial};
use itertools::Itertools;
use rand::Rng;
use std::{collections::HashMap, sync::Arc};
use stoffelnet::network_utils::Network;
use tokio::sync::Mutex;
use tracing::info;

/// Represents the shares stored by a player
#[derive(Debug, Clone)]
pub struct PRandBitDNode<F: PrimeField, G: PrimeField> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    pub l: usize,
    pub k: usize,
    pub store: Arc<Mutex<HashMap<SessionId, Arc<Mutex<PRandBitDStore<F, G>>>>>>,
}

impl<F: PrimeField, G: PrimeField> PRandBitDNode<F, G> {
    /// Creates a new PRandBitDNode with empty shares.
    pub fn new(id: usize, n: usize, t: usize, l: usize, k: usize) -> Self {
        Self {
            id,
            n,
            t,
            l,
            k,
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Distributed RISS generation
    pub async fn generate_riss<N: Network>(
        &mut self,
        session_id: SessionId,
        network: Arc<N>,
    ) -> Result<(), PRandError> {
        info!(node_id = self.id, "RISS started");
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

        // Step 2: P_i samples randomness and sends
        // Random integer range: [-2^(l+k), 2^(l+k)]
        let bound: i64 = 1 << (self.l + self.k);
        for tset in tsets {
            if tset.contains(&self.id) {
                continue;
            }
            let r_t_i = rand::thread_rng().gen_range(0, bound + 1);
            // send to all players not in T
            for j in 0..self.n {
                if !tset.contains(&j) {
                    let msg = PRandBitDMessage::new(
                        self.id,
                        MessageType::RissMessage,
                        session_id,
                        tset.clone(),
                        r_t_i,
                        vec![],
                    );
                    let bytes_msg = bincode::serialize(&msg)?;
                    network.send(j, &bytes_msg).await?;
                }
            }
        }
        Ok(())
    }

    pub async fn riss_handler<N: Network>(
        &mut self,
        msg: PRandBitDMessage,
        network: Arc<N>,
    ) -> Result<(), PRandError> {
        info!(node_id = self.id, sender = msg.sender_id, "At RISS handler");

        let binding = self.get_or_create_store(msg.session_id).await;
        let mut store = binding.lock().await;
        let total_tsets = store.no_of_tsets.ok_or_else(|| PRandError::NotSet)?;

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
        let expected = self.n - msg.tset.len(); // all not in T
        if tset_entry.len() == expected {
            // Compute r_T = sum of contributions
            let r_t_sum: i64 = tset_entry.values().copied().sum();
            store.r_t.insert(msg.tset.clone(), r_t_sum);

            if msg.session_id.calling_protocol() == Some(ProtocolType::PRandbInt) {
                //output the shared random integer,r_t
                info!(node_id = self.id, "Output for PRandInt");
                return Ok(());
            }
        }
        // Check if all tsets are done
        if store.r_t.len() == total_tsets {
            info!(node_id = self.id, "Constructing Polynomials");

            // Ready to do the conversions of shares
            let poly_fq = self.build_all_f_polys::<F>(store.r_t.clone()).await?;
            let poly_fp = self.build_all_f_polys::<G>(store.r_t.clone()).await?;
            //build f polys for Fq and F_2^8
            let poly_f2 = self.build_all_f_polys_2_8(store.r_t.clone()).await?;

            // My evaluation points in each field
            let xi_q = F::from(self.id as u64 + 1);
            let xi_p = G::from(self.id as u64 + 1);
            let xi_2 = F2_8::from(self.id as u16 + 1);

            let mut share_q = F::zero();
            let mut share_p = G::zero();
            let mut share_2 = F2_8::zero();

            for (tset, r_t) in store.r_t.clone() {
                let poly_q = &poly_fq[&tset];
                let poly_p = &poly_fp[&tset];
                let poly_2 = &poly_f2[&tset];

                // Evaluate polynomials at my xi
                let coeff_q = poly_q.evaluate(&xi_q);
                let coeff_p = poly_p.evaluate(&xi_p);
                let coeff_2 = poly_2.evaluate(xi_2);

                // Reduce r_T into each field
                let r_q = F::from(r_t);
                let r_p = G::from(r_t);
                let r_2 = F2_8::from((r_t & 1) as u8); // parity

                // Accumulate
                share_q += r_q * coeff_q;
                share_p += r_p * coeff_p;
                share_2 = share_2 + (r_2 * coeff_2);
            }

            // Save Shamir shares
            store.share_r_q = Some(share_q);
            store.share_r_p = Some(share_p);
            store.share_r_2 = Some(share_2);

            //Compute
            // Require that [b]_p is already set, otherwise return an error
            let share_b_p = store.share_b_q.ok_or_else(|| {
                PRandError::NotSet // or define a more specific error variant if you prefer
            })?;

            // share of r + b
            let share_rplusb = share_q + share_b_p;

            // Broadcast to everyone
            let mut payload = Vec::new();
            share_rplusb.serialize_compressed(&mut payload)?;
            let msg = PRandBitDMessage::new(
                self.id,
                MessageType::OutputMessage,
                msg.session_id,
                vec![],
                0,
                payload,
            );
            let bytes_msg = bincode::serialize(&msg)?;
            info!(node_id = self.id, "Broadcasting r+b");
            network.broadcast(&bytes_msg).await?;
        }

        Ok(())
    }

    pub async fn output_handler<N: Network>(
        &mut self,
        msg: PRandBitDMessage,
        _network: Arc<N>,
    ) -> Result<(), PRandError> {
        info!(node_id = self.id, "At output handler");

        let binding = self.get_or_create_store(msg.session_id).await;
        let mut store = binding.lock().await;

        // deserialize the field element from the payload
        let share_i: F =
            ark_serialize::CanonicalDeserialize::deserialize_compressed(msg.payload.as_slice())?;

        // Deduplicate
        if store.share_r_plus_b.contains_key(&msg.sender_id) {
            return Err(PRandError::Duplicate(format!(
                "Already received output share from {}",
                msg.sender_id
            )));
        }

        store.share_r_plus_b.insert(msg.sender_id, share_i);

        // Check if we have enough shares to reconstruct (t + 1)
        let needed = self.t + 1;
        if store.share_r_plus_b.len() >= needed {
            // Collect (x_vals, y_vals)
            let mut x_vals: Vec<F> = Vec::with_capacity(needed);
            let mut y_vals: Vec<F> = Vec::with_capacity(needed);

            for (&sender, share) in store.share_r_plus_b.iter().take(needed) {
                // x_i = (sender + 1) as field element (same mapping used earlier)
                x_vals.push(F::from((sender + 1) as u64));
                y_vals.push(*share);
            }

            // interpolate polynomial and evaluate at 0
            let poly = lagrange_interpolate(&x_vals, &y_vals)?;
            let v = poly.coeffs[0];

            // Compute lsb(v)
            // BigInteger has is_odd() method.
            let repr = v.into_bigint();
            let lsb = repr.is_odd(); // boolean
            let lsb_elem_2 = F2_8::from(lsb as u8);

            let bytes = repr.to_bytes_le();
            let v_g = G::from_le_bytes_mod_order(&bytes); // reduction into G

            // Now finalize GF(2^8) share: b = r0 XOR lsb
            let my_r0_share_2 = store.share_r_2.ok_or_else(|| PRandError::NotSet)?;
            let my_r0_share_g = store.share_r_p.ok_or_else(|| PRandError::NotSet)?;

            let my_b2_share = my_r0_share_2 + (lsb_elem_2);
            let my_b_p_share = v_g - my_r0_share_g;

            info!(node_id = self.id, "Generated [b] shares");
            store.share_b_2 = Some(my_b2_share);
            store.share_b_p = Some(my_b_p_share);

            // Clear collected opens to avoid reuse for subsequent openings
            store.share_r_plus_b.clear();
        }

        Ok(())
    }
    pub async fn process<N: Network>(
        &mut self,
        msg: PRandBitDMessage,
        network: Arc<N>,
    ) -> Result<(), PRandError> {
        match msg.msg_type {
            MessageType::RissMessage => self.riss_handler(msg, network).await?,
            MessageType::OutputMessage => self.output_handler(msg, network).await?,
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

    pub async fn build_all_f_polys<H: PrimeField>(
        &mut self,
        tsets: HashMap<Vec<usize>, i64>,
    ) -> Result<HashMap<Vec<usize>, DensePolynomial<H>>, PRandError> {
        tsets
            .into_iter()
            .map(|(tset, _)| {
                // Construct interpolation points
                let xs = std::iter::once(H::zero())
                    .chain(tset.iter().map(|&j| H::from((j + 1) as u64)))
                    .collect::<Vec<_>>();
                let ys = std::iter::once(H::one())
                    .chain(std::iter::repeat(H::zero()).take(tset.len()))
                    .collect::<Vec<_>>();
                // Interpolate polynomial
                let poly = lagrange_interpolate(&xs, &ys)?;
                Ok((tset, poly))
            })
            .collect()
    }

    pub async fn build_all_f_polys_2_8(
        &mut self,
        tsets: HashMap<Vec<usize>, i64>,
    ) -> Result<HashMap<Vec<usize>, Poly>, PRandError> {
        tsets
            .into_iter()
            .map(|(tset, _)| {
                // Construct interpolation points
                let xs = std::iter::once(F2_8::zero())
                    .chain(tset.iter().map(|&j| F2_8::from((j + 1) as u16)))
                    .collect::<Vec<_>>();
                let ys = std::iter::once(F2_8::one())
                    .chain(std::iter::repeat(F2_8::zero()).take(tset.len()))
                    .collect::<Vec<_>>();
                // Interpolate polynomial
                let poly = lagrange_interpolate_f2_8(&xs, &ys);
                Ok((tset, poly))
            })
            .collect()
    }
}
