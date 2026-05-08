//! BitLTC1 — Protocol 4.5 (Catrina & de Hoogh 2010).
//!
//! Computes [a <_k b] where a is a CLEAR value (public bit decomposition)
//! and [b]^B = ([b_0,...,b_{k-1}]) are SECRET bit shares (LSB = index 0).
//!
//! Protocol steps:
//!   1. [d_i] = a_i + [b_i] - 2*a_i*[b_i]   (XOR of a_i and b_i — local)
//!   2. PreMulC([d_{k-1}]+1, ..., [d_0]+1)   (MSB-first prefix products)
//!   3. [s_j] = [p_j] - [p_{j+1}]  for j=0..k-2;  [s_{k-1}] = [p_{k-1}] - 1   (local)
//!   4. [s] = Σ [s_j]*(1 - a_j)              (local scalar sum)
//!   5. [u] ← Mod2([s], k)                   (Protocol 3.4)
//!
//! Session routing (add to HoneyBadgerMPCNode.process):
//!   PreMulCOn BatchRecon (round_id=0): → pre_mul_c.batch_recon
//!   PreMulCOn BatchRecon (round_id=1): → pre_mul_c.mul.batch_recon
//!   PreMulCOn RBC        (round_id=2): → pre_mul_c.mul.rbc
//!   Mod2      Rbc        (round_id=0): → mod2.rbc.process + mod2.drain_rbc_output

use crate::{
    common::RBC,
    honeybadger::{
        comparison::{
            mod2::Mod2Node, pre_mulc::PreMulCOnlineNode, BitLTC1Error, PRandMPrep, PreMulCPrep,
        },
        robust_interpolate::robust_interpolate::RobustShare,
        SessionId,
    },
};
use ark_ff::PrimeField;
use std::sync::Arc;
use stoffelnet::network_utils::Network;
use tokio::time::Duration;

#[derive(Clone, Debug)]
pub struct BitLTC1Node<F: PrimeField, R: RBC> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    pub pre_mul_c: PreMulCOnlineNode<F, R>,
    pub mod2: Mod2Node<F, R>,
}

impl<F: PrimeField, R: RBC<Id = SessionId>> BitLTC1Node<F, R> {
    pub fn new(id: usize, n: usize, t: usize) -> Result<Self, BitLTC1Error> {
        Ok(Self {
            id,
            n,
            t,
            pre_mul_c: PreMulCOnlineNode::new(id, n, t)?,
            mod2: Mod2Node::new(id, n, t)?,
        })
    }

    /// PreMulC requires k to be a multiple of (t+1).
    /// Returns the padded length for `k_bits` bits.
    pub fn premulc_k(k_bits: usize, t: usize) -> usize {
        let chunk = t + 1;
        ((k_bits + chunk - 1) / chunk) * chunk
    }

    /// Protocol 4.5 BitLTC1.
    ///
    /// `a`:         clear k-bit value to compare against.
    /// `b_bits[i]`: secret share of bit i of b, LSB = index 0. Length determines k.
    /// `w`, `z`:    PreMulC offline output for `premulc_k(k, t)` elements.
    /// `triples`:   `premulc_k(k, t)` Beaver triples for PreMulC online.
    /// `r_double_prime`: [r''] from PRandM(k, 1) for Mod2 (must be a k-bit integer).
    /// `r_zero_prime`:   [r0'] from PRandM(k, 1) for Mod2 (0 or 1).
    pub async fn run<N: Network + Send + Sync>(
        &mut self,
        a: F,
        b_bits: Vec<RobustShare<F>>,
        premulc_prep: PreMulCPrep<F>,
        mod2_prep: PRandMPrep<F>,
        session: SessionId,
        network: Arc<N>,
        duration: Duration,
    ) -> Result<RobustShare<F>, BitLTC1Error> {
        let k = b_bits.len();
        if k == 0 {
            return Err(BitLTC1Error::LengthError);
        }
        // Decompose the clear value a into k bits, LSB first.
        let a_int = a.into_bigint().as_ref()[0]; // k <= 64, all bits in first limb
        let a_bits: Vec<F> = (0..k).map(|i| F::from((a_int >> i) & 1)).collect();

        let two = F::one() + F::one();

        // ── Step 1: [d_i] = a_i + [b_i] - 2*a_i*[b_i]  (all local) ──────────
        let mut d_shares: Vec<RobustShare<F>> = Vec::with_capacity(k);
        for i in 0..k {
            let coeff = F::one() - two * a_bits[i];
            let d_i = ((b_bits[i].clone() * coeff)? + a_bits[i])?;
            d_shares.push(d_i);
        }

        // ── Step 2: PreMulC on [d_{k-1}+1, ..., d_0+1]  (MSB-first) ─────────
        let pk = Self::premulc_k(k, self.t);
        let one_share = RobustShare::new(F::one(), self.id, self.t);
        let mut premulc_input: Vec<RobustShare<F>> = Vec::with_capacity(pk);
        for i in (0..k).rev() {
            premulc_input.push((d_shares[i].clone() + F::one())?);
        }
        while premulc_input.len() < pk {
            premulc_input.push(one_share.clone());
        }

        self.pre_mul_c
            .init(
                premulc_input,
                premulc_prep,
                session,
                Arc::clone(&network),
                duration,
            )
            .await?;
        let mut p_shares = self.pre_mul_c.wait_for_result(session, duration).await?;
        p_shares.reverse();
        // ── Step 3: differences of prefix products ────────────────────────────
        // p_shares[0..pk-k] are duplicates from padding with [1]s; valid products
        // start at index pk-k.
        let offset = pk - k;
        let mut s_shares: Vec<RobustShare<F>> = Vec::with_capacity(k);
        for j in 0..k - 1 {
            s_shares.push((p_shares[offset + j].clone() - p_shares[offset + j + 1].clone())?);
        }
        s_shares.push((p_shares[offset + k - 1].clone() - F::one())?);

        // ── Step 4: [s] = Σ [s_j]*(1 - a_j)  (local scalar sum) ─────────────
        let mut s_val = (s_shares[0].clone() * (F::one() - a_bits[0]))?;
        for j in 1..k {
            let term = (s_shares[j].clone() * (F::one() - a_bits[j]))?;
            s_val = (s_val + term)?;
        }

        // ── Step 5: [u] ← Mod2([s], k) ───────────────────────────────────────
        self.mod2
            .init(s_val, k, mod2_prep, session, Arc::clone(&network))
            .await?;
        let u = self.mod2.wait_for_result(session, duration).await?;

        Ok(u)
    }
}
