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
//!   Mod2 BatchRecon      (round_id=0): → mod2.batch_recon

use crate::{
    common::RBC,
    honeybadger::{
        comparison::{mod2::Mod2Node, pre_mulc::PreMulCNode, BitLTC1Error},
        robust_interpolate::robust_interpolate::RobustShare,
        triple_gen::ShamirBeaverTriple,
        SessionId,
    },
};
use ark_ff::PrimeField;
use std::sync::Arc;
use stoffelnet::network_utils::Network;
use tokio::time::Duration;

pub struct BitLTC1Node<F: PrimeField, R: RBC<Id = SessionId>> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    pub pre_mul_c: PreMulCNode<F, R>,
    pub mod2: Mod2Node<F, R>,
}

impl<F: PrimeField, R: RBC<Id = SessionId>> BitLTC1Node<F, R> {
    pub fn new(id: usize, n: usize, t: usize) -> Result<Self, BitLTC1Error> {
        Ok(Self {
            id,
            n,
            t,
            pre_mul_c: PreMulCNode::new(id, n, t)?,
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
    /// `a_bits[i]`: clear bit i of a (public field element, 0 or 1), LSB = index 0.
    /// `b_bits[i]`: secret share of bit i of b, LSB = index 0.
    /// `w`, `z`:    PreMulC offline output for `premulc_k(k, t)` elements.
    /// `triples`:   `premulc_k(k, t)` Beaver triples for PreMulC online.
    /// `r_double_prime`: [r''] from PRandM(k, 1) for Mod2.
    /// `r_zero_prime`:   [r0'] from PRandM(k, 1) for Mod2.
    pub async fn run<N: Network + Send + Sync>(
        &mut self,
        a_bits: Vec<F>,
        b_bits: Vec<RobustShare<F>>,
        w: Vec<RobustShare<F>>,
        z: Vec<RobustShare<F>>,
        triples: Vec<ShamirBeaverTriple<F>>,
        r_double_prime: RobustShare<F>,
        r_zero_prime: RobustShare<F>,
        session: SessionId,
        network: Arc<N>,
        mul_duration: Duration,
    ) -> Result<RobustShare<F>, BitLTC1Error> {
        let k = a_bits.len();
        if k == 0 || b_bits.len() != k {
            return Err(BitLTC1Error::LengthError);
        }

        let two = F::one() + F::one();

        // ── Step 1: [d_i] = a_i + [b_i] - 2*a_i*[b_i]  (all local) ──────────
        // Equivalent to XOR(a_i, b_i) as field elements when both are bits.
        // [d_i] = (1 - 2*a_i)*[b_i] + a_i
        let mut d_shares: Vec<RobustShare<F>> = Vec::with_capacity(k);
        for i in 0..k {
            let coeff = F::one() - two * a_bits[i];
            let d_i = ((b_bits[i].clone() * coeff)? + a_bits[i])?;
            d_shares.push(d_i);
        }

        // ── Step 2: PreMulC on [d_{k-1}+1, ..., d_0+1]  (MSB-first) ─────────
        // PreMulC input[j] = d_shares[k-1-j] + 1.
        // Padded to premulc_k with trivial [1] shares.
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
                w,
                z,
                triples,
                session,
                Arc::clone(&network),
                mul_duration,
            )
            .await?;
        let p_shares = self
            .pre_mul_c
            .wait_for_result(session, mul_duration)
            .await?;
        // p_shares[j] = product of PreMulC inputs 0..=j  (0-indexed).
        // p_shares[0] = d_{k-1}+1  (MSB prefix of length 1).

        // ── Step 3: differences of prefix products ────────────────────────────
        // [s_j] = [p_j] - [p_{j+1}]  for j = 0..k-2
        // [s_{k-1}] = [p_{k-1}] - 1
        let mut s_shares: Vec<RobustShare<F>> = Vec::with_capacity(k);
        for j in 0..k - 1 {
            s_shares.push((p_shares[j].clone() - p_shares[j + 1].clone())?);
        }
        s_shares.push((p_shares[k - 1].clone() - F::one())?);

        // ── Step 4: [s] = Σ [s_j]*(1 - a_j)  (local scalar sum) ─────────────
        let mut s_val = (s_shares[0].clone() * (F::one() - a_bits[0]))?;
        for j in 1..k {
            let term = (s_shares[j].clone() * (F::one() - a_bits[j]))?;
            s_val = (s_val + term)?;
        }

        // ── Step 5: [u] ← Mod2([s], k) ───────────────────────────────────────
        // Mod2 session: batch recon messages tagged with ProtocolType::Mod2
        // so the router sends them to mod2.batch_recon (distinct from pre_mul_c).
        self.mod2
            .init(
                s_val,
                k,
                r_double_prime,
                r_zero_prime,
                session,
                Arc::clone(&network),
            )
            .await?;
        let u = self.mod2.wait_for_result(session, mul_duration).await?;

        Ok(u)
    }
}
