//! SufOr — suffix OR over shared bits (Catrina & de Hoogh 2010, Section 4.2).
//!
//! Computes [SufOr_j] = b_j OR b_{j+1} OR ... OR b_k  for each j in [1..k].
//!
//! # Why complements?
//!
//! OR cannot be computed directly as a field operation. De Morgan's law gives
//! the algebraic bridge:
//!
//!   OR(b_j, ..., b_k) = 1 - (1-b_j)(1-b_{j+1})...(1-b_k)
//!
//! For bits b_i in {0,1}, each complement (1-b_i) is also in {0,1}, so their
//! product is in {0,1}: it equals 1 iff ALL bits are 0, and 0 iff ANY bit is 1.
//! Complementing the product recovers OR. This means OR reduces to a product
//! computation — exactly what PreMulC does efficiently.
//!
//! # Why reverse?
//!
//! Without reversal, complement → PreMulC → complement gives PREFIX OR:
//!
//!   PrefOr_j = OR(b_1, ..., b_j)        [products grow left-to-right]
//!
//! Reversing the input before PreMulC makes the prefix products grow
//! right-to-left over the original array. Reversing the output maps them back
//! to the original index order, giving SUFFIX OR:
//!
//!   SufOr_j = OR(b_j, ..., b_k)         [same formula, reversed direction]
//!
//! Reversal is the only difference between Prefix OR and Suffix OR.
//! The paper states this directly: "SufOr is PreOr with inputs and outputs
//! in inverse order."
//!
//! # Steps (all local except the embedded PreMulCOnline call)
//!
//!   1. [c_i] = 1 - [b_i]                complement each bit (De Morgan)
//!   2. reverse [c_1..c_k] → [c_k..c_1]  so PreMulC runs right-to-left
//!   3. PreMulCOnline → prefix products of reversed complements
//!   4. reverse output → suffix products of complements in original order
//!   5. [SufOr_j] = 1 - [S_j]            complement recovers OR from product
//!
//! # Efficiency vs paper's PreOrC
//!
//! The paper's PreOrC feeds (b_i + 1) into PreMulC and then calls Mod2 on each
//! product to extract its LSB. That extra Mod2 step costs 1 round and 2k
//! invocations. Since our inputs are guaranteed bits, (1-b_i) is already in
//! {0,1} and the product is already a bit — Mod2 is unnecessary.
//!   My SufOr:  2 rounds, 3k-1 invocations
//!   PreOrC:    3 rounds, 5k-1 invocations
//!
//! # Preprocessing
//!
//! Identical to PreMulC: call PreMulCOfflineNode offline and pass the resulting
//! PreMulCPrep here. No new message types or session IDs are introduced.

use crate::{
    common::RBC,
    honeybadger::{
        bitwise::{pre_mulc::PreMulCOnlineNode, PreMulCError, PreMulCPrep},
        robust_interpolate::robust_interpolate::RobustShare,
        SessionId,
    },
};
use ark_ff::PrimeField;
use std::sync::Arc;
use stoffelnet::network_utils::Network;
use tokio::time::Duration;

#[derive(Clone, Debug)]
pub struct SufOrNode<F: PrimeField, R: RBC> {
    pub inner: PreMulCOnlineNode<F, R>,
}

impl<F: PrimeField, R: RBC<Id = SessionId>> SufOrNode<F, R> {
    pub fn new(id: usize, n: usize, t: usize) -> Result<Self, PreMulCError> {
        Ok(Self {
            inner: PreMulCOnlineNode::new(id, n, t)?,
        })
    }

    /// Runs suffix-OR on shared bits [b_1, ..., b_k] to completion and returns
    /// [SufOr_1, ..., SufOr_k] in original (non-reversed) order.
    ///
    /// Inputs must be secret-shared bits (values in {0,1}).
    /// Blocks internally on the embedded PreMulCOnline round until the result
    /// is ready or `duration` elapses. The outer message loop must keep
    /// routing incoming batch-recon messages to `inner.batch_recon` and
    /// calling `inner.drain_batch_recon_output()` concurrently while this
    /// call is in flight, or it will time out.
    pub async fn init<N: Network + Send + Sync>(
        &mut self,
        bits: Vec<RobustShare<F>>,
        prep: PreMulCPrep<F>,
        session: SessionId,
        network: Arc<N>,
        mul_duration: Duration,
        duration: Duration,
    ) -> Result<Vec<RobustShare<F>>, PreMulCError> {
        let neg_one = -F::one();

        // Step 1: [c_i] = 1 - [b_i].
        let mut complements: Vec<RobustShare<F>> = Vec::with_capacity(bits.len());
        for b in bits {
            let c = ((b * neg_one)? + F::one())?;
            complements.push(c);
        }

        // Step 2: reverse complements [c_1..c_k] → [c_k..c_1].
        complements.reverse();

        // Step 3: prefix products of reversed complements via PreMulC.
        // P'_j = c_k * c_{k-1} * ... * c_{k-j+1} = ∏_{i=k-j+1}^{k} (1-b_i)
        self.inner
            .init(complements, prep, session, network, mul_duration)
            .await?;
        let (mut p, _) = self.inner.wait_for_result(session, duration).await?;

        // Step 4: reverse prefix products back to original index order.
        // After reversal, position j holds S_j = ∏_{i=j}^{k} (1-b_i),
        // which is the suffix product of complements starting at j.
        p.reverse();

        // Step 5: [SufOr_j] = 1 - [S_j].
        // S_j = 0 if any b_i = 1 for i in [j..k], else S_j = 1.
        // Complementing gives SufOr_j = OR(b_j, ..., b_k).
        let mut result = Vec::with_capacity(p.len());
        for s in p {
            let or_j = ((s * neg_one)? + F::one())?;
            result.push(or_j);
        }
        Ok(result)
    }

    pub async fn clear_store(&self, session: SessionId) -> Result<(), PreMulCError> {
        self.inner.clear_store(session).await
    }
}
