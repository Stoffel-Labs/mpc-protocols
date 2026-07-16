//! SufMulInv — suffix products and their multiplicative inverses.
//!
//! For inputs [a_0, ..., a_{k-1}] (all non-zero in F), computes:
//!   [S_j]     = [a_j * ... * a_{k-1}]          (suffix products)
//!   [S_j^{-1}] = [(a_j * ... * a_{k-1})^{-1}]  (suffix product inverses)
//!
//! # Algorithm
//!
//! SufMul: run PreMulC on the reversed input [a_{k-1}, ..., a_0].
//! Prefix products of the reversed array are the suffix products in reverse
//! order. Re-reversing the output recovers [S_0, ..., S_{k-1}].
//!
//! Inverses come for free from the PreMulC preprocessing material.
//! In the reversed PreMulC run:
//!   [P'_j]     = [z'_j] * M'_j              (prefix product, 0-indexed)
//!   [P'_j^{-1}] = [r'_j] * (M'_j)^{-1}     (r'_j = z'_j^{-1}, M'_j is public)
//!
//! init stores prep.r in the online store so try_finalize_online can compute
//! [p^{-1}] alongside [p] using the M_j values that are already on hand.
//!
//! After re-reversing (P'[k-1-j] = S[j]):
//!   [S_j^{-1}] = [P'[k-1-j]^{-1}]
//!
//! No additional rounds beyond SufMul (2 rounds total).
//!
//! # Preprocessing
//!
//! Identical to PreMulC: use PreMulCOfflineNode. PreMulCPrep.r is required.

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
pub struct SufMulInvNode<F: PrimeField, R: RBC> {
    pub inner: PreMulCOnlineNode<F, R>,
}

impl<F: PrimeField, R: RBC<Id = SessionId>> SufMulInvNode<F, R> {
    pub fn new(id: usize, n: usize, t: usize) -> Result<Self, PreMulCError> {
        Ok(Self {
            inner: PreMulCOnlineNode::new(id, n, t)?,
        })
    }

    pub async fn init<N: Network + Send + Sync>(
        &mut self,
        a: Vec<RobustShare<F>>,
        prep: PreMulCPrep<F>,
        session: SessionId,
        network: Arc<N>,
        mul_duration: Duration,
        duration: Duration,
    ) -> Result<(Vec<RobustShare<F>>, Vec<RobustShare<F>>), PreMulCError> {
        // Reverse input: suffix products = prefix products of reversed input.
        let mut rev_a = a;
        rev_a.reverse();

        // inner.init stores prep.r in the online store so try_finalize_online
        // computes [p_j^{-1}] = [r_j] * M_j^{-1} alongside [p_j].
        self.inner
            .init(rev_a, prep, session, network, mul_duration)
            .await?;
        let (mut prefix_products, p_inv_opt) =
            self.inner.wait_for_result(session, duration).await?;

        let mut p_inv = p_inv_opt.ok_or(PreMulCError::Abort)?;

        // Re-reverse both: prefix products of reversed input → suffix products.
        // After reversal position j holds P'[k-1-j] = S[j] and its inverse.
        prefix_products.reverse();
        p_inv.reverse();

        Ok((prefix_products, p_inv))
    }

    pub async fn clear_store(&self, session: SessionId) -> Result<(), PreMulCError> {
        self.inner.clear_store(session).await
    }
}
