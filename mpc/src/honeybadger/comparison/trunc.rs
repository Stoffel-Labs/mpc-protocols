//! Trunc — Protocol 3.3 (Catrina & de Hoogh 2010).
//!
//! Computes [floor(a / 2^m)] given [a] and PRandM(k, m) preprocessing.
//!
//! Protocol steps:
//!   1. [a'] ← Mod2m([a], k, m)
//!   2. [d]  ← ([a] - [a']) * (2^{-m} mod q)   (local)
//!
//! No independent routing needed — all network activity is inside Mod2m.

use crate::{
    common::RBC,
    honeybadger::{
        comparison::{mod2m::Mod2mNode, PRandMPrep, PreMulCPrep, TruncError},
        robust_interpolate::robust_interpolate::RobustShare,
        SessionId,
    },
};
use ark_ff::PrimeField;
use std::sync::Arc;
use stoffelnet::network_utils::Network;
use tokio::time::Duration;
#[derive(Clone)]
pub struct TruncNode<F: PrimeField, R: RBC<Id = SessionId>> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    pub mod2m: Mod2mNode<F, R>,
}

impl<F: PrimeField, R: RBC<Id = SessionId>> TruncNode<F, R> {
    pub fn new(id: usize, n: usize, t: usize) -> Result<Self, TruncError> {
        Ok(Self {
            id,
            n,
            t,
            mod2m: Mod2mNode::new(id, n, t)?,
        })
    }

    /// Protocol 3.3 Trunc — computes [floor(a / 2^m)].
    ///
    /// All parameters beyond `a`, `k`, `m` are passed through to Mod2m.
    /// See `Mod2mNode::run` for preprocessing requirements.
    pub async fn run<N: Network + Send + Sync>(
        &mut self,
        a: RobustShare<F>,
        k: usize,
        m: usize,
        prandm_prep: PRandMPrep<F>,
        premulc_prep: PreMulCPrep<F>,
        mod2_prep: PRandMPrep<F>,
        session: SessionId,
        network: Arc<N>,
        duration: Duration,
    ) -> Result<RobustShare<F>, TruncError> {
        let a_prime = self
            .mod2m
            .run(
                a.clone(),
                k,
                m,
                prandm_prep,
                premulc_prep,
                mod2_prep,
                session,
                Arc::clone(&network),
                duration,
            )
            .await?;

        let inv_two_m = F::from(2u64)
            .pow([m as u64])
            .inverse()
            .expect("2^m is invertible in any prime field");
        let d = ((a - a_prime)? * inv_two_m)?;

        Ok(d)
    }
}
