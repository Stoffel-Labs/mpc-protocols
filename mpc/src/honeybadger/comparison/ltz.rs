//! LTZ — Protocol 3.6 (Catrina & de Hoogh 2010).
//!
//! Computes [a < 0] for a k-bit signed value [a].
//!
//! Protocol step:
//!   [s] ← −Trunc([a], k, k−1)
//!
//! Trunc([a], k, k-1) = floor(a / 2^{k-1}) which equals -1 if a < 0, else 0.
//! Negating gives 1 if a < 0, else 0.

use crate::honeybadger::comparison::{trunc::TruncNode, LTZError, PRandMPrep, PreMulCPrep};
use crate::{
    common::RBC,
    honeybadger::{robust_interpolate::robust_interpolate::RobustShare, SessionId},
};
use ark_ff::PrimeField;
use std::sync::Arc;
use stoffelnet::network_utils::Network;
use tokio::time::Duration;

#[derive(Clone)]
pub struct LTZNode<F: PrimeField, R: RBC<Id = SessionId>> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    pub trunc: TruncNode<F, R>,
}

impl<F: PrimeField, R: RBC<Id = SessionId>> LTZNode<F, R> {
    pub fn new(id: usize, n: usize, t: usize) -> Result<Self, LTZError> {
        Ok(Self {
            id,
            n,
            t,
            trunc: TruncNode::new(id, n, t)?,
        })
    }

    /// Protocol 3.6 LTZ — returns [1] if a < 0, [0] otherwise.
    ///
    /// `k`: bit length of [a]
    /// All remaining parameters are passed through to Trunc / Mod2m.
    pub async fn run<N: Network + Send + Sync>(
        &mut self,
        a: RobustShare<F>,
        k: usize,
        prandm_prep: PRandMPrep<F>,
        premulc_prep: PreMulCPrep<F>,
        mod2_prep: PRandMPrep<F>,
        session: SessionId,
        network: Arc<N>,
        duration: Duration,
    ) -> Result<RobustShare<F>, LTZError> {
        // Trunc([a], k, k-1) = floor(a / 2^{k-1}) ∈ {-1, 0}
        let d = self
            .trunc
            .run(
                a,
                k,
                k - 1,
                prandm_prep,
                premulc_prep,
                mod2_prep,
                session,
                network,
                duration,
            )
            .await?;

        // [s] = -[d]  ∈ {0, 1}
        let s = (d * (-F::one()))?;

        Ok(s)
    }
}
