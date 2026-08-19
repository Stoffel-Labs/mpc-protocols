//! LTZ — Protocol 3.6 (Catrina & de Hoogh 2010): [a < 0] for a k-bit signed [a].
//!
//! LTZ(a, k) = -Trunc(a, k, k-1), and Trunc(a, k, m) = (a - (a mod 2^m)) * 2^-m.
//! Rather than a dedicated Mod2m/Trunc chain, this reuses PreMod2m (Protocol 9,
//! Catrina COMM 2018) directly: PreMod2m(a, k, m=k-1) already computes
//! {a mod 2^i}_{i=1}^{k-1} in one batched call, so LTZ just takes the last
//! entry (a mod 2^{k-1}) and does the trivial local truncation + negation.
//! No extra network round beyond PreMod2m's own — this adds no session
//! routing of its own, matching how the same primitive with no additional
//! interaction of its own is wrapped elsewhere in this codebase.

use crate::honeybadger::{
    bitwise::{pre_mod2m::PreMod2mNode, PreMod2mPrep},
    comparison::LTZError,
    robust_interpolate::robust_interpolate::RobustShare,
    SessionId,
};
use ark_ff::{FftField, PrimeField};
use std::sync::Arc;
use stoffelnet::network_utils::Network;
use tokio::time::Duration;

#[derive(Clone, Debug)]
pub struct LTZNode<F: PrimeField + FftField> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    pub pre_mod2m: PreMod2mNode<F>,
}

impl<F: PrimeField + FftField> LTZNode<F> {
    pub fn new(id: usize, n: usize, t: usize) -> Result<Self, LTZError> {
        Ok(Self {
            id,
            n,
            t,
            pre_mod2m: PreMod2mNode::new(id, n, t)?,
        })
    }

    /// Protocol 3.6 LTZ — returns [1] if a < 0, [0] otherwise.
    ///
    /// `k`: bit length of `a` (k >= 3, since PreMod2m requires m = k-1 >= 2).
    /// `prep`: PreMod2mPrep sized for m = k-1.
    pub async fn run<N: Network + Send + Sync + 'static>(
        &mut self,
        a: RobustShare<F>,
        k: usize,
        prep: PreMod2mPrep<F>,
        session: SessionId,
        network: Arc<N>,
        duration: Duration,
    ) -> Result<RobustShare<F>, LTZError> {
        if k < 3 {
            return Err(LTZError::InvalidInput(format!(
                "k must be >= 3 (got {k}); PreMod2m requires m = k-1 >= 2"
            )));
        }
        let m = k - 1;

        let mut results = self
            .pre_mod2m
            .init(a.clone(), k, m, prep, session, network, duration)
            .await?;

        // Last entry = a mod 2^{k-1} (Protocol 9's {a'_i}_{i=1}^m, 1-indexed,
        // 0-indexed here as results[m-1]).
        let a_mod = results.pop().ok_or_else(|| {
            LTZError::InvalidInput("PreMod2m returned an empty result vector".to_string())
        })?;

        let inv_two_pow_m = F::from(2u64)
            .pow([m as u64])
            .inverse()
            .expect("2^m is invertible in any prime field");
        let d = ((a - a_mod)? * inv_two_pow_m)?;
        let s = (d * (-F::one()))?;

        Ok(s)
    }
}
