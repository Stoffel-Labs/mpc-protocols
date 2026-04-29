//! LTZ — Protocol 3.6 (Catrina & de Hoogh 2010).
//!
//! Computes [a < 0] for a k-bit signed value [a].
//!
//! Protocol step:
//!   [s] ← −Trunc([a], k, k−1)
//!
//! Trunc([a], k, k-1) = floor(a / 2^{k-1}) which equals -1 if a < 0, else 0.
//! Negating gives 1 if a < 0, else 0.

use crate::{
    common::RBC,
    honeybadger::{
        comparison::{trunc::TruncNode, LTZError},
        robust_interpolate::robust_interpolate::RobustShare,
        triple_gen::ShamirBeaverTriple,
        SessionId,
    },
};
use ark_ff::PrimeField;
use std::sync::Arc;
use stoffelnet::network_utils::Network;
use tokio::time::Duration;

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
    /// `k`: bit length of [a] (signed two's complement).
    /// All remaining parameters are passed through to Trunc / Mod2m.
    pub async fn run<N: Network + Send + Sync>(
        &mut self,
        a: RobustShare<F>,
        k: usize,
        r_double_prime: RobustShare<F>,
        r_prime: RobustShare<F>,
        r_prime_bits: Vec<RobustShare<F>>,
        w: Vec<RobustShare<F>>,
        z: Vec<RobustShare<F>>,
        triples: Vec<ShamirBeaverTriple<F>>,
        r_dp_mod2: RobustShare<F>,
        r_zp_mod2: RobustShare<F>,
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
                r_double_prime,
                r_prime,
                r_prime_bits,
                w,
                z,
                triples,
                r_dp_mod2,
                r_zp_mod2,
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
