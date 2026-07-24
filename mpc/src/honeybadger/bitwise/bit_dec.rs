//! BitDec — bit decomposition of a secret-shared signed integer (Catrina 2018,
//! Protocol 10).
//!
//! Given `[a]` with `a ∈ Z⟨k⟩ = [-2^{k-1}, 2^{k-1}-1]` (two's-complement signed,
//! matching the field encoding `fld(a) = a mod q` used throughout this crate),
//! computes `[a_0], [a_1], ..., [a_{k-1}]` — the two's-complement bit pattern,
//! `a_{k-1}` the sign bit — such that `a = -2^{k-1}a_{k-1} + Σ_{j=0}^{k-2} 2^j a_j`.
//!
//! # Algorithm
//!
//! 1. `{[a'_i]}_{i=1}^{k-1}` ← PreMod2m([a], k, k-1)
//!    where `a'_i = a mod 2^i`.
//!
//!    m = k-1, not k: the paper only defines PreMod2m for m < k (its 2^{k-1}
//!    reveal offset vanishes mod 2^i only for i ≤ k-1). The missing k-th
//!    prefix is degenerate anyway: `a mod 2^{k-1}` (= `a'_{k-1}`) is already
//!    the non-negative representative of a's lower k-1 bits, so the sign bit
//!    falls out of `a = -2^{k-1}a_{k-1} + a'_{k-1}` directly — no need to ask
//!    PreMod2m for a genuine k-th prefix.
//! 2. For j = 0:       `[a_0] = [a'_1]`         (LSB = a mod 2)
//! 3. For j = 1..k-2:  `[a_j] = ([a'_{j+1}] - [a'_j]) * 2^{-j}`
//!    For j = k-1:      `[a_{k-1}] = ([a'_{k-1}] - [a]) * 2^{-(k-1)}`
//!
//!    Correctness: `a'_{j+1} - a'_j = 2^j a_j` (either 0 or 2^j) for the
//!    ordinary prefixes. The top bit is the mirror image (`a'_{k-1} - a`, not
//!    `a - a'_{k-1}`) because rearranging `a = -2^{k-1}a_{k-1} + a'_{k-1}`
//!    gives `a_{k-1} = (a'_{k-1} - a) * 2^{-(k-1)}`. For non-negative a this
//!    coincides with either order (a'_{k-1} = a exactly, so the difference is
//!    0 regardless) — the two orderings only diverge once a is negative.
//!    Multiplying by `2^{-j}` in the prime field recovers the bit.
//! # Preconditions
//!
//! * k ≥ 3   (PreMod2m requires m ≥ 2; here m = k-1).
//! * `a ∈ Z⟨k⟩ = [-2^{k-1}, 2^{k-1}-1]` (signed).
//! * `prep.prandm.r_prime_bits.len() == k-1`.

use crate::{
    common::RBC,
    honeybadger::{
        bitwise::{pre_mod2m::PreMod2mNode, PreMod2mError, PreMod2mPrep},
        robust_interpolate::robust_interpolate::RobustShare,
        SessionId,
    },
};
use ark_ff::{FftField, PrimeField};
use std::sync::Arc;
use stoffelnet::network_utils::Network;
use tokio::time::Duration;
use tracing::warn;

// ── Type aliases ──────────────────────────────────────────────────────────────
/// Error type re-exported from PreMod2m.
pub type BitDecError = PreMod2mError;

// ── Node ──────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct BitDecNode<F: PrimeField, R: RBC> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    pub pre_mod2m: PreMod2mNode<F, R>,
}

impl<F: PrimeField + FftField, R: RBC<Id = SessionId>> BitDecNode<F, R> {
    pub fn new(id: usize, n: usize, t: usize) -> Result<Self, BitDecError> {
        Ok(Self {
            id,
            n,
            t,
            pre_mod2m: PreMod2mNode::new(id, n, t)?,
        })
    }

    /// Execute BitDec.
    ///
    /// # Arguments
    /// * `a`         – secret share; must lie in Z⟨k⟩ = [-2^{k-1}, 2^{k-1}-1] (signed).
    /// * `k`         – declared bit length (k ≥ 3).
    /// * `prep`      – preprocessing (BitDecPrep = PreMod2mPrep with m = k-1).
    /// * `session`   – caller session; `instance_id()` is inherited.
    /// * `network`   – network handle shared with the message loop.
    /// * `duration`  – per-phase timeout.
    ///
    /// # Returns
    /// `[[a_0], [a_1], ..., [a_{k-1}]]` — k shares, LSB first, each a bit in {0,1}.
    pub async fn init<N: Network + Send + Sync + 'static>(
        &mut self,
        a: RobustShare<F>,
        k: usize,
        prep: PreMod2mPrep<F>,
        session: SessionId,
        network: Arc<N>,
        duration: Duration,
    ) -> Result<Vec<RobustShare<F>>, BitDecError> {
        if k < 3 {
            return Err(BitDecError::InvalidInput(format!(
                "k must be ≥ 3 (got {k})"
            )));
        }

        // Step 1: get {[a mod 2^i]}_{i=1}^{k-1} via PreMod2m with m = k-1
        // (m < k, per the paper). prefix[j] = [a mod 2^{j+1}] for j = 0..k-2.
        // Cloned here so the original share is still available for the sign
        // bit derivation below.
        let m = k - 1;
        let result = self
            .pre_mod2m
            .init(
                a.clone(),
                k,
                m,
                prep,
                session,
                Arc::clone(&network),
                duration,
            )
            .await;
        if let Err(e) = self.pre_mod2m.clear_store(session).await {
            warn!("BitDec: failed to clear pre_mod2m store for session {session:?}: {e:?}");
        }
        let prefix = result?;

        // Step 2: extract individual bits by local arithmetic.
        // bits[0] = prefix[0]                              (a mod 2)
        // bits[j] = (prefix[j] - prefix[j-1]) * 2^{-j}      for j = 1..k-2
        // bits[k-1] = (prefix[k-2] - [a]) * 2^{-(k-1)}      (sign bit; note the
        //   order — from a = -2^{k-1}a_{k-1} + prefix[k-2], rearranged)
        let mut bits: Vec<RobustShare<F>> = Vec::with_capacity(k);
        bits.push(prefix[0].clone());

        let two = F::one() + F::one();
        let mut power_of_two = two; // 2^j, starts at 2^1
        for j in 1..m {
            let diff = (prefix[j].clone() - prefix[j - 1].clone())?;
            let inv = power_of_two.inverse().ok_or(BitDecError::Abort)?;
            let bit = (diff * inv)?;
            bits.push(bit);
            power_of_two = power_of_two + power_of_two;
        }

        // power_of_two is now 2^{k-1} (doubled once per iteration above),
        // exactly what the sign bit needs.
        let diff = (prefix[m - 1].clone() - a)?;
        let inv = power_of_two.inverse().ok_or(BitDecError::Abort)?;
        bits.push((diff * inv)?);

        Ok(bits)
    }
}
