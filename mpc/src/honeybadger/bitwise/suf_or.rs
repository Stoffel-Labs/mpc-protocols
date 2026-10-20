//! SufOr — suffix OR over shared bits (Catrina & de Hoogh 2010, Section 4.2,
//! Protocol 4.4 PreOrC, reversed).
//!
//! Computes [SufOr_j] = b_j OR b_{j+1} OR ... OR b_k  for each j in [1..k].
//!
//! # Construction (PreOrC)
//!
//! De Morgan's law gives the algebraic bridge from product to OR:
//!
//!   OR(a_1, ..., a_i) = 1 - (1-a_1)(1-a_2)...(1-a_i)
//!
//! but complementing the bits first and feeding `(1-a_i)` straight into
//! PreMulC — this module's previous construction — reveals each bit directly:
//! PreMulC's online phase opens a mask times the raw input at every position,
//! and a multiplicative mask can never hide whether its input was zero
//! (`w * 0 = 0` for any `w`). `(1-a_i)` is zero exactly when `a_i` is 1, so
//! that reveal leaked the bit on every honest execution (see pre_mulc.rs's
//! precondition doc, and project history: this was the secret-divisor-bit
//! leak in FXDiv's AppRec).
//!
//! PreOrC avoids this by shifting instead of complementing: feed `(a_i + 1)`
//! into PreMulC. Each factor is in {1, 2} — always non-zero regardless of
//! `a_i` — so the masked reveal carries no information about any individual
//! bit (same safety argument as SufMulInv's `d_i + 1`). The prefix product
//! `b_i = Π_{j=1}^i (a_j + 1)` is then odd iff every `a_j` in the prefix is 0,
//! and even iff any is 1 — so OR is recovered from `b_i`'s *parity alone*,
//! extracted via Mod2's own (additive, equally safe) masked reveal:
//!
//!   [b_1],...,[b_k] ← PreMulC([a_1]+1, ..., [a_k]+1)
//!   [p_1] ← [a_1]
//!   [p_i] ← 1 - Mod2([b_i], k)   for i ∈ [2..k]
//!
//! # Why reverse?
//!
//! PreOrC computes PREFIX OR. Reversing the input before it and the output
//! after it turns prefix-OR over the reversed array into SUFFIX OR over the
//! original array — the paper states this directly: "SufOr is PreOr with
//! inputs and outputs in inverse order." Reversal is the only difference
//! between the two; it's unchanged by this fix.
//!
//! # Preprocessing
//!
//! `SufOrPrep` bundles the inner PreMulC bundle (sized for k inputs) with
//! k-1 PRandMPrep values for the k-1 Mod2 calls (`p_1` needs none).

use crate::honeybadger::{
    bitwise::{
        mod2::Mod2Node,
        pre_mulc::PreMulCOnlineNode,
        {SufOrError, SufOrPrep},
    },
    robust_interpolate::robust_interpolate::RobustShare,
    SessionId,
};
use ark_ff::PrimeField;
use std::sync::Arc;
use stoffelnet::network_utils::Network;
use tokio::time::Duration;
use tracing::warn;

#[derive(Clone, Debug)]
pub struct SufOrNode<F: PrimeField> {
    pub inner: PreMulCOnlineNode<F>,
    pub mod2: Mod2Node<F>,
}

impl<F: PrimeField> SufOrNode<F> {
    pub fn new(id: usize, n: usize, t: usize) -> Result<Self, SufOrError> {
        Ok(Self {
            inner: PreMulCOnlineNode::new(id, n, t)?,
            mod2: Mod2Node::new(id, n, t)?,
        })
    }

    /// Runs suffix-OR on shared bits [b_1, ..., b_k] to completion and returns
    /// [SufOr_1, ..., SufOr_k] in original (non-reversed) order.
    ///
    /// `k_bits`: public bit-width passed through to Mod2's reveal offset
    /// (`2^{k_bits-1}`) — reuse the caller's own outer bit-width here, the
    /// same convention PreBitLT follows for its internal Mod2 calls on
    /// derived (not full-width) quantities; it only needs to exceed every
    /// prefix product's possible magnitude (bounded by `2^bits.len()`).
    ///
    /// Inputs must be secret-shared bits (values in {0,1}).
    /// Blocks internally on the embedded PreMulCOnline round and the Mod2
    /// batch round until the result is ready or `duration` elapses. The
    /// outer message loop must keep routing incoming batch-recon messages to
    /// `inner.batch_recon`/`inner.mul.batch_recon` and Mod2 messages to
    /// `mod2`, calling the respective drain functions concurrently while
    /// this call is in flight, or it will time out.
    pub async fn init<N: Network + Send + Sync>(
        &mut self,
        bits: Vec<RobustShare<F>>,
        k_bits: usize,
        prep: SufOrPrep<F>,
        session: SessionId,
        network: Arc<N>,
        mul_duration: Duration,
        duration: Duration,
    ) -> Result<Vec<RobustShare<F>>, SufOrError> {
        let k = bits.len();
        if prep.mod2_preps.len() != k.saturating_sub(1) {
            return Err(SufOrError::InvalidInput(format!(
                "mod2_preps.len() ({}) != k-1 ({})",
                prep.mod2_preps.len(),
                k.saturating_sub(1)
            )));
        }

        // Step 1: reverse input so PreMulC's prefix runs right-to-left over
        // the original array — prefix-OR of the reversed array is suffix-OR
        // of the original (see module docs).
        let mut rev = bits;
        rev.reverse();

        // Step 2: [a_i + 1] — always in {1,2}, non-zero regardless of a_i.
        let shifted: Vec<RobustShare<F>> = rev
            .iter()
            .map(|a| a.clone() + F::one())
            .collect::<Result<_, _>>()?;

        // Step 3: prefix products of the shifted array via PreMulC.
        let init_result = self
            .inner
            .init(
                shifted,
                prep.premulc_prep,
                session,
                Arc::clone(&network),
                mul_duration,
            )
            .await;
        if init_result.is_err() {
            if let Err(e) = self.inner.clear_store(session).await {
                warn!("SufOr: failed to clear premulc store for session {session:?}: {e:?}");
            }
        }
        init_result?;
        let inner_result = self.inner.wait_for_result(session, duration).await;
        if let Err(e) = self.inner.clear_store(session).await {
            warn!("SufOr: failed to clear premulc store for session {session:?}: {e:?}");
        }
        let (b_vals, _) = inner_result?;
        if b_vals.len() != k {
            return Err(SufOrError::InvalidInput(format!(
                "PreMulC returned {} values, expected {k}",
                b_vals.len()
            )));
        }

        // Step 4: p_1 = a_1 directly; p_i = 1 - Mod2(b_i, k) for i = 2..k,
        // batched into one combined Mod2 round (b_vals[1..], i.e. b_2..b_k).
        let mut p: Vec<RobustShare<F>> = Vec::with_capacity(k);
        p.push(rev[0].clone());

        if k > 1 {
            let mod2_inputs = b_vals[1..].to_vec();
            let mod2_result = self
                .mod2
                .init_batch(
                    mod2_inputs,
                    k_bits,
                    prep.mod2_preps,
                    session,
                    Arc::clone(&network),
                )
                .await;
            if mod2_result.is_err() {
                if let Err(e) = self.mod2.clear_store(session).await {
                    warn!("SufOr: failed to clear mod2 store for session {session:?}: {e:?}");
                }
            }
            mod2_result?;
            let mod2_out = self.mod2.wait_for_batch_result(session, duration).await;
            if let Err(e) = self.mod2.clear_store(session).await {
                warn!("SufOr: failed to clear mod2 store for session {session:?}: {e:?}");
            }
            let mod2_vals = mod2_out?;
            if mod2_vals.len() != k - 1 {
                return Err(SufOrError::InvalidInput(format!(
                    "Mod2 returned {} values, expected {}",
                    mod2_vals.len(),
                    k - 1
                )));
            }

            let one = RobustShare::new(F::one(), self.inner.id, self.inner.t);
            for m in mod2_vals {
                p.push((one.clone() - m)?);
            }
        }

        // Step 5: reverse back — prefix-OR of the reversed array, in
        // reversed-index order, is suffix-OR of the original array, in
        // original index order.
        p.reverse();
        Ok(p)
    }

    pub async fn clear_store(&self, session: SessionId) -> Result<(), SufOrError> {
        self.inner.clear_store(session).await?;
        self.mod2.clear_store(session).await?;
        Ok(())
    }
}
