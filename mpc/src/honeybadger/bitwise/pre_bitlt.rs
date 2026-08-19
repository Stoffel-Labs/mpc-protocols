//! PreBitLT — Protocol 11 (Catrina 2018).
//!
//! Given a *public* bit-decomposition a = [a_1, ..., a_k] (each a_i ∈ {0,1}) and
//! bitwise-shared secret b with shares [b_1], ..., [b_k], computes:
//!
//!   {[u_i]}^k_{i=1}  where  [u_i] = (a'_i < b'_i) ? 1 : 0
//!
//! with prefix sums  a'_i = Σ_{j=1}^{i} 2^j a_j  and  b'_i = Σ_{j=1}^{i} 2^j b_j.
//!
//! # Replacing D-variants
//!
//! The paper uses `Mod2D([s_i] ∗ [p'_{i+1}], k)` which multiplies locally to
//! degree-2t and reconstructs with a degree-2t-aware protocol.  We replace this
//! with a standard Beaver `Mul([s_i], [p'_{i+1}])` producing degree-t shares,
//! followed by ordinary `Mod2` — keeping all shares at degree t throughout.
//!
//! # Network rounds
//!
//! * Phase 1 – SufMulInv:  2 rounds (PreMulC offline already done)
//! * Phase 2 – Multiply:   1 round  (k-1 Beaver multiplications in parallel)
//! * Phase 3 – Mod2:       1 round  (k Mod2 invocations in parallel)
//! Total: 4 rounds (vs. paper's 2, because we avoid D-variants).
//!
//! # Preconditions
//!
//! * k ≥ 2
//! * k must be a multiple of (t + 1) — required by the internal PreMulCOnlineNode.
//! * `a_bits` and `b_shares` each have exactly k elements.
//! * `prep.mul_triples` has exactly k-1 elements.
//! * `prep.mod2_preps` has exactly k elements.

use crate::{
    common::ProtocolSessionId,
    honeybadger::{
        bitwise::{mod2::Mod2Node, suf_mul_inv::SufMulInvNode, PreBitLTError, PreBitLTPrep},
        mul::multiplication::Multiply,
        robust_interpolate::robust_interpolate::RobustShare,
        ProtocolType, SessionId,
    },
};
use ark_ff::{FftField, PrimeField};
use std::sync::Arc;
use stoffelnet::network_utils::Network;
use tokio::time::Duration;
use tracing::warn;

// ── Node ───────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct PreBitLTNode<F: PrimeField> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    /// Inner SufMulInv node — also handles its own Mul and BatchRecon for phase 1.
    pub suf_mul_inv: SufMulInvNode<F>,
    /// Standalone Multiply node for phase 3 (s_i × p_inv_{i+1}).
    pub mul: Multiply<F>,
    /// Mod2 node, shared across all k parallel Mod2 invocations in phase 4.
    pub mod2: Mod2Node<F>,
}

impl<F: PrimeField + FftField> PreBitLTNode<F> {
    pub fn new(id: usize, n: usize, t: usize) -> Result<Self, PreBitLTError> {
        Ok(Self {
            id,
            n,
            t,
            suf_mul_inv: SufMulInvNode::new(id, n, t)?,
            mul: Multiply::new(id, n, t)?,
            mod2: Mod2Node::new(id, n, t)?,
        })
    }

    /// Execute Protocol 11 (PreBitLT).
    ///
    /// # Arguments
    /// * `a_bits`   – public bit decomposition [a_1, ..., a_k], each value ∈ {0,1} as F.
    /// * `b_shares` – secret-shared bit decomposition [[b_1], ..., [b_k]].
    /// * `prep`     – all preprocessing for this execution.
    /// * `session`  – caller-provided session;
    /// * `network`  – network handle (shared with the message loop).
    /// * `duration` – per-phase timeout for `wait_for_result` calls.
    ///
    /// # Returns
    /// `[u_1, ..., u_k]` where `[u_i] = (a'_i < b'_i) ? 1 : 0`.
    pub async fn init<N: Network + Send + Sync + 'static>(
        &mut self,
        a_bits: Vec<F>,
        b_shares: Vec<RobustShare<F>>,
        prep: PreBitLTPrep<F>,
        session: SessionId,
        network: Arc<N>,
        duration: Duration,
    ) -> Result<Vec<RobustShare<F>>, PreBitLTError> {
        let k = a_bits.len();

        if k < 2 {
            return Err(PreBitLTError::InvalidInput(format!(
                "k must be ≥ 2 (got {k})"
            )));
        }
        if b_shares.len() != k {
            return Err(PreBitLTError::InvalidInput(format!(
                "a_bits.len() ({k}) != b_shares.len() ({})",
                b_shares.len()
            )));
        }
        if prep.mul_triples.len() != k - 1 {
            return Err(PreBitLTError::InvalidInput(format!(
                "mul_triples.len() ({}) != k-1 ({})",
                prep.mul_triples.len(),
                k - 1
            )));
        }
        if prep.mod2_preps.len() != k {
            return Err(PreBitLTError::InvalidInput(format!(
                "mod2_preps.len() ({}) != k ({k})",
                prep.mod2_preps.len()
            )));
        }

        // ── Phase 1: local XOR ──────────────────────────────────────────────────
        //
        // Protocol 11 lines 1-2:
        //   [d_i] = XOR(a_i, [b_i]) = a_i + [b_i] - 2*a_i*[b_i]
        //
        // Since a_i is a public scalar:
        //   [d_i] = [b_i] * (1 - 2*a_i) + a_i
        //

        let two = F::one() + F::one();
        let mut d: Vec<RobustShare<F>> = Vec::with_capacity(k);
        for (a_i, b_i) in a_bits.iter().zip(b_shares.iter()) {
            let coeff = F::one() - two * (*a_i); // 1 - 2*a_i (public)
            let d_i = ((b_i.clone() * coeff)? + *a_i)?;
            d.push(d_i);
        }

        // [d_i + 1] is the SufMulInv input; values are in {1, 2} — always non-zero. ✓
        let d_plus_1: Vec<RobustShare<F>> = d
            .iter()
            .map(|d_i| d_i.clone() + F::one())
            .collect::<Result<_, _>>()?;

        // ── Phase 2: SufMulInv ─────────────────────────────────────────────────
        //
        // Protocol 11 line 3:
        //   ({[p_i]}, {[p_i^{-1}]}) ← SufMulInv({[d_i + 1]})
        //
        // Output (0-indexed): p[j] = ∏_{i=j}^{k-1} (d[i]+1)
        //                     p_inv[j] = (p[j])^{-1}

        let (p, p_inv) = self
            .suf_mul_inv
            .init(
                d_plus_1,
                prep.suf_mul_inv_prep,
                session,
                Arc::clone(&network),
                duration,
                duration,
            )
            .await?;

        // p/p_inv are indexed by k below; validate their length now rather than
        // trusting SufMulInv/PreMulC's batch_recon-derived output to match k.
        if p.len() != k || p_inv.len() != k {
            return Err(PreBitLTError::InvalidInput(format!(
                "SufMulInv returned {} p and {} p_inv values, expected {k}",
                p.len(),
                p_inv.len()
            )));
        }

        // ── Phase 3: local s-computation ───────────────────────────────────────
        //
        // Protocol 11 lines 4-7 (0-indexed, paper uses 1-indexed):
        //
        //   s[0]   = (1 - a[0]) * (p[0] - p[1])
        //   s[i]   = s[i-1] + (1 - a[i]) * (p[i] - p[i+1])  for i ∈ [1, k-2]
        //   s[k-1] = s[k-2] + (1 - a[k-1]) * d[k-1]

        let mut s: Vec<RobustShare<F>> = Vec::with_capacity(k);

        // i = 0
        {
            let diff = (p[0].clone() - p[1].clone())?;
            let s0 = (diff * (F::one() - a_bits[0]))?;
            s.push(s0);
        }

        // i = 1 .. k-2 (middle terms)
        for i in 1..k - 1 {
            let diff = (p[i].clone() - p[i + 1].clone())?;
            let term = (diff * (F::one() - a_bits[i]))?;
            let si = (s[i - 1].clone() + term)?;
            s.push(si);
        }

        // i = k-1 (final term uses d instead of p difference)
        {
            let term = (d[k - 1].clone() * (F::one() - a_bits[k - 1]))?;
            let sk = (s[k - 2].clone() + term)?;
            s.push(sk);
        }

        // ── Phase 4: Multiply [s_i] × [p_inv_{i+1}] for i = 0..k-2 ───────────
        //
        // Protocol 11 line 9 (replacing Mod2D(local_product) with Mul+Mod2):
        //   [m_i] = Mul([s_i], [p_inv_{i+1}])  via Beaver triples → degree-t
        // This round is keyed on a standalone tag rather than the caller's, so
        // it needs one tag per top-level caller — FpDiv and LTZ both start
        // their exec_id counters at 0 and would otherwise share a session.
        let mul_tag = match session.calling_protocol() {
            Some(ProtocolType::LTZ) => ProtocolType::LTZBitMul,
            _ => ProtocolType::PreBitMul3,
        };
        let mul_session = SessionId::new(
            mul_tag,
            SessionId::pack_slot(session.exec_id(), 0, 0),
            session.instance_id(),
        );
        self.mul
            .init(
                mul_session,
                s[..k - 1].to_vec(), // [s_0, ..., s_{k-2}]
                p_inv[1..].to_vec(), // [p_inv_1, ..., p_inv_{k-1}]
                prep.mul_triples,
                Arc::clone(&network),
            )
            .await?;
        let mul_result = self.mul.wait_for_result(mul_session, duration).await;
        if let Err(e) = self.mul.clear_store(mul_session).await {
            warn!("PreBitLT: failed to clear mul store for session {mul_session:?}: {e:?}");
        }
        let m_shares = mul_result?;

        // ── Phase 5: batched Mod2 across all k values in one round ────────────
        //
        // Protocol 11 lines 9-10:
        //   [u_i] = Mod2([m_i], k)   for i = 0..k-2   (from Mul output)
        //   [u_{k-1}] = Mod2([s_{k-1}], k)             (direct from s)
        //
        // Batched rather than k separate Mod2::init calls: those would all
        // share session.exec_id() (only sub_id would vary), which collides
        // in Mod2Node's own session bookkeeping (see mod2.rs module docs).
        //
        // Reuse `session` (round=0, sub_id=0) directly as mod2_session:
        // Mod2Node's drain_rbc_output/try_finalize_batch reconstruct their
        // store key assuming round=0/sub_id=0, and self.mod2 is a separate
        // node — its own store and RBC engine — from self.suf_mul_inv/self.mul,
        // so reusing the same SessionId value here doesn't collide with theirs.

        let mod2_inputs: Vec<RobustShare<F>> = m_shares
            .into_iter()
            .chain(std::iter::once(s[k - 1].clone()))
            .collect();

        let mod2_session = session;
        self.mod2
            .init_batch(
                mod2_inputs,
                k,
                prep.mod2_preps,
                mod2_session,
                Arc::clone(&network),
            )
            .await?;
        let mod2_result = self
            .mod2
            .wait_for_batch_result(mod2_session, duration)
            .await;
        if let Err(e) = self.mod2.clear_store(mod2_session).await {
            warn!("PreBitLT: failed to clear mod2 store for session {mod2_session:?}: {e:?}");
        }
        let u_shares = mod2_result?;

        Ok(u_shares)
    }
}
