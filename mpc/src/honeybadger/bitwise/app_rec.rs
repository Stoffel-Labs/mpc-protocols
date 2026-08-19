//! AppRec — Approximate Reciprocal (Protocol 8, Catrina, COMM 2018).
//!
//! Given a secret fixed-point `[b]` (k-bit signed, f fractional bits, `b ≠ 0`),
//! computes `[w] ≈ 1/b` and `[z] = (b == 0)?`.
//!
//! # Algorithm
//!
//! 1. `α ← fld(int_{k-1}(2.9142))`                         (local constant)
//! 2. `{b_i}_{i=0}^{k-1} ← BitDec([b], k, k)`                — full two's-complement
//!    decomposition; `b_{k-1}` is the sign bit.
//! 3. `b'_i ← b_i ⊕ b_{k-1}`  for `i ∈ [0,k-2]`               — XOR each non-sign bit
//!    with the sign bit, so positive and negative `b` are handled uniformly.
//! 4. `{c_i}_{i=0}^{k-2} ← SufOr({b'_i}_{i=0}^{k-2})`         — locates the leading bit.
//! 5. `v ← 1 + Σ_{i=0}^{k-2} 2^i(1-c_i)`                      — normalization factor,
//!    as a secret share (never reveals its exponent).
//! 6. `z ← 1 - (c_0 ∨ b_{k-1})`                               — zero flag.
//! 7. `w' ← α(1-2b_{k-1}) - 2v·b`                             — linear approximation
//!    of `1/b'` where `b' = v·b` is the (still secret) normalized divisor.
//! 8. `w ← TruncPr(v·w', 2k, 2(k-f-1))`                       — undo normalization
//!    and truncate back to f fractional bits.

use crate::{
    common::ProtocolSessionId,
    honeybadger::{
        bitwise::{
            bit_dec::BitDecNode, suf_or::SufOrNode, AppRecPrep, PreMod2mError, PreMulCError,
        },
        fpmul::{truncpr::TruncPrNode, TruncPrError},
        mul::{multiplication::Multiply, MulError},
        robust_interpolate::robust_interpolate::RobustShare,
        triple_gen::ShamirBeaverTriple,
        ProtocolType, SessionId,
    },
};
use ark_ff::{FftField, PrimeField};
use std::sync::Arc;
use stoffelnet::network_utils::Network;
use thiserror::Error;
use tokio::time::Duration;
use tracing::warn;

#[derive(Debug, Error)]
pub enum AppRecError {
    #[error("BitDec/PreMod2m error: {0}")]
    BitDecError(#[from] PreMod2mError),
    #[error("SufOr/PreMulC error: {0}")]
    SufOrError(#[from] PreMulCError),
    #[error("Multiply error: {0}")]
    MulError(#[from] MulError),
    #[error("TruncPr error: {0}")]
    TruncPrError(#[from] TruncPrError),
    #[error("share error: {0}")]
    ShareError(#[from] crate::common::share::ShareError),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("session ID error: {0:?}")]
    SessionIdError(SessionId),
}

#[derive(Clone, Debug)]
pub struct AppRecNode<F: PrimeField + FftField> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    pub bit_dec: BitDecNode<F>,
    pub suf_or: SufOrNode<F>,
    pub mul: Multiply<F>,
    pub trunc: TruncPrNode<F>,
}

impl<F: PrimeField + FftField> AppRecNode<F> {
    pub fn new(id: usize, n: usize, t: usize) -> Result<Self, AppRecError> {
        Ok(Self {
            id,
            n,
            t,
            bit_dec: BitDecNode::new(id, n, t)?,
            suf_or: SufOrNode::new(id, n, t)?,
            mul: Multiply::new(id, n, t)?,
            trunc: TruncPrNode::new(id, n, t)?,
        })
    }

    /// Runs one Multiply round to completion and clears its store
    async fn mul_round<N: Network + Send + Sync + 'static>(
        &mut self,
        session: SessionId,
        x: Vec<RobustShare<F>>,
        y: Vec<RobustShare<F>>,
        triples: Vec<ShamirBeaverTriple<F>>,
        network: Arc<N>,
        duration: Duration,
    ) -> Result<Vec<RobustShare<F>>, AppRecError> {
        self.mul
            .init(session, x, y, triples, Arc::clone(&network))
            .await?;
        let result = self.mul.wait_for_result(session, duration).await;
        if let Err(e) = self.mul.clear_store(session).await {
            warn!("AppRec: failed to clear mul store for session {session:?}: {e:?}");
        }
        Ok(result?)
    }

    /// Protocol 8 (AppRec). Returns `([w], [z])` where `w ≈ 1/b` and
    /// `z = (b == 0) ? 1 : 0`.
    pub async fn init<N: Network + Send + Sync + 'static>(
        &mut self,
        b: RobustShare<F>,
        k: usize,
        f: usize,
        prep: AppRecPrep<F>,
        session: SessionId,
        network: Arc<N>,
        duration: Duration,
    ) -> Result<(RobustShare<F>, RobustShare<F>), AppRecError> {
        if k < 3 {
            return Err(AppRecError::InvalidInput(format!(
                "k must be ≥ 3 (got {k})"
            )));
        }
        if f + 1 >= k {
            return Err(AppRecError::InvalidInput(format!(
                "f+1 must be < k (got f={f}, k={k})"
            )));
        }

        // ── Step 1: α = fld(int_{k-1}(2.9142)), computed as an exact integer ──
        //
        // round(29142 * 2^{k-1} / 10000), using u128 arithmetic (not f64) to
        // avoid precision loss for the k∈[64,112] range the paper targets.
        let two_pow_km1: u128 = 1u128 << (k as u32 - 1);
        let alpha_int: u128 = (29142u128 * two_pow_km1 + 5000) / 10000;
        let alpha = F::from(alpha_int);

        // ── Step 2: full k-bit decomposition, b_{k-1} is the sign bit ────────
        let bits = self
            .bit_dec
            .init(
                b.clone(),
                k,
                prep.bitdec_prep,
                session,
                Arc::clone(&network),
                duration,
            )
            .await?;
        let sign = bits[k - 1].clone();

        // ── Step 3: b'_i = b_i XOR sign, for i ∈ [0,k-2] ─────────────────────
        let mul_session = SessionId::new(
            ProtocolType::PreBitMul,
            SessionId::pack_slot(session.exec_id(), 0, 0),
            session.instance_id(),
        );
        let non_sign_bits: Vec<RobustShare<F>> = bits[..k - 1].to_vec();
        let sign_repeated: Vec<RobustShare<F>> = vec![sign.clone(); k - 1];
        let bit_sign_products = self
            .mul_round(
                mul_session,
                non_sign_bits.clone(),
                sign_repeated,
                prep.xor_triples,
                Arc::clone(&network),
                duration,
            )
            .await?;

        let two = F::one() + F::one();
        let mut xor_bits: Vec<RobustShare<F>> = Vec::with_capacity(k - 1);
        for (b_i, prod) in non_sign_bits.iter().zip(bit_sign_products.iter()) {
            // b_i + sign - 2*(b_i*sign)
            let sum = (b_i.clone() + sign.clone())?;
            let scaled = (prod.clone() * two)?;
            xor_bits.push((sum - scaled)?);
        }

        // ── Step 4: suffix OR locates the leading bit ────────────────────────
        let sufor_session = SessionId::new(
            ProtocolType::SufOr,
            SessionId::pack_slot(session.exec_id(), 0, 0),
            session.instance_id(),
        );
        let c = self
            .suf_or
            .init(
                xor_bits,
                prep.sufor_prep,
                sufor_session,
                Arc::clone(&network),
                duration,
                duration,
            )
            .await?;

        // ── Step 5: v, local ──────────────────────────────────────────────────
        //
        // Not the paper's printed line (`v = 1 + Σ 2^i(1-c_i)`) — that doesn't
        // reduce to the paper's own stated target `v̄ = 2^(k-m-1)` (checked by
        // hand: k=5,m=2 gives 13, not 4), most likely a typo where the exponent
        // should run `2^(k-2-i)` instead of `2^i`. Uses instead
        // `v = Σ_{i=0}^{k-2} (c_i-c_{i+1}) * 2^(k-2-i)` (c_{k-1}:=0), derived
        // from the paper's own (correct) fact that `c` is a suffix-OR, hence
        // monotone (1,1,...,1,0,...,0), switching once at index m-1→m: the
        // consecutive difference `c_i - c_{i+1}` is a one-hot vector, nonzero
        // only at that transition, so the weighted sum collapses to the single
        // surviving term `2^(k-2-(m-1)) = 2^(k-m-1)` — the paper's target,
        // reached without depending on the suspect line.
        let mut v = RobustShare::new(F::zero(), self.id, self.t);
        let m = c.len(); // = k-1
        for i in 0..m {
            let c_next = if i + 1 < m {
                c[i + 1].clone()
            } else {
                RobustShare::new(F::zero(), self.id, self.t)
            };
            let diff = (c[i].clone() - c_next)?;
            let weight = two.pow([(k - 2 - i) as u64]);
            v = (v + (diff * weight)?)?;
        }

        // ── Steps 6/7: batched round — {v*b, c_0*sign} ───────────────────────
        let mul_session = SessionId::new(
            ProtocolType::PreBitMul1,
            SessionId::pack_slot(session.exec_id(), 0, 0),
            session.instance_id(),
        );
        let batch_products = self
            .mul_round(
                mul_session,
                vec![v.clone(), c[0].clone()],
                vec![b, sign.clone()],
                prep.batch_triples,
                Arc::clone(&network),
                duration,
            )
            .await?;
        let vb = batch_products[0].clone();
        let c0_sign = batch_products[1].clone();

        // z = 1 - (c_0 OR sign) = 1 - c_0 - sign + c_0*sign
        let one = RobustShare::new(F::one(), self.id, self.t);
        let z = (((one - c[0].clone())? - sign.clone())? + c0_sign)?;

        // w' = α(1-2*sign) - 2*v*b
        let alpha_term = ((sign.clone() * (-(alpha + alpha)))? + alpha)?;
        let vb_term = (vb * (-two))?;
        let w_prime = (alpha_term + vb_term)?;

        // ── Step 8: final round — v*w', then truncate ────────────────────────
        let mul_session = SessionId::new(
            ProtocolType::PreBitMul2,
            SessionId::pack_slot(session.exec_id(), 0, 0),
            session.instance_id(),
        );
        let final_products = self
            .mul_round(
                mul_session,
                vec![v],
                vec![w_prime],
                prep.final_triple,
                Arc::clone(&network),
                duration,
            )
            .await?;
        let vw_prime = final_products[0].clone();

        let trunc_session = session;
        let k_trunc = 2 * k;
        let m_trunc = 2 * (k - f - 1);
        self.trunc
            .init(
                vw_prime,
                k_trunc,
                m_trunc,
                prep.trunc_r_bits,
                prep.trunc_r_int,
                trunc_session,
                Arc::clone(&network),
            )
            .await?;
        let trunc_result = self.trunc.wait_for_result(trunc_session, duration).await;
        if let Err(e) = self.trunc.clear_store(trunc_session).await {
            warn!("AppRec: failed to clear trunc store for session {trunc_session:?}: {e:?}");
        }
        let w = trunc_result?;

        Ok((w, z))
    }
}
