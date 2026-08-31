//! FXDiv — secret/secret fixed-point division (Catrina, COMM 2018, Protocol 7).
//!
//! Given secret fixed-point `[a]`, `[b]` (k-bit signed, f fractional bits),
//! computes `[c] ≈ a/b` and `[z] = (b == 0)`.
//!
//! # Algorithm
//!
//! θ ← ⌈log2(k/3.5)⌉;  α ← fld(int_{2f}(1.0)) = 2^{2f}
//! ([w], [z]) ← AppRec([b], k, f)
//! [c] ← Div2mP([a]*[w], 2k, f)
//! [d] ← α − [b]*[w]
//! for i in 1..θ-1:
//!     [c] ← Div2mP([c]*(α+[d]), 2k, 2f)
//!     [d] ← Div2mP([d]*[d], 2k, 2f)
//! [c] ← Div2mP([c]*(α+[d]), 2k, 2f)
//! return ([c], [z])
//! `α = 2^{2f}` exactly — no rounding, unlike AppRec's `2.9142` constant.

use crate::{
    common::{
        types::fixed::{FixedPointPrecision, SecretFixedPoint},
        ProtocolSessionId,
    },
    honeybadger::{
        bitwise::{
            app_rec::{AppRecError, AppRecNode},
            AppRecPrep,
        },
        fpdiv::fpdiv_theta,
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
pub enum FpDivError {
    #[error("AppRec error: {0}")]
    AppRecError(#[from] AppRecError),
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
    #[error("prep length mismatch: expected {expected} iterations, got {got}")]
    PrepLengthMismatch { expected: usize, got: usize },
}

/// One refinement-loop iteration's preprocessing (steps 6-7 of Protocol 7 —
/// one plain Goldschmidt step). Step 8 runs once, after the loop, and its
/// preprocessing lives on `FpDivPrep` directly, not here.
#[derive(Clone, Debug)]
pub struct FpDivIterPrep<F: FftField> {
    /// 2 triples for Round A: `c*(α+d)` (step 6) and `d*d` (step 7).
    pub round_a_triples: Vec<ShamirBeaverTriple<F>>,
    /// Step 6's TruncPr randomness (m = 2f).
    pub step6_trunc_r_bits: Vec<RobustShare<F>>,
    pub step6_trunc_r_int: RobustShare<F>,
    /// Step 7's TruncPr randomness (m = 2f).
    pub step7_trunc_r_bits: Vec<RobustShare<F>>,
    pub step7_trunc_r_int: RobustShare<F>,
}

/// All preprocessing material required for one FXDiv execution.
#[derive(Clone, Debug)]
pub struct FpDivPrep<F: FftField> {
    /// AppRec's own preprocessing (step 2).
    pub app_rec_prep: AppRecPrep<F>,
    /// 2 triples for the step-3/4 batch: `a*w`, `b*w`.
    pub step3_4_triples: Vec<ShamirBeaverTriple<F>>,
    /// Step 3's TruncPr randomness (m = f).
    pub step3_trunc_r_bits: Vec<RobustShare<F>>,
    pub step3_trunc_r_int: RobustShare<F>,
    /// One entry per loop iteration; length must equal
    /// `fpdiv_theta(k).saturating_sub(1)`.
    pub iters: Vec<FpDivIterPrep<F>>,
    /// 1 triple for the final, one-shot Round B: `c*(α+d)` (step 8), run
    /// once after the refinement loop — not per iteration.
    pub round_b_triple: Vec<ShamirBeaverTriple<F>>,
    /// Step 8's TruncPr randomness (m = 2f).
    pub step8_trunc_r_bits: Vec<RobustShare<F>>,
    pub step8_trunc_r_int: RobustShare<F>,
}

#[derive(Clone, Debug)]
pub struct FpDivNode<F: PrimeField + FftField> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    pub app_rec: AppRecNode<F>,
    pub mul: Multiply<F>,
    pub trunc: TruncPrNode<F>,
}

impl<F: PrimeField + FftField> FpDivNode<F> {
    pub fn new(id: usize, n: usize, t: usize) -> Result<Self, FpDivError> {
        Ok(Self {
            id,
            n,
            t,
            app_rec: AppRecNode::new(id, n, t)?,
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
    ) -> Result<Vec<RobustShare<F>>, FpDivError> {
        self.mul
            .init(session, x, y, triples, Arc::clone(&network))
            .await?;
        let result = self.mul.wait_for_result(session, duration).await;
        if let Err(e) = self.mul.clear_store(session).await {
            warn!("FpDiv: failed to clear mul store for session {session:?}: {e:?}");
        }
        Ok(result?)
    }

    /// Runs one TruncPr call to completion and clears its store,
    async fn trunc_round<N: Network + Send + Sync + 'static>(
        &mut self,
        session: SessionId,
        x: RobustShare<F>,
        k: usize,
        m: usize,
        r_bits: Vec<RobustShare<F>>,
        r_int: RobustShare<F>,
        network: Arc<N>,
        duration: Duration,
    ) -> Result<RobustShare<F>, FpDivError> {
        self.trunc
            .init(x, k, m, r_bits, r_int, session, Arc::clone(&network))
            .await?;
        let result = self.trunc.wait_for_result(session, duration).await;
        if let Err(e) = self.trunc.clear_store(session).await {
            warn!("FpDiv: failed to clear trunc store for session {session:?}: {e:?}");
        }
        Ok(result?)
    }

    /// Protocol 7 (FXDiv). Returns `([c], [z])` where `c ≈ a/b` and
    /// `z = (b == 0) ? 1 : 0`.
    pub async fn init<N: Network + Send + Sync + 'static>(
        &mut self,
        a: RobustShare<F>,
        b: RobustShare<F>,
        k: usize,
        f: usize,
        prep: FpDivPrep<F>,
        session: SessionId,
        network: Arc<N>,
        duration: Duration,
    ) -> Result<(SecretFixedPoint<F, RobustShare<F>>, RobustShare<F>), FpDivError> {
        if session.calling_protocol() != Some(ProtocolType::FpDiv) {
            return Err(FpDivError::SessionIdError(session));
        }

        let theta = fpdiv_theta(k);
        let expected_iters = theta.saturating_sub(1);
        if prep.iters.len() != expected_iters {
            return Err(FpDivError::PrepLengthMismatch {
                expected: expected_iters,
                got: prep.iters.len(),
            });
        }

        let two = F::one() + F::one();
        let alpha = two.pow([2 * f as u64]);

        // ── Step 2: (w, z) ← AppRec(b, k, f) ─────────────────────────────
        let (w, z) = self
            .app_rec
            .init(
                b.clone(),
                k,
                f,
                prep.app_rec_prep,
                session,
                Arc::clone(&network),
                duration,
            )
            .await?;

        // ── Steps 3/4: batched a*w, b*w ───────────────────────────────────
        let base_mul_a_session = SessionId::new(
            ProtocolType::FpDivMulA,
            SessionId::pack_slot(session.exec_id(), 0, 0),
            session.instance_id(),
        );
        let mul_a_session_for = |call_index: u8| base_mul_a_session.with_extra_bits(call_index);

        let step3_4_products = self
            .mul_round(
                mul_a_session_for(0),
                vec![a, b],
                vec![w.clone(), w],
                prep.step3_4_triples,
                Arc::clone(&network),
                duration,
            )
            .await?;
        let aw = step3_4_products[0].clone();
        let bw = step3_4_products[1].clone();

        let mut trunc_round_id: u8 = 0;
        let trunc_session = |exec_id: u64, instance_id: u32, round: u8| {
            SessionId::new(
                ProtocolType::FpDivTrunc,
                SessionId::pack_slot(exec_id, 0, round),
                instance_id,
            )
        };

        let mut c = self
            .trunc_round(
                trunc_session(session.exec_id(), session.instance_id(), trunc_round_id),
                aw,
                2 * k,
                f,
                prep.step3_trunc_r_bits,
                prep.step3_trunc_r_int,
                Arc::clone(&network),
                duration,
            )
            .await?;
        trunc_round_id += 1;

        // d = α - b*w
        let neg_bw = (bw * (-F::one()))?;
        let mut d = (neg_bw + alpha)?;

        // ── Steps 5-7: θ-1 refinement iterations, one plain Goldschmidt
        // step each: c_n = c_{n-1}(1+d_{n-1}), d_n = d_{n-1}^2 ────────────
        let mul_b_session = SessionId::new(
            ProtocolType::FpDivMulB,
            SessionId::pack_slot(session.exec_id(), 0, 0),
            session.instance_id(),
        );

        for (iter_index, iter_prep) in prep.iters.into_iter().enumerate() {
            let call_index = u8::try_from(iter_index + 1).map_err(|_| {
                FpDivError::InvalidInput(format!(
                    "k={k} needs too many refinement iterations ({iter_index_plus_1}) for the \
                     mul_a_session_for per-call extra_bits encoding (max 255)",
                    iter_index_plus_1 = iter_index + 1
                ))
            })?;
            let alpha_plus_d = (d.clone() + alpha)?;
            let round_a_products = self
                .mul_round(
                    mul_a_session_for(call_index),
                    vec![c.clone(), d.clone()],
                    vec![alpha_plus_d, d.clone()],
                    iter_prep.round_a_triples,
                    Arc::clone(&network),
                    duration,
                )
                .await?;
            let c_prod = round_a_products[0].clone();
            let d_prod = round_a_products[1].clone();

            c = self
                .trunc_round(
                    trunc_session(session.exec_id(), session.instance_id(), trunc_round_id),
                    c_prod,
                    2 * k,
                    2 * f,
                    iter_prep.step6_trunc_r_bits,
                    iter_prep.step6_trunc_r_int,
                    Arc::clone(&network),
                    duration,
                )
                .await?;
            trunc_round_id += 1;

            d = self
                .trunc_round(
                    trunc_session(session.exec_id(), session.instance_id(), trunc_round_id),
                    d_prod,
                    2 * k,
                    2 * f,
                    iter_prep.step7_trunc_r_bits,
                    iter_prep.step7_trunc_r_int,
                    Arc::clone(&network),
                    duration,
                )
                .await?;
            trunc_round_id += 1;
        }

        // ── Step 8: one final half-step, run ONCE
        let alpha_plus_d = (d + alpha)?;
        let round_b_products = self
            .mul_round(
                mul_b_session,
                vec![c],
                vec![alpha_plus_d],
                prep.round_b_triple,
                Arc::clone(&network),
                duration,
            )
            .await?;
        let c8_prod = round_b_products[0].clone();

        let c = self
            .trunc_round(
                trunc_session(session.exec_id(), session.instance_id(), trunc_round_id),
                c8_prod,
                2 * k,
                2 * f,
                prep.step8_trunc_r_bits,
                prep.step8_trunc_r_int,
                Arc::clone(&network),
                duration,
            )
            .await?;

        Ok((
            SecretFixedPoint::new_with_precision(c, FixedPointPrecision::new(k, f)),
            z,
        ))
    }
}
