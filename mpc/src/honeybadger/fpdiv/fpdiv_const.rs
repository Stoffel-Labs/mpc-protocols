use crate::common::types::fixed::ClearFixedPoint;
use crate::common::types::TypeError;
use crate::honeybadger::fpdiv::fixed_point_reciprocal_scaled;
use crate::honeybadger::{fpmul::TruncPrError, SessionId};
use crate::{
    common::{types::fixed::SecretFixedPoint, RBC},
    honeybadger::{
        fpmul::truncpr::TruncPrNode, robust_interpolate::robust_interpolate::RobustShare,
    },
};
use ark_ff::PrimeField;
use std::ops::Mul;
use std::sync::Arc;
use stoffelnet::network_utils::Network;
use thiserror::Error;
use tokio::sync::mpsc::error::SendError;
use tokio::time::Duration;

#[derive(Error, Debug)]
pub enum FPDivConstError {
    #[error("Incompatible precision")]
    IncompatiblePrecision,
    #[error("Truncation error: {0:?}")]
    TruncPrError(#[from] TruncPrError),
    #[error("Division failed")]
    Failed,
    #[error("Invalid divisor")]
    InvalidDivisor,
    #[error("Send error: {0:?}")]
    SendError(#[from] SendError<SessionId>),
    #[error("Type error: {0:?}")]
    TypeError(#[from] TypeError),
}

#[derive(Clone, Debug)]
pub struct FPDivConstNode<F, R>
where
    F: PrimeField,
    R: RBC,
{
    pub id: usize,
    pub n_parties: usize,
    pub threshold: usize,
    pub trunc_node: TruncPrNode<F, R>,
}

impl<F, R> FPDivConstNode<F, R>
where
    F: PrimeField,
    R: RBC<Id = SessionId>,
{
    pub fn new(id: usize, n_parties: usize, threshold: usize) -> Result<Self, FPDivConstError> {
        Ok(Self {
            id,
            n_parties,
            threshold,
            trunc_node: TruncPrNode::new(id, n_parties, threshold)?,
        })
    }

    pub async fn init<N: Network + Send + Sync + 'static>(
        &mut self,
        a: SecretFixedPoint<F, RobustShare<F>>,
        denom: ClearFixedPoint<F>,
        r_bits: Vec<RobustShare<F>>,
        r_int: RobustShare<F>,
        session_id: SessionId,
        net: Arc<N>,
    ) -> Result<SecretFixedPoint<F, RobustShare<F>>, FPDivConstError> {
        // build w = int_f(1/denom)
        if denom.value().is_zero() {
            return Err(FPDivConstError::InvalidDivisor);
        }
        let f = a.precision().f();
        let recip = fixed_point_reciprocal_scaled::<F>(&denom)?;

        // [c] = [a] * w  (local multiply)
        let c_share = a.clone().mul(recip)?;
        // Truncation
        let k_twice = 2 * a.precision().k();
        self.trunc_node
            .init(
                c_share.value().clone(),
                k_twice,
                f,
                r_bits,
                r_int,
                session_id,
                net.clone(),
            )
            .await?;

        let output = self
            .trunc_node
            .wait_for_result(session_id, Duration::from_millis(500))
            .await?;
        Ok(SecretFixedPoint::new(output))
    }
}
