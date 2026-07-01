use crate::{
    common::{types::fixed::SecretFixedPoint, RBC},
    honeybadger::{
        fpmul::{truncpr::TruncPrNode, TruncPrError},
        mul::{multiplication::Multiply, MulError},
        robust_interpolate::robust_interpolate::RobustShare,
        triple_gen::ShamirBeaverTriple,
        SessionId,
    },
};
use ark_ff::PrimeField;
use std::sync::Arc;
use stoffelnet::network_utils::Network;
use thiserror::Error;
use tokio::{sync::mpsc::error::SendError, time::Duration};
use tracing::warn;

#[derive(Error, Debug)]
pub enum FPError {
    #[error("error in the secure multiplication protocol: {0:?}")]
    MulError(#[from] MulError),
    #[error("error in the truncation protocol: {0:?}")]
    TruncPrError(#[from] TruncPrError),
    #[error("FpMul failed")]
    Failed,
    #[error("Incompatible precision")]
    IncompatiblePrecision,
    #[error("error sending the thread asynchronously")]
    SendError(#[from] SendError<SessionId>),
}

#[derive(Clone, Debug)]
pub struct FPMulNode<F, R>
where
    F: PrimeField,
    R: RBC,
{
    pub id: usize,
    pub n_parties: usize,
    pub threshold: usize,
    pub mult_node: Multiply<F, R>,
    pub trunc_node: TruncPrNode<F, R>,
}

impl<F, R> FPMulNode<F, R>
where
    F: PrimeField,
    R: RBC<Id = SessionId>,
{
    pub fn new(id: usize, n_parties: usize, threshold: usize) -> Result<Self, FPError> {
        let trunc_node = TruncPrNode::new(id, n_parties, threshold)?;
        let mult_node = Multiply::new(id, n_parties, threshold)?;
        Ok(Self {
            id,
            n_parties,
            threshold,
            mult_node,
            trunc_node,
        })
    }

    pub async fn init<N: Network + Send + Sync + 'static>(
        &mut self,
        a: SecretFixedPoint<F, RobustShare<F>>,
        b: SecretFixedPoint<F, RobustShare<F>>,
        triple: ShamirBeaverTriple<F>,
        r_bits: Vec<RobustShare<F>>,
        r_int: RobustShare<F>,
        duration: Duration,
        session_id: SessionId,
        network: Arc<N>,
    ) -> Result<SecretFixedPoint<F, RobustShare<F>>, FPError> {
        let p = if a.precision() == b.precision() {
            a.precision()
        } else {
            return Err(FPError::IncompatiblePrecision);
        };

        self.mult_node
            .init(
                session_id,
                vec![a.value().clone()],
                vec![b.value().clone()],
                vec![triple],
                network.clone(),
            )
            .await?;

        let trunc_input = self.mult_node.wait_for_result(session_id, duration).await?;

        if !self.mult_node.clear_store(session_id).await {
            warn!(?session_id, "failed to clear completed FPMul multiplication state");
        }
        self.trunc_node
            .init(
                trunc_input[0].clone(),
                2 * p.k(),
                p.f(),
                r_bits,
                r_int,
                session_id,
                network,
            )
            .await?;

        let trunc_output = self
            .trunc_node
            .wait_for_result(session_id, duration)
            .await?;

        if !self.trunc_node.clear_store(session_id).await {
            warn!(?session_id, "failed to clear completed FPMul truncation state");
        }
        Ok(SecretFixedPoint::new(trunc_output))
    }
}
