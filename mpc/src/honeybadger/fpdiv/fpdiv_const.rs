use crate::common::types::fixed::ClearFixedPoint;
use crate::common::types::TypeError;
use crate::honeybadger::fpdiv::fixed_point_reciprocal_scaled;
use crate::honeybadger::{fpmul::TruncPrError, mul::MulError, SessionId};
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
use tokio::sync::{
    mpsc::{self, Receiver, Sender},
    Mutex,
};

#[derive(Error, Debug)]
pub enum FPDivConstError {
    #[error("Multiplication error: {0:?}")]
    MulError(#[from] MulError),
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
    pub trunc_output: Arc<Mutex<Receiver<SessionId>>>,
    pub protocol_output: Option<SecretFixedPoint<F, RobustShare<F>>>,
    pub output_channel: Sender<SessionId>,
}

impl<F, R> FPDivConstNode<F, R>
where
    F: PrimeField,
    R: RBC,
{
    pub fn new(
        id: usize,
        n_parties: usize,
        threshold: usize,
        output_channel: Sender<SessionId>,
    ) -> Result<Self, FPDivConstError> {
        let (trunc_sender, trunc_receiver) = mpsc::channel(128);
        Ok(Self {
            id,
            n_parties,
            threshold,
            trunc_node: TruncPrNode::new(id, n_parties, threshold, trunc_sender)?,
            trunc_output: Arc::new(Mutex::new(trunc_receiver)),
            protocol_output: None,
            output_channel,
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
    ) -> Result<(), FPDivConstError> {
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

        let mut rx = self.trunc_output.lock().await;
        while let Some(id) = rx.recv().await {
            if id == session_id {
                let mut trunc_store = self.trunc_node.store.lock().await;
                let trunc_lock = trunc_store.remove(&id).unwrap();
                let store = trunc_lock.lock().await;
                self.protocol_output = Some(SecretFixedPoint::new(
                    store.share_d.clone().ok_or(FPDivConstError::Failed)?,
                ));
                self.output_channel.send(session_id).await?;
                return Ok(());
            }
        }
        Err(FPDivConstError::Failed)
    }
}
