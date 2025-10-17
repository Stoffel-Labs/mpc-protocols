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
use tokio::{
    time::Duration,
    sync::{
        mpsc::{self, error::SendError, Receiver, Sender},
        Mutex,
    }
};

#[derive(Error, Debug)]
pub enum FPMulError {
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
    pub trunc_output: Arc<Mutex<Receiver<SessionId>>>,
    pub protocol_output: Option<SecretFixedPoint<F, RobustShare<F>>>,
    pub output_channel: Sender<SessionId>,
}

impl<F, R> FPMulNode<F, R>
where
    F: PrimeField,
    R: RBC,
{
    pub fn new(
        id: usize,
        n_parties: usize,
        threshold: usize,
        output_channel: Sender<SessionId>,
    ) -> Result<Self, FPMulError> {
        let (trunc_sender, trunc_receiver) = mpsc::channel(128);

        let trunc_node = TruncPrNode::new(id, n_parties, threshold, trunc_sender)?;
        let mult_node = Multiply::new(id, n_parties, threshold)?;
        Ok(Self {
            id,
            n_parties,
            threshold,
            mult_node,
            trunc_output: Arc::new(Mutex::new(trunc_receiver)),
            trunc_node,
            protocol_output: None,
            output_channel,
        })
    }

    pub async fn init<N: Network + Send + Sync + 'static>(
        &mut self,
        a: SecretFixedPoint<F, RobustShare<F>>,
        b: SecretFixedPoint<F, RobustShare<F>>,
        triple: ShamirBeaverTriple<F>,
        r_bits: Vec<RobustShare<F>>,
        r_int: RobustShare<F>,
        session_id: SessionId,
        network: Arc<N>,
    ) -> Result<(), FPMulError> {
        let p = if a.precision() == b.precision() {
            a.precision()
        } else {
            return Err(FPMulError::IncompatiblePrecision);
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

        let trunc_input = self.mult_node.wait_for_result(session_id, Duration::from_millis(500)).await?;

        self.mult_node.clear_store().await;
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

        let mut rx = self.trunc_output.lock().await;
        if let Some(id) = rx.recv().await {
            if id == session_id {
                let mut trunc_store = self.trunc_node.store.lock().await;
                let trunc_lock = trunc_store.remove(&id).unwrap();
                let store = trunc_lock.lock().await;
                self.protocol_output = Some(SecretFixedPoint::new(
                    store.share_d.clone().ok_or_else(|| {
                        FPMulError::TruncPrError(TruncPrError::NotSet(
                            "Output not set for truncation".to_string(),
                        ))
                    })?,
                    *p,
                ));
                self.output_channel.send(session_id).await?;
                return Ok(());
            }
        }
        self.trunc_node.clear_store().await;
        Err(FPMulError::Failed)
    }
}
