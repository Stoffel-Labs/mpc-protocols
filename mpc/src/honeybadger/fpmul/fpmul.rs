use crate::{
    common::RBC,
    honeybadger::{
        fpmul::{truncpr::TruncPrNode, TruncPrError},
        mul::{multiplication::Multiply, MulError},
        robust_interpolate::robust_interpolate::RobustShare,
        triple_gen::ShamirBeaverTriple,
        ProtocolType, SessionId,
    },
};
use ark_ff::PrimeField;
use std::sync::Arc;
use stoffelnet::network_utils::Network;
use thiserror::Error;
use tokio::sync::{
    mpsc::{self, Receiver},
    Mutex,
};

#[derive(Error, Debug)]
pub enum FPMulError {
    #[error("error in the secure multiplication protocol: {0:?}")]
    MulError(#[from] MulError),
    #[error("error in the truncation protocol: {0:?}")]
    TruncPrError(#[from] TruncPrError),
    #[error("FpMul failed")]
    Failed,
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
    pub mult_output: Arc<Mutex<Receiver<SessionId>>>,
    pub trunc_node: TruncPrNode<F>,
    pub trunc_output: Arc<Mutex<Receiver<SessionId>>>,
}

impl<F, R> FPMulNode<F, R>
where
    F: PrimeField,
    R: RBC,
{
    pub fn new(id: usize, n_parties: usize, threshold: usize) -> Result<Self, FPMulError> {
        let (mul_sender, mul_receiver) = mpsc::channel(128);
        let (trunc_sender, trunc_receiver) = mpsc::channel(128);

        let trunc_node = TruncPrNode::new(id, n_parties, threshold, trunc_sender);
        let mult_node = Multiply::new(id, n_parties, threshold, mul_sender)?;
        Ok(Self {
            id,
            n_parties,
            threshold,
            mult_node,
            mult_output: Arc::new(Mutex::new(mul_receiver)),
            trunc_output: Arc::new(Mutex::new(trunc_receiver)),
            trunc_node,
        })
    }

    pub async fn init<N: Network + Send + Sync + 'static>(
        &mut self,
        a: RobustShare<F>,
        b: RobustShare<F>,
        triple: Vec<ShamirBeaverTriple<F>>,
        k: usize,
        m: usize,
        session_id: SessionId,
        network: Arc<N>,
    ) -> Result<F, FPMulError> {
        let session_id_mult = SessionId::new(ProtocolType::Mul, 0, 0, session_id.instance_id());

        self.mult_node
            .init(session_id_mult, vec![a], vec![b], triple, network.clone())
            .await?;

        let mut trunc_input = Vec::new();
        let mut rx = self.mult_output.lock().await;
        while let Some(id) = rx.recv().await {
            if id == session_id_mult {
                let mul_store = self.mult_node.mult_storage.lock().await;
                if let Some(mul_lock) = mul_store.get(&id) {
                    let store = mul_lock.lock().await;
                    trunc_input = store.protocol_output.clone();
                }
            }
        }

        let session_id_trunc = SessionId::new(ProtocolType::None, 0, 0, session_id.instance_id());
        self.trunc_node
            .init(trunc_input[0].share[0], k, m, session_id_trunc, network)
            .await?;

        let mut rx = self.trunc_output.lock().await;
        while let Some(id) = rx.recv().await {
            if id == session_id_trunc {
                let trunc_store = self.trunc_node.store.lock().await;
                if let Some(trunc_lock) = trunc_store.get(&id) {
                    let store = trunc_lock.lock().await;
                    return Ok(store.share_d.unwrap());
                }
            }
        }
        Err(FPMulError::Failed)
    }
}
