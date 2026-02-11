use crate::honeybadger::fpmul::ProtocolState;
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
use std::collections::HashMap;
use std::sync::Arc;
use stoffelnet::network_utils::Network;
use thiserror::Error;
use tokio::{
    sync::{
        mpsc::{self, error::SendError, Receiver, Sender},
        Mutex,
    },
    time::Duration,
};

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
    pub storage: Arc<Mutex<HashMap<SessionId, Arc<Mutex<FPMulStorage<F>>>>>>,
    pub trunc_output: Arc<Mutex<Receiver<SessionId>>>,
    pub output_channel: Sender<SessionId>,
}

#[derive(Debug)]
pub struct FPMulStorage<F>
where
    F: PrimeField,
{
    pub protocol_state: ProtocolState,
    pub protocol_output: Option<SecretFixedPoint<F, RobustShare<F>>>,
}

impl<F> FPMulStorage<F>
where
    F: PrimeField,
{
    pub fn empty() -> Self {
        Self {
            protocol_state: ProtocolState::NotInitialized,
            protocol_output: None,
        }
    }
}

impl<F, R> FPMulNode<F, R>
where
    F: PrimeField,
    R: RBC<Id = SessionId>,
{
    pub fn new(
        id: usize,
        n_parties: usize,
        threshold: usize,
        output_channel: Sender<SessionId>,
    ) -> Result<Self, FPError> {
        let (trunc_sender, trunc_receiver) = mpsc::channel(128);

        let trunc_node = TruncPrNode::new(id, n_parties, threshold, trunc_sender)?;
        let mult_node = Multiply::new(id, n_parties, threshold)?;
        Ok(Self {
            id,
            n_parties,
            threshold,
            mult_node,
            trunc_output: Arc::new(Mutex::new(trunc_receiver)),
            storage: Arc::new(Mutex::new(HashMap::new())),
            trunc_node,
            output_channel,
        })
    }

    pub async fn get_or_create_store(&mut self, session: SessionId) -> Arc<Mutex<FPMulStorage<F>>> {
        let mut map = self.storage.lock().await;
        map.entry(session)
            .or_insert((|| Arc::new(Mutex::new(FPMulStorage::empty())))())
            .clone()
    }

    pub async fn clear_store(&self) {
        let mut store = self.storage.lock().await;
        store.clear();
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
    ) -> Result<(), FPError> {
        let p = if a.precision() == b.precision() {
            a.precision()
        } else {
            return Err(FPError::IncompatiblePrecision);
        };

        {
            let store = self.get_or_create_store(session_id).await;
            let mut store_guard = store.lock().await;
            store_guard.protocol_state = ProtocolState::Initialized;
        }

        self.mult_node
            .init(
                session_id,
                vec![a.value().clone()],
                vec![b.value().clone()],
                vec![triple],
                network.clone(),
            )
            .await?;

        let trunc_input = self
            .mult_node
            .wait_for_result(session_id, Duration::from_millis(500))
            .await?;

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

        let fpmul_store = self.get_or_create_store(session_id).await;
        let mut fpmul_store_guard = fpmul_store.lock().await;
        let mut rx = self.trunc_output.lock().await;
        if let Some(id) = rx.recv().await {
            if id == session_id {
                let mut trunc_store = self.trunc_node.store.lock().await;
                let trunc_lock = trunc_store.remove(&id).unwrap();
                let store = trunc_lock.lock().await;
                fpmul_store_guard.protocol_output = Some(SecretFixedPoint::new(
                    store.share_d.clone().ok_or_else(|| {
                        FPError::TruncPrError(TruncPrError::NotSet(
                            "Output not set for truncation".to_string(),
                        ))
                    })?,
                ));
                self.output_channel.send(session_id).await?;
                fpmul_store_guard.protocol_state = ProtocolState::Finished;
                return Ok(());
            }
        }
        self.trunc_node.clear_store().await;
        Err(FPError::Failed)
    }
}
