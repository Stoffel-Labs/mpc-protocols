use std::sync::Arc;

use ark_ff::FftField;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use stoffelmpc_network::Network;

use crate::{
    common::{rbc::{rbc::ACS, rbc_store::Msg}, MPCNode, RBC},
    honeybadger::{
        batch_recon::{batch_recon::BatchReconNode, BatchReconMsg},
        ran_dou_sha::{messages::RanDouShaMessage, RanDouShaNode},
    },
};

/// This module contains the implementation of the Robust interpolate protocol presented in
/// Figure 1 in the paper "HoneyBadgerMPC and AsynchroMix: Practical AsynchronousMPC and its
/// Application to Anonymous Communication".
pub mod robust_interpolate;

/// This module contains the implementation of the Batch Reconstruction protocol presented in
/// Figure 2 in the paper "HoneyBadgerMPC and AsynchroMix: Practical AsynchronousMPC and its
/// Application to Anonymous Communication".
pub mod batch_recon;

/// This module contains the implementation of the Batch Reconstruction protocol presented in
/// Figure 3 in the paper "HoneyBadgerMPC and AsynchroMix: Practical AsynchronousMPC and its
/// Application to Anonymous Communication".
pub mod ran_dou_sha;

#[derive(Serialize, Deserialize, Debug)]
pub enum WrappedMessage {
    RanDouSha(RanDouShaMessage),
    Rbc(Msg),
    BatchRecon(BatchReconMsg),
}

pub struct Node<F: FftField, R: RBC> {
    pub id: usize,
    pub rbc: R,
    pub acs : ACS,
    pub batch_recon: BatchReconNode<F>,
    pub randousha: RanDouShaNode<F, R>,
}
#[async_trait]
impl<F, R> MPCNode<F, R> for Node<F, R>
where
    F: FftField + 'static,
    R: RBC,
{
    fn new(
        id: usize,
        n: usize,
        t: usize,
        k: usize, // used by RBC
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Create RBC instance
        let rbc = R::new(id as u32, n as u32, t as u32, k as u32)?;
        //Create ACS instance
        let acs = ACS::new(id as u32, n as u32, t as u32, k as u32)?;
        // Create BatchReconNode
        let batch_recon = BatchReconNode::new(id, n, t)?;
        // Create RanDouShaNode
        let randousha = RanDouShaNode::new(id, n, t, k)?;

        Ok(Self {
            id,
            rbc,
            acs,
            batch_recon,
            randousha,
        })
    }
    fn id(&self) -> usize {
        self.id
    }

    async fn process<N: Network + Send + Sync + 'static>(
        &mut self,
        raw_msg: Vec<u8>,
        net: Arc<N>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let wrapped: WrappedMessage = bincode::deserialize(&raw_msg)
            .map_err(|e| format!("Failed to deserialize WrappedMessage: {e}"))?;

        match wrapped {
            WrappedMessage::Rbc(rbc_msg) => {
                self.rbc.process(rbc_msg, net).await?;
            }

            WrappedMessage::BatchRecon(batch_msg) => {
                self.batch_recon.process(batch_msg, net).await?;
            }

            WrappedMessage::RanDouSha(rds_msg) => {
                self.randousha.process(rds_msg, net).await?;
            }
        }

        Ok(())
    }
}
