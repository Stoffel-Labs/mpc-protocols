use std::{error::Error, sync::Arc};

use ark_ff::FftField;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use stoffelmpc_network::Network;

use crate::{
    common::{
        rbc::rbc_store::Msg,
        MPCNode, RBC,
    },
    honeybadger::{
        batch_recon::BatchReconMsg, input::InputMessage, ran_dou_sha::{messages::RanDouShaMessage, RanDouShaNode}, share_gen::RanShaMessage
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
pub mod input;
pub mod share_gen;

#[derive(Serialize, Deserialize, Debug)]
pub enum WrappedMessage {
    RanDouSha(RanDouShaMessage),
    Rbc(Msg),
    BatchRecon(BatchReconMsg),
    Input(InputMessage),
    RanSha(RanShaMessage)
}
#[derive(Clone)]
pub struct Node<F: FftField, R: RBC> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    pub preprocessing: PreprocessingEngine<F, R>,
    //pub input: Input<F>,
    //pub operation: Operations<F>,
    //pub output: Output<F>,
}
#[derive(Clone)]
pub struct PreprocessingEngine<F: FftField, R: RBC> {
    //pub share_gen: ShareGenerator<F>,
    //pub double_share_gen: DoubleShareGenerator<F>,
    pub randousha: RanDouShaNode<F, R>,
    //pub beaver: BeaverTripleGen<F>,
}

// pub struct Operations<F: FftField> {
//     pub mul_operation: MulOperation<F>,
// }

// pub struct Input<F: FftField> {
//     pub id: usize,
// }

// pub struct Output<F: FftField> {
//     pub interpolator: RobustInterpolator<F>,
// }

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
        // Create RanDouShaNode
        let randousha = RanDouShaNode::new(id, n, t, k)?;
        let preprocessing = PreprocessingEngine { randousha };

        Ok(Self {
            id,
            n,
            t,
            preprocessing,
        })
    }
    fn id(&self) -> usize {
        self.id
    }

    async fn process<N: Network + Send + Sync + 'static>(
        &mut self,
        raw_msg: Vec<u8>,
        net: Arc<N>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let wrapped: WrappedMessage = bincode::deserialize(&raw_msg)
            .map_err(|e| format!("Failed to deserialize WrappedMessage: {e}"))?;

        match wrapped {
            WrappedMessage::Rbc(rbc_msg) => {
                self.preprocessing
                    .randousha
                    .rbc
                    .process(rbc_msg, net)
                    .await?;
            }

            WrappedMessage::BatchRecon(_) => {
                todo!()
            }
            WrappedMessage::Input(_) => {
                todo!()
            }
            WrappedMessage::RanSha(_)=>{
                todo!()
            }
            WrappedMessage::RanDouSha(rds_msg) => {
                self.preprocessing.randousha.process(rds_msg, net).await?;
            }
        }

        Ok(())
    }
}
