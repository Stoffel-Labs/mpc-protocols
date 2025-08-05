use std::{error::Error, sync::Arc};

use ark_ff::FftField;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use stoffelmpc_network::Network;
use tracing::warn;

use crate::{
    common::{rbc::rbc_store::Msg, MPCNode, RBC},
    honeybadger::{
        batch_recon::BatchReconMsg,
        input::{input::InputServer, InputMessage},
        ran_dou_sha::{messages::RanDouShaMessage, RanDouShaNode},
        share_gen::{share_gen::RanShaNode, RanShaMessage},
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

pub mod input;
/// This module contains the implementation of the Batch Reconstruction protocol presented in
/// Figure 3 in the paper "HoneyBadgerMPC and AsynchroMix: Practical AsynchronousMPC and its
/// Application to Anonymous Communication".
pub mod ran_dou_sha;
pub mod share_gen;

#[derive(Serialize, Deserialize, Debug)]
pub enum WrappedMessage {
    RanDouSha(RanDouShaMessage),
    Rbc(Msg),
    BatchRecon(BatchReconMsg),
    Input(InputMessage),
    RanSha(RanShaMessage),
}
#[derive(Clone)]
pub struct Node<F: FftField, R: RBC> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    pub preprocessing: PreprocessingEngine<F, R>,
    //pub operation: Operations<F>,
    //pub output: Output<F>,
}
#[derive(Clone)]
pub struct PreprocessingEngine<F: FftField, R: RBC> {
    pub share_gen: RanShaNode<F, R>,
    //pub double_share_gen: DoubleShareGenerator<F>,
    pub randousha: RanDouShaNode<F, R>,
    //pub beaver: BeaverTripleGen<F>,
    pub input: InputServer<F, R>,
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
        let share_gen = RanShaNode::new(id, n, t, k)?;
        let input = InputServer::new(id, n, t)?;
        let preprocessing = PreprocessingEngine {
            share_gen,
            randousha,
            input,
        };

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
            WrappedMessage::Rbc(rbc_msg) => match rbc_msg.session_id.protocol() {
                Some(ProtocolType::Randousha) => {
                    self.preprocessing
                        .randousha
                        .rbc
                        .process(rbc_msg, net)
                        .await?
                }
                Some(ProtocolType::Ransha) => {
                    self.preprocessing
                        .share_gen
                        .rbc
                        .process(rbc_msg, net)
                        .await?
                }
                Some(ProtocolType::Input) => {
                    self.preprocessing.input.rbc.process(rbc_msg, net).await?
                }
                Some(ProtocolType::Rbc) => {
                    todo!()
                }
                None => {
                    warn!(
                        "Unknown protocol ID in session ID: {:?}",
                        rbc_msg.session_id
                    );
                }
            },

            WrappedMessage::BatchRecon(_) => {
                todo!()
            }
            WrappedMessage::Input(input) => {
                self.preprocessing.input.process(input).await?;
            }
            WrappedMessage::RanSha(rs_msg) => {
                self.preprocessing.share_gen.process(rs_msg, net).await?;
            }
            WrappedMessage::RanDouSha(rds_msg) => {
                self.preprocessing.randousha.process(rds_msg, net).await?;
            }
        }

        Ok(())
    }
}

///-----------------Session-ID-----------------
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolType {
    Randousha = 1,
    Ransha = 2,
    Input = 3,
    Rbc = 4,
}

impl TryFrom<u16> for ProtocolType {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(ProtocolType::Randousha),
            2 => Ok(ProtocolType::Ransha),
            3 => Ok(ProtocolType::Input),
            4 => Ok(ProtocolType::Rbc),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(u64);

impl SessionId {
    pub fn new(protocol: ProtocolType, context_id: u64) -> Self {
        // upper 16 bits = protocol, lower 48 bits = context id
        let value = ((protocol as u64) << 48) | (context_id & 0x0000_FFFF_FFFF_FFFF);
        SessionId(value)
    }

    pub fn protocol(self) -> Option<ProtocolType> {
        let proto = ((self.0 >> 48) & 0xFFFF) as u16;
        ProtocolType::try_from(proto).ok()
    }

    pub fn context_id(self) -> u64 {
        self.0 & 0x0000_FFFF_FFFF_FFFF
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }
}
