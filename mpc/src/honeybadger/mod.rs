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

/// Implementation for the protocol of double share generation.
pub mod double_share;

/// Implements a Beaver triple generation protocol for the HoneyBadgerMPC protocol.
pub mod triple_gen;

pub mod fpdiv;
pub mod fpmul;
pub mod input;
pub mod mul;
pub mod output;
pub mod preprocessing;
pub mod share_gen;

use crate::{
    common::{
        rbc::{rbc_store::Msg, RbcError},
        types::{
            fixed::{ClearFixedPoint, SecretFixedPoint},
            integer::{ClearInt, SecretInt},
            TypeError,
        },
        MPCProtocol, MPCTypeOps, PreprocessingMPCProtocol, ShamirShare, RBC,
    },
    honeybadger::{
        batch_recon::{BatchReconError, BatchReconMsg},
        double_share::{double_share_generation, DouShaError, DouShaMessage, DoubleShamirShare},
        fpdiv::fpdiv_const::{FPDivConstError, FPDivConstNode},
        fpmul::{
            f256::F2_8,
            fpmul::{FPError, FPMulNode},
            prandbitd::PRandBitNode,
            rand_bit::RandBit,
            PRandBitDMessage, PRandError, RandBitError, RandBitMessage, TruncPrError,
            TruncPrMessage,
        },
        input::{
            input::{InputClient, InputServer},
            InputError, InputMessage,
        },
        mul::{multiplication::Multiply, MulError, MultMessage},
        output::{
            output::{OutputClient, OutputServer},
            OutputError, OutputMessage,
        },
        preprocessing::HoneyBadgerMPCNodePreprocMaterial,
        ran_dou_sha::messages::RanDouShaMessage,
        robust_interpolate::robust_interpolate::Robust,
        share_gen::{
            batched_share_gen::BatchedRanShaNode, share_gen::RanShaNode, RanShaError,
            RanShaMessage, RanShaPayload,
        },
        triple_gen::{ShamirBeaverTriple, TripleGenError, TripleGenMessage},
    },
};
use ark_ff::{FftField, PrimeField};
use ark_std::rand::rngs::{OsRng, StdRng};
use ark_std::rand::{Rng, SeedableRng};
use async_trait::async_trait;
use bincode::ErrorKind;
use double_share_generation::DoubleShareNode;
use ran_dou_sha::{RanDouShaError, RanDouShaNode, batched_ran_dou_sha::BatchedRanDouShaNode};
use robust_interpolate::robust_interpolate::RobustShare;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt, sync::{Arc, atomic::{Ordering, AtomicU8}}};
use stoffelnet::network_utils::{Network, NetworkError, ClientId, PartyId};
use thiserror::Error;
use tokio::{
    sync::{
        mpsc::{self, Receiver},
        Mutex,
    },
    time::Duration
};
use futures::future::try_join_all;
use tracing::{info, warn};
use triple_gen::triple_generation::TripleGenNode;

#[derive(Error, Debug)]
pub enum HoneyBadgerError {
    #[error("network error: {0:?}")]
    NetworkError(#[from] NetworkError),
    #[error("error in share generation: {0:?}")]
    RanShaError(#[from] RanShaError),
    #[error("error in Input share generation: {0:?}")]
    InputError(#[from] InputError),
    #[error("error in faulty double share generation: {0:?}")]
    DouShaError(#[from] DouShaError),
    #[error("error in random double share generation: {0:?}")]
    RanDouShaError(#[from] RanDouShaError),
    #[error("there is not enough preprocessing to complete the protocol")]
    NotEnoughPreprocessing,
    #[error("error in triple generation protocol: {0:?}")]
    TripleGenError(#[from] TripleGenError),
    #[error("error in the RBC: {0:?}")]
    RbcError(#[from] RbcError),
    #[error("error in the Mul: {0:?}")]
    MulError(#[from] MulError),
    #[error("error in the Output server: {0:?}")]
    OutputError(#[from] OutputError),
    #[error("error in the Batch Reconstruction: {0:?}")]
    BatchReconError(#[from] BatchReconError),
    #[error("error in random bit generation: {0:?}")]
    RandBitError(#[from] RandBitError),
    #[error("error in Prand bit generation: {0:?}")]
    PRandError(#[from] PRandError),
    #[error("error in FPMul: {0:?}")]
    FPError(#[from] FPError),
    #[error("error in FPDiv_Const: {0:?}")]
    FPDivConstError(#[from] FPDivConstError),
    #[error("error in Truncation: {0:?}")]
    TruncPrError(#[from] TruncPrError),
    #[error("error in types: {0:?}")]
    TypeError(#[from] TypeError),
    #[error("Already reserved batch")]
    AlreadyReserved,
    /// Error during the serialization using [`bincode`].
    #[error("error during the serialization using bincode: {0:?}")]
    BincodeSerializationError(#[from] Box<ErrorKind>),
    #[error("failed to join spawned task")]
    JoinError,
    #[error("output channel closed before result was received")]
    ChannelClosed,
}

pub struct HoneyBadgerMPCClient<F: FftField, R: RBC> {
    pub id: usize,
    pub input: InputClient<F, R>,
    pub output: OutputClient<F>,
}

// implement manually because derive(Clone) requires R: Clone, which is not needed at all
impl<F, R> Clone for HoneyBadgerMPCClient<F, R>
where
    F: FftField,
    R: RBC,
{
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            input: self.input.clone(),
            output: self.output.clone(),
        }
    }
}

impl<F: FftField, R: RBC> HoneyBadgerMPCClient<F, R> {
    pub fn new(
        id: usize,
        n: usize,
        t: usize,
        instance_id: u32,
        inputs: Vec<F>,
        input_len: usize,
    ) -> Result<Self, HoneyBadgerError> {
        let input = InputClient::new(id, n, t, instance_id, inputs)?;
        let output = OutputClient::new(id, n, t, input_len)?;
        Ok(Self { id, input, output })
    }
    pub async fn process<N: Network + Send + Sync>(
        &mut self,
        raw_msg: Vec<u8>,
        net: Arc<N>,
    ) -> Result<(), HoneyBadgerError> {
        let wrapped: WrappedMessage = bincode::deserialize(&raw_msg)?;

        match wrapped {
            WrappedMessage::Input(input_msg) => {
                self.input.process(input_msg, net).await?;
            }
            WrappedMessage::Output(output_msg) => self.output.process(output_msg).await?,
            _ => warn!("Incorrect message type recieved at input"),
        }
        Ok(())
    }
}
/// Information pertaining a HoneyBadgerMPCNode protocol participant.
#[derive(Clone, Debug)]
pub struct HoneyBadgerMPCNode<F: PrimeField, R: RBC> {
    /// ID of the current execution node.
    pub id: PartyId,
    /// Preprocessing material used in the protocol execution.
    pub preprocessing_material: Arc<Mutex<HoneyBadgerMPCNodePreprocMaterial<F>>>,
    // Preprocessing parameters.
    pub params: HoneyBadgerMPCNodeOpts,
    pub preprocess: PreprocessNodes<F, R>,
    pub operations: Operation<F, R>,
    pub type_ops: TypeOperations<F, R>,
    pub output: OutputServer,
    pub outputchannels: OutputChannels,
    pub counters: SubProtocolCounters
}

#[derive(Clone, Debug)]
pub struct Operation<F: FftField, R: RBC> {
    pub mul: Multiply<F, R>,
}

#[derive(Clone, Debug)]
pub struct TypeOperations<F: PrimeField, R: RBC> {
    pub fpmul: FPMulNode<F, R>,
    pub fpdiv_const: FPDivConstNode<F, R>,
}

#[derive(Clone, Debug)]
pub struct PreprocessNodes<F: PrimeField, R: RBC> {
    // Nodes for subprotocols.
    pub input: InputServer<F, R>,
    pub share_gen: RanShaNode<F, R>,
    pub batched_share_gen: BatchedRanShaNode<F, R>,
    pub dou_sha: DoubleShareNode<F>,
    pub ran_dou_sha: RanDouShaNode<F, R>,
    pub batched_ran_dou_sha: BatchedRanDouShaNode<F, R>,
    pub triple_gen: TripleGenNode<F>,
    pub rand_bit: RandBit<F, R>,
    pub prand_bit: PRandBitNode<F, F>,
}

#[derive(Clone, Debug)]
pub struct OutputChannels {
    pub share_gen_channel: Arc<Mutex<Receiver<SessionId>>>,
    pub batched_share_gen_channel: Arc<Mutex<Receiver<SessionId>>>,
    pub dou_sha_channel: Arc<Mutex<Receiver<SessionId>>>,
    pub ran_dou_sha_channel: Arc<Mutex<Receiver<SessionId>>>,
    pub batched_ran_dou_sha_channel: Arc<Mutex<Receiver<SessionId>>>,
    pub triple_channel: Arc<Mutex<Receiver<SessionId>>>,
    pub rand_bit_channel: Arc<Mutex<Receiver<SessionId>>>,
    pub prand_bit_channel: Arc<Mutex<Receiver<SessionId>>>,
    pub prand_int_channel: Arc<Mutex<Receiver<SessionId>>>,
    pub fpmul_channel: Arc<Mutex<Receiver<SessionId>>>,
    pub fpdiv_const_channel: Arc<Mutex<Receiver<SessionId>>>,
}

#[derive(Clone, Debug)]
pub struct SubProtocolCounter(Arc<AtomicU8>);

trait GetNext<T> {
    fn get_next(&self) -> T;
}

impl GetNext<u8> for SubProtocolCounter {
    fn get_next(&self) -> u8 {
        self.0.fetch_add(1, Ordering::SeqCst)
    }
}

/// Per sub-protocol there is a counter to increment the exec ID within the
/// session ID and distinguish different executions of the same sub-protocol.
/// Since the exec ID is a `u8`, the counter is an `AtomicU8`.
#[derive(Clone, Debug)]
pub struct SubProtocolCounters {
    pub ran_dou_sha_counter: SubProtocolCounter,
    pub ran_sha_counter: SubProtocolCounter,
    pub triple_counter: SubProtocolCounter,
    pub batch_recon_counter: SubProtocolCounter,
    pub dou_sha_counter: SubProtocolCounter,
    pub mul_counter: SubProtocolCounter,
    pub rand_bit_counter: SubProtocolCounter,
    pub prand_bit_counter: SubProtocolCounter,
    pub prand_int_counter: SubProtocolCounter,
    pub fpmul_counter: SubProtocolCounter,
    pub fpdiv_const_counter: SubProtocolCounter,
}

impl SubProtocolCounters {
    pub fn new() -> Self {
        Self {
            ran_dou_sha_counter: SubProtocolCounter(Arc::new(AtomicU8::new(0))),
            ran_sha_counter: SubProtocolCounter(Arc::new(AtomicU8::new(0))),
            triple_counter: SubProtocolCounter(Arc::new(AtomicU8::new(0))),
            batch_recon_counter: SubProtocolCounter(Arc::new(AtomicU8::new(0))),
            dou_sha_counter: SubProtocolCounter(Arc::new(AtomicU8::new(0))),
            mul_counter: SubProtocolCounter(Arc::new(AtomicU8::new(0))),
            rand_bit_counter: SubProtocolCounter(Arc::new(AtomicU8::new(0))),
            prand_bit_counter: SubProtocolCounter(Arc::new(AtomicU8::new(0))),
            prand_int_counter: SubProtocolCounter(Arc::new(AtomicU8::new(0))),
            fpmul_counter: SubProtocolCounter(Arc::new(AtomicU8::new(0))),
            fpdiv_const_counter: SubProtocolCounter(Arc::new(AtomicU8::new(0)))
        }
    }
}

#[derive(Clone, Debug)]
/// Configuration options for the HoneyBadgerMPCNode protocol.
pub struct HoneyBadgerMPCNodeOpts {
    /// Number of parties in the protocol.
    /// Minimum 5 for hbmpc
    pub n_parties: usize,
    /// Upper bound of corrupt parties.
    pub threshold: usize,
    /// Number of random double sharing pairs that need to be generated.
    pub n_triples: usize,
    /// Number of random shares needed.
    /// This is usually = No of inputs + 2 * no of triples
    pub n_random_shares: usize,
    /// Instance ID
    pub instance_id: u32,
    ///Number of Prandbit shares
    pub n_prandbit: usize,
    ///Number of PrandInt shares
    pub n_prandint: usize,
    ///Security parameter
    pub k: usize,
    ///Bit size for fixed point
    pub l: usize
}

impl HoneyBadgerMPCNodeOpts {
    /// Creates a new struct of initialization options for the HoneyBadgerMPCNode protocol.
    pub fn new(
        n_parties: usize,
        threshold: usize,
        n_triples: usize,
        n_random_shares: usize,
        instance_id: u32,
        n_prandbit: usize,
        n_prandint: usize,
        l: usize,
        k: usize,
    ) -> Self {
        Self {
            n_parties,
            threshold,
            n_triples,
            n_random_shares,
            instance_id,
            n_prandbit,
            n_prandint,
            k,
            l,
        }
    }
}

#[async_trait]
impl<F, R, N> MPCProtocol<F, RobustShare<F>, N> for HoneyBadgerMPCNode<F, R>
where
    N: Network + Send + Sync + 'static,
    F: PrimeField,
    R: RBC,
{
    type MPCOpts = HoneyBadgerMPCNodeOpts;
    type Error = HoneyBadgerError;

    fn setup(id: PartyId, params: Self::MPCOpts, input_ids: Vec<ClientId>) -> Result<Self, HoneyBadgerError> {
        // Create channels for sub protocol output.
        let (dou_sha_sender, dou_sha_receiver) = mpsc::channel(128);
        let (ran_dou_sha_sender, ran_dou_sha_receiver) = mpsc::channel(128);
        let (batched_ran_dou_sha_sender, batched_ran_dou_sha_receiver) = mpsc::channel(128);
        let (triple_sender, triple_receiver) = mpsc::channel(128);
        let (share_gen_sender, share_gen_reciever) = mpsc::channel(128);
        let (batched_share_gen_sender, batched_share_gen_receiver) = mpsc::channel(128);
        let (rand_bit_sender, rand_bit_receiver) = mpsc::channel(128);
        let (prand_bit_sender, prand_bit_receiver) = mpsc::channel(128);
        let (prand_int_sender, prand_int_receiver) = mpsc::channel(128);
        let (fpmul_sender, fpmul_receiver) = mpsc::channel(128);
        let (fpdiv_const_sender, fpdiv_const_receiver) = mpsc::channel(128);

        // Create nodes for preprocessing.
        let dousha_node =
            DoubleShareNode::new(id, params.n_parties, params.threshold, dou_sha_sender);
        let rand_bit_node = RandBit::new(id, params.n_parties, params.threshold, rand_bit_sender)?;
        let prand_bit_node = PRandBitNode::new(
            id,
            params.n_parties,
            params.threshold,
            prand_bit_sender,
            prand_int_sender,
        )?;
        let ran_dou_sha_node = RanDouShaNode::new(
            id,
            ran_dou_sha_sender,
            params.n_parties,
            params.threshold,
            params.threshold + 1,
        )?;
        let batched_ran_dou_sha_node = BatchedRanDouShaNode::new(
            id,
            batched_ran_dou_sha_sender,
            params.n_parties,
            params.threshold,
            params.threshold + 1,
        )?;

        let triple_gen_node =
            TripleGenNode::new(id, params.n_parties, params.threshold, triple_sender)?;
        let mul_node = Multiply::new(id, params.n_parties, params.threshold)?;
        let share_gen = RanShaNode::new(
            id,
            params.n_parties,
            params.threshold,
            params.threshold + 1,
            share_gen_sender,
        )?;
        let batched_share_gen = BatchedRanShaNode::new(
            id,
            params.n_parties,
            params.threshold,
            params.threshold + 1,
            batched_share_gen_sender,
        )?;
        let fpmul_node = FPMulNode::new(id, params.n_parties, params.threshold, fpmul_sender)?;
        let fpdiv_const_node =
            FPDivConstNode::new(id, params.n_parties, params.threshold, fpdiv_const_sender)?;
        let input = InputServer::new(id, params.n_parties, params.threshold, input_ids)?;
        let output = OutputServer::new(id, params.n_parties)?;
        Ok(Self {
            id,
            preprocessing_material: Arc::new(
                Mutex::new(HoneyBadgerMPCNodePreprocMaterial::empty()),
            ),
            params,
            preprocess: PreprocessNodes {
                input,
                share_gen,
                batched_share_gen,
                dou_sha: dousha_node,
                ran_dou_sha: ran_dou_sha_node,
                batched_ran_dou_sha: batched_ran_dou_sha_node,
                triple_gen: triple_gen_node,
                rand_bit: rand_bit_node,
                prand_bit: prand_bit_node,
            },
            operations: Operation { mul: mul_node },
            type_ops: TypeOperations {
                fpmul: fpmul_node,
                fpdiv_const: fpdiv_const_node,
            },
            output,
            outputchannels: OutputChannels {
                share_gen_channel: Arc::new(Mutex::new(share_gen_reciever)),
                batched_share_gen_channel: Arc::new(Mutex::new(batched_share_gen_receiver)),
                dou_sha_channel: Arc::new(Mutex::new(dou_sha_receiver)),
                ran_dou_sha_channel: Arc::new(Mutex::new(ran_dou_sha_receiver)),
                batched_ran_dou_sha_channel: Arc::new(Mutex::new(batched_ran_dou_sha_receiver)),
                triple_channel: Arc::new(Mutex::new(triple_receiver)),
                rand_bit_channel: Arc::new(Mutex::new(rand_bit_receiver)),
                prand_bit_channel: Arc::new(Mutex::new(prand_bit_receiver)),
                prand_int_channel: Arc::new(Mutex::new(prand_int_receiver)),
                fpmul_channel: Arc::new(Mutex::new(fpmul_receiver)),
                fpdiv_const_channel: Arc::new(Mutex::new(fpdiv_const_receiver)),
            },
            counters: SubProtocolCounters::new()
        })
    }

    async fn mul(
        &mut self,
        x: Vec<RobustShare<F>>,
        y: Vec<RobustShare<F>>,
        network: Arc<N>,
    ) -> Result<Vec<RobustShare<F>>, Self::Error> {
        // Both lists must have the same length.
        assert_eq!(x.len(), y.len());

        let (no_triples, _, _, _) = {
            let store = self.preprocessing_material.lock().await;
            store.len()
        };
        if no_triples < x.len() {
            //Run preprocessing
            let mut rng = StdRng::from_rng(OsRng).unwrap();
            self.run_preprocessing(network.clone(), &mut rng).await?;
        }
        // Extract the preprocessing triple.
        let beaver_triples = self
            .preprocessing_material
            .lock()
            .await
            .take_beaver_triples(x.len())?;

        let session_id = SessionId::new(ProtocolType::Mul, self.counters.mul_counter.get_next(), 0, 0, self.params.instance_id);

        // Call the mul function
        self.operations
            .mul
            .init(session_id, x, y, beaver_triples, network)
            .await?;

        self.operations.mul.wait_for_result(session_id, Duration::MAX).await.map_err(HoneyBadgerError::from)
    }

    async fn process(&mut self, raw_msg: Vec<u8>, net: Arc<N>) -> Result<(), Self::Error> {
        let wrapped: WrappedMessage = bincode::deserialize(&raw_msg)?;

        match wrapped {
            WrappedMessage::Rbc(rbc_msg) => match rbc_msg.session_id.calling_protocol() {
                Some(ProtocolType::Randousha) => {
                    self.preprocess
                        .ran_dou_sha
                        .rbc
                        .process(rbc_msg, net)
                        .await?
                }
                Some(ProtocolType::Ransha) => {
                    self.preprocess.share_gen.rbc.process(rbc_msg, net).await?
                }
                Some(ProtocolType::BatchedRansha) => {
                    self.preprocess.batched_share_gen.rbc.process(rbc_msg, net).await?
                }
                Some(ProtocolType::BatchedRandousha) => {
                    self.preprocess.batched_ran_dou_sha.rbc.process(rbc_msg, net).await?
                }
                Some(ProtocolType::Input) => {
                    self.preprocess.input.rbc.process(rbc_msg, net).await?
                }
                Some(ProtocolType::Mul) => self.operations.mul.rbc.process(rbc_msg, net).await?,
                Some(ProtocolType::RandBit) => {
                    self.preprocess
                        .rand_bit
                        .mult_node
                        .rbc
                        .process(rbc_msg, net)
                        .await?
                }
                Some(ProtocolType::FpMul) => {
                    if rbc_msg.session_id.sub_id() == 0 {
                        self.type_ops
                            .fpmul
                            .trunc_node
                            .rbc
                            .process(rbc_msg, net)
                            .await?
                    } else {
                        self.type_ops
                            .fpmul
                            .mult_node
                            .rbc
                            .process(rbc_msg, net)
                            .await?
                    }
                }
                Some(ProtocolType::FpDivConst) => {
                    self.type_ops
                        .fpdiv_const
                        .trunc_node
                        .rbc
                        .process(rbc_msg, net)
                        .await?
                }
                _ => {
                    warn!(
                        "Unknown protocol ID in session ID: {:?} in RBC",
                        rbc_msg.session_id
                    );
                }
            },

            WrappedMessage::Input(input) => {
                self.preprocess.input.process(input).await?;
            }
            WrappedMessage::RanSha(rs_msg) => {
                // Route to batched or regular ShareGen based on payload type or session protocol
                let is_batched = match &rs_msg.payload {
                    RanShaPayload::BatchedShare(_) | RanShaPayload::BatchedReconstruct(_) => true,
                    RanShaPayload::Output(_) => {
                        // For Output messages, check the session's protocol type
                        rs_msg.session_id.calling_protocol()
                            == Some(ProtocolType::BatchedRansha)
                    }
                    _ => false,
                };

                if is_batched {
                    self.preprocess.batched_share_gen.process(rs_msg, net).await?;
                } else {
                    self.preprocess.share_gen.process(rs_msg, net).await?;
                }
            }
            WrappedMessage::Dousha(ds_msg) => {
                self.preprocess.dou_sha.process(ds_msg).await?;
            }
            WrappedMessage::RanDouSha(rds_msg) => {
                // Route to batched or regular RanDouSha based on message type or session protocol
                use ran_dou_sha::messages::RanDouShaMessageType;
                let is_batched = match rds_msg.msg_type {
                    RanDouShaMessageType::BatchedShareMessage
                    | RanDouShaMessageType::BatchedReconstructMessage => true,
                    RanDouShaMessageType::OutputMessage => {
                        // For Output messages, check the session's protocol type
                        rds_msg.session_id.calling_protocol()
                            == Some(ProtocolType::BatchedRandousha)
                    }
                    _ => false,
                };

                if is_batched {
                    self.preprocess.batched_ran_dou_sha.process(rds_msg, net).await?;
                } else {
                    self.preprocess.ran_dou_sha.process(rds_msg, net).await?;
                }
            }
            WrappedMessage::Mul(mul_msg) => match mul_msg.session_id.calling_protocol() {
                Some(ProtocolType::Mul) => self.operations.mul.process(mul_msg).await?,
                Some(ProtocolType::RandBit) => {
                    self.preprocess.rand_bit.mult_node.process(mul_msg).await?
                }
                Some(ProtocolType::FpMul) => self.type_ops.fpmul.mult_node.process(mul_msg).await?,
                _ => {
                    warn!(
                        "Unknown protocol ID in session ID: {:?} in MUL",
                        mul_msg.session_id
                    );
                }
            },
            WrappedMessage::Triple(triple_msg) => {
                self.preprocess.triple_gen.process(triple_msg).await?;
            }
            WrappedMessage::BatchRecon(batch_msg) => {
                match batch_msg.session_id.calling_protocol() {
                    Some(ProtocolType::Mul) => {
                        self.operations
                            .mul
                            .batch_recon
                            .process(batch_msg, net)
                            .await?
                    }
                    Some(ProtocolType::Triple) => {
                        self.preprocess
                            .triple_gen
                            .batch_recon_node
                            .process(batch_msg, net)
                            .await?
                    }
                    Some(ProtocolType::RandBit) => {
                        if batch_msg.session_id.sub_id() == 0 {
                            self.preprocess
                                .rand_bit
                                .batch_recon
                                .process(batch_msg, net)
                                .await?
                        } else {
                            self.preprocess
                                .rand_bit
                                .mult_node
                                .batch_recon
                                .process(batch_msg, net)
                                .await?
                        }
                    }
                    Some(ProtocolType::PRandBit) => {
                        self.preprocess
                            .prand_bit
                            .batch_recon
                            .process(batch_msg, net)
                            .await?
                    }
                    Some(ProtocolType::FpMul) => {
                        self.type_ops
                            .fpmul
                            .mult_node
                            .batch_recon
                            .process(batch_msg, net)
                            .await?
                    }
                    _ => {
                        warn!(
                            "Unknown protocol ID in session ID: {:?} at Batch reconstruction",
                            batch_msg.session_id
                        );
                    }
                }
            }
            WrappedMessage::RandBit(rand_bit_message) => {
                self.preprocess.rand_bit.process(rand_bit_message).await?;
            }
            WrappedMessage::PRandBit(prand_message) => {
                self.preprocess
                    .prand_bit
                    .process(prand_message, net)
                    .await?;
            }
            WrappedMessage::Trunc(trunc_message) => {
                match trunc_message.session_id.calling_protocol() {
                    Some(ProtocolType::FpMul) => {
                        self.type_ops
                            .fpmul
                            .trunc_node
                            .process(trunc_message, net)
                            .await?;
                    }
                    Some(ProtocolType::FpDivConst) => {
                        self.type_ops
                            .fpdiv_const
                            .trunc_node
                            .process(trunc_message, net)
                            .await?;
                    }
                    _ => {
                        warn!(
                            "Unknown protocol ID in session ID: {:?} at truncation",
                            trunc_message.session_id
                        );
                    }
                }
            }
            WrappedMessage::Output(_) => warn!("Incorrect message recieved at process function"),
        }

        Ok(())
    }
}
#[async_trait]
impl<F, N, R> MPCTypeOps<F, RobustShare<F>, N> for HoneyBadgerMPCNode<F, R>
where
    F: PrimeField,
    N: Network + Send + Sync + 'static,
    R: RBC,
{
    type Error = HoneyBadgerError;
    type Sfix = SecretFixedPoint<F, RobustShare<F>>;
    type Sint = SecretInt<F, RobustShare<F>>;
    type Cfix = ClearFixedPoint<F>;
    type Cint = ClearInt<F>;

    /// Fixed-point addition: x + y
    async fn add_fixed(
        &self,
        x: Vec<Self::Sfix>,
        y: Vec<Self::Sfix>,
    ) -> Result<Vec<Self::Sfix>, Self::Error> {
        if x.len() != y.len() {
            return Err(HoneyBadgerError::FPError(FPError::IncompatiblePrecision));
        }
        Ok(x.into_iter()
            .zip(y)
            .map(|(a, b)| a + b)
            .collect::<Result<Vec<_>, _>>()?)
    }

    /// Fixed-point subtraction: x - y
    async fn sub_fixed(
        &self,
        x: Vec<Self::Sfix>,
        y: Vec<Self::Sfix>,
    ) -> Result<Vec<Self::Sfix>, Self::Error> {
        if x.len() != y.len() {
            return Err(HoneyBadgerError::FPError(FPError::IncompatiblePrecision));
        }

        Ok(x.into_iter()
            .zip(y)
            .map(|(a, b)| a - b)
            .collect::<Result<Vec<_>, _>>()?)
    }

    /// Fixed-point multiplication with truncation for fixed precision
    async fn mul_fixed(
        &mut self,
        x: SecretFixedPoint<F, RobustShare<F>>,
        y: SecretFixedPoint<F, RobustShare<F>>,
        net: Arc<N>,
    ) -> Result<SecretFixedPoint<F, RobustShare<F>>, Self::Error> {
        if x.precision() != y.precision() {
            return Err(HoneyBadgerError::FPError(FPError::IncompatiblePrecision));
        }
        let (_, _, no_rand_bit, no_rand_int) = {
            let store = self.preprocessing_material.lock().await;
            store.len()
        };
        if no_rand_bit < x.precision().f() || no_rand_int == 0 {
            //Run preprocessing
            let mut rng = StdRng::from_rng(OsRng).unwrap();
            self.run_preprocessing(net.clone(), &mut rng).await?;
        }
        // Extract the preprocessing triple.
        let beaver_triples = self
            .preprocessing_material
            .lock()
            .await
            .take_beaver_triples(1)?;
        let r_bits_vec = self
            .preprocessing_material
            .lock()
            .await
            .take_prandbit_shares(x.precision().f())?;
        let r_int = self
            .preprocessing_material
            .lock()
            .await
            .take_prandint_shares(1)?;

        let session_id = SessionId::new(ProtocolType::FpMul, self.counters.fpmul_counter.get_next(), 0, 0, self.params.instance_id);
        let r_bits = r_bits_vec.iter().map(|(a, _)| a.clone()).collect();

        // Call the fpmul function
        self.type_ops
            .fpmul
            .init(
                x,
                y,
                beaver_triples[0].clone(),
                r_bits,
                r_int[0].clone(),
                session_id,
                net,
            )
            .await?;

        let mut rx = self.outputchannels.fpmul_channel.lock().await;
        while let Some(id) = rx.recv().await {
            if id == session_id {
                let output = self
                    .type_ops
                    .fpmul
                    .protocol_output
                    .clone()
                    .ok_or(FPError::Failed)?;

                return Ok(output);
            }
        }
        Err(HoneyBadgerError::ChannelClosed)
    }

    async fn div_with_const_fixed(
        &mut self,
        x: SecretFixedPoint<F, RobustShare<F>>,
        y: ClearFixedPoint<F>,
        net: Arc<N>,
    ) -> Result<SecretFixedPoint<F, RobustShare<F>>, Self::Error> {
        // 1. Precision check ---------------------------------------------
        if x.precision() != y.precision() {
            return Err(HoneyBadgerError::FPDivConstError(
                FPDivConstError::IncompatiblePrecision,
            ));
        }

        // 2. Check preprocessing inventory --------------------------------
        let (_, _, no_rand_bit, no_rand_int) = {
            let store = self.preprocessing_material.lock().await;
            store.len()
        };

        // Need f random bits and 1 random integer for truncation
        if no_rand_bit < x.precision().f() || no_rand_int == 0 {
            // Run full preprocessing if insufficient
            let mut rng = StdRng::from_rng(OsRng).unwrap();
            self.run_preprocessing(net.clone(), &mut rng).await?;
        }

        // 3. Pull preprocessing randomness --------------------------------
        let r_bits_vec = self
            .preprocessing_material
            .lock()
            .await
            .take_prandbit_shares(x.precision().f())?;

        let r_int = self
            .preprocessing_material
            .lock()
            .await
            .take_prandint_shares(1)?;

        // Extract just the shares (drop F2_8 auxiliary)
        let r_bits_only = r_bits_vec
            .iter()
            .map(|(a, _)| a.clone())
            .collect::<Vec<_>>();

        // 4. Prepare SessionId --------------------------------------------
        let session_id = SessionId::new(
            ProtocolType::FpDivConst,
            self.counters.fpdiv_const_counter.get_next(),
            0,
            0,
            self.params.instance_id
        );
                    

        // 5. Call the division node ---------------------------------------
        self.type_ops
            .fpdiv_const
            .init(x, y, r_bits_only, r_int[0].clone(), session_id, net.clone())
            .await?;

        // 6. Wait for output on the channel --------------------------------
        let mut rx = self.outputchannels.fpdiv_const_channel.lock().await;

        while let Some(id) = rx.recv().await {
            if id == session_id {
                let output = self
                    .type_ops
                    .fpdiv_const
                    .protocol_output
                    .clone()
                    .ok_or(HoneyBadgerError::FPDivConstError(FPDivConstError::Failed))?;

                return Ok(output);
            }
        }

        Err(HoneyBadgerError::ChannelClosed)
    }

    /// Integer addition (int8/16/32/64)
    async fn add_int(
        &self,
        x: Vec<Self::Sint>,
        y: Vec<Self::Sint>,
    ) -> Result<Vec<Self::Sint>, Self::Error> {
        if x.len() != y.len() {
            return Err(HoneyBadgerError::FPError(FPError::IncompatiblePrecision));
        }

        let mut out = Vec::with_capacity(x.len());
        for (a, b) in x.into_iter().zip(y.into_iter()) {
            // Local addition of shares
            let sum = (a + b)?;
            out.push(sum);
        }
        Ok(out)
    }

    /// Integer addition (int8/16/32/64)
    async fn sub_int(
        &self,
        x: Vec<Self::Sint>,
        y: Vec<Self::Sint>,
    ) -> Result<Vec<Self::Sint>, Self::Error> {
        if x.len() != y.len() {
            return Err(HoneyBadgerError::FPError(FPError::IncompatiblePrecision));
        }
        let mut out = Vec::with_capacity(x.len());
        for (a, b) in x.into_iter().zip(y.into_iter()) {
            // Local addition of shares
            let sum = (a - b)?;
            out.push(sum);
        }
        Ok(out)
    }

    /// Integer multiplication (int8/16/32/64)
    async fn mul_int(
        &mut self,
        x: Vec<Self::Sint>,
        y: Vec<Self::Sint>,
        net: Arc<N>,
    ) -> Result<Vec<Self::Sint>, Self::Error> {
        if x.len() != y.len() {
            return Err(HoneyBadgerError::FPError(FPError::IncompatiblePrecision));
        }

        let bitlen_x = x
            .first()
            .map(|v| v.bit_length())
            .ok_or(HoneyBadgerError::FPError(FPError::IncompatiblePrecision))?;

        let x_ok = x.iter().all(|v| v.bit_length() == bitlen_x);
        if !x_ok {
            return Err(HoneyBadgerError::FPError(FPError::IncompatiblePrecision));
        }

        let bitlen_y = y
            .first()
            .map(|v| v.bit_length())
            .ok_or(HoneyBadgerError::FPError(FPError::IncompatiblePrecision))?;

        let y_ok = y.iter().all(|v| v.bit_length() == bitlen_y);
        if !y_ok {
            return Err(HoneyBadgerError::FPError(FPError::IncompatiblePrecision));
        }

        if bitlen_x != bitlen_y {
            return Err(HoneyBadgerError::FPError(FPError::IncompatiblePrecision));
        }

        let bitlen = bitlen_x;

        let a: Vec<ShamirShare<F, 1, Robust>> = x.iter().map(|s| s.share().clone()).collect();
        let b: Vec<ShamirShare<F, 1, Robust>> = y.iter().map(|s| s.share().clone()).collect();

        // Perform secure Beaver multiplication
        let result = self.mul(a, b, net).await?;
        let output = result
            .into_iter()
            .map(|share| SecretInt::new(share, bitlen))
            .collect();
        Ok(output)
    }
}

#[async_trait]
impl<F, R, N> PreprocessingMPCProtocol<F, RobustShare<F>, N> for HoneyBadgerMPCNode<F, R>
where
    N: Network + Send + Sync + 'static,
    F: PrimeField,
    R: RBC,
{
    /// Runs preprocessing to produce Random shares and Beaver triples
    /// Steps:
    /// 1. Ensure enough random shares are available = No of inputs + No of PRandbit
    /// 2. Generate double shares if missing.
    /// 3. Generate RanDouSha pairs if missing.
    /// 4. Generate Beaver triples from all the above. No of Multiplications + No of Multiplication of PRandbit
    async fn run_preprocessing<G>(
        &mut self,
        network: Arc<N>,
        rng: &mut G,
    ) -> Result<(), Self::Error>
    where
        N: 'async_trait,
        G: Rng + Send,
    {
        // Get how many triples and random shares are already available
        let (no_of_triples_avail, no_of_random_shares_avail, _, _) = {
            let store = self.preprocessing_material.lock().await;
            store.len()
        };

        // Desired total counts from protocol parameters
        let mut no_of_triples = self.params.n_triples;
        let mut no_of_random_shares = self.params.n_random_shares;
        // Each triple batch produces (2t + 1) triples at a time
        let group_size = 2 * self.params.threshold + 1;
        let total_triples_to_generate = if no_of_triples_avail >= no_of_triples {
            no_of_triples = 0;
            0
        } else {
            ((no_of_triples - no_of_triples_avail + group_size - 1) / group_size) * group_size
        };

        // Calculate how many random shares PRandbit will consume
        let prandbit_batch = self.params.threshold + 1;
        let (_, _, no_prandbit_avail, _) = {
            let store = self.preprocessing_material.lock().await;
            store.len()
        };
        let prandbit_missing = self.params.n_prandbit.saturating_sub(no_prandbit_avail);
        let total_randbit_to_generate = if prandbit_missing > 0 {
            ((prandbit_missing + prandbit_batch - 1) / prandbit_batch) * prandbit_batch
        } else {
            0
        };

        let total_random_shares_to_generate = if total_triples_to_generate > 0 {
            // Add baseline (user's requested random shares) + 2× per triple + PRandbit consumption
            let baseline = if no_of_random_shares_avail < no_of_random_shares {
                no_of_random_shares - no_of_random_shares_avail
            } else {
                no_of_random_shares = 0;
                0
            };
            baseline + 2 * total_triples_to_generate + total_randbit_to_generate
        } else if no_of_random_shares_avail < no_of_random_shares {
            no_of_random_shares - no_of_random_shares_avail + total_randbit_to_generate
        } else {
            no_of_random_shares = 0;
            total_randbit_to_generate
        };

        if no_of_triples == 0 && no_of_random_shares == 0 {
            info!("There are enough Random shares and Beaver triples");
            // return Ok(());
        } else {
            // ------------------------
            // Step 1. Ensure random shares
            // ------------------------
            self.ensure_random_shares(network.clone(), rng, total_random_shares_to_generate)
                .await?;
            info!("Random share generation done");

            // ------------------------
            // Step 2. Ensure RanDouSha pair
            // ------------------------
            let ran_dou_sha_pair = self
                .ensure_ran_dou_sha_pair(network.clone(), rng, total_triples_to_generate)
                .await?;
            info!("Randousha pair generation done");

            // ------------------------
            // Step 3. Generate triples (parallel)
            // ------------------------

            // Take random shares for triples
            let random_shares_a = self
                .preprocessing_material
                .lock()
                .await
                .take_random_shares(total_triples_to_generate)?;
            let random_shares_b = self
                .preprocessing_material
                .lock()
                .await
                .take_random_shares(total_triples_to_generate)?;

            // Outputs 2t+1 triples at a time
            let a_chunks: Vec<_> = random_shares_a.chunks_exact(group_size).map(|c| c.to_vec()).collect();
            let b_chunks: Vec<_> = random_shares_b.chunks_exact(group_size).map(|c| c.to_vec()).collect();
            let r_chunks: Vec<_> = ran_dou_sha_pair[..total_triples_to_generate]
                .chunks_exact(group_size)
                .map(|c| c.to_vec())
                .collect();

            let num_triple_batches = a_chunks.len();

            if num_triple_batches > 0 {
                info!("Starting parallel triple generation: {} batches", num_triple_batches);

                // Pre-compute all session IDs using nested counters for 16-bit range
                // For each exec_id, round_id counts 0-255, then exec_id increments
                let mut triple_exec_id = self.counters.triple_counter.get_next();
                let mut triple_round_id: u8 = 0;
                let triple_session_ids: Vec<SessionId> = (0..num_triple_batches)
                    .map(|_| {
                        let session_id = SessionId::new(
                            ProtocolType::Triple,
                            triple_exec_id,
                            0,
                            triple_round_id,
                            self.params.instance_id,
                        );
                        if triple_round_id == 255 {
                            triple_exec_id = self.counters.triple_counter.get_next();
                            triple_round_id = 0;
                        } else {
                            triple_round_id += 1;
                        }
                        session_id
                    })
                    .collect();

                // Clone shared state for parallel access
                let triple_gen = self.preprocess.triple_gen.clone();

                // Spawn all triple init tasks in parallel
                let triple_init_futures: Vec<_> = triple_session_ids
                    .iter()
                    .zip(a_chunks.into_iter().zip(b_chunks.into_iter()).zip(r_chunks.into_iter()))
                    .map(|(&session_id, ((a, b), r))| {
                        let triple_gen = triple_gen.clone();
                        let net = network.clone();

                        async move {
                            triple_gen.init(a, b, r, session_id, net).await
                        }
                    })
                    .collect();

                try_join_all(triple_init_futures).await?;

                // Collect all triple outputs into a map keyed by session ID
                // IMPORTANT: We must add outputs in deterministic session ID order, not arrival order.
                // With network delays, different parties may receive outputs in different orders.
                // If we add in arrival order, parties get mismatched triples causing interpolation failures.
                let triple_channel = self.outputchannels.triple_channel.clone();
                let mut collected_triples: HashMap<SessionId, Vec<ShamirBeaverTriple<F>>> = HashMap::new();
                let mut collected = 0;

                while collected < num_triple_batches {
                    if let Some(sid) = triple_channel.lock().await.recv().await {
                        // Check for unknown or duplicate session IDs
                        if !triple_session_ids.contains(&sid) {
                            warn!(
                                "Triple collection received unknown session ID: {:?}. \
                                This may indicate a bug or too many malicious nodes.",
                                sid
                            );
                            continue;
                        }
                        if collected_triples.contains_key(&sid) {
                            warn!(
                                "Triple collection received duplicate session ID: {:?}. \
                                This may indicate a bug or too many malicious nodes.",
                                sid
                            );
                            continue;
                        }

                        let mut triple_gen_db = self.preprocess.triple_gen.storage.lock().await;
                        if let Some(triple_storage_mutex) = triple_gen_db.remove(&sid) {
                            let triple_storage = triple_storage_mutex.lock().await;
                            let triples = triple_storage.protocol_output.clone();
                            collected_triples.insert(sid, triples);
                            self.preprocess
                                .triple_gen
                                .batch_recon_node
                                .clear_store(sid)
                                .await;
                            collected += 1;
                        }
                    } else {
                        break;
                    }
                }

                // Add triples in deterministic session ID order
                for session_id in &triple_session_ids {
                    if let Some(triples) = collected_triples.remove(session_id) {
                        self.preprocessing_material.lock().await.add(
                            Some(triples),
                            None,
                            None,
                            None,
                        );
                    }
                }

                info!("Parallel triple generation complete: {} batches", collected);
            }
        }
        // ------------------------
        // Step 5. Generate Random bits
        // ------------------------
        self.ensure_prandbit_shares(network.clone()).await?;
        info!("PrandBit share generation done");

        // ------------------------
        // Step 6. Generate Random Int
        // ------------------------
        self.ensure_prandint_shares(network.clone()).await?;
        info!("PrandInt share generation done");
        Ok(())
    }
}
impl<F, R> HoneyBadgerMPCNode<F, R>
where
    F: PrimeField,
    R: RBC,
{
    /// Ensure we have enough random shares by running ShareGen.
    ///
    /// For small numbers of shares (< 100), uses the regular ShareGen protocol.
    /// For large numbers, uses the batched ShareGen protocol which produces
    /// K*(n-2t) shares per run instead of just (n-2t).
    ///
    /// This function spawns multiple instances concurrently, each with a unique
    /// SessionId. The parallelization is safe because:
    /// - Each session uses a unique SessionId (via round_id and exec_id)
    /// - Storage is keyed by SessionId (no cross-session interference)
    /// - The network layer supports concurrent message handling
    async fn ensure_random_shares<G, N>(
        &mut self,
        network: Arc<N>,
        rng: &mut G,
        needed: usize,
    ) -> Result<(), HoneyBadgerError>
    where
        N: Network + Send + Sync + 'static,
        G: Rng,
    {
        // Outputs in batches of (n-2t) for regular protocol
        let output_per_run = self.params.n_parties - 2 * self.params.threshold;

        // Use batched protocol for larger needs (threshold: 100 shares)
        // This reduces protocol runs significantly for large share counts
        const BATCHED_THRESHOLD: usize = 100;
        const BATCH_SIZE_K: usize = 256; // K secrets per party

        if needed >= BATCHED_THRESHOLD {
            self.ensure_random_shares_batched(network, rng, needed, BATCH_SIZE_K)
                .await
        } else {
            self.ensure_random_shares_regular(network, rng, needed, output_per_run)
                .await
        }
    }

    /// Regular (non-batched) random share generation for small batch sizes.
    async fn ensure_random_shares_regular<G, N>(
        &mut self,
        network: Arc<N>,
        rng: &mut G,
        needed: usize,
        output_per_run: usize,
    ) -> Result<(), HoneyBadgerError>
    where
        N: Network + Send + Sync + 'static,
        G: Rng,
    {
        let run = (needed + output_per_run - 1) / output_per_run; // ceil(needed / output_per_run)

        if run == 0 {
            return Ok(());
        }

        info!(
            "Starting regular random share generation: {} runs needed for {} shares",
            run, needed
        );

        // Pre-compute all session IDs using nested counters for 16-bit range
        // For each exec_id, round_id counts 0-255, then exec_id increments
        let mut ransha_exec_id = self.counters.ran_sha_counter.get_next();
        let mut ransha_round_id: u8 = 0;
        let session_ids: Vec<SessionId> = (0..run)
            .map(|_| {
                let session_id = SessionId::new(
                    ProtocolType::Ransha,
                    ransha_exec_id,
                    0,
                    ransha_round_id,
                    self.params.instance_id,
                );
                if ransha_round_id == 255 {
                    ransha_exec_id = self.counters.ran_sha_counter.get_next();
                    ransha_round_id = 0;
                } else {
                    ransha_round_id += 1;
                }
                session_id
            })
            .collect();

        // Create a base seed from the provided RNG to derive child RNGs
        let base_seed: [u8; 32] = rng.gen();

        // Clone shared state for parallel access
        let share_gen = self.preprocess.share_gen.clone();

        // Spawn all init tasks in parallel
        let init_futures: Vec<_> = session_ids
            .iter()
            .enumerate()
            .map(|(i, &session_id)| {
                let share_gen = share_gen.clone();
                let net = network.clone();
                let mut task_seed = base_seed;
                task_seed[0] = task_seed[0].wrapping_add(i as u8);
                task_seed[1] = task_seed[1].wrapping_add((i >> 8) as u8);
                let mut task_rng = StdRng::from_seed(task_seed);

                async move {
                    share_gen.init(session_id, &mut task_rng, net).await
                }
            })
            .collect();

        // Wait for all init calls to complete
        try_join_all(init_futures).await?;

        // Collect all outputs into a map keyed by session ID
        // IMPORTANT: We must add outputs in deterministic session ID order, not arrival order.
        // With network delays, different parties may receive outputs in different orders.
        // If we add in arrival order, parties get mismatched shares causing interpolation failures.
        let mut collected_outputs: HashMap<SessionId, Vec<RobustShare<F>>> = HashMap::new();
        let mut collected = 0;
        let channel = self.outputchannels.share_gen_channel.clone();

        while collected < run {
            if let Some(id) = channel.lock().await.recv().await {
                // Check for unknown or duplicate session IDs
                if !session_ids.contains(&id) {
                    warn!(
                        "RanSha collection received unknown session ID: {:?}. \
                        This may indicate a bug or too many malicious nodes.",
                        id
                    );
                    continue;
                }
                if collected_outputs.contains_key(&id) {
                    warn!(
                        "RanSha collection received duplicate session ID: {:?}. \
                        This may indicate a bug or too many malicious nodes.",
                        id
                    );
                    continue;
                }

                let mut share_store = self.preprocess.share_gen.store.lock().await;
                if let Some(store_lock) = share_store.remove(&id) {
                    let store = store_lock.lock().await;
                    let output = store.protocol_output.clone();
                    collected_outputs.insert(id, output);
                    collected += 1;
                }
            } else {
                break;
            }
        }

        // Add outputs in deterministic session ID order (sorted by the pre-computed order)
        for session_id in &session_ids {
            if let Some(output) = collected_outputs.remove(session_id) {
                self.preprocessing_material
                    .lock()
                    .await
                    .add(None, Some(output), None, None);
            }
        }

        info!(
            "Regular random share generation complete: {} sessions",
            collected
        );

        self.preprocess.share_gen.rbc.clear_store().await;
        Ok(())
    }

    /// Batched random share generation for large batch sizes.
    /// Each party contributes K secrets, producing K*(n-2t) output shares per run.
    async fn ensure_random_shares_batched<G, N>(
        &mut self,
        network: Arc<N>,
        rng: &mut G,
        needed: usize,
        batch_size_k: usize,
    ) -> Result<(), HoneyBadgerError>
    where
        N: Network + Send + Sync + 'static,
        G: Rng,
    {
        // Batched protocol produces K*(n-2t) shares per run
        let output_per_run =
            batch_size_k * (self.params.n_parties - 2 * self.params.threshold);
        let run = (needed + output_per_run - 1) / output_per_run; // ceil

        if run == 0 {
            return Ok(());
        }

        info!(
            "Starting batched random share generation: {} runs with K={} for {} shares ({} per run)",
            run, batch_size_k, needed, output_per_run
        );

        // Pre-compute all session IDs using nested counters for 16-bit range
        // For each exec_id, round_id counts 0-255, then exec_id increments
        let mut batched_ransha_exec_id = self.counters.ran_sha_counter.get_next();
        let mut batched_ransha_round_id: u8 = 0;
        let session_ids: Vec<SessionId> = (0..run)
            .map(|_| {
                let session_id = SessionId::new(
                    ProtocolType::BatchedRansha,
                    batched_ransha_exec_id,
                    0,
                    batched_ransha_round_id,
                    self.params.instance_id,
                );
                if batched_ransha_round_id == 255 {
                    batched_ransha_exec_id = self.counters.ran_sha_counter.get_next();
                    batched_ransha_round_id = 0;
                } else {
                    batched_ransha_round_id += 1;
                }
                session_id
            })
            .collect();

        // Create a base seed from the provided RNG to derive child RNGs
        let base_seed: [u8; 32] = rng.gen();

        // Clone shared state for parallel access
        let batched_share_gen = self.preprocess.batched_share_gen.clone();

        // Spawn all init tasks in parallel
        let init_futures: Vec<_> = session_ids
            .iter()
            .enumerate()
            .map(|(i, &session_id)| {
                let batched_share_gen = batched_share_gen.clone();
                let net = network.clone();
                let mut task_seed = base_seed;
                task_seed[0] = task_seed[0].wrapping_add(i as u8);
                task_seed[1] = task_seed[1].wrapping_add((i >> 8) as u8);
                let mut task_rng = StdRng::from_seed(task_seed);

                async move {
                    batched_share_gen
                        .init(session_id, batch_size_k, &mut task_rng, net)
                        .await
                }
            })
            .collect();

        // Wait for all init calls to complete
        try_join_all(init_futures).await?;

        // Collect all outputs into a map keyed by session ID
        // IMPORTANT: We must add outputs in deterministic session ID order, not arrival order.
        // With network delays, different parties may receive outputs in different orders.
        // If we add in arrival order, parties get mismatched shares causing interpolation failures.
        let mut collected_outputs: HashMap<SessionId, Vec<RobustShare<F>>> = HashMap::new();
        let mut collected = 0;
        let channel = self.outputchannels.batched_share_gen_channel.clone();

        while collected < run {
            if let Some(id) = channel.lock().await.recv().await {
                // Check for unknown or duplicate session IDs
                if !session_ids.contains(&id) {
                    warn!(
                        "BatchedRanSha collection received unknown session ID: {:?}. \
                        This may indicate a bug or too many malicious nodes.",
                        id
                    );
                    continue;
                }
                if collected_outputs.contains_key(&id) {
                    warn!(
                        "BatchedRanSha collection received duplicate session ID: {:?}. \
                        This may indicate a bug or too many malicious nodes.",
                        id
                    );
                    continue;
                }

                let mut share_store = self.preprocess.batched_share_gen.store.lock().await;
                if let Some(store_lock) = share_store.remove(&id) {
                    let store = store_lock.lock().await;
                    let output = store.protocol_output.clone();
                    collected_outputs.insert(id, output);
                    collected += 1;
                }
            } else {
                break;
            }
        }

        // Add outputs in deterministic session ID order (sorted by the pre-computed order)
        for session_id in &session_ids {
            if let Some(output) = collected_outputs.remove(session_id) {
                self.preprocessing_material
                    .lock()
                    .await
                    .add(None, Some(output), None, None);
            }
        }

        info!(
            "Batched random share generation complete: {} sessions, {} shares total",
            collected,
            collected * output_per_run
        );

        self.preprocess.batched_share_gen.rbc.clear_store().await;
        Ok(())
    }

    /// Ensure we have a RanDouSha pair available, generating double shares if needed.
    ///
    /// For small numbers of shares (< 100), uses the regular two-phase protocol.
    /// For large numbers, uses the batched BatchedRanDouSha protocol which produces
    /// K*(t+1) shares per run instead of just (t+1).
    async fn ensure_ran_dou_sha_pair<G, N>(
        &mut self,
        network: Arc<N>,
        rng: &mut G,
        needed: usize,
    ) -> Result<Vec<DoubleShamirShare<F>>, HoneyBadgerError>
    where
        N: Network + Send + Sync + 'static,
        G: Rng + Send,
    {
        // Use batched protocol for larger needs (threshold: 100 shares)
        const BATCHED_THRESHOLD: usize = 100;
        const BATCH_SIZE_K: usize = 256; // K secrets per party

        if needed >= BATCHED_THRESHOLD {
            self.ensure_ran_dou_sha_pair_batched(network, rng, needed, BATCH_SIZE_K)
                .await
        } else {
            self.ensure_ran_dou_sha_pair_regular(network, rng, needed)
                .await
        }
    }

    /// Regular (non-batched) RanDouSha pair generation for small batch sizes.
    ///
    /// This function runs in two parallel phases:
    /// 1. All DouSha (double share generation) instances run in parallel
    /// 2. All RanDouSha instances run in parallel with the outputs from phase 1
    ///
    /// This reduces round trips from O(run * protocol_depth) to O(2 * protocol_depth).
    async fn ensure_ran_dou_sha_pair_regular<G, N>(
        &mut self,
        network: Arc<N>,
        rng: &mut G,
        needed: usize,
    ) -> Result<Vec<DoubleShamirShare<F>>, HoneyBadgerError>
    where
        N: Network + Send + Sync + 'static,
        G: Rng + Send,
    {
        // How many batches do we need to cover?
        let batch = self.params.threshold + 1;
        let run = (needed + batch - 1) / batch; // ceil(missing / batch)

        if run == 0 {
            return Ok(Vec::new());
        }

        info!("Starting regular RanDouSha pair generation: {} runs needed", run);

        // Pre-compute all session IDs using nested counters for 16-bit range
        // For each exec_id, round_id counts 0-255, then exec_id increments
        let mut randousha_exec_id = self.counters.ran_dou_sha_counter.get_next();
        let mut randousha_round_id: u8 = 0;
        let session_ids: Vec<SessionId> = (0..run)
            .map(|_| {
                let session_id = SessionId::new(
                    ProtocolType::Randousha,
                    randousha_exec_id,
                    0,
                    randousha_round_id,
                    self.params.instance_id,
                );
                if randousha_round_id == 255 {
                    randousha_exec_id = self.counters.ran_dou_sha_counter.get_next();
                    randousha_round_id = 0;
                } else {
                    randousha_round_id += 1;
                }
                session_id
            })
            .collect();

        // Create a base seed from the provided RNG to derive child RNGs
        let base_seed: [u8; 32] = rng.gen();

        // --- Phase 1: Parallel double share generation ---
        info!("Phase 1: Starting parallel double share generation");

        let dou_sha = self.preprocess.dou_sha.clone();
        let dou_sha_init_futures: Vec<_> = session_ids
            .iter()
            .enumerate()
            .map(|(i, &session_id)| {
                let dou_sha = dou_sha.clone();
                let net = network.clone();
                let mut task_seed = base_seed;
                task_seed[0] = task_seed[0].wrapping_add(i as u8);
                task_seed[1] = task_seed[1].wrapping_add((i >> 8) as u8);
                let mut task_rng = StdRng::from_seed(task_seed);

                async move {
                    dou_sha.init(session_id, &mut task_rng, net).await
                }
            })
            .collect();

        try_join_all(dou_sha_init_futures).await?;

        // Collect all double share outputs into a map keyed by session ID
        // IMPORTANT: We must process outputs in deterministic session ID order, not arrival order.
        let mut dou_sha_outputs_map: HashMap<SessionId, Vec<DoubleShamirShare<F>>> = HashMap::new();
        let dou_sha_channel = self.outputchannels.dou_sha_channel.clone();

        let mut collected = 0;
        while collected < run {
            if let Some(sid) = dou_sha_channel.lock().await.recv().await {
                // Check for unknown or duplicate session IDs
                if !session_ids.contains(&sid) {
                    warn!(
                        "DouSha collection received unknown session ID: {:?}. \
                        This may indicate a bug or too many malicious nodes.",
                        sid
                    );
                    continue;
                }
                if dou_sha_outputs_map.contains_key(&sid) {
                    warn!(
                        "DouSha collection received duplicate session ID: {:?}. \
                        This may indicate a bug or too many malicious nodes.",
                        sid
                    );
                    continue;
                }

                if let Some((_, dou_sha_storage_mutex)) = self.preprocess.dou_sha.storage.remove(&sid) {
                    let dou_sha_storage = dou_sha_storage_mutex.lock().await;
                    dou_sha_outputs_map.insert(sid, dou_sha_storage.protocol_output.clone());
                    collected += 1;
                }
            } else {
                break;
            }
        }

        // Build outputs in deterministic session ID order
        let dou_sha_outputs: Vec<(SessionId, Vec<DoubleShamirShare<F>>)> = session_ids
            .iter()
            .filter_map(|sid| dou_sha_outputs_map.remove(sid).map(|output| (*sid, output)))
            .collect();

        info!("Phase 1 complete: collected {} double share outputs", dou_sha_outputs.len());

        // --- Phase 2: Parallel RanDouSha with collected double shares ---
        info!("Phase 2: Starting parallel RanDouSha");

        let ran_dou_sha = self.preprocess.ran_dou_sha.clone();

        let ran_dou_sha_init_futures: Vec<_> = dou_sha_outputs
            .iter()
            .map(|(session_id, double_shares)| {
                let ran_dou_sha = ran_dou_sha.clone();
                let net = network.clone();
                let session_id = *session_id;

                let (shares_deg_t, shares_deg_2t): (Vec<_>, Vec<_>) = double_shares
                    .iter()
                    .map(|d| (d.degree_t.clone(), d.degree_2t.clone()))
                    .unzip();

                async move {
                    ran_dou_sha.init(shares_deg_t, shares_deg_2t, session_id, net).await
                }
            })
            .collect();

        try_join_all(ran_dou_sha_init_futures).await?;

        // Collect all RanDouSha outputs into a map keyed by session ID
        // IMPORTANT: We must collect outputs in deterministic session ID order, not arrival order.
        let mut ran_dou_sha_outputs_map: HashMap<SessionId, Vec<DoubleShamirShare<F>>> = HashMap::new();
        let ran_dou_sha_channel = self.outputchannels.ran_dou_sha_channel.clone();

        collected = 0;
        while collected < run {
            if let Some(sid) = ran_dou_sha_channel.lock().await.recv().await {
                // Check for unknown or duplicate session IDs
                if !session_ids.contains(&sid) {
                    warn!(
                        "RanDouSha collection received unknown session ID: {:?}. \
                        This may indicate a bug or too many malicious nodes.",
                        sid
                    );
                    continue;
                }
                if ran_dou_sha_outputs_map.contains_key(&sid) {
                    warn!(
                        "RanDouSha collection received duplicate session ID: {:?}. \
                        This may indicate a bug or too many malicious nodes.",
                        sid
                    );
                    continue;
                }

                if let Some((_, ran_dou_sha_storage_mutex)) = self.preprocess.ran_dou_sha.store.remove(&sid) {
                    let storage = ran_dou_sha_storage_mutex.lock().await;
                    ran_dou_sha_outputs_map.insert(sid, storage.protocol_output.clone());
                    collected += 1;
                }
            } else {
                break;
            }
        }

        // Build pair in deterministic session ID order
        let mut pair = Vec::new();
        for session_id in &session_ids {
            if let Some(output) = ran_dou_sha_outputs_map.remove(session_id) {
                pair.extend(output);
            }
        }

        info!("Phase 2 complete: collected {} RanDouSha outputs, total pairs: {}", collected, pair.len());

        self.preprocess.ran_dou_sha.rbc.clear_store().await;
        Ok(pair)
    }

    /// Batched RanDouSha pair generation for large batch sizes.
    /// Each party contributes K secrets, producing K*(t+1) output double shares per run.
    async fn ensure_ran_dou_sha_pair_batched<G, N>(
        &mut self,
        network: Arc<N>,
        rng: &mut G,
        needed: usize,
        batch_size_k: usize,
    ) -> Result<Vec<DoubleShamirShare<F>>, HoneyBadgerError>
    where
        N: Network + Send + Sync + 'static,
        G: Rng + Send,
    {
        // Batched protocol produces K*(t+1) shares per run
        let output_per_run = batch_size_k * (self.params.threshold + 1);
        let run = (needed + output_per_run - 1) / output_per_run; // ceil

        if run == 0 {
            return Ok(Vec::new());
        }

        info!(
            "Starting batched RanDouSha pair generation: {} runs with K={} for {} shares ({} per run)",
            run, batch_size_k, needed, output_per_run
        );

        // Pre-compute all session IDs using nested counters for 16-bit range
        let mut batched_randousha_exec_id = self.counters.ran_dou_sha_counter.get_next();
        let mut batched_randousha_round_id: u8 = 0;
        let session_ids: Vec<SessionId> = (0..run)
            .map(|_| {
                let session_id = SessionId::new(
                    ProtocolType::BatchedRandousha,
                    batched_randousha_exec_id,
                    0,
                    batched_randousha_round_id,
                    self.params.instance_id,
                );
                if batched_randousha_round_id == 255 {
                    batched_randousha_exec_id = self.counters.ran_dou_sha_counter.get_next();
                    batched_randousha_round_id = 0;
                } else {
                    batched_randousha_round_id += 1;
                }
                session_id
            })
            .collect();

        // Create a base seed from the provided RNG to derive child RNGs
        let base_seed: [u8; 32] = rng.gen();

        // Clone shared state for parallel access
        let batched_ran_dou_sha = self.preprocess.batched_ran_dou_sha.clone();

        // Spawn all init tasks in parallel
        let init_futures: Vec<_> = session_ids
            .iter()
            .enumerate()
            .map(|(i, &session_id)| {
                let batched_ran_dou_sha = batched_ran_dou_sha.clone();
                let net = network.clone();
                let mut task_seed = base_seed;
                task_seed[0] = task_seed[0].wrapping_add(i as u8);
                task_seed[1] = task_seed[1].wrapping_add((i >> 8) as u8);
                let mut task_rng = StdRng::from_seed(task_seed);

                async move {
                    batched_ran_dou_sha
                        .init(session_id, batch_size_k, &mut task_rng, net)
                        .await
                }
            })
            .collect();

        // Wait for all init calls to complete
        try_join_all(init_futures).await?;

        // Collect all outputs into a map keyed by session ID
        let mut collected_outputs: HashMap<SessionId, Vec<DoubleShamirShare<F>>> = HashMap::new();
        let mut collected = 0;
        let channel = self.outputchannels.batched_ran_dou_sha_channel.clone();

        while collected < run {
            if let Some(id) = channel.lock().await.recv().await {
                // Check for unknown or duplicate session IDs
                if !session_ids.contains(&id) {
                    warn!(
                        "BatchedRanDouSha collection received unknown session ID: {:?}. \
                        This may indicate a bug or too many malicious nodes.",
                        id
                    );
                    continue;
                }
                if collected_outputs.contains_key(&id) {
                    warn!(
                        "BatchedRanDouSha collection received duplicate session ID: {:?}. \
                        This may indicate a bug or too many malicious nodes.",
                        id
                    );
                    continue;
                }

                if let Some((_, storage_mutex)) = self.preprocess.batched_ran_dou_sha.store.remove(&id) {
                    let storage = storage_mutex.lock().await;
                    collected_outputs.insert(id, storage.protocol_output.clone());
                    collected += 1;
                }
            } else {
                break;
            }
        }

        // Build outputs in deterministic session ID order
        let mut pair = Vec::new();
        for session_id in &session_ids {
            if let Some(output) = collected_outputs.remove(session_id) {
                pair.extend(output);
            }
        }

        info!(
            "Batched RanDouSha pair generation complete: {} sessions, {} pairs total",
            collected, pair.len()
        );

        self.preprocess.batched_ran_dou_sha.rbc.clear_store().await;
        Ok(pair)
    }

    async fn ensure_prandbit_shares<N>(&mut self, network: Arc<N>) -> Result<(), HoneyBadgerError>
    where
        N: Network + Send + Sync + 'static,
    {
        // How many shares are already present?
        let (_, _, no_shares, _) = {
            let store = self.preprocessing_material.lock().await;
            store.len()
        };

        if no_shares >= self.params.n_prandbit {
            info!("There are enough prandbit shares");
            return Ok(());
        }

        // How many more do we need?
        let missing = self.params.n_prandbit.saturating_sub(no_shares);
        let batch = self.params.threshold + 1;
        let total_randbit_to_generate = ((missing + batch - 1) / batch) * batch;

        let mut randbit_output: Vec<ShamirShare<F, 1, Robust>> = Vec::new();

        // Randbit share generation
        info!("Randbit share generation run");

        let sessionid = SessionId::new(
            ProtocolType::RandBit,
            self.counters.rand_bit_counter.get_next(),
            0,
            0,
            self.params.instance_id
        );

        let random_shares_a = self
            .preprocessing_material
            .lock()
            .await
            .take_random_shares(total_randbit_to_generate)?;

        let beaver_triples = self
            .preprocessing_material
            .lock()
            .await
            .take_beaver_triples(total_randbit_to_generate)?;

        // Run Randbit share protocol
        self.preprocess
            .rand_bit
            .init(random_shares_a, beaver_triples, sessionid, network.clone())
            .await?;

        // Collect its output
        if let Some(id) = self
            .outputchannels
            .rand_bit_channel
            .lock()
            .await
            .recv()
            .await
        {
            if id == sessionid {
                let mut share_store = self.preprocess.rand_bit.storage.lock().await;
                let store_lock = share_store.remove(&id).unwrap();
                let store = store_lock.lock().await;
                let output = store.protocol_output.clone().unwrap();

                //Collect the randbit outputs
                randbit_output.extend(output);
            }
        }

        // Clear stores
        self.preprocess.rand_bit.clear_store().await;

        //Prandbit share generation
        info!("PRandbit share generation");
        let sessionid = SessionId::new(
            ProtocolType::PRandBit,
            self.counters.prand_bit_counter.get_next(),
            0,
            0,
            self.params.instance_id
        );

        // Run PRandBit protocol
        self.preprocess
            .prand_bit
            .generate_riss(
                sessionid,
                randbit_output,
                self.params.l,
                self.params.k,
                total_randbit_to_generate,
                network,
            )
            .await?;

        // Collect its output
        if let Some(id) = self
            .outputchannels
            .prand_bit_channel
            .lock()
            .await
            .recv()
            .await
        {
            if id == sessionid {
                let mut share_store = self.preprocess.prand_bit.store.lock().await;
                let store_lock = share_store.remove(&id).unwrap();
                let store = store_lock.lock().await;
                let bigbit = store.share_b_p.clone();
                let smallbit = store.share_b_2.clone();
                let output: Vec<(ShamirShare<F, 1, Robust>, F2_8)> = bigbit
                    .iter()
                    .zip(smallbit)
                    .map(|(a, b)| (a.clone(), b))
                    .collect();
                self.preprocessing_material
                    .lock()
                    .await
                    .add(None, None, Some(output), None);
            }
        }

        self.preprocess.prand_bit.clear_store().await;
        Ok(())
    }

    async fn ensure_prandint_shares<N>(&mut self, network: Arc<N>) -> Result<(), HoneyBadgerError>
    where
        N: Network + Send + Sync + 'static,
    {
        // How many shares are already present?
        let (_, _, _, no_shares) = {
            let store = self.preprocessing_material.lock().await;
            store.len()
        };

        if no_shares >= self.params.n_prandint {
            info!("There are enough prandbit shares");
            return Ok(());
        }

        // How many more do we need?
        let missing = self.params.n_prandint.saturating_sub(no_shares);

        //Prandbit share generation
        info!("PRandInt share generation");
        let sessionid = SessionId::new(
            ProtocolType::PRandInt,
            self.counters.prand_int_counter.get_next(),
            0,
            0,
            self.params.instance_id
        );

        // Run PRandBit protocol
        self.preprocess
            .prand_bit
            .generate_riss(
                sessionid,
                vec![],
                self.params.l,
                self.params.k,
                missing,
                network,
            )
            .await?;

        // Collect its output
        if let Some(id) = self
            .outputchannels
            .prand_int_channel
            .lock()
            .await
            .recv()
            .await
        {
            if id == sessionid {
                let mut share_store = self.preprocess.prand_bit.store.lock().await;
                let store_lock = share_store.remove(&id).unwrap();
                let store = store_lock.lock().await;
                let output = store.share_r_p.clone().unwrap();

                self.preprocessing_material
                    .lock()
                    .await
                    .add(None, None, None, Some(output));
            }
        }
        // Clear store
        self.preprocess.prand_bit.clear_store().await;
        Ok(())
    }
}

///Used for routing messages to respective sub-protocols
#[derive(Serialize, Deserialize, Debug)]
pub enum WrappedMessage {
    RanDouSha(RanDouShaMessage),
    Rbc(Msg),
    BatchRecon(BatchReconMsg),
    Input(InputMessage),
    RanSha(RanShaMessage),
    Triple(TripleGenMessage),
    Dousha(DouShaMessage),
    Mul(MultMessage),
    Output(OutputMessage),
    RandBit(RandBitMessage),
    Trunc(TruncPrMessage),
    PRandBit(PRandBitDMessage),
}

//-----------------Session-ID-----------------
//Used for re-routing inter-protocol messages
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolType {
    None = 0,
    Randousha = 1,
    Ransha = 2,
    Input = 3,
    Rbc = 4,
    Triple = 5,
    BatchRecon = 6,
    Dousha = 7,
    Mul = 8,
    PRandInt = 9,
    PRandBit = 10,
    RandBit = 11,
    FpMul = 12,
    Trunc = 13,
    FpDivConst = 14,
    BatchedRansha = 15,
    BatchedRandousha = 16,
}

impl TryFrom<u8> for ProtocolType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ProtocolType::None),
            1 => Ok(ProtocolType::Randousha),
            2 => Ok(ProtocolType::Ransha),
            3 => Ok(ProtocolType::Input),
            4 => Ok(ProtocolType::Rbc),
            5 => Ok(ProtocolType::Triple),
            6 => Ok(ProtocolType::BatchRecon),
            7 => Ok(ProtocolType::Dousha),
            8 => Ok(ProtocolType::Mul),
            9 => Ok(ProtocolType::PRandInt),
            10 => Ok(ProtocolType::PRandBit),
            11 => Ok(ProtocolType::RandBit),
            12 => Ok(ProtocolType::FpMul),
            13 => Ok(ProtocolType::Trunc),
            14 => Ok(ProtocolType::FpDivConst),
            15 => Ok(ProtocolType::BatchedRansha),
            16 => Ok(ProtocolType::BatchedRandousha),
            _ => Err(()),
        }
    }
}

/// A session denotes the execution of a subprotocol in an instance.
/// The session ID uniquely identifies a given session.
/// As such, it consists of
/// 
/// - instance ID: binds the session to the instance
/// - protocol/caller ID: denotes the subprotocol that is being executed; if a subprotocol calls
///   another, then this will usually contain the calling subprotocols ID, hence also caller ID
/// - execution ID: differentiates between multiple execution of the same subprotocol
/// 
/// A message has either been sent over the wire between nodes (e.g., SEND messages in the AVID
/// protocol) or is only used locally (e.g., a MultMessage reconstructed via batch reconstruction
/// and passed to some handler).
/// Some subprotocols do not have their own messages (e.g., FPMul), since they entirely rely on subprotocols.
/// While such subprotocols may be called by other subprotocols, in the context of unique
/// identification of messages we assume that such subprotocols are never called.
/// Within a session, all messages for a given receiver are uniquely identified.
/// (Globally, this is not the case, e.g., SEND messages with different destinations in the AVID
/// protocol cannot be told apart unless the payload differs.)
/// In general, a message in a subprotocol that does not call any other subprotocls is identified by
///   - sender ID: the node ID of the sending node (not needed for locally used messages)
///   - message type: the type of the message within the subprotocol
///   - message ID: distinguishes between messages of the same type from the same sender
/// If a subprotocol does call another subprotocol, which has its own messages, the caller needs
/// to distinguish between such subprotocols (if different ones are called) and between different
/// executions of the same subprotocol (if the same is executed multiple times).
/// 
/// Hence, for a message that is sent in a subprotocol with `n` nested subprotocol calls, each of
/// which has their own messages, in general, the unique ID of that message is
/// 
/// instance ID/
/// protocol ID 0/execution ID 0/
/// protocol ID 1/execution ID 1/
/// ...
/// protocol ID n/execution ID n/
/// sender ID/message type/message ID
/// 
/// However, in the particular case of HoneyBadgerMPC, `n` is at most 2.
/// Protocol ID 0 is the caller ID.
/// Execution ID 0 is simply the execution ID.
/// 
/// instance ID/
/// caller ID/execution ID/
/// protocol ID 1/execution ID 1/
/// protocol ID 2/execution ID 2/
/// sender ID/message type/message ID
/// 
/// If n=1, then protocol and execution IDs 2 vanish.
/// This is still quit generic and we use a more specific layout instead:
/// 
/// protocol ID n/
/// instance ID/
/// caller ID/execution ID/
/// sub ID/round ID/
/// sender ID/message type
/// 
/// Instance, caller, execution, and sender IDs and message types map one-to-one between the two.
/// Some subprotocols do not have a message type.
/// Execution ID 1 for n=1 and protocol ID 1 and execution ID 1 and 2 for n=2 and sometimes the
/// message type map to the sub ID and round ID.
/// The message ID is not used, since we do not have any subprotocols, where a node sends multiple
/// messages of the same type to one other node.
/// 
/// The session ID itself consists of
///   - instance ID
///   - caller ID
///   - execution ID
///   - sub ID
///   - round ID
/// The sender ID is a separate field within a message.
/// Protocol ID n is sent as a tag to process a message directly from the network (see
/// `WrappedMessage`).
/// 
/// In the following, we show the mapping from protocol and execution IDs to the sub ID, round ID,
/// and the message type.
/// 
/// Random Double Sharing (n=2):
///   - round ID = execution ID 1
///   - sub ID = execution ID 2
/// Random Sharing (n=2):
///   - round ID = execution ID 1
///   - sub ID = execution ID 2
/// Input (n=1):
///   - round ID = 0
///   - sub ID = execution ID 1
/// Multiplication (n=1):
///   - round ID = execution ID 1
///   - sub ID = message type
/// Double Sharing (n=1):
///   - round ID = execution ID 1
///   - sub ID = 0
/// RBC (n=0):
///   - does not set its own values
/// Batch Reconstruction (n=0):
///   - does not set its own values
/// Fixed-Point Multiplication (n=2):
///   - calls multiplication once and truncation once
/// Truncation (n=1):
///   - round ID = execution ID 1
///   - sub ID = 0
/// RandBit (n=2):
///   - calls multiplication once, so no execution ID 1 needed
///   - round ID = execution ID 2
/// PRandBit (n=1):
///   - round ID = execution ID 1
///   - sub ID = 0
/// PRandInt (n=1):
///   - round ID = execution ID 1
///   - sub ID = 0

#[derive(PartialOrd, Ord, Clone, Serialize, Deserialize, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(u64);

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let caller = (self.0 >> 56) as u8;
        let exec_id = self.exec_id();
        let sub_id = self.sub_id();
        let round_id = self.round_id();
        let instance_id = self.instance_id();

        write!(f, "[caller={},exec_id={},sub_id={},round_id={},instance_id={}]", caller, exec_id, sub_id, round_id, instance_id)
    }
}

impl SessionId {
    pub fn new(caller: ProtocolType, exec_id: u8, sub_id: u8, round_id: u8, instance_id: u32) -> Self {
        let value = ((caller as u64 & 0xFF) << 56)
            | ((exec_id as u64 & 0xFF) << 48)
            | ((sub_id as u64 & 0xFF) << 40)
            | ((round_id as u64 & 0xFF) << 32)
            | instance_id as u64;
        SessionId(value)
    }

    //First 8 bits
    pub fn calling_protocol(self) -> Option<ProtocolType> {
        let val = ((self.0 >> 56) & 0xFF) as u8;
        ProtocolType::try_from(val).ok()
    }

    //Second 8 bits
    pub fn exec_id(self) -> u8 {
        ((self.0 >> 48) & 0xFF) as u8
    }

    //Third 8 bits
    pub fn sub_id(self) -> u8 {
        ((self.0 >> 40) & 0xFF) as u8
    }

    //Fourth 8 bits
    pub fn round_id(self) -> u8 {
        ((self.0 >> 32) & 0xFF) as u8
    }

    //Last 32 bits
    pub fn instance_id(self) -> u32 {
        self.0 as u32
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }

    //Unsafe because this is meant for the FFI
    //The caller must ensure that the u64 is well-formed
    pub unsafe fn from_u64(id: u64) -> Self {
        SessionId(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_id_debug_format() {
        let caller = ProtocolType::try_from(5u8).unwrap();
        let exec_id = 42u8;
        let sub_id = 7u8;
        let round_id = 3u8;
        let instance_id = 0xDEADBEEF;
    
        let session_id = SessionId::new(caller, exec_id, sub_id, round_id, instance_id);
        let debug_str = format!("{:?}", session_id);
    
        assert_eq!(
            debug_str,
            "[caller=5,exec_id=42,sub_id=7,round_id=3,instance_id=3735928559]"
        );
    }

    #[test]
    fn test_session_id() {
        let caller = ProtocolType::Triple;
        let exec_id = 42u8;
        let sub_id = 7u8;
        let round_id = 3u8;
        let instance_id = 0xDEADBEEF;

        let session_id = SessionId::new(caller, exec_id, sub_id, round_id, instance_id);

        assert_eq!(session_id.calling_protocol().unwrap(), caller);
        assert_eq!(session_id.exec_id(), exec_id);
        assert_eq!(session_id.sub_id(), sub_id);
        assert_eq!(session_id.round_id(), round_id);
        assert_eq!(session_id.instance_id(), instance_id);

        let session_id2 = SessionId::new(
            session_id.calling_protocol().unwrap(),
            session_id.exec_id(),
            session_id.sub_id(),
            session_id.round_id(),
            session_id.instance_id(),
        );

        assert_eq!(session_id, session_id2);
    }
}
