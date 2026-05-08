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

pub mod comparison;
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
        MPCProtocol, MPCTypeOps, PreprocessingMPCProtocol, ProtocolSessionId, ProtocolTag,
        ShamirShare, RBC,
    },
    honeybadger::{
        batch_recon::{BatchReconError, BatchReconMsg},
        comparison::{
            ltz::LTZNode, pre_mulc::PreMulCOfflineNode, LTZError, Mod2Error, Mod2mError,
            PRandMPrep, PreMulCError, PreMulCPrep,
        },
        double_share::{double_share_generation, DouShaError, DouShaMessage, DoubleShamirShare},
        fpdiv::fpdiv_const::{FPDivConstError, FPDivConstNode},
        fpmul::{
            fpmul::{FPError, FPMulNode},
            prandbitd::PRandBitDNode,
            rand_bit::RandBit,
            PRandBitDMessage, PRandError, RandBitError, TruncPrError,
        },
        input::{
            input::{InputClient, InputServer},
            InputError, InputMessage,
        },
        mul::{multiplication::Multiply, MulError},
        output::{
            output::{OutputClient, OutputServer},
            OutputError, OutputMessage,
        },
        preprocessing::HoneyBadgerMPCNodePreprocMaterial,
        ran_dou_sha::messages::RanDouShaMessage,
        robust_interpolate::robust_interpolate::Robust,
        share_gen::{share_gen::RanShaNode, RanShaError, RanShaMessage},
        triple_gen::TripleGenError,
    },
};
use ark_ff::{FftField, PrimeField};
use ark_std::rand::rngs::{OsRng, StdRng};
use ark_std::rand::{Rng, SeedableRng};
use async_trait::async_trait;
use bincode::{ErrorKind, Options};
use double_share_generation::DoubleShareNode;
use ran_dou_sha::{RanDouShaError, RanDouShaNode};
use robust_interpolate::robust_interpolate::RobustShare;
use serde::{Deserialize, Serialize};
use std::{fmt, sync::Arc};
use stoffelnet::network_utils::{ClientId, Network, NetworkError, PartyId};
use thiserror::Error;
use tokio::{sync::Mutex, time::Duration};
use tracing::{info, warn};
use triple_gen::triple_generation::TripleGenNode;

/// Maximum number of bytes accepted from a single network message before deserialization.
/// Rejects payloads that would cause multi-gigabyte allocations via a crafted length prefix.
const MAX_MESSAGE_SIZE: u64 = 10 * 1024 * 1024; // 10 MiB

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
    #[error("error in Less than Zero: {0:?}")]
    LTZError(#[from] LTZError),
    #[error("error in PreMulC generation: {0:?}")]
    PreMulCError(#[from] PreMulCError),
    #[error("error in Mod2error: {0:?}")]
    Mod2error(#[from] Mod2Error),
    #[error("error in Mod2merror: {0:?}")]
    Mod2merror(#[from] Mod2mError),
    #[error("error in types: {0:?}")]
    TypeError(#[from] TypeError),
    #[error("Already reserved batch")]
    AlreadyReserved,
    /// Error during the serialization using [`bincode`].
    #[error("error during the serialization using bincode: {0:?}")]
    BincodeSerializationError(#[from] Box<ErrorKind>),
    #[error("failed to join spawned task")]
    JoinError,
    #[error("instance ID {0:?} is incorrect")]
    InstanceIdError(u32),
    #[error("output channel closed before result was received")]
    ChannelClosed,
    #[error("Invalid threshold t={0} for n={1}, must satisfy t < ceil(n / 3)")]
    InvalidThreshold(usize, usize),
    #[error("Party size is too large")]
    InvalidPartySize,
    #[error("Party Id is out of bounds")]
    InvalidPartyId,
    #[error("the protocol cannot be executed any more")]
    LimitError,
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

impl<F: FftField, R: RBC<Id = SessionId>> HoneyBadgerMPCClient<F, R> {
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
        sender_id: ClientId,
        raw_msg: Vec<u8>,
        net: Arc<N>,
    ) -> Result<(), HoneyBadgerError> {
        let wrapped: WrappedMessage = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_limit(MAX_MESSAGE_SIZE)
            .deserialize(&raw_msg)?;

        match wrapped {
            WrappedMessage::Input(input_msg) => {
                if sender_id != input_msg.sender_id {
                    return Err(HoneyBadgerError::InvalidPartyId);
                }
                self.input.process(input_msg, net).await?;
            }
            WrappedMessage::Output(output_msg) => {
                if sender_id != output_msg.sender_id {
                    return Err(HoneyBadgerError::InvalidPartyId);
                }
                self.output.process(output_msg).await?
            }
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
    pub counters: SubProtocolCounters,
}

#[derive(Clone, Debug)]
pub struct Operation<F: FftField, R: RBC> {
    pub mul: Multiply<F, R>,
}

#[derive(Clone, Debug)]
pub struct TypeOperations<F: PrimeField, R: RBC> {
    pub fpmul: FPMulNode<F, R>,
    pub fpdiv_const: FPDivConstNode<F, R>,
    pub ltz: LTZNode<F, R>,
}

#[derive(Clone, Debug)]
pub struct PreprocessNodes<F: PrimeField, R: RBC> {
    // Nodes for subprotocols.
    pub input: InputServer<F, R>,
    pub share_gen: RanShaNode<F, R>,
    pub dou_sha: DoubleShareNode<F>,
    pub ran_dou_sha: RanDouShaNode<F, R>,
    pub triple_gen: TripleGenNode<F>,
    pub rand_bit: RandBit<F, R>,
    pub prand_bit: PRandBitDNode<F, F>,
    pub premulc: PreMulCOfflineNode<F, R>,
}

#[derive(Clone, Debug)]
pub struct SubProtocolCounter(Arc<Mutex<Option<u8>>>);

trait GetNext<T> {
    async fn get_next(&self) -> Result<T, HoneyBadgerError>;
}

impl GetNext<u8> for SubProtocolCounter {
    async fn get_next(&self) -> Result<u8, HoneyBadgerError> {
        let mut counter = self.0.lock().await;

        match &mut *counter {
            None => Err(HoneyBadgerError::LimitError),
            Some(value) => {
                let current = *value;
                if *value == 255 {
                    *counter = None;
                } else {
                    *value += 1;
                }
                Ok(current)
            }
        }
    }
}

/// Per sub-protocol there is a counter to increment the exec ID within the
/// session ID and distinguish different executions of the same sub-protocol.
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
    pub ltz_counter: SubProtocolCounter,
    pub premulc_ltz_counter: SubProtocolCounter,
}

impl SubProtocolCounters {
    pub fn new() -> Self {
        Self {
            ran_dou_sha_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            ran_sha_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            triple_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            batch_recon_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            dou_sha_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            mul_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            rand_bit_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            prand_bit_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            prand_int_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            fpmul_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            fpdiv_const_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            ltz_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            premulc_ltz_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
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
    pub l: usize,
    pub timeout: Duration,
    /// Number of LTZ (integer comparison) operations to pre-generate material for.
    pub n_ltz: usize,
    /// Bit length of the integers used in LTZ comparisons (e.g. 8, 16, 32, 64).
    pub ltz_bit_len: usize,
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
        timeout: Duration,
        n_ltz: usize,
        ltz_bit_len: usize,
    ) -> Result<Self, HoneyBadgerError> {
        //No of parties should not exceed 255
        if n_parties > 255 {
            return Err(HoneyBadgerError::InvalidPartySize);
        }
        if !(threshold < (n_parties + 2) / 3) {
            // ceil(n / 3)
            return Err(HoneyBadgerError::InvalidThreshold(threshold, n_parties));
        }
        Ok(Self {
            n_parties,
            threshold,
            n_triples,
            n_random_shares,
            instance_id,
            n_prandbit,
            n_prandint,
            k,
            l,
            timeout,
            n_ltz,
            ltz_bit_len,
        })
    }
    pub fn set_timeout(&mut self, secs: u64) {
        self.timeout = Duration::from_secs(secs)
    }
}

#[async_trait]
impl<F, R, N> MPCProtocol<F, RobustShare<F>, N> for HoneyBadgerMPCNode<F, R>
where
    N: Network + Send + Sync + 'static,
    F: PrimeField,
    R: RBC<Id = SessionId>,
{
    type MPCOpts = HoneyBadgerMPCNodeOpts;
    type Error = HoneyBadgerError;

    fn setup(
        id: PartyId,
        params: Self::MPCOpts,
        input_ids: Vec<ClientId>,
    ) -> Result<Self, HoneyBadgerError> {
        if id >= params.n_parties {
            return Err(HoneyBadgerError::InvalidPartyId);
        }
        // Create nodes for preprocessing.
        let dousha_node = DoubleShareNode::new(id, params.n_parties, params.threshold);
        let rand_bit_node = RandBit::new(id, params.n_parties, params.threshold)?;
        let prand_bit_node = PRandBitDNode::new(id, params.n_parties, params.threshold)?;
        let ran_dou_sha_node =
            RanDouShaNode::new(id, params.n_parties, params.threshold, params.threshold + 1)?;

        let triple_gen_node = TripleGenNode::new(id, params.n_parties, params.threshold)?;
        let mul_node = Multiply::new(id, params.n_parties, params.threshold)?;
        let share_gen =
            RanShaNode::new(id, params.n_parties, params.threshold, params.threshold + 1)?;
        let fpmul_node = FPMulNode::new(id, params.n_parties, params.threshold)?;
        let fpdiv_const_node = FPDivConstNode::new(id, params.n_parties, params.threshold)?;
        let input = InputServer::new(id, params.n_parties, params.threshold, input_ids)?;
        let output = OutputServer::new(id, params.n_parties)?;
        let ltz_node = LTZNode::new(id, params.n_parties, params.threshold)?;
        let premulc_node = PreMulCOfflineNode::new(id, params.n_parties, params.threshold)?;

        Ok(Self {
            id,
            preprocessing_material: Arc::new(
                Mutex::new(HoneyBadgerMPCNodePreprocMaterial::empty()),
            ),
            params,
            preprocess: PreprocessNodes {
                input,
                share_gen,
                dou_sha: dousha_node,
                ran_dou_sha: ran_dou_sha_node,
                triple_gen: triple_gen_node,
                rand_bit: rand_bit_node,
                prand_bit: prand_bit_node,
                premulc: premulc_node,
            },
            operations: Operation { mul: mul_node },
            type_ops: TypeOperations {
                fpmul: fpmul_node,
                fpdiv_const: fpdiv_const_node,
                ltz: ltz_node,
            },
            output,
            counters: SubProtocolCounters::new(),
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

        let session_id = SessionId::new(
            ProtocolType::Mul,
            SessionId::pack_slot24(self.counters.mul_counter.get_next().await?, 0, 0),
            self.params.instance_id,
        );

        // Call the mul function
        self.operations
            .mul
            .init(session_id, x, y, beaver_triples, network)
            .await?;

        self.operations
            .mul
            .wait_for_result(session_id, self.params.timeout)
            .await
            .map_err(HoneyBadgerError::from)
    }

    async fn rand(&mut self, network: Arc<N>) -> Result<RobustShare<F>, Self::Error> {
        let (_, no_rand, _, _) = {
            let store = self.preprocessing_material.lock().await;
            store.len()
        };
        if no_rand == 0 {
            //Run preprocessing
            let mut rng = StdRng::from_rng(OsRng).unwrap();
            self.run_preprocessing(network.clone(), &mut rng).await?;
        }
        // Extract the preprocessing triple.
        let rand_value = self
            .preprocessing_material
            .lock()
            .await
            .take_random_shares(1)?;
        Ok(rand_value[0].clone())
    }

    async fn process(
        &mut self,
        sender_id: PartyId,
        raw_msg: Vec<u8>,
        net: Arc<N>,
    ) -> Result<(), Self::Error> {
        let wrapped: WrappedMessage = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_limit(MAX_MESSAGE_SIZE)
            .deserialize(&raw_msg)?;

        match wrapped {
            WrappedMessage::Rbc(rbc_msg) => {
                if sender_id != rbc_msg.sender_id {
                    return Err(HoneyBadgerError::InvalidPartyId);
                }
                if rbc_msg.session_id.instance_id() != self.params.instance_id {
                    return Err(HoneyBadgerError::InstanceIdError(
                        rbc_msg.session_id.instance_id(),
                    ));
                }
                if rbc_msg.msg_type.is_dealer_message() {
                    let expected_dealer = rbc_msg.session_id.sub_id() as usize;
                    if rbc_msg.sender_id != expected_dealer {
                        warn!(
                            "Rejecting dealer message: sender {} is not expected dealer {} for session {:?}",
                            rbc_msg.sender_id, expected_dealer, rbc_msg.session_id
                        );
                        return Err(HoneyBadgerError::InvalidPartyId);
                    }
                }

                match rbc_msg.session_id.calling_protocol() {
                    Some(ProtocolType::Randousha) => {
                        self.preprocess
                            .ran_dou_sha
                            .rbc
                            .process(rbc_msg, net)
                            .await?;
                        self.preprocess.ran_dou_sha.drain_rbc_output().await?;
                    }
                    Some(ProtocolType::Ransha) => {
                        self.preprocess.share_gen.rbc.process(rbc_msg, net).await?;
                        self.preprocess.share_gen.drain_rbc_output().await?;
                    }
                    Some(ProtocolType::Input) => {
                        self.preprocess.input.rbc.process(rbc_msg, net).await?;
                        self.preprocess.input.drain_rbc_output().await?;
                    }
                    Some(ProtocolType::Mul) => {
                        self.operations.mul.rbc.process(rbc_msg, net).await?;
                        self.operations.mul.drain_rbc_output().await?;
                    }
                    Some(ProtocolType::RandBit) => {
                        self.preprocess
                            .rand_bit
                            .mult_node
                            .rbc
                            .process(rbc_msg, net)
                            .await?;
                        self.preprocess
                            .rand_bit
                            .mult_node
                            .drain_rbc_output()
                            .await?;
                    }
                    Some(ProtocolType::FpMul) => {
                        if rbc_msg.session_id.round_id() == 0 {
                            self.type_ops
                                .fpmul
                                .trunc_node
                                .rbc
                                .process(rbc_msg, net)
                                .await?;
                            self.type_ops.fpmul.trunc_node.drain_rbc_output().await?;
                        } else {
                            self.type_ops
                                .fpmul
                                .mult_node
                                .rbc
                                .process(rbc_msg, net)
                                .await?;
                            self.type_ops.fpmul.mult_node.drain_rbc_output().await?;
                        }
                    }
                    Some(ProtocolType::FpDivConst) => {
                        self.type_ops
                            .fpdiv_const
                            .trunc_node
                            .rbc
                            .process(rbc_msg, net)
                            .await?;
                        self.type_ops
                            .fpdiv_const
                            .trunc_node
                            .drain_rbc_output()
                            .await?;
                    }
                    Some(ProtocolType::PreMulCOff) => {
                        self.preprocess
                            .premulc
                            .mul
                            .rbc
                            .process(rbc_msg, net.clone())
                            .await?;
                        self.preprocess.premulc.mul.drain_rbc_output().await?;
                    }
                    Some(ProtocolType::LTZ) => match rbc_msg.session_id.round_id() {
                        0 => {
                            self.type_ops
                                .ltz
                                .trunc
                                .mod2m
                                .bit_ltc1
                                .mod2
                                .rbc
                                .process(rbc_msg, net.clone())
                                .await?;
                            self.type_ops
                                .ltz
                                .trunc
                                .mod2m
                                .bit_ltc1
                                .mod2
                                .drain_rbc_output()
                                .await?;
                        }
                        1 => {
                            self.type_ops
                                .ltz
                                .trunc
                                .mod2m
                                .rbc
                                .process(rbc_msg, net.clone())
                                .await?;
                            self.type_ops.ltz.trunc.mod2m.drain_rbc_output().await?;
                        }
                        2 => {
                            self.type_ops
                                .ltz
                                .trunc
                                .mod2m
                                .bit_ltc1
                                .pre_mul_c
                                .mul
                                .rbc
                                .process(rbc_msg, net.clone())
                                .await?;
                            self.type_ops
                                .ltz
                                .trunc
                                .mod2m
                                .bit_ltc1
                                .pre_mul_c
                                .mul
                                .drain_rbc_output()
                                .await?;
                        }

                        _ => warn!("unexpected Rbc round_id"),
                    },
                    _ => {
                        warn!(
                            "Unknown protocol ID in session ID: {:?} in RBC",
                            rbc_msg.session_id
                        );
                    }
                }
            }

            WrappedMessage::RanSha(rs_msg) => {
                if sender_id != rs_msg.sender_id {
                    return Err(HoneyBadgerError::InvalidPartyId);
                }
                if rs_msg.session_id.instance_id() != self.params.instance_id {
                    return Err(HoneyBadgerError::InstanceIdError(
                        rs_msg.session_id.instance_id(),
                    ));
                }
                self.preprocess.share_gen.process(rs_msg, net).await?;
            }
            WrappedMessage::Dousha(ds_msg) => {
                if sender_id != ds_msg.sender_id {
                    return Err(HoneyBadgerError::InvalidPartyId);
                }
                if ds_msg.session_id.instance_id() != self.params.instance_id {
                    return Err(HoneyBadgerError::InstanceIdError(
                        ds_msg.session_id.instance_id(),
                    ));
                }
                self.preprocess.dou_sha.process(ds_msg).await?;
            }
            WrappedMessage::RanDouSha(rds_msg) => {
                if sender_id != rds_msg.sender_id {
                    return Err(HoneyBadgerError::InvalidPartyId);
                }
                if rds_msg.session_id.instance_id() != self.params.instance_id {
                    return Err(HoneyBadgerError::InstanceIdError(
                        rds_msg.session_id.instance_id(),
                    ));
                }
                self.preprocess.ran_dou_sha.process(rds_msg, net).await?;
            }
            WrappedMessage::BatchRecon(batch_msg) => {
                if sender_id != batch_msg.sender_id {
                    return Err(HoneyBadgerError::InvalidPartyId);
                }
                if batch_msg.session_id.instance_id() != self.params.instance_id {
                    return Err(HoneyBadgerError::InstanceIdError(
                        batch_msg.session_id.instance_id(),
                    ));
                }
                match batch_msg.session_id.calling_protocol() {
                    Some(ProtocolType::Mul) => {
                        self.operations
                            .mul
                            .batch_recon
                            .process(batch_msg, net)
                            .await?;
                        self.operations.mul.drain_batch_recon_output().await?
                    }
                    Some(ProtocolType::Triple) => {
                        self.preprocess
                            .triple_gen
                            .batch_recon_node
                            .process(batch_msg, net)
                            .await?;
                        self.preprocess
                            .triple_gen
                            .drain_batch_recon_output()
                            .await?
                    }
                    Some(ProtocolType::RandBit) => {
                        if batch_msg.session_id.round_id() == 0 {
                            self.preprocess
                                .rand_bit
                                .batch_recon
                                .process(batch_msg, net)
                                .await?;
                            self.preprocess.rand_bit.drain_batch_recon_output().await?;
                        } else {
                            self.preprocess
                                .rand_bit
                                .mult_node
                                .batch_recon
                                .process(batch_msg, net)
                                .await?;
                            self.preprocess
                                .rand_bit
                                .mult_node
                                .drain_batch_recon_output()
                                .await?;
                        }
                    }
                    Some(ProtocolType::PRandBit) => {
                        self.preprocess
                            .prand_bit
                            .batch_recon
                            .process(batch_msg, net)
                            .await?;

                        self.preprocess.prand_bit.drain_batch_recon_output().await?;
                    }
                    Some(ProtocolType::FpMul) => {
                        self.type_ops
                            .fpmul
                            .mult_node
                            .batch_recon
                            .process(batch_msg, net)
                            .await?;
                        self.type_ops
                            .fpmul
                            .mult_node
                            .drain_batch_recon_output()
                            .await?;
                    }
                    Some(ProtocolType::PreMulCOff) => {
                        let round = batch_msg.session_id.round_id();
                        if round == 0 {
                            self.preprocess
                                .premulc
                                .batch_recon
                                .process(batch_msg, net.clone())
                                .await?;
                            self.preprocess.premulc.drain_batch_recon_output().await?;
                        } else if round == 1 {
                            self.preprocess
                                .premulc
                                .mul
                                .batch_recon
                                .process(batch_msg, net.clone())
                                .await?;
                            self.preprocess
                                .premulc
                                .mul
                                .drain_batch_recon_output()
                                .await?;
                        } else {
                            warn!("unexpected round_id {round}");
                        }
                    }
                    Some(ProtocolType::LTZ) => match batch_msg.session_id.round_id() {
                        0 => {
                            self.type_ops
                                .ltz
                                .trunc
                                .mod2m
                                .bit_ltc1
                                .pre_mul_c
                                .batch_recon
                                .process(batch_msg, net.clone())
                                .await?;
                            self.type_ops
                                .ltz
                                .trunc
                                .mod2m
                                .bit_ltc1
                                .pre_mul_c
                                .drain_batch_recon_output()
                                .await?;
                        }
                        1 => {
                            self.type_ops
                                .ltz
                                .trunc
                                .mod2m
                                .bit_ltc1
                                .pre_mul_c
                                .mul
                                .batch_recon
                                .process(batch_msg, net.clone())
                                .await?;
                            self.type_ops
                                .ltz
                                .trunc
                                .mod2m
                                .bit_ltc1
                                .pre_mul_c
                                .mul
                                .drain_batch_recon_output()
                                .await?;
                        }
                        _ => warn!("unexpected BatchRecon round_id"),
                    },
                    _ => {
                        warn!(
                            "Unknown protocol ID in session ID: {:?} at Batch reconstruction",
                            batch_msg.session_id
                        );
                    }
                }
            }
            WrappedMessage::PRandBitD(prand_message) => {
                if sender_id != prand_message.sender_id {
                    return Err(HoneyBadgerError::InvalidPartyId);
                }
                if prand_message.session_id.instance_id() != self.params.instance_id {
                    return Err(HoneyBadgerError::InstanceIdError(
                        prand_message.session_id.instance_id(),
                    ));
                }
                self.preprocess
                    .prand_bit
                    .process(prand_message, net)
                    .await?;
            }
            WrappedMessage::Input(_) => warn!("Incorrect message recieved at process function"),
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
    R: RBC<Id = SessionId>,
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
            return Err(HoneyBadgerError::TypeError(
                TypeError::IncompatibleInputLength,
            ));
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
            return Err(HoneyBadgerError::TypeError(
                TypeError::IncompatibleInputLength,
            ));
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

        let session_id = SessionId::new(
            ProtocolType::FpMul,
            SessionId::pack_slot24(self.counters.fpmul_counter.get_next().await?, 0, 0),
            self.params.instance_id,
        );
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
                self.params.timeout,
                session_id,
                net,
            )
            .await
            .map_err(HoneyBadgerError::from)
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
            SessionId::pack_slot24(self.counters.fpdiv_const_counter.get_next().await?, 0, 0),
            self.params.instance_id,
        );

        // 5. Call the division node ---------------------------------------
        self.type_ops
            .fpdiv_const
            .init(
                x,
                y,
                r_bits_only,
                r_int[0].clone(),
                self.params.timeout,
                session_id,
                net.clone(),
            )
            .await
            .map_err(HoneyBadgerError::from)
    }

    /// Integer addition (int8/16/32/64)
    async fn add_int(
        &self,
        x: Vec<Self::Sint>,
        y: Vec<Self::Sint>,
    ) -> Result<Vec<Self::Sint>, Self::Error> {
        if x.len() != y.len() {
            return Err(HoneyBadgerError::TypeError(
                TypeError::IncompatibleInputLength,
            ));
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
            return Err(HoneyBadgerError::TypeError(
                TypeError::IncompatibleInputLength,
            ));
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
            return Err(HoneyBadgerError::TypeError(
                TypeError::IncompatibleInputLength,
            ));
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
    /// x<0 Integer comparison (int8/16/32/64)
    async fn ltz_int(&mut self, x: Self::Sint, net: Arc<N>) -> Result<Self::Sint, Self::Error> {
        let k = x.bit_length();

        let chunk = self.params.threshold + 1;
        let pk = ((k - 1 + chunk - 1) / chunk) * chunk;

        // Check/run preprocessing
        let (_, _, no_prandbit, no_prandint) = {
            let store = self.preprocessing_material.lock().await;
            store.len()
        };
        let no_premulc = {
            let store = self.preprocessing_material.lock().await;
            store.premulc_ltz_len()
        };
        if no_prandbit < k || no_prandint < 2 || no_premulc < pk {
            let mut rng = StdRng::from_rng(OsRng).unwrap();
            self.run_preprocessing(net.clone(), &mut rng).await?;
        }

        let premulc_prep = self
            .preprocessing_material
            .lock()
            .await
            .take_premulc_ltz(pk)?; // drains exactly pk from the flat pool

        // Take 2 prandint shares: one for prandm_prep, one for mod2_prep.
        let prandint = self
            .preprocessing_material
            .lock()
            .await
            .take_prandint_shares(2)?;

        // Take k-1 prandbit shares for Mod2m's r', then 1 for Mod2's r0'.
        let prandbit_km1 = self
            .preprocessing_material
            .lock()
            .await
            .take_prandbit_shares(k - 1)?;
        let prandbit_one = self
            .preprocessing_material
            .lock()
            .await
            .take_prandbit_shares(1)?;

        // Build PRandMPrep for Mod2m(k, k-1): r'' is prandint, r'_bits are k-1 prandbits.
        let prandm_bits: Vec<RobustShare<F>> =
            prandbit_km1.iter().map(|(s, _)| s.clone()).collect();
        let prandm_prep = PRandMPrep::from_prand_outputs(prandint[0].clone(), prandm_bits)
            .map_err(LTZError::from)?;

        // Build PRandMPrep for Mod2(k): r'' is prandint, r0' is 1 prandbit.
        let mod2_bits: Vec<RobustShare<F>> = prandbit_one.iter().map(|(s, _)| s.clone()).collect();
        let mod2_prep = PRandMPrep::from_prand_outputs(prandint[1].clone(), mod2_bits)
            .map_err(LTZError::from)?;

        let session = SessionId::new(
            ProtocolType::LTZ,
            SessionId::pack_slot24(self.counters.ltz_counter.get_next().await?, 0, 0),
            self.params.instance_id,
        );

        let result_share = self
            .type_ops
            .ltz
            .run(
                x.share().clone(),
                k,
                prandm_prep,
                premulc_prep,
                mod2_prep,
                session,
                net,
                self.params.timeout,
            )
            .await?;

        Ok(SecretInt::new(result_share, k))
    }
}

#[async_trait]
impl<F, R, N> PreprocessingMPCProtocol<F, RobustShare<F>, N> for HoneyBadgerMPCNode<F, R>
where
    N: Network + Send + Sync + 'static,
    F: PrimeField,
    R: RBC<Id = SessionId>,
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
        // Extra demand from LTZ: each comparison needs 2*pk triples and 2*pk random shares
        // for the PreMulCOffline protocol (pk offline triples + pk online triples, pk r + pk s).
        let ltz_extra = if self.params.n_ltz > 0 && self.params.ltz_bit_len >= 2 {
            let chunk = self.params.threshold + 1;
            let pk = ((self.params.ltz_bit_len - 1 + chunk - 1) / chunk) * chunk;
            self.params.n_ltz * 2 * pk
        } else {
            0
        };

        // Get how many triples and random shares are already available
        let (no_of_triples_avail, no_of_random_shares_avail, _, _) = {
            let store = self.preprocessing_material.lock().await;
            store.len()
        };

        let mut no_of_triples = self.params.n_triples + ltz_extra;
        let mut no_of_random_shares = self.params.n_random_shares + ltz_extra;
        // Each triple batch produces (2t + 1) triples at a time
        let group_size = 2 * self.params.threshold + 1;
        let total_triples_to_generate = if no_of_triples_avail >= no_of_triples {
            no_of_triples = 0;
            0
        } else {
            ((no_of_triples - no_of_triples_avail + group_size - 1) / group_size) * group_size
        };

        let total_random_shares_to_generate = if total_triples_to_generate > 0 {
            // Always add 2× per triple group
            let baseline = if no_of_random_shares_avail < no_of_random_shares {
                no_of_random_shares - no_of_random_shares_avail
            } else {
                no_of_random_shares = 0;
                0
            };
            baseline + 2 * total_triples_to_generate
        } else if no_of_random_shares_avail < no_of_random_shares {
            no_of_random_shares - no_of_random_shares_avail
        } else {
            no_of_random_shares = 0;
            0
        };

        if no_of_triples == 0 && no_of_random_shares == 0 {
            info!("There are enough Random shares and Beaver triples");
            // return Ok(());
        } else {
            let mut triple_counter = self.counters.triple_counter.get_next().await?;
            if (256 - triple_counter as usize) * 255 < total_triples_to_generate / group_size {
                return Err(HoneyBadgerError::LimitError);
            }

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
            // Step 3. Generate triples
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

            //Outputs 2t+1 triples at a time
            let a_chunks = random_shares_a.chunks_exact(group_size);
            let b_chunks = random_shares_b.chunks_exact(group_size);
            let r_chunks = ran_dou_sha_pair[..total_triples_to_generate].chunks_exact(group_size);
            let mut round_id = 0u8;

            for ((a, b), r) in a_chunks.zip(b_chunks).zip(r_chunks) {
                let sessionid = SessionId::new(
                    ProtocolType::Triple,
                    SessionId::pack_slot24(triple_counter, 0, round_id),
                    self.params.instance_id,
                );
                self.preprocess
                    .triple_gen
                    .init(
                        a.to_vec(),
                        b.to_vec(),
                        r.to_vec(),
                        sessionid,
                        network.clone(),
                    )
                    .await?;

                // ------------------------
                // Step 4. Collect triples
                // ------------------------
                let triples = self
                    .preprocess
                    .triple_gen
                    .wait_for_result(sessionid, self.params.timeout)
                    .await?;
                self.preprocessing_material
                    .lock()
                    .await
                    .add(Some(triples), None, None, None);
                assert!(self.preprocess.triple_gen.clear_store(sessionid).await);

                if round_id == 255 {
                    triple_counter = self.counters.triple_counter.get_next().await.unwrap();
                    round_id = 0;
                } else {
                    round_id += 1;
                }
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

        // ------------------------
        // Step 7. Generate PreMulC offline outputs for LTZ
        // ------------------------
        self.ensure_premulc_for_ltz(network.clone()).await?;
        info!("PreMulC LTZ preprocessing done");

        Ok(())
    }
}
impl<F, R> HoneyBadgerMPCNode<F, R>
where
    F: PrimeField,
    R: RBC<Id = SessionId>,
{
    /// Ensure we have enough random shares by repeatedly running ShareGen if needed.
    async fn ensure_random_shares<G, N>(
        &mut self,
        network: Arc<N>,
        rng: &mut G,
        needed: usize,
    ) -> Result<(), HoneyBadgerError>
    where
        N: Network + Send + Sync + 'static,
        G: Rng + Send,
    {
        // Outputs in batches of (n-2t)
        let batch = self.params.n_parties - 2 * self.params.threshold;
        let run = (needed + batch - 1) / batch; // ceil(missing / batch)
        let mut round_id = 0u8;
        let mut ran_sha_counter = self.counters.ran_sha_counter.get_next().await?;

        if (256 - ran_sha_counter as usize) * 255 < run {
            return Err(HoneyBadgerError::LimitError);
        }

        for i in 0..run {
            info!("Random share generation run {}", i);

            let sessionid = SessionId::new(
                ProtocolType::Ransha,
                SessionId::pack_slot24(ran_sha_counter, 0, round_id),
                self.params.instance_id,
            );

            // Run ShareGen protocol
            self.preprocess
                .share_gen
                .init(sessionid, rng, network.clone())
                .await?;

            // Collect its output
            let output = self
                .preprocess
                .share_gen
                .wait_for_result(sessionid, self.params.timeout)
                .await?;

            self.preprocessing_material
                .lock()
                .await
                .add(None, Some(output), None, None);
            assert!(self.preprocess.share_gen.clear_store(sessionid).await);

            if round_id == 255 {
                ran_sha_counter = self.counters.ran_sha_counter.get_next().await.unwrap();
                round_id = 0;
            } else {
                round_id += 1;
            }
        }

        // Clear RBC store
        self.preprocess.share_gen.rbc.clear_store().await;
        Ok(())
    }

    /// Ensure we have a RanDouSha pair available, generating double shares if needed.
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
        let mut pair = Vec::new();

        // How many batches do we need to cover?
        let batch = self.params.threshold + 1;
        let run = (needed + batch - 1) / batch; // ceil(missing / batch)
        let mut round_id = 0u8;
        let mut ran_dou_sha_counter = self.counters.ran_dou_sha_counter.get_next().await?;

        if (256 - ran_dou_sha_counter as usize) * 255 < run {
            return Err(HoneyBadgerError::LimitError);
        }

        for _ in 0..run {
            let sessionid = SessionId::new(
                ProtocolType::Randousha,
                SessionId::pack_slot24(ran_dou_sha_counter, 0, round_id),
                self.params.instance_id,
            );

            let double_shares = self
                .ensure_double_shares(sessionid, network.clone(), rng)
                .await?;

            let (shares_deg_t, shares_deg_2t) = double_shares
                .into_iter()
                .map(|d| (d.degree_t, d.degree_2t))
                .unzip();

            // Run RanDouSha
            self.preprocess
                .ran_dou_sha
                .init(shares_deg_t, shares_deg_2t, sessionid, network.clone())
                .await?;

            let output = self
                .preprocess
                .ran_dou_sha
                .wait_for_result(sessionid, self.params.timeout)
                .await?;
            pair.extend(output);
            assert!(self.preprocess.ran_dou_sha.clear_store(sessionid).await);

            if round_id == 255 {
                ran_dou_sha_counter = self.counters.ran_dou_sha_counter.get_next().await.unwrap();
                round_id = 0;
            } else {
                round_id += 1;
            }
        }
        self.preprocess.ran_dou_sha.rbc.clear_store().await;
        Ok(pair)
    }

    /// Ensure we have double shares available.
    async fn ensure_double_shares<G, N>(
        &mut self,
        sessionid: SessionId,
        network: Arc<N>,
        rng: &mut G,
    ) -> Result<Vec<DoubleShamirShare<F>>, HoneyBadgerError>
    where
        N: Network + Send + Sync + 'static,
        G: Rng + Send,
    {
        self.preprocess
            .dou_sha
            .init(sessionid, rng, network.clone())
            .await?;

        let dou_sha = self
            .preprocess
            .dou_sha
            .wait_for_result(sessionid, self.params.timeout)
            .await?;
        assert!(self.preprocess.dou_sha.clear_store(sessionid).await);

        Ok(dou_sha)
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

        let randbit_sessionid = SessionId::new(
            ProtocolType::RandBit,
            SessionId::pack_slot24(self.counters.rand_bit_counter.get_next().await?, 0, 0),
            self.params.instance_id,
        );

        //Prandbit share generation
        info!("PRandbit share generation");
        let prandbit_sessionid = SessionId::new(
            ProtocolType::PRandBit,
            SessionId::pack_slot24(self.counters.prand_bit_counter.get_next().await?, 0, 0),
            self.params.instance_id,
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
            .init(
                random_shares_a,
                beaver_triples,
                randbit_sessionid,
                self.params.timeout,
                network.clone(),
            )
            .await?;

        // Collect its output
        let output = self
            .preprocess
            .rand_bit
            .wait_for_result(randbit_sessionid, self.params.timeout)
            .await?;
        randbit_output.extend(output);

        // Clear stores

        self.preprocess
            .rand_bit
            .clear_store(randbit_sessionid)
            .await?;

        //Prandbit share generation
        info!("PRandbit share generation");

        // Run PRandBit protocol
        self.preprocess
            .prand_bit
            .generate_riss(
                prandbit_sessionid,
                randbit_output,
                self.params.l,
                self.params.k,
                total_randbit_to_generate,
                network,
            )
            .await?;

        // Collect its output
        let output = self
            .preprocess
            .prand_bit
            .wait_for_bit_result(prandbit_sessionid, self.params.timeout)
            .await?;
        self.preprocessing_material
            .lock()
            .await
            .add(None, None, Some(output), None);

        self.preprocess
            .prand_bit
            .clear_store(prandbit_sessionid)
            .await?;
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
            SessionId::pack_slot24(self.counters.prand_int_counter.get_next().await?, 0, 0),
            self.params.instance_id,
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
        let output = self
            .preprocess
            .prand_bit
            .wait_for_int_result(sessionid, self.params.timeout)
            .await?;
        self.preprocessing_material
            .lock()
            .await
            .add(None, None, None, Some(output));
        // Clear store
        self.preprocess.prand_bit.clear_store(sessionid).await?;
        Ok(())
    }
    async fn ensure_premulc_for_ltz<N>(&mut self, network: Arc<N>) -> Result<(), HoneyBadgerError>
    where
        N: Network + Send + Sync + 'static,
    {
        if self.params.n_ltz == 0 || self.params.ltz_bit_len < 2 {
            return Ok(());
        }

        let chunk = self.params.threshold + 1;
        let pk = ((self.params.ltz_bit_len - 1 + chunk - 1) / chunk) * chunk;
        let needed = self.params.n_ltz * pk;

        let have = {
            let store = self.preprocessing_material.lock().await;
            store.premulc_ltz_len()
        };

        if have >= needed {
            info!("There are enough PreMulC LTZ elements");
            return Ok(());
        }

        // missing is a multiple of pk (and therefore of chunk) since both `needed`
        // and `have` are multiples of pk.
        let missing = needed - have;

        let session = SessionId::new(
            ProtocolType::PreMulCOff,
            SessionId::pack_slot24(self.counters.premulc_ltz_counter.get_next().await?, 0, 0),
            self.params.instance_id,
        );

        let r_shares = self
            .preprocessing_material
            .lock()
            .await
            .take_random_shares(missing)?;
        let s_shares = self
            .preprocessing_material
            .lock()
            .await
            .take_random_shares(missing)?;
        let offline_triples = self
            .preprocessing_material
            .lock()
            .await
            .take_beaver_triples(missing)?;
        let online_triples = self
            .preprocessing_material
            .lock()
            .await
            .take_beaver_triples(missing)?;

        self.preprocess
            .premulc
            .generate_preprocessing(
                r_shares,
                s_shares,
                offline_triples,
                session,
                network.clone(),
                self.params.timeout,
            )
            .await
            .map_err(HoneyBadgerError::from)?;

        self.preprocess
            .premulc
            .drain_batch_recon_output()
            .await
            .map_err(HoneyBadgerError::from)?;

        let (w, z) = self
            .preprocess
            .premulc
            .wait_for_preprocessing(session, self.params.timeout)
            .await
            .map_err(HoneyBadgerError::from)?;

        self.preprocess
            .premulc
            .clear_store(session)
            .await
            .map_err(HoneyBadgerError::from)?;

        self.preprocessing_material
            .lock()
            .await
            .add_premulc_ltz(PreMulCPrep {
                w,
                z,
                triples: online_triples,
            });

        info!(
            "PreMulC LTZ preprocessing done: {} elements generated",
            missing
        );
        Ok(())
    }
}

///Used for routing messages to respective sub-protocols
#[derive(Serialize, Deserialize, Debug)]
pub enum WrappedMessage {
    RanDouSha(RanDouShaMessage),
    Rbc(Msg<SessionId>),
    BatchRecon(BatchReconMsg),
    Input(InputMessage),
    RanSha(RanShaMessage),
    Dousha(DouShaMessage),
    Output(OutputMessage),
    PRandBitD(PRandBitDMessage),
}

impl WrappedMessage {
    pub fn rbc_wrap(msg: Msg<SessionId>) -> Result<Vec<u8>, RbcError> {
        let wrapped = WrappedMessage::Rbc(msg);
        Ok(bincode::serialize(&wrapped)?)
    }
}

//-----------------Session-ID-----------------
//Used for re-routing inter-protocol messages
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
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
    PreMulCOff = 15,
    LTZ = 16,
}

impl ProtocolTag for ProtocolType {
    #[inline]
    fn to_u8(self) -> u8 {
        self as u8
    }

    #[inline]
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::None),
            1 => Some(Self::Randousha),
            2 => Some(Self::Ransha),
            3 => Some(Self::Input),
            4 => Some(Self::Rbc),
            5 => Some(Self::Triple),
            6 => Some(Self::BatchRecon),
            7 => Some(Self::Dousha),
            8 => Some(Self::Mul),
            9 => Some(Self::PRandInt),
            10 => Some(Self::PRandBit),
            11 => Some(Self::RandBit),
            12 => Some(Self::FpMul),
            13 => Some(Self::Trunc),
            14 => Some(Self::FpDivConst),
            15 => Some(Self::PreMulCOff),
            16 => Some(Self::LTZ),
            _ => None,
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

        write!(
            f,
            "[caller={},exec_id={},sub_id={},round_id={},instance_id={}]",
            caller, exec_id, sub_id, round_id, instance_id
        )
    }
}

impl ProtocolSessionId for SessionId {
    type Protocol = ProtocolType;

    fn new(protocol: ProtocolType, slot24: u32, instance_id: u32) -> Self {
        let value = ((protocol as u64 & 0xFF) << 56)
            | ((slot24 as u64 & 0xFF_FFFF) << 32)
            | (instance_id as u64);

        SessionId(value)
    }
    //First 8 bits
    fn calling_protocol(self) -> Option<ProtocolType> {
        let val = ((self.0 >> 56) & 0xFF) as u8;
        ProtocolType::from_u8(val)
    }

    fn slot24(self) -> u32 {
        ((self.0 >> 32) & 0xFF_FFFF) as u32
    }

    //Last 32 bits
    fn instance_id(self) -> u32 {
        self.0 as u32
    }

    fn as_u64(self) -> u64 {
        self.0
    }
    //Unsafe because this is meant for the FFI
    //The caller must ensure that the u64 is well-formed
    unsafe fn from_u64(id: u64) -> Self {
        SessionId(id)
    }
}

impl SessionId {
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

    #[inline]
    pub fn pack_slot24(exec_id: u8, sub_id: u8, round_id: u8) -> u32 {
        ((exec_id as u32) << 16) | ((sub_id as u32) << 8) | round_id as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    #[test]
    fn test_session_id_debug_format() {
        let caller = ProtocolType::from_u8(5u8).unwrap();
        let exec_id = 42u8;
        let sub_id = 7u8;
        let round_id = 3u8;
        let instance_id = 0xDEADBEEF;

        let session_id = SessionId::new(
            caller,
            SessionId::pack_slot24(exec_id, sub_id, round_id),
            instance_id,
        );
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

        let session_id = SessionId::new(
            caller,
            SessionId::pack_slot24(exec_id, sub_id, round_id),
            instance_id,
        );

        assert_eq!(session_id.calling_protocol().unwrap(), caller);
        assert_eq!(session_id.exec_id(), exec_id);
        assert_eq!(session_id.sub_id(), sub_id);
        assert_eq!(session_id.round_id(), round_id);
        assert_eq!(session_id.instance_id(), instance_id);

        let session_id2 = SessionId::new(
            session_id.calling_protocol().unwrap(),
            SessionId::pack_slot24(
                session_id.exec_id(),
                session_id.sub_id(),
                session_id.round_id(),
            ),
            session_id.instance_id(),
        );

        assert_eq!(session_id, session_id2);
    }

    #[tokio::test]
    async fn test_subprotocol_counter_limit_error() {
        let counter = SubProtocolCounter(Arc::new(Mutex::new(Some(255))));
        // First call should return 255
        let val = counter.get_next().await;
        assert_eq!(val.unwrap(), 255);

        // Second call should return error (None)
        let err = counter.get_next().await;
        assert!(matches!(err, Err(HoneyBadgerError::LimitError)));
    }
}
