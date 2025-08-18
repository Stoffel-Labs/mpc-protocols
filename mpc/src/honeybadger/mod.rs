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

pub mod input;
pub mod mul;
pub mod share_gen;

use crate::{
    common::{
        rbc::{rbc_store::Msg, RbcError},
        MPCProtocol, PreprocessingMPCProtocol, RBC,
    },
    honeybadger::{
        batch_recon::{BatchReconError, BatchReconMsg},
        double_share::{double_share_generation, DouShaError, DouShaMessage},
        input::{input::InputServer, InputError, InputMessage},
        mul::{multiplication::Multiply, MulError, MultMessage},
        ran_dou_sha::messages::RanDouShaMessage,
        share_gen::{share_gen::RanShaNode, RanShaError, RanShaMessage},
        triple_gen::{ShamirBeaverTriple, TripleGenError, TripleGenMessage},
    },
};
use ark_ff::FftField;
use ark_std::rand::Rng;
use async_trait::async_trait;
use bincode::ErrorKind;
use double_share_generation::DoubleShareNode;
use ran_dou_sha::{RanDouShaError, RanDouShaNode};
use robust_interpolate::robust_interpolate::RobustShare;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use stoffelmpc_network::{Network, NetworkError, PartyId};
use thiserror::Error;
use tokio::sync::{
    mpsc::{self, Receiver},
    Mutex,
};
use tracing::warn;
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
    #[error("error in the Batch Reconstruction: {0:?}")]
    BatchReconError(#[from] BatchReconError),
    /// Error during the serialization using [`bincode`].
    #[error("error during the serialization using bincode: {0:?}")]
    BincodeSerializationError(#[from] Box<ErrorKind>),
    #[error("failed to join spawned task")]
    JoinError,
    #[error("output channel closed before result was received")]
    ChannelClosed,
}

/// Information pertaining a HoneyBadgerMPCNode protocol participant.
#[derive(Clone, Debug)]
pub struct HoneyBadgerMPCNode<F: FftField, R: RBC> {
    /// ID of the current execution node.
    pub id: PartyId,
    /// Preprocessing material used in the protocol execution.
    pub preprocessing_material: Arc<Mutex<HoneyBadgerMPCNodePreprocMaterial<F>>>,
    // Preprocessing parameters.
    pub params: HoneyBadgerMPCNodeOpts,
    pub preprocess: PreprocessNodes<F, R>,
    pub operations: Operation<F>,
    pub output: OutputChannels,
}

#[derive(Clone, Debug)]
pub struct Operation<F: FftField> {
    pub mul: Multiply<F>,
}

#[derive(Clone, Debug)]
pub struct PreprocessNodes<F: FftField, R: RBC> {
    // Nodes for subprotocols.
    pub input: InputServer<F, R>,
    pub share_gen: RanShaNode<F, R>,
    pub dou_sha: DoubleShareNode<F>,
    pub ran_dou_sha: RanDouShaNode<F, R>,
    pub triple_gen: TripleGenNode<F>,
}

#[derive(Clone, Debug)]
pub struct OutputChannels {
    pub dou_sha_channel: Arc<Mutex<Receiver<SessionId>>>,
    pub ran_dou_sha_channel: Arc<Mutex<Receiver<SessionId>>>,
    pub triple_channel: Arc<Mutex<Receiver<SessionId>>>,
    pub mul_channel: Arc<Mutex<Receiver<SessionId>>>,
}

/// Preprocessing material for the HoneyBadgerMPCNode protocol.
#[derive(Clone, Debug)]
pub struct HoneyBadgerMPCNodePreprocMaterial<F: FftField> {
    /// A pool of random double shares used for secure multiplication.
    beaver_triples: Vec<ShamirBeaverTriple<F>>,
    /// A pool of random shares used for inputing private data for the protocol.
    random_shares: Vec<RobustShare<F>>,
}

impl<F> HoneyBadgerMPCNodePreprocMaterial<F>
where
    F: FftField,
{
    /// Generates empty preprocessing material storage.
    pub fn empty() -> Self {
        Self {
            random_shares: Vec::new(),
            beaver_triples: Vec::new(),
        }
    }

    /// Adds the provided new preprocessing material to the current pool.
    pub fn add(
        &mut self,
        mut triples: Option<Vec<ShamirBeaverTriple<F>>>,
        mut random_shares: Option<Vec<RobustShare<F>>>,
    ) {
        if let Some(pairs) = &mut triples {
            self.beaver_triples.append(pairs);
        }

        if let Some(shares) = &mut random_shares {
            self.random_shares.append(shares);
        }
    }

    /// Returns the number of random double share pairs, and the number of random shares
    /// respectively.
    pub fn len(&self) -> (usize, usize) {
        (self.beaver_triples.len(), self.random_shares.len())
    }

    /// Take up to n pairs of random double sharings from the preprocessing material.
    pub fn take_beaver_triples(
        &mut self,
        n_pairs: usize,
    ) -> Result<Vec<ShamirBeaverTriple<F>>, HoneyBadgerError> {
        if n_pairs > self.random_shares.len() {
            return Err(HoneyBadgerError::NotEnoughPreprocessing);
        }
        Ok(self.beaver_triples.drain(0..n_pairs).collect())
    }

    /// Take up to n random shares from the preprocessing material.
    pub fn take_random_shares(
        &mut self,
        n_shares: usize,
    ) -> Result<Vec<RobustShare<F>>, HoneyBadgerError> {
        if n_shares > self.random_shares.len() {
            return Err(HoneyBadgerError::NotEnoughPreprocessing);
        }
        Ok(self.random_shares.drain(0..n_shares).collect())
    }
}

#[derive(Clone, Debug)]
/// Configuration options for the HoneyBadgerMPCNode protocol.
pub struct HoneyBadgerMPCNodeOpts {
    /// Number of parties in the protocol.
    pub n_parties: usize,
    /// Upper bound of corrupt parties.
    pub threshold: usize,
    /// Number of random double sharing pairs that need to be generated.
    pub n_triples: usize,
    /// Number of random shares needed.
    pub n_random_shares: usize,
    /// Session ID
    pub session_id: SessionId,
}

impl HoneyBadgerMPCNodeOpts {
    /// Creates a new struct of initialization options for the HoneyBadgerMPCNode protocol.
    pub fn new(
        n_parties: usize,
        threshold: usize,
        n_triples: usize,
        n_random_shares: usize,
        session_id: SessionId,
    ) -> Self {
        Self {
            n_parties,
            threshold,
            n_triples,
            n_random_shares,
            session_id,
        }
    }
}

#[async_trait]
impl<F, R, N> MPCProtocol<F, RobustShare<F>, N> for HoneyBadgerMPCNode<F, R>
where
    N: Network + Send + Sync + 'static,
    F: FftField,
    R: RBC,
{
    type MPCOpts = HoneyBadgerMPCNodeOpts;
    type Error = HoneyBadgerError;

    fn setup(id: PartyId, params: Self::MPCOpts) -> Result<Self, HoneyBadgerError> {
        // Create channels for sub protocol output.
        let (dou_sha_sender, dou_sha_receiver) = mpsc::channel(128);
        let (ran_dou_sha_sender, ran_dou_sha_receiver) = mpsc::channel(128);
        let (triple_sender, triple_receiver) = mpsc::channel(128);
        let (mul_sender, mul_receiver) = mpsc::channel(128);

        // Create nodes for preprocessing.
        let dousha_node =
            DoubleShareNode::new(id, params.n_parties, params.threshold, dou_sha_sender);
        let ran_dou_sha_node = RanDouShaNode::new(
            id,
            ran_dou_sha_sender,
            params.n_parties,
            params.threshold,
            params.threshold + 1,
        )?;

        let triple_gen_node = TripleGenNode::new(
            id,
            params.n_parties,
            params.threshold,
            params.n_triples,
            triple_sender,
        )?;
        let mul_node = Multiply::new(id, params.n_parties, params.threshold, mul_sender)?;
        let share_gen =
            RanShaNode::new(id, params.n_parties, params.threshold, params.threshold + 1)?;
        let input = InputServer::new(id, params.n_parties, params.threshold)?;
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
            },
            operations: Operation { mul: mul_node },
            output: OutputChannels {
                dou_sha_channel: Arc::new(Mutex::new(dou_sha_receiver)),
                ran_dou_sha_channel: Arc::new(Mutex::new(ran_dou_sha_receiver)),
                triple_channel: Arc::new(Mutex::new(triple_receiver)),
                mul_channel: Arc::new(Mutex::new(mul_receiver)),
            },
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
        assert_eq!(x.len(), self.params.threshold + 1);

        // Extract the preprocessing triple.
        let beaver_triples = self
            .preprocessing_material
            .lock()
            .await
            .take_beaver_triples(x.len());

        let triples = match beaver_triples {
            Ok(r) => r,
            Err(e) => return Err(e), // match self.run_preprocessing(network, rng).await {
                                     //     Ok(t) => t,
                                     //     Err(e) => return Err(e),
                                     // },
        };

        let session_id = self.params.session_id;

        // Clone required fields for the async task before we drop &mut self
        let rx_clone = self.output.mul_channel.clone();
        let mul_clone = self.operations.mul.clone();
        let params_session_id = self.params.session_id;

        // Call the mul function
        self.operations
            .mul
            .init(session_id, x, y, triples, network)
            .await?;

        let mut rx = rx_clone.lock().await;
        while let Some(id) = rx.recv().await {
            if id == params_session_id {
                let mul_store = mul_clone.mult_storage.lock().await;
                if let Some(mul_lock) = mul_store.get(&params_session_id) {
                    let store = mul_lock.lock().await;
                    return Ok(store.protocol_output.clone());
                }
            }
        }
        Err(HoneyBadgerError::ChannelClosed)
    }

    async fn process(&mut self, raw_msg: Vec<u8>, net: Arc<N>) -> Result<(), Self::Error> {
        let wrapped: WrappedMessage = bincode::deserialize(&raw_msg)?;

        match wrapped {
            WrappedMessage::Rbc(rbc_msg) => match rbc_msg.session_id.protocol() {
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
                Some(ProtocolType::Input) => {
                    self.preprocess.input.rbc.process(rbc_msg, net).await?
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
                self.preprocess.share_gen.process(rs_msg, net).await?;
            }
            WrappedMessage::Dousha(ds_msg) => {
                self.preprocess.dou_sha.process(ds_msg).await?;
            }
            WrappedMessage::RanDouSha(rds_msg) => {
                self.preprocess.ran_dou_sha.process(rds_msg, net).await?;
            }
            WrappedMessage::Mul(mul_msg) => {
                self.operations.mul.process(mul_msg).await?;
            }
            WrappedMessage::Triple(triple_msg) => {
                self.preprocess.triple_gen.process(triple_msg).await?;
            }
            WrappedMessage::BatchRecon(batch_msg) => match batch_msg.session_id.protocol() {
                Some(ProtocolType::MulOne) => {
                    self.operations
                        .mul
                        .batch_recon
                        .process(batch_msg, net)
                        .await?
                }
                Some(ProtocolType::MulTwo) => {
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
                _ => {
                    warn!(
                        "Unknown protocol ID in session ID: {:?} at Batch reconstruction",
                        batch_msg.session_id
                    );
                }
            },
        }

        Ok(())
    }
}

#[async_trait]
impl<F, R, N> PreprocessingMPCProtocol<F, RobustShare<F>, N> for HoneyBadgerMPCNode<F, R>
where
    N: Network + Send + Sync + 'static,
    F: FftField,
    R: RBC,
{
    async fn run_preprocessing<G>(
        &mut self,
        network: Arc<N>,
        rng: &mut G,
    ) -> Result<Vec<ShamirBeaverTriple<F>>, Self::Error>
    where
        N: 'async_trait,
        G: Rng + Send,
    {
        let (no_of_triples, no_of_shares) = {
            let store = self.preprocessing_material.lock().await;
            store.len()
        };
        if self.params.n_triples < no_of_triples {}
        if self.params.n_random_shares < no_of_shares {}

        // First, the node takes faulty double shares to create triples.
        let random_shares_a = self
            .preprocessing_material
            .lock()
            .await
            .take_random_shares(self.params.n_triples);
        let random_shares_b = self
            .preprocessing_material
            .lock()
            .await
            .take_random_shares(self.params.n_triples);

        if random_shares_a.is_err() || random_shares_b.is_err() {
            // TODO: Run the random share generation protocol.
            todo!()
        }

        //TODO: How do we make sure nodes are using the same preprocessed data
        let mut ran_dou_sha_pair = self
            .preprocess
            .ran_dou_sha
            .pop_finished_protocol_result()
            .await;
        if ran_dou_sha_pair.is_none() {
            //TODO: How do we make sure nodes are using the same preprocessed data
            // There are not enought random double shares. We need to construct them.
            let mut out_dou_sha = self.preprocess.dou_sha.pop_finished_protocol_result().await;
            if out_dou_sha.is_none() {
                // There are not enough faulty double shares. We need to construct them.
                self.preprocess
                    .dou_sha
                    .init(self.params.session_id, rng, Arc::clone(&network))
                    .await?;
                if let Some(sid) = self.output.dou_sha_channel.lock().await.recv().await {
                    let mut dou_sha_db = self.preprocess.dou_sha.storage.lock().await;
                    // SAFETY: the triple already exists because it was taken from the finished
                    // double sharing sessions.
                    let dou_sha_storage_mutex = dou_sha_db.remove(&sid).unwrap();
                    let dou_sha_storage = dou_sha_storage_mutex.lock().await;
                    out_dou_sha = Some(dou_sha_storage.protocol_output.clone());
                }
            }
            // SAFETY: The output of the protocol is not None given that was already generated
            // previously or generated in the previous steps.
            let double_shares = out_dou_sha.unwrap();
            let (shares_deg_t, shares_deg_2t) = double_shares
                .into_iter()
                .map(|double_share| (double_share.degree_t, double_share.degree_2t))
                .collect();

            self.preprocess
                .ran_dou_sha
                .init(
                    shares_deg_t,
                    shares_deg_2t,
                    self.params.session_id,
                    Arc::clone(&network),
                )
                .await?;
            if let Some(sid) = self.output.ran_dou_sha_channel.lock().await.recv().await {
                let mut dou_sha_db = self.preprocess.ran_dou_sha.store.lock().await;
                // SAFETY: the triple already exists because it was taken from the finished
                // double sharing sessions.
                let dou_sha_storage_mutex = dou_sha_db.remove(&sid).unwrap();
                let dou_sha_storage = dou_sha_storage_mutex.lock().await;
                ran_dou_sha_pair = Some(dou_sha_storage.protocol_output.clone());
            }
        }

        self.preprocess
            .triple_gen
            .init(
                random_shares_a.unwrap(),
                random_shares_b.unwrap(),
                // SAFETY: The given that the RanDouSha was generated. This sould be Some(_).
                ran_dou_sha_pair.unwrap(),
                self.params.session_id,
                Arc::clone(&network),
            )
            .await?;

        // Extract triples.
        let mut output_triples = Vec::new();
        if let Some(sid) = self.output.triple_channel.lock().await.recv().await {
            let mut triple_gen_db = self.preprocess.triple_gen.storage.lock().await;
            // SAFETY: the triple already exists because it was taken from the finished sessions.
            let triple_storage_mutex = triple_gen_db.remove(&sid).unwrap();
            let triple_storage = triple_storage_mutex.lock().await;
            output_triples = triple_storage.protocol_output.clone();
        }

        Ok(output_triples)
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
}

//-----------------Session-ID-----------------
//Used for re-routing inter-protocol messages
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolType {
    Randousha = 1,
    Ransha = 2,
    Input = 3,
    Rbc = 4,
    Triple = 5,
    BatchRecon = 6,
    Dousha = 7,
    MulOne = 8,
    MulTwo = 9,
    Mul = 10,
}

impl TryFrom<u16> for ProtocolType {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(ProtocolType::Randousha),
            2 => Ok(ProtocolType::Ransha),
            3 => Ok(ProtocolType::Input),
            4 => Ok(ProtocolType::Rbc),
            5 => Ok(ProtocolType::Triple),
            6 => Ok(ProtocolType::BatchRecon),
            7 => Ok(ProtocolType::Dousha),
            8 => Ok(ProtocolType::MulOne),
            9 => Ok(ProtocolType::MulTwo),
            10 => Ok(ProtocolType::Mul),
            _ => Err(()),
        }
    }
}

#[derive(Debug, PartialOrd, Ord, Clone, Serialize, Deserialize, Copy, PartialEq, Eq, Hash)]
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
