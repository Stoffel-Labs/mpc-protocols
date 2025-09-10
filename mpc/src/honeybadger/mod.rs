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
pub mod output;
pub mod rand_bit;
pub mod share_gen;

use crate::honeybadger::rand_bit::{RandBit, RandBitError, RandBitMessage};
use crate::{
    common::{
        rbc::{rbc_store::Msg, RbcError},
        MPCProtocol, PreprocessingMPCProtocol, RBC,
    },
    honeybadger::{
        batch_recon::{BatchReconError, BatchReconMsg},
        double_share::{double_share_generation, DouShaError, DouShaMessage, DoubleShamirShare},
        input::{
            input::{InputClient, InputServer},
            InputError, InputMessage,
        },
        mul::{multiplication::Multiply, MulError, MultMessage},
        output::{
            output::{OutputClient, OutputServer},
            OutputError, OutputMessage,
        },
        ran_dou_sha::messages::RanDouShaMessage,
        share_gen::{share_gen::RanShaNode, RanShaError, RanShaMessage},
        triple_gen::{ShamirBeaverTriple, TripleGenError, TripleGenMessage},
    },
};
use ark_ff::FftField;
use ark_std::rand::rngs::{OsRng, StdRng};
use ark_std::rand::{Rng, SeedableRng};
use async_trait::async_trait;
use bincode::ErrorKind;
use double_share_generation::DoubleShareNode;
use ran_dou_sha::{RanDouShaError, RanDouShaNode};
use robust_interpolate::robust_interpolate::RobustShare;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use stoffelnet::network_utils::{Network, NetworkError, PartyId};
use thiserror::Error;
use tokio::sync::{
    mpsc::{self, Receiver},
    Mutex,
};
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
    /// Error during the serialization using [`bincode`].
    #[error("error during the serialization using bincode: {0:?}")]
    BincodeSerializationError(#[from] Box<ErrorKind>),
    #[error("failed to join spawned task")]
    JoinError,
    #[error("output channel closed before result was received")]
    ChannelClosed,
    #[error("error in random bit generation: {0:?}")]
    RandBitError(#[from] RandBitError),
}

pub struct HoneyBadgerMPCClient<F: FftField, R: RBC> {
    pub id: usize,
    pub input: InputClient<F, R>,
    pub output: OutputClient<F>,
}

impl<F: FftField, R: RBC> HoneyBadgerMPCClient<F, R> {
    pub fn new(
        id: usize,
        n: usize,
        t: usize,
        instance_id: u64,
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
pub struct HoneyBadgerMPCNode<F: FftField, R: RBC> {
    /// ID of the current execution node.
    pub id: PartyId,
    /// Preprocessing material used in the protocol execution.
    pub preprocessing_material: Arc<Mutex<HoneyBadgerMPCNodePreprocMaterial<F>>>,
    // Preprocessing parameters.
    pub params: HoneyBadgerMPCNodeOpts,
    pub preprocess: PreprocessNodes<F, R>,
    pub operations: Operation<F, R>,
    pub output: OutputServer,
    pub outputchannels: OutputChannels,
}

#[derive(Clone, Debug)]
pub struct Operation<F: FftField, R: RBC> {
    pub mul: Multiply<F, R>,
}

#[derive(Clone, Debug)]
pub struct PreprocessNodes<F: FftField, R: RBC> {
    // Nodes for subprotocols.
    pub input: InputServer<F, R>,
    pub share_gen: RanShaNode<F, R>,
    pub dou_sha: DoubleShareNode<F>,
    pub ran_dou_sha: RanDouShaNode<F, R>,
    pub triple_gen: TripleGenNode<F>,
    pub rand_bit: RandBit<F, R>,
}

#[derive(Clone, Debug)]
pub struct OutputChannels {
    pub share_gen_channel: Arc<Mutex<Receiver<SessionId>>>,
    pub dou_sha_channel: Arc<Mutex<Receiver<SessionId>>>,
    pub ran_dou_sha_channel: Arc<Mutex<Receiver<SessionId>>>,
    pub triple_channel: Arc<Mutex<Receiver<SessionId>>>,
    pub mul_channel: Arc<Mutex<Receiver<SessionId>>>,
    pub rand_bit_channel: Arc<Mutex<Receiver<SessionId>>>,
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
        n_triples: usize,
    ) -> Result<Vec<ShamirBeaverTriple<F>>, HoneyBadgerError> {
        if n_triples > self.beaver_triples.len() {
            return Err(HoneyBadgerError::NotEnoughPreprocessing);
        }
        Ok(self.beaver_triples.drain(0..n_triples).collect())
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
    pub instance_id: u64,
}

impl HoneyBadgerMPCNodeOpts {
    /// Creates a new struct of initialization options for the HoneyBadgerMPCNode protocol.
    pub fn new(
        n_parties: usize,
        threshold: usize,
        n_triples: usize,
        n_random_shares: usize,
        instance_id: u64,
    ) -> Self {
        Self {
            n_parties,
            threshold,
            n_triples,
            n_random_shares,
            instance_id,
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
        let (share_gen_sender, share_gen_reciever) = mpsc::channel(128);
        let (rand_bit_sender, rand_bit_receiver) = mpsc::channel(128);

        // Create nodes for preprocessing.
        let dousha_node =
            DoubleShareNode::new(id, params.n_parties, params.threshold, dou_sha_sender);
        let rand_bit_node = RandBit::new(id, params.n_parties, params.threshold, rand_bit_sender)?;
        let ran_dou_sha_node = RanDouShaNode::new(
            id,
            ran_dou_sha_sender,
            params.n_parties,
            params.threshold,
            params.threshold + 1,
        )?;

        let triple_gen_node =
            TripleGenNode::new(id, params.n_parties, params.threshold, triple_sender)?;
        let mul_node = Multiply::new(id, params.n_parties, params.threshold, mul_sender)?;
        let share_gen = RanShaNode::new(
            id,
            params.n_parties,
            params.threshold,
            params.threshold + 1,
            share_gen_sender,
        )?;
        let input = InputServer::new(id, params.n_parties, params.threshold)?;
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
                dou_sha: dousha_node,
                ran_dou_sha: ran_dou_sha_node,
                triple_gen: triple_gen_node,
                rand_bit: rand_bit_node,
            },
            operations: Operation { mul: mul_node },
            output,
            outputchannels: OutputChannels {
                share_gen_channel: Arc::new(Mutex::new(share_gen_reciever)),
                dou_sha_channel: Arc::new(Mutex::new(dou_sha_receiver)),
                ran_dou_sha_channel: Arc::new(Mutex::new(ran_dou_sha_receiver)),
                triple_channel: Arc::new(Mutex::new(triple_receiver)),
                mul_channel: Arc::new(Mutex::new(mul_receiver)),
                rand_bit_channel: Arc::new(Mutex::new(rand_bit_receiver)),
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

        let (no_triples, _) = {
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

        let session_id = SessionId::new(ProtocolType::Mul, 0, 0, self.params.instance_id);

        // Call the mul function
        self.operations
            .mul
            .init(session_id, x, y, beaver_triples, network)
            .await?;

        let mut rx = self.outputchannels.mul_channel.lock().await;
        while let Some(id) = rx.recv().await {
            if id == session_id {
                let mul_store = self.operations.mul.mult_storage.lock().await;
                if let Some(mul_lock) = mul_store.get(&id) {
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
                Some(ProtocolType::Input) => {
                    self.preprocess.input.rbc.process(rbc_msg, net).await?
                }
                Some(ProtocolType::Mul) => self.operations.mul.rbc.process(rbc_msg, net).await?,
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
            WrappedMessage::Output(_) => warn!("Incorrect message recieved at process function"),
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
    /// Runs preprocessing to produce Random shares and Beaver triples
    /// Steps:
    /// 1. Ensure enough random shares are available (This includes the ones that will be used for triples).
    /// 2. Generate double shares if missing.
    /// 3. Generate RanDouSha pairs if missing.
    /// 4. Generate Beaver triples from all the above.
    async fn run_preprocessing<G>(
        &mut self,
        network: Arc<N>,
        rng: &mut G,
    ) -> Result<(), Self::Error>
    where
        N: 'async_trait,
        G: Rng + Send,
    {
        // ------------------------
        // Step 1. Ensure random shares
        // ------------------------
        self.ensure_random_shares(network.clone(), rng).await?;
        info!("Random share generation done");

        let (no_of_triples_avail, _) = {
            let store = self.preprocessing_material.lock().await;
            store.len()
        };
        let no_of_triples = self.params.n_triples;
        if no_of_triples_avail >= no_of_triples {
            info!("There are enough Beaver triples");
            return Ok(());
        }

        // ------------------------
        // Step 2. Ensure RanDouSha pair
        // ------------------------
        let ran_dou_sha_pair = self.ensure_ran_dou_sha_pair(network.clone(), rng).await?;
        info!("Randousha pair generation done");

        // ------------------------
        // Step 3. Generate triples
        // ------------------------

        // Take random shares for triples
        let random_shares_a = self
            .preprocessing_material
            .lock()
            .await
            .take_random_shares(no_of_triples)?;
        let random_shares_b = self
            .preprocessing_material
            .lock()
            .await
            .take_random_shares(no_of_triples)?;

        //Outputs 2t+1 triples at a time
        let group_size = 2 * self.params.threshold + 1;
        assert!(no_of_triples % group_size == 0);

        let a_chunks = random_shares_a.chunks_exact(group_size);
        let b_chunks = random_shares_b.chunks_exact(group_size);
        let r_chunks = ran_dou_sha_pair[0..no_of_triples].chunks_exact(group_size);

        for (i, ((a, b), r)) in a_chunks.zip(b_chunks).zip(r_chunks).enumerate() {
            let sessionid =
                SessionId::new(ProtocolType::Triple, 0, i as u8, self.params.instance_id);
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
            if let Some(sid) = self.outputchannels.triple_channel.lock().await.recv().await {
                if sid == sessionid {
                    let mut triple_gen_db = self.preprocess.triple_gen.storage.lock().await;
                    let triple_storage_mutex = triple_gen_db.remove(&sid).unwrap();
                    let triple_storage = triple_storage_mutex.lock().await;
                    let triples = triple_storage.protocol_output.clone();

                    self.preprocessing_material
                        .lock()
                        .await
                        .add(Some(triples), None);
                    self.preprocess
                        .triple_gen
                        .batch_recon_node
                        .clear_store()
                        .await;
                }
            }
        }
        Ok(())
    }
}
impl<F, R> HoneyBadgerMPCNode<F, R>
where
    F: FftField,
    R: RBC,
{
    /// Ensure we have enough random shares by repeatedly running ShareGen if needed.
    async fn ensure_random_shares<G, N>(
        &mut self,
        network: Arc<N>,
        rng: &mut G,
    ) -> Result<(), HoneyBadgerError>
    where
        N: Network + Send + Sync + 'static,
        G: Rng,
    {
        // How many shares are already present?
        let (_, no_shares) = {
            let store = self.preprocessing_material.lock().await;
            store.len()
        };

        // How many more do we need?
        let missing = self.params.n_random_shares.saturating_sub(no_shares);

        // Outputs in batches of (n-2t)
        let batch = self.params.n_parties - 2 * self.params.threshold;
        let run = (missing + batch - 1) / batch; // ceil(missing / batch)

        if run == 0 {
            info!("There are enough random shares");
            return Ok(());
        }

        for i in 0..run {
            info!("Random share generation run {}", i);

            let sessionid =
                SessionId::new(ProtocolType::Ransha, 0, i as u8, self.params.instance_id);

            // Run ShareGen protocol
            self.preprocess
                .share_gen
                .init(sessionid, rng, network.clone())
                .await?;

            // Collect its output
            if let Some(id) = self
                .outputchannels
                .share_gen_channel
                .lock()
                .await
                .recv()
                .await
            {
                if id == sessionid {
                    let mut share_store = self.preprocess.share_gen.store.lock().await;
                    let store_lock = share_store.remove(&id).unwrap();
                    let store = store_lock.lock().await;
                    let output = store.protocol_output.clone();

                    self.preprocessing_material
                        .lock()
                        .await
                        .add(None, Some(output));

                    // Clear RBC store
                    self.preprocess.share_gen.rbc.clear_store().await;
                }
            }
        }

        Ok(())
    }

    /// Ensure we have a RanDouSha pair available, generating double shares if needed.
    async fn ensure_ran_dou_sha_pair<G, N>(
        &mut self,
        network: Arc<N>,
        rng: &mut G,
    ) -> Result<Vec<DoubleShamirShare<F>>, HoneyBadgerError>
    where
        N: Network + Send + Sync + 'static,
        G: Rng + Send,
    {
        let mut pair = Vec::new();

        // How many triples are still missing?
        let (no_of_triples, _) = {
            let store = self.preprocessing_material.lock().await;
            store.len()
        };

        let missing = self.params.n_triples.saturating_sub(no_of_triples);
        // How many batches do we need to cover the missing amount?
        let batch = self.params.threshold + 1;
        let run = (missing + batch - 1) / batch; // ceil(missing / batch)

        for i in 0..run {
            let sessionid =
                SessionId::new(ProtocolType::Randousha, 0, i as u8, self.params.instance_id);

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

            if let Some(sid) = self
                .outputchannels
                .ran_dou_sha_channel
                .lock()
                .await
                .recv()
                .await
            {
                if sid == sessionid {
                    let mut ran_dou_sha_db = self.preprocess.ran_dou_sha.store.lock().await;
                    let ran_dou_sha_storage_mutex = ran_dou_sha_db.remove(&sid).unwrap();
                    let storage = ran_dou_sha_storage_mutex.lock().await;
                    pair.extend(storage.protocol_output.clone());
                    self.preprocess.ran_dou_sha.rbc.clear_store().await;
                }
            }
        }

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

        let mut dou_sha = Vec::new();
        if let Some(sid) = self
            .outputchannels
            .dou_sha_channel
            .lock()
            .await
            .recv()
            .await
        {
            if sid == sessionid {
                let mut dou_sha_db = self.preprocess.dou_sha.storage.lock().await;
                let dou_sha_storage_mutex = dou_sha_db.remove(&sid).unwrap();
                let dou_sha_storage = dou_sha_storage_mutex.lock().await;
                dou_sha = dou_sha_storage.protocol_output.clone();
            }
        }

        Ok(dou_sha)
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
}

//-----------------Session-ID-----------------
//Used for re-routing inter-protocol messages
#[repr(u16)]
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
    RandBit = 9,
}

impl TryFrom<u16> for ProtocolType {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
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
            _ => Err(()),
        }
    }
}

#[derive(Debug, PartialOrd, Ord, Clone, Serialize, Deserialize, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(u64);

impl SessionId {
    pub fn new(caller: ProtocolType, sub_id: u8, round_id: u8, instance_id: u64) -> Self {
        // Ensure instance_id fits in 44 bits
        let instance_id = instance_id & 0x0000_0FFF_FFFF_FFFF;
        let value = ((caller as u64 & 0xF) << 60)
            | ((sub_id as u64 & 0xFF) << 52)
            | ((round_id as u64 & 0xFF) << 44)
            | instance_id;
        SessionId(value)
    }

    //First 4 bits
    pub fn calling_protocol(self) -> Option<ProtocolType> {
        let val = ((self.0 >> 60) & 0xF) as u16;
        ProtocolType::try_from(val).ok()
    }

    //Second 8 bits
    pub fn sub_id(self) -> u8 {
        ((self.0 >> 52) & 0xFF) as u8
    }

    //Third 8 bits
    pub fn round_id(self) -> u8 {
        ((self.0 >> 44) & 0xFF) as u8
    }

    //Last 44 bits
    pub fn instance_id(self) -> u64 {
        self.0 & 0x0000_0FFF_FFFF_FFFF
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }
}
