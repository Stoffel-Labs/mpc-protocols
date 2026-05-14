use crate::{
    avss_mpc::{
        input::{
            input::{AvssInputClient, AvssInputServer},
            AvssInputError, AvssInputMessage,
        },
        mul::{deser_bounded_vec, multiplication::Multiply, MulError, MultMessage},
        output::{
            output::{AvssOutputClient, AvssOutputServer},
            AvssOutputError, AvssOutputMessage,
        },
        share_gen::{share_gen_avss::RanShaAvssNode, RanShaAvssError},
        triple_gen::{triple_gen::TripleGenNode, BeaverTriple, TripleGenError},
    },
    common::{
        rbc::{rbc_store::Msg, RbcError},
        share::{
            avss::{AvssError, AvssMessage},
            feldman::FeldmanShamirShare,
            shamir::Shamirshare,
        },
        MPCProtocol, PreprocessingMPCProtocol, ProtocolSessionId, ProtocolTag, RBC,
    },
};
use ark_ec::CurveGroup;
use ark_ff::{FftField, PrimeField};
use ark_serialize::{CanonicalDeserialize, SerializationError};
use ark_std::rand::{
    rngs::{OsRng, StdRng},
    Rng, SeedableRng,
};
use async_trait::async_trait;
use bincode::{ErrorKind, Options};
use serde::{Deserialize, Serialize};
use std::{fmt, sync::Arc, time::Duration};
use stoffelnet::network_utils::{ClientId, Network, NetworkError, PartyId};
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::{info, warn};
const MAX_MESSAGE_SIZE: u64 = 10 * 1024 * 1024; // 10 MiB

pub mod input;
pub mod mul;
pub mod output;
pub mod share_gen;
pub mod triple_gen;

#[derive(Error, Debug)]
pub enum AvssMPCError {
    #[error("network error: {0:?}")]
    NetworkError(#[from] NetworkError),
    #[error("there is not enough preprocessing to complete the protocol")]
    NotEnoughPreprocessing,
    #[error("Already reserved batch")]
    AlreadyReserved,
    #[error("Not Supported")]
    NotSupported,
    #[error("error in share generation: {0:?}")]
    RanShaAvssError(#[from] RanShaAvssError),
    #[error("error in avss generation: {0:?}")]
    AvssError(#[from] AvssError),
    #[error("error in the RBC: {0:?}")]
    RbcError(#[from] RbcError),
    /// Error during the serialization using [`bincode`].
    #[error("error during the serialization using bincode: {0:?}")]
    BincodeSerializationError(#[from] Box<ErrorKind>),
    #[error("failed to join spawned task")]
    JoinError,
    #[error("output channel closed before result was received")]
    ChannelClosed,
    #[error("error in the Mul: {0:?}")]
    MulError(#[from] MulError),
    #[error("error in triple generation protocol: {0:?}")]
    TripleGenError(#[from] TripleGenError),
    #[error("the protocol cannot be executed any more")]
    LimitError,
    #[error("instance ID {0:?} is incorrect")]
    InstanceIdError(u32),
    #[error("Party Id is out of bounds")]
    InvalidPartyId,
    #[error("Invalid threshold t={0} for n={1}, must satisfy t < ceil(n / 3)")]
    InvalidThreshold(usize, usize),
    #[error("Party size is too large")]
    InvalidPartySize,
    #[error("error in Input: {0:?}")]
    InputError(#[from] AvssInputError),
    #[error("error in Output: {0:?}")]
    OutputError(#[from] AvssOutputError),
}

pub struct AvssMPCClient<F: FftField, R: RBC, G: CurveGroup<ScalarField = F>> {
    pub id: usize,
    pub input: AvssInputClient<F, R, G>,
    pub output: AvssOutputClient<F, G>,
}

// implement manually because derive(Clone) requires R: Clone, which is not needed at all
impl<F, R, G> Clone for AvssMPCClient<F, R, G>
where
    F: FftField,
    R: RBC,
    G: CurveGroup<ScalarField = F>,
{
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            input: self.input.clone(),
            output: self.output.clone(),
        }
    }
}

impl<F: FftField, R: RBC<Id = AvssSessionId>, G: CurveGroup<ScalarField = F>>
    AvssMPCClient<F, R, G>
{
    pub fn new(
        id: usize,
        n: usize,
        t: usize,
        instance_id: u32,
        inputs: Vec<F>,
        input_len: usize,
    ) -> Result<Self, AvssMPCError> {
        let input = AvssInputClient::new(id, n, t, instance_id, inputs)?;
        let output = AvssOutputClient::new(id, n, t, input_len)?;
        Ok(Self { id, input, output })
    }

    pub async fn process<N: Network + Send + Sync>(
        &mut self,
        sender_id: ClientId,
        raw_msg: Vec<u8>,
        net: Arc<N>,
    ) -> Result<(), AvssMPCError> {
        let wrapped: AvssWrappedMessage = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_limit(MAX_MESSAGE_SIZE)
            .deserialize(&raw_msg)?;

        match wrapped {
            AvssWrappedMessage::Input(input_msg) => {
                if sender_id != input_msg.sender_id {
                    return Err(AvssMPCError::InvalidPartyId);
                }
                self.input.process(input_msg, net).await?;
            }
            AvssWrappedMessage::Output(output_msg) => {
                if sender_id != output_msg.sender_id {
                    return Err(AvssMPCError::InvalidPartyId);
                }
                self.output.process(output_msg).await?
            }
            _ => warn!("Incorrect message type received at client"),
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
/// Configuration options for the AvssMPCNode protocol.
pub struct AvssMPCNodeOpts<F, G>
where
    F: FftField,
    G: CurveGroup<ScalarField = F>,
{
    pub sk_i: F,
    pub pk_map: Arc<Vec<G>>,
    /// Number of parties in the protocol.
    pub n_parties: usize,
    /// Upper bound of corrupt parties.
    pub threshold: usize,
    /// Number of random double sharing pairs that need to be generated.
    pub n_v_random_shares: usize,
    pub n_triples: usize,
    /// Instance ID
    pub instance_id: u32,
    pub timeout: Duration,
}

impl<F, G> AvssMPCNodeOpts<F, G>
where
    F: FftField,
    G: CurveGroup<ScalarField = F>,
{
    /// Creates a new struct of initialization options for the AvssMPCNode protocol.
    pub fn new(
        n_parties: usize,
        threshold: usize,
        n_v_random_shares: usize,
        n_triples: usize,
        sk_i: F,
        pk_map: Arc<Vec<G>>,
        instance_id: u32,
        timeout: Duration,
    ) -> Result<Self, AvssMPCError> {
        //No of parties should not exceed 255
        if n_parties > 255 {
            return Err(AvssMPCError::InvalidPartySize);
        }
        if !(threshold < (n_parties + 2) / 3) {
            // ceil(n / 3)
            return Err(AvssMPCError::InvalidThreshold(threshold, n_parties));
        }
        Ok(Self {
            n_parties,
            threshold,
            n_v_random_shares,
            n_triples,
            sk_i,
            pk_map,
            instance_id,
            timeout,
        })
    }
    pub fn set_timeout(&mut self, secs: u64) {
        self.timeout = Duration::from_secs(secs)
    }
}

#[derive(Clone, Debug)]
pub struct AvssMPCNodePreprocMaterial<F: FftField, G: CurveGroup<ScalarField = F>> {
    /// A pool of verifiable random shares
    v_random_shares: Vec<FeldmanShamirShare<F, G>>,
    /// A pool of beaver triples
    triples: Vec<BeaverTriple<F, G>>,
}

impl<F, G> AvssMPCNodePreprocMaterial<F, G>
where
    F: FftField,
    G: CurveGroup<ScalarField = F>,
{
    /// Generates empty preprocessing material storage.
    pub fn empty() -> Self {
        Self {
            v_random_shares: Vec::new(),
            triples: Vec::new(),
        }
    }
    /// Adds the provided new preprocessing material to the current pool.
    pub fn add(
        &mut self,
        mut triples: Option<Vec<BeaverTriple<F, G>>>,
        mut v_random_shares: Option<Vec<FeldmanShamirShare<F, G>>>,
    ) {
        if let Some(shares) = &mut v_random_shares {
            self.v_random_shares.append(shares);
        }
        if let Some(shares) = &mut triples {
            self.triples.append(shares);
        }
    }
    /// Returns the number of triples, and the number of random shares
    /// respectively.
    pub fn len(&self) -> (usize, usize) {
        (self.triples.len(), self.v_random_shares.len())
    }
    pub fn take_v_random_shares(
        &mut self,
        n_shares: usize,
    ) -> Result<Vec<FeldmanShamirShare<F, G>>, AvssMPCError> {
        if n_shares > self.v_random_shares.len() {
            return Err(AvssMPCError::NotEnoughPreprocessing);
        }
        Ok(self.v_random_shares.drain(0..n_shares).collect())
    }
    pub fn take_triples(
        &mut self,
        n_shares: usize,
    ) -> Result<Vec<BeaverTriple<F, G>>, AvssMPCError> {
        if n_shares > self.triples.len() {
            return Err(AvssMPCError::NotEnoughPreprocessing);
        }
        Ok(self.triples.drain(0..n_shares).collect())
    }
}

/// Information pertaining a AvssMPCNode protocol participant.
#[derive(Clone, Debug)]
pub struct AvssMPCNode<F: PrimeField, R: RBC, G: CurveGroup<ScalarField = F>> {
    /// ID of the current execution node.
    pub id: PartyId,
    /// Preprocessing material used in the protocol execution.
    pub preprocessing_material: Arc<Mutex<AvssMPCNodePreprocMaterial<F, G>>>,
    // Preprocessing parameters.
    pub params: AvssMPCNodeOpts<F, G>,
    pub share_gen_avss: RanShaAvssNode<F, R, G>,
    pub triple_gen: TripleGenNode<F, R, G>,
    pub mul_node: Multiply<F, R, G>,
    pub input_server: AvssInputServer<F, R, G>,
    pub output_server: AvssOutputServer,
    pub counters: SubProtocolCounters,
}

#[derive(Clone, Debug)]
pub struct SubProtocolCounter(Arc<Mutex<Option<u8>>>);

trait GetNext<T> {
    async fn get_next(&self) -> Result<T, AvssMPCError>;
}

impl GetNext<u8> for SubProtocolCounter {
    async fn get_next(&self) -> Result<u8, AvssMPCError> {
        let mut counter = self.0.lock().await;

        match &mut *counter {
            None => Err(AvssMPCError::LimitError),
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
/// Since the exec ID is a `u8`, the counter is an `AtomicU8`.
#[derive(Clone, Debug)]
pub struct SubProtocolCounters {
    pub ran_sha_avss_counter: SubProtocolCounter,
    pub triple_counter: SubProtocolCounter,
    pub mul_counter: SubProtocolCounter,
    pub input_counter: SubProtocolCounter,
}

impl SubProtocolCounters {
    pub fn new() -> Self {
        Self {
            ran_sha_avss_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            triple_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            mul_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            input_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
        }
    }
}

#[async_trait]
impl<F, R, N, G> MPCProtocol<F, FeldmanShamirShare<F, G>, N> for AvssMPCNode<F, R, G>
where
    N: Network + Send + Sync + 'static,
    F: PrimeField,
    R: RBC<Id = AvssSessionId>,
    G: CurveGroup<ScalarField = F>,
{
    type MPCOpts = AvssMPCNodeOpts<F, G>;
    type Error = AvssMPCError;

    fn setup(
        id: PartyId,
        params: Self::MPCOpts,
        input_ids: Vec<ClientId>,
    ) -> Result<Self, AvssMPCError> {
        if id >= params.n_parties {
            return Err(AvssMPCError::InvalidPartyId);
        }
        let share_gen_avss = RanShaAvssNode::new(
            id,
            params.n_parties,
            params.threshold,
            params.sk_i,
            params.pk_map.clone(),
        )?;

        let triple_gen = TripleGenNode::new(
            id,
            params.n_parties,
            params.threshold,
            params.sk_i,
            params.pk_map.clone(),
        )?;
        let mul_node = Multiply::new(id, params.n_parties, params.threshold)?;
        let input_server = AvssInputServer::new(id, params.n_parties, params.threshold, input_ids)?;
        let output_server = AvssOutputServer::new(id, params.n_parties)?;
        Ok(Self {
            id,
            preprocessing_material: Arc::new(Mutex::new(AvssMPCNodePreprocMaterial::empty())),
            params,
            share_gen_avss,
            triple_gen,
            mul_node,
            input_server,
            output_server,
            counters: SubProtocolCounters::new(),
        })
    }
    async fn process(
        &mut self,
        sender_id: PartyId,
        raw_msg: Vec<u8>,
        net: Arc<N>,
    ) -> Result<(), Self::Error> {
        let wrapped: AvssWrappedMessage = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_limit(MAX_MESSAGE_SIZE)
            .deserialize(&raw_msg)?;
        match wrapped {
            AvssWrappedMessage::Rbc(rbc_msg) => {
                if sender_id != rbc_msg.sender_id {
                    return Err(AvssMPCError::InvalidPartyId);
                }
                if rbc_msg.session_id.instance_id() != self.params.instance_id {
                    return Err(AvssMPCError::InstanceIdError(
                        rbc_msg.session_id.instance_id(),
                    ));
                }
                if rbc_msg.msg_type.is_dealer_message() {
                    let expected_dealer = rbc_msg.session_id.sub_id() as usize;
                    if rbc_msg.sender_id != expected_dealer {
                        warn!(
                            "Rejecting dealer message: 
                            sender {} is not expected dealer {} for session {:?}",
                            rbc_msg.sender_id, expected_dealer, rbc_msg.session_id
                        );
                        return Err(AvssMPCError::InvalidPartyId);
                    }
                }

                match rbc_msg.session_id.calling_protocol() {
                    Some(ProtocolType::Avss) => {
                        self.share_gen_avss.avss.rbc.process(rbc_msg, net).await?;
                        self.share_gen_avss.avss.drain_rbc_output().await?;
                    }
                    Some(ProtocolType::Triple) => {
                        self.triple_gen.avss.rbc.process(rbc_msg, net).await?;
                        self.triple_gen.avss.drain_rbc_output().await?;
                    }
                    Some(ProtocolType::Mul) => {
                        self.mul_node.rbc.process(rbc_msg, net).await?;
                        self.mul_node.drain_rbc_output().await?;
                    }
                    Some(ProtocolType::Input) => {
                        self.input_server.rbc.process(rbc_msg, net).await?;
                        self.input_server.drain_rbc_output().await?;
                    }
                    _ => {
                        warn!(
                            "Unknown protocol ID in session ID: {:?} in RBC",
                            rbc_msg.session_id
                        );
                    }
                }
            }
            AvssWrappedMessage::Avss(_) => {
                warn!("Incorrect message received at process function (Avss)");
            }
            AvssWrappedMessage::Mul(_) => {
                warn!("Incorrect message received at process function (Input)");
            }
            AvssWrappedMessage::Input(_) => {
                warn!("Incorrect message received at process function (Input)");
            }
            AvssWrappedMessage::Output(_) => {
                warn!("Incorrect message received at process function (Output)");
            }
        }

        Ok(())
    }

    async fn mul(
        &mut self,
        x: Vec<FeldmanShamirShare<F, G>>,
        y: Vec<FeldmanShamirShare<F, G>>,
        network: Arc<N>,
    ) -> Result<Vec<FeldmanShamirShare<F, G>>, Self::Error>
    where
        N: 'async_trait,
    {
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
            .take_triples(x.len())?;

        let session_id = AvssSessionId::new(
            ProtocolType::Mul,
            AvssSessionId::pack_slot24(self.counters.mul_counter.get_next().await?, 0, 0),
            self.params.instance_id,
        );

        // Call the mul function
        self.mul_node
            .init(session_id, x, y, beaver_triples, network)
            .await?;

        self.mul_node
            .wait_for_result(session_id, self.params.timeout)
            .await
            .map_err(AvssMPCError::from)
    }
    async fn rand(&mut self, network: Arc<N>) -> Result<FeldmanShamirShare<F, G>, Self::Error> {
        let no_rand = {
            let store = self.preprocessing_material.lock().await;
            store.len()
        };
        if no_rand.1 == 0 {
            //Run preprocessing
            let mut rng = StdRng::from_rng(OsRng).unwrap();
            self.run_preprocessing(network.clone(), &mut rng).await?;
        }
        // Extract the preprocessing triple.
        let rand_value = self
            .preprocessing_material
            .lock()
            .await
            .take_v_random_shares(1)?;
        Ok(rand_value[0].clone())
    }
}

#[async_trait]
impl<F, R, N, C> PreprocessingMPCProtocol<F, FeldmanShamirShare<F, C>, N> for AvssMPCNode<F, R, C>
where
    N: Network + Send + Sync + 'static,
    F: PrimeField,
    R: RBC<Id = AvssSessionId>,
    C: CurveGroup<ScalarField = F>,
{
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
        let (no_of_triples_avail, no_of_random_shares_avail) = {
            let store = self.preprocessing_material.lock().await;
            store.len()
        };

        // Desired total counts from protocol parameters
        let mut no_of_triples = self.params.n_triples;
        let mut no_of_random_shares = self.params.n_v_random_shares;

        let group_size = self.params.n_parties;
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
                return Err(AvssMPCError::LimitError);
            }

            // ------------------------
            // Step 1. Ensure random shares
            // ------------------------
            self.ensure_v_random_shares(network.clone(), rng, total_random_shares_to_generate)
                .await?;
            info!("Random share generation done");

            // ------------------------
            // Step 2. Generate triples
            // ------------------------

            // Take random shares for triples
            let random_shares_a = self
                .preprocessing_material
                .lock()
                .await
                .take_v_random_shares(total_triples_to_generate)?;
            let random_shares_b = self
                .preprocessing_material
                .lock()
                .await
                .take_v_random_shares(total_triples_to_generate)?;

            let a_chunks = random_shares_a.chunks_exact(group_size);
            let b_chunks = random_shares_b.chunks_exact(group_size);
            let mut round_id = 0u8;

            for (a, b) in a_chunks.zip(b_chunks) {
                let sessionid = AvssSessionId::new(
                    ProtocolType::Triple,
                    AvssSessionId::pack_slot24(triple_counter, 0, round_id),
                    self.params.instance_id,
                );
                let triples = self
                    .triple_gen
                    .gen_triple(sessionid, a.to_vec(), b.to_vec(), rng, network.clone())
                    .await?;

                // ------------------------
                // Step 4. Collect triples
                // ------------------------
                {
                    self.preprocessing_material
                        .lock()
                        .await
                        .add(Some(triples), None);
                }
                if round_id == 255 {
                    triple_counter = self.counters.triple_counter.get_next().await.unwrap();
                    round_id = 0;
                } else {
                    round_id += 1;
                }
            }
        }
        Ok(())
    }
}

impl<F, R, C> AvssMPCNode<F, R, C>
where
    F: PrimeField,
    R: RBC<Id = AvssSessionId>,
    C: CurveGroup<ScalarField = F>,
{
    async fn ensure_v_random_shares<G, N>(
        &mut self,
        network: Arc<N>,
        rng: &mut G,
        needed: usize,
    ) -> Result<(), AvssMPCError>
    where
        N: Network + Send + Sync + 'static,
        G: Rng + Send,
    {
        // Outputs in batches of (n-2t)
        let batch = self.params.n_parties - 2 * self.params.threshold;
        let run = (needed + batch - 1) / batch; // ceil(missing / batch)
        let mut round_id = 0u8;
        let mut v_ran_sha_counter = self.counters.ran_sha_avss_counter.get_next().await?;

        if (256 - v_ran_sha_counter as usize) * 255 < run {
            return Err(AvssMPCError::LimitError);
        }

        for i in 0..run {
            info!("Verifiable random share generation run {}", i);
            let sessionid = AvssSessionId::new(
                ProtocolType::Avss,
                AvssSessionId::pack_slot24(v_ran_sha_counter, 0, round_id),
                self.params.instance_id,
            );

            // Run ShareGen protocol
            self.share_gen_avss
                .init(sessionid, rng, network.clone())
                .await?;

            // Collect its output
            let output = self
                .share_gen_avss
                .wait_for_result(sessionid, self.params.timeout)
                .await?;
            {
                self.preprocessing_material
                    .lock()
                    .await
                    .add(None, Some(output));
            }
            if round_id == 255 {
                v_ran_sha_counter = self.counters.ran_sha_avss_counter.get_next().await?;
                round_id = 0;
            } else {
                round_id += 1;
            }
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum AvssWrappedMessage {
    Rbc(Msg<AvssSessionId>),
    Avss(AvssMessage<AvssSessionId>),
    Mul(MultMessage),
    Input(AvssInputMessage),
    Output(AvssOutputMessage),
}

impl AvssWrappedMessage {
    pub fn rbc_wrap(msg: Msg<AvssSessionId>) -> Result<Vec<u8>, RbcError> {
        let wrapped = AvssWrappedMessage::Rbc(msg);
        Ok(bincode::serialize(&wrapped)?)
    }

    pub fn avss_wrap(msg: AvssMessage<AvssSessionId>) -> Result<Vec<u8>, RbcError> {
        let wrapped = AvssWrappedMessage::Avss(msg);
        Ok(bincode::serialize(&wrapped)?)
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ProtocolType {
    None = 0,
    Rbc = 1,
    Avss = 2,
    Triple = 3,
    Mul = 4,
    Input = 5,
    Output = 6,
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
            1 => Some(Self::Rbc),
            2 => Some(Self::Avss),
            3 => Some(Self::Triple),
            4 => Some(Self::Mul),
            5 => Some(Self::Input),
            6 => Some(Self::Output),

            _ => None,
        }
    }
}

#[derive(PartialOrd, Ord, Clone, Serialize, Deserialize, Copy, PartialEq, Eq, Hash)]
pub struct AvssSessionId(u64);

impl fmt::Debug for AvssSessionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let caller = (self.0 >> 56) as u8;
        let slot24 = self.slot24();
        let instance_id = self.instance_id();

        write!(
            f,
            "[caller={},slot24_id={},instance_id={}]",
            caller, slot24, instance_id
        )
    }
}
impl ProtocolSessionId for AvssSessionId {
    type Protocol = ProtocolType;

    fn new(protocol: ProtocolType, slot24: u32, instance_id: u32) -> Self {
        let value = ((protocol as u64 & 0xFF) << 56)
            | ((slot24 as u64 & 0xFF_FFFF) << 32)
            | (instance_id as u64);

        AvssSessionId(value)
    }

    fn calling_protocol(self) -> Option<ProtocolType> {
        let val = ((self.0 >> 56) & 0xFF) as u8;
        ProtocolType::from_u8(val)
    }

    fn slot24(self) -> u32 {
        ((self.0 >> 32) & 0xFF_FFFF) as u32
    }

    fn instance_id(self) -> u32 {
        self.0 as u32
    }

    fn as_u64(self) -> u64 {
        self.0
    }
    //Unsafe because this is meant for the FFI
    //The caller must ensure that the u64 is well-formed
    unsafe fn from_u64(id: u64) -> Self {
        AvssSessionId(id)
    }
}

impl AvssSessionId {
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

pub fn deser_bounded_feldman_vec<F, G>(
    r: &mut &[u8],
    max_outer: usize,
    max_commitments: usize,
) -> Result<Vec<FeldmanShamirShare<F, G>>, SerializationError>
where
    F: FftField,
    G: CurveGroup<ScalarField = F>,
{
    if r.len() < 8 {
        return Err(SerializationError::InvalidData);
    }
    let (head, tail) = r.split_at(8);
    let len = u64::from_le_bytes(head.try_into().unwrap()) as usize;
    if len > max_outer {
        return Err(SerializationError::InvalidData);
    }
    *r = tail;
    (0..len)
        .map(|_| {
            let feldmanshare = Shamirshare::<F>::deserialize_compressed(&mut *r)?;
            let commitments = deser_bounded_vec::<G>(r, max_commitments)?;
            Ok(FeldmanShamirShare {
                feldmanshare,
                commitments,
            })
        })
        .collect()
}
