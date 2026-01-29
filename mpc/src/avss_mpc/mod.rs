use crate::{
    avss_mpc::{
        mul::{multiplication::Multiply, MulError},
        share_gen::{share_gen_avss::RanShaAvssNode, RanShaAvssError},
        triple_gen::{triple_gen::TripleGenNode, BeaverTriple, TripleGenError},
    },
    common::{
        rbc::RbcError,
        share::{avss::AvssError, feldman::FeldmanShamirShare},
        MPCProtocol, PreprocessingMPCProtocol, RBC,
    },
    honeybadger::{ProtocolType, SessionId, WrappedMessage},
};
use ark_ec::CurveGroup;
use ark_ff::{FftField, PrimeField};
use ark_std::rand::{
    rngs::{OsRng, StdRng},
    Rng, SeedableRng,
};
use async_trait::async_trait;
use bincode::ErrorKind;
use std::{sync::Arc, time::Duration};
use stoffelnet::network_utils::{ClientId, Network, NetworkError, PartyId};
use thiserror::Error;
use tokio::sync::{
    mpsc::{self, Receiver},
    Mutex,
};
use tracing::{info, warn};

pub mod mul;
pub mod share_gen;
pub mod triple_gen;

#[derive(Error, Debug)]
pub enum AdkgError {
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
}

#[derive(Clone, Debug)]
/// Configuration options for the AdkgMPCNode protocol.
pub struct AdkgNodeOpts<F, G>
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
}

impl<F, G> AdkgNodeOpts<F, G>
where
    F: FftField,
    G: CurveGroup<ScalarField = F>,
{
    /// Creates a new struct of initialization options for the AdkgMPCNode protocol.
    pub fn new(
        n_parties: usize,
        threshold: usize,
        n_v_random_shares: usize,
        n_triples: usize,
        sk_i: F,
        pk_map: Arc<Vec<G>>,
        instance_id: u32,
    ) -> Self {
        Self {
            n_parties,
            threshold,
            n_v_random_shares,
            n_triples,
            sk_i,
            pk_map,
            instance_id,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AdkgNodePreprocMaterial<F: FftField, G: CurveGroup<ScalarField = F>> {
    /// A pool of verifiable random shares
    v_random_shares: Vec<FeldmanShamirShare<F, G>>,
    /// A pool of beaver triples
    triples: Vec<BeaverTriple<F, G>>,
}

impl<F, G> AdkgNodePreprocMaterial<F, G>
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
    ) -> Result<Vec<FeldmanShamirShare<F, G>>, AdkgError> {
        if n_shares > self.v_random_shares.len() {
            return Err(AdkgError::NotEnoughPreprocessing);
        }
        Ok(self.v_random_shares.drain(0..n_shares).collect())
    }
    pub fn take_triples(&mut self, n_shares: usize) -> Result<Vec<BeaverTriple<F, G>>, AdkgError> {
        if n_shares > self.triples.len() {
            return Err(AdkgError::NotEnoughPreprocessing);
        }
        Ok(self.triples.drain(0..n_shares).collect())
    }
}

/// Information pertaining a AdkgMPCNode protocol participant.
#[derive(Clone, Debug)]
pub struct AdkgNode<F: PrimeField, R: RBC, G: CurveGroup<ScalarField = F>> {
    /// ID of the current execution node.
    pub id: PartyId,
    /// Preprocessing material used in the protocol execution.
    pub preprocessing_material: Arc<Mutex<AdkgNodePreprocMaterial<F, G>>>,
    // Preprocessing parameters.
    pub params: AdkgNodeOpts<F, G>,
    pub share_gen_avss: RanShaAvssNode<F, R, G>,
    pub triple_gen: TripleGenNode<F, R, G>,
    pub mul_node: Multiply<F, R, G>,
    pub share_gen_avss_channel: Arc<Mutex<Receiver<SessionId>>>,
    pub triple_channel: Arc<Mutex<Receiver<SessionId>>>,
    pub counters: SubProtocolCounters,
}

#[derive(Clone, Debug)]
pub struct SubProtocolCounter(Arc<Mutex<Option<u8>>>);

trait GetNext<T> {
    async fn get_next(&self) -> Result<T, AdkgError>;
}

impl GetNext<u8> for SubProtocolCounter {
    async fn get_next(&self) -> Result<u8, AdkgError> {
        let mut counter = self.0.lock().await;

        match &mut *counter {
            None => Err(AdkgError::LimitError),
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
}

impl SubProtocolCounters {
    pub fn new() -> Self {
        Self {
            ran_sha_avss_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            triple_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            mul_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
        }
    }
}

#[async_trait]
impl<F, R, N, G> MPCProtocol<F, FeldmanShamirShare<F, G>, N> for AdkgNode<F, R, G>
where
    N: Network + Send + Sync + 'static,
    F: PrimeField,
    R: RBC,
    G: CurveGroup<ScalarField = F>,
{
    type MPCOpts = AdkgNodeOpts<F, G>;
    type Error = AdkgError;

    fn setup(
        id: PartyId,
        params: Self::MPCOpts,
        _input_ids: Vec<ClientId>,
    ) -> Result<Self, AdkgError> {
        let (share_gen_avss_sender, share_gen_avss_reciever) = mpsc::channel(128);
        let (triple_sender, triple_reciever) = mpsc::channel(128);

        let share_gen_avss = RanShaAvssNode::new(
            id,
            params.n_parties,
            params.threshold,
            params.sk_i,
            params.pk_map.clone(),
            share_gen_avss_sender,
        )?;

        let triple_gen = TripleGenNode::new(
            id,
            params.n_parties,
            params.threshold,
            params.sk_i,
            params.pk_map.clone(),
            triple_sender,
        )?;
        let mul_node = Multiply::new(id, params.n_parties, params.threshold)?;
        Ok(Self {
            id,
            preprocessing_material: Arc::new(Mutex::new(AdkgNodePreprocMaterial::empty())),
            params,
            share_gen_avss,
            triple_gen,
            mul_node,
            share_gen_avss_channel: Arc::new(Mutex::new(share_gen_avss_reciever)),
            triple_channel: Arc::new(Mutex::new(triple_reciever)),
            counters: SubProtocolCounters::new(),
        })
    }
    async fn process(
        &mut self,
        sender_id: PartyId,
        raw_msg: Vec<u8>,
        net: Arc<N>,
    ) -> Result<(), Self::Error> {
        let wrapped: WrappedMessage = bincode::deserialize(&raw_msg)?;
        match wrapped {
            WrappedMessage::Rbc(rbc_msg) => {
                if sender_id != rbc_msg.sender_id {
                    return Err(AdkgError::InvalidPartyId);
                }
                if rbc_msg.session_id.instance_id() != self.params.instance_id {
                    return Err(AdkgError::InstanceIdError(rbc_msg.session_id.instance_id()));
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
                    _ => {
                        warn!(
                            "Unknown protocol ID in session ID: {:?} in RBC",
                            rbc_msg.session_id
                        );
                    }
                }
            }
            WrappedMessage::Mul(mul_message) => {
                if sender_id != mul_message.sender {
                    return Err(AdkgError::InvalidPartyId);
                }
                if mul_message.session_id.instance_id() != self.params.instance_id {
                    return Err(AdkgError::InstanceIdError(
                        mul_message.session_id.instance_id(),
                    ));
                }
                self.mul_node.process(mul_message).await?
            }

            _ => {
                warn!("Unknown session ID in ADKG",);
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

        let session_id = SessionId::new(
            ProtocolType::Mul,
            self.counters.mul_counter.get_next().await?,
            0,
            0,
            self.params.instance_id,
        );

        // Call the mul function
        self.mul_node
            .init(session_id, x, y, beaver_triples, network)
            .await?;

        self.mul_node
            .wait_for_result(session_id, Duration::MAX)
            .await
            .map_err(AdkgError::from)
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
impl<F, R, N, C> PreprocessingMPCProtocol<F, FeldmanShamirShare<F, C>, N> for AdkgNode<F, R, C>
where
    N: Network + Send + Sync + 'static,
    F: PrimeField,
    R: RBC,
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
                return Err(AdkgError::LimitError);
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
                let sessionid = SessionId::new(
                    ProtocolType::Triple,
                    triple_counter,
                    0,
                    round_id,
                    self.params.instance_id,
                );
                self.triple_gen
                    .gen_triple(sessionid, a.to_vec(), b.to_vec(), rng, network.clone())
                    .await?;

                // ------------------------
                // Step 4. Collect triples
                // ------------------------
                if let Some(sid) = self.triple_channel.lock().await.recv().await {
                    if sid == sessionid {
                        let mut triple_gen_db = self.triple_gen.store.lock().await;
                        let triple_storage_mutex = triple_gen_db.remove(&sid).unwrap();
                        let triple_storage = triple_storage_mutex.lock().await;
                        let triples = triple_storage.output.clone();

                        self.preprocessing_material.lock().await.add(triples, None);
                    }
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

impl<F, R, C> AdkgNode<F, R, C>
where
    F: PrimeField,
    R: RBC,
    C: CurveGroup<ScalarField = F>,
{
    async fn ensure_v_random_shares<G, N>(
        &mut self,
        network: Arc<N>,
        rng: &mut G,
        needed: usize,
    ) -> Result<(), AdkgError>
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
            return Err(AdkgError::LimitError);
        }

        for i in 0..run {
            info!("Verifiable random share generation run {}", i);
            let sessionid = SessionId::new(
                ProtocolType::Avss,
                v_ran_sha_counter,
                0,
                round_id,
                self.params.instance_id,
            );

            // Run ShareGen protocol
            self.share_gen_avss
                .init(sessionid, rng, network.clone())
                .await?;

            // Collect its output
            if let Some(id) = self.share_gen_avss_channel.lock().await.recv().await {
                if id == sessionid {
                    let output = self.share_gen_avss.output(id).await;
                    self.preprocessing_material
                        .lock()
                        .await
                        .add(None, Some(output));
                }
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
