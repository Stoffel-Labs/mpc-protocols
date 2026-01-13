use crate::{
    adkg::share_gen::{share_gen_avss::RanShaAvssNode, RanShaAvssError},
    common::{
        rbc::RbcError,
        share::{
            avss::{AvssError, FeldmanShamirShare},
            shamir::Shamirshare,
        },
        MPCProtocol, PreprocessingMPCProtocol, SecretKey, ADKG, RBC,
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
use std::sync::{
    atomic::{AtomicU8, Ordering},
    Arc,
};
use stoffelnet::network_utils::{ClientId, Network, NetworkError, PartyId};
use thiserror::Error;
use tokio::sync::{
    mpsc::{self, Receiver},
    Mutex,
};
use tracing::{info, warn};

pub mod share_gen;

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
}

#[derive(Clone, Debug)]
/// Configuration options for the HoneyBadgerMPCNode protocol.
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
    /// Instance ID
    pub instance_id: u32,
}

impl<F, G> AdkgNodeOpts<F, G>
where
    F: FftField,
    G: CurveGroup<ScalarField = F>,
{
    /// Creates a new struct of initialization options for the HoneyBadgerMPCNode protocol.
    pub fn new(
        n_parties: usize,
        threshold: usize,
        n_v_random_shares: usize,
        sk_i: F,
        pk_map: Arc<Vec<G>>,
        instance_id: u32,
    ) -> Self {
        Self {
            n_parties,
            threshold,
            n_v_random_shares,
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
        }
    }
    /// Adds the provided new preprocessing material to the current pool.
    pub fn add(&mut self, mut v_random_shares: Option<Vec<FeldmanShamirShare<F, G>>>) {
        if let Some(shares) = &mut v_random_shares {
            self.v_random_shares.append(shares);
        }
    }
    /// Returns the number of random double share pairs, and the number of random shares
    /// respectively.
    pub fn len(&self) -> usize {
        self.v_random_shares.len()
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
}

/// Information pertaining a HoneyBadgerMPCNode protocol participant.
#[derive(Clone, Debug)]
pub struct AdkgNode<F: PrimeField, R: RBC, G: CurveGroup<ScalarField = F>> {
    /// ID of the current execution node.
    pub id: PartyId,
    /// Preprocessing material used in the protocol execution.
    pub preprocessing_material: Arc<Mutex<AdkgNodePreprocMaterial<F, G>>>,
    // Preprocessing parameters.
    pub params: AdkgNodeOpts<F, G>,
    pub share_gen_avss: RanShaAvssNode<F, R, G>,
    pub share_gen_avss_channel: Arc<Mutex<Receiver<SessionId>>>,
    pub counters: SubProtocolCounters,
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
    pub ran_sha_avss_counter: SubProtocolCounter,
}

impl SubProtocolCounters {
    pub fn new() -> Self {
        Self {
            ran_sha_avss_counter: SubProtocolCounter(Arc::new(AtomicU8::new(0))),
        }
    }
}

#[async_trait]
impl<F, R, N, G> MPCProtocol<F, Shamirshare<F>, N> for AdkgNode<F, R, G>
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
        let share_gen_avss = RanShaAvssNode::new(
            id,
            params.n_parties,
            params.threshold,
            params.threshold + 1,
            params.sk_i,
            params.pk_map.clone(),
            share_gen_avss_sender,
        )?;

        Ok(Self {
            id,
            preprocessing_material: Arc::new(Mutex::new(AdkgNodePreprocMaterial::empty())),
            params,
            share_gen_avss,
            share_gen_avss_channel: Arc::new(Mutex::new(share_gen_avss_reciever)),
            counters: SubProtocolCounters::new(),
        })
    }
    async fn process(&mut self, raw_msg: Vec<u8>, net: Arc<N>) -> Result<(), Self::Error> {
        let wrapped: WrappedMessage = bincode::deserialize(&raw_msg)?;
        match wrapped {
            WrappedMessage::Rbc(rbc_msg) => match rbc_msg.session_id.calling_protocol() {
                Some(ProtocolType::Avss) => {
                    self.share_gen_avss.avss.rbc.process(rbc_msg, net).await?
                }
                _ => {
                    warn!(
                        "Unknown protocol ID in session ID: {:?} in RBC",
                        rbc_msg.session_id
                    );
                }
            },
            WrappedMessage::Avss(avss_message) => {
                self.share_gen_avss.avss.process(avss_message).await?;
            }
            _ => {
                warn!("Unknown session ID in ADKG",);
            }
        }

        Ok(())
    }

    async fn mul(
        &mut self,
        _a: Vec<Shamirshare<F>>,
        _b: Vec<Shamirshare<F>>,
        _network: Arc<N>,
    ) -> Result<Vec<Shamirshare<F>>, Self::Error>
    where
        N: 'async_trait,
    {
        Err(AdkgError::NotSupported)
    }
    async fn rand(&mut self, network: Arc<N>) -> Result<Shamirshare<F>, Self::Error> {
        let no_rand = {
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
            .take_v_random_shares(1)?;
        Ok(rand_value[0].feldmanshare.clone())
    }
}

#[async_trait]
impl<F, N, R, G> ADKG<F, FeldmanShamirShare<F, G>, Shamirshare<F>, N, G> for AdkgNode<F, R, G>
where
    F: PrimeField,
    N: Network + Send + Sync + 'static,
    R: RBC,
    G: CurveGroup<ScalarField = F>,
{
    async fn secret_key(
        &mut self,
        no_of_keys: usize,
        network: Arc<N>,
    ) -> Result<Vec<FeldmanShamirShare<F, G>>, Self::Error> {
        let no_vrand = {
            let store = self.preprocessing_material.lock().await;
            store.len()
        };
        if no_vrand == 0 {
            //Run preprocessing
            let mut rng = StdRng::from_rng(OsRng).unwrap();
            self.run_preprocessing(network.clone(), &mut rng).await?;
        }

        let vrand_shares = self
            .preprocessing_material
            .lock()
            .await
            .take_v_random_shares(no_of_keys)?;

        Ok(vrand_shares.clone())
    }
    async fn public_key(
        &self,
        secret_keys: Vec<FeldmanShamirShare<F, G>>,
        _net: Arc<N>,
    ) -> Result<Vec<G>, Self::Error> {
        let commitments: Vec<_> = secret_keys.iter().map(|k| k.get_commitment()[0]).collect();
        Ok(commitments)
    }
}

#[async_trait]
impl<F, R, N, C> PreprocessingMPCProtocol<F, Shamirshare<F>, N> for AdkgNode<F, R, C>
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
        // ------------------------
        // Generate Verifiable Random share
        // ------------------------
        self.ensure_v_random_shares(network.clone(), rng).await?;
        info!("Verifiable random share generation done");
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
    ) -> Result<(), AdkgError>
    where
        N: Network + Send + Sync + 'static,
        G: Rng + Send,
    {
        let no_shares = {
            let store = self.preprocessing_material.lock().await;
            store.len()
        };
        if no_shares >= self.params.n_v_random_shares {
            info!("There are enough verifiable random shares");
            return Ok(());
        }
        // How many more do we need?
        let missing = self.params.n_v_random_shares.saturating_sub(no_shares);

        // Outputs in batches of (n-2t)
        let batch = self.params.n_parties - 2 * self.params.threshold;
        let run = (missing + batch - 1) / batch; // ceil(missing / batch)
        let mut round_id = 0u8;
        let mut v_ran_sha_counter = self.counters.ran_sha_avss_counter.get_next();

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
                    self.preprocessing_material.lock().await.add(Some(output));
                }
            }

            if round_id == 255 {
                v_ran_sha_counter = self.counters.ran_sha_avss_counter.get_next();
                round_id = 0;
            } else {
                round_id += 1;
            }
        }

        // Clear RBC store
        self.share_gen_avss.rbc.clear_store().await;
        Ok(())
    }
}
