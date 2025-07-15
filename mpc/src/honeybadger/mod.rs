use std::sync::Arc;

use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use async_trait::async_trait;
use stoffelmpc_network::Network;

use crate::common::{
    share::shamir::NonRobustShamirShare, MPCProtocol, PreprocessingMPCProtocol, ProtocolError, RBC,
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

/// Implementation for the protocol of double share generation.
pub mod double_share_generation;

/// Information pertaining the HoneyBadgerMPC protocol.
pub struct HoneyBadgerMPC<F: FftField> {
    /// Preprocessing material used in the protocol execution.
    preprocessing_material: HoneyBadgerMPCPreprocMaterial<F>,
    /// Random double shares to execute RanDouSha.
    randousha_input_shares: DoubleShamirShare<F>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct DoubleShamirShare<F: FftField> {
    /// Share of degree 2t.
    pub degree_2t: NonRobustShamirShare<F>,
    // Share of degree t.
    pub degree_t: NonRobustShamirShare<F>,
}

impl<F: FftField> DoubleShamirShare<F> {
    pub fn new(degree_t: NonRobustShamirShare<F>, degree_2t: NonRobustShamirShare<F>) -> Self {
        assert!(degree_t.id == degree_2t.id);
        Self {
            degree_2t,
            degree_t,
        }
    }
}

/// Preprocessing material for the HoneyBadgerMPC protocol.
pub struct HoneyBadgerMPCPreprocMaterial<F: FftField> {
    /// A pool of random double shares used for secure multiplication.
    randousha_pairs: Vec<DoubleShamirShare<F>>,
    /// A pool of random shares used for inputing private data for the protocol.
    random_shares: Vec<NonRobustShamirShare<F>>,
}

impl<F> HoneyBadgerMPCPreprocMaterial<F>
where
    F: FftField,
{
    /// Generates empty preprocessing material storage.
    pub fn empty() -> Self {
        Self {
            random_shares: Vec::new(),
            randousha_pairs: Vec::new(),
        }
    }

    /// Adds the provided new preprocessing material to the current pool.
    pub fn add(
        &mut self,
        mut ran_dou_sha_pair: Option<Vec<DoubleShamirShare<F>>>,
        mut random_shares: Option<Vec<NonRobustShamirShare<F>>>,
    ) {
        if let Some(pairs) = &mut ran_dou_sha_pair {
            self.randousha_pairs.append(pairs);
        }

        if let Some(shares) = &mut random_shares {
            self.random_shares.append(shares);
        }
    }

    /// Returns the number of random double share pairs, and the number of random shares
    /// respectively.
    pub fn len(&self) -> (usize, usize) {
        (self.randousha_pairs.len(), self.random_shares.len())
    }

    /// Take up to n pairs of random double sharings from the preprocessing material.
    pub fn take_randousha_pair(&mut self, n_pairs: usize) -> Vec<DoubleShamirShare<F>> {
        let pairs = n_pairs.min(self.randousha_pairs.len());
        self.randousha_pairs.drain(0..pairs).collect()
    }

    /// Take up to n random shares from the preprocessing material.
    pub fn take_random_shares(&mut self, n_shares: usize) -> Vec<NonRobustShamirShare<F>> {
        let pairs = n_shares.min(self.random_shares.len());
        self.random_shares.drain(0..pairs).collect()
    }
}

/// Configuration options for the HoneyBadgerMPC protocol.
pub struct HoneyBadgerMPCOpts {
    /// Number of parties in the protocol.
    pub n_parties: usize,
    /// Upper bound of corrupt parties.
    pub threshold: usize,
    /// Initial preprocessing parameters
    pub init_preproc_opts: HoneyBadgerMPCPreprocOpts,
}

impl HoneyBadgerMPCOpts {
    /// Creates a new struct of initialization options for the HoneyBadgerMPC protocol.
    pub fn new(
        n_parties: usize,
        threshold: usize,
        init_preproc_opts: HoneyBadgerMPCPreprocOpts,
    ) -> Self {
        Self {
            n_parties,
            threshold,
            init_preproc_opts,
        }
    }
}

/// Configuration options for the HoneyBadgerMPC preprocessing.
pub struct HoneyBadgerMPCPreprocOpts {
    /// Number of random double sharing pairs that need to be generated.
    pub n_randousha_pairs: usize,
    /// Number of random shares needed.
    pub n_random_shares: usize,
}

impl HoneyBadgerMPCPreprocOpts {
    /// Creates new configuration options for the HoneyBadgerMPC preprocessing.
    pub fn new(n_randousha_pairs: usize, n_random_shares: usize) -> Self {
        Self {
            n_randousha_pairs,
            n_random_shares,
        }
    }
}

#[async_trait]
impl<F, N> MPCProtocol<F, NonRobustShamirShare<F>, N> for HoneyBadgerMPC<F>
where
    N: Network,
    F: FftField,
{
    type MPCOpts = HoneyBadgerMPCOpts;

    async fn mul(
        &mut self,
        a: NonRobustShamirShare<F>,
        b: NonRobustShamirShare<F>,
        network: Arc<N>,
    ) -> Result<NonRobustShamirShare<F>, ProtocolError>
    where
        N: 'async_trait,
    {
        let mut randousha_pair = self
            .preprocessing_material
            .randousha_pairs
            .pop()
            .ok_or(ProtocolError::NotEnoughPreprocessing)?;
        let mult_share_deg_2t = a.share_mul(b)?;
        let open_share = mult_share_deg_2t - randousha_pair.degree_2t;

        // TODO: Implement the opening.

        todo!();
    }

    fn init(&mut self, network: Arc<N>, opts: HoneyBadgerMPCOpts) {
        let network = Arc::clone(&network);
        self.run_preprocessing(network, opts.init_preproc_opts);
    }
}

#[async_trait]
impl<F, N> PreprocessingMPCProtocol<F, NonRobustShamirShare<F>, N> for HoneyBadgerMPC<F>
where
    N: Network,
    F: FftField,
{
    type PreprocessingOpts = HoneyBadgerMPCPreprocOpts;
    type PreprocessingType = HoneyBadgerMPCPreprocMaterial<F>;

    async fn run_preprocessing(
        &mut self,
        network: Arc<N>,
        opts: Self::PreprocessingOpts,
    ) -> Vec<Self::PreprocessingType>
    where
        N: 'async_trait,
    {
        // TODO: We need:
        // - Generate random shares for preprocessing result for input.
        // - Generate double random shares for randousha.
        // - Call setup function to instatiate the nodes for randousha.
        // - Execute randousha with the shares from the previous step.
        //     - Listen to messages comming from other parties and process them.

        todo!()
    }
}
