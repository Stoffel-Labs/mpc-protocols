use std::sync::Arc;

use ark_ff::FftField;
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

pub struct HoneyBadgerMPC<F: FftField> {
    preprocessing_material: HoneyBadgerMPCPreprocMaterial<F>,
}

pub struct HoneyBadgerMPCPreprocMaterial<F: FftField> {
    randousha_pairs: Vec<(NonRobustShamirShare<F>, NonRobustShamirShare<F>)>,
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

    pub fn add(
        &mut self,
        mut ran_dou_sha_pair: Option<Vec<(NonRobustShamirShare<F>, NonRobustShamirShare<F>)>>,
        mut random_shares: Option<Vec<NonRobustShamirShare<F>>>,
    ) {
        if let Some(pairs) = &mut ran_dou_sha_pair {
            self.randousha_pairs.append(pairs);
        }

        if let Some(shares) = &mut random_shares {
            self.random_shares.append(shares);
        }
    }

    pub fn len(&self) -> (usize, usize) {
        (self.randousha_pairs.len(), self.random_shares.len())
    }

    /// Take up to n pairs of random double sharings from the preprocessing material.
    pub fn take_randousha_pair(
        &mut self,
        n_pairs: usize,
    ) -> Vec<(NonRobustShamirShare<F>, NonRobustShamirShare<F>)> {
        let pairs = n_pairs.min(self.randousha_pairs.len());
        self.randousha_pairs.drain(0..pairs).collect()
    }

    /// Take up to n random shares from the preprocessing material.
    pub fn take_random_shares(&mut self, n_shares: usize) -> Vec<NonRobustShamirShare<F>> {
        let pairs = n_shares.min(self.random_shares.len());
        self.random_shares.drain(0..pairs).collect()
    }
}

pub struct HoneyBadgerMPCOpts {
    /// Number of parties in the protocol.
    pub n_parties: usize,
    /// Upper bound of corrupt parties.
    pub threshold: usize,
    /// Initial preprocessing parameters
    pub init_preproc_opts: HoneyBadgerMPCPreprocOpts,
}

impl HoneyBadgerMPCOpts {
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

pub struct HoneyBadgerMPCPreprocOpts {
    /// Number of random double sharing pairs that need to be generated.
    pub n_randousha_pairs: usize,
    /// Number of random shares needed.
    pub n_random_shares: usize,
}

impl HoneyBadgerMPCPreprocOpts {
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
        todo!()
    }
}
