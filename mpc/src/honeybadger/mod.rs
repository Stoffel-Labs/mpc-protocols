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
    ranodusha_pairs: Vec<(NonRobustShamirShare<F>, NonRobustShamirShare<F>)>,
    random_shares: Vec<NonRobustShamirShare<F>>,
}

impl<F> HoneyBadgerMPCPreprocMaterial<F>
where
    F: FftField,
{
    /// Generates empty preprocessing material storage.
    fn empty() -> Self {
        Self {
            random_shares: Vec::new(),
            ranodusha_pairs: Vec::new(),
        }
    }

    fn add(
        &mut self,
        ran_dou_sha_pair: Option<Vec<(NonRobustShamirShare<F>, NonRobustShamirShare<F>)>>,
        random_shares: Option<Vec<NonRobustShamirShare<F>>>,
    ) {
        todo!()
    }

    fn len(&self) -> (usize, usize) {
        (self.ranodusha_pairs.len(), self.random_shares.len())
    }

    /// Take up to n pairs from ran_dou_sha_pair.
    fn take_randousha_pair(
        &mut self,
        n_pairs: usize,
    ) -> Vec<(NonRobustShamirShare<F>, NonRobustShamirShare<F>)> {
        todo!()
    }

    /// Take up to n pairs from random_shares.
    fn take_random_shares(&mut self, n_shares: usize) -> Vec<(NonRobustShamirShare<F>)> {
        todo!()
    }
}

pub struct HoneyBadgerMPCOpts {
    /// Number of parties in the protocol.
    n_parties: usize,
    /// Upper bound of corrupt parties.
    threshold: usize,
}

pub struct HoneyBadgerMPCPreprocOpts {
    /// Number of random double sharing pairs that need to be generated.
    n_randousha_pairs: usize,
    /// Number of random shares needed.
    n_random_shares: usize,
}

impl<F, R, N> MPCProtocol<F, NonRobustShamirShare<F>, R, N> for HoneyBadgerMPC<F>
where
    R: RBC,
    N: Network,
    F: FftField,
{
    type MPCOpts = HoneyBadgerMPCOpts;

    fn mul(
        &mut self,
        a: NonRobustShamirShare<F>,
        b: NonRobustShamirShare<F>,
        network: N,
    ) -> Result<NonRobustShamirShare<F>, ProtocolError> {
        let mut randousha_pair = self
            .preprocessing_material
            .ranodusha_pairs
            .pop()
            .ok_or(ProtocolError::NotEnoughPreprocessing)?;
        todo!();
    }

    fn init(opts: HoneyBadgerMPCOpts) {
        todo!()
    }
}

#[async_trait]
impl<F, R, N> PreprocessingMPCProtocol<F, NonRobustShamirShare<F>, R, N> for HoneyBadgerMPC<F>
where
    R: RBC,
    N: Network,
    F: FftField,
{
    type PreprocessingOpts = HoneyBadgerMPCPreprocOpts;
    type PreprocessingType = HoneyBadgerMPCPreprocMaterial<F>;

    async fn run_preprocessing(
        &mut self,
        opts: Self::PreprocessingOpts,
    ) -> Vec<Self::PreprocessingType> {
        todo!()
    }
}
