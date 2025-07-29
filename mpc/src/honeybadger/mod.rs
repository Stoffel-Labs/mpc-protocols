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

/// Implements a Beaver triple generation protocol for the HoneyBadgerMPC protocol.
pub mod triple_generation;

pub mod messages;

use std::sync::Arc;

use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use async_trait::async_trait;
use double_share_generation::{DouShaError, DouShaParams, DoubleShareNode};
use messages::{
    DouShaFinishedMessage, HoneyBadgerMessage, HoneyBadgerMessageType, RanDouShaFinishedMessage,
    TripleGenFinishedMessage,
};
use ran_dou_sha::{RanDouShaError, RanDouShaNode, RanDouShaParams};
use robust_interpolate::RobustShamirShare;
use sha2::digest::crypto_common::KeyInit;
use stoffelmpc_network::{Network, NetworkError, PartyId, SessionId};
use thiserror::Error;
use triple_generation::{ShamirBeaverTriple, TripleGenError, TripleGenNode, TripleGenParams};

use crate::common::{
    share::shamir::NonRobustShamirShare, MPCProtocol, PreprocessingMPCProtocol, ProtocolError,
};

/// Information pertaining a HoneyBadgerMPC protocol participant.
pub struct HoneyBadgerMPC<F: FftField> {
    /// ID of the current execution node.
    pub id: PartyId,
    /// Preprocessing material used in the protocol execution.
    pub preprocessing_material: HoneyBadgerMPCPreprocMaterial<F>,
    /// Random double shares to execute RanDouSha.
    pub randousha_input_shares: DoubleShamirShare<F>,
    pub online_opts: HoneyBadgerMPCOpts,
    pub preprocessing_opts: HoneyBadgerMPCPreprocOpts,
}

#[derive(Error, Debug)]
pub enum HoneyBadgerError {
    #[error("network error: {0:?}")]
    NetworkError(#[from] NetworkError),
    #[error("error in faulty double share generation: {0:?}")]
    DouShaError(#[from] DouShaError),
    #[error("error in random double share generation: {0:?}")]
    RanDouShaError(#[from] RanDouShaError),
    #[error("there is not enough preprocessing to complete the protocol")]
    NotEnoughPreprocessing,
    #[error("error in triple generation protocol: {0:?}")]
    TripleGenError(#[from] TripleGenError),
}

impl<F> HoneyBadgerMPC<F>
where
    F: FftField,
{
    pub fn process(&mut self, message: HoneyBadgerMessage) {
        match message.message_type {
            HoneyBadgerMessageType::DouShaFinished => {
                todo!();
            }
            HoneyBadgerMessageType::TripleGenFinished => {
                todo!();
            }
        }
    }

    pub async fn dou_sha_gen_finished_handler<N>(
        &mut self,
        dou_sha_finished_msg: DouShaFinishedMessage<F>,
        network: Arc<N>,
    ) -> Result<(), HoneyBadgerError>
    where
        N: Network,
    {
        let ran_dou_sha_params = RanDouShaParams::new(
            self.preprocessing_opts.n_parties,
            self.preprocessing_opts.threshold,
            dou_sha_finished_msg.session_id,
        );

        // Initialize the random double sharing protocol.
        let mut ran_dou_sha_node = RanDouShaNode::new(self.id);
        let s_shares_deg_t = dou_sha_finished_msg
            .faulty_dou_sha
            .iter()
            .map(|dou_sha| dou_sha.degree_t.clone())
            .collect();
        let s_shares_deg_2t = dou_sha_finished_msg
            .faulty_dou_sha
            .iter()
            .map(|dou_sha| dou_sha.degree_2t.clone())
            .collect();
        ran_dou_sha_node
            .init(
                s_shares_deg_t,
                s_shares_deg_2t,
                &ran_dou_sha_params,
                Arc::clone(&network),
            )
            .await?;

        Ok(())
    }

    pub async fn ran_dou_sha_finished_handler<N>(
        &mut self,
        ran_dou_sha_finished_msg: RanDouShaFinishedMessage<F>,
        network: Arc<N>,
    ) -> Result<(), HoneyBadgerError>
    where
        N: Network,
    {
        let triple_gen_params = TripleGenParams::new(
            self.preprocessing_opts.n_parties,
            self.preprocessing_opts.threshold,
            self.preprocessing_opts.n_triples,
        );
        let triple_gen_node = TripleGenNode::new(self.id, triple_gen_params);

        // TODO: Store the results in the local memory.

        Ok(())
    }
}

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
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
    beaver_triples: Vec<ShamirBeaverTriple<F>>,
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
            beaver_triples: Vec::new(),
        }
    }

    /// Adds the provided new preprocessing material to the current pool.
    pub fn add(
        &mut self,
        mut triples: Option<Vec<ShamirBeaverTriple<F>>>,
        mut random_shares: Option<Vec<NonRobustShamirShare<F>>>,
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
    pub fn take_beaver_triple(&mut self, n_pairs: usize) -> Vec<ShamirBeaverTriple<F>> {
        let pairs = n_pairs.min(self.beaver_triples.len());
        self.beaver_triples.drain(0..pairs).collect()
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
    pub n_triples: usize,
    /// Number of random shares needed.
    pub n_random_shares: usize,
    /// Session ID
    pub session_id: SessionId,
    /// Number of parties participating in the preprocessing,
    pub n_parties: usize,
    /// Upper bound of corrupted parties
    pub threshold: usize,
}

impl HoneyBadgerMPCPreprocOpts {
    /// Creates new configuration options for the HoneyBadgerMPC preprocessing.
    pub fn new(
        n_triples: usize,
        n_random_shares: usize,
        session_id: SessionId,
        n_parties: usize,
        threshold: usize,
    ) -> Self {
        Self {
            n_triples,
            n_random_shares,
            session_id,
            n_parties,
            threshold,
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
        a: Vec<NonRobustShamirShare<F>>,
        b: Vec<NonRobustShamirShare<F>>,
        network: Arc<N>,
    ) -> Result<NonRobustShamirShare<F>, ProtocolError>
    where
        N: 'async_trait,
    {
        // TODO: Implement multiplication.

        todo!();
    }

    async fn init(&mut self, network: Arc<N>, opts: Self::MPCOpts)
    where
        N: 'async_trait,
    {
        let network = Arc::clone(&network);
        todo!();
    }
}

#[async_trait]
impl<F, N> PreprocessingMPCProtocol<F, NonRobustShamirShare<F>, N> for HoneyBadgerMPC<F>
where
    N: Network,
    F: FftField,
{
    type ProtocolError = HoneyBadgerError;

    async fn init_preprocessing<R>(
        &mut self,
        network: Arc<N>,
        rng: &mut R,
    ) -> Result<(), Self::ProtocolError>
    where
        N: 'async_trait,
        R: Rng + Send,
    {
        // TODO: We need:
        // - Generate random double shares for preprocessing for input to randousha.
        // - Call setup function to instatiate the nodes for randousha.
        // - Execute randousha with the shares from the previous step.
        //     - Listen to messages comming from other parties and process them.

        let mut double_faulty_share_node: DoubleShareNode<F> = DoubleShareNode::new(self.id);
        let dou_sha_params = DouShaParams::new(
            self.preprocessing_opts.session_id,
            self.preprocessing_opts.n_parties,
            self.preprocessing_opts.threshold,
        );
        double_faulty_share_node
            .init(
                self.preprocessing_opts.session_id,
                &dou_sha_params,
                rng,
                Arc::clone(&network),
            )
            .await?;
        Ok(())
    }
}
