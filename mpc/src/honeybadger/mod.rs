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

use std::sync::Arc;

use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use async_trait::async_trait;
use double_share_generation::{DouShaError, DouShaParams, DoubleShareNode};
use ran_dou_sha::{RanDouShaError, RanDouShaNode, RanDouShaParams};
use robust_interpolate::RobustShamirShare;
use sha2::digest::crypto_common::KeyInit;
use stoffelmpc_network::{Network, NetworkError, PartyId, SessionId};
use thiserror::Error;
use tokio::sync::mpsc::{self, Receiver};
use triple_generation::{ShamirBeaverTriple, TripleGenError, TripleGenNode, TripleGenParams};

use crate::common::{
    share::shamir::NonRobustShamirShare, MPCProtocol, PreprocessingMPCProtocol, ProtocolError, RBC,
};

/// Information pertaining a HoneyBadgerMPCNode protocol participant.
pub struct HoneyBadgerMPCNode<F: FftField> {
    /// ID of the current execution node.
    pub id: PartyId,

    /// Preprocessing material used in the protocol execution.
    pub preprocessing_material: HoneyBadgerMPCNodePreprocMaterial<F>,

    // Preprocessing parameters.
    pub online_opts: HoneyBadgerMPCNodeOpts,
    pub preprocessing_opts: HoneyBadgerMPCNodePreprocOpts,

    // Nodes for subprotocols.
    pub dou_sha: DoubleShareNode<F>,
    pub ran_dou_sha: RanDouShaNode<F>,
    pub triple_gen: TripleGenNode<F>,

    // Channels for outputs from subprotocols. Those channels contain the session ids of protocols
    // that are already finished.
    pub dou_sha_channel: Receiver<SessionId>,
    pub ran_dou_sha_channel: Receiver<SessionId>,
    pub triple_channel: Receiver<SessionId>,
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

impl<F> HoneyBadgerMPCNode<F>
where
    F: FftField,
{
    pub fn new(
        id: PartyId,
        online_opts: HoneyBadgerMPCNodeOpts,
        preprocessing_opts: HoneyBadgerMPCNodePreprocOpts,
    ) -> Self {
        // Create channels for sub protocol output.
        let (dou_sha_sender, dou_sha_receiver) = mpsc::channel(128);
        let (ran_dou_sha_sender, ran_dou_sha_receiver) = mpsc::channel(128);
        let (triple_sender, triple_receiver) = mpsc::channel(128);

        // Create nodes for preprocessing.
        let dousha_node = DoubleShareNode::new(id, dou_sha_sender);
        let ran_dou_sha_node = RanDouShaNode::new(id, ran_dou_sha_sender);
        let triple_gen_params = TripleGenParams::new(
            preprocessing_opts.n_parties,
            preprocessing_opts.threshold,
            preprocessing_opts.n_triples,
        );
        let triple_gen_node = TripleGenNode::new(id, triple_gen_params, triple_sender);
        Self {
            id,
            preprocessing_material: HoneyBadgerMPCNodePreprocMaterial::empty(),
            online_opts,
            preprocessing_opts,
            dou_sha: dousha_node,
            ran_dou_sha: ran_dou_sha_node,
            triple_gen: triple_gen_node,
            dou_sha_channel: dou_sha_receiver,
            ran_dou_sha_channel: ran_dou_sha_receiver,
            triple_channel: triple_receiver,
        }
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

/// Preprocessing material for the HoneyBadgerMPCNode protocol.
pub struct HoneyBadgerMPCNodePreprocMaterial<F: FftField> {
    /// A pool of random double shares used for secure multiplication.
    beaver_triples: Vec<ShamirBeaverTriple<F>>,
    /// A pool of random shares used for inputing private data for the protocol.
    random_shares: Vec<RobustShamirShare<F>>,
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
        mut random_shares: Option<Vec<RobustShamirShare<F>>>,
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
    pub fn take_beaver_triples(&mut self, n_pairs: usize) -> Vec<ShamirBeaverTriple<F>> {
        let pairs = n_pairs.min(self.beaver_triples.len());
        self.beaver_triples.drain(0..pairs).collect()
    }

    /// Take up to n random shares from the preprocessing material.
    pub fn take_random_shares(&mut self, n_shares: usize) -> Vec<RobustShamirShare<F>> {
        let pairs = n_shares.min(self.random_shares.len());
        self.random_shares.drain(0..pairs).collect()
    }
}

/// Configuration options for the HoneyBadgerMPCNode protocol.
pub struct HoneyBadgerMPCNodeOpts {
    /// Number of parties in the protocol.
    pub n_parties: usize,
    /// Upper bound of corrupt parties.
    pub threshold: usize,
    /// Initial preprocessing parameters
    pub init_preproc_opts: HoneyBadgerMPCNodePreprocOpts,
}

impl HoneyBadgerMPCNodeOpts {
    /// Creates a new struct of initialization options for the HoneyBadgerMPCNode protocol.
    pub fn new(
        n_parties: usize,
        threshold: usize,
        init_preproc_opts: HoneyBadgerMPCNodePreprocOpts,
    ) -> Self {
        Self {
            n_parties,
            threshold,
            init_preproc_opts,
        }
    }
}

/// Configuration options for the HoneyBadgerMPCNode preprocessing.
pub struct HoneyBadgerMPCNodePreprocOpts {
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

impl HoneyBadgerMPCNodePreprocOpts {
    /// Creates new configuration options for the HoneyBadgerMPCNode preprocessing.
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
impl<F, N> MPCProtocol<F, NonRobustShamirShare<F>, N> for HoneyBadgerMPCNode<F>
where
    N: Network,
    F: FftField,
{
    type MPCOpts = HoneyBadgerMPCNodeOpts;

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
        todo!("implement multiplication");
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
impl<F, N> PreprocessingMPCProtocol<F, NonRobustShamirShare<F>, N> for HoneyBadgerMPCNode<F>
where
    N: Network,
    F: FftField,
{
    type ProtocolError = HoneyBadgerError;

    async fn run_preprocessing<R>(
        &mut self,
        network: Arc<N>,
        rng: &mut R,
    ) -> Result<Vec<ShamirBeaverTriple<F>>, Self::ProtocolError>
    where
        N: 'async_trait,
        R: Rng + Send,
    {
        // First, the node takes faulty double shares to create triples.
        let random_shares_a = self
            .preprocessing_material
            .take_random_shares(self.preprocessing_opts.n_triples);
        let random_shares_b = self
            .preprocessing_material
            .take_random_shares(self.preprocessing_opts.n_triples);

        if random_shares_a.len() < self.preprocessing_opts.n_triples
            || random_shares_b.len() < self.preprocessing_opts.n_triples
        {
            // TODO: Run the random share generation protocol.
            todo!()
        }

        let mut ran_dou_sha_pair = self.ran_dou_sha.pop_finished_protocol_result().await;
        if ran_dou_sha_pair.is_none() {
            // There are not enought random double shares. We need to construct them.
            let mut out_dou_sha = self.dou_sha.pop_finished_protocol_result().await;
            if out_dou_sha.is_none() {
                // There are not enough faulty double shares. We need to construct them.
                let dou_sha_params = DouShaParams::new(
                    self.preprocessing_opts.session_id,
                    self.preprocessing_opts.n_parties,
                    self.preprocessing_opts.threshold,
                );
                self.dou_sha
                    .init(
                        self.preprocessing_opts.session_id,
                        &dou_sha_params,
                        rng,
                        Arc::clone(&network),
                    )
                    .await?;
                if let Some(sid) = self.dou_sha_channel.recv().await {
                    let mut dou_sha_db = self.dou_sha.storage.lock().await;
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
            let ran_dou_sha_params = RanDouShaParams::new(
                self.preprocessing_opts.n_parties,
                self.preprocessing_opts.threshold,
                self.preprocessing_opts.session_id,
            );
            self.ran_dou_sha
                .init(
                    shares_deg_t,
                    shares_deg_2t,
                    &ran_dou_sha_params,
                    Arc::clone(&network),
                )
                .await?;
            if let Some(sid) = self.ran_dou_sha_channel.recv().await {
                let mut dou_sha_db = self.ran_dou_sha.store.lock().await;
                // SAFETY: the triple already exists because it was taken from the finished
                // double sharing sessions.
                let dou_sha_storage_mutex = dou_sha_db.remove(&sid).unwrap();
                let dou_sha_storage = dou_sha_storage_mutex.lock().await;
                ran_dou_sha_pair = Some(dou_sha_storage.protocol_output.clone());
            }
        }

        self.triple_gen
            .init(
                random_shares_a,
                random_shares_b,
                // SAFETY: The given that the RanDouSha was generated. This sould be Some(_).
                ran_dou_sha_pair.unwrap(),
                self.preprocessing_opts.session_id,
                Arc::clone(&network),
            )
            .await?;

        // Extract triples.
        let mut output_triples = Vec::new();
        if let Some(sid) = self.triple_channel.recv().await {
            let mut triple_gen_db = self.triple_gen.storage.lock().await;
            // SAFETY: the triple already exists because it was taken from the finished sessions.
            let triple_storage_mutex = triple_gen_db.remove(&sid).unwrap();
            let triple_storage = triple_storage_mutex.lock().await;
            output_triples = triple_storage.protocol_output.clone();
        }

        Ok(output_triples)
    }
}
