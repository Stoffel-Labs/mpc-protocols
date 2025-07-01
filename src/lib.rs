/// In MPC, the most fundamental underlying type is called a share.
/// Think of a share as a piece of a secret that has been split among a set of parties.
/// As such, on its own, you don't derive any information. But when combined with other parties,
/// a certain number of shares can reconstruct a secret.
/// When wanting to implement your own custom MPC protocols that can plug
/// into the StoffelVM, you must implement the Share type.
pub mod common;
use crate::common::{rbc::Network, rbc_store::Msg};
use ark_std::rand::Rng;
use async_trait::async_trait;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::mpsc::Receiver;

pub trait Share: Sized {
    /// The underlying secret that this share represents.
    type UnderlyingSecret;
    /// You can add shares together locally
    fn add(&self, other: &Self) -> Result<Self, ShareError>;

    /// You can multiply a scalar to a share locally
    fn scalar_mul(&self, scalar: &Self::UnderlyingSecret) -> Self;

    /// You can multiply shares together with other parties
    fn mul();

    /// You can reveal shares together with other parties
    /// Reveal a share means that you are revealing the underlying secret
    fn reveal();
}

pub trait SecretSharing: Sized {
    /// Secret type used in the Share
    type Secret;
    /// Share type of the SecretSharing
    type Share: Share<UnderlyingSecret = Self::Secret>;

    /// compute the shares of all ids for a secret
    /// returns a vec of shares
    fn compute_shares(
        secret: Self::Secret,
        degree: usize,
        ids: &[usize],
        rng: &mut impl Rng,
    ) -> Vec<Self::Share>;

    /// recover the secret of the input shares
    fn recover_secret(shares: &[Self]) -> Result<Self::Secret, ShareError>;
}

#[derive(Debug, Error)]
pub enum ShareError {
    #[error("insufficient shares to reconstruct the secret")]
    InsufficientShares,
    #[error("mismatch degree between shares")]
    DegreeMismatch,
    #[error("mismatch index between shares")]
    IdMismatch,
    #[error("Invalid input")]
    InvalidInput
}

/// In MPC, there needs to be a way for a dealer and the nodes to broadcast messages
/// to each other. And the receivers need to agree on the senders' messages.
/// The primitive that does this is called Reliable Broadcast (RBC).
/// When implementing your own custom MPC protocols, you must implement the RBC trait.
#[async_trait]
pub trait RBC: Send + Sync + 'static {
    /// Creates a new instance
    fn new(id: u32, n: u32, t: u32, k: u32) -> Result<Self, String>
    where
        Self: Sized;
    /// Required for initiating the broadcast
    async fn init(&self, payload: Vec<u8>, session_id: u32, parties: Arc<Network>);
    ///Processing messages sent by other nodes based on their type
    async fn process(&self, msg: Msg, parties: Arc<Network>);
    /// Broadcast messages to other nodes.
    async fn broadcast(&self, msg: Msg, parties: Arc<Network>);
    /// Send to another node
    async fn send(&self, msg: Msg, parties: Arc<Network>, recv: u32);
    ///Listen to messages
    async fn run_party(&self, receiver: &mut Receiver<Msg>, parties: Arc<Network>);
}

/// Now, it's time to define the MPC Protocol trait.
/// Given an underlying secret sharing protocol and a reliable broadcast protocol,
/// you can define an MPC protocol.
trait MPCProtocol<S: Share, R: RBC> {
    /// Defines the information needed to run and define the MPC protocol.
    type MPCOpts;

    /// Runs the online phase for an MPC protocol
    fn run(opts: Self::MPCOpts);
}

/// Some MPC protocols require preprocessing before they can be used
trait PreprocessingMPCProtocol<S: Share, R: RBC>: MPCProtocol<S, R> {
    /// Defines the information needed to run the preprocessing phase of an MPC protocol
    type PreprocessingOpts;

    /// Runs the offline/preprocessing phase for an MPC protocol
    fn run_preprocessing(opts: Self::PreprocessingOpts);
}
