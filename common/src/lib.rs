pub mod rbc;
/// In MPC, the most fundamental underlying type is called a share.
/// Think of a share as a piece of a secret that has been split among a set of parties.
/// As such, on its own, you don't derive any information. But when combined with other parties,
/// a certain number of shares can reconstruct a secret.
/// When wanting to implement your own custom MPC protocols that can plug
/// into the StoffelVM, you must implement the Share type.
pub mod share;

use crate::rbc::{rbc_store::Msg, RbcError};
use async_trait::async_trait;
use std::sync::Arc;
use stoffelmpc_network::Network;

pub trait Share {
    /// The underlying secret that this share represents.
    type UnderlyingSecret;

    /// You can add shares together locally
    fn add();

    /// You can multiply shares together with other parties
    fn mul();

    /// You can reveal shares together with other parties
    /// Reveal a share means that you are revealing the underlying secret
    fn reveal();
}

/// In MPC, there needs to be a way for a dealer and the nodes to broadcast messages
/// to each other. And the receivers need to agree on the senders' messages.
/// The primitive that does this is called Reliable Broadcast (RBC).
/// When implementing your own custom MPC protocols, you must implement the RBC trait.
#[async_trait]
pub trait RBC: Send + Sync {
    /// Creates a new instance
    fn new(id: u32, n: u32, t: u32, k: u32) -> Result<Self, RbcError>
    where
        Self: Sized;
    /// Returns the unique identifier of the current party.
    fn id(&self) -> u32;
    /// Required for initiating the broadcast
    async fn init<N: Network + Send + Sync>(
        &self,
        payload: Vec<u8>,
        session_id: u32,
        parties: Arc<N>,
    ) -> Result<(), RbcError>;
    ///Processing messages sent by other nodes based on their type
    async fn process<N: Network + Send + Sync + 'static>(
        &self,
        msg: Vec<u8>,
        parties: Arc<N>,
    ) -> Result<(), RbcError>;
    /// Broadcast messages to other nodes.
    async fn broadcast<N: Network + Send + Sync>(
        &self,
        msg: Msg,
        net: Arc<N>,
    ) -> Result<(), RbcError>;
    /// Send to another node
    async fn send<N: Network + Send + Sync>(
        &self,
        msg: Msg,
        net: Arc<N>,
        recv: u32,
    ) -> Result<(), RbcError>;
}

/// Now, it's time to define the MPC Protocol trait.
/// Given an underlying secret sharing protocol and a reliable broadcast protocol,
/// you can define an MPC protocol.
pub trait MPCProtocol<S: Share, R: RBC> {
    /// Defines the information needed to run and define the MPC protocol.
    type MPCOpts;

    /// Runs the online phase for an MPC protocol
    fn run(opts: Self::MPCOpts);
}

/// Some MPC protocols require preprocessing before they can be used
pub trait PreprocessingMPCProtocol<S: Share, R: RBC>: MPCProtocol<S, R> {
    /// Defines the information needed to run the preprocessing phase of an MPC protocol
    type PreprocessingOpts;

    /// Runs the offline/preprocessing phase for an MPC protocol
    fn run_preprocessing(opts: Self::PreprocessingOpts);
}
