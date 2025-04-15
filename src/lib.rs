/// In MPC, the most fundamental underlying type is called a share. 
/// Think of a share as a piece of a secret that has been split among a set of parties.
/// As such, on its own, you don't derive any information. But when combined with other parties,
/// a certain number of shares can reconstruct a secret.
/// When wanting to implement your own custom MPC protocols that can plug 
/// into the StoffelVM, you must implement the Share type.
mod common;
use crate::common::types::Msg;
trait Share {
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
trait RBC {
    ///Processing messages sent by other nodes
    async fn process(&self,msg:Msg); 
    /// Broadcast messages to other nodes.
    async fn broadcast(msg:Msg);
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
