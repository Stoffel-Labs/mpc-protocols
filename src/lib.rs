/// In MPC, the most fundamental underlying type is called a share. 
/// Think of a share as a piece of a secret that has been split among a set of parties.
/// As such, on its own, you don't derive any information. But when combined with other parties,
/// a certain number of shares can reconstruct a secret.
/// When wanting to implement your own custom MPC protocols that can plug 
/// into the StoffelVM, you must implement the Share type.
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


}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
