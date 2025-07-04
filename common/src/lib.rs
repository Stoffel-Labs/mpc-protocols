pub mod rbc;
/// In MPC, the most fundamental underlying type is called a share.
/// Think of a share as a piece of a secret that has been split among a set of parties.
/// As such, on its own, you don't derive any information. But when combined with other parties,
/// a certain number of shares can reconstruct a secret.
/// When wanting to implement your own custom MPC protocols that can plug
/// into the StoffelVM, you must implement the Share type.
pub mod share;

use crate::{
    rbc::{rbc::Network, rbc_store::Msg},
    share::ShareError,
};
use ark_std::rand::Rng;
use ark_ff::{FftField, Zero};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use async_trait::async_trait;
use std::{sync::Arc, usize};
use tokio::sync::mpsc::Receiver;


pub struct Share<F: FftField, const N: usize> {
    pub share: [F; N],
    pub id: usize,
    pub degree: usize,
}

pub trait SecretSharingScheme<F: FftField, const N: usize>: Sized {
    /// Secret type used in the Share
    type SecretType;

    fn compute_shares(
        secret: Self::SecretType,
        degree: usize,
        ids: &[usize],
        rng: &mut impl Rng,
    ) -> Share<F, N>;

    /// Recover the secret of the input shares.
    fn recover_secret(shares: &[Share<F, N>]) -> Result<Self::SecretType, ShareError>;

        /// Interpolates a polynomial from `(x, y)` pairs using Lagrange interpolation.
    ///
    /// # Errors
    /// - `ShareError::InsufficientShares` if `x_vals` and `y_vals` have mismatched lengths.
    fn lagrange_interpolate<F: FftField>(
        x_vals: &[F],
        y_vals: &[F],
    ) -> Result<DensePolynomial<F>, ShareError> {
        if x_vals.len() != y_vals.len() {
            return Err(ShareError::InvalidInput);
        }
        let n = x_vals.len();
        let mut result = DensePolynomial::zero();

        for j in 0..n {
            let mut numerator = DensePolynomial::from_coefficients_slice(&[F::one()]);
            let mut denominator = F::one();

            for m in 0..n {
                if m != j {
                    numerator =
                        &numerator * &DensePolynomial::from_coefficients_slice(&[-x_vals[m], F::one()]);
                    denominator *= x_vals[j] - x_vals[m];
                }
            }

            let term = numerator * DensePolynomial::from_coefficients_slice(&[y_vals[j] / denominator]);
            result = &result + &term;
        }

        Ok(result)
    }
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
trait MPCProtocol<S: SecretSharingScheme<N, F>, R: RBC> where F: FftField {
    /// Defines the information needed to run and define the MPC protocol.
    type MPCOpts;

    type ShareType;

    fn init(opts: Self::MPCOpts);

    fn input();

    fn mul();

    fn output();
}

/// Some MPC protocols require preprocessing before they can be used
trait PreprocessingMPCProtocol<S: SecretSharingScheme<F,N>, R: RBC, F: FftField, const N: usize>: MPCProtocol<S, R>{
    /// Defines the information needed to run the preprocessing phase of an MPC protocol
    type PreprocessingOpts;

    /// Runs the offline/preprocessing phase for an MPC protocol
    fn run_preprocessing(opts: Self::PreprocessingOpts);
}
