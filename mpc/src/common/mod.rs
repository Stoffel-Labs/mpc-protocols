pub mod rbc;
/// In MPC, the most fundamental underlying type is called a share.
/// Think of a share as a piece of a secret that has been split among a set of parties.
/// As such, on its own, you don't derive any information. But when combined with other parties,
/// a certain number of shares can reconstruct a secret.
/// When wanting to implement your own custom MPC protocols that can plug
/// into the StoffelVM, you must implement the Share type.
pub mod share;

use crate::common::{
    rbc::{rbc_store::Msg, RbcError},
    share::ShareError,
};

use ark_ff::{FftField, Zero};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use async_trait::async_trait;
use std::{
    marker::PhantomData,
    ops::{Add, Mul},
    sync::Arc,
    usize,
};
use stoffelmpc_network::Network;

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ShamirShare<F: FftField, const N: usize, P> {
    pub share: [F; N],
    pub id: usize,
    pub degree: usize,
    pub _sharetype: PhantomData<fn() -> P>,
}

pub trait SecretSharingScheme<F: FftField, const N: usize>: Sized {
    /// Secret type used in the Share
    type SecretType;

    /// Protocol marker type (used for Share<F, N, P>)
    type Sharetype;

    type Error;

    fn compute_shares(
        secret: Self::SecretType,
        n: usize,
        degree: usize,
        ids: Option<&[usize]>,
        rng: &mut impl Rng,
    ) -> Result<Vec<ShamirShare<F, N, Self::Sharetype>>, Self::Error>;

    /// Recover the secret of the input shares.
    fn recover_secret(
        shares: &[ShamirShare<F, N, Self::Sharetype>],
    ) -> Result<(Vec<Self::SecretType>, Self::SecretType), Self::Error>;
}
/// Interpolates a polynomial from `(x, y)` pairs using Lagrange interpolation.
///
/// # Errors
/// - `ShareError::InsufficientShares` if `x_vals` and `y_vals` have mismatched lengths.
pub fn lagrange_interpolate<F: FftField>(
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

impl<F: FftField, const N: usize, P> Add for ShamirShare<F, N, P> {
    type Output = Result<Self, ShareError>;

    fn add(self, other: Self) -> Self::Output {
        if self.degree != other.degree {
            return Err(ShareError::DegreeMismatch);
        }

        if self.id != other.id {
            return Err(ShareError::IdMismatch);
        }

        let new_share: [F; N] = std::array::from_fn(|i| self.share[i] + other.share[i]);

        Ok(Self {
            share: new_share,
            id: self.id,
            degree: self.degree,
            _sharetype: PhantomData,
        })
    }
}
impl<F: FftField, const N: usize, P> Mul<F> for ShamirShare<F, N, P> {
    type Output = Result<Self, ShareError>;

    fn mul(self, other: F) -> Self::Output {
        let new_share: [F; N] = std::array::from_fn(|i| self.share[i] * other);

        Ok(Self {
            share: new_share,
            id: self.id,
            degree: self.degree,
            _sharetype: PhantomData,
        })
    }
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
        msg: Msg,
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
pub trait MPCProtocol<F: FftField, const N: usize, S: SecretSharingScheme<F, N>, R: RBC>
where
    F: FftField,
{
    /// Defines the information needed to run and define the MPC protocol.
    type MPCOpts;

    type ShareType;
    type Node: MPCNode<F, R>;

    fn init(opts: Self::MPCOpts);

    fn input();

    fn mul();

    fn output();
}

/// Some MPC protocols require preprocessing before they can be used
pub trait PreprocessingMPCProtocol<F: FftField, const N: usize, S: SecretSharingScheme<F, N>, R: RBC>:
    MPCProtocol<F, N, S, R>
{
    /// Defines the information needed to run the preprocessing phase of an MPC protocol
    type PreprocessingOpts;

    /// Runs the offline/preprocessing phase for an MPC protocol
    fn run_preprocessing(opts: Self::PreprocessingOpts);
}

#[async_trait]
pub trait MPCNode<F: FftField, R: RBC>: Send + Sync {
    fn new(
        id: usize,
        n: usize,
        t: usize,
        k: usize, // used by RBC
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>>
    where
        Self: Sized;

    fn id(&self) -> usize;

    async fn process<N: Network + Send + Sync + 'static>(
        &mut self,
        raw_msg: Vec<u8>,
        net: Arc<N>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}
