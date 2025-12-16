pub mod rbc;
/// In MPC, the most fundamental underlying type is called a share.
/// Think of a share as a piece of a secret that has been split among a set of parties.
/// As such, on its own, you don't derive any information. But when combined with other parties,
/// a certain number of shares can reconstruct a secret.
/// When wanting to implement your own custom MPC protocols that can plug
/// into the StoffelVM, you must implement the Share type.
pub mod share;

pub mod types;

use crate::{
    common::{
        rbc::{rbc_store::Msg, RbcError},
        share::ShareError,
    },
    honeybadger::SessionId,
};
use ark_ec::CurveGroup;
use ark_ff::{FftField, Zero};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use async_trait::async_trait;
use std::{
    marker::PhantomData,
    ops::{Add, Mul, Sub},
    sync::Arc,
    usize,
};
use stoffelnet::network_utils::{ClientId, Network, PartyId};

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ShamirShare<F: FftField, const N: usize, P> {
    pub share: [F; N],
    ///index of the share(x-values),can be different from the reciever ID
    pub id: usize,
    pub degree: usize,
    pub commitments: Option<Vec<u8>>,
    pub _sharetype: PhantomData<fn() -> P>,
}

pub trait SecretSharingScheme<F: FftField>:
    Sized
    + Add<Output = Result<Self, ShareError>>
    + Sub<Output = Result<Self, ShareError>>
    + Add<F, Output = Result<Self, ShareError>>
    + Sub<F, Output = Result<Self, ShareError>>
    + Mul<F, Output = Result<Self, ShareError>>
{
    /// Secret type used in the Share
    type SecretType;

    type Error;

    fn compute_shares(
        secret: Self::SecretType,
        n: usize,
        degree: usize,
        ids: Option<&[usize]>,
        rng: &mut impl Rng,
    ) -> Result<Vec<Self>, Self::Error>;

    /// Recover the secret of the input shares.
    fn recover_secret(
        shares: &[Self],
        n: usize,
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
            commitments: self.commitments,
            _sharetype: PhantomData,
        })
    }
}

impl<F: FftField, const N: usize, P> Add<&F> for ShamirShare<F, N, P> {
    type Output = Result<Self, ShareError>;

    fn add(self, other: &F) -> Self::Output {
        let new_share: [F; N] = std::array::from_fn(|i| self.share[i] + other);

        Ok(Self {
            share: new_share,
            id: self.id,
            degree: self.degree,
            commitments: self.commitments,
            _sharetype: PhantomData,
        })
    }
}

impl<F: FftField, const N: usize, P> Add<F> for ShamirShare<F, N, P> {
    type Output = Result<Self, ShareError>;

    fn add(self, other: F) -> Self::Output {
        let new_share: [F; N] = std::array::from_fn(|i| self.share[i] + other);

        Ok(Self {
            share: new_share,
            id: self.id,
            degree: self.degree,
            commitments: self.commitments,
            _sharetype: PhantomData,
        })
    }
}

impl<F: FftField, const N: usize, P> Sub for ShamirShare<F, N, P> {
    type Output = Result<Self, ShareError>;
    fn sub(self, other: Self) -> Self::Output {
        if self.degree != other.degree {
            return Err(ShareError::DegreeMismatch);
        }

        if self.id != other.id {
            return Err(ShareError::IdMismatch);
        }

        let new_share: [F; N] = std::array::from_fn(|i| self.share[i] - other.share[i]);

        Ok(Self {
            share: new_share,
            id: self.id,
            degree: self.degree,
            commitments: self.commitments,
            _sharetype: PhantomData,
        })
    }
}

impl<F: FftField, const N: usize, P> Sub<F> for ShamirShare<F, N, P> {
    type Output = Result<Self, ShareError>;
    fn sub(self, other: F) -> Self::Output {
        let new_share: [F; N] = std::array::from_fn(|i| self.share[i] - other);

        Ok(Self {
            share: new_share,
            id: self.id,
            degree: self.degree,
            commitments: self.commitments,
            _sharetype: PhantomData,
        })
    }
}
impl<F: FftField, const N: usize, P> ShamirShare<F, N, P> {
    pub fn from_scalar_sub(scalar: F, other: &Self) -> Self {
        let new_share: [F; N] = std::array::from_fn(|i| scalar - other.share[i]);
        Self {
            share: new_share,
            id: other.id,
            degree: other.degree,
            commitments: other.commitments.clone(),
            _sharetype: PhantomData,
        }
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
            commitments: self.commitments,
            _sharetype: PhantomData,
        })
    }
}

impl<F, const N: usize, P> ShamirShare<F, N, P>
where
    F: FftField,
{
    pub fn share_mul(&self, other: &Self) -> Result<Self, ShareError> {
        if self.id != other.id {
            return Err(ShareError::IdMismatch);
        }

        let new_share: [F; N] = std::array::from_fn(|i| self.share[i] * other.share[i]);

        Ok(Self {
            share: new_share,
            id: self.id,
            degree: self.degree + other.degree,
            commitments: self.commitments.clone(),
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
    fn new(id: usize, n: usize, t: usize, k: usize) -> Result<Self, RbcError>
    where
        Self: Sized;
    /// Returns the unique identifier of the current party.
    fn id(&self) -> usize;
    async fn clear_store(&self);
    /// Required for initiating the broadcast
    async fn init<N: Network + Send + Sync>(
        &self,
        payload: Vec<u8>,
        session_id: SessionId,
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
        recv: usize,
    ) -> Result<(), RbcError>;
}

/// Now, it's time to define the MPC Protocol trait.
/// Given an underlying secret sharing protocol and a reliable broadcast protocol,
/// you can define an MPC protocol.
#[async_trait]
pub trait MPCProtocol<F, S, N>
where
    F: FftField,
    S: SecretSharingScheme<F>,
    N: Network,
{
    type MPCOpts;
    type Error: std::fmt::Debug;

    fn setup(
        id: PartyId,
        params: Self::MPCOpts,
        input_ids: Vec<ClientId>,
    ) -> Result<Self, Self::Error>
    where
        Self: Sized;

    async fn process(&mut self, raw_msg: Vec<u8>, net: Arc<N>) -> Result<(), Self::Error>;

    async fn mul(&mut self, a: Vec<S>, b: Vec<S>, network: Arc<N>) -> Result<Vec<S>, Self::Error>
    where
        N: 'async_trait;
    async fn rand(&mut self, network: Arc<N>) -> Result<S, Self::Error>;
}

#[async_trait]
pub trait PreprocessingMPCProtocol<F, S, N>: MPCProtocol<F, S, N>
where
    N: Network,
    F: FftField,
    S: SecretSharingScheme<F>,
{
    async fn run_preprocessing<R>(
        &mut self,
        network: Arc<N>,
        rng: &mut R,
    ) -> Result<(), Self::Error>
    where
        N: 'async_trait,
        R: Rng + Send;
}

#[async_trait]
pub trait MPCTypeOps<F, S, N>: Send + Sync
where
    N: Network,
    F: FftField,
    S: SecretSharingScheme<F>,
{
    type Error;
    type Sfix;
    type Sint;
    type Cfix; // clear fixed-point
    type Cint; // clear integer

    /// Fixed-point addition: x + y
    async fn add_fixed(
        &self,
        x: Vec<Self::Sfix>,
        y: Vec<Self::Sfix>,
    ) -> Result<Vec<Self::Sfix>, Self::Error>;

    /// Fixed-point subtraction: x - y
    async fn sub_fixed(
        &self,
        x: Vec<Self::Sfix>,
        y: Vec<Self::Sfix>,
    ) -> Result<Vec<Self::Sfix>, Self::Error>;

    /// Fixed-point multiplication with truncation for fixed precision
    async fn mul_fixed(
        &mut self,
        x: Self::Sfix,
        y: Self::Sfix,
        net: Arc<N>,
    ) -> Result<Self::Sfix, Self::Error>;

    /// Fixed-point Division with const
    async fn div_with_const_fixed(
        &mut self,
        x: Self::Sfix,
        y: Self::Cfix,
        net: Arc<N>,
    ) -> Result<Self::Sfix, Self::Error>;

    /// Integer addition (int8/16/32/64)
    async fn add_int(
        &self,
        x: Vec<Self::Sint>,
        y: Vec<Self::Sint>,
    ) -> Result<Vec<Self::Sint>, Self::Error>;

    /// Integer addition (int8/16/32/64)
    async fn sub_int(
        &self,
        x: Vec<Self::Sint>,
        y: Vec<Self::Sint>,
    ) -> Result<Vec<Self::Sint>, Self::Error>;

    /// Integer multiplication (int8/16/32/64)
    async fn mul_int(
        &mut self,
        x: Vec<Self::Sint>,
        y: Vec<Self::Sint>,
        net: Arc<N>,
    ) -> Result<Vec<Self::Sint>, Self::Error>;
}

#[async_trait]
pub trait MPCECProtocol<F, S, N, G>
where
    F: FftField,               // scalar field of the EC group
    S: SecretSharingScheme<F>, // shared-scalar type
    N: Network,
    G: CurveGroup<ScalarField = F>,
{
    type Error;

    /// PUBLIC SCALAR MULTIPLICATION PROTOCOL
    ///
    /// Computes pk = sk_shared * G  (G is public)
    async fn scalar_mul_basepoint(&mut self, sk_shared: S) -> Result<G, Self::Error>;

    async fn open_point(&self, point: Vec<G>, net: Arc<N>) -> Result<G, Self::Error>;
}
