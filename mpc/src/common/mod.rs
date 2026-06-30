pub mod rbc;
pub mod session_store;

/// In MPC, the most fundamental underlying type is called a share.
/// Think of a share as a piece of a secret that has been split among a set of parties.
/// As such, on its own, you don't derive any information. But when combined with other parties,
/// a certain number of shares can reconstruct a secret.
/// When wanting to implement your own custom MPC protocols that can plug
/// into the StoffelVM, you must implement the Share type.
pub mod share;

/// Implementation of the hbACSS protocol from https://eprint.iacr.org/2021/159.
pub mod acss;

pub mod math;
pub mod types;
pub mod utils;

use crate::common::{
    rbc::{rbc_store::Msg, RbcError},
    share::ShareError,
};
use ark_ff::{FftField, Zero};
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use async_trait::async_trait;
use std::any::{Any, TypeId};
use std::fmt;
use std::{
    collections::{HashMap, HashSet},
    marker::PhantomData,
    ops::{Add, Mul, Sub},
    sync::{Arc, Mutex, OnceLock},
    usize,
};
use stoffelnet::network_utils::{ClientId, Network, PartyId};
use tokio::sync::mpsc::Sender;

pub use session_store::{RetiredSet, SessionStore, DEFAULT_RETIRED_CAP};

type DomainCacheMap = HashMap<(TypeId, usize), Box<dyn Any + Send + Sync>>;

static EVALUATION_DOMAIN_CACHE: OnceLock<Mutex<DomainCacheMap>> = OnceLock::new();

/// Returns the `GeneralEvaluationDomain<F>` of size `n`, memoized across calls.
///
/// The domain is a pure deterministic function of `(F, n)`, so caching is exact (no correctness or
/// security impact). The cache is keyed by `(TypeId::<F>, n)` and stays tiny/bounded (a handful of
/// field types × a handful of party counts), so it needs no eviction. `GeneralEvaluationDomain::new`
/// is ~2.9 µs and was rebuilt on every `recover_secret` / interpolation call.
pub fn get_or_create_evaluation_domain<F: FftField + 'static>(
    n: usize,
) -> Option<GeneralEvaluationDomain<F>> {
    let key = (TypeId::of::<F>(), n);
    let cache = EVALUATION_DOMAIN_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(guard) = cache.lock() {
        if let Some(boxed) = guard.get(&key) {
            if let Some(d) = boxed.downcast_ref::<GeneralEvaluationDomain<F>>() {
                return Some(d.clone());
            }
        }
    }
    let domain = GeneralEvaluationDomain::<F>::new(n)?;
    if let Ok(mut guard) = cache.lock() {
        guard.insert(key, Box::new(domain.clone()) as Box<dyn Any + Send + Sync>);
    }
    Some(domain)
}

static G0_CACHE: OnceLock<Mutex<DomainCacheMap>> = OnceLock::new();

/// Returns the cached `g0(x) = ∏_{i<n} (x - domain.element(i))` for `(F, n)`, if present.
/// Like the domain cache, g0 is a pure deterministic function of `(F, n)`, so memoization is exact.
pub fn get_cached_g0_polynomial<F: FftField + 'static>(n: usize) -> Option<DensePolynomial<F>> {
    let key = (TypeId::of::<F>(), n);
    let cache = G0_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let guard = cache.lock().ok()?;
    guard
        .get(&key)?
        .downcast_ref::<DensePolynomial<F>>()
        .cloned()
}

/// Stores a computed g0 polynomial under `(TypeId::<F>, n)`.
pub fn store_g0_polynomial<F: FftField + 'static>(n: usize, g0: DensePolynomial<F>) {
    let key = (TypeId::of::<F>(), n);
    if let Ok(mut guard) = G0_CACHE.get_or_init(|| Mutex::new(HashMap::new())).lock() {
        guard.insert(key, Box::new(g0) as Box<dyn Any + Send + Sync>);
    }
}

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ShamirShare<F: FftField, const N: usize, P> {
    pub share: [F; N],
    ///index of the share(x-values),can be different from the reciever ID
    pub id: usize,
    pub degree: usize,
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
        t: usize,
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
    let mut seen = HashSet::new();
    if !x_vals.iter().all(|s| seen.insert(s)) {
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

impl<F: FftField, const N: usize, P> Add<&F> for ShamirShare<F, N, P> {
    type Output = Result<Self, ShareError>;

    fn add(self, other: &F) -> Self::Output {
        let new_share: [F; N] = std::array::from_fn(|i| self.share[i] + other);

        Ok(Self {
            share: new_share,
            id: self.id,
            degree: self.degree,
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
            _sharetype: PhantomData,
        })
    }
}

/// In MPC, there needs to be a way for a dealer and the nodes to broadcast messages
/// to each other. And the receivers need to agree on the senders' messages.
/// The primitive that does this is called Reliable Broadcast (RBC).
/// When implementing your own custom MPC protocols, you must implement the RBC trait.
pub type RbcWrapFn<Id> = Arc<dyn Fn(Msg<Id>) -> Result<Vec<u8>, RbcError> + Send + Sync + 'static>;

#[async_trait]
pub trait RBC: Send + Sync {
    type Id: ProtocolSessionId;

    /// Creates a new instance
    fn new(
        id: usize,
        n: usize,
        t: usize,
        k: usize,
        output_sender: Sender<Self::Id>,
        wrapper: RbcWrapFn<Self::Id>,
    ) -> Result<Self, RbcError>
    where
        Self: Sized;
    /// Returns the unique identifier of the current party.
    fn id(&self) -> usize;
    async fn clear_store(&self);
    async fn clear_session(&self, session_id: Self::Id);
    async fn get_store(&self, session_id: Self::Id) -> Result<Vec<u8>, RbcError>;
    /// Required for initiating the broadcast
    async fn init<N: Network + Send + Sync>(
        &self,
        payload: Vec<u8>,
        session_id: Self::Id,
        parties: Arc<N>,
    ) -> Result<(), RbcError>;
    ///Processing messages sent by other nodes based on their type
    async fn process<N: Network + Send + Sync + 'static>(
        &self,
        msg: Msg<Self::Id>,
        parties: Arc<N>,
    ) -> Result<(), RbcError>;
    /// Broadcast messages to other nodes.
    async fn broadcast<N: Network + Send + Sync>(
        &self,
        msg: Msg<Self::Id>,
        net: Arc<N>,
    ) -> Result<(), RbcError>;
    /// Send to another node
    async fn send<N: Network + Send + Sync>(
        &self,
        msg: Msg<Self::Id>,
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

    async fn process(
        &mut self,
        sender_id: PartyId,
        raw_msg: Vec<u8>,
        net: Arc<N>,
    ) -> Result<(), Self::Error>;

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

/// A protocol identifier that fits into 8 bits.
///
pub trait ProtocolTag:
    Copy + Clone + Eq + Ord + std::hash::Hash + Send + Sync + fmt::Debug
{
    /// Encode the protocol into an 8-bit tag
    fn to_u8(self) -> u8;

    /// Decode the protocol from an 8-bit tag
    fn from_u8(v: u8) -> Option<Self>;
}

/// Fixed-layout session identifier.
///
/// Layout (u128):
/// [ reserved | protocol | slot | instance_id ]
///     8 bits    8 bits   80 bits   32 bits
///
/// where `slot` packs (exec_id 64 bits | sub_id 8 bits | round_id 8 bits) and is produced by
/// each type's `pack_slot`. `exec_id` is 64 bits so back-to-back sessions do not wrap.
/// Interpretation of `slot` is protocol-defined.
pub trait ProtocolSessionId:
    Copy + Clone + Eq + Ord + std::hash::Hash + Send + Sync + fmt::Debug
{
    type Protocol: ProtocolTag;

    /* ---------- construction ---------- */
    fn new(protocol: Self::Protocol, slot: u128, instance_id: u32) -> Self;

    /* ---------- fixed fields ---------- */
    fn calling_protocol(self) -> Option<Self::Protocol>;
    fn instance_id(self) -> u32;

    /* ---------- flexible field ---------- */

    /// Protocol-defined 80-bit field (round | sub | exec).
    fn slot(self) -> u128;

    /* ---------- raw access ---------- */
    fn as_u128(self) -> u128;

    /// # Safety
    /// Caller must ensure the raw value is well-formed.
    unsafe fn from_u128(raw: u128) -> Self;
}
