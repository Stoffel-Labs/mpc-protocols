use crate::{
    common::{lagrange_interpolate, share::ShareError},
    honeybadger::{
        batch_recon::BatchReconError,
        fpmul::f256::{F2_8Error, F2_8},
        mul::MulError,
        robust_interpolate::{robust_interpolate::RobustShare, InterpolateError},
        SessionId,
    },
};
use ark_ff::{BigInteger, FftField, PrimeField};
use ark_poly::{univariate::DensePolynomial, EvaluationDomain, GeneralEvaluationDomain};
use ark_serialize::SerializationError;
use bincode::ErrorKind;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use stoffelnet::network_utils::{NetworkError, PartyId};
use thiserror::Error;
use tokio::sync::mpsc::error::SendError;

pub mod f256;
pub mod fpmul;
pub mod prandbitd;
pub mod rand_bit;
pub mod truncpr;
//--------------------------------------------Rand-bit--------------------------------------------
#[derive(Error, Debug)]
pub enum RandBitError {
    #[error("incompatible treshold ({0:}) and number of parties {1:}")]
    IncompatibleNumberOfParties(usize, usize),
    #[error("error in the secure multiplication protocol: {0:?}")]
    MulError(#[from] MulError),
    #[error("the square multiplication was not completed successfuly")]
    SquareMult,
    #[error("the square is zero")]
    ZeroSquare,
    #[error("the square root does not exist")]
    SquareRoot,
    #[error("the inverse does not exist")]
    Inverse,
    #[error("not initialized error")]
    NotInitialized,
    #[error("error in batch reconstruction: {0:?}")]
    BatchRecError(#[from] BatchReconError),
    #[error("error during deserialization: {0:?}")]
    SerializationError(#[from] SerializationError),
    #[error("error operating with the shares: {0:?}")]
    ShareError(#[from] ShareError),
    #[error("error sending the finished session ID to the caller: {0:?}")]
    SenderError(#[from] SendError<SessionId>),
}

#[derive(Copy, Clone, Debug)]
pub enum ProtocolState {
    Initialized,
    NotInitialized,
    Finished,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RandBitMessage {
    pub sender: PartyId,
    pub session_id: SessionId,
    pub payload: Vec<u8>,
}

impl RandBitMessage {
    pub fn new(sender: PartyId, session_id: SessionId, payload: Vec<u8>) -> Self {
        Self {
            sender,
            session_id,
            payload,
        }
    }
}

#[derive(Clone, Debug)]
pub struct RandBitStorage<F>
where
    F: FftField,
{
    /// State of the protocol.
    pub protocol_state: ProtocolState,
    /// Output of the protocol. If the protocol is not finished yet, `protocol_output` will be
    /// [`None`].
    pub protocol_output: Option<Vec<RobustShare<F>>>,
    /// Share of `a`
    pub a_share: Option<Vec<RobustShare<F>>>,
}

impl<F> RandBitStorage<F>
where
    F: FftField,
{
    pub fn empty() -> Self {
        Self {
            protocol_state: ProtocolState::NotInitialized,
            protocol_output: None,
            a_share: None,
        }
    }
}

//--------------------------------------------Prandbitd--------------------------------------------
#[derive(Debug, Error)]
pub enum PRandError {
    /// The error occurs when communicating using the network.
    #[error("there was an error in the network: {0:?}")]
    NetworkError(#[from] NetworkError),
    #[error("error while serializing an arkworks object: {0:?}")]
    ArkSerialization(#[from] SerializationError),
    #[error("error while serializing an arkworks object: {0:?}")]
    ArkDeserialization(SerializationError),
    #[error("error while serializing the object into bytes: {0:?}")]
    SerializationError(#[from] Box<ErrorKind>),
    /// The protocol received an abort signal.
    #[error("received abort signal")]
    Abort,
    #[error("Duplicate input: {0}")]
    Duplicate(String),
    #[error("Not set:{0}")]
    NotSet(String),
    #[error("ShareError: {0}")]
    ShareError(#[from] ShareError),
    #[error("error sending the finished session ID to the caller: {0:?}")]
    SenderError(#[from] SendError<SessionId>),
    #[error("F2_8 Error: {0}")]
    F2_8Error(#[from] F2_8Error),
    #[error("InterpolateError: {0}")]
    InterpolateError(#[from] InterpolateError),
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub enum MessageType {
    RissMessage,
    OutputMessage,
}

/// Message sent in the Random Double Sharing protocol.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PRandBitDMessage {
    /// ID of the sender of the message.
    pub sender_id: usize,
    pub msg_type: MessageType,
    pub session_id: SessionId,
    pub tset: Vec<usize>,
    pub r_t: Vec<i64>,
    pub payload: Vec<u8>,
}

impl PRandBitDMessage {
    /// Creates a new PRandBitDMessage.
    pub fn new(
        sender_id: usize,
        msg_type: MessageType,
        session_id: SessionId,
        tset: Vec<usize>,
        r_t: Vec<i64>,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            sender_id,
            msg_type,
            session_id,
            tset,
            r_t,
            payload,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PRandBitDStore<F: PrimeField, G: PrimeField> {
    /// For every maximal unqualified set T that excludes this player,
    /// we store the full mask r_T = sum_i r_T^i
    pub riss_shares: HashMap<Vec<usize>, HashMap<usize, Vec<i64>>>, // tset -> {sender -> val}
    pub r_t: HashMap<Vec<usize>, Vec<i64>>,
    pub no_of_tsets: Option<usize>,
    pub share_r_q: Option<Vec<RobustShare<F>>>, //smaller field
    pub share_r_p: Option<Vec<RobustShare<G>>>, // PrandInt output
    pub share_b_q: Option<Vec<RobustShare<F>>>, //smaller field
    pub share_r_2: Option<Vec<F2_8>>,
    pub share_r_plus_b: HashMap<usize, Vec<RobustShare<F>>>,
    pub share_b_2: Vec<F2_8>,           //PrandBitD output
    pub share_b_p: Vec<RobustShare<G>>, //PrandBitD/PrandBitL output
}

impl<F: PrimeField, G: PrimeField> PRandBitDStore<F, G> {
    pub fn empty() -> Self {
        Self {
            riss_shares: HashMap::new(),
            r_t: HashMap::new(),
            no_of_tsets: None,
            share_r_q: None,
            share_r_p: None,
            share_b_q: None,
            share_r_2: None,
            share_r_plus_b: HashMap::new(),
            share_b_2: Vec::new(),
            share_b_p: Vec::new(),
        }
    }
}

pub async fn build_all_f_polys<H: PrimeField>(
    n: usize,
    tsets: Vec<Vec<usize>>,
) -> Result<HashMap<Vec<usize>, DensePolynomial<H>>, ShareError> {
    let domain =
        GeneralEvaluationDomain::<H>::new(n).ok_or_else(|| ShareError::NoSuitableDomain(n))?;
    tsets
        .into_iter()
        .map(|tset| {
            // Construct interpolation points
            let xs = std::iter::once(H::zero())
                .chain(tset.iter().map(|j| domain.element(*j)))
                .collect::<Vec<_>>();
            let ys = std::iter::once(H::one())
                .chain(std::iter::repeat(H::zero()).take(tset.len()))
                .collect::<Vec<_>>();
            // Interpolate polynomial
            let poly = lagrange_interpolate(&xs, &ys)?;
            Ok((tset, poly))
        })
        .collect()
}

//--------------------------------------------TruncPr--------------------------------------------
#[derive(Debug, Error)]
pub enum TruncPrError {
    /// The error occurs when communicating using the network.
    #[error("there was an error in the network: {0:?}")]
    NetworkError(#[from] NetworkError),
    #[error("error while serializing an arkworks object: {0:?}")]
    ArkSerialization(#[from] SerializationError),
    #[error("error while serializing an arkworks object: {0:?}")]
    ArkDeserialization(SerializationError),
    #[error("error while serializing the object into bytes: {0:?}")]
    SerializationError(#[from] Box<ErrorKind>),
    /// The protocol received an abort signal.
    #[error("received abort signal")]
    Abort,
    #[error("Duplicate input: {0}")]
    Duplicate(usize),
    #[error("Not set:{0}")]
    NotSet(String),
    #[error("ShareError: {0}")]
    ShareError(#[from] ShareError),
    #[error("error sending the thread asynchronously")]
    SendError(#[from] SendError<SessionId>),
    #[error("InterpolateError: {0}")]
    InterpolateError(#[from] InterpolateError),
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct TruncPrMessage {
    pub sender_id: usize,
    pub session_id: SessionId,
    pub payload: Vec<u8>,
}

impl TruncPrMessage {
    pub fn new(sender_id: usize, session_id: SessionId, share_bytes: Vec<u8>) -> Self {
        Self {
            sender_id,
            session_id,
            payload: share_bytes,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TruncPrStore<F: PrimeField> {
    pub m: usize,
    pub k: usize,
    pub r_dash: Option<RobustShare<F>>, // [r'] = sum 2^i [r_i]
    pub share_a: Option<RobustShare<F>>,
    pub open_buf: HashMap<usize, RobustShare<F>>, // sender_id -> share of (b + r)
    pub share_d: Option<RobustShare<F>>,          // [d]
}

impl<F: PrimeField> TruncPrStore<F> {
    pub fn empty() -> Self {
        Self {
            m: 0,
            k: 0,
            r_dash: None,
            share_a: None,
            open_buf: HashMap::new(),
            share_d: None,
        }
    }
}

// ---------- helpers ----------

pub fn pow2_f<F: PrimeField>(e: usize) -> F {
    F::from(2u64).pow(&[e as u64])
}

pub fn mod_pow2_from_field<F: PrimeField>(x: F, m: usize) -> F {
    let bigint = x.into_bigint();
    let mut bytes = bigint.to_bytes_le();

    // Zero out any bits above m
    let full_bytes = m / 8;
    let extra_bits = m % 8;

    // Truncate extra bytes
    if bytes.len() > full_bytes {
        bytes.truncate(full_bytes + 1);
    }

    if extra_bits > 0 && !bytes.is_empty() {
        let mask = (1u8 << extra_bits) - 1;
        bytes[full_bytes] &= mask;
    }

    // Interpret as an integer modulo q, return as field element
    F::from_le_bytes_mod_order(&bytes)
}
