use crate::{
    common::{lagrange_interpolate, rbc::RbcError, share::ShareError},
    honeybadger::{
        batch_recon::BatchReconError,
        mul::MulError,
        mul_pub::MulPubError,
        robust_interpolate::{robust_interpolate::RobustShare, InterpolateError},
        SessionId,
    },
};
use ark_ff::{BigInteger, FftField, PrimeField};
use ark_poly::{univariate::DensePolynomial, EvaluationDomain, GeneralEvaluationDomain};
use ark_serialize::SerializationError;
use bincode::ErrorKind;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use stoffelnet::network_utils::NetworkError;
use thiserror::Error;
use tokio::sync::oneshot::{channel, Receiver, Sender};

pub mod fpmul;
pub mod prandint;
pub mod rand_bit;
pub mod truncpr;
//--------------------------------------------Rand-bit--------------------------------------------
#[derive(Error, Debug)]
pub enum RandBitError {
    #[error("incompatible treshold ({0:}) and number of parties {1:}")]
    IncompatibleNumberOfParties(usize, usize),
    #[error("the square multiplication was not completed successfuly")]
    SquareMult(#[from] MulError),
    #[error("the square is zero")]
    ZeroSquare,
    #[error("the square root does not exist")]
    SquareRoot,
    #[error("the inverse does not exist")]
    Inverse,
    #[error("number of random shares and degree-2t zero-sharings must match")]
    Incompatible,
    #[error("Duplicate input: {0}")]
    Duplicate(String),
    #[error("waiting for more openings")]
    WaitForOk,
    #[error("error in batch reconstruction: {0:?}")]
    BatchRecError(#[from] BatchReconError),
    #[error("error during deserialization: {0:?}")]
    SerializationError(#[from] SerializationError),
    #[error("error operating with the shares: {0:?}")]
    ShareError(#[from] ShareError),
    #[error("error sending the result: {0:?}")]
    SendError(SessionId),
    #[error("error receiving the result: {0:?}")]
    ReceiveError(SessionId),
    #[error("storage limit exceeded: {0}")]
    LimitError(String),
    #[error("no such session ID exists: {0:?}")]
    NoSuchSessionId(SessionId),
    #[error("unknown calling protocol in session ID {0:?}")]
    SessionIdError(SessionId),
    #[error("cannot create {0:?} random bits at once")]
    ShareLimitError(usize),
    #[error("mul pub error: {0:?}")]
    MulPubError(MulPubError),
    #[error("failed to clear the store for session {0:?}")]
    ClearStoreError(SessionId),
    #[error("result already received: {0:?}")]
    ResultAlreadyReceived(SessionId),
    #[error("multiplication {0:?} did not complete in time")]
    Timeout(SessionId),
    #[error("received abort signal")]
    Abort,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ProtocolState {
    Initialized,
    NotInitialized,
    Finished,
}

#[derive(Debug)]
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
    pub output_open: HashMap<u8, Vec<F>>,
    pub output_sender: Option<Sender<Vec<RobustShare<F>>>>,
    pub output_receiver: Option<Receiver<Vec<RobustShare<F>>>>,
}

impl<F> RandBitStorage<F>
where
    F: FftField,
{
    pub fn empty() -> Self {
        let (output_sender, output_receiver) = channel();
        Self {
            protocol_state: ProtocolState::NotInitialized,
            protocol_output: None,
            a_share: None,
            output_open: HashMap::new(),
            output_sender: Some(output_sender),
            output_receiver: Some(output_receiver),
        }
    }
}

//--------------------------------------------PRandInt--------------------------------------------
#[derive(Debug, Error)]
pub enum PRandIntError {
    /// The parameters for the precision are too big
    #[error("the parameters for k and l surpassed the field capacity")]
    SurpassedFieldCapacity,
    #[error("RISS equivocation detected from party {0} for tset {1:?}")]
    EquivocationDetected(usize, Vec<usize>),
    #[error("error in RBC: {0:?}")]
    RbcError(#[from] RbcError),
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
    #[error("unknown calling protocol in session ID {0:?}")]
    SessionIdError(SessionId),
    #[error("error sending the result: {0:?}")]
    SendError(SessionId),
    #[error("error receiving the result: {0:?}")]
    ReceiveError(SessionId),
    #[error("InterpolateError: {0}")]
    InterpolateError(#[from] InterpolateError),
    #[error("no such session ID exists: {0:?}")]
    NoSuchSessionId(SessionId),
    #[error("result already received: {0:?}")]
    ResultAlreadyReceived(SessionId),
    #[error("multiplication {0:?} did not complete in time")]
    Timeout(SessionId),
    #[error("Store Limit")]
    LimitError,
    #[error("Invalid message: {0}")]
    InvalidMessage(String),
    #[error("no PRSS keys installed; run the key setup or use the RISS path")]
    NoPrssKeys,
    #[error("PRSS error: {0:?}")]
    PrssError(#[from] crate::honeybadger::prss::PrssError),
}

/// Length of the blinding nonce in a RISS commitment.
///
/// The commitment must hide `r_T^i` from the parties inside `T`, who receive it over RBC. A bare
/// `H(values)` would not: a mask width of 40 bits is `2^40` hashes to brute-force. The nonce makes
/// hiding independent of whatever width the caller picked.
pub const PRANDINT_NONCE_LEN: usize = 32;

/// Length of a RISS commitment digest (SHA-256).
pub const PRANDINT_COMMIT_LEN: usize = 32;

/// One party's RISS contribution to one unqualified set, sent point-to-point to the parties
/// outside `T`.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PRandIntMessage {
    /// ID of the sender of the message.
    pub sender_id: usize,
    pub session_id: SessionId,
    pub tset: Vec<usize>,
    pub r_t: Vec<BigUint>,
    pub nonce: [u8; PRANDINT_NONCE_LEN],
}

impl PRandIntMessage {
    /// Creates a new PRandIntMessage.
    pub fn new(
        sender_id: usize,
        session_id: SessionId,
        tset: Vec<usize>,
        r_t: Vec<BigUint>,
        nonce: [u8; PRANDINT_NONCE_LEN],
    ) -> Self {
        Self {
            sender_id,
            session_id,
            tset,
            r_t,
            nonce,
        }
    }
}

/// A sender's commitments to *all* of its `C(n,t)` RISS contributions, reliably broadcast once per
/// session, indexed by the rank of the unqualified set in `all_tsets`.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PRandIntCommitMessage {
    pub sender_id: usize,
    pub session_id: SessionId,
    pub commitments: Vec<[u8; PRANDINT_COMMIT_LEN]>,
}

impl PRandIntCommitMessage {
    pub fn new(
        sender_id: usize,
        session_id: SessionId,
        commitments: Vec<[u8; PRANDINT_COMMIT_LEN]>,
    ) -> Self {
        Self {
            sender_id,
            session_id,
            commitments,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrandState {
    Initialized,
    IntFinished,
}

#[derive(Debug)]
pub struct PRandIntStore<G: PrimeField> {
    /// For every maximal unqualified set T that excludes this player,
    /// we store the full mask r_T = sum_i r_T^i
    pub batch_size: Option<usize>,
    /// Openings that arrived before this session was locally initialized, or before their sender's
    /// commitment was delivered by RBC. Replayed from both of those points.
    pub pending_riss_messages: Vec<PRandIntMessage>,
    /// Running total of `riss_msg_weight` over every message currently in `pending_riss_messages`.
    pub pending_riss_bytes: usize,
    /// Contributions verified against their sender's commitment and accepted into the share sum.
    pub riss_shares: HashMap<Vec<usize>, HashMap<usize, Vec<BigUint>>>, // tset -> {sender -> val}
    /// RBC-delivered commitment vectors, keyed by sender, indexed by unqualified-set rank.
    pub commitments: HashMap<usize, Vec<[u8; PRANDINT_COMMIT_LEN]>>,
    /// This party's own contributions, held back until every party has committed.
    ///
    /// Committing before opening is only worth anything if the commitment is fixed *before* its
    /// sender sees anyone else's values. Sending our openings the moment we broadcast would let a
    /// corrupt party sit on its own broadcast, collect the honest openings, choose its values to
    /// steer the sum, and only then commit — binding to a choice made after the fact constrains
    /// nothing.
    pub my_openings: Vec<(Vec<usize>, Vec<BigUint>, [u8; PRANDINT_NONCE_LEN])>,
    /// Whether the barrier has already fired. The release path is reachable from both
    /// `generate_riss` and every `drain_rbc_output`, and the openings must go out exactly once.
    pub openings_sent: bool,
    pub r_t: HashMap<Vec<usize>, Vec<BigUint>>,
    pub no_of_tsets: Option<usize>,
    /// PRandInt output.
    pub share_r_p: Option<Vec<RobustShare<G>>>,
    pub state: PrandState,
    pub output_int_sender: Option<Sender<Vec<RobustShare<G>>>>,
    pub output_int_receiver: Option<Receiver<Vec<RobustShare<G>>>>,
    pub r_t_bound: Option<BigUint>,
}

impl<G: PrimeField> PRandIntStore<G> {
    pub fn empty() -> Self {
        let (output_int_sender, output_int_receiver) = channel();
        Self {
            batch_size: None,
            pending_riss_messages: Vec::new(),
            pending_riss_bytes: 0,
            riss_shares: HashMap::new(),
            commitments: HashMap::new(),
            my_openings: Vec::new(),
            openings_sent: false,
            r_t: HashMap::new(),
            no_of_tsets: None,
            share_r_p: None,
            state: PrandState::Initialized,
            output_int_sender: Some(output_int_sender),
            output_int_receiver: Some(output_int_receiver),
            r_t_bound: None,
        }
    }
}

pub fn build_all_f_polys<H: PrimeField>(
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
    #[error("ShareError: {0}")]
    ShareError(#[from] ShareError),
    #[error("error sending the result: {0:?}")]
    SendError(SessionId),
    #[error("error receiving the result: {0:?}")]
    ReceiveError(SessionId),
    #[error("InterpolateError: {0}")]
    InterpolateError(#[from] InterpolateError),
    #[error("malformed session ID {0:?}")]
    SessionIdError(SessionId),
    #[error("no such session ID exists: {0:?}")]
    NoSuchSessionId(SessionId),
    #[error("result already received: {0:?}")]
    ResultAlreadyReceived(SessionId),
    #[error("multiplication {0:?} did not complete in time")]
    Timeout(SessionId),
    #[error("Store Limit")]
    LimitError,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TruncState {
    Initialized,
    Finished,
}

#[derive(Debug)]
pub struct TruncPrStore<F: PrimeField> {
    pub m: usize,
    pub k: usize,
    pub r_dash: Option<RobustShare<F>>, // [r'] = sum 2^i [r_i]
    pub share_a: Option<RobustShare<F>>,
    pub open_buf: HashMap<usize, RobustShare<F>>, // sender_id -> share of (b + r)
    pub share_d: Option<RobustShare<F>>,          // [d]
    pub state: TruncState,
    pub output_sender: Option<Sender<RobustShare<F>>>,
    pub output_receiver: Option<Receiver<RobustShare<F>>>,
}

impl<F: PrimeField> TruncPrStore<F> {
    pub fn empty() -> Self {
        let (output_sender, output_receiver) = channel();
        Self {
            m: 0,
            k: 0,
            r_dash: None,
            share_a: None,
            open_buf: HashMap::new(),
            share_d: None,
            state: TruncState::Initialized,
            output_sender: Some(output_sender),
            output_receiver: Some(output_receiver),
        }
    }
}

// ---------- helpers ----------

pub fn pow2_f<F: PrimeField>(e: usize) -> F {
    F::from(2u64).pow(&[e as u64])
}

pub fn mod_pow_2_from_field<F: PrimeField>(x: F, m: usize) -> F {
    let bigint = x.into_bigint();
    let mut bytes = bigint.to_bytes_le();

    let full_bytes = m / 8;
    let extra_bits = m % 8;

    let usable_bytes = if extra_bits == 0 {
        full_bytes
    } else {
        full_bytes + 1
    };

    // Truncate extra bytes
    if bytes.len() > usable_bytes {
        bytes.truncate(usable_bytes);
    }

    if extra_bits > 0 && !bytes.is_empty() {
        let mask = (1u8 << extra_bits) - 1;
        bytes[full_bytes] &= mask;
    }

    // Interpret as an integer modulo q and return it as a field element.
    F::from_le_bytes_mod_order(&bytes)
}
