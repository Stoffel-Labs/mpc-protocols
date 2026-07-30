use std::collections::HashMap;

use crate::honeybadger::bitwise::pre_mulc::PhaseState;
use crate::honeybadger::mul_pub::MulPubError;
use crate::honeybadger::{
    robust_interpolate::robust_interpolate::RobustShare, triple_gen::ShamirBeaverTriple,
};
use crate::{
    common::{rbc::RbcError, share::ShareError},
    honeybadger::{
        batch_recon::BatchReconError, mul::MulError, robust_interpolate::InterpolateError,
        SessionId,
    },
};
use ark_ff::{FftField, PrimeField};
use ark_serialize::SerializationError;
use bincode::ErrorKind;
use stoffelnet::network_utils::NetworkError;
use thiserror::Error;

pub mod app_rec;
pub mod bit_dec;
pub mod kor_cl;
pub mod kor_cs;
pub mod mod2;
pub mod pre_bitlt;
pub mod pre_mod2m;
pub mod pre_mulc;
pub mod suf_mul_inv;
pub mod suf_or;

#[derive(Clone, Debug)]
pub struct PreMulCPrep<F: FftField> {
    pub w: Vec<RobustShare<F>>,
    pub z: Vec<RobustShare<F>>,
    /// r_j values from the offline phase. r_j = z_j^{-1}.
    /// Stored here so SufMulInv can compute [S_j^{-1}] = [r'_{k-1-j}] * (M'_{k-1-j})^{-1}
    /// without any extra rounds.
    pub r: Vec<RobustShare<F>>,
    pub triples: Vec<ShamirBeaverTriple<F>>,
}

impl<F: FftField> PreMulCPrep<F> {
    /// The bundle's width — the number of correlated elements it covers.
    pub fn pk(&self) -> usize {
        self.w.len()
    }
}
#[derive(Clone, Debug)]
pub struct PRandMPrep<F: FftField> {
    pub r_double_prime: RobustShare<F>,
    pub r_prime: RobustShare<F>,
    pub r_prime_bits: Vec<RobustShare<F>>,
}
impl<F: FftField> PRandMPrep<F> {
    /// Protocol 2.2 step 3: computes [r'] = Σ_{i=0}^{m-1} 2^i * [b_i].
    /// `r_double_prime` is the PRandInt(k + κ − m) output.
    /// `r_prime_bits` must be non-empty (m >= 1), LSB first.
    pub fn from_prand_outputs(
        r_double_prime: RobustShare<F>,
        r_prime_bits: Vec<RobustShare<F>>,
    ) -> Result<Self, ShareError> {
        if r_prime_bits.is_empty() {
            return Err(ShareError::InvalidInput);
        }
        let mut r_prime = r_prime_bits[0].clone();
        for (i, bit) in r_prime_bits.iter().enumerate().skip(1) {
            let coeff = F::from(2u64).pow([i as u64]);
            r_prime = (r_prime + (bit.clone() * coeff)?)?;
        }
        Ok(Self {
            r_double_prime,
            r_prime,
            r_prime_bits,
        })
    }
}
#[derive(Debug, Error)]
pub enum PreMulCError {
    #[error("mul error: {0}")]
    MulError(#[from] MulError),
    #[error("rbc error: {0}")]
    RbcError(#[from] RbcError),
    #[error("share error: {0}")]
    ShareError(#[from] ShareError),
    #[error("serialization: {0}")]
    SerializationError(#[from] SerializationError),
    #[error("bincode: {0}")]
    BincodeError(#[from] Box<ErrorKind>),
    #[error("network: {0}")]
    NetworkError(#[from] NetworkError),
    #[error("interpolate: {0}")]
    InterpolateError(#[from] InterpolateError),
    #[error("no session: {0:?}")]
    NoSuchSessionId(SessionId),
    #[error("already received: {0:?}")]
    ResultAlreadyReceived(SessionId),
    #[error("send error: {0:?}")]
    SendError(SessionId),
    #[error("receive error: {0:?}")]
    ReceiveError(SessionId),
    #[error("timeout: {0:?}")]
    Timeout(SessionId),
    #[error("duplicate from {0}")]
    Duplicate(usize),
    #[error("session limit")]
    LimitError,
    #[error("clear store: {0:?}")]
    ClearStoreError(SessionId),
    #[error("bad session id: {0:?}")]
    SessionIdError(SessionId),
    #[error("abort")]
    Abort,
    #[error("empty input")]
    EmptyInput,
    #[error("error in batch reconstruction: {0:?}")]
    BatchRecError(#[from] BatchReconError),
    #[error("mul pub error: {0}")]
    MulPubError(#[from] MulPubError),
}

#[derive(Debug, Error)]
pub enum Mod2Error {
    #[error("rbc error: {0}")]
    RbcError(#[from] RbcError),
    #[error("share error: {0}")]
    ShareError(#[from] ShareError),
    #[error("serialization: {0}")]
    SerializationError(#[from] SerializationError),
    #[error("no session: {0:?}")]
    NoSuchSessionId(SessionId),
    #[error("already received: {0:?}")]
    ResultAlreadyReceived(SessionId),
    #[error("send error: {0:?}")]
    SendError(SessionId),
    #[error("receive error: {0:?}")]
    ReceiveError(SessionId),
    #[error("timeout: {0:?}")]
    Timeout(SessionId),
    #[error("bad session id: {0:?}")]
    SessionIdError(SessionId),
    #[error("session limit")]
    LimitError,
    #[error("clear store: {0:?}")]
    ClearStoreError(SessionId),
    #[error("abort")]
    Abort,
}

/// All preprocessing material required for one PreBitLT execution on k bits.
#[derive(Clone, Debug)]
pub struct PreBitLTPrep<F: FftField> {
    /// Preprocessing for the SufMulInv sub-protocol (one PreMulCPrep for k inputs).
    pub suf_mul_inv_prep: PreMulCPrep<F>,
    /// k-1 Beaver triples for the Multiply phase (step 4 of Protocol 11).
    pub mul_triples: Vec<ShamirBeaverTriple<F>>,
    /// k PRandMPrep values for the k parallel Mod2 calls (step 5 of Protocol 11).
    /// Index i corresponds to bit u_{i+1} (0-indexed).
    pub mod2_preps: Vec<PRandMPrep<F>>,
}

// ── Error ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum PreBitLTError {
    #[error("SufMulInv/PreMulC error: {0}")]
    PreMulCError(#[from] PreMulCError),
    #[error("Multiply error: {0}")]
    MulError(#[from] MulError),
    #[error("Mod2 error: {0}")]
    Mod2Error(#[from] Mod2Error),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("session ID error: {0:?}")]
    SessionIdError(SessionId),
    #[error("share error: {0}")]
    ShareError(#[from] ShareError),
}

// ── Preprocessing ──────────────────────────────────────────────────────────────

/// All preprocessing for one PreMod2m execution.
#[derive(Clone, Debug)]
pub struct PreMod2mPrep<F: FftField> {
    /// PRandM(k, m) output: r'', r', and the m random bits {r'_j} (LSB-first).
    pub prandm: PRandMPrep<F>,
    /// Preprocessing for the inner PreBitLT call (operating on m-bit inputs).
    pub pre_bitlt: PreBitLTPrep<F>,
}

// ── Error ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum PreMod2mError {
    #[error("PreBitLT error: {0}")]
    PreBitLTError(#[from] PreBitLTError),
    #[error("RBC error: {0}")]
    RbcError(#[from] RbcError),
    #[error("share error: {0}")]
    ShareError(#[from] crate::common::share::ShareError),
    #[error("serialization: {0}")]
    SerializationError(#[from] SerializationError),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("no session: {0:?}")]
    NoSuchSessionId(SessionId),
    #[error("session limit")]
    LimitError,
    #[error("result already received: {0:?}")]
    ResultAlreadyReceived(SessionId),
    #[error("send error: {0:?}")]
    SendError(SessionId),
    #[error("receive error: {0:?}")]
    ReceiveError(SessionId),
    #[error("timeout: {0:?}")]
    Timeout(SessionId),
    #[error("session ID error: {0:?}")]
    SessionIdError(SessionId),
    #[error("abort")]
    Abort,
    #[error("clear store: {0:?}")]
    ClearStoreError(SessionId),
}

#[derive(Debug, Error)]
pub enum KOrCSError {
    #[error("mul error: {0}")]
    MulError(#[from] MulError),
    #[error("batch recon error: {0}")]
    BatchReconError(#[from] BatchReconError),
    #[error("share error: {0}")]
    ShareError(#[from] ShareError),
    #[error("serialization: {0}")]
    SerializationError(#[from] SerializationError),
    #[error("bad session id: {0:?}")]
    SessionIdError(SessionId),
    #[error("no session: {0:?}")]
    NoSuchSessionId(SessionId),
    #[error("already received: {0:?}")]
    ResultAlreadyReceived(SessionId),
    #[error("send error: {0:?}")]
    SendError(SessionId),
    #[error("receive error: {0:?}")]
    ReceiveError(SessionId),
    #[error("timeout: {0:?}")]
    Timeout(SessionId),
    #[error("session limit")]
    LimitError,
    #[error("wrong input length")]
    LengthError,
    #[error("abort")]
    Abort,
}

#[derive(Debug, Error)]
pub enum KOrCLError {
    #[error("rbc error: {0}")]
    RbcError(#[from] RbcError),
    #[error("share error: {0}")]
    ShareError(#[from] ShareError),
    #[error("kor_cs error: {0}")]
    KOrCSError(#[from] KOrCSError),
    #[error("serialization: {0}")]
    SerializationError(#[from] SerializationError),
    #[error("no session: {0:?}")]
    NoSuchSessionId(SessionId),
    #[error("already received: {0:?}")]
    ResultAlreadyReceived(SessionId),
    #[error("send error: {0:?}")]
    SendError(SessionId),
    #[error("receive error: {0:?}")]
    ReceiveError(SessionId),
    #[error("timeout: {0:?}")]
    Timeout(SessionId),
    #[error("bad session id: {0:?}")]
    SessionIdError(SessionId),
    #[error("session limit")]
    LimitError,
    #[error("clear store: {0:?}")]
    ClearStoreError(SessionId),
    #[error("abort")]
    Abort,
    #[error("wrong input length")]
    LengthError,
}

// ── Reveal store ───────────────────────────────────────────────────────────────

/// Local-only output of `try_finalize`'s Phase 1-2 (reveal reconstruction +
/// bit/prefix extraction), everything `init` needs to drive Phase 3 (nested
/// PreBitLT) and Phase 4 (local assembly) itself: `c_bits` and `r_prime_bits`
/// (PreBitLT's public/secret inputs), `pre_bitlt_prep`, and `c_prefix_vals`/
/// `s_vals` (needed again for Phase 4's assembly formula).
pub type PreMod2mIntermediate<F> = (
    Vec<F>,
    Vec<RobustShare<F>>,
    PreBitLTPrep<F>,
    Vec<F>,
    Vec<RobustShare<F>>,
);

pub struct PreMod2mStore<F: PrimeField + FftField> {
    pub state: PhaseState,
    /// party_id → their share of v
    pub received_shares: HashMap<usize, F>,
    /// Number of prefix reductions; set by `init` before starting the RBC
    /// broadcast so `try_finalize` can extract bits once `c` is reconstructed.
    pub m: Option<usize>,
    /// Stashed by `init` so `try_finalize` can run Phase 2's s_vals and
    /// gather Phase 3's inputs after the reveal, without re-supplying `prep`.
    pub r_prime_bits: Option<Vec<RobustShare<F>>>,
    pub pre_bitlt_prep: Option<PreBitLTPrep<F>>,
    /// Carries Phase 1-2's local-only result — try_finalize never touches the
    /// network, so this always resolves promptly regardless of who's driving
    /// PreBitLT's own round-trip; `init` awaits this itself and then runs
    /// Phase 3-4 in its own task, not the dispatch loop's.
    pub output_sender: Option<tokio::sync::oneshot::Sender<PreMod2mIntermediate<F>>>,
    pub output_receiver: Option<tokio::sync::oneshot::Receiver<PreMod2mIntermediate<F>>>,
}

impl<F: PrimeField + FftField> std::fmt::Debug for PreMod2mStore<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreMod2mStore")
            .field("state", &self.state)
            .field("received_shares", &self.received_shares.len())
            .field("m", &self.m)
            .finish()
    }
}

impl<F: PrimeField + FftField> PreMod2mStore<F> {
    fn new() -> Self {
        let (tx, rx) = tokio::sync::oneshot::channel();
        Self {
            state: PhaseState::Waiting,
            received_shares: HashMap::new(),
            m: None,
            r_prime_bits: None,
            pre_bitlt_prep: None,
            output_sender: Some(tx),
            output_receiver: Some(rx),
        }
    }
}

/// All preprocessing material required for one AppRec execution on a k-bit input.
#[derive(Clone, Debug)]
pub struct AppRecPrep<F: FftField> {
    /// BitDec's own preprocessing (internally PreMod2m with m = k-1).
    pub bitdec_prep: PreMod2mPrep<F>,
    /// SufOr's preprocessing, sized for k-1 inputs.
    pub sufor_prep: PreMulCPrep<F>,
    /// k-1 triples for step 3's XOR round (`b_i * b_{k-1}`).
    pub xor_triples: Vec<ShamirBeaverTriple<F>>,
    /// 2 triples for the batched round: `v*b` (step 7) and `c_0*b_{k-1}` (step 6).
    pub batch_triples: Vec<ShamirBeaverTriple<F>>,
    /// 1 triple for the final round: `v*w'` (step 8).
    pub final_triple: Vec<ShamirBeaverTriple<F>>,
    /// Random bits for the final TruncPr call, sized for m = 2(k-f-1).
    pub trunc_r_bits: Vec<RobustShare<F>>,
    /// Random r'' for the final TruncPr call, sized for k_trunc = 2k.
    pub trunc_r_int: RobustShare<F>,
}
