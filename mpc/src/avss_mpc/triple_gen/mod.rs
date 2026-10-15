use crate::{
    avss_mpc::AvssSessionId,
    common::{
        rbc::RbcError,
        share::{avss::AvssError, feldman::FeldmanShamirShare, ShareError},
    },
};
use ark_ec::CurveGroup;
use ark_ff::FftField;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use tokio::sync::oneshot::{channel, Receiver, Sender};

pub mod triple_gen;

/// Output triple: local shares of a, b, and c = ab
#[derive(Clone, Debug)]
pub struct BeaverTriple<F: FftField, C: CurveGroup<ScalarField = F>> {
    pub a: FeldmanShamirShare<F, C>,
    pub b: FeldmanShamirShare<F, C>,
    pub c: FeldmanShamirShare<F, C>,
}

#[derive(Debug, Error)]
pub enum TripleGenError {
    #[error("avss error: {0}")]
    Avss(#[from] AvssError),
    #[error("missing avss output for dealer {0}")]
    MissingDealer(usize),
    #[error("commitment length mismatch")]
    CommitmentLengthMismatch,
    #[error("Not a dealer")]
    NotADealer,
    #[error("rbc error: {0:?}")]
    RbcError(#[from] RbcError),
    #[error("ShareError: {0}")]
    ShareError(#[from] ShareError),
    #[error("invalid share length")]
    InvalidShareLength,
    #[error("error sending the result: {0:?}")]
    SendError(AvssSessionId),
    #[error("error receiving the result: {0:?}")]
    ReceiveError(AvssSessionId),
    #[error("no such session ID exists: {0:?}")]
    NoSuchSessionId(AvssSessionId),
    #[error("result already received: {0:?}")]
    ResultAlreadyReceived(AvssSessionId),
    #[error("multiplication {0:?} did not complete in time")]
    Timeout(AvssSessionId),
    #[error("Store Limit")]
    LimitError,
    #[error("sacrifice check failed for session {0:?}: at least one generated triple is invalid")]
    CheckFailed(AvssSessionId),
    #[error("invalid batch size: gen_triple needs at least one real triple plus one sacrifice")]
    InvalidBatchSize,
    #[error("error while serializing an arkworks object: {0:?}")]
    ArkSerialization(#[from] ark_serialize::SerializationError),
    #[error("error while deserializing an arkworks object: {0:?}")]
    ArkDeserialization(ark_serialize::SerializationError),
    #[error("error during bincode serialization: {0:?}")]
    BincodeSerializationError(#[from] Box<bincode::ErrorKind>),
    #[error("unauthenticated or malformed sacrifice-check message from sender {0}")]
    InvalidCheckMessage(usize),
}

/// Store for one triple session
#[derive(Debug)]
pub struct TripleGenStore<F: FftField, C: CurveGroup<ScalarField = F>> {
    pub received: HashMap<usize, Vec<FeldmanShamirShare<F, C>>>,
    pub reception_tracker: Vec<bool>,
    pub output: Option<Vec<BeaverTriple<F, C>>>,
    pub output_sender: Option<Sender<Vec<BeaverTriple<F, C>>>>,
    pub output_receiver: Option<Receiver<Vec<BeaverTriple<F, C>>>>,
}

impl<F: FftField, C: CurveGroup<ScalarField = F>> TripleGenStore<F, C> {
    pub fn empty(num_dealers: usize) -> Self {
        let (output_sender, output_receiver) = channel();
        Self {
            received: HashMap::new(),
            reception_tracker: vec![false; num_dealers],
            output: None,
            output_sender: Some(output_sender),
            output_receiver: Some(output_receiver),
        }
    }
}

/// Message carrying this party's own share(s) for one round of the sacrifice-check
/// opening (round 0: rho/sigma, round 1: check)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TripleCheckMessage {
    pub sender: usize,
    pub session_id: AvssSessionId,
    pub payload: Vec<u8>,
}

impl TripleCheckMessage {
    pub fn new(sender: usize, session_id: AvssSessionId, payload: Vec<u8>) -> Self {
        Self {
            sender,
            session_id,
            payload,
        }
    }
}

/// Raw per-sender receive buffer for the sacrifice-check opening rounds. Deliberately
/// dumb: it only stores what arrived from each sender. All threshold/verification/
/// finalization logic lives in `gen_triple` itself, which is the only place that knows
/// the expected commitments, the batch size, and the Fiat-Shamir challenge.
#[derive(Debug)]
pub struct TripleCheckStore<F: FftField, C: CurveGroup<ScalarField = F>> {
    pub received_rho_sigma:
        HashMap<usize, (Vec<FeldmanShamirShare<F, C>>, Vec<FeldmanShamirShare<F, C>>)>,
    pub received_check: HashMap<usize, Vec<FeldmanShamirShare<F, C>>>,
}

impl<F: FftField, C: CurveGroup<ScalarField = F>> TripleCheckStore<F, C> {
    pub fn empty() -> Self {
        Self {
            received_rho_sigma: HashMap::new(),
            received_check: HashMap::new(),
        }
    }
}
