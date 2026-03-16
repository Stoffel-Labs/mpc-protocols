use crate::{
    avss_mpc::AvssSessionId,
    common::{
        rbc::RbcError,
        share::{avss::AvssError, feldman::FeldmanShamirShare, ShareError},
    },
};
use ark_ec::CurveGroup;
use ark_ff::FftField;
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
    #[error("invalid session ID: calling_protocol is None")]
    InvalidSessionId,
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
