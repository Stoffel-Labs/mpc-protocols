use crate::common::{
    rbc::RbcError,
    share::{avss::AvssError, feldman::FeldmanShamirShare, ShareError},
};
use ark_ec::CurveGroup;
use ark_ff::FftField;
use std::collections::HashMap;
use thiserror::Error;

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
}

/// Store for one triple session
#[derive(Clone, Debug)]
pub struct TripleGenStore<F: FftField, C: CurveGroup<ScalarField = F>> {
    pub received: HashMap<usize, FeldmanShamirShare<F, C>>,
    pub reception_tracker: Vec<bool>,
    pub output: Option<BeaverTriple<F, C>>,
}

impl<F: FftField, C: CurveGroup<ScalarField = F>> TripleGenStore<F, C> {
    pub fn empty(num_dealers: usize) -> Self {
        Self {
            received: HashMap::new(),
            reception_tracker: vec![false; num_dealers],
            output: None,
        }
    }
}
