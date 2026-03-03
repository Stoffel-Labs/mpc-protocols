pub mod share_gen_avss;

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

/// Error type for the Random Single Share (RanSha) protocol.
#[derive(Debug, Error)]
pub enum RanShaAvssError {
    #[error("Rbc error: {0:?}")]
    RbcError(#[from] RbcError),
    #[error("Avss error: {0:?}")]
    AvssError(#[from] AvssError),
    #[error("inner error: {0:?}")]
    ShareError(#[from] ShareError),
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
    #[error("Channel closed")]
    Abort,
}

#[derive(Debug)]
pub struct RanShaAvssStore<F: FftField, G: CurveGroup<ScalarField = F>> {
    pub initial_shares: HashMap<usize, FeldmanShamirShare<F, G>>,
    pub reception_tracker: Vec<bool>,
    pub computed_r_shares: Vec<FeldmanShamirShare<F, G>>,
    pub protocol_output: Vec<FeldmanShamirShare<F, G>>,
    pub output_sender: Option<Sender<Vec<FeldmanShamirShare<F, G>>>>,
    pub output_receiver: Option<Receiver<Vec<FeldmanShamirShare<F, G>>>>,
}

impl<F: FftField, G: CurveGroup<ScalarField = F>> RanShaAvssStore<F, G> {
    pub fn empty(n_parties: usize) -> Self {
        let (output_sender, output_receiver) = channel();
        Self {
            initial_shares: HashMap::new(),
            reception_tracker: vec![false; n_parties],
            computed_r_shares: Vec::new(),
            protocol_output: Vec::new(),
            output_sender: Some(output_sender),
            output_receiver: Some(output_receiver),
        }
    }
}
