use std::collections::HashMap;

use crate::common::types::f256::F2_8;
use crate::common::types::fixed::FixedPointPrecision;
use crate::{common::share::ShareError, honeybadger::SessionId};
use ark_ff::PrimeField;
use ark_serialize::SerializationError;
use bincode::ErrorKind;
use serde::{Deserialize, Serialize};
use stoffelnet::network_utils::NetworkError;
use thiserror::Error;

/// Implements the secure fixed-point arithmetic.
///
/// The implementation of secure fixed-point arithmetic follows the paper "Secure Computation With
/// Fixed-Point Numbers" by Catrina and Saxena.
pub mod fixed;

pub mod f256;
/// Implements the secure fixed-point arithmetic between shared values.
pub mod integer;
pub mod prandbitd;

#[derive(Error, Debug)]
pub enum Error {
    #[error("error operating incompatible types - self precision: {current:?}, other precision: {other:?}")]
    IncompatibleIntegerPrecision { current: usize, other: usize },
    #[error("error operating incompatible types - self precision: {current:?}, other precision: {other:?}")]
    IncompatibleFixedPointPrecision {
        current: FixedPointPrecision,
        other: FixedPointPrecision,
    },
    #[error("error operating with shares: {0:?}")]
    ShareError(#[from] ShareError),
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
    #[error("No of tsets not set")]
    NotSet,
    #[error("ShareError: {0}")]
    ShareError(#[from] ShareError),
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
    pub r_t: i64,
    pub payload: Vec<u8>,
}

impl PRandBitDMessage {
    /// Creates a new PRandBitDMessage.
    pub fn new(
        sender_id: usize,
        msg_type: MessageType,
        session_id: SessionId,
        tset: Vec<usize>,
        r_t: i64,
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
pub struct PRandBitDStore<F: PrimeField> {
    /// For every maximal unqualified set T that excludes this player,
    /// we store the full mask r_T = sum_i r_T^i
    pub riss_shares: HashMap<Vec<usize>, HashMap<usize, i64>>, // tset -> {sender -> val}
    pub r_t: HashMap<Vec<usize>, i64>,
    pub no_of_tsets: Option<usize>,
    pub share_r_q: Option<F>,
    pub share_b_q: Option<F>,
    pub share_r_2: Option<F2_8>,
    pub share_r_plus_b: HashMap<usize, F>,
    pub share_b_2: Option<F2_8>,
}

impl<F: PrimeField> PRandBitDStore<F> {
    pub fn empty() -> Self {
        Self {
            riss_shares: HashMap::new(),
            r_t: HashMap::new(),
            no_of_tsets: None,
            share_r_q: None,
            share_b_q: None,
            share_r_2: None,
            share_r_plus_b: HashMap::new(),
            share_b_2: None,
        }
    }
}
