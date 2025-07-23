use bincode::ErrorKind;
use serde::{Deserialize, Serialize};
use stoffelmpc_network::{NetworkError, SessionId};
use thiserror::Error;

pub mod rbc;
pub mod rbc_store;
pub mod utils;

#[derive(Error, Debug)]
pub enum ShardError {
    #[error("Invalid shard configuration: {0}")]
    Config(String),

    #[error("Operation failed: {0}")]
    Failed(String),

    #[error("Missing shards")]
    Incomplete,

    #[error("Merkle error: {0}")]
    Merkle(String),

    #[error("Index {0} is out of bounds (max {1})")]
    OutOfBounds(u32, usize),
}

#[derive(Debug, Error)]
pub enum RbcError {
    #[error("Invalid threshold t={0} for n={1}, must satisfy t < ceil(n / 3)")]
    InvalidThreshold(u32, u32),

    #[error("Session {0} already ended")]
    SessionEnded(u32),

    #[error("Unknown Bracha message type: {0}")]
    UnknownMsgType(String),

    #[error("Message send failed")]
    SendFailed,

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("there was an error in the network: {0:?}")]
    NetworkError(NetworkError),

    #[error("error while serializing the object into bytes: {0:?}")]
    SerializationError(Box<ErrorKind>),

    #[error("inner error: {0}")]
    Inner(#[from] ShardError),
}
