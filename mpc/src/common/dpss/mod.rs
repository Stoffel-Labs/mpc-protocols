//! Implementation of the [high-threshold batched DPSS protocol](https://eprint.iacr.org/2022/971.pdf) (see Algorithm 5).

use std::{collections::HashMap, sync::Arc};

use thiserror::Error;
use tokio::sync::Mutex;

use crate::avss_mpc::AvssSessionId;

/// Error returned by the resharing protocol.
#[derive(Error, Debug)]
pub enum DpssError {}

/// Tag for the committee a node belongs to in the resharing protocol.
enum CommitteeTag {
    /// The node belongs to the new commitee.
    New,
    /// The node belogs to the old committee.
    Old,
}

pub struct ReshareStore;

/// Node executing the resharing protocol.
pub struct DpssNode {
    /// ID of this node.
    id: usize,
    /// The committee to which this node belongs to.
    my_committee: CommitteeTag,
    /// Store for each execution instance of MBVA.
    ///
    /// The structure is `Session ID => (initiator, store)` where the initiator is the ID of who
    /// created the store.
    store: Arc<Mutex<HashMap<AvssSessionId, (usize, ReshareStore)>>>,
}
