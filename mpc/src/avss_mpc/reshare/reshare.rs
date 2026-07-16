use std::{collections::HashMap, sync::Arc};

use futures::lock::Mutex;
use thiserror::Error;

use crate::avss_mpc::{reshare::mvba::MbvaNode, AvssSessionId};

/// Error returned by the resharing protocol.
#[derive(Error, Debug)]
pub enum ReshareError {}

/// Tag for the committee a node belongs to in the resharing protocol.
enum Committee {
    /// The node belongs to the new commitee.
    New,
    /// The node belogs to the old committee.
    Old,
}

pub struct ReshareStore;

/// Node executing the resharing protocol.
pub struct ReshareNode {
    /// ID of this node.
    id: usize,
    /// The committee to which this node belongs to.
    my_committee: Committee,
    /// Store for each execution instance of MBVA.
    ///
    /// The structure is `Session ID => (initiator, store)` where the initiator is the ID of who
    /// created the store.
    store: Arc<Mutex<HashMap<AvssSessionId, (usize, ReshareStore)>>>,
    /// MBVA node to execute inside the resharing protocol.
    mbva_node: MbvaNode,
}
