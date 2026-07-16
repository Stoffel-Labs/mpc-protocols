//! Implementation of Two More Algorithms for Randomized Signature-Free Asynchronous Binary Byzantine Consensus with t < n/3 and O(n^2) Messages and O(1) Round Expected Termination.

use serde::{Deserialize, Serialize};

pub mod bv_bc;
pub mod sbv_bc;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TaggedMessage {
    Aux(u8),
    Binary(u8),
    AuxSet { round: usize, bin_set: Vec<u8> },
}

/// A node runing Crain's ABA.
pub struct CrainAba;

pub struct CrainAbaStore;
