use super::types::*;
use std::collections::HashMap;

///Storage of message info for Bracha
pub struct BrachaStore{
    pub echo_sent : HashMap<u32,bool>,
    pub ready_sent : HashMap<u32,bool>,
    pub echo_count : HashMap<Vec<u8>,u32>,
    pub ready_count :HashMap<Vec<u8>,u32>,
    pub ended : bool,
    pub echo : bool,
    pub ready : bool,
}

impl BrachaStore {
    /// Creates a new BrachaStore with all maps empty and flags set to false.
    pub fn new() -> Self {
        BrachaStore {
            echo_sent: HashMap::new(),
            ready_sent: HashMap::new(),
            echo_count: HashMap::new(),
            ready_count: HashMap::new(),
            ended: false,
            echo: false,
            ready: false,
        }
    }

    /// Marks that an echo was sent by a given node
    pub fn set_echo_sent(&mut self, node_id: u32) {
        self.echo_sent.insert(node_id, true);
    }

    /// Marks that a ready was sent by a given node
    pub fn set_ready_sent(&mut self, node_id: u32) {
        self.ready_sent.insert(node_id, true);
    }

    /// Increments echo count for a given message
    pub fn increment_echo(&mut self, message: &[u8]) {
        *self.echo_count.entry(message.to_vec()).or_insert(0) += 1;
    }

    /// Increments ready count for a given message
    pub fn increment_ready(&mut self, message: &[u8]) {
        *self.ready_count.entry(message.to_vec()).or_insert(0) += 1;
    }

    /// Gets echo count for a message
    pub fn get_echo_count(&self, message: &[u8]) -> u32 {
        *self.echo_count.get(message).unwrap_or(&0)
    }

    /// Gets ready count for a message
    pub fn get_ready_count(&self, message: &[u8]) -> u32 {
        *self.ready_count.get(message).unwrap_or(&0)
    }

    /// Sets ended flag to true
    pub fn mark_ended(&mut self) {
        self.ended = true;
    }

    /// Sets echo flag to true
    pub fn mark_echo(&mut self) {
        self.echo = true;
    }

    /// Sets ready flag to true
    pub fn mark_ready(&mut self) {
        self.ready = true;
    }
}
