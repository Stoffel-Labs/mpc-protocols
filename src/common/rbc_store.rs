use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;

fn hash_message(message: &[u8]) -> Vec<u8> {
    Sha256::digest(message).to_vec()
}

/// Generic message type used in Reliable Broadcast (RBC) communication.
#[derive(Clone)]
pub struct Msg {
    pub sender_id: u32,           // ID of the sender node
    pub session_id: u32,          // Unique session ID for each broadcast instance
    pub payload: Vec<u8>, // Actual data being broadcasted (e.g., bytes of a secret or message)
    pub proof: Vec<u8>,   // Proofs related to the message shared
    pub msg_type: GenericMsgType, // Type of message like INIT, ECHO, or READY
    pub msg_len: usize,   // length of the original message
}

impl Msg {
    /// Constructor to create a new message.
    pub fn new(
        sender_id: u32,
        session_id: u32,
        payload: Vec<u8>,
        proof: Vec<u8>,
        msg_type: GenericMsgType,
        msg_len: usize,
    ) -> Self {
        Msg {
            sender_id,
            session_id,
            payload,
            proof,
            msg_type,
            msg_len,
        }
    }
}
#[derive(Debug, Clone)]
pub enum GenericMsgType {
    Bracha(MsgType),
    Avid(MsgTypeAvid),
}
// Implement Display for GenericMsgType
impl fmt::Display for GenericMsgType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            GenericMsgType::Bracha(ref msg) => write!(f, "Bracha({})", msg),
            GenericMsgType::Avid(ref msg) => write!(f, "Avid({})", msg),
        }
    }
}

///--------------------------Bracha RBC--------------------------
/// Enum to interpret message types in Bracha's protocol.
#[derive(Debug, Clone)]
pub enum MsgType {
    Init,
    Echo,
    Ready,
    Unknown(String),
}
// Implement Display for MsgType
impl fmt::Display for MsgType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            MsgType::Init => write!(f, "Init"),
            MsgType::Echo => write!(f, "Echo"),
            MsgType::Ready => write!(f, "Ready"),
            MsgType::Unknown(ref s) => write!(f, "Unknown({})", s),
        }
    }
}

/// Stores the internal state for each RBC session at a party.
/// Bracha's RBC involves thresholds for ECHO and READY messages to achieve consensus.
#[derive(Default)]
pub struct BrachaStore {
    pub echo_senders: HashMap<u32, bool>, // Which parties sent ECHO (sender_id -> true)
    pub ready_senders: HashMap<u32, bool>, // Which parties sent READY (sender_id -> true)
    pub echo_count: HashMap<Vec<u8>, u32>, // Count of ECHO messages per payload
    pub ready_count: HashMap<Vec<u8>, u32>, // Count of READY messages per payload
    pub ended: bool,                      // True if consensus is reached and protocol ended
    pub echo: bool,                       // True if this party already sent an ECHO
    pub ready: bool,                      // True if this party already sent a READY
    pub output: Vec<u8>,                  // Agreed value after consensus
}

impl BrachaStore {
    /// Initializes an empty session store.
    pub fn new() -> Self {
        BrachaStore {
            echo_senders: HashMap::new(),
            ready_senders: HashMap::new(),
            echo_count: HashMap::new(),
            ready_count: HashMap::new(),
            ended: false,
            echo: false,
            ready: false,
            output: Vec::new(),
        }
    }
    /// Returns true if the given sender_id has sent an echo (i.e., is set to true in echo_senders).
    pub fn has_echo(&self, sender_id: u32) -> bool {
        self.echo_senders.get(&sender_id).copied().unwrap_or(false)
    }
    /// Returns true if the given sender_id has sent a ready (i.e., is set to true in ready_senders).
    pub fn has_ready(&self, sender_id: u32) -> bool {
        self.ready_senders.get(&sender_id).copied().unwrap_or(false)
    }

    /// Marks that an echo was sent by a given node
    pub fn set_echo_sent(&mut self, node_id: u32) {
        self.echo_senders.insert(node_id, true);
    }

    /// Marks that a ready was sent by a given node
    pub fn set_ready_sent(&mut self, node_id: u32) {
        self.ready_senders.insert(node_id, true);
    }

    /// Increments echo count for a given message
    pub fn increment_echo(&mut self, message: &[u8]) {
        let hash = hash_message(message);
        *self.echo_count.entry(hash).or_insert(0) += 1;
    }

    /// Increments ready count for a given message
    pub fn increment_ready(&mut self, message: &[u8]) {
        let hash = hash_message(message);
        *self.ready_count.entry(hash).or_insert(0) += 1;
    }

    /// Gets echo count for a message
    pub fn get_echo_count(&self, message: &[u8]) -> u32 {
        let hash = hash_message(message);
        *self.echo_count.get(&hash).unwrap_or(&0)
    }

    /// Gets ready count for a message
    pub fn get_ready_count(&self, message: &[u8]) -> u32 {
        let hash = hash_message(message);
        *self.ready_count.get(&hash).unwrap_or(&0)
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
    /// Sets the output value.
    pub fn set_output(&mut self, value: Vec<u8>) {
        self.output = value;
    }
}

///--------------------------AVID RBC--------------------------
/// Enum to interpret message types in AVID's protocol.
#[derive(Debug, Clone)]
pub enum MsgTypeAvid {
    Send,
    Echo,
    Ready,
    Unknown(String),
}
// Implement Display for MsgTypeAvid
impl fmt::Display for MsgTypeAvid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            MsgTypeAvid::Send => write!(f, "Send"),
            MsgTypeAvid::Echo => write!(f, "Echo"),
            MsgTypeAvid::Ready => write!(f, "Ready"),
            MsgTypeAvid::Unknown(ref s) => write!(f, "Unknown({})", s),
        }
    }
}
/// Stores the internal state for each RBC session at a party.
#[derive(Default)]
pub struct AvidStore {
    pub shards: HashMap<Vec<u8>, HashMap<u32, Vec<u8>>>, // Merkle root → (shard ID → shard data).
    pub fingerprint: HashMap<Vec<u8>, HashMap<u32, Vec<u8>>>, // Merkle root → (shard ID → Merkle proof/fingerprint).
    pub echo_senders: HashMap<u32, bool>, // Which parties sent ECHO (sender_id -> true)
    pub ready_senders: HashMap<u32, bool>, // Which parties sent READY (sender_id -> true)
    pub echo_count: HashMap<Vec<u8>, u32>, // Count of ECHO messages per root
    pub ready_count: HashMap<Vec<u8>, u32>, // Count of READY messages per root
    pub ended: bool,                      // True if consensus is reached and protocol ended
    pub echo: bool,                       // True if this party already sent an ECHO
    pub output: Vec<u8>,                  // Agreed value after consensus
}
impl AvidStore {
    /// Initializes an empty session store.
    pub fn new() -> Self {
        AvidStore {
            shards: HashMap::new(),
            fingerprint: HashMap::new(),
            echo_senders: HashMap::new(),
            ready_senders: HashMap::new(),
            echo_count: HashMap::new(),
            ready_count: HashMap::new(),
            ended: false,
            echo: false,
            output: Vec::new(),
        }
    }
    /// Returns true if the given sender_id has sent an echo (i.e., is set to true in echo_senders).
    pub fn has_echo(&self, sender_id: u32) -> bool {
        self.echo_senders.get(&sender_id).copied().unwrap_or(false)
    }
    /// Returns true if the given sender_id has sent an ready (i.e., is set to true in ready_senders).
    pub fn has_ready(&self, sender_id: u32) -> bool {
        self.ready_senders.get(&sender_id).copied().unwrap_or(false)
    }
    /// Marks that an echo was sent by a given node
    pub fn set_echo_sent(&mut self, node_id: u32) {
        self.echo_senders.insert(node_id, true);
    }
    /// Marks that an ready was sent by a given node
    pub fn set_ready_sent(&mut self, node_id: u32) {
        self.ready_senders.insert(node_id, true);
    }
    /// Increments echo count for a given root
    pub fn increment_echo(&mut self, root: &[u8]) {
        *self.echo_count.entry(root.to_vec()).or_insert(0) += 1;
    }
    /// Increments ready count for a given root
    pub fn increment_ready(&mut self, root: &[u8]) {
        *self.ready_count.entry(root.to_vec()).or_insert(0) += 1;
    }
    /// Gets echo count for a root
    pub fn get_echo_count(&self, root: &[u8]) -> u32 {
        *self.echo_count.get(root).unwrap_or(&0)
    }
    /// Gets ready count for a root
    pub fn get_ready_count(&self, root: &[u8]) -> u32 {
        *self.ready_count.get(root).unwrap_or(&0)
    }
    /// Sets echo flag to true
    pub fn mark_echo(&mut self) {
        self.echo = true;
    }
    /// Sets ended flag to true
    pub fn mark_ended(&mut self) {
        self.ended = true;
    }
    /// Sets the output value.
    pub fn set_output(&mut self, value: Vec<u8>) {
        self.output = value;
    }

    /// Inserts a shard for a given root and sender ID
    pub fn insert_shard(&mut self, root: Vec<u8>, sender_id: u32, shard: Vec<u8>) {
        self.shards
            .entry(root)
            .or_default()
            .insert(sender_id, shard);
    }

    /// Inserts fingerprint/merkle proof  for a given root and sender ID
    pub fn insert_fingerprint(&mut self, root: Vec<u8>, sender_id: u32, proof: Vec<u8>) {
        self.fingerprint
            .entry(root)
            .or_default()
            .insert(sender_id, proof);
    }
    /// Returns the set of shards associated with a given Merkle root.
    pub fn get_shards_for_root(&self, root: &Vec<u8>) -> HashMap<u32, Vec<u8>> {
        self.shards.get(root).cloned().unwrap_or_else(HashMap::new)
    }
}
