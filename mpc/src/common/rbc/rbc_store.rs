use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

/// Generic message type used in Reliable Broadcast (RBC) communication.
#[derive(Clone,Serialize, Deserialize)]
pub struct Msg {
    pub sender_id: u32,           // ID of the sender node
    pub session_id: u32,          // Unique session ID for each broadcast instance
    pub round_id: u32,            //Round ID
    pub payload: Vec<u8>, // Actual data being broadcasted (e.g., bytes of a secret or message)
    pub metadata: Vec<u8>, // info related to the message shared
    pub msg_type: GenericMsgType, // Type of message like INIT, ECHO, or READY
    pub msg_len: usize,   // length of the original message
}

fn hash_message(message: &[u8]) -> Vec<u8> {
    Sha256::digest(message).to_vec()
}

impl Msg {
    /// Constructor to create a new message.
    pub fn new(
        sender_id: u32,
        session_id: u32,
        round_id: u32,
        payload: Vec<u8>,
        metadata: Vec<u8>,
        msg_type: GenericMsgType,
        msg_len: usize,
    ) -> Self {
        Msg {
            sender_id,
            session_id,
            round_id,
            payload,
            metadata,
            msg_type,
            msg_len,
        }
    }
}
#[derive(Debug, Clone,Serialize, Deserialize)]
pub enum GenericMsgType {
    Bracha(MsgType),
    Avid(MsgTypeAvid),
    ABA(MsgTypeAba),
    Acs(MsgTypeAcs),
}
// Implement Display for GenericMsgType
impl fmt::Display for GenericMsgType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            GenericMsgType::Bracha(ref msg) => write!(f, "Bracha({})", msg),
            GenericMsgType::Avid(ref msg) => write!(f, "Avid({})", msg),
            GenericMsgType::ABA(ref msg) => write!(f, "ABA({})", msg),
            GenericMsgType::Acs(ref msg) => write!(f, "ACS({})", msg),
        }
    }
}

///--------------------------Bracha RBC--------------------------
/// Enum to interpret message types in Bracha's protocol.
#[derive(Debug, Clone,Serialize, Deserialize)]
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
#[derive(Debug, Clone,Serialize, Deserialize)]
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

///--------------------------ABA--------------------------
/// Enum to interpret message types in ABA protocol.
#[derive(Debug, Clone,Serialize, Deserialize)]
pub enum MsgTypeAba {
    Est,
    Aux,
    Key,
    Coin,
    Unknown(String),
}
// Implement Display for MsgType
impl fmt::Display for MsgTypeAba {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            MsgTypeAba::Est => write!(f, "Est"),
            MsgTypeAba::Aux => write!(f, "Aux"),
            MsgTypeAba::Key => write!(f, "Key"),
            MsgTypeAba::Coin => write!(f, "Coin"),
            MsgTypeAba::Unknown(ref s) => write!(f, "Unknown({})", s),
        }
    }
}

/// Stores the internal state for each ABA session at a party.
#[derive(Default)]
pub struct AbaStore {
    //  roundid => Sender => [bool,bool] , to check if a sender has sent an est value either 0 or 1
    pub est_senders: HashMap<u32, HashMap<u32, [bool; 2]>>,
    //  roundid => Sender => [bool,bool], to check if a sender has sent an aux value either 0 or 1
    pub aux_senders: HashMap<u32, HashMap<u32, [bool; 2]>>,
    pub est_count: HashMap<u32, [u32; 2]>, // roundid => est value count[0 count ,1 count]
    pub est: HashMap<u32, [bool; 2]>,      // roundid => [sent 0 value , sent 1 value]
    pub aux: HashMap<u32, [bool; 2]>,      // roundid => aux value
    // roundid => Sender => [bool,bool] , set of values shared by sender
    pub values: HashMap<u32, HashMap<u32, HashSet<bool>>>,
    pub bin_values: HashMap<u32, HashSet<bool>>, // roundid => {bool}
    pub ended: bool,                             //ABA session ended or not
    pub output: bool,                            // Agreed value after consensus
    pub notify: Arc<Notify>,
}

impl AbaStore {
    /// Set the estimate value for a given round id
    pub fn mark_est(&mut self, round: u32, value: bool) {
        let est = self.est.entry(round).or_insert([false; 2]);
        est[value as usize] = true;
    }

    /// Get the estimate value for a given round id, defaulting to `false` if not set
    pub fn get_est(&self, round: u32, value: bool) -> bool {
        self.est
            .get(&round)
            .map(|arr| arr[value as usize])
            .unwrap_or(false)
    }
    /// Mark the aux value for a given round id
    pub fn mark_aux(&mut self, round: u32, value: bool) {
        let aux_arr = self.aux.entry(round).or_insert([false; 2]);
        aux_arr[value as usize] = true;
    }
    /// Get the aux value for a given round id, defaulting to `false` if not set
    pub fn get_aux(&self, round: u32, value: bool) -> bool {
        self.aux
            .get(&round)
            .map(|arr| arr[value as usize])
            .unwrap_or(false)
    }

    /// Check if a sender has already sent an estimate(0 or 1) in a given round
    pub fn has_sent_est(&self, round: u32, sender: u32, value: bool) -> bool {
        self.est_senders
            .get(&round)
            .and_then(|senders| senders.get(&sender))
            .map(|arr| arr[value as usize])
            .unwrap_or(false)
    }

    /// Mark a sender as having sent an estimate(0 or 1) in a given round
    pub fn set_est_sent(&mut self, round: u32, sender: u32, value: bool) {
        self.est_senders
            .entry(round)
            .or_default()
            .entry(sender)
            .or_insert([false; 2])[value as usize] = true;
    }

    /// Increase the est count of 0s or 1s received in a round
    pub fn increment_est(&mut self, round: u32, value: bool) {
        let counts = self.est_count.entry(round).or_insert([0, 0]);
        if value {
            counts[1] += 1;
        } else {
            counts[0] += 1;
        }
    }

    /// Get the current estimate count ([0s, 1s]) for a round
    pub fn get_est_count(&self, round: u32) -> [u32; 2] {
        self.est_count.get(&round).copied().unwrap_or([0, 0])
    }
    /// Insert a binary value into the bin_values set for a given round ID
    pub fn insert_bin_value(&mut self, round: u32, value: bool) {
        self.bin_values
            .entry(round)
            .or_insert_with(HashSet::new)
            .insert(value);
    }

    //Get the bin_values set for a given round
    pub fn get_bin_values(&self, round: u32) -> HashSet<bool> {
        self.bin_values.get(&round).cloned().unwrap_or_default()
    }

    /// Check if a sender has already sent an aux value either 0 or 1 in a given round
    pub fn has_sent_aux(&self, round: u32, sender: u32, value: bool) -> bool {
        self.aux_senders
            .get(&round)
            .and_then(|senders| senders.get(&sender))
            .map(|arr| arr[value as usize])
            .unwrap_or(false)
    }

    /// Mark a sender as having sent an value either 0 or 1 in a given round
    pub fn set_aux_sent(&mut self, round: u32, sender: u32, value: bool) {
        self.aux_senders
            .entry(round)
            .or_default()
            .entry(sender)
            .or_insert([false; 2])[value as usize] = true;
    }

    /// Insert a binary value into the values set for a given round ID and given sender
    pub fn insert_values(&mut self, round: u32, sender: u32, value: bool) {
        self.values
            .entry(round)
            .or_insert_with(HashMap::new)
            .entry(sender)
            .or_insert_with(HashSet::new)
            .insert(value);
    }

    /// Get the current count of senders who sent aux messages for a given round
    pub fn get_sender_count(&self, round: u32) -> usize {
        self.values
            .get(&round)
            .map(|sender_map| sender_map.len())
            .unwrap_or(0)
    }

    // Get the union of all the values set for a given round
    pub fn get_all_values(&self, round: u32) -> HashSet<bool> {
        self.values
            .get(&round)
            .map(|sender_map| {
                sender_map
                    .values()
                    .flat_map(|value_set| value_set.iter().copied())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Sets ended flag to true
    pub fn mark_ended(&mut self) {
        self.ended = true;
        self.notify.notify_waiters();
    }

    /// Sets the output value.
    pub fn set_output(&mut self, value: bool) {
        self.output = value;
    }
}
/// Stores the internal state for each Common coin session at a party.
#[derive(Default)]
pub struct CoinStore {
    pub sign_senders: HashMap<u32, HashMap<u32, bool>>, //roundid => Sender => bool, check if signature shares were sent
    pub sign_count: HashMap<u32, u32>,                  // roundid => signature share count
    pub sign_shares: HashMap<u32, HashMap<u32, Vec<u8>>>, // roundid => sender_id => Signature share
    pub coins: HashMap<u32, bool>,                      //roundid => Coin
    pub start: HashMap<u32, bool>, //roundid => yes or no , checks if common coin has been initiated yet
    pub notifiers: HashMap<u32, Arc<Notify>>, // round_id => Notify ,Checks if common coin is ready to be used
}
impl CoinStore {
    /// Check if a sender has already sent a signature share in a given round
    pub fn has_sent_sign(&self, round: u32, sender: u32) -> bool {
        self.sign_senders
            .get(&round)
            .and_then(|senders| senders.get(&sender))
            .copied()
            .unwrap_or(false)
    }

    /// Increase the count of signature shares received in a round
    pub fn increment_sign(&mut self, round: u32) {
        *self.sign_count.entry(round).or_insert(0) += 1;
    }

    /// Mark a sender as having sent a signature share in a given round
    pub fn set_sign_sent(&mut self, round: u32, sender: u32) {
        self.sign_senders
            .entry(round)
            .or_default()
            .insert(sender, true);
    }

    /// Get the current signature share count for a round
    pub fn get_sign_count(&self, round: u32) -> u32 {
        self.sign_count.get(&round).copied().unwrap_or(0)
    }

    /// Insert a signature share for a given round
    pub fn insert_share(&mut self, round_id: u32, sender_id: u32, share: Vec<u8>) {
        self.sign_shares
            .entry(round_id)
            .or_insert_with(HashMap::new)
            .insert(sender_id, share);
    }

    //Get the signature share map for a given round
    pub fn get_shares_map(&self, round_id: u32) -> Option<&HashMap<u32, Vec<u8>>> {
        self.sign_shares.get(&round_id)
    }

    //Set the common coin as ready to be used and notify waiter
    pub fn set_coin(&mut self, round_id: u32, value: bool) {
        self.coins.insert(round_id, value);
        if let Some(notify) = self.notifiers.remove(&round_id) {
            notify.notify_waiters(); // Wake up all waiting tasks
        }
    }

    /// Get the coin value for a given round, if it exists.
    pub fn coin(&self, round: u32) -> Option<bool> {
        self.coins.get(&round).copied()
    }

    //Marks the start of common coin generation
    pub fn set_start(&mut self, round_id: u32) {
        self.start.insert(round_id, true);
    }

    //Checks if common coin generation has started
    pub fn get_start(&self, round: u32) -> bool {
        *self.start.get(&round).unwrap_or(&false)
    }
}

/// Stores the internal state for each ACS session at a party.
#[derive(Debug, Clone,Serialize, Deserialize)]
pub enum MsgTypeAcs {
    Acs,
    Unknown(String),
}
// Implement Display for MsgType
impl fmt::Display for MsgTypeAcs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            MsgTypeAcs::Acs => write!(f, "Acs"),
            MsgTypeAcs::Unknown(ref s) => write!(f, "Unknown({})", s),
        }
    }
}
#[derive(Default, Clone)]
pub struct AcsStore {
    pub aba_input: HashMap<u32, bool>,     //Session id => aba input
    pub aba_output: HashMap<u32, bool>,    //Session id => aba output
    pub rbc_output: HashMap<u32, Vec<u8>>, //Session id => rbc output
    pub ended: bool,
    pub commonsubset: Vec<Vec<u8>>,
}

impl AcsStore {
    /// Checks if ABA input is stored for the given session ID.
    pub fn has_aba_input(&self, session_id: u32) -> bool {
        self.aba_input.contains_key(&session_id)
    }
    /// Sets the ABA input for a given session ID.
    pub fn set_aba_input(&mut self, session_id: u32, value: bool) {
        self.aba_input.insert(session_id, value);
    }
    /// Sets the ABA output for a given session ID.
    pub fn set_aba_output(&mut self, session_id: u32, value: bool) {
        self.aba_output.insert(session_id, value);
    }
    /// Get the ABA output 1 count
    pub fn get_aba_output_one_count(&mut self) -> u32 {
        self.aba_output.iter().filter(|&(_, &val)| val).count() as u32
    }
    /// Checks if RBC output is stored for the given session ID.
    pub fn has_rbc_output(&self, session_id: u32) -> bool {
        self.rbc_output.contains_key(&session_id)
    }
    /// Sets the RBC output for a given session ID.
    pub fn set_rbc_output(&mut self, session_id: u32, output: Vec<u8>) {
        self.rbc_output.insert(session_id, output);
    }
    /// Get the RBC output for a given session ID.
    pub fn get_rbc_output(&mut self, session_id: u32) -> Option<&Vec<u8>> {
        self.rbc_output.get(&session_id)
    }

    ///Set the common subset
    pub fn set_acs(&mut self, set: Vec<Vec<u8>>) {
        self.commonsubset = set;
    }

    /// Sets ended flag to true
    pub fn mark_ended(&mut self) {
        self.ended = true;
    }
}
