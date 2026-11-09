use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex as StdMutex};
use tokio::sync::Notify;

use super::{ShardError, MAX_PAYLOAD_SIZE};
use crate::common::ProtocolSessionId;
/// Generic message type used in Reliable Broadcast (RBC) communication.
///
/// # Sender authentication
///
/// `sender_id` is carried inside the serialized message and is NOT self-authenticating.
/// Authentication is the responsibility of the caller before passing a `Msg` to any RBC
/// handler.
///   1. Rejects any message where the transport-layer sender differs from `msg.sender_id`.
///   2. For INIT/SEND (dealer) messages, additionally verifies `msg.sender_id == session_id.sub_id()`,
///      ensuring only the designated broadcaster can open a session.
///
/// The RBC implementations (Bracha, AVID) therefore assume `sender_id` is already
/// authenticated and do not repeat the check internally. Do not call RBC handlers
/// directly without performing this authentication step first.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Msg<Id: ProtocolSessionId> {
    pub sender_id: usize,         // ID of the sender node
    pub session_id: Id,           // Unique session ID for each broadcast instance
    pub round_id: usize,          //Round ID
    pub payload: Vec<u8>, // Actual data being broadcasted (e.g., bytes of a secret or message)
    pub metadata: Vec<u8>, // info related to the message shared
    pub msg_type: GenericMsgType, // Type of message like INIT, ECHO, or READY
}

fn hash_message(message: &[u8]) -> Vec<u8> {
    Sha256::digest(message).to_vec()
}

impl<Id: ProtocolSessionId> Msg<Id> {
    /// Constructor to create a new message.
    pub fn new(
        sender_id: usize,
        session_id: Id,
        round_id: usize,
        payload: Vec<u8>,
        metadata: Vec<u8>,
        msg_type: GenericMsgType,
    ) -> Self {
        Msg {
            sender_id,
            session_id,
            round_id,
            payload,
            metadata,
            msg_type,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GenericMsgType {
    Bracha(MsgType),
    Avid(MsgTypeAvid),
    ABA(MsgTypeAba),
    Acs(MsgTypeAcs),
}
impl GenericMsgType {
    pub fn is_dealer_message(&self) -> bool {
        match self {
            GenericMsgType::Bracha(MsgType::Init) => true,
            GenericMsgType::Bracha(_) => false,
            GenericMsgType::Avid(MsgTypeAvid::Send) => true,
            GenericMsgType::Avid(_) => false,
            GenericMsgType::ABA(_) => false,
            GenericMsgType::Acs(_) => false,
        }
    }
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub echo_senders: HashMap<usize, bool>, // Which parties sent ECHO (sender_id -> true)
    pub ready_senders: HashMap<usize, bool>, // Which parties sent READY (sender_id -> true)
    pub echo_count: HashMap<Vec<u8>, usize>, // Count of ECHO messages per payload
    pub ready_count: HashMap<Vec<u8>, usize>, // Count of READY messages per payload
    pub ended: bool,                        // True if consensus is reached and protocol ended
    pub echo: bool,                         // True if this party already sent an ECHO
    pub ready: bool,                        // True if this party already sent a READY
    pub output: Vec<u8>,                    // Agreed value after consensus
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
    pub fn has_echo(&self, sender_id: usize) -> bool {
        self.echo_senders.get(&sender_id).copied().unwrap_or(false)
    }
    /// Returns true if the given sender_id has sent a ready (i.e., is set to true in ready_senders).
    pub fn has_ready(&self, sender_id: usize) -> bool {
        self.ready_senders.get(&sender_id).copied().unwrap_or(false)
    }

    /// Marks that an echo was sent by a given node
    pub fn set_echo_sent(&mut self, node_id: usize) {
        self.echo_senders.insert(node_id, true);
    }

    /// Marks that a ready was sent by a given node
    pub fn set_ready_sent(&mut self, node_id: usize) {
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
    pub fn get_echo_count(&self, message: &[u8]) -> usize {
        let hash = hash_message(message);
        *self.echo_count.get(&hash).unwrap_or(&0)
    }

    /// Gets ready count for a message
    pub fn get_ready_count(&self, message: &[u8]) -> usize {
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

/// Shared, process-local ledger bounding the total AVID shard bytes a node retains, keyed by the
/// **authenticated sender** that transmitted each shard — never the session's dealer field, which is
/// attacker-forgeable on ECHO/READY. Count caps alone cannot bound memory: one sender can hold
/// `MAX_RBC_SESSIONS / n` sessions, each retaining a shard up to `MAX_PAYLOAD_SIZE / k` (multi-MiB),
/// so a single authenticated peer could pin gigabytes under the count cap. The per-sender cap keeps
/// one peer's footprint bounded; sizing the global cap as `n * per_sender` guarantees the `<= t`
/// malicious peers can never consume the share the `n - t` honest peers need.
#[derive(Default, Debug)]
pub struct ByteLedger {
    global: usize,
    per_sender: HashMap<usize, usize>,
}

impl ByteLedger {
    /// Charges `bytes` to `sender` iff it fits both the global and per-sender caps. Returns false
    /// (charging nothing) when it would exceed either — the caller then drops the shard.
    pub fn try_charge(
        &mut self,
        sender: usize,
        bytes: usize,
        global_cap: usize,
        per_sender_cap: usize,
    ) -> bool {
        let used = self.per_sender.get(&sender).copied().unwrap_or(0);
        if self.global.saturating_add(bytes) > global_cap
            || used.saturating_add(bytes) > per_sender_cap
        {
            return false;
        }
        self.global += bytes;
        *self.per_sender.entry(sender).or_insert(0) += bytes;
        true
    }

    /// Returns bytes previously charged to `sender` back to the pool.
    pub fn release(&mut self, sender: usize, bytes: usize) {
        self.global = self.global.saturating_sub(bytes);
        if let Some(v) = self.per_sender.get_mut(&sender) {
            *v = v.saturating_sub(bytes);
            if *v == 0 {
                self.per_sender.remove(&sender);
            }
        }
    }

    /// Current global bytes charged. Test/metrics helper.
    pub fn global_bytes(&self) -> usize {
        self.global
    }

    /// Current bytes charged to `sender`. Test/metrics helper.
    pub fn sender_bytes(&self, sender: usize) -> usize {
        self.per_sender.get(&sender).copied().unwrap_or(0)
    }
}

/// Outcome of a byte-accounted shard insert.
#[derive(Debug, PartialEq, Eq)]
pub enum ShardInsert {
    /// The shard was stored (and any new bytes charged to the sender).
    Inserted,
    /// The shard's bytes would exceed the global or per-sender cap: nothing stored, drop the message.
    OverBudget,
}

///--------------------------AVID RBC--------------------------
/// Enum to interpret message types in AVID's protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub shards: HashMap<Vec<u8>, HashMap<usize, Vec<u8>>>, // Merkle root → (shard ID → shard data).
    /// The Merkle root this session has committed to, once one is *corroborated*. `verify_merkle`
    /// only checks that a shard is a valid leaf of the root carried in the *same* message — it has
    /// no way to know what root any other party saw, so a dealer can equivocate by sending
    /// different (root, shard) pairs to different honest parties, and each recipient's own check
    /// still passes. Committing to a root lets every later mismatched root be rejected outright
    /// rather than retained.
    ///
    pub accepted_root: Option<Vec<u8>>,
    pub fingerprint: HashMap<Vec<u8>, HashMap<usize, Vec<u8>>>, // Merkle root → (shard ID → Merkle proof/fingerprint).
    pub echo_senders: HashMap<usize, bool>, // Which parties sent ECHO (sender_id -> true)
    pub ready_senders: HashMap<usize, bool>, // Which parties sent READY (sender_id -> true)
    pub echo_count: HashMap<Vec<u8>, usize>, // Count of ECHO messages per root
    pub ready_count: HashMap<Vec<u8>, usize>, // Count of READY messages per root
    pub ended: bool,                        // True if consensus is reached and protocol ended
    pub echo: bool,                         // True if this party already sent an ECHO
    pub output: Vec<u8>,                    // Agreed value after consensus
    /// Shared byte ledger this session charges shard bytes to (`None` = accounting disabled, e.g.
    /// isolated unit tests). Injected at creation so every session shares one process-local pool.
    byte_ledger: Option<Arc<StdMutex<ByteLedger>>>,
    /// Exactly what this session has charged to `byte_ledger`, per sender. Kept in lockstep with the
    /// ledger so every teardown path — retire, TTL-evict, `clear_all`, or a bare drop — releases
    /// precisely via [`Drop`], with no leak and no double-release.
    charged_by_sender: HashMap<usize, usize>,
}
impl AvidStore {
    /// Initializes an empty session store with no byte accounting.
    pub fn new() -> Self {
        AvidStore {
            shards: HashMap::new(),
            accepted_root: None,
            fingerprint: HashMap::new(),
            echo_senders: HashMap::new(),
            ready_senders: HashMap::new(),
            echo_count: HashMap::new(),
            ready_count: HashMap::new(),
            ended: false,
            echo: false,
            output: Vec::new(),
            byte_ledger: None,
            charged_by_sender: HashMap::new(),
        }
    }

    /// Initializes an empty session store that charges shard bytes to the shared `ledger`.
    pub fn with_ledger(ledger: Arc<StdMutex<ByteLedger>>) -> Self {
        let mut store = AvidStore::new();
        store.byte_ledger = Some(ledger);
        store
    }
    /// Returns true if the given sender_id has sent an echo (i.e., is set to true in echo_senders).
    pub fn has_echo(&self, sender_id: usize) -> bool {
        self.echo_senders.get(&sender_id).copied().unwrap_or(false)
    }
    /// Returns true if the given sender_id has sent an ready (i.e., is set to true in ready_senders).
    pub fn has_ready(&self, sender_id: usize) -> bool {
        self.ready_senders.get(&sender_id).copied().unwrap_or(false)
    }
    /// Marks that an echo was sent by a given node
    pub fn set_echo_sent(&mut self, node_id: usize) {
        self.echo_senders.insert(node_id, true);
    }
    /// Marks that an ready was sent by a given node
    pub fn set_ready_sent(&mut self, node_id: usize) {
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
    pub fn get_echo_count(&self, root: &[u8]) -> usize {
        *self.echo_count.get(root).unwrap_or(&0)
    }
    /// Gets ready count for a root
    pub fn get_ready_count(&self, root: &[u8]) -> usize {
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

    /// Inserts a shard for a given root and sender ID, charging its bytes to `sender_id` in the
    /// shared [`ByteLedger`] (when one is attached). Returns [`ShardInsert::OverBudget`] — storing
    /// nothing — when the charge would exceed `global_cap` or `per_sender_cap`, so the caller drops
    /// the message without retaining memory. Callers that do not enforce a budget (tests, or paths
    /// with no ledger attached) pass `usize::MAX` for both caps.
    ///
    /// Only the *delta* over any shard already held for this `(root, sender_id)` is charged, so a
    /// sender's ECHO followed by its READY (same leaf, same value) is not double-counted.
    pub fn insert_shard(
        &mut self,
        root: Vec<u8>,
        sender_id: usize,
        shard: Vec<u8>,
        data_shards: usize,
        global_cap: usize,
        per_sender_cap: usize,
    ) -> Result<ShardInsert, ShardError> {
        if let Some(accepted) = &self.accepted_root {
            if accepted != &root {
                return Err(ShardError::Config(
                    "Equivocation detected: mismatched Merkle roots for this session".to_string(),
                ));
            }
        }

        let max_shard_size = (MAX_PAYLOAD_SIZE + 8 + data_shards - 1) / data_shards;
        if shard.len() > max_shard_size {
            return Err(ShardError::Config(format!(
                "Shard from {} exceeds maximum allowed size ({})",
                sender_id,
                shard.len()
            )));
        }

        // Charge only the increase over whatever this (root, sender) already holds.
        let old_len = self
            .shards
            .get(&root)
            .and_then(|m| m.get(&sender_id))
            .map(|s| s.len())
            .unwrap_or(0);
        let delta = shard.len().saturating_sub(old_len);
        if delta > 0 {
            if let Some(ledger) = &self.byte_ledger {
                let charged =
                    ledger
                        .lock()
                        .unwrap()
                        .try_charge(sender_id, delta, global_cap, per_sender_cap);
                if !charged {
                    return Ok(ShardInsert::OverBudget);
                }
                *self.charged_by_sender.entry(sender_id).or_insert(0) += delta;
            }
        }

        self.shards
            .entry(root)
            .or_default()
            .insert(sender_id, shard);
        Ok(ShardInsert::Inserted)
    }

    /// Releases ledger charges for every shard whose root satisfies `drop_root`, keeping
    /// `charged_by_sender` in lockstep. Does not remove the shards themselves — the caller does.
    fn release_shards<P: Fn(&[u8]) -> bool>(&mut self, drop_root: P) {
        let ledger = match &self.byte_ledger {
            Some(l) => l.clone(),
            None => return,
        };
        let mut releases: Vec<(usize, usize)> = Vec::new();
        for (r, by_sender) in self.shards.iter() {
            if drop_root(r) {
                for (sender, shard) in by_sender.iter() {
                    releases.push((*sender, shard.len()));
                }
            }
        }
        let mut lg = ledger.lock().unwrap();
        for (sender, bytes) in releases {
            lg.release(sender, bytes);
            if let Some(v) = self.charged_by_sender.get_mut(&sender) {
                *v = v.saturating_sub(bytes);
            }
        }
    }

    /// Inserts fingerprint/merkle proof  for a given root and sender ID
    pub fn insert_fingerprint(&mut self, root: Vec<u8>, sender_id: usize, proof: Vec<u8>) {
        self.fingerprint
            .entry(root)
            .or_default()
            .insert(sender_id, proof);
    }
    /// Returns the set of shards associated with a given Merkle root.
    pub fn get_shards_for_root(&self, root: &Vec<u8>) -> HashMap<usize, Vec<u8>> {
        self.shards.get(root).cloned().unwrap_or_else(HashMap::new)
    }

    /// Commits the session to `root` if enough distinct senders have now backed it, and discards
    /// every competing root's state once that happens.
    ///
    /// `corroboration_threshold` must be the intersection-guaranteeing quorum (`> (n + t) / 2`,
    /// e.g. `max((n + t + 2) / 2, k)`), not merely `t + 1`. `t + 1` only proves at least one honest
    /// party saw this root — it does not prove *uniqueness*, so under dealer equivocation two
    /// disjoint honest observers could each independently reach `t + 1` backing for two different
    /// roots and both commit, permanently diverging. The strong quorum guarantees any two
    /// quorum-sized sender sets share at least one honest member, who can only have backed one
    /// root. ECHO and READY tallies are compared separately rather than summed, because a single
    /// sender may contribute to both and a sum would let `t` Byzantine parties reach `2t`.
    ///
    /// Returns true if the session is committed to `root` after this call.
    pub fn try_commit_root(&mut self, root: &[u8], corroboration_threshold: usize) -> bool {
        if let Some(accepted) = &self.accepted_root {
            return accepted == root;
        }
        let backing = self.get_echo_count(root).max(self.get_ready_count(root));
        if backing < corroboration_threshold {
            return false;
        }

        self.accepted_root = Some(root.to_vec());
        // Release byte charges for every losing root before its shards are dropped below.
        let committed = root.to_vec();
        self.release_shards(|r| r != committed.as_slice());
        self.shards.retain(|r, _| r == root);
        self.fingerprint.retain(|r, _| r == root);
        self.echo_count.retain(|r, _| r == root);
        self.ready_count.retain(|r, _| r == root);
        true
    }
}

impl Drop for AvidStore {
    /// Releases this session's remaining shard-byte charges on every teardown path (retire,
    /// TTL-evict, `clear_all`, or a bare drop), so the ledger can never leak capacity.
    fn drop(&mut self) {
        if self.charged_by_sender.is_empty() {
            return;
        }
        if let Some(ledger) = &self.byte_ledger {
            let mut lg = ledger.lock().unwrap();
            for (sender, bytes) in self.charged_by_sender.iter() {
                lg.release(*sender, *bytes);
            }
        }
    }
}

///--------------------------ABA--------------------------
/// Enum to interpret message types in ABA protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub est_senders: HashMap<usize, HashMap<usize, [bool; 2]>>,
    //  roundid => Sender => [bool,bool], to check if a sender has sent an aux value either 0 or 1
    pub aux_senders: HashMap<usize, HashMap<usize, [bool; 2]>>,
    pub est_count: HashMap<usize, [usize; 2]>, // roundid => est value count[0 count ,1 count]
    pub est: HashMap<usize, [bool; 2]>,        // roundid => [sent 0 value , sent 1 value]
    pub aux: HashMap<usize, [bool; 2]>,        // roundid => aux value
    // roundid => Sender => [bool,bool] , set of values shared by sender
    pub values: HashMap<usize, HashMap<usize, HashSet<bool>>>,
    pub bin_values: HashMap<usize, HashSet<bool>>, // roundid => {bool}
    pub ended: bool,                               //ABA session ended or not
    pub output: bool,                              // Agreed value after consensus
    pub notify: Arc<Notify>,
}

impl AbaStore {
    /// Set the estimate value for a given round id
    pub fn mark_est(&mut self, round: usize, value: bool) {
        let est = self.est.entry(round).or_insert([false; 2]);
        est[value as usize] = true;
    }

    /// Get the estimate value for a given round id, defaulting to `false` if not set
    pub fn get_est(&self, round: usize, value: bool) -> bool {
        self.est
            .get(&round)
            .map(|arr| arr[value as usize])
            .unwrap_or(false)
    }
    /// Mark the aux value for a given round id
    pub fn mark_aux(&mut self, round: usize, value: bool) {
        let aux_arr = self.aux.entry(round).or_insert([false; 2]);
        aux_arr[value as usize] = true;
    }
    /// Get the aux value for a given round id, defaulting to `false` if not set
    pub fn get_aux(&self, round: usize, value: bool) -> bool {
        self.aux
            .get(&round)
            .map(|arr| arr[value as usize])
            .unwrap_or(false)
    }

    /// Check if a sender has already sent an estimate(0 or 1) in a given round
    pub fn has_sent_est(&self, round: usize, sender: usize, value: bool) -> bool {
        self.est_senders
            .get(&round)
            .and_then(|senders| senders.get(&sender))
            .map(|arr| arr[value as usize])
            .unwrap_or(false)
    }

    /// Mark a sender as having sent an estimate(0 or 1) in a given round
    pub fn set_est_sent(&mut self, round: usize, sender: usize, value: bool) {
        self.est_senders
            .entry(round)
            .or_default()
            .entry(sender)
            .or_insert([false; 2])[value as usize] = true;
    }

    /// Increase the est count of 0s or 1s received in a round
    pub fn increment_est(&mut self, round: usize, value: bool) {
        let counts = self.est_count.entry(round).or_insert([0, 0]);
        if value {
            counts[1] += 1;
        } else {
            counts[0] += 1;
        }
    }

    /// Get the current estimate count ([0s, 1s]) for a round
    pub fn get_est_count(&self, round: usize) -> [usize; 2] {
        self.est_count.get(&round).copied().unwrap_or([0, 0])
    }
    /// Insert a binary value into the bin_values set for a given round ID
    pub fn insert_bin_value(&mut self, round: usize, value: bool) {
        self.bin_values
            .entry(round)
            .or_insert_with(HashSet::new)
            .insert(value);
    }

    //Get the bin_values set for a given round
    pub fn get_bin_values(&self, round: usize) -> HashSet<bool> {
        self.bin_values.get(&round).cloned().unwrap_or_default()
    }

    /// Check if a sender has already sent an aux value either 0 or 1 in a given round
    pub fn has_sent_aux(&self, round: usize, sender: usize, value: bool) -> bool {
        self.aux_senders
            .get(&round)
            .and_then(|senders| senders.get(&sender))
            .map(|arr| arr[value as usize])
            .unwrap_or(false)
    }

    /// Mark a sender as having sent an value either 0 or 1 in a given round
    pub fn set_aux_sent(&mut self, round: usize, sender: usize, value: bool) {
        self.aux_senders
            .entry(round)
            .or_default()
            .entry(sender)
            .or_insert([false; 2])[value as usize] = true;
    }

    /// Insert a binary value into the values set for a given round ID and given sender
    pub fn insert_values(&mut self, round: usize, sender: usize, value: bool) {
        self.values
            .entry(round)
            .or_insert_with(HashMap::new)
            .entry(sender)
            .or_insert_with(HashSet::new)
            .insert(value);
    }

    /// Get the current count of senders who sent aux messages for a given round
    pub fn get_sender_count(&self, round: usize) -> usize {
        self.values
            .get(&round)
            .map(|sender_map| sender_map.len())
            .unwrap_or(0)
    }

    // Get the union of all the values set for a given round
    pub fn get_all_values(&self, round: usize) -> HashSet<bool> {
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
    pub sign_senders: HashMap<usize, HashMap<usize, bool>>, //roundid => Sender => bool, check if signature shares were sent
    pub sign_count: HashMap<usize, usize>,                  // roundid => signature share count
    pub sign_shares: HashMap<usize, HashMap<usize, Vec<u8>>>, // roundid => sender_id => Signature share
    pub coins: HashMap<usize, bool>,                          //roundid => Coin
    pub start: HashMap<usize, bool>, //roundid => yes or no , checks if common coin has been initiated yet
    pub notifiers: HashMap<usize, Arc<Notify>>, // round_id => Notify ,Checks if common coin is ready to be used
}
impl CoinStore {
    /// Check if a sender has already sent a signature share in a given round
    pub fn has_sent_sign(&self, round: usize, sender: usize) -> bool {
        self.sign_senders
            .get(&round)
            .and_then(|senders| senders.get(&sender))
            .copied()
            .unwrap_or(false)
    }

    /// Increase the count of signature shares received in a round
    pub fn increment_sign(&mut self, round: usize) {
        *self.sign_count.entry(round).or_insert(0) += 1;
    }

    /// Mark a sender as having sent a signature share in a given round
    pub fn set_sign_sent(&mut self, round: usize, sender: usize) {
        self.sign_senders
            .entry(round)
            .or_default()
            .insert(sender, true);
    }

    /// Get the current signature share count for a round
    pub fn get_sign_count(&self, round: usize) -> usize {
        self.sign_count.get(&round).copied().unwrap_or(0)
    }

    /// Insert a signature share for a given round
    pub fn insert_share(&mut self, round_id: usize, sender_id: usize, share: Vec<u8>) {
        self.sign_shares
            .entry(round_id)
            .or_insert_with(HashMap::new)
            .insert(sender_id, share);
    }

    //Get the signature share map for a given round
    pub fn get_shares_map(&self, round_id: usize) -> Option<&HashMap<usize, Vec<u8>>> {
        self.sign_shares.get(&round_id)
    }

    //Set the common coin as ready to be used and notify waiter
    pub fn set_coin(&mut self, round_id: usize, value: bool) {
        self.coins.insert(round_id, value);
        if let Some(notify) = self.notifiers.remove(&round_id) {
            notify.notify_waiters(); // Wake up all waiting tasks
        }
    }

    /// Get the coin value for a given round, if it exists.
    pub fn coin(&self, round: usize) -> Option<bool> {
        self.coins.get(&round).copied()
    }

    //Marks the start of common coin generation
    pub fn set_start(&mut self, round_id: usize) {
        self.start.insert(round_id, true);
    }

    //Checks if common coin generation has started
    pub fn get_start(&self, round: usize) -> bool {
        *self.start.get(&round).unwrap_or(&false)
    }
}

/// Stores the internal state for each ACS session at a party.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub aba_input: HashMap<u128, bool>,     //Session slot => aba input
    pub aba_output: HashMap<u128, bool>,    //Session slot => aba output
    pub rbc_output: HashMap<u128, Vec<u8>>, //Session slot => rbc output
    pub ended: bool,
    pub commonsubset: Vec<Vec<u8>>,
}

impl AcsStore {
    /// Checks if ABA input is stored for the given session slot.
    pub fn has_aba_input(&self, session_id: u128) -> bool {
        self.aba_input.contains_key(&session_id)
    }
    /// Sets the ABA input for a given session slot.
    pub fn set_aba_input(&mut self, session_id: u128, value: bool) {
        self.aba_input.insert(session_id, value);
    }
    /// Sets the ABA output for a given session slot.
    pub fn set_aba_output(&mut self, session_id: u128, value: bool) {
        self.aba_output.insert(session_id, value);
    }
    /// Get the ABA output 1 count
    pub fn get_aba_output_one_count(&mut self) -> usize {
        self.aba_output.iter().filter(|&(_, &val)| val).count()
    }
    /// Checks if RBC output is stored for the given session slot.
    pub fn has_rbc_output(&self, session_id: u128) -> bool {
        self.rbc_output.contains_key(&session_id)
    }
    /// Sets the RBC output for a given session slot.
    pub fn set_rbc_output(&mut self, session_id: u128, output: Vec<u8>) {
        self.rbc_output.insert(session_id, output);
    }
    /// Get the RBC output for a given session slot.
    pub fn get_rbc_output(&mut self, session_id: u128) -> Option<&Vec<u8>> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_shard_accepts_same_root_from_multiple_senders() {
        let mut store = AvidStore::new();
        let root = vec![1u8; 32];
        store
            .insert_shard(root.clone(), 0, vec![0u8; 10], 2, usize::MAX, usize::MAX)
            .unwrap();
        store
            .insert_shard(root.clone(), 1, vec![0u8; 10], 2, usize::MAX, usize::MAX)
            .unwrap();
        assert_eq!(store.shards.get(&root).unwrap().len(), 2);
    }

    /// Once a root is committed, a mismatched root is equivocation and must be rejected outright.
    #[test]
    fn insert_shard_rejects_mismatched_root_after_commit() {
        let mut store = AvidStore::new();
        let root_a = vec![1u8; 32];
        let root_b = vec![2u8; 32];

        // Two senders back root_a, which commits the session at t = 1.
        for sender in 0..2 {
            store
                .insert_shard(root_a.clone(), sender, vec![0u8; 10], 2, usize::MAX, usize::MAX)
                .unwrap();
            store.increment_echo(&root_a);
        }
        assert!(store.try_commit_root(&root_a, 2), "root_a must commit");

        let result = store.insert_shard(root_b.clone(), 2, vec![0u8; 10], 2, usize::MAX, usize::MAX);
        assert!(result.is_err(), "mismatched root must be rejected");
        assert!(
            !store.shards.contains_key(&root_b),
            "rejected root's shard must not be stored"
        );
        assert_eq!(
            store.shards.get(&root_a).unwrap().len(),
            2,
            "the committed root's data must be unaffected"
        );
    }

    /// A lone sender must not be able to commit the session to a root of its choosing. Binding on
    /// first arrival let any single party stall an honest dealer's broadcast permanently by racing
    /// one ECHO with a self-built tree; commitment requires multiple distinct backers instead (in
    /// production, the caller passes the intersection-guaranteeing quorum — see `try_commit_root`).
    #[test]
    fn one_sender_cannot_commit_a_root() {
        let mut store = AvidStore::new();
        let forged = vec![9u8; 32];
        let honest = vec![1u8; 32];

        store
            .insert_shard(forged.clone(), 3, vec![0u8; 10], 2, usize::MAX, usize::MAX)
            .unwrap();
        store.increment_echo(&forged);
        assert!(
            !store.try_commit_root(&forged, 2),
            "a single backer must not commit a root"
        );

        // The honest root still gets in, and wins once corroborated.
        for sender in 0..2 {
            store
                .insert_shard(honest.clone(), sender, vec![0u8; 10], 2, usize::MAX, usize::MAX)
                .unwrap();
            store.increment_echo(&honest);
        }
        assert!(
            store.try_commit_root(&honest, 2),
            "the corroborated root must commit"
        );
        assert_eq!(store.accepted_root.as_ref(), Some(&honest));
        assert!(
            !store.shards.contains_key(&forged),
            "the losing root's state must be dropped on commit"
        );
    }

    /// ECHO and READY tallies must not be summed: a single sender contributes to both, so a sum
    /// would let `t` Byzantine parties reach `2t` backing and commit a root of their own.
    #[test]
    fn echo_and_ready_backing_is_not_summed() {
        let mut store = AvidStore::new();
        let forged = vec![9u8; 32];

        store
            .insert_shard(forged.clone(), 3, vec![0u8; 10], 2, usize::MAX, usize::MAX)
            .unwrap();
        store.increment_echo(&forged);
        store.increment_ready(&forged);

        assert!(
            !store.try_commit_root(&forged, 2),
            "one sender backing a root twice must not reach a threshold of 2"
        );
    }

    /// Retention before commitment is bounded by the callers' per-sender dedup, not by the root
    /// count: each sender contributes at most one ECHO and one READY shard, so competing roots
    /// split a fixed `2n` budget rather than multiplying it.
    #[test]
    fn uncommitted_retention_is_bounded_by_sender_count() {
        let n = 4;
        let mut store = AvidStore::new();

        // Worst case: every sender backs a distinct root via ECHO, and another via READY.
        for sender in 0..n {
            store
                .insert_shard(vec![sender as u8; 32], sender, vec![0u8; 10], 2, usize::MAX, usize::MAX)
                .unwrap();
            store
                .insert_shard(vec![(100 + sender) as u8; 32], sender, vec![0u8; 10], 2, usize::MAX, usize::MAX)
                .unwrap();
        }

        let total: usize = store.shards.values().map(|m| m.len()).sum();
        assert_eq!(total, 2 * n, "retention must be exactly 2n shards");
        assert!(store.accepted_root.is_none(), "no root reached t + 1");
    }

    /// The per-sender byte cap bounds one sender's retained shard bytes regardless of how many
    /// distinct sessions it floods: over-budget inserts are rejected and store nothing.
    #[test]
    fn byte_ledger_caps_a_single_sender() {
        let ledger = Arc::new(StdMutex::new(ByteLedger::default()));
        let global_cap = 1000;
        let per_sender_cap = 100;

        // One sender floods distinct sessions, each with a 40-byte shard. The third would exceed the
        // 100-byte per-sender cap and must be refused.
        let mut stores = Vec::new();
        let mut inserted = 0usize;
        for i in 0..5u8 {
            let mut store = AvidStore::with_ledger(ledger.clone());
            let outcome = store
                .insert_shard(vec![i; 32], 7, vec![0u8; 40], 2, global_cap, per_sender_cap)
                .unwrap();
            if outcome == ShardInsert::Inserted {
                inserted += 1;
            }
            stores.push(store); // keep alive so Drop doesn't release mid-loop
        }
        assert_eq!(inserted, 2, "only two 40-byte shards fit under a 100-byte cap");
        assert_eq!(ledger.lock().unwrap().sender_bytes(7), 80);
        assert!(ledger.lock().unwrap().global_bytes() <= global_cap);
    }

    /// Dropping a session (any teardown path) releases its charges back to the ledger, so a flood of
    /// abandoned sessions cannot permanently exhaust the pool.
    #[test]
    fn dropping_a_session_releases_its_bytes() {
        let ledger = Arc::new(StdMutex::new(ByteLedger::default()));
        {
            let mut store = AvidStore::with_ledger(ledger.clone());
            store
                .insert_shard(vec![1u8; 32], 2, vec![0u8; 50], 2, 1000, 1000)
                .unwrap();
            assert_eq!(ledger.lock().unwrap().sender_bytes(2), 50);
        }
        assert_eq!(
            ledger.lock().unwrap().global_bytes(),
            0,
            "drop must release every charge"
        );
        assert_eq!(ledger.lock().unwrap().sender_bytes(2), 0);
    }

    /// Committing a root releases the byte charges for every losing (equivocated) root's shards.
    #[test]
    fn commit_releases_losing_root_bytes() {
        let ledger = Arc::new(StdMutex::new(ByteLedger::default()));
        let mut store = AvidStore::with_ledger(ledger.clone());
        let winner = vec![1u8; 32];
        let loser = vec![2u8; 32];

        // Two senders back the winner; one sender also backs a competing (losing) root.
        for sender in 0..2 {
            store
                .insert_shard(winner.clone(), sender, vec![0u8; 30], 2, 10_000, 10_000)
                .unwrap();
            store.increment_echo(&winner);
        }
        store
            .insert_shard(loser.clone(), 3, vec![0u8; 30], 2, 10_000, 10_000)
            .unwrap();
        assert_eq!(ledger.lock().unwrap().global_bytes(), 90, "3 shards charged");

        assert!(store.try_commit_root(&winner, 2));
        assert_eq!(
            ledger.lock().unwrap().global_bytes(),
            60,
            "the losing root's 30 bytes must be released on commit"
        );
        assert_eq!(ledger.lock().unwrap().sender_bytes(3), 0);
    }

    /// A sender's ECHO then READY for the same (root, leaf) is charged once, not twice.
    #[test]
    fn re_inserting_same_shard_is_not_double_charged() {
        let ledger = Arc::new(StdMutex::new(ByteLedger::default()));
        let mut store = AvidStore::with_ledger(ledger.clone());
        let root = vec![1u8; 32];
        store
            .insert_shard(root.clone(), 2, vec![0u8; 40], 2, 1000, 1000)
            .unwrap();
        store
            .insert_shard(root.clone(), 2, vec![0u8; 40], 2, 1000, 1000)
            .unwrap();
        assert_eq!(ledger.lock().unwrap().sender_bytes(2), 40, "charged once");
    }
}
