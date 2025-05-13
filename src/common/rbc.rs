/// This file contains more common reliable broadcast protocols used in MPC.
/// You can reuse them in your own custom MPC protocol implementations.
use super::rbc_store::*;
use super::utils::*;
use crate::RBC;
use async_trait::async_trait;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{
    mpsc::{Receiver, Sender},
    Mutex,
};
use tracing::{debug, error, info, warn};

//Mock a network for testing purposes
#[derive(Clone)]
pub struct Network {
    pub id: u32,                   // The identifier of the current party in the network
    pub senders: Vec<Sender<Msg>>, // List of all senders, including the current party itself
}

///--------------------------Bracha RBC--------------------------
/// Protocol works as follows(m is the message to broadcast) :
/// 1. Initiator sends (INIT,m)
/// 2. Party on recieveing (INIT,m) and haven't sent (ECHO,m), sends (ECHO,m)
/// 3. Party on recieving 2t+1 (ECHO, m) and haven't sent :
///     a. (ECHO,m) -> sends (ECHO,m)
///     b. (READY,m) -> sends (READY, m)
/// 4. Party on recieving t+1 (READY, m) and haven't sent :
///     a. (ECHO,m) -> sends (ECHO,m)
///     b. (READY,m) -> sends (READY, m)
/// 4. Party on recieving 2t+1 (READY, m) output m and terminate
#[derive(Clone)]
pub struct Bracha {
    pub id: u32,                                                  // The ID of the initiator
    pub n: u32, // Total number of parties in the network
    pub t: u32, // Number of allowed malicious parties
    pub k: u32, //threshold (Not really used in Bracha)
    pub store: Arc<Mutex<HashMap<u32, Arc<Mutex<BrachaStore>>>>>, // Stores the session state for each session
}
#[async_trait]
impl RBC for Bracha {
    /// Creates a new Bracha instance with the given parameters.
    fn new(id: u32, n: u32, t: u32, k: u32) -> Result<Self, String> {
        if !(t < (n + 2) / 3) {
            // ceil(n / 3)
            return Err(format!(
                "Invalid t: must satisfy 0 <= t < n / 3 (t={}, n={})",
                t, n
            ));
        }
        Ok(Bracha {
            id,
            n,
            t,
            k,
            store: Arc::new(Mutex::new(HashMap::new())),
        })
    }
    /// This initiates the Bracha protocol.
    async fn init(&self, payload: Vec<u8>, session_id: u32, net: Arc<Network>) {
        // Create an INIT message with the given payload and session ID.
        let msg = Msg::new(
            self.id,
            session_id,
            payload.clone(),
            vec![],
            GenericMsgType::Bracha(MsgType::Init),
            payload.len(),
        );
        info!(
            id = self.id,
            session_id,
            msg_type = "INIT",
            "Broadcasting INIT message"
        );
        Bracha::broadcast(&self, msg, net).await;
    }
    /// Processes incoming messages based on their type.
    async fn process(&self, msg: Msg, net: Arc<Network>) {
        match &msg.msg_type {
            GenericMsgType::Bracha(msg_type) => match msg_type {
                MsgType::Init => self.init_handler(msg, net).await,
                MsgType::Echo => self.echo_handler(msg, net).await,
                MsgType::Ready => self.ready_handler(msg, net).await,
                MsgType::Unknown(t) => {
                    warn!("Avid: Unknown message type: {}", t);
                }
            },
            _ => {
                warn!("process: received non-Bracha message");
            }
        }
    }
    /// Broadcasts a message to all parties in the network.
    async fn broadcast(&self, msg: Msg, net: Arc<Network>) {
        for sender in &net.senders {
            let _ = sender.send(msg.clone()).await;
        }
    }
    /// Send a message to a party in the network.
    async fn send(&self, msg: Msg, net: Arc<Network>, recv: u32) {
        let _ = net.senders[recv as usize].send(msg).await;
    }
    /// Runs the party logic, continuously receiving and processing messages.
    async fn run_party(&self, receiver: &mut Receiver<Msg>, net: Arc<Network>) {
        while let Some(msg) = receiver.recv().await {
            self.process(msg, net.clone()).await;
        }
    }
}
impl Bracha {
    /// Handlers
    /// Handles the "INIT" message. Responds by broadcasting an "ECHO" message if necessary.
    pub async fn init_handler(&self, msg: Msg, net: Arc<Network>) {
        info!(
            id = self.id,
            session_id = msg.session_id,
            sender = msg.sender_id,
            msg_type = %msg.msg_type,
            "Handling INIT message"
        );

        // Lock the session store to update the session state.
        let session_store = self.get_or_create_store(msg.session_id).await;
        // Lock the session-specific store to access or update the session state.
        let mut store = session_store.lock().await;

        // Only broadcast the ECHO if it hasn't already been sent.
        if !store.echo {
            let new_msg = Msg::new(
                self.id,
                msg.session_id,
                msg.payload.clone(),
                vec![],
                GenericMsgType::Bracha(MsgType::Echo),
                msg.payload.len(),
            );
            store.mark_echo(); // Mark that ECHO has been sent.
            info!(
                id = self.id,
                session_id = msg.session_id,
                msg_type = "ECHO",
                "Broadcasting ECHO in response to INIT"
            );
            Bracha::broadcast(&self, new_msg, net).await;
        }
    }
    /// Handles the "ECHO" message. If the threshold of echoes is met, a "READY" message is broadcast.
    pub async fn echo_handler(&self, msg: Msg, net: Arc<Network>) {
        info!(
            id = self.id,
            session_id = msg.session_id,
            sender = msg.sender_id,
            msg_type = %msg.msg_type,
            "Handling ECHO message"
        );
        // Lock the session store to update the session state.
        let session_store = self.get_or_create_store(msg.session_id).await;
        // Lock the session-specific store to access or update the session state.
        let mut store = session_store.lock().await;

        // Ignore the message if the session has already ended.
        if store.ended {
            debug!(
                id = self.id,
                session_id = msg.session_id,
                "Session already ended, ignoring ECHO"
            );
            return;
        }

        // If this sender has not already sent an ECHO, process it.
        if !store.has_echo(msg.sender_id) {
            store.set_echo_sent(msg.sender_id); // Mark this sender as having sent an ECHO.
            store.increment_echo(&msg.payload); // Increment the count for the corresponding payload.
            let count = store.get_echo_count(&msg.payload);
            // If the threshold for receiving echoes is met, broadcast the READY message.
            if count >= 2 * self.t + 1 {
                if !store.ready {
                    store.mark_ready(); // Mark the session as ready.
                    let new_msg = Msg::new(
                        self.id,
                        msg.session_id,
                        msg.payload.clone(),
                        vec![],
                        GenericMsgType::Bracha(MsgType::Ready),
                        msg.payload.clone().len(),
                    );
                    info!(
                        id = self.id,
                        session_id = msg.session_id,
                        msg_type = "READY",
                        "Broadcasting READY after ECHO threshold met"
                    );
                    Bracha::broadcast(&self, new_msg, net.clone()).await; // Broadcast the READY message.
                }
                // If ECHO hasn't been sent yet, broadcast the ECHO message.
                if !store.echo {
                    store.mark_echo(); // Mark ECHO as sent.
                    let new_msg = Msg::new(
                        self.id,
                        msg.session_id,
                        msg.payload.clone(),
                        vec![],
                        GenericMsgType::Bracha(MsgType::Echo),
                        msg.payload.len(),
                    );
                    info!(
                        id = self.id,
                        session_id = msg.session_id,
                        msg_type = "ECHO",
                        "Re-broadcasting ECHO due to threshold"
                    );

                    Bracha::broadcast(&self, new_msg, net).await;
                }
            }
        }
    }
    /// Handles the "READY" message. If the threshold is met, the session ends and the output is stored.
    pub async fn ready_handler(&self, msg: Msg, net: Arc<Network>) {
        info!(
            id = self.id,
            session_id = msg.session_id,
            sender = msg.sender_id,
            msg_type = %msg.msg_type,
            "Handling READY message"
        );

        // Lock the session store to update the session state.
        let session_store = self.get_or_create_store(msg.session_id).await;
        // Lock the session-specific store to access or update the session state.
        let mut store = session_store.lock().await;

        // Ignore the message if the session has already ended.
        if store.ended {
            debug!(
                id = self.id,
                session_id = msg.session_id,
                "Session already ended, ignoring READY"
            );
            return;
        }

        // If this sender hasn't sent READY yet, process it.
        if !store.has_ready(msg.sender_id) {
            store.set_ready_sent(msg.sender_id); // Mark this sender as having sent READY.
            store.increment_ready(&msg.payload); // Increment the count for the corresponding payload.
            let count = store.get_ready_count(&msg.payload);

            // If the threshold for receiving READIES is met, finalize the session.
            if count >= self.t + 1 && count < 2 * self.t + 1 {
                if !store.ready {
                    store.mark_ready(); // Mark the session as ready.
                    let new_msg = Msg::new(
                        self.id,
                        msg.session_id,
                        msg.payload.clone(),
                        vec![],
                        GenericMsgType::Bracha(MsgType::Ready),
                        msg.payload.clone().len(),
                    );
                    info!(
                        id = self.id,
                        session_id = msg.session_id,
                        msg_type = "READY",
                        "Broadcasting READY after t+1 threshold"
                    );
                    Bracha::broadcast(&self, new_msg, net.clone()).await;
                }
                // If ECHO hasn't been sent yet, broadcast it along with READY.
                if !store.echo {
                    store.mark_echo(); // Mark ECHO as sent.
                    let new_msg = Msg::new(
                        self.id,
                        msg.session_id,
                        msg.payload.clone(),
                        vec![],
                        GenericMsgType::Bracha(MsgType::Echo),
                        msg.payload.len(),
                    );
                    info!(
                        id = self.id,
                        session_id = msg.session_id,
                        msg_type = "ECHO",
                        "Broadcasting ECHO along with READY"
                    );
                    Bracha::broadcast(&self, new_msg, net).await;
                }
            } else if count >= 2 * self.t + 1 {
                // If consensus is reached, mark the session as ended and store the output.
                store.mark_ended();
                store.set_output(msg.payload.clone());
                info!(
                    id = self.id,
                    session_id = msg.session_id,
                    output = ?msg.payload,
                    "Consensus achieved; RBC instance ended"
                );
            }
        }
    }
    async fn get_or_create_store(&self, session_id: u32) -> Arc<Mutex<BrachaStore>> {
        let mut store = self.store.lock().await;
        // Get or create the session state for the current session.
        store
            .entry(session_id)
            .or_insert_with(|| Arc::new(Mutex::new(BrachaStore::default())))
            .clone()
    }
}

///--------------------------AVID RBC--------------------------
/// 
/// https://homes.cs.washington.edu/~tessaro/papers/dds.pdf
/// 
/// Assumptions:
/// - n parties: P1, P2, ..., Pn
/// - t < n / 3 Byzantine faults
/// - H: collision-resistant hash function
///
///------------------------------------------------------------
/// Dealer Protocol (Sender)
/// 
/// 1. Encode message m as a polynomial f(x) of degree ≤ k - 1.
/// 2. Compute n shares: Fj := f(j) for j ∈ [1, n].
/// 3. Build Merkle tree (binary hash tree) over [F1, ..., Fn]:
///     Leaf i: val(i) := H(Fi)
///     Internal node v: val(v) := H(val(left), val(right))
/// 4. Compute root hash hr := val(root).
/// 5. For each j ∈ [1, n]:
///     Compute fingerprint FP(j): the sibling hashes along path from j to root.
///     Send message: (ID, send, hr, FP(j), Fj) to server Pj.
/// 
///------------------------------------------------------------
/// Server Protocol (Executed by Pi)
/// 
/// Initialization for each root hash hr:
/// - A_hr := ∅        // set of accepted (index, share)
/// - e_hr := 0        // echo counter
/// - r_hr := 0        // ready counter
/// 
/// On receiving (ID, send, hr, FP(i), Fi):
/// - If verify(i, Fi, FP(i), hr):
///     - Send (ID, echo, hr, FP(i), Fi) to all servers.
/// 
/// On receiving (ID, echo, hr, FP(m), Fm) from Pm:
/// - If verify(m, Fm, FP(m), hr) and first from Pm:
///     - Add (m, Fm) to A_hr.
///     - Increment e_hr.
/// - If e_hr ≥ max((n + t + 1)/2, k) and r_hr < k:
///     - Interpolate polynomial f̄(x) from points in A_hr.
///     - Compute F̄j := f̄(j) for all j ∈ [1, n].
///     - Compute fingerprints FP(j) from Merkle tree.
///     - If verify(j, F̄j, FP(j), hr) for all j:
///         - Send (ID, ready, hr, FP(i), F̄i) to all servers.
///     - Else:
///         - Output (ID, out, abort).
/// 
/// On receiving (ID, ready, hr, FP(m), Fm) from Pm:
/// - If verify(m, Fm, FP(m), hr) and first from Pm:
///     - Add (m, Fm) to A_hr.
///     - Increment r_hr.
/// - If r_hr = k and e_hr < max((n + t + 1)/2, k):
///     - Interpolate f̄(x) from A_hr.
///     - Compute F̄j := f̄(j) for all j ∈ [1, n].
///     - Compute fingerprints FP(j) from Merkle tree.
///     - If verify(j, F̄j, FP(j), hr) for all j:
///         - Send (ID, ready, hr, FP(i), F̄i) to all servers.
///     - Else:
///         - Output (ID, out, abort).
/// - Else if r_hr = k + t:
///     - Output (ID, out, [F̄1, ..., F̄k]) as the delivered broadcast message m₀.
/// 
///------------------------------------------------------------
/// Verification Function
/// verify(i, Fi, FP, hr) -> bool:
/// - h := H(Fi)
/// - For j = l down to 1:
///     - Use sibling hash FP[j-1] and path direction (left/right) to compute:
///         h := H(h, FP[j-1]) or H(FP[j-1], h)
/// - Return (h == hr)


#[derive(Clone)]
pub struct Avid {
    pub id: u32,                                                //Initiators ID
    pub n: u32,                                                 //Network size
    pub t: u32,                                                 //No. of malicious parties
    pub k: u32,                                                 //Threshold
    pub store: Arc<Mutex<HashMap<u32, Arc<Mutex<AvidStore>>>>>, //Sessionid => store
}
#[async_trait]
impl RBC for Avid {
    /// Creates a new Avid instance with the given parameters.
    fn new(id: u32, n: u32, t: u32, k: u32) -> Result<Self, String> {
        if !(t < (n + 2) / 3) {
            // ceil(n / 3)
            return Err(format!(
                "Invalid t: must satisfy 0 <= t < n / 3 (t={}, n={})",
                t, n
            ));
        }
        if !(t + 1 <= k && k <= n - 2 * t) {
            return Err(format!(
                "Invalid k: must satisfy t + 1 <= k <= n - 2t (t={}, k={}, n={})",
                t, k, n
            ));
        }

        Ok(Avid {
            id,
            n,
            t,
            k,
            store: Arc::new(Mutex::new(HashMap::new())),
        })
    }
    ///This initiates the Avid protocol.
    async fn init(&self, payload: Vec<u8>, session_id: u32, net: Arc<Network>) {
        info!(
            id = self.id,
            session_id,
            msg_type = "SEND",
            "Sending SEND message for AVID to all parties"
        );

        //Generating shards for the message to be broadcasted, here we are using Reed Solomon erasure coding
        let shards_result = encode_rs(payload.clone(), self.k as usize, (self.n - self.k) as usize);
        let shards = match shards_result {
            // Handle potential error from encoding
            Ok(shards) => shards,
            Err(e) => {
                error!(
                    id = self.id,
                    session_id = session_id,
                    error = %e,
                    "Error while generating shards at Init"
                );
                return;
            }
        };
        //Generating the merkle tree out of the shards
        let tree = gen_merkletree(shards.clone());

        let root = match tree.root() {
            Some(r) => r,
            None => {
                error!("Merkle tree root not found for session: {}", session_id);
                return;
            }
        };

        // Generating fingerprint for each server and sending it to them along with root and respective shard
        for i in 0..self.n {
            let i_usize = i as usize;
            let fingerprint = tree.proof(&[i_usize]).to_bytes();
            let mut fp = Vec::with_capacity(root.len() + fingerprint.len());
            fp.extend_from_slice(&root);
            fp.extend_from_slice(&fingerprint);

            let shard = shards[i_usize].clone();
            // Create an SEND message with the given fingerprint,root,shard and session ID.
            let msg = Msg::new(
                self.id,
                session_id,
                shard,
                fp, // [root||fingerprint]
                GenericMsgType::Avid(MsgTypeAvid::Send),
                payload.len(),
            );

            self.send(msg, net.clone(), i).await;
        }
    }
    /// Processes incoming messages based on their type.
    async fn process(&self, msg: Msg, net: Arc<Network>) {
        match &msg.msg_type {
            GenericMsgType::Avid(msg_type) => match msg_type {
                MsgTypeAvid::Send => self.send_handler(msg, net).await,
                MsgTypeAvid::Echo => self.echo_handler(msg, net).await,
                MsgTypeAvid::Ready => self.ready_handler(msg, net).await,
                MsgTypeAvid::Unknown(t) => {
                    warn!("Avid: Unknown message type: {}", t);
                }
            },
            _ => {
                warn!("process: received non-AVID message");
            }
        }
    }
    /// Broadcasts a message to all parties in the network.
    async fn broadcast(&self, msg: Msg, net: Arc<Network>) {
        for sender in &net.senders {
            let _ = sender.send(msg.clone()).await;
        }
    }
    /// Send a message to a party in the network.
    async fn send(&self, msg: Msg, net: Arc<Network>, recv: u32) {
        let _ = net.senders[recv as usize].send(msg).await;
    }
    /// Runs the party logic, continuously receiving and processing messages.
    async fn run_party(&self, receiver: &mut Receiver<Msg>, net: Arc<Network>) {
        while let Some(msg) = receiver.recv().await {
            self.process(msg, net.clone()).await;
        }
    }
}

impl Avid {
    /// Handlers

    /// Handles the "SEND" message. Responds by broadcasting an "ECHO" message if necessary.
    pub async fn send_handler(&self, msg: Msg, net: Arc<Network>) {
        info!(
            id = self.id,
            session_id = msg.session_id,
            sender = msg.sender_id,
            msg_type = %msg.msg_type,
            "Handling SEND message"
        );

        // Lock the session store to update the session state.
        let session_store = self.get_or_create_store(msg.session_id).await;
        // Lock the session-specific store to access or update the session state.
        let mut store = session_store.lock().await;

        // Only broadcast the ECHO if it hasn't already been sent.
        if !store.echo {
            //Verify the merkle path(fingerprint) against shared root for the given shard
            match verify_merkle(self.id, self.n, msg.metadata.clone(), msg.payload.clone()) {
                Ok(true) => {
                    //Create echo message
                    let msg = Msg::new(
                        self.id,
                        msg.session_id,
                        msg.payload,
                        msg.metadata,
                        GenericMsgType::Avid(MsgTypeAvid::Echo),
                        msg.msg_len,
                    );
                    store.mark_echo(); // Mark that ECHO has been sent to avoid resending it
                    info!(
                        id = self.id,
                        session_id = msg.session_id,
                        msg_type = "ECHO",
                        "Broadcasting ECHO in response to SEND"
                    );
                    //Send message to every party
                    Avid::broadcast(&self, msg, net).await;
                }
                Ok(false) => {
                    error!(
                        id = self.id,
                        session_id = msg.session_id,
                        sender = msg.sender_id,
                        "Merkle proof verification failed on SEND message"
                    );
                    return;
                }
                Err(e) => {
                    error!(
                        id = self.id,
                        session_id = msg.session_id,
                        sender = msg.sender_id,
                        error = %e,
                        "Error during Merkle proof verification"
                    );
                    return;
                }
            };
        }
    }
    /// Handles the "ECHO" message. Might broadcast "READY" message .
    pub async fn echo_handler(&self, msg: Msg, net: Arc<Network>) {
        info!(
            id = self.id,
            session_id = msg.session_id,
            sender = msg.sender_id,
            msg_type = %msg.msg_type,
            "Handling ECHO message"
        );
        // Lock the session store to update the session state.
        let session_store = self.get_or_create_store(msg.session_id).await;
        // Lock the session-specific store to access or update the session state.
        let mut store = session_store.lock().await;

        // Ignore the message if the session has already ended.
        if store.ended {
            debug!(
                id = self.id,
                session_id = msg.session_id,
                "Session already ended, ignoring ECHO"
            );
            return;
        }
        // If this sender has not already sent an ECHO, process it.
        if !store.has_echo(msg.sender_id) {
            let root = &&msg.metadata[0..32];
            let proof_bytes = &msg.metadata[32..];

            //Verify merkle proof
            match verify_merkle(
                msg.sender_id,
                self.n,
                msg.metadata.clone(),
                msg.payload.clone(),
            ) {
                Ok(true) => {
                    //Store fingerprint and shard
                    store.insert_shard(root.to_vec(), msg.sender_id, msg.payload.clone());
                    store.insert_fingerprint(root.to_vec(), msg.sender_id, proof_bytes.to_vec());
                    //Increment echo count
                    store.increment_echo(root);
                    // Mark this sender as having sent an ECHO.
                    store.set_echo_sent(msg.sender_id);

                    let echo_count = store.get_echo_count(root);
                    let ready_count = store.get_ready_count(root);
                    //compact way to compute ceil((n + t + 1) / 2) using integer arithmetic
                    let threshold = u32::max((self.n + self.t + 2) / 2, self.k);
                    // READY broadcast logic
                    if echo_count == threshold && ready_count < self.k {
                        //Send ready logic
                        let shards_map = store.get_shards_for_root(&root.to_vec());
                        self.send_ready(msg, shards_map, net).await;
                    }
                }
                Ok(false) => {
                    warn!(
                        id = self.id,
                        session_id = msg.session_id,
                        sender = msg.sender_id,
                        "Merkle verification failed for ECHO"
                    );
                    return;
                }
                Err(e) => {
                    warn!(
                        id = self.id,
                        session_id = msg.session_id,
                        sender = msg.sender_id,
                        error = %e,
                        "Merkle verification threw error"
                    );
                    return;
                }
            }
        }
    }
    /// Handles the "READY" message. If the threshold is met, the session ends and the output is stored.
    pub async fn ready_handler(&self, msg: Msg, net: Arc<Network>) {
        info!(
            id = self.id,
            session_id = msg.session_id,
            sender = msg.sender_id,
            msg_type = %msg.msg_type,
            "Handling READY message"
        );
        // Lock the session store to update the session state.
        let session_store = self.get_or_create_store(msg.session_id).await;
        // Lock the session-specific store to access or update the session state.
        let mut store = session_store.lock().await;

        // Ignore the message if the session has already ended.
        if store.ended {
            debug!(
                id = self.id,
                session_id = msg.session_id,
                "Session already ended, ignoring READY"
            );
            return;
        }
        // If this sender has not already sent an READY, process it.
        if !store.has_ready(msg.sender_id) {
            let root = &msg.metadata[0..32];
            let proof_bytes = &msg.metadata[32..];

            //Verify merkle proof
            match verify_merkle(
                msg.sender_id,
                self.n,
                msg.metadata.clone(),
                msg.payload.clone(),
            ) {
                Ok(true) => {
                    //Store fingerprint and shard
                    store.insert_shard(root.to_vec(), msg.sender_id, msg.payload.clone());
                    store.insert_fingerprint(
                        msg.metadata[0..32].to_vec(),
                        msg.sender_id,
                        proof_bytes.to_vec(),
                    );
                    //Increment ready count
                    store.increment_ready(root);
                    // Mark this sender as having sent an READY.
                    store.set_ready_sent(msg.sender_id);

                    let echo_count = store.get_echo_count(root);
                    let ready_count = store.get_ready_count(root);
                    //compact way to compute ceil((n + t + 1) / 2) using integer arithmetic
                    let threshold = u32::max((self.n + self.t + 2) / 2, self.k);

                    // READY broadcast logic
                    if echo_count < threshold && ready_count == self.k {
                        //Send ready logic
                        let shards_map = store.get_shards_for_root(&root.to_vec());
                        self.send_ready(msg.clone(), shards_map, net).await;
                    }

                    // Final consensus stage: enough READY messages to reconstruct
                    if ready_count == (self.k + self.t) {
                        let shards_result = decode_rs(
                            store.get_shards_for_root(&root.to_vec()),
                            self.k as usize,
                            (self.n - self.k) as usize,
                        );
                        let shards = match shards_result {
                            // Handle potential error from decoding
                            Ok(shards) => shards,
                            Err(e) => {
                                error!(
                                    id = self.id,
                                    session_id = msg.session_id,
                                    error = %e,
                                    "Error while decoding shards at ready handler"
                                );
                                return;
                            }
                        };
                        //Reconstruct the original message to be broadcasted
                        let output_result =
                            reconstruct_payload(shards, msg.msg_len, self.k as usize);
                        let output = match output_result {
                            // Handle potential error from reconstructing
                            Ok(output) => output,
                            Err(e) => {
                                error!(
                                    id = self.id,
                                    session_id = msg.session_id,
                                    error = %e,
                                    "Error while reconstructing payload "
                                );
                                return;
                            }
                        };

                        store.mark_ended(); //Terminate broadcast
                        store.set_output(output.clone()); //store the output

                        info!(
                            id = self.id,
                            session_id = msg.session_id,
                            output = ?output,
                            "Consensus achieved; AVID instance ended"
                        );
                    }
                }
                Ok(false) => {
                    warn!(
                        id = self.id,
                        session_id = msg.session_id,
                        sender = msg.sender_id,
                        "Merkle verification failed in READY handler"
                    );
                    return;
                }
                Err(e) => {
                    warn!(
                        id = self.id,
                        session_id = msg.session_id,
                        sender = msg.sender_id,
                        error = %e,
                        "Error during Merkle verification in READY handler"
                    );
                    return;
                }
            }
        }
    }
    //This the logic for sending a READY message in both the echo and ready handler
    async fn send_ready(&self, msg: Msg, shards_map: HashMap<u32, Vec<u8>>, net: Arc<Network>) {
        let root = &msg.metadata[0..32];
        let handler_type = msg.msg_type;
        // Reconstruct all shards from existing shards
        let shards_result = decode_rs(shards_map, self.k as usize, (self.n - self.k) as usize);
        let shards = match shards_result {
            // Handle potential error from decoding
            Ok(shards) => shards,
            Err(e) => {
                error!(
                    id = self.id,
                    session_id = msg.session_id,
                    error = %e,
                    "Error while decoding shards at {handler_type} handler"
                );
                return;
            }
        };
        //Setting up payload and fingerprint for creating a message later
        let payload = shards[self.id as usize].clone();
        let mut fingerprint = root.to_vec();

        // When a server reconstructs a shard, it also reconstructs the corresponding
        // hashes on the path from j to the root, and uses them for later verification
        match generate_merkle_proofs_map(shards.clone(), self.n as usize) {
            Ok(proof_map) => {
                // Get fingerprint for self, for creating message later
                let self_proof = proof_map
                    .get(&(self.id as usize))
                    .cloned()
                    .unwrap_or_else(|| {
                        tracing::warn!(index = self.id, "Missing Merkle proof");
                        Vec::new()
                    });
                fingerprint.extend(self_proof);

                // Verify each proof per shard reconstructed
                for (id, proof) in proof_map {
                    let mut fp = root.to_vec();
                    fp.extend(proof);

                    match verify_merkle(id as u32, self.n, fp, shards[id as usize].clone()) {
                        Ok(true) => {}
                        Ok(false) => {
                            error!(
                                id = self.id,
                                session_id = msg.session_id,
                                "Merkle proof generation failed in {handler_type} handler. Aborting."
                            );
                            return;
                        }
                        Err(e) => {
                            error!(
                                id = self.id,
                                session_id = msg.session_id,
                                error = %e,
                                "Error during Merkle verification in {handler_type} handler"
                            );
                            return;
                        }
                    }
                }
            }
            Err(e) => {
                error!(
                    id = self.id,
                    session_id = msg.session_id,
                    error = %e,
                    "Failed to generate Merkle proof map in {handler_type} handler"
                );
                return;
            }
        }

        // Create ready message
        let ready_msg = Msg::new(
            self.id,
            msg.session_id,
            payload,
            fingerprint,
            GenericMsgType::Avid(MsgTypeAvid::Ready),
            msg.msg_len,
        );
        info!(
            id = self.id,
            session_id = msg.session_id,
            msg_type = "READY",
            "Broadcasting READY in response to a {handler_type}"
        );

        // Send message
        Avid::broadcast(self, ready_msg, net).await;
    }
    async fn get_or_create_store(&self, session_id: u32) -> Arc<Mutex<AvidStore>> {
        let mut store = self.store.lock().await;
        // Get or create the session state for the current session.
        store
            .entry(session_id)
            .or_insert_with(|| Arc::new(Mutex::new(AvidStore::default())))
            .clone()
    }
}

/// Common subset is a sub-protocol used to agree on the termination of rbcs
/// Common subset based on https://eprint.iacr.org/2016/199.pdf works in the following steps :
/// 1. RBCs of proposed values
/// 2. Asynchronous Binary agreement(ABA) protocol to agree on the RBCs
pub struct ABA {
    pub id: u32,                                               // The ID of the initiator
    pub n: u32, // Total number of parties in the network
    pub t: u32, // Number of allowed malicious parties
    pub k: u32, //threshold
    pub store: Arc<Mutex<HashMap<u32, Arc<Mutex<AbaStore>>>>>, // Stores the session state for each session
}
#[async_trait]
impl RBC for ABA {
    /// Creates a new ABA instance with the given parameters.
    fn new(id: u32, n: u32, t: u32, k: u32) -> Result<Self, String> {
        if !(t < (n + 2) / 3) {
            // ceil(n / 3)
            return Err(format!(
                "Invalid t: must satisfy 0 <= t < n / 3 (t={}, n={})",
                t, n
            ));
        }
        Ok(ABA {
            id,
            n,
            t,
            k,
            store: Arc::new(Mutex::new(HashMap::new())),
        })
    }
    /// This is the initial broadcast message in the ABA protocol.
    async fn init(&self, payload: Vec<u8>, session_id: u32, net: Arc<Network>) {
        let v_r = match get_value_round(&payload) {
            Some(r) => r,
            None => {
                error!(
                    id = self.id,
                    session_id = session_id,
                    "Error while getting roundid at init"
                );
                return;
            }
        };
        // Create an est message with the given value and round id for a specific session ID.
        let msg = Msg::new(
            self.id,
            session_id,
            vec![v_r.0 as u8],            // [value]
            v_r.1.to_le_bytes().to_vec(), //[round ID]
            GenericMsgType::ABA(MsgTypeAba::Est),
            payload.len(),
        );
        info!(
            id = self.id,
            session_id,
            msg_type = "EST",
            "Broadcasting EST message"
        );
        ABA::broadcast(&self, msg, net).await;
    }
    /// Processes incoming messages based on their type.
    async fn process(&self, msg: Msg, net: Arc<Network>) {
        match &msg.msg_type {
            GenericMsgType::ABA(msg_type) => match msg_type {
                MsgTypeAba::Est => self.est_handler(msg, net).await,
                MsgTypeAba::Aux => self.aux_handler(msg, net).await,
                MsgTypeAba::Unknown(t) => {
                    warn!("Aba: Unknown message type: {}", t);
                }
            },
            _ => {
                warn!("process: received non-ABA message");
            }
        }
    }
    /// Broadcasts a message to all parties in the network.
    async fn broadcast(&self, msg: Msg, net: Arc<Network>) {
        for sender in &net.senders {
            let _ = sender.send(msg.clone()).await;
        }
    }
    /// Send a message to a party in the network.
    async fn send(&self, msg: Msg, net: Arc<Network>, recv: u32) {
        let _ = net.senders[recv as usize].send(msg).await;
    }
    /// Runs the party logic, continuously receiving and processing messages.
    async fn run_party(&self, receiver: &mut Receiver<Msg>, net: Arc<Network>) {
        while let Some(msg) = receiver.recv().await {
            self.process(msg, net.clone()).await;
        }
    }
}
impl ABA {
    ///Handlers
    /// Handles the estimate value, Responds by broadcasting an aux message if necessary.
    pub async fn est_handler(&self, msg: Msg, net: Arc<Network>) {
        info!(
            id = self.id,
            session_id = msg.session_id,
            sender = msg.sender_id,
            msg_type = %msg.msg_type,
            "Handling EST for round message"
        );

        // Lock the session store to update the session state.
        let session_store = self.get_or_create_store(msg.session_id).await;
        // Lock the session-specific store to access or update the session state.
        let mut store = session_store.lock().await;

        // Ignore the message if the session has already ended.
        if store.ended {
            debug!(
                id = self.id,
                session_id = msg.session_id,
                "Session already ended, ignoring est"
            );
            return;
        }

        let round = match get_round(&msg.metadata) {
            Some(r) => r,
            None => {
                error!(
                    id = self.id,
                    session_id = msg.session_id,
                    "Error while getting roundid at est handler"
                );
                return;
            }
        };
        let value = match get_value(&msg.payload) {
            Some(v) => v,
            None => {
                error!(
                    id = self.id,
                    session_id = msg.session_id,
                    "Error while getting value at est handler"
                );
                return;
            }
        };
        if !store.has_sent_est(round, msg.sender_id) {
            store.set_est_sent(round, msg.sender_id);
            store.increment_est(round, value);
            let count = store.get_est_count(round)[value as usize];
            if count >= self.t + 1 && !store.get_est(round) {
                store.mark_est(round, value);
                let new_msg = Msg::new(
                    self.id,
                    msg.session_id,
                    msg.payload.clone(),
                    msg.metadata.clone(),
                    GenericMsgType::ABA(MsgTypeAba::Est),
                    msg.msg_len,
                );
                ABA::broadcast(&self, new_msg, net.clone()).await;
            }
            if count == 2 * self.t + 1 {
                store.insert_bin_value(round, value);
                let new_msg = Msg::new(
                    self.id,
                    msg.session_id,
                    msg.payload,
                    msg.metadata,
                    GenericMsgType::ABA(MsgTypeAba::Aux),
                    msg.msg_len,
                );
                ABA::broadcast(&self, new_msg, net).await;
            }
        }
    }
    /// Handles the aux value and sends a new est message or terminates.
    pub async fn aux_handler(&self, msg: Msg, net: Arc<Network>) {
        info!(
            id = self.id,
            session_id = msg.session_id,
            sender = msg.sender_id,
            msg_type = %msg.msg_type,
            "Handling AUX for round message"
        );

        // Lock the session store to update the session state.
        let session_store = self.get_or_create_store(msg.session_id).await;
        // Lock the session-specific store to access or update the session state.
        let mut store = session_store.lock().await;

        let round = match get_round(&msg.metadata) {
            Some(r) => r,
            None => {
                error!(
                    id = self.id,
                    session_id = msg.session_id,
                    "Error while getting roundid at est handler"
                );
                return;
            }
        };
        let value = match get_value(&msg.payload) {
            Some(v) => v,
            None => {
                error!(
                    id = self.id,
                    session_id = msg.session_id,
                    "Error while getting value at est handler"
                );
                return;
            }
        };
        // Ignore the message if the session has already ended.
        if store.ended {
            debug!(
                id = self.id,
                session_id = msg.session_id,
                "Session already ended, ignoring aux"
            );
            return;
        }

        if !store.has_sent_aux(round, msg.sender_id) {
            store.set_aux_sent(round, msg.sender_id);
            store.increment_aux(round);
            store.insert_values(round, value);
            let count = store.get_aux_count(round);
            if count == self.n - self.t {
                let s = {
                    true /*Common coin to be implemented*/
                };
                if store.get_values_len(round) == 1 {
                    if value == s {
                        // If agreement is reached, mark the session as ended and store the output.
                        store.mark_ended();
                        store.set_output(value);
                        info!(
                            id = self.id,
                            session_id = msg.session_id,
                            output = ?msg.payload,
                            "Binary agreement achieved; ABA instance ended"
                        );
                    } else {
                        self.send_est_for_next_round(&msg, round + 1, value, net)
                            .await;
                    }
                } else {
                    self.send_est_for_next_round(&msg, round + 1, s, net).await;
                }
            }
        }
    }
    async fn get_or_create_store(&self, session_id: u32) -> Arc<Mutex<AbaStore>> {
        let mut store = self.store.lock().await;
        // Get or create the session state for the current session.
        store
            .entry(session_id)
            .or_insert_with(|| Arc::new(Mutex::new(AbaStore::default())))
            .clone()
    }
    async fn send_est_for_next_round(&self, msg: &Msg, round: u32, value: bool, net: Arc<Network>) {
        let payload = vec![value as u8];
        let metadata = round.to_le_bytes().to_vec();
        let msg = Msg::new(
            msg.sender_id,
            msg.session_id,
            payload,
            metadata,
            GenericMsgType::ABA(MsgTypeAba::Est),
            msg.msg_len,
        );
        ABA::broadcast(self, msg, net).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bracha_avid_valid_params() {
        // Test for Bracha
        let bracha = Bracha::new(0, 4, 1, 2);
        assert!(
            bracha.is_ok(),
            "Expected valid parameters for Bracha to succeed"
        );

        // Test for Avid
        let avid = Avid::new(0, 6, 1, 2);
        assert!(
            avid.is_ok(),
            "Expected valid parameters for Avid to succeed"
        );

        let avid = Avid::new(1, 9, 2, 4);
        assert!(
            avid.is_ok(),
            "Expected valid parameters for Avid to succeed"
        );
    }

    #[test]
    fn test_bracha_avid_invalid_t() {
        // Test for Bracha
        let bracha = Bracha::new(0, 4, 2, 2); // Invalid t
        assert!(bracha.is_err(), "Expected invalid t to fail for Bracha");
        if let Err(msg) = bracha {
            assert!(
                msg.contains("t"),
                "Expected error message to mention t for Bracha"
            );
        }

        // Test for Avid
        let avid = Avid::new(0, 6, 2, 2); // Invalid t (t >= ceil(n / 3))
        assert!(avid.is_err(), "Expected invalid t to fail for Avid");
        if let Err(msg) = avid {
            assert!(
                msg.contains("t"),
                "Expected error message to mention t for Avid"
            );
        }

        let avid = Avid::new(1, 9, 4, 4); // Invalid t (t >= ceil(n / 3))
        assert!(avid.is_err(), "Expected invalid t to fail for Avid");
    }

    #[test]
    fn test_bracha_avid_invalid_k() {
        // Test for Avid with invalid k
        let avid = Avid::new(0, 6, 1, 0); // Invalid k (k < t + 1)
        assert!(avid.is_err(), "Expected invalid k to fail for Avid");
        if let Err(msg) = avid {
            assert!(
                msg.contains("k"),
                "Expected error message to mention k for Avid"
            );
        }

        let avid = Avid::new(1, 9, 2, 7); // Invalid k (k > n - 2t)
        assert!(avid.is_err(), "Expected invalid k to fail for Avid");

        // Test for Bracha with valid parameters
        let bracha = Bracha::new(0, 5, 1, 3); // Valid k for Bracha
        assert!(bracha.is_ok(), "Expected valid parameters for Bracha");
    }

    #[test]
    fn test_bracha_avid_edge_cases() {
        // n = 5, t = 1, k = 2: valid case for both Bracha and Avid
        let bracha = Bracha::new(0, 5, 1, 2);
        assert!(bracha.is_ok(), "Expected valid parameters for Bracha");
        let avid = Avid::new(0, 5, 1, 2);
        assert!(avid.is_ok(), "Expected valid parameters for Avid");

        // n = 5, t = 2, k = 2: invalid for Avid as k cannot be n - 2 * t
        let avid_invalid = Avid::new(0, 5, 2, 2);
        assert!(avid_invalid.is_err(), "Expected invalid k to fail for Avid");

        // n = 5, t = 2: invalid as t cannot be >= ceil(n / 3)
        let bracha_invalid = Bracha::new(0, 5, 2, 2);
        assert!(
            bracha_invalid.is_err(),
            "Expected invalid t to fail for Bracha"
        );
    }

    #[test]
    fn test_bracha_avid_zero_t() {
        // t = 0 should always be valid for both Bracha and Avid as long as k >= 1
        let bracha = Bracha::new(2, 3, 0, 1);
        assert!(bracha.is_ok(), "Expected t = 0 to be valid for Bracha");

        let avid = Avid::new(2, 5, 0, 1);
        assert!(avid.is_ok(), "Expected t = 0 to be valid for Avid");

        // n = 3, t = 0, k = 2: valid for both Bracha and Avid
        let bracha = Bracha::new(2, 3, 0, 2);
        assert!(bracha.is_ok(), "Expected valid parameters for Bracha");

        let avid = Avid::new(3, 3, 0, 2);
        assert!(avid.is_ok(), "Expected valid parameters for Avid");
    }
}
