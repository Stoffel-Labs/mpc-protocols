/// This file contains more common reliable broadcast protocols used in MPC.
/// You can reuse them in your own custom MPC protocol implementations.
use super::rbc_store::*;
use super::utils::*;
use crate::RBC;
use async_trait::async_trait;
use bincode;
use std::{collections::HashMap, sync::Arc};
use threshold_crypto::{
    serde_impl::SerdeSecret, PublicKeySet, SecretKeySet, SecretKeyShare, SignatureShare,
};
use tokio::{
    sync::{
        mpsc::{Receiver, Sender},
        Mutex, Notify, OnceCell,
    },
    time::Duration,
};
use tracing::{debug, error, info, warn};

//Mock a network for testing purposes
#[derive(Clone)]
pub struct Network {
    pub id: u32,                   // The identifier of the current party in the network
    pub senders: Vec<Sender<Msg>>, // List of all senders, including the current party itself
}

///--------------------------Bracha RBC--------------------------
///
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
    pub store: Arc<Mutex<HashMap<u32, Arc<Mutex<BrachaStore>>>>>, // Stores the session state
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
            0,
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
    // Handlers
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
                msg.round_id,
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
            drop(store);
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
                        msg.round_id,
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
                        msg.round_id,
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
                        msg.round_id,
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
                        msg.round_id,
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
    pub store: Arc<Mutex<HashMap<u32, Arc<Mutex<AvidStore>>>>>, // Sessionid => store
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
                0,
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
    // Handlers

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
                        msg.round_id,
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
                    drop(store);
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
                        drop(store);
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
            msg.round_id,
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

///------------------------------ABA------------------------------
///
/// Algorithm: Binary Agreement (BA) for party P_i :
///
/// Upon receiving input `b_input`, set `est_0 := b_input` and enter the epoch loop.
/// Loop: for increasing round labels `r`:
/// 1. Multicast `BVAL_r(est_r)`
///
/// 2. Initialize: `bin_values_r := ∅`
///
/// 3. Upon receiving `BVAL_r(b)` messages from `f + 1` distinct nodes:
///    - If `BVAL_r(b)` has not yet been sent, multicast `BVAL_r(b)`
///
/// 4. Upon receiving `BVAL_r(b)` messages from `2f + 1` distinct nodes:
///    - Add `b` to `bin_values_r`: `bin_values_r := bin_values_r ∪ {b}`
///
/// 5. Wait until `bin_values_r ≠ ∅`, then:
///    - Multicast `AUX_r(w)`, where `w ∈ bin_values_r`
///
/// 6. Wait until at least `(N - f)` `AUX_r` messages are received
///    - Let `vals` be the set of values contained in these `AUX_r` messages
///    - Condition: `vals ⊆ bin_values_r`
///      (Note: `bin_values_r` may still be changing)
///      This condition can be satisfied after receiving either `AUX_r` or `BVAL_r` messages
///
/// 7. Sample common coin for round `r`: `s ← Coin_r.GetCoin()`
///
/// 8. Decision logic:
///    - If `vals == {b}` (singleton set):
///        * Set `est_{r+1} := b`
///        * If `b == (s % 2)`, then output `b`
///    - Else (i.e., `vals` contain

#[derive(Clone)]
pub struct ABA {
    pub id: u32,                                               // The ID of the initiator
    pub n: u32,                          // Total number of parties in the network
    pub t: u32,                          // Number of allowed malicious parties
    pub k: u32,                          //threshold
    pub skshare: Arc<OnceCell<Vec<u8>>>, //Secret key share
    pub pkset: Arc<OnceCell<Vec<u8>>>,   //Public key set
    pub store: Arc<Mutex<HashMap<u32, Arc<Mutex<AbaStore>>>>>, // Stores the ABA session state
    pub coin: Arc<Mutex<HashMap<u32, Arc<Mutex<CoinStore>>>>>, // Stores the common coin session state
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
            skshare: Arc::new(OnceCell::new()),
            pkset: Arc::new(OnceCell::new()),
            store: Arc::new(Mutex::new(HashMap::new())),
            coin: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// This initiates the ABA protocol.
    async fn init(&self, payload: Vec<u8>, session_id: u32, net: Arc<Network>) {
        info!(
            id = self.id,
            session_id,
            msg_type = "EST",
            "Broadcasting EST message"
        );
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
            v_r.1,             //[round ID]
            vec![v_r.0 as u8], // [value]
            vec![],
            GenericMsgType::ABA(MsgTypeAba::Est),
            payload.len(),
        );

        // Lock the session store to update the session state.
        let session_store = self.get_or_create_store(msg.session_id).await;
        // Lock the session-specific store to access or update the session state.
        let mut store = session_store.lock().await;
        //Mark as having sent est value for round id
        store.mark_est(msg.round_id, v_r.0);
        drop(store);
        ABA::broadcast(&self, msg, net).await;
    }

    /// Processes incoming messages based on their type.
    async fn process(&self, msg: Msg, net: Arc<Network>) {
        match &msg.msg_type {
            GenericMsgType::ABA(msg_type) => match msg_type {
                MsgTypeAba::Est => self.est_handler(msg, net).await,
                MsgTypeAba::Aux => self.aux_handler(msg, net).await,
                MsgTypeAba::Key => self.key_handler(msg),
                MsgTypeAba::Coin => self.coin_handler(msg).await,
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
    //Handlers

    /// Handles the estimate value, Responds by broadcasting an aux message if necessary.
    pub async fn est_handler(&self, msg: Msg, net: Arc<Network>) {
        info!(
            session_id = msg.session_id,
            id = self.id,
            sender = msg.sender_id,
            msg_type = %msg.msg_type,
            "Handling EST message for round {}",msg.round_id,
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

        //Get est value
        let value = match get_value(&msg.payload) {
            Some(v) => v,
            None => {
                warn!(
                    id = self.id,
                    session_id = msg.session_id,
                    "Error while getting value at est handler"
                );
                return;
            }
        };
        //Check if sender sent before
        if !store.has_sent_est(msg.round_id, msg.sender_id, value) {
            store.set_est_sent(msg.round_id, msg.sender_id, value); //Mark sender against est value
            store.increment_est(msg.round_id, value); // count est value
            let count = store.get_est_count(msg.round_id)[value as usize]; // get the est count

            //protocol logic for sending est value
            if count >= self.t + 1 && !store.get_est(msg.round_id, value) {
                store.mark_est(msg.round_id, value); // Mark as having sent est value
                let new_msg = Msg::new(
                    self.id,
                    msg.session_id,
                    msg.round_id,
                    msg.payload.clone(),
                    msg.metadata.clone(),
                    GenericMsgType::ABA(MsgTypeAba::Est),
                    msg.msg_len,
                );
                ABA::broadcast(&self, new_msg, net.clone()).await;
            }

            //protocol logic for sending aux value
            if count >= 2 * self.t + 1 {
                store.insert_bin_value(msg.round_id, value);
                if !store.get_aux(msg.round_id, value) {
                    store.mark_aux(msg.round_id, value); // Mark as having sent aux value
                    let new_msg = Msg::new(
                        self.id,
                        msg.session_id,
                        msg.round_id,
                        msg.payload,
                        msg.metadata,
                        GenericMsgType::ABA(MsgTypeAba::Aux),
                        msg.msg_len,
                    );
                    drop(store);
                    ABA::broadcast(&self, new_msg, net).await;
                }
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
            "Handling AUX message for round {}",msg.round_id
        );

        // Lock the session store to update the session state.
        let session_store = self.get_or_create_store(msg.session_id).await;
        // Lock the session-specific store to access or update the session state.
        let mut store = session_store.lock().await;

        //Get aux value
        let value = match get_value(&msg.payload) {
            Some(v) => v,
            None => {
                warn!(
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
        let bin_val = store.get_bin_values(msg.round_id);

        if !bin_val.contains(&value) {
            // Don't accept AUX messages for values not in bin_values
            return;
        }

        //Check if sender sent before
        if !store.has_sent_aux(msg.round_id, msg.sender_id, value) {
            store.set_aux_sent(msg.round_id, msg.sender_id, value); // Mark sender for sending aux value
            store.insert_values(msg.round_id, msg.sender_id, value); //Store aux value against sender

            //Get aux message sender count
            let count = store.get_sender_count(msg.round_id) as u32;
            //Get bin_value set
            let bin_val = store.get_bin_values(msg.round_id);
            //Get values set
            let values = store.get_all_values(msg.round_id);
            drop(store);
            //protocol logic for starting next or termination
            if count >= self.n - self.t && values.is_subset(&bin_val) {
                // Call coin generation, return if already started
                {
                    let coin_store = self.get_or_create_coinstore(msg.session_id).await;
                    let mut store = coin_store.lock().await;
                    if store.get_start(msg.round_id) {
                        return;
                    }
                    store.set_start(msg.round_id);
                }

                self.init_coin(msg.clone(), net.clone()).await;
                //Set up to wait for coin to be ready
                let cloned_msg = msg.clone();
                let cloned_net = net.clone();
                let cloned_self = self.clone();

                tokio::spawn(async move {
                    let coin_opt = cloned_self
                        .wait_for_coin(cloned_msg.session_id, cloned_msg.round_id, 500)
                        .await;

                    let coin_value = match coin_opt {
                        Some(coin) => coin,
                        None => {
                            error!(
                                id = cloned_self.id,
                                session_id = cloned_msg.session_id,
                                round = cloned_msg.round_id,
                                "Failed to get coin value in time"
                            );
                            return;
                        }
                    };
                    // Lock the session store to update the session state.
                    let session_store =
                        cloned_self.get_or_create_store(cloned_msg.session_id).await;
                    // Lock the session-specific store to access or update the session state.
                    let mut store = session_store.lock().await;

                    if store.ended {
                        debug!(
                            id = cloned_self.id,
                            session_id = cloned_msg.session_id,
                            "Session already ended, ignoring coin result"
                        );
                        return;
                    }
                    //If |values| = 1, pi decides v (the single value present in values) if additionally s = v
                    if values.len() == 1 {
                        let v = match values.iter().next().copied() {
                            Some(v) => v,
                            None => {
                                error!(
                                    id = cloned_self.id,
                                    session_id = cloned_msg.session_id,
                                    round = cloned_msg.round_id,
                                    "Could not get the value from values set"
                                );
                                return;
                            }
                        };
                        if v == coin_value {
                            store.mark_ended();
                            store.set_output(v);
                            info!(
                                id = cloned_self.id,
                                session_id = cloned_msg.session_id,
                                output = ?cloned_msg.payload,
                                "Binary agreement achieved; ABA instance ended at round {}",msg.round_id
                            );
                        } else {
                            //adopts v as its new estimate
                            info!(
                                id = cloned_self.id,
                                session_id = cloned_msg.session_id,
                                "Entering round {} with value",
                                msg.round_id
                            );
                            cloned_self
                                .send_est_for_next_round(
                                    &cloned_msg,
                                    cloned_msg.round_id + 1,
                                    v,
                                    cloned_net,
                                )
                                .await;
                        }
                    } else {
                        //If |values| = 2, both the value 0 and the value 1 are estimate values of correct processes.
                        //In this cases, pi adopts the value s of the common coin
                        info!(
                            id = cloned_self.id,
                            session_id = cloned_msg.session_id,
                            "Entering round {} with coin",
                            msg.round_id + 1
                        );
                        cloned_self
                            .send_est_for_next_round(
                                &cloned_msg,
                                cloned_msg.round_id + 1,
                                coin_value,
                                cloned_net,
                            )
                            .await;
                    }
                });
            }
        }
    }

    //Function to wait and get notified when the coin is ready
    async fn wait_for_coin(&self, session_id: u32, round_id: u32, timeout_ms: u64) -> Option<bool> {
        let coin_store = self.get_or_create_coinstore(session_id).await;

        let notify = {
            let mut store = coin_store.lock().await;

            //Check if coin is ready
            if let Some(coin) = store.coin(round_id) {
                return Some(coin);
            }

            // Create and store Notify
            let entry = store
                .notifiers
                .entry(round_id)
                .or_insert_with(|| Arc::new(Notify::new()));
            Arc::clone(entry)
        };

        // Wait for notification or timeout
        let timeout = Duration::from_millis(timeout_ms);
        tokio::select! {
            _ = notify.notified() => {
                let store = coin_store.lock().await;
                store.coins.get(&round_id).copied()
            }
            _ = tokio::time::sleep(timeout) => {
                warn!(
                    "Timed out waiting for coin for session {} round {}",
                    session_id, round_id
                );
                None
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

    async fn get_or_create_coinstore(&self, session_id: u32) -> Arc<Mutex<CoinStore>> {
        let mut store = self.coin.lock().await;
        // Get or create the session state for the current session.
        store
            .entry(session_id)
            .or_insert_with(|| Arc::new(Mutex::new(CoinStore::default())))
            .clone()
    }

    //Create and broadcast est message for the next round
    async fn send_est_for_next_round(&self, msg: &Msg, round: u32, value: bool, net: Arc<Network>) {
        let msg = Msg::new(
            self.id,
            msg.session_id,
            round,
            vec![value as u8],
            msg.metadata.clone(),
            GenericMsgType::ABA(MsgTypeAba::Est),
            msg.msg_len,
        );
        ABA::broadcast(self, msg, net).await;
    }

    //Store secret key shares and public keyshare set
    fn key_handler(&self, msg: Msg) {
        info!(
            id = self.id,
            session_id = msg.session_id,
            sender = msg.sender_id,
            msg_type = %msg.msg_type,
            "Handling Key setup message"
        );

        let _ = self.skshare.set(msg.payload);
        let _ = self.pkset.set(msg.metadata);
    }

    //Initialise the common coin
    pub async fn init_coin(&self, msg: Msg, net: Arc<Network>) {
        info!(
            id = self.id,
            session_id = msg.session_id,
            sender = msg.sender_id,
            msg_type = %msg.msg_type,
            round = msg.round_id,
            "Initialising common coin"
        );

        let sk_payload = match self.skshare.get() {
            Some(sk) => sk,
            None => {
                error!(
                    id = self.id,
                    session_id = msg.session_id,
                    "Error while getting secret key share"
                );
                return;
            }
        };
        // Deserialize the secret key share
        //Might be unsafe : We are exposing the secret key share
        //To do : Replace with a more controllablle crate
        let skshare: SerdeSecret<SecretKeyShare> = match bincode::deserialize(&sk_payload) {
            Ok(sks) => sks,
            Err(err) => {
                error!(
                    id = self.id,
                    session_id = msg.session_id,
                    "Failed to deserialize secret key share: {:?}",
                    err
                );
                return;
            }
        };

        //Sign the session id with the secret key share and broadcast to others
        let signshare = skshare.sign(msg.round_id.to_be_bytes());
        let new_msg = Msg::new(
            self.id,
            msg.session_id,
            msg.round_id,
            signshare.to_bytes().to_vec(),
            vec![],
            GenericMsgType::ABA(MsgTypeAba::Coin),
            msg.msg_len,
        );
        info!(
            session_id = msg.session_id,
            id = self.id,
            sender = msg.sender_id,
            msg_type = %msg.msg_type,
            "Broadcasting signature shares"
        );
        ABA::broadcast(&self, new_msg, net).await;
    }

    //Collect the signature share and generate the common coin
    async fn coin_handler(&self, msg: Msg) {
        info!(
            session_id = msg.session_id,
            id = self.id,
            sender = msg.sender_id,
            msg_type = %msg.msg_type,
            "At coin handler"
        );

        // Lock the session store to update the session state.
        let coin_store = self.get_or_create_coinstore(msg.session_id).await;
        // Lock the session-specific store to access or update the session state.
        let mut store = coin_store.lock().await;

        //Check if the sender has sent a signature share before
        if !store.has_sent_sign(msg.round_id, msg.sender_id) {
            // --- Deserialize incoming signature share ---
            let sigshare_bytes: &[u8; 96] = match msg.payload.as_slice().try_into() {
                Ok(bytes) => bytes,
                Err(_) => {
                    warn!("Invalid signature share size from {}", msg.sender_id);
                    return;
                }
            };

            let sigshare = match SignatureShare::from_bytes(sigshare_bytes) {
                Ok(share) => share,
                Err(_) => {
                    warn!(
                        "Failed to deserialize signature share from {}",
                        msg.sender_id
                    );
                    return;
                }
            };

            //Get the public key share set
            let pkset_bytes = match self.pkset.get() {
                Some(pk) => pk,
                None => {
                    error!(
                        id = self.id,
                        session_id = msg.session_id,
                        "Error while getting pk key set"
                    );
                    return;
                }
            };

            let pkset: PublicKeySet = match bincode::deserialize(&pkset_bytes) {
                Ok(pk) => pk,
                Err(_) => {
                    warn!("Failed to deserialize PublicKeySet");
                    return;
                }
            };

            //Verfiy the signature share
            if !pkset
                .public_key_share(msg.sender_id as i32)
                .verify(&sigshare, msg.round_id.to_be_bytes())
            {
                warn!("Invalid signature share from {}", msg.sender_id);
                return;
            }

            //Mark the sender
            store.set_sign_sent(msg.round_id, msg.sender_id);
            store.insert_share(msg.round_id, msg.sender_id, msg.payload); //Store signature share
            store.increment_sign(msg.round_id); //Increment share count
            let count = store.get_sign_count(msg.round_id); //Get share count

            //Collect enough share to get the Signature
            if count == self.t + 1 {
                let shares = store.get_shares_map(msg.round_id);
                if let Some(shares_map) = shares {
                    let sig_shares: Vec<(usize, SignatureShare)> = shares_map
                        .iter()
                        .filter_map(|(&sender_id, bytes)| {
                            let array: &[u8; 96] = bytes.as_slice().try_into().ok()?;
                            SignatureShare::from_bytes(array)
                                .ok()
                                .map(|s| (sender_id as usize, s))
                        })
                        .collect();

                    match pkset.combine_signatures(sig_shares.iter().map(|(i, s)| (*i, s))) {
                        Ok(signature) => {
                            if pkset
                                .public_key()
                                .verify(&signature, msg.round_id.to_be_bytes())
                            {
                                // Convert the final signature to a coin value (e.g., bool)
                                let coin_bit = signature.to_bytes()[0] & 1 == 1;

                                store.set_coin(msg.round_id, coin_bit);
                                info!(
                                    session_id = msg.session_id,
                                    id = self.id,
                                    "Successfully combined and verified signature for round {}",
                                    msg.round_id,
                                );
                            } else {
                                warn!("Combined signature failed verification");
                            }
                        }
                        Err(err) => {
                            error!("Failed to combine signature shares: {:?}", err);
                        }
                    }
                }
            }
        }
    }
}

/// Mock trusted dealer for testing.
/// Might replace with a DKG.
///To do: Replace threshold signature crate with a more reliable option or build from scratch
pub struct Dealer {
    n: u32,
    t: u32,
}
impl Dealer {
    pub fn new(n: u32, t: u32) -> Self {
        Dealer { n, t }
    }

    /// Perform key generation and send shares to all parties
    pub async fn distribute_keys(&self, msg: Msg, net: Arc<Network>) {
        let mut rng = rand::thread_rng();
        let skset = SecretKeySet::random(self.t as usize, &mut rng);
        let pkset = skset.public_keys();

        let pkset_serial = bincode::serialize(&pkset).expect("Failed to serialize pkset");

        for i in 0..self.n {
            let skshare = SerdeSecret(skset.secret_key_share(i as i32));
            let serialized_share = bincode::serialize(&skshare).expect("Failed to serialize share");

            let key_msg = Msg::new(
                msg.sender_id,
                msg.session_id,
                msg.round_id,
                serialized_share,
                pkset_serial.clone(),
                msg.msg_type.clone(),
                msg.msg_len,
            );

            let _ = net.senders[i as usize].send(key_msg).await;
        }
    }
}

/// ------------------------------ASYNCHRONOUS COMMON SUBSET------------------------------
///
/// Common subset is a sub-protocol used to agree on the termination of RBCs
/// Common subset based on https://eprint.iacr.org/2016/199.pdf works in the following steps :
/// 1. n RBCs of proposed values
/// 2. Run n Asynchronous Binary agreement(ABA) protocol per RBC to decide whether that RBC should be part of
/// the common subset
#[derive(Clone)]
pub struct ACS {
    pub id: u32,                     // The ID of the initiator
    pub n: u32,                      // Total number of parties in the network
    pub t: u32,                      // Number of allowed malicious parties
    pub k: u32,                      // threshold
    pub store: Arc<Mutex<AcsStore>>, // Stores the ACS session state
    pub aba: ABA,                    //ABA instance for the common subset
}

impl ACS {
    /// Creates a new ACS instance with the given parameters.
    pub fn new(id: u32, n: u32, t: u32, k: u32) -> Result<Self, String> {
        if !(t < (n + 2) / 3) {
            // ceil(n / 3)
            return Err(format!(
                "Invalid t: must satisfy 0 <= t < n / 3 (t={}, n={})",
                t, n
            ));
        }
        let aba = ABA::new(id, n, t, k)?;
        Ok(ACS {
            id,
            n,
            t,
            k,
            store: Arc::new(Mutex::new(AcsStore::default())),
            aba: aba,
        })
    }

    ///Initialies the ABA protocol, called when an RBC terminates
    pub async fn init(&self, msg: Msg, net: Arc<Network>) {
        info!(
            id = self.id,
            session_id = msg.session_id,
            sender = msg.sender_id,
            msg_type = %msg.msg_type,
            "Initiating common subset"
        );

        let mut store = self.store.lock().await;

        if !store.has_aba_input(msg.session_id) {
            store.set_aba_input(msg.session_id, true);
            store.set_rbc_output(msg.session_id, msg.payload);

            //Initiate aba for session id
            let payload = set_value_round(true, 0);
            self.aba.init(payload, msg.session_id, net.clone()).await;

            // Spawn task to watch for ABA completion
            let aba_store = self.aba.get_or_create_store(msg.session_id).await;
            let aba_store_clone = aba_store.clone();
            let self_clone = self.clone();
            let net_clone = net.clone();
            let store_clone = self.store.clone();
            drop(store);
            tokio::spawn(async move {
                let notify = {
                    let aba = aba_store_clone.lock().await;
                    aba.notify.clone()
                };

                notify.notified().await;

                let output: bool = {
                    let aba = aba_store_clone.lock().await;
                    aba.output
                };

                // Store ABA output
                let mut store = store_clone.lock().await;
                store.set_aba_output(msg.session_id, output);

                // Check if enough parties agreed with output 1
                let true_count = store.get_aba_output_one_count();
                if true_count >= self_clone.n - self_clone.t {
                    // For any party that hasn't provided input yet, provide input 0
                    //We assume the session ID is of some form (broadcasterID||... ),
                    //for now we can assume session ID is just the broadcasters ID
                    let uninitiated = (0..self_clone.n)
                        .filter(|sid| !store.has_aba_input(*sid))
                        .collect::<Vec<_>>();
                    if uninitiated.len() == 0 {
                        let store_clone2 = store_clone.clone();
                        let self_clone2 = self_clone.clone();
                        tokio::spawn(async move {
                            self_clone2.check_and_finalize_output(store_clone2).await;
                        });
                        return;
                    } else {
                        for sid in uninitiated {
                            let payload = set_value_round(false, 0);
                            self_clone.aba.init(payload, sid, net_clone.clone()).await;
                            store.set_aba_input(sid, false);

                            // Spawn task for ABA completion of each uninitiated session
                            let aba_store = self_clone.aba.get_or_create_store(sid).await;
                            let aba_store_clone = aba_store.clone();
                            let self_clone2 = self_clone.clone();
                            let store_clone2 = store_clone.clone();

                            tokio::spawn(async move {
                                let notify = {
                                    let aba = aba_store_clone.lock().await;
                                    aba.notify.clone()
                                };

                                notify.notified().await;

                                let output = {
                                    let aba = aba_store_clone.lock().await;
                                    aba.output
                                };

                                {
                                    let mut store = self_clone2.store.lock().await;
                                    store.set_aba_output(sid, output);
                                }

                                self_clone2.check_and_finalize_output(store_clone2).await;
                            });
                        }
                    }
                }
            });
        } else if store.get_rbc_output(msg.session_id).is_none() {
            // RBC finished *after* ABA started
            store.set_rbc_output(msg.session_id, msg.payload);

            // Now try finalizing in case all ABA + RBC outputs are ready
            let store_clone = self.store.clone();
            let self_clone = self.clone();
            drop(store);
            info!(id = self.id, "Collect rbc");
            tokio::spawn(async move {
                self_clone.check_and_finalize_output(store_clone).await;
            });
        }
    }
    async fn check_and_finalize_output(&self, session_store: Arc<Mutex<AcsStore>>) {
        let mut store = session_store.lock().await;
        // If not all ABA instances have outputs, return early
        if store.aba_output.len() < self.n as usize {
            return;
        }

        // Gather indices where ABA output is 1
        let mut consensus_indices: Vec<u32> = store
            .aba_output
            .iter()
            .filter(|(_, &v)| v)
            .map(|(&id, _)| id)
            .collect();

        consensus_indices.sort(); // Sort the indices

        // Wait until RBC output is available for all j in C
        let mut values = Vec::new();
        for &j in &consensus_indices {
            if let Some(value) = store.get_rbc_output(j) {
                values.push(value.clone());
            } else {
                // If even one is missing, wait and try later
                return;
            }
        }

        // Output the union of all values from parties in C
        info!(
            id = self.id,
            "ACS output finalized with {} values from {:?}",
            values.len(),
            consensus_indices
        );

        store.set_acs(values);
        store.mark_ended();
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
