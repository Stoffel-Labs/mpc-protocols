/// This file contains more common reliable broadcast protocols used in MPC.
/// You can reuse them in your own custom MPC protocol implementations.
use super::rbc_store::*;
use crate::RBC;
use std::{
    collections::HashMap,
    sync::Arc
};
use tokio::sync::{Mutex,mpsc::{Receiver, Sender}};
use tracing::{info, debug};

/*
/// CommonSubset is a subroutine used to implement many RBC protocols.
/// It is used to determine which RBC instances have terminated.
trait CommonSubset {}
struct AVID {}
impl RBC for AVID {
    fn new(id: u32, n: u32, t: u32) -> self {}
    async fn process(&mut self, msg: Msg) {}
    async fn broadcast(msg: Msg) {}
}
*/

//Mock a network for testing
#[derive(Clone)]
pub struct Network {
    pub id: u32,
    pub senders: Vec<Sender<Msg>>, // All party senders including self
}

///--------------------------Bracha RBC--------------------------
#[derive(Clone)]
pub struct Bracha {
    pub id: u32,                                      //Initiators ID
    pub n: u32,                                       //Network size
    pub t: u32,                                       //No. of malicious parties
    pub store: Arc<Mutex<HashMap<u32, BrachaStore>>>, // <- wrap only this in a lock //Sessionid => store
}

impl RBC for Bracha {
    /// Creates a new Bracha instance
    fn new(id: u32, n: u32, t: u32) -> Self {
        Bracha {
            id,
            n,
            t,
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    async fn process(&self, msg: Msg, parties: Arc<Network>) {
        match MsgType::from(msg.msg_type.clone()) {
            MsgType::Init => self.init_handler(msg, parties).await,
            MsgType::Echo => self.echo_handler(msg, parties).await,
            MsgType::Ready => self.ready_handler(msg, parties).await,
            MsgType::Unknown(t) => {
                eprintln!("Bracha: Unknown message type: {}", t);
            }
        }
    }
    async fn broadcast(&self, msg: Msg, net: Arc<Network>) {
        for sender in &net.senders {
            let _ = sender.send(msg.clone()).await;
        }
    }
    async fn run_party(&self, receiver: &mut Receiver<Msg>, parties: Arc<Network>) {
        while let Some(msg) = receiver.recv().await {
            self.process(msg, parties.clone()).await;
        }
    }
}
impl Bracha {
    /// Handlers
    pub async fn init(&self, payload: Vec<u8>, session_id: u32, parties: Arc<Network>) {
        //Create message
        let msg = Msg::new(self.id, session_id, payload, "INIT".to_string());
        info!(
            id = self.id,
            session_id,
            msg_type = "INIT",
            "Broadcasting INIT message"
        );
        Bracha::broadcast(&self, msg, parties).await;
    }

    pub async fn init_handler(&self, msg: Msg, parties: Arc<Network>) {
        info!(
            id = self.id,
            session_id = msg.session_id,
            sender = msg.sender_id,
            msg_type = %msg.msg_type,
            "Handling INIT message"
        );
        let mut store_lock = self.store.lock().await;

        // Get or initialize the store entry for the session_id
        let store = store_lock
            .entry(msg.session_id)
            .or_insert_with(BrachaStore::default);

        // Only broadcast if echo hasn't already been sent
        if !store.echo {
            let new_msg = Msg::new(self.id, msg.session_id, msg.payload, "ECHO".to_string());
            store.mark_echo();
            info!(
                id = self.id,
                session_id = msg.session_id,
                msg_type = "ECHO",
                "Broadcasting ECHO in response to INIT"
            );
            Bracha::broadcast(&self, new_msg, parties).await;
        }
    }
    pub async fn echo_handler(&self, msg: Msg, parties: Arc<Network>) {
        info!(
            id = self.id,
            session_id = msg.session_id,
            sender = msg.sender_id,
            msg_type = %msg.msg_type,
            "Handling ECHO message"
        );
        let mut store_lock = self.store.lock().await;

        // Get or initialize the store entry for the session_id
        let store = store_lock
            .entry(msg.session_id)
            .or_insert_with(BrachaStore::default);

        // Ignore if session has already ended
        if store.ended {
            debug!(id = self.id, session_id = msg.session_id, "Session already ended, ignoring ECHO");
            return;
        }

        // If this sender hasn't already sent an echo
        if !store.has_echo(msg.sender_id) {
            store.set_echo_sent(msg.sender_id);
            store.increment_echo(&msg.payload);
            let count = store.get_echo_count(&msg.payload);
            
            if count >= 2 * self.t + 1 {
                if !store.ready {
                    store.mark_ready();
                    let new_msg = Msg::new(
                        self.id,
                        msg.session_id,
                        msg.payload.clone(),
                        "READY".to_string(),
                    );
                    info!(
                        id = self.id,
                        session_id = msg.session_id,
                        msg_type = "READY",
                        "Broadcasting READY after ECHO threshold met"
                    );
                    Bracha::broadcast(&self, new_msg, parties.clone()).await;
                }

                if !store.echo {
                    store.mark_echo();
                    let new_msg =
                        Msg::new(self.id, msg.session_id, msg.payload, "ECHO".to_string());
                        info!(
                            id = self.id,
                            session_id = msg.session_id,
                            msg_type = "ECHO",
                            "Re-broadcasting ECHO due to threshold"
                        );
    
                    Bracha::broadcast(&self, new_msg, parties).await;
                }
            }
        }
    }
    pub async fn ready_handler(&self, msg: Msg, parties: Arc<Network>) {
        info!(
            id = self.id,
            session_id = msg.session_id,
            sender = msg.sender_id,
            msg_type = %msg.msg_type,
            "Handling READY message"
        );
        let mut store_lock = self.store.lock().await;

        // Get or initialize the store entry for the session_id
        let store = store_lock
            .entry(msg.session_id)
            .or_insert_with(BrachaStore::default);

        // Ignore if session has already ended
        if store.ended {
            debug!(id = self.id, session_id = msg.session_id, "Session already ended, ignoring READY");
            return;
        }

        // Process only if this sender hasn't sent READY yet
        if !store.has_ready(msg.sender_id) {
            store.set_ready_sent(msg.sender_id);
            store.increment_ready(&msg.payload);
            let count = store.get_ready_count(&msg.payload);
    
            if count >= self.t + 1 && count < 2 * self.t + 1 {
                if !store.ready {
                    store.mark_ready();
                    let new_msg = Msg::new(
                        self.id,
                        msg.session_id,
                        msg.payload.clone(),
                        "READY".to_string(),
                    );
                    info!(
                        id = self.id,
                        session_id = msg.session_id,
                        msg_type = "READY",
                        "Broadcasting READY after t+1 threshold"
                    );
                    Bracha::broadcast(&self, new_msg, parties.clone()).await;
                }

                if !store.echo {
                    store.mark_echo();
                    let new_msg =
                        Msg::new(self.id, msg.session_id, msg.payload, "ECHO".to_string());
                        info!(
                            id = self.id,
                            session_id = msg.session_id,
                            msg_type = "ECHO",
                            "Broadcasting ECHO along with READY"
                        );
                    Bracha::broadcast(&self, new_msg, parties).await;
                }
            } else if count >= 2 * self.t + 1 {
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
}


#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;
    use std::time::Duration;
    use tracing_subscriber;


    #[tokio::test]
    async fn test_bracha_rbc_basic() {
        let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer() 
        .try_init();

        // Set the parameters
        let n = 4;
        let t = 1;
        let payload = b"Hello, MPC!".to_vec();
        let session_id = 42;

        //Set the channels for broadcasting
        let mut receivers = Vec::new();
        let mut senders = Vec::new();
        for _ in 0..n {
            let (tx, rx) = mpsc::channel(100);
            senders.push(tx);
            receivers.push(rx);
        }

        // Create Bracha instances and their networks
        let mut parties = Vec::new();
        for i in 0..n {
            let bracha = Bracha::new(i as u32, n, t);
            let net = Arc::new(Network {
                id: i as u32,
                senders: senders.clone(),
            });
            parties.push((bracha, net));
        }

        // Spawn party runners
        for i in 0..n {
            let (bracha, net) = parties[i as usize].clone();
            let mut rx = receivers.remove(0);
            tokio::spawn(async move {
                bracha.run_party(&mut rx, net).await;
            });
        }

        // Party 0 initiates broadcast
        let (bracha0, net0) = &parties[0];
        bracha0.init(payload.clone(), session_id, net0.clone()).await;

        // Give time for broadcast to propagate
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Check that all parties completed broadcast and agreed on output
        for (bracha, _) in &parties {
            let store = bracha.store.lock().await;
            let session_store = store.get(&session_id);
            assert!(session_store.is_some(), "Party did not create session store");
            let s = session_store.unwrap();
            assert!(s.ended, "Broadcast not completed for party {}", bracha.id);
            assert_eq!(&s.output, &payload, "Incorrect payload at party {}", bracha.id);
        }
        
    }
}
