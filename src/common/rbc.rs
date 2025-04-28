/// This file contains more common reliable broadcast protocols used in MPC.
/// You can reuse them in your own custom MPC protocol implementations.
use super::rbc_store::*;
use crate::RBC;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{
    mpsc::{Receiver, Sender},
    Mutex,
};
use tracing::{debug, info};

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
    pub id: u32,                                                  //Initiators ID
    pub n: u32,                                                   //Network size
    pub t: u32,                                                   //No. of malicious parties
    pub store: Arc<Mutex<HashMap<u32, Arc<Mutex<BrachaStore>>>>>, // <- wrap only this in a lock //Sessionid => store
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

        // Lock the HashMap to access or insert the session entry
        let session_store = {
            let mut store = self.store.lock().await;

            // Get or insert the Arc<Mutex<BrachaStore>> for the session
            store
                .entry(msg.session_id)
                .or_insert_with(|| Arc::new(Mutex::new(BrachaStore::default())))
                .clone()
        };
        //Locking specific session store
        let mut store = session_store.lock().await;

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
        // Lock the HashMap to access or insert the session entry
        let session_store = {
            let mut store = self.store.lock().await;

            // Get or insert the Arc<Mutex<BrachaStore>> for the session
            store
                .entry(msg.session_id)
                .or_insert_with(|| Arc::new(Mutex::new(BrachaStore::default())))
                .clone()
        };
        //Locking specific session store
        let mut store = session_store.lock().await;

        // Ignore if session has already ended
        if store.ended {
            debug!(
                id = self.id,
                session_id = msg.session_id,
                "Session already ended, ignoring ECHO"
            );
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
         // Lock the HashMap to access or insert the session entry
         let session_store = {
            let mut store = self.store.lock().await;

            // Get or insert the Arc<Mutex<BrachaStore>> for the session
            store
                .entry(msg.session_id)
                .or_insert_with(|| Arc::new(Mutex::new(BrachaStore::default())))
                .clone()
        };
        //Locking specific session store
        let mut store = session_store.lock().await;

        // Ignore if session has already ended
        if store.ended {
            debug!(
                id = self.id,
                session_id = msg.session_id,
                "Session already ended, ignoring READY"
            );
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
    use std::time::Duration;
    use tokio::sync::mpsc;
    use tracing_subscriber;

    async fn setup_channels(n: u32) -> (Vec<mpsc::Sender<Msg>>, Vec<mpsc::Receiver<Msg>>) {
        let mut senders = Vec::new();
        let mut receivers = Vec::new();
        for _ in 0..n {
            let (tx, rx) = mpsc::channel(100);
            senders.push(tx);
            receivers.push(rx);
        }
        (senders, receivers)
    }

    async fn setup_parties(
        n: u32,
        t: u32,
        senders: Vec<mpsc::Sender<Msg>>,
    ) -> Vec<(Bracha, Arc<Network>)> {
        (0..n)
            .map(|i| {
                let bracha = Bracha::new(i as u32, n, t);
                let net = Arc::new(Network {
                    id: i as u32,
                    senders: senders.clone(),
                });
                (bracha, net)
            })
            .collect()
    }

    async fn spawn_party_runners(
        parties: &[(Bracha, Arc<Network>)],
        mut receivers: Vec<mpsc::Receiver<Msg>>,
    ) {
        for (bracha, net) in parties.iter().cloned() {
            let mut rx = receivers.remove(0);
            tokio::spawn(async move {
                bracha.run_party(&mut rx, net).await;
            });
        }
    }
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
        let session_id = 12;

        let (senders, receivers) = setup_channels(n).await;
        let parties = setup_parties(n, t, senders).await;
        spawn_party_runners(&parties, receivers).await;

        // Party 0 initiates broadcast
        let (bracha0, net0) = &parties[0];
        bracha0
            .init(payload.clone(), session_id, net0.clone())
            .await;

        // Give time for broadcast to propagate
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Check that all parties completed broadcast and agreed on output
        for (bracha, _) in &parties {
            let session_store = {
                let store_map = bracha.store.lock().await;
                store_map
                    .get(&session_id)
                    .cloned()
                    .expect(&format!("Party {} did not create session store", bracha.id))
            };
    
            // Step 2: Lock the specific store for this session
            let s = session_store.lock().await;

            assert!(s.ended, "Broadcast not completed for party {}", bracha.id);
            assert_eq!(
                &s.output, &payload,
                "Incorrect payload at party {}",
                bracha.id
            );
        }
    }

    #[tokio::test]
    async fn test_multiple_sessions() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_test_writer()
            .try_init();

        let n = 4;
        let t = 1;
        let session_ids = vec![101, 202, 303];
        let payloads = vec![
            b"Payload A".to_vec(),
            b"Payload B".to_vec(),
            b"Payload C".to_vec(),
        ];

        let (senders, receivers) = setup_channels(n).await;
        let parties = setup_parties(n, t, senders).await;
        spawn_party_runners(&parties, receivers).await;

        // Launch all sessions from party 0
        let (bracha0, net0) = &parties[0];
        for (i, sid) in session_ids.iter().enumerate() {
            bracha0.init(payloads[i].clone(), *sid, net0.clone()).await;
        }

        tokio::time::sleep(Duration::from_millis(200)).await;

        for (bracha, _) in &parties {
            let store = bracha.store.lock().await;
            for (i, sid) in session_ids.iter().enumerate() {
                let store_arc = store.get(sid).expect("Missing session");
                let s = store_arc.lock().await;

                assert!(
                    s.ended,
                    "Session {} not completed at party {}",
                    sid, bracha.id
                );
                assert_eq!(
                    &s.output, &payloads[i],
                    "Incorrect payload for session {}",
                    sid
                );
            }
        }
    }
    #[tokio::test]
    async fn test_multiple_sessions_different_party() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_test_writer()
            .try_init();

        let n = 4;
        let t = 1;
        let session_ids = vec![10, 20, 30, 40];
        let payloads = vec![
            b"From Party 0".to_vec(),
            b"From Party 1".to_vec(),
            b"From Party 2".to_vec(),
            b"From Party 3".to_vec(),
        ];

        let (senders, receivers) = setup_channels(n).await;
        let parties = setup_parties(n, t, senders).await;
        spawn_party_runners(&parties, receivers).await;

        // Each party initiates one session
        for (i, (bracha, net)) in parties.iter().enumerate() {
            bracha
                .init(payloads[i].clone(), session_ids[i], net.clone())
                .await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Validate all sessions completed successfully and consistently
        for (bracha, _) in &parties {
            let store = bracha.store.lock().await;
            for (i, session_id) in session_ids.iter().enumerate() {
                let store_arc = store.get(session_id).expect("Missing session");
                let s = store_arc.lock().await;
                assert!(
                    s.ended,
                    "Session {} not completed at party {}",
                    session_id, bracha.id
                );
                assert_eq!(
                    &s.output, &payloads[i],
                    "Incorrect output at party {} for session {}",
                    bracha.id, session_id
                );
            }
        }
    }
    #[tokio::test]
    async fn test_out_of_order_delivery() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_test_writer()
            .try_init();

        let n = 4;
        let t = 1;
        let session_id = 11;
        let payload = b"out-of-order".to_vec();

        let (senders, receivers) = setup_channels(n).await;
        let parties = setup_parties(n, t, senders.clone()).await;
        spawn_party_runners(&parties, receivers).await;

        // Simulate sending READY before ECHO and INIT
        let sender_id = 1;
        let ready_msg = Msg::new(sender_id, session_id, payload.clone(), "READY".to_string());
        let echo_msg = Msg::new(sender_id, session_id, payload.clone(), "ECHO".to_string());

        // Send READY first
        senders[2].send(ready_msg).await.unwrap();

        // Then ECHO
        senders[3].send(echo_msg).await.unwrap();

        // Party 0 initiates broadcast
        let (bracha0, net0) = &parties[0];
        bracha0
            .init(payload.clone(), session_id, net0.clone())
            .await;

        // Allow time for processing
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Check if parties reached consensus
        for (bracha, _) in &parties {
            let store = bracha.store.lock().await;
            if let Some(state) = store.get(&session_id) {
                let s = state.lock().await;

                if s.ended {
                    println!("Party {} ended with output: {:?}", bracha.id, s.output);
                } else {
                    println!("Party {} has not yet ended", bracha.id);
                }
            } else {
                println!("Party {} has a missing session", bracha.id);

            }
        }
    }
}
