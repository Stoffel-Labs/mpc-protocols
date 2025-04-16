/// This file contains more common reliable broadcast protocols used in MPC.
/// You can reuse them in your own custom MPC protocol implementations.

/// CommonSubset is a subroutine used to implement many RBC protocols.
/// It is used to determine which RBC instances have terminated.
use super::{bracha::*, types::*};
use crate::RBC;
use std::collections::HashMap;

trait CommonSubset {}
struct AVID {}
impl RBC for AVID {
    async fn process(&mut self, msg: Msg) {}
    async fn broadcast(msg: Msg) {}
}

///Bracha RBC
struct Bracha {
    pub id: u32,                          //Initiators ID
    pub n: u32,                           //Network size
    pub t: u32,                           //No. of malicious parties
    pub store: HashMap<u32, BrachaStore>, //Sessionid => store
}

impl RBC for Bracha {
    async fn process(&mut self, msg: Msg) {
        match msg.msg_type.as_str() {
            "INIT" => {
                self.init_handler(msg).await
            }
            "ECHO" => {
                self.echo_handler(msg).await
            }
            "READY" => {
                self.ready_handler(msg).await
            }
            _ => {}
        }
    }
    async fn broadcast(msg: Msg) {}
}

impl Bracha {
    /// Handlers
    pub async fn init(&self, value: Vec<u8>, session_id: u32) {
        //Create message
        let msg = Msg::new(self.id, session_id, value, "INIT".to_string());
        Bracha::broadcast(msg).await;
    }

    pub async fn init_handler(&mut self, msg: Msg) {
        //Check if for this session id an init has been before sending an echo
        match self.store.get_mut(&msg.session_id) {
            Some(store) => {
                if !store.echo {
                    let new_msg = Msg::new(self.id, msg.session_id, msg.value, "ECHO".to_string());
                    store.mark_echo();
                    Bracha::broadcast(new_msg).await;
                } else {
                    return;
                }
            }
            None => {
                return;
            }
        }
    }
    pub async fn echo_handler(&mut self, msg: Msg) {
        match self.store.get_mut(&msg.session_id) {
            Some(store) => {
                if store.ended {
                    return
                }
                if !store.has_echo(msg.sender_id) {
                    store.set_echo_sent(msg.sender_id);
                    store.increment_echo(&msg.value.clone());
                    let count = store.get_echo_count(&msg.value);
                    if count >= 2 * self.t + 1 {
                        if !store.ready {
                            store.mark_ready();
                            let new_msg =
                                Msg::new(self.id, msg.session_id, msg.value.clone(), "READY".to_string());
                            Bracha::broadcast(new_msg).await;
                        } 
                        if !store.echo {
                            store.mark_echo();
                            let new_msg =
                                Msg::new(self.id, msg.session_id, msg.value, "ECHO".to_string());
                            Bracha::broadcast(new_msg).await;
                        }
                    }
                }
            }
            None => {
                return;
            }
        }
    }
    pub async fn ready_handler(&mut self, msg: Msg) {
        match self.store.get_mut(&msg.session_id) {
            Some(store) => {
                if store.ended {
                    return
                }
                if !store.has_ready(msg.sender_id) {
                    store.set_ready_sent(msg.sender_id);
                    store.increment_ready(&msg.value.clone());
                    let count = store.get_ready_count(&msg.value);
                    if count >= self.t + 1 && count < 2 * self.t + 1 {
                        if !store.ready {
                            store.mark_ready();
                            let new_msg =
                                Msg::new(self.id, msg.session_id, msg.value.clone(), "READY".to_string());
                            Bracha::broadcast(new_msg).await;
                        } 
                        if !store.echo {
                            store.mark_echo();
                            let new_msg =
                                Msg::new(self.id, msg.session_id, msg.value, "ECHO".to_string());
                            Bracha::broadcast(new_msg).await;
                        }
                    } else if count >= 2 * self.t + 1 {
                        store.mark_ended();
                        store.set_output(msg.value);
                    }
                }
            }
            None => {
                return;
            }
        }
    }
}
