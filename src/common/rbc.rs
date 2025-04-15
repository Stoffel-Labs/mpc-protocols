/// This file contains more common reliable broadcast protocols used in MPC.
/// You can reuse them in your own custom MPC protocol implementations.

/// CommonSubset is a subroutine used to implement many RBC protocols.
/// It is used to determine which RBC instances have terminated.

use super::{bracha::*, types::*};
use std::collections::HashMap;
use crate::RBC;
trait CommonSubset {}
struct AVID {}

impl RBC for AVID {
    async fn process(&self, msg:Msg){

    }
    async fn broadcast(msg:Msg) {
        
    }
}

///Bracha RBC
struct Bracha {
    pub id :u32, //Initiators ID 
    pub n : u32, //Network size 
    pub t : u32, //No. of malicious parties  
    pub store : HashMap<u32, BrachaStore>, //Sessionid => store
}


impl RBC for Bracha {
    async fn process(&self, msg:Msg){
        match msg.msg_type.as_str() {
            "INIT" =>{},
            "ECHO" =>{},
            "READY" =>{},
            _ =>{}
        }

    }
    async fn broadcast(msg:Msg) {
        
    }

}

impl Bracha {
    ///Starters
    pub async fn init(&self,value:Vec<u8>,session_id : u32){
        //Create message
        let msg = Msg::new(self.id, session_id, value, "INIT".to_string());
        Bracha::broadcast(msg);
    }
    pub async fn echo(&self,value:Vec<u8>,session_id : u32){}
    pub async fn ready(&self,value:Vec<u8>,session_id : u32){}
    /// Handlers
    pub async fn init_handler(&self,value:Vec<u8>,session_id : u32){}
    pub async fn echo_handler(&self,value:Vec<u8>,session_id : u32){}
    pub async fn ready_handler(&self,value:Vec<u8>,session_id : u32){}


}
