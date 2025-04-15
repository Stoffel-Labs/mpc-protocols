///Generic message for rbc
pub struct Msg{
    pub sender_id : u32,
    pub session_id :u32,
    pub value : Vec<u8>,
    pub msg_type : String
}

impl Msg {

    pub fn new(sender_id: u32, session_id: u32, value: Vec<u8> ,msg_type : String) -> Self {
        Msg {
            sender_id,
            session_id,
            value,
            msg_type
        }
    }

}
 