use std::{mem::ManuallyDrop, slice, sync::Arc};

use stoffelmpc_network::fake_network::{FakeNetwork, FakeNetworkConfig};

use crate::{
    common::{
        rbc::{
            rbc::Bracha,
            rbc_store::{GenericMsgType, Msg, MsgType, MsgTypeAba, MsgTypeAcs, MsgTypeAvid},
            RbcError,
        },
        RBC,
    },
    ffi::c_bindings::{
        network::{
            fake_network::{FakeNetworkReceivers, FakeNetworkReceiversOpaque},
            GenericNetwork, NetworkOpaque,
        },
        ByteSlice,
    },
    honeybadger::{SessionId, WrappedMessage},
};

//TODO - create cleanup functions

#[repr(C)]
pub enum RbcErrorCode {
    RbcSuccess,
    // Invalid threshold t for n must satisfy t < ceil(n / 3)
    RbcInvalidThreshold,
    // Session already ended
    RbcSessionEnded,
    // Unknown Bracha message type
    RbcUnknownMsgType,
    // Message send failed
    RbcSendFailed,
    // Internal error
    RbcInternal,
    // The message was not sent correctly
    RbcNetworkSendError,
    // The request reached a time out
    RbcNetworkTimeout,
    // The party is not found in the network
    RbcNetworkPartyNotFound,
    // The client is not connected
    RbcNetworkClientNotFound,
    // Error while serializing the object into bytes
    RbcSerializationError,
    // Inner error
    RbcShardError,
}

#[repr(C)]
pub enum RbcMessageType {
    BrachaInit,
    BrachaEcho,
    BrachaReady,
    BrachaUnknown,
    AvidSend,
    AvidEcho,
    AvidReady,
    AvidUnknown,
    AbaEst,
    AbaAux,
    AbaKey,
    AbaCoin,
    AbaUnknown,
    Acs,
    AcsUnknown,
}

// opaque pointer for bracha
#[repr(C)]
pub struct BrachaOpaque {
    _data: (),
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

#[repr(C)]
pub struct RbcMsg {
    pub sender_id: usize,         // ID of the sender node
    pub session_id: u64,          // Unique session ID for each broadcast instance
    pub round_id: usize,          //Round ID
    pub payload: ByteSlice, // Actual data being broadcasted (e.g., bytes of a secret or message)
    pub metadata: ByteSlice, // info related to the message shared
    pub msg_type: RbcMessageType, // Type of message like INIT, ECHO, or READY
    pub msg_len: usize,     // length of the original message
}

impl From<Msg> for RbcMsg {
    fn from(value: Msg) -> Self {
        let mut payload_bind = ManuallyDrop::new(value.payload);
        let mut metadata_bind = ManuallyDrop::new(value.metadata);
        let payload = ByteSlice {
            pointer: payload_bind.as_mut_ptr(),
            len: payload_bind.len(),
        };
        let metadata = ByteSlice {
            pointer: metadata_bind.as_mut_ptr(),
            len: metadata_bind.len(),
        };
        RbcMsg {
            sender_id: value.sender_id,
            session_id: value.session_id.as_u64(),
            round_id: value.round_id,
            payload: payload,
            metadata: metadata,
            msg_type: (&value.msg_type).into(),
            msg_len: value.msg_len,
        }
    }
}

impl From<RbcError> for RbcErrorCode {
    fn from(value: RbcError) -> Self {
        match value {
            RbcError::InvalidThreshold(_, _) => RbcErrorCode::RbcInvalidThreshold,
            RbcError::SessionEnded(_) => RbcErrorCode::RbcSessionEnded,
            RbcError::UnknownMsgType(_) => RbcErrorCode::RbcUnknownMsgType,
            RbcError::SendFailed => RbcErrorCode::RbcSendFailed,
            RbcError::Internal(_) => RbcErrorCode::RbcInternal,
            RbcError::NetworkError(network_error) => match network_error {
                stoffelnet::network_utils::NetworkError::SendError => {
                    RbcErrorCode::RbcNetworkSendError
                }
                stoffelnet::network_utils::NetworkError::Timeout => RbcErrorCode::RbcNetworkTimeout,
                stoffelnet::network_utils::NetworkError::PartyNotFound(_) => {
                    RbcErrorCode::RbcNetworkPartyNotFound
                }
                stoffelnet::network_utils::NetworkError::ClientNotFound(_) => {
                    RbcErrorCode::RbcNetworkClientNotFound
                }
            },
            RbcError::SerializationError(_) => RbcErrorCode::RbcSerializationError,
            RbcError::ShardError(_) => RbcErrorCode::RbcShardError,
        }
    }
}

impl From<&RbcMessageType> for GenericMsgType {
    fn from(value: &RbcMessageType) -> Self {
        match value {
            RbcMessageType::BrachaInit => Self::Bracha(MsgType::Init),
            RbcMessageType::BrachaEcho => Self::Bracha(MsgType::Echo),
            RbcMessageType::BrachaReady => Self::Bracha(MsgType::Ready),
            RbcMessageType::BrachaUnknown => Self::Bracha(MsgType::Unknown("".into())),
            RbcMessageType::AvidSend => Self::Avid(MsgTypeAvid::Send),
            RbcMessageType::AvidEcho => Self::Avid(MsgTypeAvid::Echo),
            RbcMessageType::AvidReady => Self::Avid(MsgTypeAvid::Ready),
            RbcMessageType::AvidUnknown => Self::Avid(MsgTypeAvid::Unknown("".into())),
            RbcMessageType::AbaEst => Self::ABA(MsgTypeAba::Est),
            RbcMessageType::AbaAux => Self::ABA(MsgTypeAba::Aux),
            RbcMessageType::AbaKey => Self::ABA(MsgTypeAba::Key),
            RbcMessageType::AbaCoin => Self::ABA(MsgTypeAba::Coin),
            RbcMessageType::AbaUnknown => Self::ABA(MsgTypeAba::Unknown("".into())),
            RbcMessageType::Acs => Self::Acs(MsgTypeAcs::Acs),
            RbcMessageType::AcsUnknown => Self::Acs(MsgTypeAcs::Unknown("".into())),
        }
    }
}

impl From<&GenericMsgType> for RbcMessageType {
    fn from(value: &GenericMsgType) -> Self {
        match value {
            GenericMsgType::Bracha(msg_type) => match msg_type {
                MsgType::Init => Self::BrachaInit,
                MsgType::Echo => Self::BrachaEcho,
                MsgType::Ready => Self::BrachaReady,
                MsgType::Unknown(_) => Self::BrachaUnknown,
            },
            GenericMsgType::Avid(msg_type_avid) => match msg_type_avid {
                MsgTypeAvid::Send => Self::AvidSend,
                MsgTypeAvid::Echo => Self::AvidEcho,
                MsgTypeAvid::Ready => Self::AvidReady,
                MsgTypeAvid::Unknown(_) => Self::AvidUnknown,
            },
            GenericMsgType::ABA(msg_type_aba) => match msg_type_aba {
                MsgTypeAba::Est => Self::AbaEst,
                MsgTypeAba::Aux => Self::AbaAux,
                MsgTypeAba::Key => Self::AbaKey,
                MsgTypeAba::Coin => Self::AbaCoin,
                MsgTypeAba::Unknown(_) => Self::AbaUnknown,
            },
            GenericMsgType::Acs(msg_type_acs) => match msg_type_acs {
                MsgTypeAcs::Acs => Self::Acs,
                MsgTypeAcs::Unknown(_) => Self::AcsUnknown,
            },
        }
    }
}

#[no_mangle]
pub extern "C" fn deserialize_rbc_msg(msg: ByteSlice, output_rbc_msg: *mut RbcMsg) -> RbcErrorCode {
    let bytes = unsafe { slice::from_raw_parts(msg.pointer, msg.len) };
    let wrapped: WrappedMessage = match bincode::deserialize(bytes) {
        Ok(m) => m,
        Err(_) => return RbcErrorCode::RbcSerializationError,
    };
    match wrapped {
        WrappedMessage::Rbc(msg) => {
            let rbc_msg: RbcMsg = msg.into();
            unsafe {
                *output_rbc_msg = rbc_msg;
            }
            return RbcErrorCode::RbcSuccess;
        }
        _ => return RbcErrorCode::RbcSerializationError,
    }
}
/// Creates a new Bracha instance with the given parameters.
///
/// # Arguments
/// * `id` - the ID of the initiator
/// * `n` - total number of parties in the network
/// * `t` - number of allowed malicious parties
#[no_mangle]
pub extern "C" fn bracha_new(
    id: usize,
    n: usize,
    t: usize,
    bracha_pointer: *mut *mut BrachaOpaque,
) -> RbcErrorCode {
    // k is unused in bracha
    let res = Bracha::new(id, n, t, 0);
    match res {
        Ok(b) => {
            let ptr = Box::into_raw(Box::new(b)) as *mut BrachaOpaque;
            unsafe {
                *bracha_pointer = ptr;
            }
        }
        Err(e) => return e.into(),
    }
    return RbcErrorCode::RbcSuccess;
}

#[no_mangle]
pub extern "C" fn get_bracha_id(bracha_pointer: *mut BrachaOpaque) -> usize {
    let bracha = unsafe { &mut *(bracha_pointer as *mut Bracha) };
    bracha.id
}

#[no_mangle]
pub extern "C" fn get_bracha_n(bracha_pointer: *mut BrachaOpaque) -> usize {
    let bracha = unsafe { &mut *(bracha_pointer as *mut Bracha) };
    bracha.n
}

#[no_mangle]
pub extern "C" fn get_bracha_t(bracha_pointer: *mut BrachaOpaque) -> usize {
    let bracha = unsafe { &mut *(bracha_pointer as *mut Bracha) };
    bracha.t
}

#[no_mangle]
pub extern "C" fn sync_bracha_clear_store(bracha_pointer: *mut BrachaOpaque) {
    let bracha = unsafe { &mut *(bracha_pointer as *mut Bracha) };
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(bracha.clear_store());
}

#[no_mangle]
pub extern "C" fn has_bracha_session_ended(
    bracha_pointer: *mut BrachaOpaque,
    session_id: u64,
) -> bool {
    let bracha = unsafe { &mut *(bracha_pointer as *mut Bracha) };
    let session_id = unsafe { SessionId::from_u64(session_id) };
    let session_store = {
        let store_map = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(bracha.store.lock());
        store_map
            .get(&session_id)
            .cloned()
            .expect(&format!("Party {} did not create session store", bracha.id))
    };
    let s = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(session_store.lock());
    s.ended
}

#[no_mangle]
pub extern "C" fn get_bracha_output(
    bracha_pointer: *mut BrachaOpaque,
    session_id: u64,
) -> ByteSlice {
    let bracha = unsafe { &mut *(bracha_pointer as *mut Bracha) };
    let session_id = unsafe { SessionId::from_u64(session_id) };
    let session_store = {
        let store_map = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(bracha.store.lock());
        store_map
            .get(&session_id)
            .cloned()
            .expect(&format!("Party {} did not create session store", bracha.id))
    };
    let s = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(session_store.lock());
    let output = s.output.clone();
    let mut output = ManuallyDrop::new(output);
    ByteSlice {
        pointer: output.as_mut_ptr(),
        len: output.len(),
    }
}

#[no_mangle]
pub extern "C" fn sync_bracha_init(
    bracha_pointer: *mut BrachaOpaque,
    payload: ByteSlice,
    session_id: u64,
    net_ptr: *mut NetworkOpaque,
) -> RbcErrorCode {
    // prevent payload from being dropped
    let payload = ManuallyDrop::new(payload);
    let payload = unsafe { slice::from_raw_parts(payload.pointer, payload.len) }.to_vec();
    let bracha = unsafe { &mut *(bracha_pointer as *mut Bracha) };
    let network = unsafe { &*(net_ptr as *mut GenericNetwork) };

    let result = match network {
        GenericNetwork::FakeNetwork(n) => {
            let r = tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(bracha.init(
                    payload,
                    unsafe { SessionId::from_u64(session_id) },
                    Arc::clone(n),
                ));
            r
        }
        GenericNetwork::QuicNetworkManager(n) => {
            let r = tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(bracha.init(
                    payload,
                    unsafe { SessionId::from_u64(session_id) },
                    Arc::clone(n),
                ));
            r
        }
    };

    match result {
        Ok(()) => RbcErrorCode::RbcSuccess,
        Err(e) => e.into(),
    }
}

#[no_mangle]
pub extern "C" fn sync_bracha_process(
    bracha_pointer: *mut BrachaOpaque,
    msg: RbcMsg,
    net_ptr: *mut NetworkOpaque,
) -> RbcErrorCode {
    let bracha = unsafe { &*(bracha_pointer as *mut Bracha) };
    let network = unsafe { &*(net_ptr as *mut GenericNetwork) };
    // prevent msg from being dropped
    let msg = ManuallyDrop::new(msg);
    let payload =
        unsafe { Vec::from_raw_parts(msg.payload.pointer, msg.payload.len, msg.payload.len) };
    let metadata =
        unsafe { Vec::from_raw_parts(msg.metadata.pointer, msg.metadata.len, msg.metadata.len) };

    let rbc_msg = Msg {
        sender_id: msg.sender_id,
        session_id: unsafe { SessionId::from_u64(msg.session_id) },
        round_id: msg.round_id,
        payload: payload,
        metadata: metadata,
        msg_type: GenericMsgType::from(&msg.msg_type),
        msg_len: msg.msg_len,
    };
    let result = match &*network {
        GenericNetwork::FakeNetwork(n) => tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(bracha.process(rbc_msg, Arc::clone(n))),
        GenericNetwork::QuicNetworkManager(n) => tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(bracha.process(rbc_msg, Arc::clone(n))),
    };

    match result {
        Ok(()) => RbcErrorCode::RbcSuccess,
        Err(e) => e.into(),
    }
}

#[no_mangle]
pub extern "C" fn sync_bracha_broadcast(
    bracha_pointer: *mut BrachaOpaque,
    msg: RbcMsg,
    net_ptr: *mut NetworkOpaque,
) -> RbcErrorCode {
    let bracha = unsafe { &*(bracha_pointer as *mut Bracha) };
    let network = unsafe { &*(net_ptr as *mut GenericNetwork) };
    // prevent msg from being dropped
    let msg = ManuallyDrop::new(msg);
    let payload =
        unsafe { Vec::from_raw_parts(msg.payload.pointer, msg.payload.len, msg.payload.len) };
    let metadata =
        unsafe { Vec::from_raw_parts(msg.metadata.pointer, msg.metadata.len, msg.metadata.len) };

    let rbc_msg = Msg {
        sender_id: msg.sender_id,
        session_id: unsafe { SessionId::from_u64(msg.session_id) },
        round_id: msg.round_id,
        payload: payload,
        metadata: metadata,
        msg_type: GenericMsgType::from(&msg.msg_type),
        msg_len: msg.msg_len,
    };
    let result = match &*network {
        GenericNetwork::FakeNetwork(n) => tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(bracha.broadcast(rbc_msg, Arc::clone(n))),
        GenericNetwork::QuicNetworkManager(n) => tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(bracha.broadcast(rbc_msg, Arc::clone(n))),
    };

    match result {
        Ok(()) => RbcErrorCode::RbcSuccess,
        Err(e) => e.into(),
    }
}

#[no_mangle]
pub extern "C" fn sync_bracha_send(
    bracha_pointer: *mut BrachaOpaque,
    msg: RbcMsg,
    net_ptr: *mut NetworkOpaque,
    recv: usize,
) -> RbcErrorCode {
    let bracha = unsafe { &*(bracha_pointer as *mut Bracha) };
    let network = unsafe { &*(net_ptr as *mut GenericNetwork) };
    // prevent msg from being dropped
    let msg = ManuallyDrop::new(msg);
    let payload =
        unsafe { Vec::from_raw_parts(msg.payload.pointer, msg.payload.len, msg.payload.len) };
    let metadata =
        unsafe { Vec::from_raw_parts(msg.metadata.pointer, msg.metadata.len, msg.metadata.len) };

    let rbc_msg = Msg {
        sender_id: msg.sender_id,
        session_id: unsafe { SessionId::from_u64(msg.session_id) },
        round_id: msg.round_id,
        payload: payload,
        metadata: metadata,
        msg_type: GenericMsgType::from(&msg.msg_type),
        msg_len: msg.msg_len,
    };
    let result = match &*network {
        GenericNetwork::FakeNetwork(n) => tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(bracha.send(rbc_msg, Arc::clone(n), recv)),
        GenericNetwork::QuicNetworkManager(n) => tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(bracha.send(rbc_msg, Arc::clone(n), recv)),
    };

    match result {
        Ok(()) => RbcErrorCode::RbcSuccess,
        Err(e) => e.into(),
    }
}

#[no_mangle]
pub extern "C" fn free_bracha(bracha_pointer: *mut BrachaOpaque) {
    if !bracha_pointer.is_null() {
        unsafe {
            let _ = Box::from_raw(bracha_pointer as *mut Bracha);
        }
    }
}
