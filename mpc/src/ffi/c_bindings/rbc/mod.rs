use std::{mem::ManuallyDrop, slice, sync::Arc};

use crate::{
    common::{
        rbc::{
            rbc::{Avid, Bracha, ABA},
            rbc_store::{GenericMsgType, Msg, MsgType, MsgTypeAba, MsgTypeAcs, MsgTypeAvid},
            RbcError,
        },
        ProtocolSessionId, RbcWrapFn, RBC,
    },
    ffi::c_bindings::{
        free_bytes_slice,
        network::{GenericNetwork, NetworkOpaque},
        ByteSlice, SessionIdBits,
    },
    honeybadger::{SessionId, WrappedMessage},
};

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RbcErrorCode {
    RbcSuccess,
    // Invalid threshold t for n must satisfy t < ceil(n / 3)
    RbcInvalidThreshold,
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
    // Session does not exits
    RbcSessionNotFound,
    RbcSendError,
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
pub struct BrachaOutputReceiverOpaque {
    _data: (),
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

// opaque pointer for Avid
#[repr(C)]
pub struct AvidOpaque {
    _data: (),
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

#[repr(C)]
pub struct AvidOutputReceiverOpaque {
    _data: (),
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

// opaque pointer for ABA
#[repr(C)]
pub struct AbaOpaque {
    _data: (),
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}
struct AbaInner {
    pub _aba: ABA<SessionId>,
    pub _output_rx: tokio::sync::mpsc::Receiver<SessionId>,
}

#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct FfiCtx(pub usize);

// SAFETY: usize handle is thread-safe by construction
unsafe impl Send for FfiCtx {}
unsafe impl Sync for FfiCtx {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct RbcWrapCtx {
    pub ctx: FfiCtx,
    pub call: extern "C" fn(
        ctx: *mut core::ffi::c_void,
        msg_ptr: *const u8,
        msg_len: usize,
        out_ptr: *mut *mut u8,
        out_len: *mut usize,
    ) -> RbcErrorCode,
}

#[repr(C)]
pub struct AbaOutputReceiverOpaque {
    _data: (),
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}
#[repr(C)]
pub struct RbcMsg {
    pub sender_id: usize,          // ID of the sender node
    pub session_id: SessionIdBits, // Unique session ID for each broadcast instance
    pub round_id: usize,           //Round ID
    pub payload: ByteSlice, // Actual data being broadcasted (e.g., bytes of a secret or message)
    pub metadata: ByteSlice, // info related to the message shared
    pub msg_type: RbcMessageType, // Type of message like INIT, ECHO, or READY
}

impl<Id: ProtocolSessionId> From<Msg<Id>> for RbcMsg {
    fn from(value: Msg<Id>) -> Self {
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
            session_id: value.session_id.as_u128().into(),
            round_id: value.round_id,
            payload,
            metadata,
            msg_type: (&value.msg_type).into(),
        }
    }
}

#[no_mangle]
pub extern "C" fn free_rbc_msg(msg: RbcMsg) {
    free_bytes_slice(msg.payload);
    free_bytes_slice(msg.metadata);
}

impl From<RbcError> for RbcErrorCode {
    fn from(value: RbcError) -> Self {
        match value {
            RbcError::InvalidThreshold(_, _) => RbcErrorCode::RbcInvalidThreshold,
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
            RbcError::SendError => RbcErrorCode::RbcSendError,
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

#[no_mangle]
pub extern "C" fn rbc_alloc(len: usize) -> *mut u8 {
    let mut v = Vec::<u8>::with_capacity(len);
    let ptr = v.as_mut_ptr();
    std::mem::forget(v);
    ptr
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
    wrapper: RbcWrapCtx,
) -> RbcErrorCode {
    let ctx = wrapper.ctx;
    let call = wrapper.call;

    let rust_wrapper: RbcWrapFn<SessionId> = Arc::new(move |msg| {
        let wrapped = WrappedMessage::Rbc(msg);
        let encoded = bincode::serialize(&wrapped)?;

        let mut out_ptr = core::ptr::null_mut();
        let mut out_len = 0;

        let code = (call)(
            ctx.0 as *mut core::ffi::c_void,
            encoded.as_ptr(),
            encoded.len(),
            &mut out_ptr,
            &mut out_len,
        );

        if code != RbcErrorCode::RbcSuccess {
            return Err(RbcError::Internal(format!(
                "FFI wrapper failed with code {:?}",
                code
            )));
        }

        unsafe { Ok(Vec::from_raw_parts(out_ptr, out_len, out_len)) }
    });

    // RBC output channel
    let (output_sender, _output_receiver) = tokio::sync::mpsc::channel(200);

    // k unused for Bracha
    let res = Bracha::new(id, n, t, 0, output_sender, rust_wrapper);

    match res {
        Ok(b) => {
            unsafe {
                *bracha_pointer = Box::into_raw(Box::new(b)) as *mut BrachaOpaque;
            }
            RbcErrorCode::RbcSuccess
        }
        Err(e) => e.into(),
    }
}

#[no_mangle]
pub extern "C" fn free_bracha(bracha_pointer: *mut BrachaOpaque) {
    if !bracha_pointer.is_null() {
        unsafe {
            let _ = Box::from_raw(bracha_pointer as *mut Bracha<SessionId>);
        }
    }
}

#[no_mangle]
pub extern "C" fn get_bracha_id(bracha_pointer: *mut BrachaOpaque) -> usize {
    let bracha = unsafe { &mut *(bracha_pointer as *mut Bracha<SessionId>) };
    bracha.id
}

#[no_mangle]
pub extern "C" fn get_bracha_n(bracha_pointer: *mut BrachaOpaque) -> usize {
    let bracha = unsafe { &mut *(bracha_pointer as *mut Bracha<SessionId>) };
    bracha.n
}

#[no_mangle]
pub extern "C" fn get_bracha_t(bracha_pointer: *mut BrachaOpaque) -> usize {
    let bracha = unsafe { &mut *(bracha_pointer as *mut Bracha<SessionId>) };
    bracha.t
}

#[no_mangle]
pub extern "C" fn sync_bracha_clear_store(bracha_pointer: *mut BrachaOpaque) {
    let bracha = unsafe { &mut *(bracha_pointer as *mut Bracha<SessionId>) };
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(bracha.clear_store());
}

#[no_mangle]
pub extern "C" fn has_bracha_session_ended(
    bracha_pointer: *mut BrachaOpaque,
    session_id: SessionIdBits,
    output: *mut bool,
) -> RbcErrorCode {
    let bracha = unsafe { &mut *(bracha_pointer as *mut Bracha<SessionId>) };
    let session_id = unsafe { session_id.to_session_id() };
    let session_store = {
        let store_map = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(bracha.store.lock());
        let result = store_map.get(&session_id);
        match result {
            Some(s) => s.clone(),
            None => return RbcErrorCode::RbcSessionNotFound,
        }
    };
    let s = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(session_store.lock());
    unsafe {
        *output = s.ended;
    };
    return RbcErrorCode::RbcSuccess;
}

#[no_mangle]
pub extern "C" fn get_bracha_output(
    bracha_pointer: *mut BrachaOpaque,
    session_id: SessionIdBits,
    output: *mut ByteSlice,
) -> RbcErrorCode {
    let bracha = unsafe { &mut *(bracha_pointer as *mut Bracha<SessionId>) };
    let session_id = unsafe { session_id.to_session_id() };
    let session_store = {
        let store_map = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(bracha.store.lock());
        let result = store_map.get(&session_id);
        match result {
            Some(s) => s.clone(),
            None => return RbcErrorCode::RbcSessionNotFound,
        }
    };
    let s = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(session_store.lock());
    let out = s.output.clone();
    let mut out = ManuallyDrop::new(out);
    unsafe {
        *output = ByteSlice {
            pointer: out.as_mut_ptr(),
            len: out.len(),
        };
    };
    return RbcErrorCode::RbcSuccess;
}

#[no_mangle]
pub extern "C" fn sync_bracha_init(
    bracha_pointer: *mut BrachaOpaque,
    payload: ByteSlice,
    session_id: SessionIdBits,
    net_ptr: *mut NetworkOpaque,
) -> RbcErrorCode {
    let payload = unsafe { slice::from_raw_parts(payload.pointer, payload.len) }.to_vec();
    let bracha = unsafe { &mut *(bracha_pointer as *mut Bracha<SessionId>) };
    let network = unsafe { &*(net_ptr as *mut GenericNetwork) };

    let result = match network {
        GenericNetwork::FakeNetwork(n) => {
            let r = tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(bracha.init(
                    payload,
                    unsafe { session_id.to_session_id() },
                    Arc::clone(n),
                ));
            r
        }
        GenericNetwork::QuicNetworkManager(n) => {
            let r = tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(bracha.init(
                    payload,
                    unsafe { session_id.to_session_id() },
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
    let bracha = unsafe { &*(bracha_pointer as *mut Bracha<SessionId>) };
    let network = unsafe { &*(net_ptr as *mut GenericNetwork) };
    let payload = unsafe { slice::from_raw_parts(msg.payload.pointer, msg.payload.len) };
    let metadata = unsafe { slice::from_raw_parts(msg.metadata.pointer, msg.metadata.len) };

    let rbc_msg = Msg {
        sender_id: msg.sender_id,
        session_id: unsafe { msg.session_id.to_session_id() },
        round_id: msg.round_id,
        payload: payload.to_vec(),
        metadata: metadata.to_vec(),
        msg_type: GenericMsgType::from(&msg.msg_type),
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
    let bracha = unsafe { &*(bracha_pointer as *mut Bracha<SessionId>) };
    let network = unsafe { &*(net_ptr as *mut GenericNetwork) };
    let payload = unsafe { slice::from_raw_parts(msg.payload.pointer, msg.payload.len) };
    let metadata = unsafe { slice::from_raw_parts(msg.metadata.pointer, msg.metadata.len) };

    let rbc_msg = Msg {
        sender_id: msg.sender_id,
        session_id: unsafe { msg.session_id.to_session_id() },
        round_id: msg.round_id,
        payload: payload.to_vec(),
        metadata: metadata.to_vec(),
        msg_type: GenericMsgType::from(&msg.msg_type),
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
    let bracha = unsafe { &*(bracha_pointer as *mut Bracha<SessionId>) };
    let network = unsafe { &*(net_ptr as *mut GenericNetwork) };
    let payload = unsafe { slice::from_raw_parts(msg.payload.pointer, msg.payload.len) };
    let metadata = unsafe { slice::from_raw_parts(msg.metadata.pointer, msg.metadata.len) };

    let rbc_msg = Msg {
        sender_id: msg.sender_id,
        session_id: unsafe { msg.session_id.to_session_id() },
        round_id: msg.round_id,
        payload: payload.to_vec(),
        metadata: metadata.to_vec(),
        msg_type: GenericMsgType::from(&msg.msg_type),
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

/// Creates a new Avid instance with the given parameters.
#[no_mangle]
pub extern "C" fn avid_new(
    id: usize,
    n: usize,
    t: usize,
    k: usize,
    avid_pointer: *mut *mut AvidOpaque,
    wrapper: RbcWrapCtx,
) -> RbcErrorCode {
    let ctx = wrapper.ctx; // FfiCtx(usize)
    let call = wrapper.call;

    let rust_wrapper: RbcWrapFn<SessionId> = Arc::new(move |msg| {
        let wrapped = WrappedMessage::Rbc(msg);
        let encoded = bincode::serialize(&wrapped)?;

        let mut out_ptr = core::ptr::null_mut();
        let mut out_len = 0;

        let code = (call)(
            ctx.0 as *mut core::ffi::c_void,
            encoded.as_ptr(),
            encoded.len(),
            &mut out_ptr,
            &mut out_len,
        );

        if code != RbcErrorCode::RbcSuccess {
            return Err(RbcError::Internal(format!(
                "FFI wrapper failed with code {:?}",
                code
            )));
        }

        unsafe { Ok(Vec::from_raw_parts(out_ptr, out_len, out_len)) }
    });

    let (output_sender, _output_receiver) = tokio::sync::mpsc::channel(200);

    let res = Avid::new(id, n, t, k, output_sender, rust_wrapper);
    match res {
        Ok(a) => {
            unsafe {
                *avid_pointer = Box::into_raw(Box::new(a)) as *mut AvidOpaque;
            }
            RbcErrorCode::RbcSuccess
        }
        Err(e) => e.into(),
    }
}

#[no_mangle]
pub extern "C" fn free_avid(avid_pointer: *mut AvidOpaque) {
    if !avid_pointer.is_null() {
        unsafe {
            let _ = Box::from_raw(avid_pointer as *mut Avid<SessionId>);
        }
    }
}

#[no_mangle]
pub extern "C" fn get_avid_id(avid_pointer: *mut AvidOpaque) -> usize {
    let avid = unsafe { &mut *(avid_pointer as *mut Avid<SessionId>) };
    avid.id
}

#[no_mangle]
pub extern "C" fn get_avid_n(avid_pointer: *mut AvidOpaque) -> usize {
    let avid = unsafe { &mut *(avid_pointer as *mut Avid<SessionId>) };
    avid.n
}

#[no_mangle]
pub extern "C" fn get_avid_t(avid_pointer: *mut AvidOpaque) -> usize {
    let avid = unsafe { &mut *(avid_pointer as *mut Avid<SessionId>) };
    avid.t
}

#[no_mangle]
pub extern "C" fn sync_avid_clear_store(avid_pointer: *mut AvidOpaque) {
    let avid = unsafe { &mut *(avid_pointer as *mut Avid<SessionId>) };
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(avid.clear_store());
}

#[no_mangle]
pub extern "C" fn has_avid_session_ended(
    avid_pointer: *mut AvidOpaque,
    session_id: SessionIdBits,
    output: *mut bool,
) -> RbcErrorCode {
    let avid = unsafe { &mut *(avid_pointer as *mut Avid<SessionId>) };
    let session_id = unsafe { session_id.to_session_id() };
    let session_store = {
        let store_map = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(avid.store.lock());
        let result = store_map.get(&session_id);
        match result {
            Some(s) => s.clone(),
            None => return RbcErrorCode::RbcSessionNotFound,
        }
    };
    let s = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(session_store.lock());
    unsafe {
        *output = s.ended;
    };
    return RbcErrorCode::RbcSuccess;
}

#[no_mangle]
pub extern "C" fn get_avid_output(
    avid_pointer: *mut AvidOpaque,
    session_id: SessionIdBits,
    output: *mut ByteSlice,
) -> RbcErrorCode {
    let avid = unsafe { &mut *(avid_pointer as *mut Avid<SessionId>) };
    let session_id = unsafe { session_id.to_session_id() };
    let session_store = {
        let store_map = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(avid.store.lock());
        let result = store_map.get(&session_id);
        match result {
            Some(s) => s.clone(),
            None => return RbcErrorCode::RbcSessionNotFound,
        }
    };
    let s = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(session_store.lock());
    let out = s.output.clone();
    let mut out = ManuallyDrop::new(out);
    unsafe {
        *output = ByteSlice {
            pointer: out.as_mut_ptr(),
            len: out.len(),
        };
    };
    return RbcErrorCode::RbcSuccess;
}

#[no_mangle]
pub extern "C" fn sync_avid_init(
    avid_pointer: *mut AvidOpaque,
    payload: ByteSlice,
    session_id: SessionIdBits,
    net_ptr: *mut NetworkOpaque,
) -> RbcErrorCode {
    let payload = unsafe { slice::from_raw_parts(payload.pointer, payload.len) }.to_vec();
    let avid = unsafe { &mut *(avid_pointer as *mut Avid<SessionId>) };
    let network = unsafe { &*(net_ptr as *mut GenericNetwork) };

    let result = match network {
        GenericNetwork::FakeNetwork(n) => {
            let r = tokio::runtime::Runtime::new().unwrap().block_on(avid.init(
                payload,
                unsafe { session_id.to_session_id() },
                Arc::clone(n),
            ));
            r
        }
        GenericNetwork::QuicNetworkManager(n) => {
            let r = tokio::runtime::Runtime::new().unwrap().block_on(avid.init(
                payload,
                unsafe { session_id.to_session_id() },
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
pub extern "C" fn sync_avid_process(
    avid_pointer: *mut AvidOpaque,
    msg: RbcMsg,
    net_ptr: *mut NetworkOpaque,
) -> RbcErrorCode {
    let avid = unsafe { &*(avid_pointer as *mut Avid<SessionId>) };
    let network = unsafe { &*(net_ptr as *mut GenericNetwork) };
    let payload = unsafe { slice::from_raw_parts(msg.payload.pointer, msg.payload.len) };
    let metadata = unsafe { slice::from_raw_parts(msg.metadata.pointer, msg.metadata.len) };

    let rbc_msg = Msg {
        sender_id: msg.sender_id,
        session_id: unsafe { msg.session_id.to_session_id() },
        round_id: msg.round_id,
        payload: payload.to_vec(),
        metadata: metadata.to_vec(),
        msg_type: GenericMsgType::from(&msg.msg_type),
    };
    let result = match &*network {
        GenericNetwork::FakeNetwork(n) => tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(avid.process(rbc_msg, Arc::clone(n))),
        GenericNetwork::QuicNetworkManager(n) => tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(avid.process(rbc_msg, Arc::clone(n))),
    };

    match result {
        Ok(()) => RbcErrorCode::RbcSuccess,
        Err(e) => e.into(),
    }
}

#[no_mangle]
pub extern "C" fn sync_avid_broadcast(
    avid_pointer: *mut AvidOpaque,
    msg: RbcMsg,
    net_ptr: *mut NetworkOpaque,
) -> RbcErrorCode {
    let avid = unsafe { &*(avid_pointer as *mut Avid<SessionId>) };
    let network = unsafe { &*(net_ptr as *mut GenericNetwork) };
    let payload = unsafe { slice::from_raw_parts(msg.payload.pointer, msg.payload.len) };
    let metadata = unsafe { slice::from_raw_parts(msg.metadata.pointer, msg.metadata.len) };

    let rbc_msg = Msg {
        sender_id: msg.sender_id,
        session_id: unsafe { msg.session_id.to_session_id() },
        round_id: msg.round_id,
        payload: payload.to_vec(),
        metadata: metadata.to_vec(),
        msg_type: GenericMsgType::from(&msg.msg_type),
    };
    let result = match &*network {
        GenericNetwork::FakeNetwork(n) => tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(avid.broadcast(rbc_msg, Arc::clone(n))),
        GenericNetwork::QuicNetworkManager(n) => tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(avid.broadcast(rbc_msg, Arc::clone(n))),
    };

    match result {
        Ok(()) => RbcErrorCode::RbcSuccess,
        Err(e) => e.into(),
    }
}

#[no_mangle]
pub extern "C" fn sync_avid_send(
    avid_pointer: *mut AvidOpaque,
    msg: RbcMsg,
    net_ptr: *mut NetworkOpaque,
    recv: usize,
) -> RbcErrorCode {
    let avid = unsafe { &*(avid_pointer as *mut Avid<SessionId>) };
    let network = unsafe { &*(net_ptr as *mut GenericNetwork) };
    let payload = unsafe { slice::from_raw_parts(msg.payload.pointer, msg.payload.len) };
    let metadata = unsafe { slice::from_raw_parts(msg.metadata.pointer, msg.metadata.len) };

    let rbc_msg = Msg {
        sender_id: msg.sender_id,
        session_id: unsafe { msg.session_id.to_session_id() },
        round_id: msg.round_id,
        payload: payload.to_vec(),
        metadata: metadata.to_vec(),
        msg_type: GenericMsgType::from(&msg.msg_type),
    };
    let result = match &*network {
        GenericNetwork::FakeNetwork(n) => tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(avid.send(rbc_msg, Arc::clone(n), recv)),
        GenericNetwork::QuicNetworkManager(n) => tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(avid.send(rbc_msg, Arc::clone(n), recv)),
    };

    match result {
        Ok(()) => RbcErrorCode::RbcSuccess,
        Err(e) => e.into(),
    }
}

#[no_mangle]
pub extern "C" fn aba_new(
    id: usize,
    n: usize,
    t: usize,
    k: usize,
    aba_pointer: *mut *mut AbaOpaque,
    wrapper: RbcWrapCtx,
) -> RbcErrorCode {
    let ctx = wrapper.ctx;
    let call = wrapper.call;

    let rust_wrapper: RbcWrapFn<SessionId> = Arc::new(move |msg| {
        let wrapped = WrappedMessage::Rbc(msg);
        let encoded = bincode::serialize(&wrapped)?;

        let mut out_ptr = core::ptr::null_mut();
        let mut out_len = 0;

        let code = (call)(
            ctx.0 as *mut core::ffi::c_void,
            encoded.as_ptr(),
            encoded.len(),
            &mut out_ptr,
            &mut out_len,
        );

        if code != RbcErrorCode::RbcSuccess {
            return Err(RbcError::Internal(format!(
                "FFI wrapper failed with code {:?}",
                code
            )));
        }

        unsafe { Ok(Vec::from_raw_parts(out_ptr, out_len, out_len)) }
    });

    // ABA output channel
    let (output_sender, output_rx) = tokio::sync::mpsc::channel(200);

    let res = ABA::new(id, n, t, k, output_sender, rust_wrapper);

    match res {
        Ok(aba_instance) => {
            let inner = AbaInner {
                _aba: aba_instance,
                _output_rx: output_rx,
            };

            unsafe {
                *aba_pointer = Box::into_raw(Box::new(inner)) as *mut AbaOpaque;
            }

            RbcErrorCode::RbcSuccess
        }
        Err(e) => e.into(),
    }
}

#[no_mangle]
pub extern "C" fn free_aba(aba_pointer: *mut AbaOpaque) {
    if !aba_pointer.is_null() {
        unsafe {
            let _ = Box::from_raw(aba_pointer as *mut ABA<SessionId>);
        }
    }
}

#[no_mangle]
pub extern "C" fn get_aba_id(aba_pointer: *mut AbaOpaque) -> usize {
    let aba = unsafe { &mut *(aba_pointer as *mut ABA<SessionId>) };
    aba.id
}

#[no_mangle]
pub extern "C" fn get_aba_n(aba_pointer: *mut AbaOpaque) -> usize {
    let aba = unsafe { &mut *(aba_pointer as *mut ABA<SessionId>) };
    aba.n
}

#[no_mangle]
pub extern "C" fn get_aba_t(aba_pointer: *mut AbaOpaque) -> usize {
    let aba = unsafe { &mut *(aba_pointer as *mut ABA<SessionId>) };
    aba.t
}

#[no_mangle]
pub extern "C" fn sync_aba_clear_store(aba_pointer: *mut AbaOpaque) {
    let aba = unsafe { &mut *(aba_pointer as *mut ABA<SessionId>) };
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(aba.clear_store());
}

#[no_mangle]
pub extern "C" fn has_aba_session_ended(
    aba_pointer: *mut AbaOpaque,
    session_id: SessionIdBits,
    output: *mut bool,
) -> RbcErrorCode {
    let aba = unsafe { &mut *(aba_pointer as *mut ABA<SessionId>) };
    let session_id = unsafe { session_id.to_session_id() };
    let session_store = {
        let store_map = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(aba.store.lock());
        let result = store_map.get(&session_id);
        match result {
            Some(s) => s.clone(),
            None => return RbcErrorCode::RbcSessionNotFound,
        }
    };
    let s = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(session_store.lock());
    unsafe {
        *output = s.ended;
    };
    return RbcErrorCode::RbcSuccess;
}

#[no_mangle]
pub extern "C" fn get_aba_output(
    aba_pointer: *mut AbaOpaque,
    session_id: SessionIdBits,
    output: *mut bool,
) -> RbcErrorCode {
    let aba = unsafe { &mut *(aba_pointer as *mut ABA<SessionId>) };
    let session_id = unsafe { session_id.to_session_id() };
    let session_store = {
        let store_map = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(aba.store.lock());
        let result = store_map.get(&session_id);
        match result {
            Some(s) => s.clone(),
            None => return RbcErrorCode::RbcSessionNotFound,
        }
    };
    let s = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(session_store.lock());
    let out = s.output.clone();
    unsafe {
        *output = out;
    };
    return RbcErrorCode::RbcSuccess;
}

#[no_mangle]
pub extern "C" fn sync_aba_init(
    aba_pointer: *mut AbaOpaque,
    payload: ByteSlice,
    session_id: SessionIdBits,
    net_ptr: *mut NetworkOpaque,
) -> RbcErrorCode {
    let payload = unsafe { slice::from_raw_parts(payload.pointer, payload.len) }.to_vec();
    let aba = unsafe { &mut *(aba_pointer as *mut ABA<SessionId>) };
    let network = unsafe { &*(net_ptr as *mut GenericNetwork) };

    let result = match network {
        GenericNetwork::FakeNetwork(n) => {
            let r = tokio::runtime::Runtime::new().unwrap().block_on(aba.init(
                payload,
                unsafe { session_id.to_session_id() },
                Arc::clone(n),
            ));
            r
        }
        GenericNetwork::QuicNetworkManager(n) => {
            let r = tokio::runtime::Runtime::new().unwrap().block_on(aba.init(
                payload,
                unsafe { session_id.to_session_id() },
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
pub extern "C" fn sync_aba_process(
    aba_pointer: *mut AbaOpaque,
    msg: RbcMsg,
    net_ptr: *mut NetworkOpaque,
) -> RbcErrorCode {
    let aba = unsafe { &*(aba_pointer as *mut ABA<SessionId>) };
    let network = unsafe { &*(net_ptr as *mut GenericNetwork) };
    let payload = unsafe { slice::from_raw_parts(msg.payload.pointer, msg.payload.len) };
    let metadata = unsafe { slice::from_raw_parts(msg.metadata.pointer, msg.metadata.len) };

    let rbc_msg = Msg {
        sender_id: msg.sender_id,
        session_id: unsafe { msg.session_id.to_session_id() },
        round_id: msg.round_id,
        payload: payload.to_vec(),
        metadata: metadata.to_vec(),
        msg_type: GenericMsgType::from(&msg.msg_type),
    };
    let result = match &*network {
        GenericNetwork::FakeNetwork(n) => tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(aba.process(rbc_msg, Arc::clone(n))),
        GenericNetwork::QuicNetworkManager(n) => tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(aba.process(rbc_msg, Arc::clone(n))),
    };

    match result {
        Ok(()) => RbcErrorCode::RbcSuccess,
        Err(e) => e.into(),
    }
}

#[no_mangle]
pub extern "C" fn sync_aba_broadcast(
    aba_pointer: *mut AbaOpaque,
    msg: RbcMsg,
    net_ptr: *mut NetworkOpaque,
) -> RbcErrorCode {
    let aba = unsafe { &*(aba_pointer as *mut ABA<SessionId>) };
    let network = unsafe { &*(net_ptr as *mut GenericNetwork) };
    let payload = unsafe { slice::from_raw_parts(msg.payload.pointer, msg.payload.len) };
    let metadata = unsafe { slice::from_raw_parts(msg.metadata.pointer, msg.metadata.len) };

    let rbc_msg = Msg {
        sender_id: msg.sender_id,
        session_id: unsafe { msg.session_id.to_session_id() },
        round_id: msg.round_id,
        payload: payload.to_vec(),
        metadata: metadata.to_vec(),
        msg_type: GenericMsgType::from(&msg.msg_type),
    };
    let result = match &*network {
        GenericNetwork::FakeNetwork(n) => tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(aba.broadcast(rbc_msg, Arc::clone(n))),
        GenericNetwork::QuicNetworkManager(n) => tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(aba.broadcast(rbc_msg, Arc::clone(n))),
    };

    match result {
        Ok(()) => RbcErrorCode::RbcSuccess,
        Err(e) => e.into(),
    }
}

#[no_mangle]
pub extern "C" fn sync_aba_send(
    aba_pointer: *mut AbaOpaque,
    msg: RbcMsg,
    net_ptr: *mut NetworkOpaque,
    recv: usize,
) -> RbcErrorCode {
    let aba = unsafe { &*(aba_pointer as *mut ABA<SessionId>) };
    let network = unsafe { &*(net_ptr as *mut GenericNetwork) };
    let payload = unsafe { slice::from_raw_parts(msg.payload.pointer, msg.payload.len) };
    let metadata = unsafe { slice::from_raw_parts(msg.metadata.pointer, msg.metadata.len) };

    let rbc_msg = Msg {
        sender_id: msg.sender_id,
        session_id: unsafe { msg.session_id.to_session_id() },
        round_id: msg.round_id,
        payload: payload.to_vec(),
        metadata: metadata.to_vec(),
        msg_type: GenericMsgType::from(&msg.msg_type),
    };
    let result = match &*network {
        GenericNetwork::FakeNetwork(n) => tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(aba.send(rbc_msg, Arc::clone(n), recv)),
        GenericNetwork::QuicNetworkManager(n) => tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(aba.send(rbc_msg, Arc::clone(n), recv)),
    };

    match result {
        Ok(()) => RbcErrorCode::RbcSuccess,
        Err(e) => e.into(),
    }
}
