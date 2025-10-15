pub mod fake_network;
pub mod quic;
use std::slice;
use std::sync::Arc;

use stoffelmpc_network::fake_network::FakeNetwork;
use stoffelnet::network_utils::{Network, NetworkError};
use stoffelnet::transports::quic::QuicNetworkManager;

use crate::ffi::c_bindings::ByteSlice;
#[repr(C)]
pub enum NetworkErrorCode {
    NetworkSuccess,
    IncorrectNetworkType,
    IncorrectSockAddr,
    ConnectError,
    NetworkAlreadyInUse,
    RecvError,
    SendError,
    Timeout,
    PartyNotFound,
    ClientNotFound,
}

impl From<NetworkError> for NetworkErrorCode {
    fn from(value: NetworkError) -> Self {
        match value {
            NetworkError::SendError => Self::SendError,
            NetworkError::Timeout => Self::Timeout,
            NetworkError::PartyNotFound(_) => Self::PartyNotFound,
            NetworkError::ClientNotFound(_) => Self::ClientNotFound,
        }
    }
}

// opaque pointer for GenericNetwork
#[repr(C)]
pub struct NetworkOpaque {
    _data: (),
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

pub enum GenericNetwork {
    FakeNetwork(Arc<FakeNetwork>),
    QuicNetworkManager(Arc<QuicNetworkManager>),
}

#[no_mangle]
pub extern "C" fn free_network(network: *mut NetworkOpaque) {
    if !network.is_null() {
        unsafe {
            let _ = Box::from_raw(network as *mut GenericNetwork);
        }
    }
}

#[no_mangle]
pub extern "C" fn clone_network(network: *mut NetworkOpaque) -> *mut NetworkOpaque {
    if network.is_null() {
        return std::ptr::null_mut();
    }
    let net = unsafe { &*(network as *mut GenericNetwork) };
    let cloned = match net {
        GenericNetwork::FakeNetwork(n) => GenericNetwork::FakeNetwork(Arc::clone(n)),
        GenericNetwork::QuicNetworkManager(n) => GenericNetwork::QuicNetworkManager(Arc::clone(n)),
    };
    Box::into_raw(Box::new(cloned)) as *mut NetworkOpaque
}

#[no_mangle]
pub extern "C" fn network_send(
    net_ptr: *mut NetworkOpaque,
    recipient_id: usize,
    message: ByteSlice,
    sent_size: *mut usize,
) -> NetworkErrorCode {
    let network = unsafe { &*(net_ptr as *mut GenericNetwork) };
    let message = unsafe { slice::from_raw_parts(message.pointer, message.len) };
    let res = match &*network {
        GenericNetwork::FakeNetwork(n) => tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(n.send(recipient_id, message)),
        GenericNetwork::QuicNetworkManager(n) => tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(n.send(recipient_id, message)),
    };
    match res {
        Ok(u) => {
            unsafe {
                *sent_size = u;
            };
            return NetworkErrorCode::NetworkSuccess;
        }
        Err(e) => return e.into(),
    }
}
