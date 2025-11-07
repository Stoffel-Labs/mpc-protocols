use std::{
    alloc::GlobalAlloc,
    collections::HashMap,
    ffi::{c_char, CStr, CString},
    mem::{self, ManuallyDrop},
    net::SocketAddr,
    slice,
    str::FromStr,
    sync::{Arc, LazyLock},
};

use rustls::crypto::hash::Hash;
use stoffelnet::{
    network_utils::{ClientId, PartyId},
    transports::quic::{NetworkManager, PeerConnection, QuicNetworkManager},
};

use crate::ffi::c_bindings::{
    network::{GenericNetwork, NetworkErrorCode, NetworkOpaque},
    ByteSlice,
};

//struct that includes connections of the QuicPeerConnections
pub struct QuicPeerConnections {
    pub connections: HashMap<SocketAddr, Arc<dyn PeerConnection>>,
}

pub struct QuicNetwork {
    quic_manager: QuicNetworkManager,
    // runtime: tokio::runtime::Runtime,
}

static GLOBAL_RUNTIME: LazyLock<tokio::runtime::Runtime> =
    LazyLock::new(|| tokio::runtime::Runtime::new().unwrap());

//opaque pointer for QuicPeerConnections
#[repr(C)]
pub struct QuicPeerConnectionsOpaque {
    _data: (),
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

#[repr(C)]
pub struct QuicNetworkOpaque {
    _data: (),
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

#[repr(C)]
pub struct RuntimeOpauqe {
    _data: (),
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

/// Select crypto provider for rustls
/// Must be called before using quic network
#[no_mangle]
pub extern "C" fn init_tls() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");
}

/// Creates a new QUIC network instance
///
/// This initializes a network manager with no active endpoints or configurations.
/// Before using the manager, you must call either `connect()` or `listen()`
/// to set up the appropriate endpoint.
/// It also initializes a peer connection map.
#[no_mangle]
pub extern "C" fn new_quic_network(
    returned_connections: *mut *mut QuicPeerConnectionsOpaque,
) -> *mut QuicNetworkOpaque {
    let quic_network = QuicNetwork {
        quic_manager: QuicNetworkManager::new(),
    };
    let peer_connections = QuicPeerConnections {
        connections: HashMap::new(),
    };
    unsafe {
        *returned_connections =
            Box::into_raw(Box::new(peer_connections)) as *mut QuicPeerConnectionsOpaque;
    }

    Box::into_raw(Box::new(quic_network)) as *mut QuicNetworkOpaque
}

/// Establishes a connection to a new peer
///
/// This method initiates an outgoing connection to a peer at the specified address.
/// It handles the connection establishment process, including any necessary
/// handshaking, encryption setup, and protocol negotiation.
///
/// # Arguments
/// * `address` - The network address of the peer to connect to
#[no_mangle]
pub extern "C" fn quic_connect(
    quic_network_ptr: *mut QuicNetworkOpaque,
    peer_connections: *mut QuicPeerConnectionsOpaque,
    addr: *const c_char,
) -> NetworkErrorCode {
    let quic_network = unsafe { &mut *(quic_network_ptr as *mut QuicNetwork) };
    let peer_connections = unsafe { &mut *(peer_connections as *mut QuicPeerConnections) };
    let addr = unsafe { CStr::from_ptr(addr) };
    let addr = match addr.to_str() {
        Ok(a) => a,
        Err(_) => return NetworkErrorCode::IncorrectSockAddr,
    };
    let address: SocketAddr = match addr.parse() {
        Ok(a) => a,
        Err(_) => return NetworkErrorCode::IncorrectSockAddr,
    };

    let f = quic_network.quic_manager.connect(address);
    let r = GLOBAL_RUNTIME.block_on(f);
    match r {
        Ok(connection) => {
            peer_connections
                .connections
                .insert(connection.remote_address(), connection);
            return NetworkErrorCode::NetworkSuccess;
        }
        Err(_) => {
            return NetworkErrorCode::ConnectError;
        }
    }
}

/// Accepts an incoming connection
///
/// This method accepts a pending incoming connection from a peer.
/// It should be called after `listen()` has been called to set up
/// the listening endpoint.
///
/// This method will block until a connection is available or an error occurs.
#[no_mangle]
pub extern "C" fn quic_accept(
    quic_network_ptr: *mut QuicNetworkOpaque,
    peer_connections: *mut QuicPeerConnectionsOpaque,
    connected_addr: *mut *mut c_char,
) -> NetworkErrorCode {
    let quic_network = unsafe { &mut *(quic_network_ptr as *mut QuicNetwork) };
    let peer_connections = unsafe { &mut *(peer_connections as *mut QuicPeerConnections) };
    let f = quic_network.quic_manager.accept();
    let r = GLOBAL_RUNTIME.block_on(f);
    match r {
        Ok(connection) => {
            let addr = connection.remote_address().to_string();
            let addr = CString::from_str(&addr).unwrap();
            unsafe { *connected_addr = addr.into_raw() };

            peer_connections
                .connections
                .insert(connection.remote_address(), connection);
            return NetworkErrorCode::NetworkSuccess;
        }
        Err(_) => {
            return NetworkErrorCode::ConnectError;
        }
    }
}

/// Listens for incoming connections
///
/// This method sets up a network endpoint to listen for incoming connections
/// at the specified address. After calling this method, `accept()` can be
/// called to accept incoming connections.
///
/// # Arguments
/// * `bind_address` - The local address to bind to for listening
#[no_mangle]
pub extern "C" fn quic_listen(
    quic_network_ptr: *mut QuicNetworkOpaque,
    bind_address: *const c_char,
) -> NetworkErrorCode {
    let quic_network = unsafe { &mut *(quic_network_ptr as *mut QuicNetwork) };
    let bind_address = unsafe { CStr::from_ptr(bind_address) };
    let bind_address = match bind_address.to_str() {
        Ok(a) => a,
        Err(_) => return NetworkErrorCode::IncorrectSockAddr,
    };
    let bind_address: SocketAddr = match bind_address.parse() {
        Ok(a) => a,
        Err(_) => return NetworkErrorCode::IncorrectSockAddr,
    };
    let f = quic_network.quic_manager.listen(bind_address);
    let r = GLOBAL_RUNTIME.block_on(f);
    match r {
        Ok(_) => return NetworkErrorCode::NetworkSuccess,
        Err(_) => return NetworkErrorCode::ConnectError,
    }
}

/// Cast a QUIC network into HoneyBadgerMPC network.
/// This method will comsume the original pointer and set it to Null.
/// Make sure to finish QUIC setup before this function.
#[no_mangle]
pub extern "C" fn quic_into_hb_network(
    quic_network_ptr: *mut *mut QuicNetworkOpaque,
) -> *mut NetworkOpaque {
    let quic_network = unsafe { Box::from_raw(*quic_network_ptr as *mut QuicNetwork) };
    let net = GenericNetwork::QuicNetworkManager(Arc::new(quic_network.quic_manager));
    unsafe { *quic_network_ptr = std::ptr::null_mut() }
    Box::into_raw(Box::new(net)) as *mut NetworkOpaque
}

#[no_mangle]
pub extern "C" fn quic_receive_from_sync(
    peer_connections: *mut QuicPeerConnectionsOpaque,
    addr: *const c_char,
    msg: *mut ByteSlice,
) -> NetworkErrorCode {
    let peer_connections = unsafe { &mut *(peer_connections as *mut QuicPeerConnections) };
    let addr = unsafe { CStr::from_ptr(addr) };
    let addr = match addr.to_str() {
        Ok(a) => a,
        Err(_) => return NetworkErrorCode::IncorrectSockAddr,
    };
    let addr: SocketAddr = match addr.parse() {
        Ok(a) => a,
        Err(_) => return NetworkErrorCode::IncorrectSockAddr,
    };
    let connection = match peer_connections.connections.get(&addr) {
        Some(c) => c,
        None => return NetworkErrorCode::IncorrectSockAddr,
    };
    let f = connection.receive();
    match GLOBAL_RUNTIME.block_on(f) {
        Ok(m) => {
            let mut m = ManuallyDrop::new(m);
            unsafe {
                *msg = ByteSlice {
                    pointer: m.as_mut_ptr(),
                    len: m.len(),
                }
            }
            return NetworkErrorCode::NetworkSuccess;
        }
        Err(_) => {
            unsafe {
                *msg = ByteSlice {
                    pointer: std::ptr::null_mut(),
                    len: 0,
                };
            }
            return NetworkErrorCode::RecvError;
        }
    };
}

#[no_mangle]
pub extern "C" fn quic_send(
    peer_connections: *mut QuicPeerConnectionsOpaque,
    recp: *const c_char,
    msg: ByteSlice,
) -> NetworkErrorCode {
    let peer_connections = unsafe { &mut *(peer_connections as *mut QuicPeerConnections) };
    let msg = unsafe { slice::from_raw_parts(msg.pointer, msg.len) };
    let addr = unsafe { CStr::from_ptr(recp) };
    let addr = match addr.to_str() {
        Ok(a) => a,
        Err(_) => return NetworkErrorCode::IncorrectSockAddr,
    };
    let addr: SocketAddr = match addr.parse() {
        Ok(a) => a,
        Err(_) => return NetworkErrorCode::IncorrectSockAddr,
    };
    let connection = match peer_connections.connections.get_mut(&addr) {
        Some(c) => c,
        None => return NetworkErrorCode::IncorrectSockAddr,
    };
    let r = GLOBAL_RUNTIME.block_on(connection.send(msg));
    match r {
        Ok(_) => NetworkErrorCode::NetworkSuccess,
        Err(_) => NetworkErrorCode::SendError,
    }
}

#[no_mangle]
pub extern "C" fn free_quic_network(quic_network_ptr: *mut QuicNetworkOpaque) {
    if !quic_network_ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(quic_network_ptr as *mut QuicNetwork);
        }
    }
}

#[no_mangle]
pub extern "C" fn free_quic_peer_connections(peer_connections: *mut QuicPeerConnectionsOpaque) {
    if !peer_connections.is_null() {
        unsafe {
            let _ = Box::from_raw(peer_connections as *mut QuicPeerConnections);
        }
    }
}
