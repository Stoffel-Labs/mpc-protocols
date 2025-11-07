pub mod fake_network;
use std::sync::Arc;

use stoffelmpc_network::fake_network::{FakeNetwork, FakeNetworkConfig};
use stoffelnet::transports::quic::QuicNetworkManager;

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
