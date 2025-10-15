use crate::ffi::c_bindings::{
    network::{GenericNetwork, NetworkOpaque},
    ByteSlice, UsizeSlice,
};
use std::{collections::HashMap, mem::ManuallyDrop, sync::Arc};
use stoffelmpc_network::fake_network::{FakeNetwork, FakeNetworkConfig};
use stoffelnet::network_utils::ClientId;
use tokio::sync::mpsc::Receiver;

// struct that includes receivers of the FakeNetwork
pub struct FakeNetworkReceivers {
    pub node_receivers: Vec<Receiver<Vec<u8>>>,
    pub client_receivers: HashMap<ClientId, Receiver<Vec<u8>>>,
}

// opaque pointer for FakeNetworkReceivers
#[repr(C)]
pub struct FakeNetworkReceiversOpaque {
    _data: (),
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

// create FakeNetwork
#[no_mangle]
pub extern "C" fn new_fake_network(
    n_nodes: usize,
    n_clients: Option<&UsizeSlice>,
    channel_buff_size: usize,
    returned_receivers: *mut *mut FakeNetworkReceiversOpaque,
) -> *mut NetworkOpaque {
    let config = FakeNetworkConfig::new(channel_buff_size);
    let n_clients = match n_clients {
        None => None,
        Some(u) => {
            let c_vec = unsafe { Vec::from_raw_parts(u.pointer, u.len, u.len) };
            let r_vec = c_vec.clone();
            // prevent rust from dropping the pointer from C
            std::mem::forget(c_vec);
            Some(r_vec)
        }
    };

    let (network, node_receivers, client_receivers) = FakeNetwork::new(n_nodes, n_clients, config);
    // return the receivers
    let receivers = FakeNetworkReceivers {
        node_receivers,
        client_receivers,
    };
    unsafe {
        *returned_receivers = Box::into_raw(Box::new(receivers)) as *mut FakeNetworkReceiversOpaque;
    };

    let network = GenericNetwork::FakeNetwork(Arc::new(network));

    Box::into_raw(Box::new(network)) as *mut NetworkOpaque
}

#[no_mangle]
pub extern "C" fn node_receiver_recv_sync(
    receivers: *mut FakeNetworkReceiversOpaque,
    node_index: usize,
) -> ByteSlice {
    let receivers = unsafe { &mut *(receivers as *mut FakeNetworkReceivers) };
    let receiver = &mut receivers.node_receivers[node_index];
    let msg = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(receiver.recv());
    match msg {
        None => ByteSlice {
            pointer: std::ptr::null_mut(),
            len: 0,
        },
        Some(m) => {
            let mut m = ManuallyDrop::new(m);
            let slice = ByteSlice {
                pointer: m.as_mut_ptr(),
                len: m.len(),
            };
            slice
        }
    }
}
