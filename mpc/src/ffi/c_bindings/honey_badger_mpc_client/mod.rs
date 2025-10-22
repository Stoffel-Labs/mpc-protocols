use std::{ptr::slice_from_raw_parts, sync::Arc};

use ark_bls12_381::Fr;

use crate::{
    common::{rbc::rbc::Bracha, RBC},
    ffi::c_bindings::{
        network::{self, GenericNetwork},
        share::FieldKind,
        ByteSlice, U256Slice, U256,
    },
    honeybadger::{output, HoneyBadgerError, HoneyBadgerMPCClient},
};

// opaque pointer for HoneyBadgerMPCClient
#[repr(C)]
pub struct HoneyBadgerMPCClientOpaque {
    _data: (),
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

#[repr(C)]
pub enum HoneyBadgerErrorCode {
    HoneyBadgerSuccess,
    HoneyBadgerNetworkError,
    HoneyBadgerRanShaError,
    HoneyBadgerInputError,
    HoneyBadgerDouShaError,
    HoneyBadgerRanDouShaError,
    HoneyBadgerNotEnoughPreprocessing,
    HoneyBadgerTripleGenError,
    HoneyBadgerRbcError,
    HoneyBadgerMulError,
    HoneyBadgerOutputError,
    HoneyBadgerBatchReconError,
    HoneyBadgerBincodeSerializationError,
    HoneyBadgerJoinError,
    HoneyBadgerChannelClosed,
    HoneyBadgerOutputNotReady,
}

impl From<HoneyBadgerError> for HoneyBadgerErrorCode {
    fn from(value: HoneyBadgerError) -> Self {
        match value {
            HoneyBadgerError::NetworkError(_) => Self::HoneyBadgerNetworkError,
            HoneyBadgerError::RanShaError(_) => Self::HoneyBadgerRanShaError,
            HoneyBadgerError::InputError(_) => Self::HoneyBadgerInputError,
            HoneyBadgerError::DouShaError(_) => Self::HoneyBadgerDouShaError,
            HoneyBadgerError::RanDouShaError(_) => Self::HoneyBadgerRanDouShaError,
            HoneyBadgerError::NotEnoughPreprocessing => Self::HoneyBadgerNotEnoughPreprocessing,
            HoneyBadgerError::TripleGenError(_) => Self::HoneyBadgerTripleGenError,
            HoneyBadgerError::RbcError(_) => Self::HoneyBadgerRbcError,
            HoneyBadgerError::MulError(_) => Self::HoneyBadgerMulError,
            HoneyBadgerError::OutputError(_) => Self::HoneyBadgerOutputError,
            HoneyBadgerError::BatchReconError(_) => Self::HoneyBadgerBatchReconError,
            HoneyBadgerError::BincodeSerializationError(_) => {
                Self::HoneyBadgerBincodeSerializationError
            }
            HoneyBadgerError::JoinError => Self::HoneyBadgerJoinError,
            HoneyBadgerError::ChannelClosed => Self::HoneyBadgerChannelClosed,
        }
    }
}

#[no_mangle]
pub extern "C" fn new_honey_badger_mpc_client(
    id: usize,
    n: usize,
    t: usize,
    instance_id: u64,
    inputs: U256Slice,
    input_len: usize,
    field_kind: FieldKind,
) -> *mut HoneyBadgerMPCClientOpaque {
    let inputs_slice = unsafe { &*slice_from_raw_parts(inputs.pointer, inputs.len) };
    match field_kind {
        FieldKind::Bls12_381Fr => {
            let inputs_vec = inputs_slice
                .iter()
                .map(|fr| Fr::from(fr.clone()))
                .collect::<Vec<_>>();
            let client = HoneyBadgerMPCClient::<_, Bracha>::new(
                id,
                n,
                t,
                instance_id,
                inputs_vec,
                input_len,
            );
            Box::into_raw(Box::new(client)) as *mut HoneyBadgerMPCClientOpaque
        }
    }
}

#[no_mangle]
pub extern "C" fn hb_client_process(
    client_ptr: *mut HoneyBadgerMPCClientOpaque,
    net_ptr: *mut network::NetworkOpaque,
    raw_msg: ByteSlice,
) -> HoneyBadgerErrorCode {
    let client = unsafe { &mut *(client_ptr as *mut HoneyBadgerMPCClient<Fr, Bracha>) };
    let network = unsafe { &*(net_ptr as *mut network::GenericNetwork) };
    let msg_slice = unsafe { &*slice_from_raw_parts(raw_msg.pointer, raw_msg.len) };
    let msg = msg_slice.to_vec();
    let result = match network {
        GenericNetwork::FakeNetwork(n) => tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(client.process(msg, Arc::clone(n))),
        GenericNetwork::QuicNetworkManager(n) => tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(client.process(msg, Arc::clone(n))),
    };
    match result {
        Ok(_) => HoneyBadgerErrorCode::HoneyBadgerSuccess,
        Err(e) => e.into(),
    }
}

#[no_mangle]
pub extern "C" fn hb_client_get_output(
    client_ptr: *mut HoneyBadgerMPCClientOpaque,
    returned_output: *mut U256,
    field_kind: FieldKind,
) -> HoneyBadgerErrorCode {
    match field_kind {
        FieldKind::Bls12_381Fr => {
            let client = unsafe { &mut *(client_ptr as *mut HoneyBadgerMPCClient<Fr, Bracha>) };
            let output_client = &client.output;
            let output = output_client.output;
            match output {
                None => return HoneyBadgerErrorCode::HoneyBadgerOutputNotReady,
                Some(out) => unsafe { *returned_output = out.into() },
            }
            HoneyBadgerErrorCode::HoneyBadgerSuccess
        }
    }
}

#[no_mangle]
pub extern "C" fn free_honey_badger_mpc_client(client_ptr: *mut HoneyBadgerMPCClientOpaque) {
    if !client_ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(client_ptr as *mut HoneyBadgerMPCClient<Fr, Bracha>);
        }
    }
}
