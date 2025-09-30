use ark_bls12_381::Fr;
use ark_ff::{BigInt, BigInteger, PrimeField};
use std::slice;

use crate::honeybadger::SessionId;

pub mod network;
pub mod rbc;
pub mod share;

// a sequence of `u64` limbs, least-significant limb first
#[repr(C)]
#[derive(Clone, Debug)]
pub struct Bls12Fr {
    pub data: [u64; 4],
}

// &[Bls12Fr] pointer and length
#[repr(C)]
pub struct Bls12FrSlice {
    pub pointer: *mut Bls12Fr,
    pub len: usize,
}

// &[u8] pointer and length
#[repr(C)]
pub struct ByteSlice {
    pub pointer: *mut u8,
    pub len: usize,
}

impl From<Bls12Fr> for Fr {
    fn from(value: Bls12Fr) -> Self {
        Fr::from_bigint(BigInt::new(value.data)).unwrap()
    }
}

impl From<Fr> for Bls12Fr {
    fn from(value: Fr) -> Self {
        Self {
            data: value.into_bigint().0,
        }
    }
}

// &[usize] pointer and length
#[repr(C)]
pub struct UsizeSlice {
    pub pointer: *mut usize,
    pub len: usize,
}

// Used for re-routing inter-protocol messages
#[repr(C)]
pub enum ProtocolType {
    None = 0,
    Randousha = 1,
    Ransha = 2,
    Input = 3,
    Rbc = 4,
    Triple = 5,
    BatchRecon = 6,
    Dousha = 7,
    Mul = 8,
}

impl From<ProtocolType> for crate::honeybadger::ProtocolType {
    fn from(value: ProtocolType) -> Self {
        match value {
            ProtocolType::None => crate::honeybadger::ProtocolType::None,
            ProtocolType::Randousha => crate::honeybadger::ProtocolType::Randousha,
            ProtocolType::Ransha => crate::honeybadger::ProtocolType::Ransha,
            ProtocolType::Input => crate::honeybadger::ProtocolType::Input,
            ProtocolType::Rbc => crate::honeybadger::ProtocolType::Rbc,
            ProtocolType::Triple => crate::honeybadger::ProtocolType::Triple,
            ProtocolType::BatchRecon => crate::honeybadger::ProtocolType::BatchRecon,
            ProtocolType::Dousha => crate::honeybadger::ProtocolType::Dousha,
            ProtocolType::Mul => crate::honeybadger::ProtocolType::Mul,
        }
    }
}

impl From<crate::honeybadger::ProtocolType> for ProtocolType {
    fn from(value: crate::honeybadger::ProtocolType) -> Self {
        match value {
            crate::honeybadger::ProtocolType::None => ProtocolType::None,
            crate::honeybadger::ProtocolType::Randousha => ProtocolType::Randousha,
            crate::honeybadger::ProtocolType::Ransha => ProtocolType::Ransha,
            crate::honeybadger::ProtocolType::Input => ProtocolType::Input,
            crate::honeybadger::ProtocolType::Rbc => ProtocolType::Rbc,
            crate::honeybadger::ProtocolType::Triple => ProtocolType::Triple,
            crate::honeybadger::ProtocolType::BatchRecon => ProtocolType::BatchRecon,
            crate::honeybadger::ProtocolType::Dousha => ProtocolType::Dousha,
            crate::honeybadger::ProtocolType::Mul => ProtocolType::Mul,
        }
    }
}

// free the memory of a Bls12FrSlice
#[no_mangle]
pub extern "C" fn free_bls12_fr_slice(slice: Bls12FrSlice) {
    if !slice.pointer.is_null() {
        unsafe {
            let _ = Vec::from_raw_parts(slice.pointer, slice.len, slice.len);
        }
    }
}

// free the memory of a ByteSlice
#[no_mangle]
pub extern "C" fn free_bytes_slice(slice: ByteSlice) {
    if !slice.pointer.is_null() {
        unsafe {
            let _ = Vec::from_raw_parts(slice.pointer, slice.len, slice.len);
        }
    }
}

#[no_mangle]
pub extern "C" fn be_bytes_to_bls12_fr(bytes: ByteSlice) -> Bls12Fr {
    let bytes_slice = unsafe { slice::from_raw_parts(bytes.pointer, bytes.len) };
    Bls12Fr {
        data: Fr::from_be_bytes_mod_order(bytes_slice).into_bigint().0,
    }
}

#[no_mangle]
pub extern "C" fn le_bytes_to_bls12_fr(bytes: ByteSlice) -> Bls12Fr {
    let bytes_slice = unsafe { slice::from_raw_parts(bytes.pointer, bytes.len) };
    Bls12Fr {
        data: Fr::from_le_bytes_mod_order(bytes_slice).into_bigint().0,
    }
}

#[no_mangle]
pub extern "C" fn bls12_fr_to_be_bytes(fr: Bls12Fr) -> ByteSlice {
    let mut bytes = BigInt::new(fr.data).to_bytes_be();
    ByteSlice {
        pointer: bytes.as_mut_ptr(),
        len: bytes.len(),
    }
}

#[no_mangle]
pub extern "C" fn bls12_fr_to_le_bytes(fr: Bls12Fr) -> ByteSlice {
    let mut bytes = BigInt::new(fr.data).to_bytes_le();
    ByteSlice {
        pointer: bytes.as_mut_ptr(),
        len: bytes.len(),
    }
}

#[no_mangle]
pub extern "C" fn new_session_id(
    caller: ProtocolType,
    sub_id: u8,
    round_id: u8,
    instance_id: u64,
) -> u64 {
    let session_id = SessionId::new(caller.into(), sub_id, round_id, instance_id);
    session_id.as_u64()
}

#[no_mangle]
pub extern "C" fn calling_protocol(session_id: u64) -> ProtocolType {
    let session_id = unsafe { SessionId::from_u64(session_id) };
    session_id.calling_protocol().unwrap().into()
}

#[no_mangle]
pub extern "C" fn sub_id(session_id: u64) -> u8 {
    let session_id = unsafe { SessionId::from_u64(session_id) };
    session_id.sub_id()
}

#[no_mangle]
pub extern "C" fn round_id(session_id: u64) -> u8 {
    let session_id = unsafe { SessionId::from_u64(session_id) };
    session_id.round_id()
}

#[no_mangle]
pub extern "C" fn instance_id(session_id: u64) -> u64 {
    let session_id = unsafe { SessionId::from_u64(session_id) };
    session_id.instance_id()
}
