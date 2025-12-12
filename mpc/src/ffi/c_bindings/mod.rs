use ark_bls12_381::Fr;
use ark_ff::biginteger;
use ark_ff::{BigInt, BigInteger, PrimeField};
use num_bigint::BigUint;
use std::{
    ffi::{c_char, CString},
    slice,
};

use crate::honeybadger::SessionId;

pub mod honey_badger_mpc_client;
pub mod network;
pub mod rbc;
pub mod share;

// a sequence of `u64` limbs, least-significant limb first
#[repr(C)]
#[derive(Clone, Debug)]
pub struct U256 {
    pub data: [u64; 4],
}

// &[U256] pointer and length
#[repr(C)]
pub struct U256Slice {
    pub pointer: *mut U256,
    pub len: usize,
}

// &[u8] pointer and length
#[repr(C)]
pub struct ByteSlice {
    pub pointer: *mut u8,
    pub len: usize,
}

impl From<U256> for Fr {
    fn from(value: U256) -> Self {
        Fr::from_bigint(BigInt::new(value.data)).unwrap()
    }
}

impl From<Fr> for U256 {
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
    PRandInt = 9,
    PRandBit = 10,
    RandBit = 11,
    FpMul = 12,
    Trunc = 13,
    FpDivConst = 14,
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
            ProtocolType::PRandInt => crate::honeybadger::ProtocolType::PRandInt,
            ProtocolType::PRandBit => crate::honeybadger::ProtocolType::PRandBit,
            ProtocolType::RandBit => crate::honeybadger::ProtocolType::RandBit,
            ProtocolType::FpMul => crate::honeybadger::ProtocolType::FpMul,
            ProtocolType::Trunc => crate::honeybadger::ProtocolType::Trunc,
            ProtocolType::FpDivConst => crate::honeybadger::ProtocolType::FpDivConst,
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
            crate::honeybadger::ProtocolType::PRandInt => ProtocolType::PRandInt,
            crate::honeybadger::ProtocolType::PRandBit => ProtocolType::RandBit,
            crate::honeybadger::ProtocolType::RandBit => ProtocolType::RandBit,
            crate::honeybadger::ProtocolType::FpMul => ProtocolType::FpMul,
            crate::honeybadger::ProtocolType::Trunc => ProtocolType::Trunc,
            crate::honeybadger::ProtocolType::FpDivConst => ProtocolType::FpDivConst,
        }
    }
}

// free the memory of a U256Slice
#[no_mangle]
pub extern "C" fn free_u256_slice(slice: U256Slice) {
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

// free the memory of a CString
#[no_mangle]
pub extern "C" fn free_c_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

#[no_mangle]
pub extern "C" fn be_bytes_to_u256(bytes: ByteSlice) -> U256 {
    let bytes_slice = unsafe { slice::from_raw_parts(bytes.pointer, bytes.len) };
    let big_uint = BigInt::<4>::try_from(BigUint::from_bytes_be(bytes_slice))
        .expect("bytes too long for u256");
    U256 { data: big_uint.0 }
}

#[no_mangle]
pub extern "C" fn le_bytes_to_u256(bytes: ByteSlice) -> U256 {
    let bytes_slice = unsafe { slice::from_raw_parts(bytes.pointer, bytes.len) };
    let big_uint = BigInt::<4>::try_from(BigUint::from_bytes_le(bytes_slice))
        .expect("bytes too long for u256");
    U256 { data: big_uint.0 }
}

#[no_mangle]
pub extern "C" fn u256_to_be_bytes(num: U256) -> ByteSlice {
    let mut bytes = BigInt::new(num.data).to_bytes_be();
    ByteSlice {
        pointer: bytes.as_mut_ptr(),
        len: bytes.len(),
    }
}

#[no_mangle]
pub extern "C" fn u256_to_le_bytes(num: U256) -> ByteSlice {
    let mut bytes = BigInt::new(num.data).to_bytes_le();
    ByteSlice {
        pointer: bytes.as_mut_ptr(),
        len: bytes.len(),
    }
}

#[no_mangle]
pub extern "C" fn new_session_id(
    caller: ProtocolType,
    exec_id: u8,
    sub_id: u8,
    round_id: u8,
    instance_id: u32,
) -> u64 {
    let session_id = SessionId::new(caller.into(), exec_id, sub_id, round_id, instance_id);
    session_id.as_u64()
}

#[no_mangle]
pub extern "C" fn calling_protocol(session_id: u64) -> ProtocolType {
    let session_id = unsafe { SessionId::from_u64(session_id) };
    session_id.calling_protocol().unwrap().into()
}

#[no_mangle]
pub extern "C" fn exec_id(session_id: u64) -> u8 {
    let session_id = unsafe { SessionId::from_u64(session_id) };
    session_id.exec_id()
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
pub extern "C" fn instance_id(session_id: u64) -> u32 {
    let session_id = unsafe { SessionId::from_u64(session_id) };
    session_id.instance_id()
}
