use ark_bls12_381::Fr;
use ark_ff::{BigInt, BigInteger, PrimeField};
use std::slice;

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
