use std::{any::TypeId, mem::ManuallyDrop, slice};

use ark_bls12_381::Fr;
use ark_ff::{BigInteger, FftField, PrimeField};

use crate::{
    common::{
        share::{
            shamir::{self, Shamirshare},
            ShareError,
        },
        SecretSharingScheme,
    },
    ffi::c_bindings::{ByteSlice, U256Slice, UsizeSlice, U256},
    honeybadger::robust_interpolate::{robust_interpolate, InterpolateError},
};

#[repr(C)]
pub enum ShareErrorCode {
    ShareSuccess,
    // Insufficient shares to reconstruct the secret
    InsufficientShares,
    // Mismatch degree between shares
    DegreeMismatch,
    // Mismatch index between shares
    IdMismatch,
    // Errors specific to invalid input parameters or conditions
    InvalidInput,
    // Types are different
    TypeMismatch,
    // No suitable FFT evaluation domain could be found
    NoSuitableDomain,
    // Errors related to polynomial operations, potentially with an underlying cause.
    PolynomialOperationError,
    // Errors that occur during the decoding process.
    DecodingError,
}
// opaque pointer for GenericField
#[repr(C)]
pub struct FieldOpaque {
    _data: (),
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

pub enum GenericField {
    Bls12_381Fr(Fr),
}

#[repr(C)]
pub enum FieldKind {
    Bls12_381Fr,
}

#[no_mangle]
pub extern "C" fn field_ptr_to_bytes(field: *mut FieldOpaque, be: bool) -> ByteSlice {
    let field_ref = unsafe { &*(field as *mut GenericField) };
    match field_ref {
        GenericField::Bls12_381Fr(f) => {
            let bytes = if be {
                f.into_bigint().to_bytes_be()
            } else {
                f.into_bigint().to_bytes_le()
            };
            let mut bytes = ManuallyDrop::new(bytes);
            ByteSlice {
                pointer: bytes.as_mut_ptr(),
                len: bytes.len(),
            }
        }
    }
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct ShamirShare {
    pub share: *mut FieldOpaque,
    pub id: usize,
    pub degree: usize,
}

#[repr(C)]
pub struct ShamirShareSlice {
    pub pointer: *mut ShamirShare,
    pub len: usize,
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct RobustShare {
    pub share: *mut FieldOpaque,
    pub id: usize,
    pub degree: usize,
}

#[repr(C)]
pub struct RobustShareSlice {
    pub pointer: *mut RobustShare,
    pub len: usize,
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct NonRobustShare {
    pub share: *mut FieldOpaque,
    pub id: usize,
    pub degree: usize,
}

#[repr(C)]
pub struct NonRobustShareSlice {
    pub pointer: *mut NonRobustShare,
    pub len: usize,
}

// free the memory of a ShamirshareSlice
#[no_mangle]
pub extern "C" fn free_shamir_share_slice(slice: ShamirShareSlice) {
    if !slice.pointer.is_null() {
        unsafe {
            let _ = Vec::from_raw_parts(slice.pointer, slice.len, slice.len);
        }
    }
}

// free the memory of a RobustShareSlice
#[no_mangle]
pub extern "C" fn free_robust_share_slice(slice: RobustShareSlice) {
    if !slice.pointer.is_null() {
        unsafe {
            let _ = Vec::from_raw_parts(slice.pointer, slice.len, slice.len);
        }
    }
}

// free the memory of a NonRobustShareSlice
#[no_mangle]
pub extern "C" fn free_non_robust_share_slice(slice: NonRobustShareSlice) {
    if !slice.pointer.is_null() {
        unsafe {
            let _ = Vec::from_raw_parts(slice.pointer, slice.len, slice.len);
        }
    }
}
impl From<ShamirShare> for Shamirshare<Fr> {
    fn from(value: ShamirShare) -> Self {
        let share_field = unsafe { &*(value.share as *mut GenericField) };
        let share_value = match share_field {
            GenericField::Bls12_381Fr(f) => *f,
        };
        Shamirshare::<Fr>::new(share_value, value.id, value.degree, None)
    }
}

impl From<Shamirshare<Fr>> for ShamirShare {
    fn from(value: Shamirshare<Fr>) -> Self {
        let share_enum = GenericField::Bls12_381Fr(value.share[0]);
        let share_ptr = Box::into_raw(Box::new(share_enum)) as *mut FieldOpaque;
        Self {
            share: share_ptr,
            id: value.id,
            degree: value.degree,
        }
    }
}

impl From<RobustShare> for robust_interpolate::RobustShare<Fr> {
    fn from(value: RobustShare) -> Self {
        let share_field = unsafe { &*(value.share as *mut GenericField) };
        let share_value = match share_field {
            GenericField::Bls12_381Fr(f) => *f,
        };
        robust_interpolate::RobustShare::<Fr>::new(share_value, value.id, value.degree)
    }
}

impl From<robust_interpolate::RobustShare<Fr>> for RobustShare {
    fn from(value: robust_interpolate::RobustShare<Fr>) -> Self {
        let share_enum = GenericField::Bls12_381Fr(value.share[0]);
        let share_ptr = Box::into_raw(Box::new(share_enum)) as *mut FieldOpaque;
        Self {
            share: share_ptr,
            id: value.id,
            degree: value.degree,
        }
    }
}

impl From<NonRobustShare> for shamir::NonRobustShare<Fr> {
    fn from(value: NonRobustShare) -> Self {
        let share_field = unsafe { &*(value.share as *mut GenericField) };
        let share_value = match share_field {
            GenericField::Bls12_381Fr(f) => *f,
        };
        shamir::NonRobustShare::<Fr>::new(share_value, value.id, value.degree)
    }
}

impl From<shamir::NonRobustShare<Fr>> for NonRobustShare {
    fn from(value: shamir::NonRobustShare<Fr>) -> Self {
        let share_enum = GenericField::Bls12_381Fr(value.share[0]);
        let share_ptr = Box::into_raw(Box::new(share_enum)) as *mut FieldOpaque;
        Self {
            share: share_ptr,
            id: value.id,
            degree: value.degree,
        }
    }
}

impl From<ShareError> for ShareErrorCode {
    fn from(e: ShareError) -> Self {
        match e {
            ShareError::InsufficientShares => Self::InsufficientShares,
            ShareError::DegreeMismatch => Self::DegreeMismatch,
            ShareError::IdMismatch => Self::IdMismatch,
            ShareError::InvalidInput => Self::InvalidInput,
            ShareError::TypeMismatch => Self::TypeMismatch,
            ShareError::NoSuitableDomain(_) => Self::NoSuitableDomain,
        }
    }
}

impl From<InterpolateError> for ShareErrorCode {
    fn from(e: InterpolateError) -> Self {
        match e {
            InterpolateError::PolynomialOperationError(_) => Self::PolynomialOperationError,
            InterpolateError::InvalidInput(_) => Self::InvalidInput,
            InterpolateError::DecodingError(_) => Self::DecodingError,
            InterpolateError::NoSuitableDomain(_) => Self::NoSuitableDomain,
            InterpolateError::ShareError(se) => se.into(),
        }
    }
}

// create new Shamirshare
#[no_mangle]
pub extern "C" fn shamir_share_new(
    secret: U256,
    id: usize,
    degree: usize,
    field_kind: FieldKind,
) -> ShamirShare {
    match field_kind {
        FieldKind::Bls12_381Fr => {
            let share = Shamirshare::<Fr>::new(secret.into(), id, degree, None).into();
            return share;
        }
    };
}

// compute the shamir shares of all ids for a secret
#[no_mangle]
pub extern "C" fn shamir_share_compute_shares(
    secret: U256,
    degree: usize,
    ids: Option<&UsizeSlice>,
    field_kind: FieldKind,
    output_shares: *mut ShamirShareSlice,
) -> ShareErrorCode {
    let mut rng = ark_std::rand::thread_rng();
    let ids = ids.and_then(|ids| {
        let ids_slice = unsafe { slice::from_raw_parts(ids.pointer, ids.len) };
        Some(ids_slice)
    });
    match field_kind {
        FieldKind::Bls12_381Fr => {
            let compute_result: Result<Vec<Shamirshare<Fr>>, ShareError> =
                Shamirshare::compute_shares(secret.into(), 0, degree, ids, &mut rng);
            match compute_result {
                Ok(shares) => {
                    let shares_vec = shares
                        .into_iter()
                        .map(|share| share.into())
                        .collect::<Vec<ShamirShare>>();
                    // prevent Rust from dropping the vec
                    let mut shares_vec = ManuallyDrop::new(shares_vec);
                    unsafe {
                        *output_shares = ShamirShareSlice {
                            pointer: shares_vec.as_mut_ptr(),
                            len: shares_vec.len(),
                        };
                    };
                    return ShareErrorCode::ShareSuccess;
                }
                Err(e) => return e.into(),
            }
        }
    }
}

// recover the secret of the input shares
#[no_mangle]
pub extern "C" fn shamir_share_recover_secret(
    shares: ShamirShareSlice,
    output_secret: *mut U256,
    output_coeffs: *mut U256Slice,
    field_kind: FieldKind,
) -> ShareErrorCode {
    let shares_slice = unsafe { Vec::from_raw_parts(shares.pointer, shares.len, shares.len) };
    // since the pointer comes from C, we should not drop it here
    // use free_shamir_share_bls12_slice() instead
    let shares_slice = ManuallyDrop::new(shares_slice);
    match field_kind {
        FieldKind::Bls12_381Fr => {
            let shares = shares_slice
                .iter()
                .map(|f| f.clone().into())
                .collect::<Vec<Shamirshare<Fr>>>();
            let recover_result = Shamirshare::recover_secret(&shares, 0);
            match recover_result {
                Ok((coeffs, secret)) => {
                    let bls12fr_coeffs =
                        coeffs.into_iter().map(|c| c.into()).collect::<Vec<U256>>();
                    // prevent Rust from dropping the vec
                    let mut bls12fr_coeffs = ManuallyDrop::new(bls12fr_coeffs);
                    let coeffs_pointer = U256Slice {
                        pointer: bls12fr_coeffs.as_mut_ptr(),
                        len: bls12fr_coeffs.len(),
                    };
                    // store results to the pointer
                    unsafe {
                        *output_coeffs = coeffs_pointer;
                        *output_secret = secret.into();
                    }

                    return ShareErrorCode::ShareSuccess;
                }
                Err(e) => return e.into(),
            }
        }
    }
}

// create new RobustShare
#[no_mangle]
pub extern "C" fn robust_share_new(
    secret: U256,
    id: usize,
    degree: usize,
    field_kind: FieldKind,
) -> RobustShare {
    match field_kind {
        FieldKind::Bls12_381Fr => {
            let share =
                robust_interpolate::RobustShare::<Fr>::new(secret.into(), id, degree).into();
            return share;
        }
    };
}

/// Generates `n` secret shares for a `value` using a degree `t` polynomial,
/// such that `f(0) = value`. Any `t + 1` shares can reconstruct the secret.
///
/// Shares are evaluations of `f(x)` on an FFT domain.
///
/// # Errors
/// - `InvalidInput` if `n` is not greater than `t`.
/// - `NoSuitableDomain` if a suitable FFT evaluation domain of size `n` isn't found.
#[no_mangle]
pub extern "C" fn robust_share_compute_shares(
    secret: U256,
    degree: usize,
    n: usize,
    output_shares: *mut RobustShareSlice,
    field_kind: FieldKind,
) -> ShareErrorCode {
    let mut rng = ark_std::rand::thread_rng();
    match field_kind {
        FieldKind::Bls12_381Fr => {
            let compute_result: Result<Vec<robust_interpolate::RobustShare<Fr>>, InterpolateError> =
                robust_interpolate::RobustShare::compute_shares(
                    secret.into(),
                    n,
                    degree,
                    None,
                    &mut rng,
                );
            match compute_result {
                Ok(shares) => {
                    let shares_vec = shares
                        .into_iter()
                        .map(|share| share.into())
                        .collect::<Vec<RobustShare>>();
                    // prevent Rust from dropping the vec
                    let mut shares_vec = ManuallyDrop::new(shares_vec);
                    let output_shares_t = RobustShareSlice {
                        pointer: shares_vec.as_mut_ptr(),
                        len: shares_vec.len(),
                    };
                    let ptr = Box::into_raw(Box::new(output_shares_t)) as *mut RobustShareSlice;
                    unsafe {
                        *output_shares = *Box::from_raw(ptr);
                    }

                    return ShareErrorCode::ShareSuccess;
                }
                Err(e) => return e.into(),
            }
        }
    }
}

/// Full robust interpolation combining optimistic decoding and error correction
///
/// # Arguments
/// * `n` - total number of shares
/// * `shares` - pointer to the RobustShareSlice, unordered
#[no_mangle]
pub extern "C" fn robust_share_recover_secret(
    shares: RobustShareSlice,
    n: usize,
    output_secret: *mut U256,
    output_coeffs: *mut U256Slice,
    field_kind: FieldKind,
) -> ShareErrorCode {
    let shares_slice = unsafe { Vec::from_raw_parts(shares.pointer, shares.len, shares.len) };
    // since the pointer comes from C, we should not drop it here
    // use free_robust_share_bls12_slice() instead
    let shares_slice = ManuallyDrop::new(shares_slice);
    match field_kind {
        FieldKind::Bls12_381Fr => {
            let shares = shares_slice
                .iter()
                .map(|f| f.clone().into())
                .collect::<Vec<robust_interpolate::RobustShare<Fr>>>();
            let recover_result = robust_interpolate::RobustShare::recover_secret(&shares, n);
            match recover_result {
                Ok((coeffs, secret)) => {
                    let bls12fr_coeffs =
                        coeffs.into_iter().map(|c| c.into()).collect::<Vec<U256>>();
                    // prevent Rust from dropping the vec
                    let mut bls12fr_coeffs = ManuallyDrop::new(bls12fr_coeffs);
                    // store results to the pointer
                    unsafe {
                        *output_coeffs = U256Slice {
                            pointer: bls12fr_coeffs.as_mut_ptr(),
                            len: bls12fr_coeffs.len(),
                        };
                        *output_secret = secret.into();
                    }

                    return ShareErrorCode::ShareSuccess;
                }
                Err(e) => return e.into(),
            }
        }
    }
}

// create new NonRobustShare
#[no_mangle]
pub extern "C" fn non_robust_share_new(
    secret: U256,
    id: usize,
    degree: usize,
    field_kind: FieldKind,
) -> NonRobustShare {
    match field_kind {
        FieldKind::Bls12_381Fr => {
            let share = shamir::NonRobustShare::<Fr>::new(secret.into(), id, degree).into();
            return share;
        }
    };
}

// compute the non-robust shamir shares for a secret
#[no_mangle]
pub extern "C" fn non_robust_share_compute_shares(
    secret: U256,
    degree: usize,
    n: usize,
    output_shares: *mut NonRobustShareSlice,
    field_kind: FieldKind,
) -> ShareErrorCode {
    let mut rng = ark_std::rand::thread_rng();

    match field_kind {
        FieldKind::Bls12_381Fr => {
            let compute_result: Result<Vec<shamir::NonRobustShare<Fr>>, ShareError> =
                shamir::NonRobustShare::compute_shares(secret.into(), n, degree, None, &mut rng);
            match compute_result {
                Ok(shares) => {
                    let shares_vec = shares
                        .into_iter()
                        .map(|share| share.into())
                        .collect::<Vec<NonRobustShare>>();
                    // prevent Rust from dropping the vec
                    let mut shares_vec = ManuallyDrop::new(shares_vec);
                    unsafe {
                        *output_shares = NonRobustShareSlice {
                            pointer: shares_vec.as_mut_ptr(),
                            len: shares_vec.len(),
                        };
                    }

                    return ShareErrorCode::ShareSuccess;
                }
                Err(e) => return e.into(),
            }
        }
    }
}

// recover the secret of the input shares
#[no_mangle]
pub extern "C" fn non_robust_share_recover_secret(
    shares: NonRobustShareSlice,
    n: usize,
    output_secret: *mut U256,
    output_coeffs: *mut U256Slice,
    field_kind: FieldKind,
) -> ShareErrorCode {
    let shares_slice = unsafe { Vec::from_raw_parts(shares.pointer, shares.len, shares.len) };
    // since the pointer comes from C, we should not drop it here
    // use free_non_robust_share_bls12_slice() instead
    let shares_slice = ManuallyDrop::new(shares_slice);
    match field_kind {
        FieldKind::Bls12_381Fr => {
            let shares = shares_slice
                .iter()
                .map(|f| f.clone().into())
                .collect::<Vec<shamir::NonRobustShare<Fr>>>();
            let recover_result = shamir::NonRobustShare::recover_secret(&shares, n);
            match recover_result {
                Ok((coeffs, secret)) => {
                    let bls12fr_coeffs =
                        coeffs.into_iter().map(|c| c.into()).collect::<Vec<U256>>();
                    // prevent Rust from dropping the vec
                    let mut bls12fr_coeffs = ManuallyDrop::new(bls12fr_coeffs);
                    // store results to the pointer
                    unsafe {
                        *output_coeffs = U256Slice {
                            pointer: bls12fr_coeffs.as_mut_ptr(),
                            len: bls12fr_coeffs.len(),
                        };
                        *output_secret = secret.into()
                    }

                    return ShareErrorCode::ShareSuccess;
                }
                Err(e) => return e.into(),
            }
        }
    }
}
