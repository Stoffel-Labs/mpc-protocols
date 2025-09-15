use std::{mem::ManuallyDrop, slice};

use ark_bls12_381::Fr;
use ark_ff::PrimeField;

use crate::{
    common::{
        share::{
            shamir::{NonRobustShare, Shamirshare},
            ShareError,
        },
        SecretSharingScheme,
    },
    ffi::c_bindings::{Bls12Fr, Bls12FrSlice, UsizeSlice},
    honeybadger::robust_interpolate::{robust_interpolate::RobustShare, InterpolateError},
};

#[repr(C)]
pub enum ShareErrorCode {
    Success,
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

#[repr(C)]
#[derive(Clone, Debug)]
pub struct ShamirShareBls12 {
    pub share: Bls12Fr,
    pub id: usize,
    pub degree: usize,
}

#[repr(C)]
pub struct ShamirShareSliceBls12 {
    pub pointer: *mut ShamirShareBls12,
    pub len: usize,
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct RobustShareBls12 {
    pub share: Bls12Fr,
    pub id: usize,
    pub degree: usize,
}

#[repr(C)]
pub struct RobustShareSliceBls12 {
    pub pointer: *mut RobustShareBls12,
    pub len: usize,
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct NonRobustShareBls12 {
    pub share: Bls12Fr,
    pub id: usize,
    pub degree: usize,
}

#[repr(C)]
pub struct NonRobustShareSliceBls12 {
    pub pointer: *mut NonRobustShareBls12,
    pub len: usize,
}

// free the memory of a ShamirshareSliceBls12
#[no_mangle]
pub extern "C" fn free_shamir_share_bls12_slice(slice: ShamirShareSliceBls12) {
    if !slice.pointer.is_null() {
        unsafe {
            let _ = Vec::from_raw_parts(slice.pointer, slice.len, slice.len);
        }
    }
}

// free the memory of a RobustShareSliceBls12
#[no_mangle]
pub extern "C" fn free_robust_share_bls12_slice(slice: RobustShareSliceBls12) {
    if !slice.pointer.is_null() {
        unsafe {
            let _ = Vec::from_raw_parts(slice.pointer, slice.len, slice.len);
        }
    }
}

// free the memory of a NonRobustShareSliceBls12
#[no_mangle]
pub extern "C" fn free_non_robust_share_bls12_slice(slice: NonRobustShareSliceBls12) {
    if !slice.pointer.is_null() {
        unsafe {
            let _ = Vec::from_raw_parts(slice.pointer, slice.len, slice.len);
        }
    }
}

impl From<ShamirShareBls12> for Shamirshare<Fr> {
    fn from(value: ShamirShareBls12) -> Self {
        Self::new(value.share.into(), value.id, value.degree)
    }
}

impl From<Shamirshare<Fr>> for ShamirShareBls12 {
    fn from(value: Shamirshare<Fr>) -> Self {
        Self {
            share: Bls12Fr {
                data: value.share[0].into_bigint().0,
            },
            id: value.id,
            degree: value.degree,
        }
    }
}

impl From<RobustShareBls12> for RobustShare<Fr> {
    fn from(value: RobustShareBls12) -> Self {
        Self::new(value.share.into(), value.id, value.degree)
    }
}

impl From<RobustShare<Fr>> for RobustShareBls12 {
    fn from(value: RobustShare<Fr>) -> Self {
        Self {
            share: Bls12Fr {
                data: value.share[0].into_bigint().0,
            },
            id: value.id,
            degree: value.degree,
        }
    }
}

impl From<NonRobustShareBls12> for NonRobustShare<Fr> {
    fn from(value: NonRobustShareBls12) -> Self {
        Self::new(value.share.into(), value.id, value.degree)
    }
}

impl From<NonRobustShare<Fr>> for NonRobustShareBls12 {
    fn from(value: NonRobustShare<Fr>) -> Self {
        Self {
            share: Bls12Fr {
                data: value.share[0].into_bigint().0,
            },
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
pub extern "C" fn shamir_share_new(secret: Bls12Fr, id: usize, degree: usize) -> ShamirShareBls12 {
    Shamirshare::<Fr>::new(secret.into(), id, degree).into()
}

// compute the shamir shares of all ids for a secret
#[no_mangle]
pub extern "C" fn shamir_share_compute_shares(
    secret: Bls12Fr,
    degree: usize,
    ids: Option<&UsizeSlice>,
    output_shares: *mut ShamirShareSliceBls12,
) -> ShareErrorCode {
    let mut rng = ark_std::rand::thread_rng();
    let ids = ids.and_then(|ids| {
        let ids_slice = unsafe { slice::from_raw_parts(ids.pointer, ids.len) };
        Some(ids_slice)
    });

    let compute_result: Result<Vec<Shamirshare<Fr>>, ShareError> =
        Shamirshare::compute_shares(secret.into(), 0, degree, ids, &mut rng);
    match compute_result {
        Ok(shares) => {
            let shares_vec = shares
                .into_iter()
                .map(|share| share.into())
                .collect::<Vec<ShamirShareBls12>>();
            // prevent Rust from dropping the vec
            let mut shares_vec = ManuallyDrop::new(shares_vec);
            unsafe {
                *output_shares = ShamirShareSliceBls12 {
                    pointer: shares_vec.as_mut_ptr(),
                    len: shares_vec.len(),
                };
            };
            return ShareErrorCode::Success;
        }
        Err(e) => return e.into(),
    }
}

// recover the secret of the input shares
#[no_mangle]
pub extern "C" fn shamir_share_recover_secret(
    shares: ShamirShareSliceBls12,
    output_secret: *mut Bls12Fr,
    output_coeffs: *mut Bls12FrSlice,
) -> ShareErrorCode {
    let shares_slice = unsafe { Vec::from_raw_parts(shares.pointer, shares.len, shares.len) };
    // since the pointer comes from C, we should not drop it here
    // use free_shamir_share_bls12_slice() instead
    let shares_slice = ManuallyDrop::new(shares_slice);
    let shares = shares_slice
        .iter()
        .map(|f| f.clone().into())
        .collect::<Vec<Shamirshare<Fr>>>();
    let recover_result = Shamirshare::recover_secret(&shares, 0);
    match recover_result {
        Ok((coeffs, secret)) => {
            let bls12fr_coeffs = coeffs
                .into_iter()
                .map(|c| c.into())
                .collect::<Vec<Bls12Fr>>();
            // prevent Rust from dropping the vec
            let mut bls12fr_coeffs = ManuallyDrop::new(bls12fr_coeffs);
            let coeffs_pointer = Bls12FrSlice {
                pointer: bls12fr_coeffs.as_mut_ptr(),
                len: bls12fr_coeffs.len(),
            };
            // store results to the pointer
            unsafe {
                *output_coeffs = coeffs_pointer;
                *output_secret = secret.into();
            }

            return ShareErrorCode::Success;
        }
        Err(e) => return e.into(),
    }
}

// create new RobustShare
#[no_mangle]
pub extern "C" fn robust_share_new(secret: Bls12Fr, id: usize, degree: usize) -> RobustShareBls12 {
    RobustShare::<Fr>::new(secret.into(), id, degree).into()
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
    secret: Bls12Fr,
    degree: usize,
    n: usize,
    output_shares: *mut RobustShareSliceBls12,
) -> ShareErrorCode {
    let mut rng = ark_std::rand::thread_rng();

    let compute_result: Result<Vec<RobustShare<Fr>>, InterpolateError> =
        RobustShare::compute_shares(secret.into(), n, degree, None, &mut rng);
    match compute_result {
        Ok(shares) => {
            let shares_vec = shares
                .into_iter()
                .map(|share| share.into())
                .collect::<Vec<RobustShareBls12>>();
            // prevent Rust from dropping the vec
            let mut shares_vec = ManuallyDrop::new(shares_vec);
            unsafe {
                *output_shares = RobustShareSliceBls12 {
                    pointer: shares_vec.as_mut_ptr(),
                    len: shares_vec.len(),
                };
            }
            return ShareErrorCode::Success;
        }
        Err(e) => return e.into(),
    }
}

/// Full robust interpolation combining optimistic decoding and error correction
///
/// # Arguments
/// * `n` - total number of shares
/// * `shares` - pointer to the RobustShareSlice, unordered
#[no_mangle]
pub extern "C" fn robust_share_recover_secret(
    shares: RobustShareSliceBls12,
    n: usize,
    output_secret: *mut Bls12Fr,
    output_coeffs: *mut Bls12FrSlice,
) -> ShareErrorCode {
    let shares_slice = unsafe { Vec::from_raw_parts(shares.pointer, shares.len, shares.len) };
    // since the pointer comes from C, we should not drop it here
    // use free_robust_share_bls12_slice() instead
    let shares_slice = ManuallyDrop::new(shares_slice);
    let shares = shares_slice
        .iter()
        .map(|f| f.clone().into())
        .collect::<Vec<RobustShare<Fr>>>();
    let recover_result = RobustShare::recover_secret(&shares, n);
    match recover_result {
        Ok((coeffs, secret)) => {
            let bls12fr_coeffs = coeffs
                .into_iter()
                .map(|c| c.into())
                .collect::<Vec<Bls12Fr>>();
            // prevent Rust from dropping the vec
            let mut bls12fr_coeffs = ManuallyDrop::new(bls12fr_coeffs);
            // store results to the pointer
            unsafe {
                *output_coeffs = Bls12FrSlice {
                    pointer: bls12fr_coeffs.as_mut_ptr(),
                    len: bls12fr_coeffs.len(),
                };
                *output_secret = secret.into();
            }

            return ShareErrorCode::Success;
        }
        Err(e) => return e.into(),
    }
}

// create new NonRobustShare
#[no_mangle]
pub extern "C" fn non_robust_share_new(
    secret: Bls12Fr,
    id: usize,
    degree: usize,
) -> NonRobustShareBls12 {
    NonRobustShare::<Fr>::new(secret.into(), id, degree).into()
}

// compute the non-robust shamir shares for a secret
#[no_mangle]
pub extern "C" fn non_robust_share_compute_shares(
    secret: Bls12Fr,
    degree: usize,
    n: usize,
    output_shares: *mut NonRobustShareSliceBls12,
) -> ShareErrorCode {
    let mut rng = ark_std::rand::thread_rng();

    let compute_result: Result<Vec<NonRobustShare<Fr>>, ShareError> =
        NonRobustShare::compute_shares(secret.into(), n, degree, None, &mut rng);
    match compute_result {
        Ok(shares) => {
            let shares_vec = shares
                .into_iter()
                .map(|share| share.into())
                .collect::<Vec<NonRobustShareBls12>>();
            // prevent Rust from dropping the vec
            let mut shares_vec = ManuallyDrop::new(shares_vec);
            unsafe {
                *output_shares = NonRobustShareSliceBls12 {
                    pointer: shares_vec.as_mut_ptr(),
                    len: shares_vec.len(),
                };
            }

            return ShareErrorCode::Success;
        }
        Err(e) => return e.into(),
    }
}

// recover the secret of the input shares
#[no_mangle]
pub extern "C" fn non_robust_share_recover_secret(
    shares: NonRobustShareSliceBls12,
    n: usize,
    output_secret: *mut Bls12Fr,
    output_coeffs: *mut Bls12FrSlice,
) -> ShareErrorCode {
    let shares_slice = unsafe { Vec::from_raw_parts(shares.pointer, shares.len, shares.len) };
    // since the pointer comes from C, we should not drop it here
    // use free_non_robust_share_bls12_slice() instead
    let shares_slice = ManuallyDrop::new(shares_slice);
    let shares = shares_slice
        .iter()
        .map(|f| f.clone().into())
        .collect::<Vec<NonRobustShare<Fr>>>();
    let recover_result = NonRobustShare::recover_secret(&shares, n);
    match recover_result {
        Ok((coeffs, secret)) => {
            let bls12fr_coeffs = coeffs
                .into_iter()
                .map(|c| c.into())
                .collect::<Vec<Bls12Fr>>();
            // prevent Rust from dropping the vec
            let mut bls12fr_coeffs = ManuallyDrop::new(bls12fr_coeffs);
            // store results to the pointer
            unsafe {
                *output_coeffs = Bls12FrSlice {
                    pointer: bls12fr_coeffs.as_mut_ptr(),
                    len: bls12fr_coeffs.len(),
                };
                *output_secret = secret.into()
            }

            return ShareErrorCode::Success;
        }
        Err(e) => return e.into(),
    }
}
