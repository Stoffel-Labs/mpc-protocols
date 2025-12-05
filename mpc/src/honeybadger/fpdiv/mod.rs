use crate::{
    common::types::fixed::ClearFixedPoint, honeybadger::fpdiv::fpdiv_const::FPDivConstError,
};
use ark_ff::{BigInteger, PrimeField};

pub mod fpdiv_const;

pub fn fixed_point_reciprocal_scaled<F: PrimeField>(
    denom: &ClearFixedPoint<F>,
) -> Result<ClearFixedPoint<F>, FPDivConstError> {
    let precision = denom.precision();
    let f = precision.f();

    // --------------------------
    // Step 1: extract denom integer b̄
    // --------------------------
    let denom_val = denom.value();
    if denom_val.is_zero() {
        return Err(FPDivConstError::InvalidDivisor);
    }

    // Convert field element integer to bytes (LE)
    let b_bytes = denom_val.into_bigint().to_bytes_le();

    // Take the *lowest 16 bytes* → u128 (fits all practical MPC fixed-point ranges)
    let mut buf = [0u8; 16];
    let copy_len = core::cmp::min(16, b_bytes.len());
    buf[..copy_len].copy_from_slice(&b_bytes[..copy_len]);

    let b_u128 = u128::from_le_bytes(buf);

    if b_u128 == 0 {
        return Err(FPDivConstError::InvalidDivisor);
    }

    // --------------------------
    // Step 2: numerator = 2^(2f)
    // --------------------------
    let num_u128: u128 = 1u128 << (2 * f);

    // --------------------------
    // Step 3: rounded division w̄ = round(2^f / b̄)
    // --------------------------
    let w_u128 = (num_u128 + (b_u128 >> 1)) / b_u128;

    // --------------------------
    // Step 4: convert u128 → F::BigInt
    // --------------------------
    let mut w_big = F::BigInt::default();
    let w_bytes = w_u128.to_le_bytes(); // 16 bytes

    // write into first 2 limbs
    let limbs = w_big.as_mut();
    limbs[0] = u64::from_le_bytes(w_bytes[0..8].try_into().unwrap());
    limbs[1] = u64::from_le_bytes(w_bytes[8..16].try_into().unwrap());

    let w_field = F::from_bigint(w_big).ok_or(FPDivConstError::Failed)?;

    Ok(ClearFixedPoint::new(w_field))
}
