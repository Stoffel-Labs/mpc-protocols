use crate::{
    common::types::fixed::ClearFixedPoint, honeybadger::fpdiv::fpdiv_const::FPDivConstError,
};
use ark_ff::{BigInteger, PrimeField};
use std::ops::ShlAssign;

pub mod fpdiv_const;

/// Compute an *integer-scaled* reciprocal of a clear fixed-point value:
///     w = round(2^{2f} / denom)
/// Returned as a `ClearFixedPoint` in the same precision.
///
/// For example, if denom = 3.0 and f = 8:
///   2^{2f} = 65536
///   w = round(65536 / 3.0) = 21845
/// So the resulting ClearFixedPoint represents roughly 0.3333 scaled.
pub fn fixed_point_reciprocal_scaled<F: PrimeField>(
    denom: &ClearFixedPoint<F>,
) -> Result<ClearFixedPoint<F>, FPDivConstError> {
    todo!()
    // let precision = denom.precision();
    // let f = precision.f();

    // let denom_val = denom.value();
    // if denom_val.is_zero() {
    //     return Err(FPDivConstError::InvalidDivisor);
    // }

    // // Extract integer representation (b̄)
    // let b_big = denom_val.into_bigint();

    // // Compute numerator = 2^{2f}
    // let mut num = F::BigInt::from(1u64);
    // num.shl_assign((2 * f).try_into().unwrap()); // shift left to multiply by 2^{2f}

    // // Rounded division: w = (num + b̄/2) / b̄
    // let half_b = *&b_big >> 1u32;
    // let temp = num.add_with_carry(&half_b); // this returns a carry bit, what do I do?

    // let w_big = num / &b_big; // theres no division

    // // Convert to field element
    // let w_bytes = w_big.to_bytes_le();
    // let w_field = F::from_le_bytes_mod_order(&w_bytes);

    // Ok(ClearFixedPoint::new(w_field))
}
