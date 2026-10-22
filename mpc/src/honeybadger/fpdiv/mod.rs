use crate::{
    common::types::fixed::ClearFixedPoint, honeybadger::fpdiv::fpdiv_const::FPDivConstError,
};
use ark_ff::{BigInteger, PrimeField};

pub mod fpdiv;
pub mod fpdiv_const;

/// `θ = ⌈log2(k/3.5)⌉` (Catrina COMM 2018, Protocol 7 step 1) — the number of
/// Newton/Goldschmidt refinement rounds FXDiv needs for a k-bit result; the
/// loop itself runs `θ-1` times. Computed via exact integer arithmetic
/// (`θ = ⌈log2(k/3.5)⌉ = ⌈log2(2k/7)⌉`, i.e. the bit-length of
/// `⌈2k/7⌉ - 1`) to avoid float imprecision near powers of two.
pub fn fpdiv_theta(k: usize) -> usize {
    let target = (2 * k as u64 + 6) / 7;
    if target <= 1 {
        0
    } else {
        (u64::BITS - (target - 1).leading_zeros()) as usize
    }
}

/// Total raw preprocessing-pool consumption — `(triples, random_shares,
/// prandbit, prandint)` — for one FXDiv(k,f) call. Used to check pool
/// inventory before assembling an `FpDivPrep` from real preprocessing.
///
/// Cross-checked numerically against the fully-composed version for several
/// (k, f) pairs. Step 8 (Round B: 1 triple, `2f` prandbit, 1 prandint) runs
/// once total, not once per loop iteration. `sufor_mod2 = (k-1)-1 = k-2`
/// accounts for SufOr's PreOrC-based Mod2 calls (one per input but the
/// first; SufOr runs on AppRec's k-1 xor_bits) — each draws 1 randbit + 1
/// prandint via `take_mod2_prandm_prep`.
pub fn fpdiv_prep_counts(k: usize, f: usize) -> (usize, usize, usize, usize) {
    let num_iters = fpdiv_theta(k).saturating_sub(1);
    let sufor_mod2 = k.saturating_sub(2);
    let triples = 6 * k - 3 + 2 * num_iters;
    let random_shares = 4 * k - 4;
    let prandbit = 4 * k + f - 4 + 4 * f * num_iters + sufor_mod2;
    let prandint = k + 3 + 2 * num_iters + sufor_mod2;
    (triples, random_shares, prandbit, prandint)
}

pub fn fixed_point_reciprocal_scaled<F: PrimeField>(
    denom: &ClearFixedPoint<F>,
) -> Result<ClearFixedPoint<F>, FPDivConstError> {
    let precision = denom.precision();
    let f = precision.f();
    let k = precision.k();

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

    // `div_with_const_fixed` feeds a*w into TruncPr, whose mask pool is sized for
    // max_masked_width = 2k-f bits assuming the secret numerator a < 2^k. That bound only
    // holds if w <= 2^(k-f); a divisor small enough to push w past that inflates the
    // pre-truncation value beyond the mask's coverage and leaks the numerator's high bits
    // through TruncPr's public opening instead of failing.
    //
    // To allow smaller divisors, widen k-f (not f) -- w depends only on f, the threshold only
    // on k-f, so growing f alone doesn't help.
    if w_u128 > (1u128 << (k - f)) {
        return Err(FPDivConstError::DivisorTooSmall {
            k,
            f,
            divisor_raw: b_u128,
        });
    }

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

#[cfg(test)]
mod theta_tests {
    use super::fpdiv_theta;

    #[test]
    fn matches_float_log2_formula() {
        for k in [3usize, 4, 9, 15, 32, 64, 128, 256] {
            let expected = (k as f64 / 3.5).log2().ceil().max(0.0) as usize;
            assert_eq!(fpdiv_theta(k), expected, "mismatch at k={k}");
        }
    }
}
