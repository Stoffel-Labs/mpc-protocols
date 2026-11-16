//! Value-level helpers that bridge the prime-field domain (`F: PrimeField`, e.g. the scalar field
//! of BLS12-381) and the binary domain (`K: BinaryField`, e.g. `Gf256`).
//!
//! This module is the **only** place where the two domains are allowed to touch, and it touches
//! them at the level of *clear values* — a `bool`, a field element, a little-endian bit vector.
//!
//! # INVARIANT (C5/C20): nothing here ever takes or returns a share
//!
//! Never derive a cross-domain relation from share ids or from evaluation-domain elements.
//! [`crate::common::ShamirShare::id`] (and hence `RobustShare::id`) indexes the FFT domain
//! (`domain.element(id)`), while
//! [`crate::common::gf2k::share::GfShare::id`] indexes the powers of the multiplicative generator
//! `[1, g, g^2, ...]` (see [`crate::common::gf2k::field::Gf2kDomain`]) — indeed
//! `GfShare::compute_shares` has no `ids` parameter at all. The two x-coordinate sets are
//! unrelated; only the *party index* is common to both. A doubly-shared bit (daBit) ties the two
//! domains **by value**, never by share algebra, and that value-level tie is what lives here.
//!
//! # Bit-vector convention
//!
//! Every `Vec<bool>` produced or consumed by this module is **little-endian (LSB first)** and has
//! an explicit, exact length. `bits[i]` is the coefficient of `2^i`.
//!
//! # Canonical representative, not two's complement
//!
//! [`canonical_bits`] decomposes the representative of `x` in `[0, p)`. The fixed-point encoding in
//! [`crate::common::types::fixed`] represents a negative value `-|v|` as `p - |v|`, so `-1` comes
//! back from here as the bits of `p - 1`, **not** as the two's-complement all-ones pattern. A caller that wants a sign bit must shift the value by
//! `2^(k-1)` first, which is the same convention `truncpr.rs` already uses.

use crate::common::gf2k::field::BinaryField;
use ark_ff::{BigInteger, PrimeField};
use thiserror::Error;

/// Errors raised by the value-level cross-domain conversions.
///
/// Every one of these is a *caller* error: the helpers in this module are pure and see no network
/// data directly. They are nevertheless fallible rather than panicking, because the values they are
/// handed (an opened mask, a reconstructed bit) are derived from robustly-opened public values and
/// must therefore never be able to abort an honest party (C12).
#[derive(Error, Debug)]
pub enum ConvertError {
    /// A prime-field element that was expected to lie in `{0, 1}` did not.
    #[error("field element is not 0 or 1")]
    NotAFieldBit,

    /// A binary-field element that was expected to lie in the canonical `GF(2)` subfield `{0, 1}`
    /// did not. Note this is exactly `!K::is_bit()`, i.e. `x^2 != x`.
    #[error("binary element is not in the GF(2) subfield")]
    NotABinaryBit,

    /// More bits were requested than a canonical representative of the field can ever occupy.
    /// The surplus bits would be identically zero, so asking for them is always a sizing bug.
    #[error("width {width} exceeds capacity {capacity}")]
    WidthTooLarge { width: usize, capacity: usize },

    /// The value does not fit in the requested number of bits. Returned instead of silently
    /// truncating: a truncated decomposition is a correctness break, exactly like the `ell = 64`
    /// wrap that `B2AError::WidthTooLarge` exists to prevent.
    #[error("value needs {value_bits} bits, which exceeds the requested width {width}")]
    ValueTooWide { value_bits: usize, width: usize },

    /// A zero-width decomposition was requested. Rejected because an empty bit vector makes every
    /// downstream verification loop pass vacuously (C13).
    #[error("a zero-width bit decomposition was requested")]
    ZeroWidth,
}

/// Embeds a clear bit into the canonical `GF(2)` subfield of `K`.
///
/// `K::zero()` / `K::one()` are the only two elements `x` of `K` with `x^2 = x`, which is precisely
/// what [`BinaryField::is_bit`] tests.
pub fn bit_to_gf<K: BinaryField>(b: bool) -> K {
    if b {
        K::one()
    } else {
        K::zero()
    }
}

/// Extracts a clear bit from an element of `K`, rejecting anything outside `{0, 1}`.
///
/// The comparison is against the two subfield elements directly, never against `x * x == x` plus a
/// sign convention: in `GF(2^k)` the Frobenius map `x -> x^2` is a **bijection**, so squaring
/// determines `x` exactly and carries no information that distinguishes `0` from `1` more cheaply.
pub fn gf_to_bit<K: BinaryField>(x: K) -> Result<bool, ConvertError> {
    if x.is_zero() {
        Ok(false)
    } else if x == K::one() {
        Ok(true)
    } else {
        Err(ConvertError::NotABinaryBit)
    }
}

/// Embeds a clear bit into `F` as `0` or `1`.
pub fn bit_to_field<F: PrimeField>(b: bool) -> F {
    if b {
        F::one()
    } else {
        F::zero()
    }
}

/// Extracts a clear bit from an element of `F`, rejecting anything outside `{0, 1}`.
///
/// Note that `F::zero() - F::one()` (i.e. `p - 1`) is **not** a bit under this definition, matching
/// the canonical-representative convention documented at the module level.
pub fn field_to_bit<F: PrimeField>(x: F) -> Result<bool, ConvertError> {
    if x.is_zero() {
        Ok(false)
    } else if x.is_one() {
        Ok(true)
    } else {
        Err(ConvertError::NotAFieldBit)
    }
}

/// `ceil(log2 p)` — the number of bits a canonical representative in `[0, p)` can occupy.
///
/// This is 255 for BLS12-381's scalar field and 254 for BN254's. It equals `F::MODULUS_BIT_SIZE`, the bit
/// length of `p`: for any odd prime `p` is not a power of two, so `ceil(log2 p)` and
/// `floor(log2 p) + 1` coincide.
pub fn field_bit_width<F: PrimeField>() -> usize {
    F::MODULUS_BIT_SIZE as usize
}

/// Canonical little-endian bit decomposition of the representative of `x` in `[0, p)`.
///
/// Returns **exactly** `width` bits, LSB first. Both failure modes are hard errors rather than a
/// silent resize:
///
/// * `width > field_bit_width::<F>()` — the surplus bits are always zero, so the request is a
///   sizing bug ([`ConvertError::WidthTooLarge`]);
/// * the representative needs more than `width` bits — truncating would change the value
///   ([`ConvertError::ValueTooWide`]).
pub fn canonical_bits<F: PrimeField>(x: F, width: usize) -> Result<Vec<bool>, ConvertError> {
    if width == 0 {
        return Err(ConvertError::ZeroWidth);
    }
    let capacity = field_bit_width::<F>();
    if width > capacity {
        return Err(ConvertError::WidthTooLarge { width, capacity });
    }

    // `into_bigint` leaves Montgomery form and yields the canonical representative in `[0, p)`.
    let repr = x.into_bigint();
    let value_bits = repr.num_bits() as usize;
    if value_bits > width {
        return Err(ConvertError::ValueTooWide { value_bits, width });
    }

    // `to_bits_le` is padded out to the `BigInt`'s limb capacity, which may exceed `width`; the
    // check above guarantees every bit removed by this resize is zero.
    let mut bits = repr.to_bits_le();
    bits.resize(width, false);
    Ok(bits)
}

/// `p` as exactly `field_bit_width::<F>()` little-endian bits.
///
/// Used by the edaBit `r < p` filter and by the A2B conditional reduction.
pub fn modulus_bits<F: PrimeField>() -> Vec<bool> {
    let width = field_bit_width::<F>();
    let mut bits = F::MODULUS.to_bits_le();
    // `F::MODULUS_BIT_SIZE` is by definition `num_bits(p)`, so every bit at or above `width` is
    // zero and this resize is lossless.
    bits.resize(width, false);
    bits
}

/// `2^w - p` as exactly `w` little-endian bits, where `w = field_bit_width::<F>()`.
///
/// This is the constant A2B's second addition adds in order to test-and-perform the single
/// conditional subtraction of `p`.
pub fn two_pow_w_minus_modulus_bits<F: PrimeField>() -> Vec<bool> {
    // `2^w - p == (!p) + 1` over `w` bits (two's complement). The carry can only escape bit `w-1`
    // when `p == 0`, which no prime modulus is, so the result is exact in `w` bits. Also
    // `2^(w-1) <= p < 2^w`, hence `0 < 2^w - p <= 2^(w-1)`.
    let modulus = modulus_bits::<F>();
    let mut bits = Vec::with_capacity(modulus.len());
    let mut carry = true;
    for bit in modulus {
        let complemented = !bit;
        bits.push(complemented ^ carry);
        carry &= complemented;
    }
    bits
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::gf2k::field::Gf256;
    use ark_std::test_rng;
    use num_bigint::BigUint;

    /// The scalar field of BLS12-381: 255 bits.
    type Bls = ark_bls12_381::Fr;
    /// The scalar field of BN254: 254 bits.
    type Bn = ark_bn254::Fr;

    fn modulus<F: PrimeField>() -> BigUint {
        F::MODULUS.into()
    }

    fn canonical<F: PrimeField>(x: F) -> BigUint {
        x.into_bigint().into()
    }

    /// Recomposes a little-endian bit vector.
    fn from_bits(bits: &[bool]) -> BigUint {
        let mut acc = BigUint::from(0u8);
        for (i, b) in bits.iter().enumerate() {
            acc.set_bit(i as u64, *b);
        }
        acc
    }

    fn pow2(exponent: usize) -> BigUint {
        BigUint::from(1u8) << exponent
    }

    #[test]
    fn test_field_bit_width_of_the_curve_fields() {
        assert_eq!(field_bit_width::<Bls>(), 255);
        assert_eq!(field_bit_width::<Bn>(), 254);
    }

    #[test]
    fn test_bit_to_gf_and_back() {
        for b in [false, true] {
            let k: Gf256 = bit_to_gf(b);
            assert!(k.is_bit(), "embedded bit must satisfy x^2 = x");
            assert_eq!(gf_to_bit(k).expect("subfield element"), b);
        }
        assert_eq!(bit_to_gf::<Gf256>(false), Gf256::zero());
        assert_eq!(bit_to_gf::<Gf256>(true), Gf256::one());
    }

    #[test]
    fn test_gf_to_bit_rejects_non_subfield_exhaustively() {
        // Only Gf256(0) and Gf256(1) are in the canonical GF(2) subfield. In particular Gf256(2)
        // and Gf256(3) — the values an adversarial dealer would reach for — must be rejected.
        for v in 0u8..=255 {
            let x = Gf256(v);
            let expected = v == 0 || v == 1;
            assert_eq!(
                gf_to_bit(x).is_ok(),
                expected,
                "gf_to_bit mismatch for {x:?}"
            );
            assert_eq!(gf_to_bit(x).is_ok(), x.is_bit(), "disagrees with is_bit");
        }
        assert!(matches!(
            gf_to_bit(Gf256(2)),
            Err(ConvertError::NotABinaryBit)
        ));
    }

    #[test]
    fn test_bit_to_field_and_back() {
        fn check<F: PrimeField>() {
            for b in [false, true] {
                let f: F = bit_to_field(b);
                assert_eq!(field_to_bit(f).expect("0 or 1"), b);
            }
            assert_eq!(bit_to_field::<F>(false), F::zero());
            assert_eq!(bit_to_field::<F>(true), F::one());
        }
        check::<Bls>();
        check::<Bn>();
    }

    #[test]
    fn test_field_to_bit_rejects_non_bits() {
        fn check<F: PrimeField>() {
            assert!(matches!(
                field_to_bit(F::from(2u64)),
                Err(ConvertError::NotAFieldBit)
            ));
            // -1 is p - 1, not a bit: the canonical-representative convention, not two's
            // complement.
            assert!(matches!(
                field_to_bit(-F::one()),
                Err(ConvertError::NotAFieldBit)
            ));
        }
        check::<Bls>();
        check::<Bn>();
    }

    #[test]
    fn test_canonical_bits_is_little_endian() {
        fn check<F: PrimeField>() {
            let w = field_bit_width::<F>();
            let one = canonical_bits(F::one(), w).expect("1 fits");
            assert_eq!(one.len(), w);
            assert!(one[0], "bit 0 of 1 must be set");
            assert!(one[1..].iter().all(|b| !*b), "no other bit of 1 may be set");

            let two = canonical_bits(F::from(2u64), w).expect("2 fits");
            assert!(!two[0] && two[1]);

            // A single bit at every position that is a field element on its own.
            for position in [32usize, 63, 64, 128, w - 2] {
                let bits = canonical_bits(F::from(pow2(position)), w).expect("fits");
                assert!(bits[position]);
                assert_eq!(bits.iter().filter(|b| **b).count(), 1);
            }
        }
        check::<Bls>();
        check::<Bn>();
    }

    #[test]
    fn test_canonical_bits_boundary_values() {
        // Both ends of the range, the offset `2^w - p` A2B folds into its adder, and the top bit:
        // the values A2B's carry branches and the edaBit `r < p` filter hinge on.
        fn check<F: PrimeField>() {
            let p = modulus::<F>();
            let w = field_bit_width::<F>();
            let one = BigUint::from(1u8);
            let d = pow2(w) - &p;
            let cases = [
                BigUint::from(0u8),
                one.clone(),
                BigUint::from(2u8),
                &d - &one,
                d.clone(),
                pow2(w - 1) - &one,
                pow2(w - 1),
                &p - BigUint::from(2u8),
                &p - &one,
            ];
            for v in cases.iter().filter(|v| **v < p) {
                let x = F::from(v.clone());
                assert_eq!(&canonical(x), v, "test vector {v} must be canonical");
                let bits = canonical_bits(x, w).expect("every value below p fits in w bits");
                assert_eq!(bits.len(), w);
                assert_eq!(&from_bits(&bits), v, "round-trip failed for {v}");
            }
        }
        check::<Bls>();
        check::<Bn>();
    }

    #[test]
    fn test_canonical_bits_of_minus_one_is_not_twos_complement() {
        // Pins the signed-value convention: -1 decomposes as p - 1, NOT as all ones. A caller
        // wanting a sign bit must shift by 2^(k-1) first.
        fn check<F: PrimeField>() {
            let w = field_bit_width::<F>();
            let bits = canonical_bits(-F::one(), w).expect("p - 1 fits");
            assert_eq!(from_bits(&bits), modulus::<F>() - BigUint::from(1u8));
            assert!(bits.iter().any(|b| !*b), "p - 1 is not all ones");
        }
        check::<Bls>();
        check::<Bn>();
    }

    #[test]
    fn test_canonical_bits_reduces_before_decomposing() {
        // `2^w - 1` is not a canonical representative: it reduces modulo `p` first.
        fn check<F: PrimeField>() {
            let p = modulus::<F>();
            let w = field_bit_width::<F>();
            let all_ones = pow2(w) - BigUint::from(1u8);
            let expected = &all_ones % &p;
            assert_ne!(expected, all_ones);
            let x = F::from(all_ones);
            assert_eq!(canonical(x), expected);
            assert_eq!(from_bits(&canonical_bits(x, w).expect("fits")), expected);
        }
        check::<Bls>();
        check::<Bn>();
    }

    #[test]
    fn test_canonical_bits_random_round_trip() {
        fn check<F: PrimeField>() {
            let p = modulus::<F>();
            let w = field_bit_width::<F>();
            let mut rng = test_rng();
            for _ in 0..2_000 {
                let x = F::rand(&mut rng);
                let bits = canonical_bits(x, w).expect("a canonical representative always fits");
                assert_eq!(bits.len(), w);
                let recomposed = from_bits(&bits);
                assert_eq!(recomposed, canonical(x));
                assert!(recomposed < p, "canonical representative must be < p");
                assert_eq!(F::from(recomposed), x);
            }
        }
        check::<Bls>();
        check::<Bn>();
    }

    #[test]
    fn test_canonical_bits_narrow_widths() {
        // A value that fits in the requested width is decomposed exactly.
        let bits = canonical_bits(Bls::from(0xABu64), 8).expect("0xAB fits in 8 bits");
        assert_eq!(bits.len(), 8);
        assert_eq!(from_bits(&bits), BigUint::from(0xABu64));

        // Exactly-fitting boundary: 2^32 - 1 needs 32 bits.
        let bits = canonical_bits(Bls::from(0xFFFF_FFFFu64), 32).expect("fits");
        assert_eq!(bits.len(), 32);
        assert!(bits.iter().all(|b| *b));
    }

    #[test]
    fn test_canonical_bits_rejects_bad_widths() {
        // Truncation is never silent.
        assert!(matches!(
            canonical_bits(Bls::from(256u64), 8),
            Err(ConvertError::ValueTooWide {
                value_bits: 9,
                width: 8
            })
        ));
        // 2^32 needs 33 bits.
        assert!(matches!(
            canonical_bits(Bls::from(1u64 << 32), 32),
            Err(ConvertError::ValueTooWide {
                value_bits: 33,
                width: 32
            })
        ));
        // More bits than a representative can ever occupy.
        assert!(matches!(
            canonical_bits(Bls::from(1u64), 256),
            Err(ConvertError::WidthTooLarge {
                width: 256,
                capacity: 255
            })
        ));
        assert!(matches!(
            canonical_bits(Bn::from(1u64), 255),
            Err(ConvertError::WidthTooLarge {
                width: 255,
                capacity: 254
            })
        ));
        // A vacuous empty decomposition.
        assert!(matches!(
            canonical_bits(Bls::from(0u64), 0),
            Err(ConvertError::ZeroWidth)
        ));
    }

    #[test]
    fn test_modulus_bits_are_the_modulus() {
        fn check<F: PrimeField>() {
            let bits = modulus_bits::<F>();
            assert_eq!(bits.len(), field_bit_width::<F>());
            assert_eq!(from_bits(&bits), modulus::<F>());
            assert!(bits[0], "an odd prime has bit 0 set");
            assert!(
                *bits.last().unwrap(),
                "the width is the modulus's own bit length"
            );
        }
        check::<Bls>();
        check::<Bn>();
    }

    #[test]
    fn test_modulus_and_complement_sum_to_two_pow_w() {
        // p + (2^w - p) == 2^w. Pins the two's-complement derivation in
        // `two_pow_w_minus_modulus_bits` against the modulus itself rather than against a
        // hard-coded constant.
        fn check<F: PrimeField>() {
            let w = field_bit_width::<F>();
            let bits = two_pow_w_minus_modulus_bits::<F>();
            assert_eq!(bits.len(), w);
            let c = from_bits(&bits);
            assert_eq!(modulus::<F>() + &c, pow2(w));
            assert_ne!(c, BigUint::from(0u8), "2^w - p must be non-zero");
            assert!(c < pow2(w - 1), "2^w - p must be below 2^(w-1)");
        }
        check::<Bls>();
        check::<Bn>();
    }

    #[test]
    fn test_bit_vectors_agree_across_domains() {
        // The only legitimate cross-domain statement this module makes: the same clear bit embeds
        // into F and into K, and comes back unchanged from either. No share, id, or evaluation
        // point is involved.
        for b in [false, true] {
            let f: Bls = bit_to_field(b);
            let k: Gf256 = bit_to_gf(b);
            assert_eq!(field_to_bit(f).expect("bit"), gf_to_bit(k).expect("bit"));
        }
    }
}
