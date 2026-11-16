//! Compiles production source files, unchanged, so that `cargo kani` checks the code that ships
//! rather than a copy of it.
#![allow(dead_code)]

#[path = "../../../mpc/src/honeybadger/dabit/packing.rs"]
mod packing;

mod gf2k;

/// `Gf256` is a field of characteristic 2 — which is what every proof about the binary side
/// assumes of `K`. Checked for all 256 elements (all 2^24 triples where three are involved).
#[cfg(kani)]
mod gf256_is_a_field {
    use super::gf2k::field::{BinaryField, Gf256};

    fn any() -> Gf256 {
        Gf256(kani::any())
    }

    #[kani::proof]
    fn addition_is_xor_and_has_characteristic_two() {
        let (a, b) = (any(), any());
        assert_eq!((a + b).0, a.0 ^ b.0);
        assert_eq!(a + a, Gf256::zero());
        assert_eq!(a - b, a + b);
        assert_eq!(a + Gf256::zero(), a);
    }

    #[kani::proof]
    #[kani::unwind(9)]
    fn multiplication_is_commutative_with_identity_one() {
        let (a, b) = (any(), any());
        assert_eq!(a * b, b * a);
        assert_eq!(a * Gf256::one(), a);
        assert_eq!(a * Gf256::zero(), Gf256::zero());
    }

    /// Associativity on the basis `1, x, .., x^7`. Multiplication is commutative and distributes
    /// over addition (the two harnesses around this one), so it is bilinear, and a bilinear
    /// product that is associative on a basis is associative everywhere. The direct statement
    /// over all `2^24` triples is beyond the SAT solver in reasonable time; the test
    /// `gf256_exhaustive::multiplication_is_associative_on_every_triple` checks it by
    /// enumeration instead.
    #[kani::proof]
    #[kani::unwind(9)]
    fn multiplication_is_associative_on_the_basis() {
        let (i, j, k): (u8, u8, u8) = (kani::any(), kani::any(), kani::any());
        kani::assume(i < 8 && j < 8 && k < 8);
        let (a, b, c) = (Gf256(1 << i), Gf256(1 << j), Gf256(1 << k));
        assert_eq!((a * b) * c, a * (b * c));
    }

    #[kani::proof]
    #[kani::unwind(9)]
    fn multiplication_distributes_over_addition() {
        let (a, b, c) = (any(), any(), any());
        assert_eq!(a * (b + c), a * b + a * c);
    }

    /// Every non-zero element has the inverse `inverse()` returns, and zero has none.
    #[kani::proof]
    #[kani::unwind(65)]
    fn every_nonzero_element_has_an_inverse() {
        let a = any();
        match a.inverse() {
            Some(inv) => {
                assert!(!a.is_zero());
                assert_eq!(a * inv, Gf256::one());
            }
            None => assert!(a.is_zero()),
        }
    }

    /// `is_bit` accepts exactly 0 and 1: the check behind `gf_to_bit` and `NonBooleanInput`.
    #[kani::proof]
    #[kani::unwind(9)]
    fn is_bit_holds_exactly_for_zero_and_one() {
        let a = any();
        assert_eq!(a.is_bit(), a.0 == 0 || a.0 == 1);
    }

    /// The canonical domain — the powers of the generator — never repeats or hits zero within
    /// `MAX_DOMAIN_SIZE` elements, so share evaluation points are distinct and non-zero.
    #[kani::proof]
    #[kani::unwind(257)]
    fn the_generator_has_full_order() {
        let mut x = Gf256::one();
        let mut steps = 0usize;
        loop {
            x = x * Gf256::generator();
            steps += 1;
            assert!(!x.is_zero());
            if x == Gf256::one() {
                break;
            }
        }
        assert_eq!(steps, Gf256::MAX_DOMAIN_SIZE);
    }
}

/// The same axioms by plain enumeration (`cargo test`), including the one statement the solver
/// cannot finish: associativity over all `2^24` triples.
#[cfg(test)]
mod gf256_exhaustive {
    use super::gf2k::field::{BinaryField, Gf256};

    #[test]
    fn multiplication_is_associative_on_every_triple() {
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                let ab = Gf256(a) * Gf256(b);
                for c in 0..=255u8 {
                    assert_eq!(ab * Gf256(c), Gf256(a) * (Gf256(b) * Gf256(c)));
                }
            }
        }
    }

    #[test]
    fn multiplication_distributes_on_every_triple() {
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                for c in 0..=255u8 {
                    let (a, b, c) = (Gf256(a), Gf256(b), Gf256(c));
                    assert_eq!(a * (b + c), a * b + a * c);
                }
            }
        }
    }

    #[test]
    fn every_nonzero_element_has_an_inverse() {
        assert!(Gf256::zero().inverse().is_none());
        for a in 1..=255u8 {
            assert_eq!(Gf256(a) * Gf256(a).inverse().unwrap(), Gf256::one());
        }
    }
}
