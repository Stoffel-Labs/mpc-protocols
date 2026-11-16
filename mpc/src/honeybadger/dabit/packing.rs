//! Bit packing of dealt daBit batches: LSB-first, unused high bits of the last byte cleared.
//!
//! Canonical packing matters: the echo compares bytes, so two honest holders must agree on the
//! padding as well as on the bits.
//!
//! This file depends on nothing but `core`, so that `formal/kani` can model-check it in
//! isolation. Keep it that way.

pub(super) fn packed_len(count: usize) -> usize {
    count.div_ceil(8)
}

pub(super) fn bit_at(packed: &[u8], index: usize) -> bool {
    packed
        .get(index / 8)
        .is_some_and(|byte| (byte >> (index % 8)) & 1 == 1)
}

pub(super) fn clear_padding(packed: &mut [u8], count: usize) {
    let used = count % 8;
    if used != 0 {
        if let Some(last) = packed.last_mut() {
            *last &= (1u8 << used) - 1;
        }
    }
}

pub(super) fn is_canonical(packed: &[u8], count: usize) -> bool {
    if packed.len() != packed_len(count) {
        return false;
    }
    let used = count % 8;
    used == 0 || packed.last().is_none_or(|last| last >> used == 0)
}

/// Bounded model checking of the bit packing with Kani. Run from `formal/kani`, which compiles
/// this very file on its own: `cargo kani`.
///
/// The echo compares packed bytes, and every share is derived from `bit_at`. These harnesses
/// check, for every batch size up to 16 and every byte content, that the two views agree.
#[cfg(kani)]
mod verification {
    use super::*;

    const MAX_COUNT: usize = 16;

    fn any_count() -> usize {
        let count: usize = kani::any();
        kani::assume(count >= 1 && count <= MAX_COUNT);
        count
    }

    /// What `sample_bits` produces is canonical, whatever the generator returned.
    #[kani::proof]
    fn clear_padding_yields_a_canonical_packing() {
        let count = any_count();
        let mut bytes: [u8; 2] = kani::any();
        let packed = &mut bytes[..packed_len(count)];
        clear_padding(packed, count);
        assert!(is_canonical(packed, count));
    }

    /// Clearing the padding changes no bit of the batch.
    #[kani::proof]
    #[kani::unwind(17)]
    fn clear_padding_keeps_every_bit() {
        let count = any_count();
        let before: [u8; 2] = kani::any();
        let mut after = before;
        let len = packed_len(count);
        clear_padding(&mut after[..len], count);
        for index in 0..count {
            assert_eq!(bit_at(&before[..len], index), bit_at(&after[..len], index));
        }
    }

    /// Two canonical packings are byte-equal exactly when they hold the same bits: an echo that
    /// compares bytes compares the bits, no more and no less.
    #[kani::proof]
    #[kani::unwind(17)]
    fn canonical_packings_are_equal_iff_their_bits_are() {
        let count = any_count();
        let a: [u8; 2] = kani::any();
        let b: [u8; 2] = kani::any();
        let len = packed_len(count);
        let (a, b) = (&a[..len], &b[..len]);
        kani::assume(is_canonical(a, count) && is_canonical(b, count));
        let mut same_bits = true;
        for index in 0..count {
            if bit_at(a, index) != bit_at(b, index) {
                same_bits = false;
            }
        }
        assert_eq!(a == b, same_bits);
    }

    /// A canonical packing carries nothing outside the batch: every position past `count` reads
    /// as zero, so a dealer cannot smuggle a value through the padding.
    #[kani::proof]
    fn nothing_is_readable_past_the_batch() {
        let count = any_count();
        let bytes: [u8; 2] = kani::any();
        let packed = &bytes[..packed_len(count)];
        kani::assume(is_canonical(packed, count));
        let index: usize = kani::any();
        kani::assume(index >= count);
        assert!(!bit_at(packed, index));
    }
}
