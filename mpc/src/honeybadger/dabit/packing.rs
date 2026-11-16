//! Bit packing of dealt daBit batches: LSB-first, unused high bits of the last byte cleared.
//!
//! Canonical packing matters: the echo compares bytes, so two honest holders must agree on the
//! padding as well as on the bits.

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
