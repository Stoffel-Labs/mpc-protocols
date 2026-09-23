#![allow(dead_code)]
//! Width and circuit-shape helpers shared by the three conversion-correctness test binaries
//! (`a2b_test.rs`, `b2a_test.rs`, `a2b_node_test.rs`).
//!
//! Two things live here that [`utils::a2b_utils`] deliberately does not carry, because they are
//! about the *shape* of the conversion rather than about dealing its preprocessing:
//!
//! * the `ell = 33` fixed-point width and the corpus that exercises it, and
//! * clear-text models of the **depth-13 serial chain** the A2B circuit used to be and the
//!   **depth-7 parallel offset adder** that replaced it, so that "the new circuit computes the
//!   same function" is a checkable statement and not a claim in a commit message.
//!
//! Everything here is pure: no network, no shares, no async. The only protocol object it touches
//! is [`Builder`], and only to rebuild the replaced netlist for its cost — evaluating a netlist in
//! the clear is crate-private, so output equivalence is pinned against the `u64` models below and
//! against the real protocol's output, not against a re-evaluated netlist.

use stoffelcrypto::common::math::goldilocks::GoldilocksField;
use stoffelcrypto::common::types::fixed::FixedPointPrecision;
use stoffelcrypto::honeybadger::binary_circuits::prefix::{add_public_constant, mux};
use stoffelcrypto::honeybadger::binary_circuits::{Builder, Netlist};

pub type F = GoldilocksField;

/// `p = 2^64 - 2^32 + 1`, the Goldilocks modulus.
pub const P: u64 = 0xFFFF_FFFF_0000_0001;

/// `d = 2^64 - p = 2^32 - 1`. The offset both circuits are built around: `A >= p` iff `A + d`
/// carries out of bit 63, which is what turns the second addition into the conditional reduction.
pub const DELTA: u64 = P.wrapping_neg();

/// The bound the A2B preprocessing is sized at, and the depth it runs at, after the plan's §1.5
/// change. Quoted here so the two files that assert them agree on one pair of numbers.
pub const PARALLEL_AND_BOUND: usize = 695;
pub const PARALLEL_DEPTH: usize = 7;

/// The same two figures for the serial `ADD64 -> ADD64 -> MUX` chain this replaced: `321` for the
/// first adder under an all-ones `y` (its carry out is live there, and feeds the `c1 XOR c2`),
/// `241` for the second, whose public operand is the sparse constant `d = 2^32 - 1`, and `64` for
/// the multiplexer.
pub const SERIAL_AND_BOUND: usize = 626;
pub const SERIAL_DEPTH: usize = 13;

// -------------------------------------------------------------------------------------------
// The fixed-point width
// -------------------------------------------------------------------------------------------

/// The repo's default fixed-point precision, `(k, f) = (32, 16)` (`types/fixed.rs`).
///
/// Constructed rather than read from `global_precision()`: that is a process-wide `OnceLock`, and
/// a test that initialised it would change the behaviour of every other test sharing the binary.
pub fn fixed_point_precision() -> FixedPointPrecision {
    FixedPointPrecision::new(32, 16)
}

/// `ell = k + 1 = 33`, the conversion width the default precision carries (plan §2.4).
///
/// The `+1` is the headroom bit, and it is not decorative. `truncpr.rs:192` carries a signed
/// `k`-bit `a` into the non-negative domain as `b = 2^(k-1) + a`, which lands in `[0, 2^k]` — a
/// closed interval, so `2^k` itself is reachable and `k` bits do not suffice for it. It is also
/// the bit an unrescaled *sum* of two shifted operands sets. A conversion sized at `k` bits is
/// therefore right on every value it was tested with and wrong on the carry.
pub fn fixed_point_width() -> usize {
    fixed_point_precision().k() + 1
}

/// The shift `truncpr` already applies, `b = 2^(k-1) + v`, for a signed `k`-bit `v`.
///
/// Panics on a `v` outside `[-2^(k-1), 2^(k-1)]`, which is the caller's obligation and not
/// something the conversion can check.
pub fn shift_to_unsigned(v: i64) -> u64 {
    let k = fixed_point_precision().k();
    let half = 1i64 << (k - 1);
    assert!(
        (-half..=half).contains(&v),
        "{v} is outside the signed range the precision admits"
    );
    (v + half) as u64
}

/// The `ell = 33` payloads a fixed-point A2B/B2A has to get right, and why each is here.
///
/// These are *post-shift* values — non-negative integers below `2^33` — because that is the only
/// form in which a signed fixed-point value occupies 33 bits at all. The un-shifted form is the
/// subject of the standing negative result: `-1` encodes as `p - 1` and is 64 bits wide.
pub fn fixed_point_corpus() -> Vec<(&'static str, u64)> {
    let k = fixed_point_precision().k();
    let f = fixed_point_precision().f();
    vec![
        // `v = -2^(k-1)`, the most negative value, which the shift takes to exactly zero.
        ("shift(-2^31) = 0", 0),
        ("shift(-2^31 + 1) = 1", 1),
        // `v = 0` and `v = 1.0`: the two values a reader would hand-check.
        ("shift(0) = 2^31", 1u64 << (k - 1)),
        ("shift(1.0) = 2^31 + 2^16", (1u64 << (k - 1)) + (1u64 << f)),
        // `v = 2^(k-1) - 1`, the most positive: every one of the low `k` bits set, bit `k` clear.
        ("shift(2^31 - 1) = 2^32 - 1", (1u64 << k) - 1),
        // Bit `k` set. Unreachable from a single shifted value, reachable from the sum of two —
        // which is precisely the carry the headroom bit exists for.
        ("2^32, the headroom bit alone", 1u64 << k),
        ("2^32 + 1", (1u64 << k) + 1),
        // The widest payload `ell = 33` can carry, and the one an off-by-one in the width drops.
        ("2^33 - 1, every bit of the width", (1u64 << (k + 1)) - 1),
    ]
}

// -------------------------------------------------------------------------------------------
// Clear-text models of the two circuits
// -------------------------------------------------------------------------------------------

/// The **depth-13 serial chain**: `ADD64(y, r) -> ADD64(d, t1) -> MUX(c1 XOR c2)`.
///
/// This is the circuit `FieldA2BCircuit` used to build, transcribed as `u64` arithmetic. Its
/// reduction test is `c1 XOR c2`, where `c1` is the carry out of `y + r` and `c2` the carry out
/// of adding `d` to the truncated sum — so it needs the `(c1, c2) = (1, 1)`-unreachability lemma
/// to be sound, and it cannot start the second addition until the first has finished.
///
/// # Panics
///
/// Never; every operation is explicitly wrapping. The *result* is only the A2B of `y + r` when
/// `y < p` and `r < p`, which is the circuit's precondition and the caller's obligation.
pub fn serial_offset_adder(y: u64, r: u64) -> u64 {
    let (t1, c1) = y.overflowing_add(r);
    let (t2, c2) = t1.overflowing_add(DELTA);
    if c1 ^ c2 {
        t2
    } else {
        t1
    }
}

/// The **depth-7 parallel offset adder** (plan §1.5): the offset moves onto the *public* operand,
/// so the two additions read only `r` and run concurrently, and `c2` alone decides the reduction.
///
/// `c1` is never formed, which is what makes the unreachability lemma unnecessary rather than
/// merely free, and what lets `Builder::finish` delete the first adder's whole carry-out cone.
///
/// # Panics
///
/// Debug-asserts `y < p`. `Y = y + d` must not wrap, and that holds exactly when `y` is the
/// canonical representative of an opened field element — which `FieldA2BCircuit::new` enforces by
/// returning `MaskNotCanonical`.
pub fn parallel_offset_adder(y: u64, r: u64) -> u64 {
    debug_assert!(y < P, "the public operand must be canonical");
    let (t1, _c1) = y.overflowing_add(r);
    let (t2, c2) = y.wrapping_add(DELTA).overflowing_add(r);
    if c2 {
        t2
    } else {
        t1
    }
}

/// Little-endian bits of `value` at `width`, so a model's output can be compared against what a
/// conversion returns without going through `F`.
pub fn bits_le(value: u64, width: usize) -> Vec<bool> {
    (0..width).map(|i| (value >> i) & 1 == 1).collect()
}

/// `sum_i 2^i bits[i]` as a `u128`, so an overshoot past `2^64` shows up rather than wrapping.
pub fn as_integer(bits: &[bool]) -> u128 {
    bits.iter()
        .enumerate()
        .filter(|(_, set)| **set)
        .map(|(i, _)| 1u128 << i)
        .sum()
}

// -------------------------------------------------------------------------------------------
// The replaced netlist, rebuilt for its cost
// -------------------------------------------------------------------------------------------

/// Rebuilds the **serial** A2B netlist at its sizing bound, gate for gate, from the same public
/// `Builder` and prefix-adder primitives the parallel one is built from.
///
/// The bound is taken from an all-ones `y`, which is what the serial form could legitimately do:
/// nothing folds away under it, and unlike the parallel form there is no `Y = y + d` to wrap, so
/// an all-ones public operand is an *admissible* input there rather than a synthetic one. That
/// asymmetry is the whole reason the parallel circuit's bound has to be argued analytically.
///
/// Only the cost is used. There is no public evaluator for a `Netlist`, so this cannot be run
/// against the parallel circuit input by input; [`serial_offset_adder`] is the model that does
/// that job, and the AND count and depth here are what pin the netlist to it.
pub fn serial_a2b_netlist(width: usize) -> Netlist {
    let mut builder = Builder::new();
    let r = builder.inputs(width);
    let ones = vec![true; width];
    let delta = bits_le(DELTA, width);

    // `t1 = y + r`, carry out live: the serial chain's reduction test is `c1 XOR c2`.
    let (t1, c1) = add_public_constant(&mut builder, &ones, &r).expect("first adder");
    // `t2 = t1 + d`, which cannot start until `t1` exists — the serialisation that costs the
    // six extra AND layers.
    let (t2, c2) = add_public_constant(&mut builder, &delta, &t1).expect("second adder");
    let reduce = builder.xor(c1, c2);
    let outputs = mux(&mut builder, reduce, &t1, &t2).expect("multiplexer");
    builder.finish(&r, &outputs)
}
