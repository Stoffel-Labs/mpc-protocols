//! Parallel-prefix gadgets: the carry networks, the `public + secret` adder built on them, and the
//! AND/OR/MUX helpers the A2B reduction needs.
//!
//! Everything in this module emits into a [`Builder`] and performs no I/O. The gadgets are written
//! as free functions over a builder so that a larger circuit (A2B is one addition, a second
//! addition, and a multiplexer) can fuse them into a single netlist and let the ASAP scheduler
//! overlap them; the wrapper structs at the bottom expose the same gadgets stand-alone, mostly so
//! they can be tested and costed in isolation.
//!
//! # The carry recurrence
//!
//! For `A + B` with `A` public and `B` secret, define per bit
//!
//! ```text
//! g_i = a_i AND b_i        -- "this position generates a carry"
//! p_i = a_i XOR b_i        -- "this position propagates an incoming carry"
//! ```
//!
//! Both are **free** here: `a_i` is public, so `g_i` is either `b_i` or the constant `0`, and `p_i`
//! is either `b_i` or `NOT b_i`. That is the whole reason A2B adds a public mask to a secret
//! sharing rather than two secret values — the generate/propagate layer of a secret+secret adder
//! costs `w` ANDs, and its prefix costs roughly twice as much again.
//!
//! The carries satisfy `c_i = g_i OR (p_i AND c_{i-1})`, with `c_{-1} = 0`. With the **XOR**
//! propagate the two terms are never both `1` (`g_i = 1` forces `a_i = b_i = 1`, hence `p_i = 0`),
//! so the `OR` is an `XOR` and the recurrence is the associative monoid
//!
//! ```text
//! (G, P) o (G', P') = (G + P G', P P')
//! ```
//!
//! whose prefix `(G_{i:0}, P_{i:0})` has `G_{i:0} = c_i`. The sum bits `s_i = p_i XOR c_{i-1}` and
//! the carry out `c_{w-1}` are then free.
//!
//! # Sklansky
//!
//! [`sklansky_plan`] realises that prefix in `ceil(log2 w)` levels. At level `d` the array is cut
//! into blocks of `2^(d+1)`; every index in the upper half of a block absorbs the block's lower
//! half, whose prefix is already sitting in its top element. Sources always lie strictly below
//! their targets and the two halves are disjoint, so a level can be applied in place, and the
//! plan truncates cleanly to any width that is not a power of two.
//!
//! A "black" cell costs 2 ANDs (`G` and `P`), a "grey" cell 1 (`P` is dead). Rather than special-
//! casing grey cells, this module emits both and lets [`Builder::finish`]'s liveness pass delete
//! the dead ones — which also deletes whole sub-trees when the public operand is sparse, and
//! collapses the network down to the single carry-out chain for a comparison.
//!
//! At `w = 64` that is 6 levels of 32 cells, so 384 ANDs before pruning. A full 64-bit adder keeps
//! at most 321 of them (all 192 generate cells — every carry is read — and 129 of the 192
//! propagate cells); against the sparse constant `2^32 - 1` it keeps 241, and a comparison, which
//! reads only the carry out, keeps 89. Note that 89 is the count for that *sparse* constant; a
//! uniform public value leaves 120 in the worst case and 99 on average, which is the figure a
//! comparison gadget over an arbitrary constant must be sized against.
//!
//! # Other topologies
//!
//! Sklansky is the minimum-depth point and the default. [`PrefixTopology`] also offers
//! [`brent_kung_plan`], which is 120 cells over 11 levels at `w = 64` — fewer triples, nearly
//! twice the rounds. The online phase is asynchronous and latency-bound, so nothing in the repo
//! selects it; it exists so that the choice is a parameter rather than a hard-coded point.

use super::{Builder, CircuitError, HasNetlist, Netlist};

/// `ceil(log2 width)` — the number of Sklansky levels needed to reach a full prefix.
pub fn sklansky_levels(width: usize) -> usize {
    if width <= 1 {
        return 0;
    }
    (usize::BITS - (width - 1).leading_zeros()) as usize
}

/// Which parallel-prefix network [`add_public_constant`] lays the carry recurrence out on.
///
/// The recurrence itself is fixed; only the *shape* of the tree that evaluates it changes, so
/// every topology here computes the same sum bits and the same carry out and differs only in
/// (ANDs, AND layers). AND layers are online **rounds**, and on an asynchronous BFT network a
/// round costs far more than a triple, which is why the default is the minimum-depth point.
///
/// | Topology | cells at `w = 64` | levels | A2B ANDs / depth (bound) |
/// |---|---|---|---|
/// | [`Sklansky`](PrefixTopology::Sklansky) | 192 | 6 | 695 / 7 |
/// | [`BrentKung`](PrefixTopology::BrentKung) | 120 | 11 | 407 / 11 |
///
/// This is a knob, not a policy: the online phase is asynchronous and latency-bound, so
/// [`PrefixTopology::Sklansky`] is the default and nothing in the repo selects anything else. A
/// deployment that is bandwidth-bound rather than latency-bound can trade the other way, and a
/// caller that does must say so explicitly at the call site.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum PrefixTopology {
    /// Depth `ceil(log2 w)`, roughly `(w/2) log2 w` cells. Minimum depth; the default.
    #[default]
    Sklansky,
    /// The Brent-Kung up-sweep/down-sweep, `2 ceil(log2 w) - 1` levels and about `2w` cells.
    /// At `w = 64` it takes A2B to 407 ANDs over 11 layers: 41% fewer triples for 57% more
    /// online rounds.
    BrentKung,
}

/// The prefix network of `topology` for `width` positions.
///
/// `plan[d]` lists the `(target, source)` cells of level `d`. Whatever the topology, every plan
/// satisfies the three properties [`add_public_constant`] relies on: a source always lies strictly
/// below its target, a target is written at most once per level, and the span a cell absorbs is
/// exactly adjacent to the span its target already holds — so after the last level every position
/// holds the prefix over `[0, i]`.
pub fn prefix_plan(topology: PrefixTopology, width: usize) -> Vec<Vec<(usize, usize)>> {
    match topology {
        PrefixTopology::Sklansky => sklansky_plan(width),
        PrefixTopology::BrentKung => brent_kung_plan(width),
    }
}

/// The Brent-Kung prefix network for `width` positions.
///
/// Two sweeps. The **up-sweep** is the reduction tree: at level `d` every position whose index is
/// `2^(d+1) - 1` modulo `2^(d+1)` absorbs the position `2^d` below it, so afterwards a position
/// with exactly `m` trailing one-bits holds the span `[i - 2^m + 1, i]` and the top of each
/// complete block holds a full prefix. The **down-sweep** fills the rest in decreasing order of
/// `m`: when it reaches the positions with exactly `m` trailing ones, position `i - 2^m` already
/// holds `[0, i - 2^m]` (its trailing-one count is strictly greater), so one cell completes them.
///
/// Levels that come out empty — at the top of the up-sweep for a narrow `width`, and at the start
/// of the down-sweep always — are dropped rather than emitted, so `plan.len()` is the real depth.
/// At `w = 64` that is 11 levels of 120 cells, against Sklansky's 6 of 192.
pub fn brent_kung_plan(width: usize) -> Vec<Vec<(usize, usize)>> {
    let levels = sklansky_levels(width);
    let mut plan: Vec<Vec<(usize, usize)>> = Vec::with_capacity(2 * levels);

    // Up-sweep: targets are the tops of the blocks of size 2^(d+1).
    for d in 0..levels {
        let half = 1usize << d;
        let block = half << 1;
        let mut cells = Vec::new();
        let mut target = block - 1;
        while target < width {
            cells.push((target, target - half));
            target += block;
        }
        if !cells.is_empty() {
            plan.push(cells);
        }
    }

    // Down-sweep: level `d` completes exactly the positions with `d` trailing one-bits, i.e.
    // `i == 2^d - 1` modulo `2^(d+1)`. The first such position has no source below it.
    for d in (0..levels).rev() {
        let half = 1usize << d;
        let block = half << 1;
        let mut cells = Vec::new();
        let mut target = half - 1;
        while target < width {
            if target >= half {
                cells.push((target, target - half));
            }
            target += block;
        }
        if !cells.is_empty() {
            plan.push(cells);
        }
    }

    plan
}

/// The Sklansky prefix network for `width` positions.
///
/// `plan[d]` lists the `(target, source)` cells of level `d`. After level `d` position `i` holds
/// the prefix over `[i & !(2^(d+1) - 1), i]`, so after `sklansky_levels(width)` levels every
/// position holds the prefix over `[0, i]`.
///
/// Cells whose target is past `width` are dropped; since a source always lies strictly below its
/// target, the remaining cells are exactly the ones a power-of-two network would have run, which
/// is why a non-power-of-two width needs no padding wires.
pub fn sklansky_plan(width: usize) -> Vec<Vec<(usize, usize)>> {
    let levels = sklansky_levels(width);
    let mut plan = Vec::with_capacity(levels);
    for d in 0..levels {
        let half = 1usize << d;
        let block = half << 1;
        let mut cells = Vec::new();
        let mut start = 0usize;
        while start < width {
            let source = start + half - 1;
            if source < width {
                let end = (start + block).min(width);
                for target in (start + half)..end {
                    cells.push((target, source));
                }
            }
            start += block;
        }
        plan.push(cells);
    }
    plan
}

/// `constant + x` over `w = x.len()` bits, where `constant` is public and `x` is a little-endian
/// vector of secret bit wires.
///
/// Returns `(sum, carry_out)`: `sum` is the `w` low bits of the integer sum, LSB first, and
/// `carry_out` is bit `w` — so the true integer value is `carry_out * 2^w + sum`.
///
/// Costs, after liveness: `(w/2) * ceil(log2 w)` ANDs for the generate half of the prefix — fewer
/// where `constant` is sparse — plus the propagate cells that survive, in at most `ceil(log2 w)`
/// AND layers. At `w = 64` that is 321 for the worst (all-ones) constant, 241 for `2^32 - 1`, and
/// 0 for a zero constant, which folds the whole circuit away.
///
/// Uses the default [`PrefixTopology`]; [`add_public_constant_on`] takes one explicitly.
pub fn add_public_constant(
    builder: &mut Builder,
    constant: &[bool],
    x: &[usize],
) -> Result<(Vec<usize>, usize), CircuitError> {
    add_public_constant_on(builder, PrefixTopology::default(), constant, x)
}

/// [`add_public_constant`] over an explicitly chosen prefix network.
///
/// The gate-level construction is identical — generate/propagate seeding, the prefix, and the free
/// sum bits; only [`prefix_plan`] changes. Every topology yields the same `(sum, carry_out)`, so
/// this is a cost knob and never a semantic one.
pub fn add_public_constant_on(
    builder: &mut Builder,
    topology: PrefixTopology,
    constant: &[bool],
    x: &[usize],
) -> Result<(Vec<usize>, usize), CircuitError> {
    let width = x.len();
    if width == 0 {
        return Err(CircuitError::EmptyInput);
    }
    if constant.len() != width {
        return Err(CircuitError::InputLengthMismatch {
            expected: width,
            got: constant.len(),
        });
    }

    // Generate / propagate — both free, because one operand is public.
    let zero = builder.constant(false);
    let mut generate: Vec<usize> = Vec::with_capacity(width);
    let mut propagate_seed: Vec<usize> = Vec::with_capacity(width);
    for i in 0..width {
        generate.push(if constant[i] { x[i] } else { zero });
        propagate_seed.push(builder.xor_const(x[i], constant[i]));
    }
    let mut propagate = propagate_seed.clone();

    for level in prefix_plan(topology, width) {
        // Snapshot: a cell must combine the *pre-level* pairs. Sources sit in the lower half of a
        // block and targets in the upper half, so the two never collide, but the snapshot makes
        // that independent of the order cells happen to be listed in.
        let generate_prev = generate.clone();
        let propagate_prev = propagate.clone();
        for (target, source) in level {
            generate[target] = builder.and_xor(
                propagate_prev[target],
                generate_prev[source],
                generate_prev[target],
            );
            propagate[target] = builder.and(propagate_prev[target], propagate_prev[source]);
        }
    }

    // s_0 = p_0 (there is no incoming carry); s_i = p_i XOR c_{i-1}. All free.
    let mut sum = Vec::with_capacity(width);
    sum.push(propagate_seed[0]);
    for i in 1..width {
        sum.push(builder.xor(propagate_seed[i], generate[i - 1]));
    }
    Ok((sum, generate[width - 1]))
}

/// `x >= c` for a public `c`, given `complement` = the `w` little-endian bits of `2^w - c`.
///
/// `x >= c` exactly when `x + (2^w - c) >= 2^w`, i.e. exactly when the addition carries out of the
/// top bit — so this is [`add_public_constant`] with every wire but the carry left dead, and
/// [`Builder::finish`] prunes the rest of the prefix network away.
///
/// The caller supplies the complement rather than `c` itself because computing `2^w - c` needs
/// arbitrary-precision arithmetic over the field's modulus, which lives in
/// `common::convert::two_pow_w_minus_modulus_bits`. Note `c = 0` has no `w`-bit complement; the
/// comparison is trivially true in that case and the caller must handle it.
pub fn geq_public_constant(
    builder: &mut Builder,
    complement: &[bool],
    x: &[usize],
) -> Result<usize, CircuitError> {
    let (_, carry_out) = add_public_constant(builder, complement, x)?;
    Ok(carry_out)
}

/// Balanced AND of every wire in `xs`: `xs.len() - 1` gates, `ceil(log2 xs.len())` layers.
///
/// C13: an empty input is rejected rather than folded to the constant `1`, which would make a
/// downstream "all of these bits are set" test pass vacuously.
pub fn and_tree(builder: &mut Builder, xs: &[usize]) -> Result<usize, CircuitError> {
    if xs.is_empty() {
        return Err(CircuitError::EmptyInput);
    }
    let mut level: Vec<usize> = xs.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i + 1 < level.len() {
            next.push(builder.and(level[i], level[i + 1]));
            i += 2;
        }
        if i < level.len() {
            next.push(level[i]);
        }
        level = next;
    }
    level.first().copied().ok_or(CircuitError::EmptyInput)
}

/// Balanced OR of every wire in `xs`, as `NOT AND_i (NOT x_i)`. Same cost as [`and_tree`] — the
/// negations are free in characteristic 2.
pub fn or_tree(builder: &mut Builder, xs: &[usize]) -> Result<usize, CircuitError> {
    if xs.is_empty() {
        return Err(CircuitError::EmptyInput);
    }
    let mut negated = Vec::with_capacity(xs.len());
    for &x in xs {
        negated.push(builder.xor_const(x, true));
    }
    let all = and_tree(builder, &negated)?;
    Ok(builder.xor_const(all, true))
}

/// Bitwise select: `cond ? b : a`, as `a_i XOR cond (a_i XOR b_i)`.
///
/// One AND per bit, one layer. Note the `cond (a XOR b)` form and not `cond b + (1 - cond) a`:
/// the latter is two ANDs per bit in a prime field and, here, would also need the constant `1`
/// materialised as a sharing.
pub fn mux(
    builder: &mut Builder,
    cond: usize,
    a: &[usize],
    b: &[usize],
) -> Result<Vec<usize>, CircuitError> {
    if a.is_empty() {
        return Err(CircuitError::EmptyInput);
    }
    if a.len() != b.len() {
        return Err(CircuitError::InputLengthMismatch {
            expected: a.len(),
            got: b.len(),
        });
    }
    let mut out = Vec::with_capacity(a.len());
    for i in 0..a.len() {
        let diff = builder.xor(a[i], b[i]);
        out.push(builder.and_xor(cond, diff, a[i]));
    }
    Ok(out)
}

/// Stand-alone `public constant + secret` adder.
///
/// Inputs: `width` secret bit shares, LSB first.
/// Outputs: `width` sum bits, LSB first, followed by the carry out — `width + 1` shares in total.
#[derive(Clone, Debug)]
pub struct PublicPlusSecretAdder {
    width: usize,
    constant: Vec<bool>,
    net: Netlist,
}

impl PublicPlusSecretAdder {
    pub fn new(constant: Vec<bool>) -> Result<Self, CircuitError> {
        let width = constant.len();
        if width == 0 {
            return Err(CircuitError::UnsupportedWidth(0));
        }
        let mut builder = Builder::new();
        let x = builder.inputs(width);
        let (sum, carry) = add_public_constant(&mut builder, &constant, &x)?;
        let mut outputs = sum;
        outputs.push(carry);
        let net = builder.finish(&x, &outputs);
        Ok(PublicPlusSecretAdder {
            width,
            constant,
            net,
        })
    }

    pub fn width(&self) -> usize {
        self.width
    }

    /// The public operand, LSB first.
    pub fn constant(&self) -> &[bool] {
        &self.constant
    }
}

impl HasNetlist for PublicPlusSecretAdder {
    fn netlist(&self) -> &Netlist {
        &self.net
    }
}

/// Stand-alone balanced AND over `width` secret bits. One output.
#[derive(Clone, Debug)]
pub struct AndTree {
    width: usize,
    net: Netlist,
}

impl AndTree {
    pub fn new(width: usize) -> Result<Self, CircuitError> {
        if width == 0 {
            return Err(CircuitError::UnsupportedWidth(0));
        }
        let mut builder = Builder::new();
        let x = builder.inputs(width);
        let out = and_tree(&mut builder, &x)?;
        let net = builder.finish(&x, &[out]);
        Ok(AndTree { width, net })
    }

    pub fn width(&self) -> usize {
        self.width
    }
}

impl HasNetlist for AndTree {
    fn netlist(&self) -> &Netlist {
        &self.net
    }
}

/// Stand-alone bitwise multiplexer.
///
/// Inputs: the condition bit, then `width` bits of `a`, then `width` bits of `b` — `2 * width + 1`
/// shares. Outputs: `width` bits, `cond ? b : a`.
#[derive(Clone, Debug)]
pub struct Mux {
    width: usize,
    net: Netlist,
}

impl Mux {
    pub fn new(width: usize) -> Result<Self, CircuitError> {
        if width == 0 {
            return Err(CircuitError::UnsupportedWidth(0));
        }
        let mut builder = Builder::new();
        let wires = builder.inputs(2 * width + 1);
        let cond = wires[0];
        let a = wires[1..=width].to_vec();
        let b = wires[width + 1..].to_vec();
        let out = mux(&mut builder, cond, &a, &b)?;
        let net = builder.finish(&wires, &out);
        Ok(Mux { width, net })
    }

    pub fn width(&self) -> usize {
        self.width
    }
}

impl HasNetlist for Mux {
    fn netlist(&self) -> &Netlist {
        &self.net
    }
}

#[cfg(test)]
mod tests {
    use super::super::evaluate_in_the_clear;
    use super::*;

    /// Little-endian bits of `value`, exactly `width` of them.
    fn bits_le(value: u64, width: usize) -> Vec<bool> {
        (0..width).map(|i| (value >> i) & 1 == 1).collect()
    }

    fn u64_from_bits(bits: &[bool]) -> u64 {
        let mut acc = 0u64;
        for (i, b) in bits.iter().enumerate() {
            if *b {
                acc |= 1u64 << i;
            }
        }
        acc
    }

    #[test]
    fn test_sklansky_levels() {
        assert_eq!(sklansky_levels(1), 0);
        assert_eq!(sklansky_levels(2), 1);
        assert_eq!(sklansky_levels(3), 2);
        assert_eq!(sklansky_levels(4), 2);
        assert_eq!(sklansky_levels(5), 3);
        assert_eq!(sklansky_levels(8), 3);
        assert_eq!(sklansky_levels(64), 6);
    }

    /// The 64-bit network is the textbook one: 6 levels of 32 cells, 192 in total, every source
    /// strictly below its target and every target touched at most once per level.
    #[test]
    fn test_sklansky_plan_shape_64() {
        let plan = sklansky_plan(64);
        assert_eq!(plan.len(), 6, "Sklansky depth at width 64");
        assert_eq!(
            plan.iter().map(Vec::len).sum::<usize>(),
            192,
            "Sklansky cell count at width 64"
        );
        for level in &plan {
            assert_eq!(level.len(), 32);
            let mut seen = std::collections::HashSet::new();
            for &(target, source) in level {
                assert!(
                    source < target,
                    "source {source} must precede target {target}"
                );
                assert!(target < 64);
                assert!(
                    seen.insert(target),
                    "target {target} updated twice in one level"
                );
            }
        }
    }

    /// The prefix invariant, checked structurally for every width up to 40: after level `d` index
    /// `i` must span `[i & !(2^(d+1) - 1), i]`, and after the last level `[0, i]`.
    #[test]
    fn test_sklansky_prefix_spans() {
        for width in 1..=40usize {
            let mut span: Vec<usize> = (0..width).collect(); // span[i] = low end of [lo, i]
            for (d, level) in sklansky_plan(width).iter().enumerate() {
                for &(target, source) in level {
                    assert_eq!(
                        span[target],
                        source + 1,
                        "level {d} target {target} is not adjacent to its source"
                    );
                    span[target] = span[source];
                }
                let block = 1usize << (d + 1);
                for i in 0..width {
                    assert_eq!(
                        span[i],
                        i & !(block - 1),
                        "width {width} level {d} index {i}"
                    );
                }
            }
            for i in 0..width {
                assert_eq!(span[i], 0, "width {width} index {i} not a full prefix");
            }
        }
    }

    /// Exhaustive: every public constant against every secret operand, for every width up to 8.
    /// This is the test that pins the carry recurrence, the grey/black cell folding and the
    /// truncation of the plan at non-power-of-two widths.
    #[test]
    fn test_adder_exhaustive_small_widths() {
        for width in 1..=8usize {
            let span = 1u64 << width;
            for a in 0..span {
                let adder = PublicPlusSecretAdder::new(bits_le(a, width)).expect("adder");
                assert!(
                    adder.layers() <= sklansky_levels(width),
                    "width {width} constant {a}: depth exceeded the Sklansky bound"
                );
                for b in 0..span {
                    let out = evaluate_in_the_clear(&adder, &bits_le(b, width)).expect("eval");
                    assert_eq!(out.len(), width + 1);
                    let sum = u64_from_bits(&out[..width]);
                    let carry = out[width];
                    let expected = a + b;
                    assert_eq!(sum, expected % span, "width {width}: {a} + {b} low bits");
                    assert_eq!(
                        carry,
                        expected >= span,
                        "width {width}: {a} + {b} carry out"
                    );
                }
            }
        }
    }

    /// 64-bit vectors, including every boundary the Goldilocks reduction turns on.
    #[test]
    fn test_adder_64bit_vectors() {
        const P: u64 = 0xFFFF_FFFF_0000_0001; // 2^64 - 2^32 + 1
        let vectors: [u64; 12] = [
            0,
            1,
            2,
            0xFFFF_FFFF,   // 2^32 - 1, the reduction constant
            0x1_0000_0000, // 2^32
            0x1_0000_0001, // 2^32 + 1
            P - 1,
            P,
            P + 1,
            u64::MAX,              // 2^64 - 1
            0x8000_0000_0000_0000, // 2^63
            0x1234_5678_9ABC_DEF0,
        ];
        for &a in &vectors {
            let adder = PublicPlusSecretAdder::new(bits_le(a, 64)).expect("adder");
            for &b in &vectors {
                let out = evaluate_in_the_clear(&adder, &bits_le(b, 64)).expect("eval");
                let sum = u64_from_bits(&out[..64]);
                let carry = out[64];
                assert_eq!(sum, a.wrapping_add(b), "{a:#x} + {b:#x} low 64 bits");
                assert_eq!(
                    carry,
                    (a as u128 + b as u128) >= 1u128 << 64,
                    "{a:#x} + {b:#x} carry out"
                );
            }
        }
    }

    /// The worst case over all 64-bit constants is the all-ones constant: nothing folds away.
    #[test]
    fn test_adder_64bit_gate_budget() {
        let adder = PublicPlusSecretAdder::new(vec![true; 64]).expect("adder");
        assert_eq!(
            adder.layers(),
            6,
            "a 64-bit Sklansky adder must be 6 AND layers deep"
        );
        assert_eq!(
            adder.and_count(),
            321,
            "64-bit public+secret Sklansky adder AND count (192 generate + 129 propagate)"
        );

        // Every other constant folds at least as much away.
        for constant in [0u64, 1, 0xFFFF_FFFF, P_MINUS_ONE, 0xAAAA_AAAA_AAAA_AAAA] {
            let a = PublicPlusSecretAdder::new(bits_le(constant, 64)).expect("adder");
            assert!(
                a.and_count() <= 321,
                "constant {constant:#x} exceeded the all-ones budget"
            );
        }
    }

    const P_MINUS_ONE: u64 = 0xFFFF_FFFF_0000_0000;

    /// The Goldilocks reduction constant `2^32 - 1` is sparse in exactly the way the folding
    /// exploits: the top half generates nothing, so its half of the prefix collapses to a
    /// propagate-only chain.
    #[test]
    fn test_adder_sparse_constant_is_cheaper() {
        let sparse = PublicPlusSecretAdder::new(bits_le(0xFFFF_FFFF, 64)).expect("adder");
        assert_eq!(sparse.and_count(), 241, "ADD64 against 2^32 - 1 AND count");
        assert_eq!(sparse.layers(), 6);
    }

    #[test]
    fn test_and_tree_and_or_tree() {
        for width in 1..=10usize {
            let tree = AndTree::new(width).expect("tree");
            assert_eq!(tree.and_count(), width - 1);
            assert_eq!(tree.layers(), sklansky_levels(width));
            for value in 0..(1u64 << width) {
                let inputs = bits_le(value, width);
                let out = evaluate_in_the_clear(&tree, &inputs).expect("eval");
                assert_eq!(out.len(), 1);
                assert_eq!(out[0], inputs.iter().all(|b| *b), "AND over {value:#b}");
            }
        }
        assert!(AndTree::new(0).is_err());
    }

    /// `or_tree` is `and_tree` under free negations, so it is checked the same way: exhaustively,
    /// against the clear-text OR.
    #[test]
    fn test_or_tree_values() {
        for width in 1..=8usize {
            let mut builder = Builder::new();
            let x = builder.inputs(width);
            let out = or_tree(&mut builder, &x).expect("or tree");
            let net = builder.finish(&x, &[out]);
            assert_eq!(net.and_count(), width - 1);
            for value in 0..(1u64 << width) {
                let inputs = bits_le(value, width);
                let got = evaluate_in_the_clear(&net, &inputs).expect("eval");
                assert_eq!(got[0], inputs.iter().any(|b| *b), "OR over {value:#b}");
            }
        }
    }

    /// The Brent-Kung network at width 64: a 6-level up-sweep and a 5-level down-sweep, 120 cells
    /// against Sklansky's 192, with the same structural guarantees the emitter relies on.
    #[test]
    fn test_brent_kung_plan_shape_64() {
        let plan = brent_kung_plan(64);
        assert_eq!(plan.len(), 11, "Brent-Kung depth at width 64");
        assert_eq!(
            plan.iter().map(Vec::len).sum::<usize>(),
            120,
            "Brent-Kung cell count at width 64"
        );
        assert_eq!(
            plan.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![32, 16, 8, 4, 2, 1, 1, 3, 7, 15, 31],
            "up-sweep halves, then the down-sweep fills in"
        );
        for level in &plan {
            let mut seen = std::collections::HashSet::new();
            for &(target, source) in level {
                assert!(
                    source < target,
                    "source {source} must precede target {target}"
                );
                assert!(target < 64);
                assert!(
                    seen.insert(target),
                    "target {target} updated twice in one level"
                );
            }
        }
    }

    /// The one property [`add_public_constant_on`] actually needs from a plan, checked for every
    /// topology and every width up to 40: each cell absorbs the span immediately below the one its
    /// target already holds, and after the last level every position spans `[0, i]`.
    #[test]
    fn test_every_topology_reaches_a_full_prefix() {
        for topology in [PrefixTopology::Sklansky, PrefixTopology::BrentKung] {
            for width in 1..=40usize {
                let mut span: Vec<usize> = (0..width).collect(); // span[i] = low end of [lo, i]
                for (d, level) in prefix_plan(topology, width).iter().enumerate() {
                    let before = span.clone();
                    for &(target, source) in level {
                        assert_eq!(
                            before[target],
                            source + 1,
                            "{topology:?} width {width} level {d}: target {target} is not \
                             adjacent to its source"
                        );
                        span[target] = before[source];
                    }
                }
                for i in 0..width {
                    assert_eq!(
                        span[i], 0,
                        "{topology:?} width {width}: index {i} is not a full prefix"
                    );
                }
            }
        }
    }

    /// Exhaustive over every constant and every operand up to width 8: a topology may change the
    /// cost but never the value.
    #[test]
    fn test_brent_kung_adder_exhaustive_small_widths() {
        for width in 1..=8usize {
            let span = 1u64 << width;
            for a in 0..span {
                let constant = bits_le(a, width);
                let mut builder = Builder::new();
                let x = builder.inputs(width);
                let (sum, carry) =
                    add_public_constant_on(&mut builder, PrefixTopology::BrentKung, &constant, &x)
                        .expect("adder");
                let mut outputs = sum;
                outputs.push(carry);
                let net = builder.finish(&x, &outputs);
                for b in 0..span {
                    let out = evaluate_in_the_clear(&net, &bits_le(b, width)).expect("eval");
                    let expected = a + b;
                    assert_eq!(
                        u64_from_bits(&out[..width]),
                        expected % span,
                        "width {width}: {a} + {b} low bits"
                    );
                    assert_eq!(
                        out[width],
                        expected >= span,
                        "width {width}: {a} + {b} carry"
                    );
                }
            }
        }
    }

    /// At width 64 the trade is explicit: Brent-Kung spends fewer triples over more rounds, and
    /// agrees with Sklansky on every boundary vector.
    #[test]
    fn test_brent_kung_trades_ands_for_layers_at_64() {
        const P: u64 = 0xFFFF_FFFF_0000_0001;
        let constant = bits_le(u64::MAX, 64);

        let sklansky = PublicPlusSecretAdder::new(constant.clone()).expect("adder");

        let mut builder = Builder::new();
        let x = builder.inputs(64);
        let (sum, carry) =
            add_public_constant_on(&mut builder, PrefixTopology::BrentKung, &constant, &x)
                .expect("adder");
        let mut outputs = sum;
        outputs.push(carry);
        let brent_kung = builder.finish(&x, &outputs);

        assert_eq!(sklansky.and_count(), 321);
        assert_eq!(sklansky.layers(), 6);
        assert_eq!(brent_kung.and_count(), 177);
        // 11 plan levels, but the last down-sweep level only fills carries that the sum bits
        // read as free XORs, so one level holds no surviving AND and `finish` collapses it.
        assert_eq!(brent_kung.layers(), 10);

        for &b in &[
            0u64,
            1,
            0xFFFF_FFFF,
            P - 1,
            P,
            u64::MAX,
            0x8000_0000_0000_0000,
        ] {
            let got = evaluate_in_the_clear(&brent_kung, &bits_le(b, 64)).expect("eval");
            let want = evaluate_in_the_clear(&sklansky, &bits_le(b, 64)).expect("eval");
            assert_eq!(got, want, "topologies disagree on {b:#x}");
        }
    }

    /// `geq_public_constant` keeps only the carry-out chain, so it must cost strictly less than
    /// the full adder while agreeing with it on every boundary.
    #[test]
    fn test_geq_public_constant_matches_full_adder() {
        const P: u64 = 0xFFFF_FFFF_0000_0001;
        // 2^64 - p = 2^32 - 1.
        let complement = bits_le(0xFFFF_FFFF, 64);

        let mut builder = Builder::new();
        let x = builder.inputs(64);
        let carry = geq_public_constant(&mut builder, &complement, &x).expect("geq");
        let net = builder.finish(&x, &[carry]);

        let full = PublicPlusSecretAdder::new(complement.clone()).expect("adder");
        assert!(
            net.and_count() < full.and_count(),
            "the comparison must prune the sum bits away"
        );

        for value in [
            0u64,
            1,
            0xFFFF_FFFF,
            0x1_0000_0000,
            P - 2,
            P - 1,
            P,
            P + 1,
            u64::MAX,
        ] {
            let got = evaluate_in_the_clear(&net, &bits_le(value, 64)).expect("eval");
            assert_eq!(got[0], value >= P, "{value:#x} >= p");
        }
    }

    #[test]
    fn test_mux() {
        for width in 1..=6usize {
            let gadget = Mux::new(width).expect("mux");
            assert_eq!(gadget.and_count(), width);
            assert_eq!(gadget.layers(), 1);
            for cond in [false, true] {
                for a in 0..(1u64 << width) {
                    for b in 0..(1u64 << width) {
                        let mut inputs = vec![cond];
                        inputs.extend(bits_le(a, width));
                        inputs.extend(bits_le(b, width));
                        let out = evaluate_in_the_clear(&gadget, &inputs).expect("eval");
                        assert_eq!(u64_from_bits(&out), if cond { b } else { a });
                    }
                }
            }
        }
    }

    /// Rejections, not panics (C12/C13).
    #[test]
    fn test_gadget_input_validation() {
        let mut builder = Builder::new();
        let x = builder.inputs(4);
        assert!(matches!(
            add_public_constant(&mut builder, &[true, false], &x),
            Err(CircuitError::InputLengthMismatch { .. })
        ));
        assert!(matches!(
            add_public_constant(&mut builder, &[], &[]),
            Err(CircuitError::EmptyInput)
        ));
        assert!(matches!(
            and_tree(&mut builder, &[]),
            Err(CircuitError::EmptyInput)
        ));
        assert!(matches!(
            or_tree(&mut builder, &[]),
            Err(CircuitError::EmptyInput)
        ));
        assert!(matches!(
            mux(&mut builder, x[0], &x[..2], &x[..3]),
            Err(CircuitError::InputLengthMismatch { .. })
        ));
        assert!(matches!(
            PublicPlusSecretAdder::new(vec![]),
            Err(CircuitError::UnsupportedWidth(0))
        ));
        assert!(matches!(
            Mux::new(0),
            Err(CircuitError::UnsupportedWidth(0))
        ));
    }
}
