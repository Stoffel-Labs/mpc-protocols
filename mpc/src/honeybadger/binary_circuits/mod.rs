//! Layered Boolean netlists over `GfShare<K>` — the online circuit layer of A2B.
//!
//! # This module performs no I/O
//!
//! Nothing here sends, receives, opens, or reconstructs. A circuit is a piece of **pure data**: an
//! arena of wires plus a schedule that says, for each AND layer, which pairs of wire values must be
//! multiplied. The caller (`honeybadger::a2b`) drives it:
//!
//! ```text
//! let circuit = FieldA2BCircuit::<F>::new(y)?;          // y is the opened, public mask
//! let mut wires = circuit.init(&edabit.bits)?;          // secret r bits, LSB first
//! for layer in 0..circuit.layers() {
//!     let and_layer = circuit.build_layer(layer, &mut wires)?;
//!     let products  = gf_mul(and_layer.lhs, and_layer.rhs).await?;   // <- the only I/O
//!     circuit.absorb_layer(layer, products, &mut wires)?;
//! }
//! let x_bits = circuit.outputs(&wires)?;
//! ```
//!
//! XOR, NOT and "mix in a public constant" are **free**: `GF(2^k)` has characteristic 2, so
//! `GfShare: Add` is XOR and `GfShare: Add<K>` folds in a public bit (`gf2k/share.rs`). Only AND
//! costs a Beaver triple and a network round. The whole point of the layering is therefore to keep
//! the number of *sequential* AND layers — which is the number of online rounds — minimal, while
//! letting every gate inside one layer ride a single batched multiplication.
//!
//! # Scheduling and dead-code elimination
//!
//! [`Builder`] emits gates into an SSA arena and schedules each one **as soon as its operands are
//! ready** (ASAP). Constant folding happens while the plan is built: a gate whose operand is a
//! statically-known `0` or `1` is never emitted at all, so the sparsity of a public constant turns
//! directly into fewer triples. [`Builder::finish`] then runs a backward liveness pass over the
//! plan and drops every gate whose result no output depends on, and collapses layers that end up
//! empty. Both passes are driven **only by public data**, so every honest party builds a
//! bit-identical plan and consumes exactly the same number of triples in exactly the same order.
//!
//! # Gate counts and depth on Goldilocks (`p = 2^64 - 2^32 + 1`, `w = 64`)
//!
//! A2B is a **parallel offset adder**: the mod-`p` offset `d = 2^w - p` is folded into the
//! *public* operand, so the two additions both read only the secret `r` and the ASAP scheduler
//! runs them in the same layers. See [`FieldA2BCircuit`] for the construction and its proof.
//!
//! | Stage | ANDs | AND layers |
//! |---|---|---|
//! | `ADD_w(public y, secret r)` — Sklansky prefix, carry-out cone dead | <= 310 | 6 |
//! | `ADD_w(public y + d, secret r)` — concurrent with the above | <= 321 | 6 |
//! | MUX `x_i = t1_i + c2 (t1_i + t2_i)` | 64 | 1 |
//! | **[`FieldA2BCircuit`] total** | **<= 695** | **7** |
//! | [`ModulusOverflowCircuit`] (`r >= p`, edaBit filter) | 63 | 6 |
//!
//! The `<=` is because the generate/propagate seeding of a `public + secret` adder is free, and a
//! cleared bit of the public operand makes a whole sub-tree of the carry prefix statically zero.
//! 695 is an *analytic* bound rather than a realisable plan — see
//! [`FieldA2BCircuit::max_and_count_on`] — and it is what the preprocessing sizer is handed. The
//! exact figure for the `y` actually opened is [`HasNetlist::and_count`]: measured 642 on average
//! over a uniform `y`, and 693 at the dearest admissible mask found by hill-climbing over `y`
//! (`0xDDD5_D776_7D77_F7D7`), two short of the bound. It is the same at every honest party,
//! because `y` was robustly opened. The depth is exactly 7 for every `y` that can carry at all,
//! and never more than 7.
//!
//! That is 7 AND layers rather than the 13 of the serial `ADD -> ADD -> MUX` chain this replaced,
//! i.e. **16 online rounds instead of 28**, bought for about 7% more ANDs on average (11% on the
//! sizing bound). On an asynchronous BFT network that is the right side of the trade, which is
//! also why [`prefix::PrefixTopology`] defaults to the minimum-depth prefix network.
//!
//! A caller that has certified it needs only the low `l` output bits gets a further saving for
//! free, because backward liveness then prunes the high cones of **both** adders: measured 316
//! ANDs on average at `l = 33`, against 488 for the serial chain, which had to keep all 64 bits
//! of its first adder alive to feed its second. There is deliberately no narrow entry point —
//! the repo's signed encoding `-|v| -> p - |v|` means a value of nominal width `l` still occupies
//! the high bits, so narrowing is the caller's certification to make, not this module's.
//!
//! # Why Sklansky and not Kogge-Stone
//!
//! Identical depth `ceil(log2 w) = 6`, roughly a third of the ANDs. Kogge-Stone's advantage is
//! bounded wire fan-out, which is a hardware property; fan-out is free here, because a wire is a
//! local `GfShare` that can be cloned.
//!
//! # Preconditions (correctness, not privacy)
//!
//! [`FieldA2BCircuit`] is exact **only** when both operands of the first addition are canonical
//! representatives: `y < p` (guaranteed — it is the `into_bigint()` of an opened field element)
//! and `r < p` (guaranteed by the edaBit `r < p` filter, which is what
//! [`ModulusOverflowCircuit`] is for). With `r >= p` the "at most one subtraction of `p`" argument
//! fails. There is no way for this module to check `r < p` locally — `r` is secret-shared — so the
//! caller must not skip the filter. `y < p` *is* checked here: a non-canonical mask is rejected
//! with [`CircuitError::MaskNotCanonical`] rather than silently wrapping the public offset.
//!
//! # Canonical representative, not two's complement
//!
//! The output bits are the bits of the representative of `x` in `[0, p)`. `mpc/src/common/types`
//! encodes a negative fixed-point value `-|v|` as `p - |v|`, so `-1` comes out of A2B as
//! `0xFFFF_FFFF_0000_0000`, **not** as `0xFFFF_FFFF_FFFF_FFFF`. A caller that wants a sign bit must
//! shift by `2^(k-1)` first, as `truncpr.rs` already does.
//!
//! # INVARIANTS (C12/C20)
//!
//! * Nothing here indexes, `unwrap`s or `expect`s on data that could come off the network: every
//!   fallible step returns [`CircuitError`]. The one value a circuit takes from outside is the
//!   product vector handed back by the multiplier, and [`BinaryCircuit::absorb_layer`] checks its
//!   length, every share id and every share degree before touching a wire.
//! * A circuit plan is a function of **public** data only (the width, the opened mask `y`, the
//!   modulus). It never branches on a share.
//! * `GfShare::id` and `RobustShare::id` index unrelated point sets; only the party index is
//!   common to both. Nothing in this module ever looks at a share id except to check that all of
//!   them agree (C5).
//!
//! # Scope
//!
//! Exact, full-range conversion only. There is deliberately no bounded/statistical variant: on
//! Goldilocks it would cap the input at 22 bits at `kappa = 40`, below what the repo's own default
//! `FixedPointPrecision(32, 16)` already needs. Consequently nothing here has a statistical
//! parameter, and `HoneyBadgerMPCNodeOpts::max_masked_width` / `check_mask_security` are
//! deliberately not involved: `y = (x - r) mod p` with `r` uniform on `[0, p)` is *exactly*
//! uniform, so the masking is perfect rather than statistical (C14).
//!
//! # Where this deviates from the design blueprint
//!
//! * A wire is a [`BitWire`] — `Const(bool)` or `Secret(GfShare<K>)` — rather than a bare
//!   `GfShare`. Keeping public bits symbolic is what makes a sparse public operand actually cheap;
//!   with constants materialised as shares, ANDing with a public `0` would burn a Beaver triple.
//! * The three cost queries (`layers`, `and_count`, `layer_width`) sit on [`HasNetlist`] rather
//!   than on [`BinaryCircuit<K>`], because they say nothing about `K` and would otherwise be
//!   ambiguous at every call site.
//! * [`BinaryCircuit`] gains an `init` method; the blueprint sketch had no way to populate a wire
//!   store.
//! * [`ModulusOverflowCircuit`] keeps the blueprint's AND/OR-tree construction (63 ANDs, 6 layers
//!   on Goldilocks) but recognises the required modulus shape rather than assuming it, and falls
//!   back to a general carry-out comparison for any other prime. Both branches are cross-checked
//!   against each other in the tests.
//! * The blueprint's A2B is the **serial** `ADD_w(y, r) -> ADD_w(d, t1) -> MUX` chain, 626 ANDs
//!   over 13 layers, whose `c = c1 XOR c2` needed a lemma that `(c1, c2) = (1, 1)` is unreachable.
//!   This module applies the offset to the public operand instead (695 / 7). The lemma is not
//!   weakened, it is unnecessary: the first adder's carry out is never formed.
//! * **The blueprint's cost tables undercount, and any figure quoted from them here has been
//!   re-derived.** They price a Beaver multiplication at the triple alone and omit the
//!   `4n/(t+1)` field elements of the two openings that spend it, so every "bytes per conversion"
//!   number in blueprint §6.2/§6.3 is low by roughly a factor of 1.4 on the preprocessing side.
//!   Nothing in this module depends on those figures — an AND count is an AND count — but a
//!   caller sizing a network budget from them will under-provision. **And so will one sizing it
//!   from the corrected figures**, which are still *payload*: every such number omits the 48- or
//!   52-byte per-message frame, which measurement puts at half of a 64-bit A2B's real traffic.
//!   [`crate::honeybadger::dn07`] carries the wire model; a network budget must come from that,
//!   or from `mpc/tests/conv_cost_measurement.rs`, and never from an element count. The gate counts in the table
//!   above are measured by `HasNetlist::and_count()` on the real planner, not estimated.

pub mod prefix;

use std::collections::HashSet;
use std::marker::PhantomData;

use ark_ff::PrimeField;
use thiserror::Error;

use crate::common::convert::{
    canonical_bits, field_bit_width, two_pow_w_minus_modulus_bits, ConvertError,
};
use crate::common::gf2k::field::BinaryField;
use crate::common::gf2k::share::GfShare;
use crate::common::share::ShareError;

use prefix::{add_public_constant_on, and_tree, geq_public_constant, mux, or_tree, PrefixTopology};

/// Errors raised while planning or evaluating a binary circuit.
///
/// Every variant is a hard error rather than a panic: `absorb_layer` is fed the output of a
/// multiplication that a peer participated in, so it sits on a network-reachable path (C12).
#[derive(Debug, Error)]
pub enum CircuitError {
    #[error("circuit width {0} is not supported")]
    UnsupportedWidth(usize),
    #[error("expected {expected} input wires, got {got}")]
    InputLengthMismatch { expected: usize, got: usize },
    #[error("AND layer {layer} expected {expected} products, got {got}")]
    LayerLengthMismatch {
        layer: usize,
        expected: usize,
        got: usize,
    },
    #[error("AND layer {0} is out of range")]
    LayerOutOfRange(usize),
    #[error("AND layer {0} was built but never absorbed")]
    LayerNotAbsorbed(usize),
    #[error("no AND layer is awaiting absorption")]
    NothingToAbsorb,
    #[error("wire {0} is out of range")]
    WireOutOfRange(usize),
    #[error("wire {wire} holds a public constant where a share was required")]
    ConstantOperand { wire: usize },
    #[error("share id mismatch: expected {expected}, got {got}")]
    IdMismatch { expected: usize, got: usize },
    #[error("share degree mismatch: expected {expected}, got {got}")]
    DegreeMismatch { expected: usize, got: usize },
    #[error("a circuit cannot be built over an empty input")]
    EmptyInput,
    /// The public A2B mask is not a canonical representative, so `y + (2^w - p)` does not fit in
    /// `w` bits and the parallel offset adder's case analysis does not apply. Unreachable through
    /// [`FieldA2BCircuit::new`], which derives the bits with `canonical_bits`; returned rather
    /// than asserted so a future caller that hands over raw bits degrades into an error (C12).
    #[error("the public mask is not a canonical representative below the modulus")]
    MaskNotCanonical,
    #[error("share error: {0:?}")]
    Share(#[from] ShareError),
    #[error("cross-domain conversion error: {0:?}")]
    Convert(#[from] ConvertError),
}

/// One wire of a binary circuit: either a publicly-known bit or a degree-`t` sharing of a bit.
///
/// Keeping constants symbolic is what makes the free operations actually free — XORing a public
/// `0` into a wire must not turn it into a share, and ANDing with a public `0` must not consume a
/// Beaver triple.
#[derive(Clone, Debug, PartialEq)]
pub enum BitWire<K: BinaryField> {
    /// A bit every party knows. Never secret, never counted against the triple budget.
    Const(bool),
    /// A degree-`t` `GF(2^k)` sharing of a bit.
    Secret(GfShare<K>),
}

impl<K: BinaryField> BitWire<K> {
    /// Renders the wire as a share held by party `id` on a degree-`degree` polynomial.
    ///
    /// A public constant becomes the constant sharing — every party's evaluation equals the
    /// constant, which is exactly the degree-0 (hence also degree-`degree`) codeword of that value.
    /// This is the same representation `mul_pub.rs` uses when it pads a batch with `GfShare::new(
    /// K::one(), ..)`.
    pub fn materialize(&self, id: usize, degree: usize) -> GfShare<K> {
        match self {
            BitWire::Const(b) => GfShare::new(if *b { K::one() } else { K::zero() }, id, degree),
            BitWire::Secret(s) => s.clone(),
        }
    }

    /// The underlying share, or `None` for a public constant.
    pub fn as_share(&self) -> Option<&GfShare<K>> {
        match self {
            BitWire::Const(_) => None,
            BitWire::Secret(s) => Some(s),
        }
    }

    /// `self XOR other`, free in characteristic 2.
    fn xor(&self, other: &Self) -> Result<Self, CircuitError> {
        Ok(match (self, other) {
            (BitWire::Const(a), BitWire::Const(b)) => BitWire::Const(a ^ b),
            (BitWire::Const(false), s) | (s, BitWire::Const(false)) => s.clone(),
            (BitWire::Const(true), BitWire::Secret(s))
            | (BitWire::Secret(s), BitWire::Const(true)) => {
                BitWire::Secret((s.clone() + K::one())?)
            }
            (BitWire::Secret(a), BitWire::Secret(b)) => BitWire::Secret((a.clone() + b.clone())?),
        })
    }

    /// `self XOR value` for a public `value` — a NOT when `value` is `true`.
    fn xor_const(&self, value: bool) -> Result<Self, CircuitError> {
        if !value {
            return Ok(self.clone());
        }
        Ok(match self {
            BitWire::Const(b) => BitWire::Const(!b),
            BitWire::Secret(s) => BitWire::Secret((s.clone() + K::one())?),
        })
    }
}

/// One AND layer, ready to be handed to the multiplier as a single batched call.
///
/// `lhs[i]` is to be multiplied by `rhs[i]`; the products must come back in the same order.
#[derive(Clone, Debug, PartialEq)]
pub struct AndLayer<K: BinaryField> {
    pub lhs: Vec<GfShare<K>>,
    pub rhs: Vec<GfShare<K>>,
}

impl<K: BinaryField> AndLayer<K> {
    pub fn len(&self) -> usize {
        self.lhs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lhs.is_empty()
    }
}

/// The live state of one circuit evaluation: the wire arena plus the bookkeeping for the AND layer
/// currently in flight.
///
/// A store belongs to exactly one [`Netlist`]; feeding it to a different circuit is caught by the
/// arena-length and layer checks rather than silently producing a wrong result.
#[derive(Clone, Debug)]
pub struct WireStore<K: BinaryField> {
    wires: Vec<BitWire<K>>,
    /// Party index every share in this evaluation carries, taken from the inputs (C5).
    id: usize,
    /// Sharing degree every share in this evaluation carries, taken from the inputs (C5).
    degree: usize,
    /// Destinations for the products of the layer currently in flight, in gate order.
    pending: Vec<(usize, Option<usize>)>,
    pending_layer: Option<usize>,
}

impl<K: BinaryField> WireStore<K> {
    /// The party index shared by every share in this evaluation.
    pub fn id(&self) -> usize {
        self.id
    }

    /// The sharing degree shared by every share in this evaluation.
    pub fn degree(&self) -> usize {
        self.degree
    }

    /// Number of wires in the arena.
    pub fn len(&self) -> usize {
        self.wires.len()
    }

    pub fn is_empty(&self) -> bool {
        self.wires.is_empty()
    }

    /// Reads one wire.
    pub fn get(&self, wire: usize) -> Result<&BitWire<K>, CircuitError> {
        self.wires
            .get(wire)
            .ok_or(CircuitError::WireOutOfRange(wire))
    }

    fn set(&mut self, wire: usize, value: BitWire<K>) -> Result<(), CircuitError> {
        let slot = self
            .wires
            .get_mut(wire)
            .ok_or(CircuitError::WireOutOfRange(wire))?;
        *slot = value;
        Ok(())
    }

    /// Operand of an AND gate: must be a share, never a constant.
    ///
    /// A constant here would mean the planner and the runtime disagreed about which wires are
    /// public, which can only be a bug in this module — the plan is a pure function of public
    /// data. It is still an error rather than a panic (C12).
    fn operand(&self, wire: usize) -> Result<GfShare<K>, CircuitError> {
        match self.get(wire)? {
            BitWire::Secret(s) => Ok(s.clone()),
            BitWire::Const(_) => Err(CircuitError::ConstantOperand { wire }),
        }
    }
}

/// A free (multiplication-free) operation. These are applied locally, cost nothing and never touch
/// the network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FreeOp {
    /// `dst = value`
    SetConst { dst: usize, value: bool },
    /// `dst = a XOR b`
    Xor { dst: usize, a: usize, b: usize },
    /// `dst = src XOR value` for a public `value`
    XorConst { dst: usize, src: usize, value: bool },
}

impl FreeOp {
    fn dst(&self) -> usize {
        match *self {
            FreeOp::SetConst { dst, .. } => dst,
            FreeOp::Xor { dst, .. } => dst,
            FreeOp::XorConst { dst, .. } => dst,
        }
    }
}

/// One scheduled AND gate: `dst = lhs * rhs`, or `dst = xor_in XOR lhs * rhs` when `xor_in` is set.
///
/// The fused XOR form exists so that a Sklansky "black cell" (`G_t ^= P_t * G_s`) is one gate and
/// one wire rather than a gate plus a free XOR — it changes no cost, only the bookkeeping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Gate {
    lhs: usize,
    rhs: usize,
    dst: usize,
    xor_in: Option<usize>,
}

/// A layered netlist: pure data, no shares, no session state.
///
/// `pre[l]` is the batch of free operations that must run before AND layer `l`; `pre` always has
/// exactly `layers.len() + 1` entries, the last of which runs after the final layer is absorbed.
#[derive(Clone, Debug, PartialEq)]
pub struct Netlist {
    arena_len: usize,
    pre: Vec<Vec<FreeOp>>,
    layers: Vec<Vec<Gate>>,
    inputs: Vec<usize>,
    outputs: Vec<usize>,
}

impl Netlist {
    /// Number of sequential AND layers — i.e. the number of online rounds of multiplication.
    pub fn layers(&self) -> usize {
        self.layers.len()
    }

    /// Total number of AND gates, i.e. the number of Beaver triples this circuit consumes.
    pub fn and_count(&self) -> usize {
        self.layers.iter().map(Vec::len).sum()
    }

    /// Number of AND gates in layer `layer`.
    pub fn layer_width(&self, layer: usize) -> Result<usize, CircuitError> {
        self.layers
            .get(layer)
            .map(Vec::len)
            .ok_or(CircuitError::LayerOutOfRange(layer))
    }

    /// Number of input bit shares the circuit expects.
    pub fn input_len(&self) -> usize {
        self.inputs.len()
    }

    /// Number of output bit shares the circuit produces.
    pub fn output_len(&self) -> usize {
        self.outputs.len()
    }

    fn apply_free<K: BinaryField>(
        op: &FreeOp,
        wires: &mut WireStore<K>,
    ) -> Result<(), CircuitError> {
        let value = match *op {
            FreeOp::SetConst { value, .. } => BitWire::Const(value),
            FreeOp::Xor { a, b, .. } => wires.get(a)?.xor(wires.get(b)?)?,
            FreeOp::XorConst { src, value, .. } => wires.get(src)?.xor_const(value)?,
        };
        wires.set(op.dst(), value)
    }

    fn run_free_bucket<K: BinaryField>(
        &self,
        bucket: usize,
        wires: &mut WireStore<K>,
    ) -> Result<(), CircuitError> {
        let ops = self
            .pre
            .get(bucket)
            .ok_or(CircuitError::LayerOutOfRange(bucket))?;
        for op in ops {
            Self::apply_free(op, wires)?;
        }
        Ok(())
    }
}

/// Implemented by everything that is, at bottom, one [`Netlist`].
///
/// This is the single extension point: a new gadget builds a `Netlist` and gets the whole
/// [`BinaryCircuit`] driver for free, so there is exactly one implementation of the
/// build/absorb bookkeeping in the crate.
///
/// The three cost queries live here rather than on [`BinaryCircuit`] — deviating from the
/// blueprint sketch — because they say nothing about `K`: on the generic trait, `circuit.layers()`
/// would be ambiguous at every call site and would have to be spelled
/// `BinaryCircuit::<Gf256>::layers(&circuit)`.
pub trait HasNetlist {
    fn netlist(&self) -> &Netlist;

    /// Number of sequential AND layers, i.e. online multiplication rounds.
    fn layers(&self) -> usize {
        self.netlist().layers()
    }

    /// Total AND gates, i.e. Beaver triples consumed.
    fn and_count(&self) -> usize {
        self.netlist().and_count()
    }

    /// Number of AND gates in `layer`.
    fn layer_width(&self, layer: usize) -> Result<usize, CircuitError> {
        self.netlist().layer_width(layer)
    }
}

impl HasNetlist for Netlist {
    fn netlist(&self) -> &Netlist {
        self
    }
}

/// A layered Boolean circuit over degree-`t` `GF(2^k)` bit shares.
///
/// The contract is strictly sequential: `init`, then for each `layer` in `0..layers()` a
/// `build_layer` followed by the matching `absorb_layer`, then `outputs`. Building a layer while
/// another is in flight, absorbing the wrong layer, or absorbing the wrong number of products are
/// all errors.
pub trait BinaryCircuit<K: BinaryField> {
    /// Loads the circuit's inputs and applies every free operation that precedes layer 0.
    ///
    /// C5: all inputs must carry the same share id and the same degree; those become the id and
    /// degree of every wire, and every product absorbed later is checked against them.
    fn init(&self, inputs: &[GfShare<K>]) -> Result<WireStore<K>, CircuitError>;

    /// Collects the AND gates of `layer` into one batched multiplication request.
    fn build_layer(
        &self,
        layer: usize,
        wires: &mut WireStore<K>,
    ) -> Result<AndLayer<K>, CircuitError>;

    /// Writes the products of `layer` back into the arena and applies the free operations that
    /// follow it. `products` must be in the same order as the [`AndLayer`] that produced them.
    fn absorb_layer(
        &self,
        layer: usize,
        products: Vec<GfShare<K>>,
        wires: &mut WireStore<K>,
    ) -> Result<(), CircuitError>;

    /// The circuit's outputs, once every layer has been absorbed.
    fn outputs(&self, wires: &WireStore<K>) -> Result<Vec<GfShare<K>>, CircuitError>;
}

impl<K: BinaryField, C: HasNetlist> BinaryCircuit<K> for C {
    fn init(&self, inputs: &[GfShare<K>]) -> Result<WireStore<K>, CircuitError> {
        let net = self.netlist();
        if inputs.len() != net.inputs.len() {
            return Err(CircuitError::InputLengthMismatch {
                expected: net.inputs.len(),
                got: inputs.len(),
            });
        }
        // C13: an empty input would make every downstream check pass vacuously.
        let first = inputs.first().ok_or(CircuitError::EmptyInput)?;
        let (id, degree) = (first.id, first.degree);
        // C5: the whole evaluation is pinned to one (id, degree); a mixed batch would interpolate
        // points of different polynomials at the same x-coordinate.
        for share in inputs {
            if share.id != id {
                return Err(CircuitError::IdMismatch {
                    expected: id,
                    got: share.id,
                });
            }
            if share.degree != degree {
                return Err(CircuitError::DegreeMismatch {
                    expected: degree,
                    got: share.degree,
                });
            }
        }

        let mut wires = WireStore {
            wires: vec![BitWire::Const(false); net.arena_len],
            id,
            degree,
            pending: Vec::new(),
            pending_layer: None,
        };
        for (slot, share) in net.inputs.iter().zip(inputs.iter()) {
            wires.set(*slot, BitWire::Secret(share.clone()))?;
        }
        net.run_free_bucket(0, &mut wires)?;
        Ok(wires)
    }

    fn build_layer(
        &self,
        layer: usize,
        wires: &mut WireStore<K>,
    ) -> Result<AndLayer<K>, CircuitError> {
        let net = self.netlist();
        if let Some(open) = wires.pending_layer {
            return Err(CircuitError::LayerNotAbsorbed(open));
        }
        let gates = net
            .layers
            .get(layer)
            .ok_or(CircuitError::LayerOutOfRange(layer))?;

        let mut lhs = Vec::with_capacity(gates.len());
        let mut rhs = Vec::with_capacity(gates.len());
        let mut pending = Vec::with_capacity(gates.len());
        for gate in gates {
            lhs.push(wires.operand(gate.lhs)?);
            rhs.push(wires.operand(gate.rhs)?);
            pending.push((gate.dst, gate.xor_in));
        }
        wires.pending = pending;
        wires.pending_layer = Some(layer);
        Ok(AndLayer { lhs, rhs })
    }

    fn absorb_layer(
        &self,
        layer: usize,
        products: Vec<GfShare<K>>,
        wires: &mut WireStore<K>,
    ) -> Result<(), CircuitError> {
        let net = self.netlist();
        match wires.pending_layer {
            None => return Err(CircuitError::NothingToAbsorb),
            Some(open) if open != layer => return Err(CircuitError::LayerNotAbsorbed(open)),
            Some(_) => {}
        }
        if products.len() != wires.pending.len() {
            return Err(CircuitError::LayerLengthMismatch {
                layer,
                expected: wires.pending.len(),
                got: products.len(),
            });
        }

        // C5/C12: the products come back from a multiplication other parties took part in. Check
        // every index and degree BEFORE touching the arena, so that a malformed batch leaves the
        // evaluation exactly as it was rather than half-applied; a share carrying a foreign id
        // would otherwise be interpolated at the wrong x-coordinate downstream.
        for product in &products {
            if product.id != wires.id {
                return Err(CircuitError::IdMismatch {
                    expected: wires.id,
                    got: product.id,
                });
            }
            if product.degree != wires.degree {
                return Err(CircuitError::DegreeMismatch {
                    expected: wires.degree,
                    got: product.degree,
                });
            }
        }

        let pending = std::mem::take(&mut wires.pending);
        for ((dst, xor_in), product) in pending.into_iter().zip(products) {
            let value = match xor_in {
                None => BitWire::Secret(product),
                Some(src) => wires.get(src)?.xor(&BitWire::Secret(product))?,
            };
            wires.set(dst, value)?;
        }
        wires.pending_layer = None;
        net.run_free_bucket(layer + 1, wires)
    }

    fn outputs(&self, wires: &WireStore<K>) -> Result<Vec<GfShare<K>>, CircuitError> {
        let net = self.netlist();
        if let Some(open) = wires.pending_layer {
            return Err(CircuitError::LayerNotAbsorbed(open));
        }
        net.outputs
            .iter()
            .map(|w| Ok(wires.get(*w)?.materialize(wires.id, wires.degree)))
            .collect()
    }
}

/// Static shape of a wire, as seen by the planner. Drives constant folding, and nothing else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    Zero,
    One,
    Secret,
}

fn xor_shape(a: Shape, b: Shape) -> Shape {
    match (a, b) {
        (Shape::Zero, other) | (other, Shape::Zero) => other,
        (Shape::One, Shape::One) => Shape::Zero,
        _ => Shape::Secret,
    }
}

/// Builds a [`Netlist`] in SSA form: every wire is written exactly once, so a wire id can be
/// aliased freely and a gate can always read its operands' pre-layer values.
///
/// The builder schedules each gate as early as its operands allow (ASAP). That is what lets the
/// second 64-bit addition of A2B start on its low bits while the first one is still resolving its
/// high carries, and it is why the depth falls out of the dependency graph instead of being
/// asserted by hand.
#[derive(Clone, Debug)]
pub struct Builder {
    shapes: Vec<Shape>,
    /// `ready[w]` is the earliest free-op bucket in which wire `w` holds its final value. A gate
    /// scheduled into layer `l` produces a wire that is ready in bucket `l + 1`.
    ready: Vec<usize>,
    pre: Vec<Vec<FreeOp>>,
    layers: Vec<Vec<Gate>>,
    zero: Option<usize>,
    one: Option<usize>,
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}

impl Builder {
    /// An empty plan. Note the invariant `pre.len() == layers.len() + 1`: free-op bucket `l` runs
    /// before AND layer `l`, and the extra bucket at the end runs after the last layer. A
    /// `Default`-derived value would violate it, which is why `Default` forwards here.
    pub fn new() -> Self {
        Builder {
            shapes: Vec::new(),
            ready: Vec::new(),
            pre: vec![Vec::new()],
            layers: Vec::new(),
            zero: None,
            one: None,
        }
    }

    fn alloc(&mut self, shape: Shape, ready: usize) -> usize {
        let id = self.shapes.len();
        self.shapes.push(shape);
        self.ready.push(ready);
        id
    }

    /// Grows the schedule so that layer `layer` (and free-op bucket `layer + 1`) exist.
    fn ensure_layer(&mut self, layer: usize) {
        while self.layers.len() <= layer {
            self.layers.push(Vec::new());
            self.pre.push(Vec::new());
        }
    }

    fn ensure_bucket(&mut self, bucket: usize) {
        while self.pre.len() <= bucket {
            self.layers.push(Vec::new());
            self.pre.push(Vec::new());
        }
    }

    fn shape(&self, wire: usize) -> Shape {
        self.shapes[wire]
    }

    /// `true` when the planner knows this wire's value, i.e. it costs nothing to use.
    pub fn is_constant(&self, wire: usize) -> bool {
        !matches!(self.shape(wire), Shape::Secret)
    }

    /// Allocates `n` secret input wires, in order.
    pub fn inputs(&mut self, n: usize) -> Vec<usize> {
        (0..n).map(|_| self.alloc(Shape::Secret, 0)).collect()
    }

    /// A wire holding the public bit `value`. Cached, so a circuit allocates at most one of each.
    pub fn constant(&mut self, value: bool) -> usize {
        let cached = if value { self.one } else { self.zero };
        if let Some(w) = cached {
            return w;
        }
        let shape = if value { Shape::One } else { Shape::Zero };
        let w = self.alloc(shape, 0);
        self.pre[0].push(FreeOp::SetConst { dst: w, value });
        if value {
            self.one = Some(w);
        } else {
            self.zero = Some(w);
        }
        w
    }

    /// `a XOR b` — free. Returns an existing wire when the result is one of the operands.
    pub fn xor(&mut self, a: usize, b: usize) -> usize {
        match (self.shape(a), self.shape(b)) {
            (Shape::Zero, _) => b,
            (_, Shape::Zero) => a,
            (Shape::One, Shape::One) => self.constant(false),
            (Shape::One, _) => self.xor_const(b, true),
            (_, Shape::One) => self.xor_const(a, true),
            (Shape::Secret, Shape::Secret) => {
                let bucket = self.ready[a].max(self.ready[b]);
                let dst = self.alloc(Shape::Secret, bucket);
                self.ensure_bucket(bucket);
                self.pre[bucket].push(FreeOp::Xor { dst, a, b });
                dst
            }
        }
    }

    /// `a XOR value` for a public `value` — free, and a no-op when `value` is `false`.
    pub fn xor_const(&mut self, a: usize, value: bool) -> usize {
        if !value {
            return a;
        }
        match self.shape(a) {
            Shape::Zero => self.constant(true),
            Shape::One => self.constant(false),
            Shape::Secret => {
                let bucket = self.ready[a];
                let dst = self.alloc(Shape::Secret, bucket);
                self.ensure_bucket(bucket);
                self.pre[bucket].push(FreeOp::XorConst {
                    dst,
                    src: a,
                    value: true,
                });
                dst
            }
        }
    }

    /// `a AND b`. Emits a gate only when both operands are genuinely secret; otherwise the result
    /// is an existing wire and no triple is spent.
    pub fn and(&mut self, a: usize, b: usize) -> usize {
        match (self.shape(a), self.shape(b)) {
            (Shape::Zero, _) | (_, Shape::Zero) => self.constant(false),
            (Shape::One, _) => b,
            (_, Shape::One) => a,
            (Shape::Secret, Shape::Secret) => {
                let layer = self.ready[a].max(self.ready[b]);
                self.ensure_layer(layer);
                let dst = self.alloc(Shape::Secret, layer + 1);
                self.layers[layer].push(Gate {
                    lhs: a,
                    rhs: b,
                    dst,
                    xor_in: None,
                });
                dst
            }
        }
    }

    /// `xor_in XOR (a AND b)`, fused into a single gate when the AND survives folding.
    pub fn and_xor(&mut self, a: usize, b: usize, xor_in: usize) -> usize {
        match (self.shape(a), self.shape(b)) {
            (Shape::Zero, _) | (_, Shape::Zero) => xor_in,
            (Shape::One, _) => self.xor(xor_in, b),
            (_, Shape::One) => self.xor(xor_in, a),
            (Shape::Secret, Shape::Secret) => {
                let layer = self.ready[a].max(self.ready[b]).max(self.ready[xor_in]);
                self.ensure_layer(layer);
                let shape = xor_shape(self.shape(xor_in), Shape::Secret);
                let dst = self.alloc(shape, layer + 1);
                self.layers[layer].push(Gate {
                    lhs: a,
                    rhs: b,
                    dst,
                    xor_in: Some(xor_in),
                });
                dst
            }
        }
    }

    /// Freezes the plan: drops every operation no output depends on, then removes AND layers that
    /// ended up empty (each empty layer would otherwise cost a pointless network round).
    ///
    /// Liveness is computed backwards over the execution order. The arena is SSA, so each wire has
    /// exactly one defining operation and "is this wire live?" is the whole analysis.
    pub fn finish(self, inputs: &[usize], outputs: &[usize]) -> Netlist {
        let Builder {
            shapes,
            pre,
            layers,
            ..
        } = self;

        let mut live: HashSet<usize> = outputs.iter().copied().collect();
        live.extend(inputs.iter().copied());

        let depth = layers.len();
        let mut kept_pre: Vec<Vec<FreeOp>> = vec![Vec::new(); depth + 1];
        let mut kept_layers: Vec<Vec<Gate>> = vec![Vec::new(); depth];

        // Execution order is pre[0], layers[0], pre[1], ..., layers[depth-1], pre[depth]; walk it
        // backwards so that a consumer is always seen before its producer.
        for bucket in (0..=depth).rev() {
            for op in pre[bucket].iter().rev() {
                if !live.contains(&op.dst()) {
                    continue;
                }
                match *op {
                    FreeOp::SetConst { .. } => {}
                    FreeOp::Xor { a, b, .. } => {
                        live.insert(a);
                        live.insert(b);
                    }
                    FreeOp::XorConst { src, .. } => {
                        live.insert(src);
                    }
                }
                kept_pre[bucket].push(*op);
            }
            kept_pre[bucket].reverse();

            if bucket == 0 {
                break;
            }
            let layer = bucket - 1;
            for gate in layers[layer].iter().rev() {
                if !live.contains(&gate.dst) {
                    continue;
                }
                live.insert(gate.lhs);
                live.insert(gate.rhs);
                if let Some(x) = gate.xor_in {
                    live.insert(x);
                }
                kept_layers[layer].push(*gate);
            }
            kept_layers[layer].reverse();
        }

        // Collapse empty layers, merging their free-op buckets forwards.
        let mut out_pre: Vec<Vec<FreeOp>> = Vec::with_capacity(depth + 1);
        let mut out_layers: Vec<Vec<Gate>> = Vec::with_capacity(depth);
        let mut carry: Vec<FreeOp> = Vec::new();
        for layer in 0..depth {
            carry.append(&mut kept_pre[layer]);
            if kept_layers[layer].is_empty() {
                continue;
            }
            out_pre.push(std::mem::take(&mut carry));
            out_layers.push(std::mem::take(&mut kept_layers[layer]));
        }
        carry.append(&mut kept_pre[depth]);
        out_pre.push(carry);

        Netlist {
            arena_len: shapes.len(),
            pre: out_pre,
            layers: out_layers,
            inputs: inputs.to_vec(),
            outputs: outputs.to_vec(),
        }
    }
}

/// The full-range arithmetic-to-binary circuit for `F`.
///
/// Given the **public** mask `y = (x - r) mod p` and the secret bits of an edaBit's mask `r`, it
/// produces the bits of the canonical representative of `x` in `[0, p)`, LSB first.
///
/// # Phase: ONLINE — asynchronous, robust, no abort
///
/// Planning is pure local computation, but what is planned runs on the online path, and the shape
/// below is what keeps that path robust: every gate becomes a degree-`t` Beaver AND over `GF(2^k)`,
/// the plan is a function of the robustly opened public `y` alone, and nothing here introduces a
/// timeout, a broadcast, a degree-`2t` opening or an abort. An AND layer is an online round, so
/// **depth is the figure of merit** and a triple is the cheaper currency.
///
/// # Construction — the parallel offset adder
///
/// ```text
/// d        = 2^w - p                        -- public
/// Y        = y + d                          -- public; fits in w bits because y < p
///
/// (t1, _)  = ADD_w(public y, secret r)      -- independent of the other adder ...
/// (t2, c2) = ADD_w(public Y, secret r)      -- ... so both run in the same AND layers
///
/// x_i      = t1_i XOR c2 (t1_i XOR t2_i)    -- one AND layer
/// ```
///
/// The mod-`p` offset is applied to the **public** operand rather than to the first adder's secret
/// output, so both additions depend only on `r` and the ASAP scheduler overlaps them completely:
/// `ceil(log2 w)` layers for the pair plus one for the multiplexer, i.e. **7** at `w = 64` instead
/// of the `6 + 6 + 1 = 13` of a serial `ADD -> ADD -> MUX` chain. On the wire that is 16 online
/// rounds rather than 28. The price is the second full-width adder: about 7% more ANDs on average.
///
/// # Why it is exact — any prime with `2^(w-1) < p < 2^w`
///
/// Write `A = y + r` over the integers. `y, r < p` gives `A <= 2p - 2`, so at most one subtraction
/// of `p` is due and `x = A - p * [A >= p]`.
///
/// * `t1 = A mod 2^w`, and `Y + r = A + d <= (2^w - 1) + (p - 1) < 2^(w+1)`, so `c2` is the single
///   carry out of `Y + r` and `c2 = 1  <=>  A + d >= 2^w  <=>  A >= 2^w - d = p`.
/// * `c2 = 0`: then `A < p < 2^w`, so `t1 = A = x`.
/// * `c2 = 1`: then `t2 = (A + d) - 2^w = A - p = x`, and `x < p < 2^w`, so that wrap is exact.
///
/// The first adder's carry out is never formed, which is why the blueprint's
/// `(c1, c2) = (1, 1)`-unreachability lemma is *unnecessary* here rather than merely free: it was
/// load-bearing for the serial chain's `c = c1 XOR c2`, and there is no such XOR left. The whole
/// carry-out cone of the first adder is dead and [`Builder::finish`] deletes it, which is where
/// the 310 of the 695 bound comes from.
///
/// # Cost at `w = 64`
///
/// | Stage | ANDs | AND layers |
/// |---|---|---|
/// | `ADD_w(public y, secret r)`, carry-out cone dead | <= 310 | 6 |
/// | `ADD_w(public y + d, secret r)` | <= 321 | 6 (concurrent) |
/// | MUX `x_i = t1_i XOR c2 (t1_i XOR t2_i)` | 64 | 1 |
/// | **total** | **<= 695** | **7** |
///
/// 642 on average over a uniform `y`; the largest count reachable by an admissible `y` is 693.
///
/// # PRECONDITION
///
/// `r < p`. `y < p` is automatic — it is the canonical representative of an opened field element,
/// and [`FieldA2BCircuit::new`] rejects anything else — but `r` is secret, so nothing here can
/// check it. A mask with `r >= p` breaks the "at most one reduction" bound above. That is exactly
/// what the edaBit `r < p` filter ([`ModulusOverflowCircuit`]) exists to guarantee; skipping it is
/// both a correctness break and a privacy break, because `r mod p` for `r` uniform on `[0, 2^w)`
/// is `2^-(w - log2 d)` away from uniform.
///
/// # Output convention
///
/// The bits are those of the representative in `[0, p)`, **not** two's complement: on Goldilocks
/// `-1` comes back as `0xFFFF_FFFF_0000_0000`. See the module header.
#[derive(Clone, Debug)]
pub struct FieldA2BCircuit<F: PrimeField> {
    width: usize,
    topology: PrefixTopology,
    net: Netlist,
    _f: PhantomData<fn() -> F>,
}

impl<F: PrimeField> FieldA2BCircuit<F> {
    /// Builds the circuit for one conversion, from the opened public mask `y`.
    ///
    /// The plan is a function of `y` alone, and `y` was robustly opened, so every honest party
    /// builds the same plan, spends the same triples and runs the same number of layers. There is
    /// no agreement sub-protocol here and none is needed (C20).
    pub fn new(y: F) -> Result<Self, CircuitError> {
        Self::new_on(y, PrefixTopology::default())
    }

    /// [`FieldA2BCircuit::new`] over an explicitly chosen prefix network.
    ///
    /// The topology changes only the (ANDs, layers) trade; every choice computes the same bits.
    /// It is a **public** parameter, so a deployment that selects a non-default one must select it
    /// at every party — a party planning a different topology would consume a different number of
    /// triples in a different order, which the batched multiplier would surface as a length
    /// mismatch rather than as a wrong answer, but it is still a configuration error.
    pub fn new_on(y: F, topology: PrefixTopology) -> Result<Self, CircuitError> {
        let width = field_bit_width::<F>();
        let y_bits = canonical_bits(y, width)?;
        Self::plan(y_bits, topology)
    }

    /// Number of bits the circuit consumes and produces: `ceil(log2 p)`, 64 for Goldilocks.
    pub fn width(&self) -> usize {
        self.width
    }

    /// The prefix network this plan was laid out on.
    pub fn topology(&self) -> PrefixTopology {
        self.topology
    }

    /// Upper bound on [`HasNetlist::and_count`] over every admissible `y`, for sizing the triple
    /// pool **before** `y` is known. 695 on Goldilocks.
    ///
    /// See [`FieldA2BCircuit::max_and_count_on`] for why the bound is analytic.
    pub fn max_and_count() -> Result<usize, CircuitError> {
        Self::max_and_count_on(PrefixTopology::default())
    }

    /// [`FieldA2BCircuit::max_and_count`] for an explicitly chosen prefix network.
    ///
    /// The bound is **analytic, not a realisable plan**. The serial circuit this replaced could
    /// take its bound from an all-ones mask, under which nothing folds away; here an all-ones `y`
    /// is inadmissible, because `Y = y + d` would wrap. So the bound is taken from a synthetic
    /// plan in which *both* public operands are all-ones — the two adders read only `r`, so their
    /// costs are independent and each is separately maximised by an all-ones constant, and their
    /// sum plus the `w` multiplexer gates therefore bounds every real `y`. At `w = 64` that is
    /// `310 + 321 + 64 = 695`; the largest count any admissible `y` actually reaches is 693 and a
    /// uniform `y` averages 642.
    pub fn max_and_count_on(topology: PrefixTopology) -> Result<usize, CircuitError> {
        Ok(Self::worst_case_plan(topology)?.and_count())
    }

    /// Upper bound on [`HasNetlist::layers`], i.e. on the online AND rounds. 7 on Goldilocks.
    pub fn max_layers() -> Result<usize, CircuitError> {
        Self::max_layers_on(PrefixTopology::default())
    }

    /// [`FieldA2BCircuit::max_layers`] for an explicitly chosen prefix network.
    pub fn max_layers_on(topology: PrefixTopology) -> Result<usize, CircuitError> {
        Ok(Self::worst_case_plan(topology)?.layers())
    }

    /// The synthetic all-ones/all-ones plan behind the two bounds above. Not a conversion: no `y`
    /// satisfies `y = Y = 2^w - 1`, and evaluating it would not compute an A2B.
    fn worst_case_plan(topology: PrefixTopology) -> Result<Self, CircuitError> {
        let width = field_bit_width::<F>();
        let ones = vec![true; width];
        Self::build(width, &ones, &ones, topology)
    }

    fn plan(y_bits: Vec<bool>, topology: PrefixTopology) -> Result<Self, CircuitError> {
        let width = field_bit_width::<F>();
        if width == 0 {
            return Err(CircuitError::UnsupportedWidth(0));
        }
        if y_bits.len() != width {
            return Err(CircuitError::InputLengthMismatch {
                expected: width,
                got: y_bits.len(),
            });
        }
        // `d = 2^w - p`. On Goldilocks this is `2^32 - 1`.
        let reduce = two_pow_w_minus_modulus_bits::<F>();
        if reduce.len() != width {
            return Err(CircuitError::InputLengthMismatch {
                expected: width,
                got: reduce.len(),
            });
        }
        // `Y = y + d`, the offset applied to the public operand. It fits in `w` bits exactly when
        // `y < p`, so the overflow branch is the "mask was not canonical" rejection.
        let offset = add_bits_le(&y_bits, &reduce).ok_or(CircuitError::MaskNotCanonical)?;
        Self::build(width, &y_bits, &offset, topology)
    }

    /// The netlist for two independent `public + secret` additions on one secret operand, selected
    /// between by the second one's carry out.
    fn build(
        width: usize,
        plain: &[bool],
        offset: &[bool],
        topology: PrefixTopology,
    ) -> Result<Self, CircuitError> {
        if width == 0 {
            return Err(CircuitError::UnsupportedWidth(0));
        }
        let mut builder = Builder::new();
        let r = builder.inputs(width);
        // Both adders read `r` and nothing else, so the scheduler gives them the same layers.
        // The first one's carry out is deliberately dropped: `c2` alone decides the reduction.
        let (t1, _c1) = add_public_constant_on(&mut builder, topology, plain, &r)?;
        let (t2, c2) = add_public_constant_on(&mut builder, topology, offset, &r)?;
        let outputs = mux(&mut builder, c2, &t1, &t2)?;
        let net = builder.finish(&r, &outputs);
        Ok(FieldA2BCircuit {
            width,
            topology,
            net,
            _f: PhantomData,
        })
    }
}

impl<F: PrimeField> HasNetlist for FieldA2BCircuit<F> {
    fn netlist(&self) -> &Netlist {
        &self.net
    }
}

/// `r >= p` over the bits of `r` — the edaBit `r < p` filter.
///
/// An edaBit is 64 daBits composed as `[r]_F = sum 2^i [b_i]_F`, which equals the integer
/// `sum 2^i r_i` only while that integer is below `p`. Since `p` is not a power of two, roughly
/// `(2^w - p) / 2^w` of the candidates (`2^-32` on Goldilocks) must be rejected, and this circuit
/// computes the one bit that decides it. The caller opens that bit at degree `t`; because the
/// opening is robust, every honest party sees the same verdict and no agreement step is needed —
/// the same argument `rand_bit.rs` uses for its "square opened to zero, drop this index" branch.
///
/// # Two implementations, one meaning
///
/// * **Solinas shape.** When `2^w - p = 2^m - 1` — i.e. `p = 2^w - 2^m + 1`, which is exactly
///   Goldilocks with `w = 64, m = 32` — then `r >= p` iff every bit at or above `m` is set *and*
///   at least one bit below `m` is set. That is an `AND` tree over the top `w - m` bits beside an
///   `OR` tree over the bottom `m`, plus one final `AND`: **63 ANDs, 6 layers** at `w = 64`.
/// * **General.** Otherwise `r >= p` is the carry out of `r + (2^w - p)`, via
///   [`prefix::geq_public_constant`]. Correct for any prime modulus, a little dearer (89 ANDs at
///   `w = 64`, were Goldilocks to take this path).
///
/// Both branches are checked against each other on the boundary vectors in
/// `test_modulus_overflow_general_path_agrees`.
#[derive(Clone, Debug)]
pub struct ModulusOverflowCircuit<F: PrimeField> {
    width: usize,
    specialised: bool,
    net: Netlist,
    _f: PhantomData<fn() -> F>,
}

impl<F: PrimeField> ModulusOverflowCircuit<F> {
    pub fn new() -> Result<Self, CircuitError> {
        let width = field_bit_width::<F>();
        if width == 0 {
            return Err(CircuitError::UnsupportedWidth(0));
        }
        let reduce = two_pow_w_minus_modulus_bits::<F>();
        if reduce.len() != width {
            return Err(CircuitError::InputLengthMismatch {
                expected: width,
                got: reduce.len(),
            });
        }

        let mut builder = Builder::new();
        let r = builder.inputs(width);
        let specialised_at = solinas_exponent(&reduce);
        let overflow = match specialised_at {
            Some(m) => {
                // p = 2^w - 2^m + 1, so r >= p iff bits m.. are all set and bits ..m are not all
                // clear. Both boundaries: r = 2^w - 2^m = p - 1 gives 1 AND 0 = 0 (accept);
                // r = p gives 1 AND 1 = 1 (reject).
                let high = and_tree(&mut builder, &r[m..])?;
                let low = or_tree(&mut builder, &r[..m])?;
                builder.and(high, low)
            }
            None => geq_public_constant(&mut builder, &reduce, &r)?,
        };
        let net = builder.finish(&r, &[overflow]);
        Ok(ModulusOverflowCircuit {
            width,
            specialised: specialised_at.is_some(),
            net,
            _f: PhantomData,
        })
    }

    /// Number of input bits: `ceil(log2 p)`.
    pub fn width(&self) -> usize {
        self.width
    }

    /// Whether the cheaper Solinas-shaped construction was used.
    pub fn is_specialised(&self) -> bool {
        self.specialised
    }
}

impl<F: PrimeField> HasNetlist for ModulusOverflowCircuit<F> {
    fn netlist(&self) -> &Netlist {
        &self.net
    }
}

/// `a + b` over exactly `a.len()` little-endian bits, or `None` when the sum does not fit.
///
/// Used once, to fold the mod-`p` offset `2^w - p` into the **public** operand of A2B's second
/// addition. Overflow means the caller's mask was not a canonical representative, which is a
/// rejection rather than a wrap.
fn add_bits_le(a: &[bool], b: &[bool]) -> Option<Vec<bool>> {
    if a.len() != b.len() {
        return None;
    }
    let mut out = Vec::with_capacity(a.len());
    let mut carry = false;
    for (x, y) in a.iter().zip(b.iter()) {
        out.push(x ^ y ^ carry);
        carry = (*x && *y) || (carry && (*x || *y));
    }
    if carry {
        None
    } else {
        Some(out)
    }
}

/// `m` such that `complement == 2^m - 1`, i.e. bits `0..m` set and everything above clear, with
/// `0 < m < complement.len()`.
///
/// `complement` is `2^w - p`, so this recognises `p = 2^w - 2^m + 1` — the Solinas/Goldilocks
/// shape. `m = 0` would mean `p = 2^w` and `m = w` would mean `p = 1`; neither is a prime modulus,
/// so both fall through to the general comparison rather than being special-cased.
fn solinas_exponent(complement: &[bool]) -> Option<usize> {
    let m = complement.iter().take_while(|bit| **bit).count();
    if m == 0 || m >= complement.len() {
        return None;
    }
    if complement[m..].iter().any(|bit| *bit) {
        return None;
    }
    Some(m)
}

/// Evaluates a circuit on **plain-text** bits, standing in for the MPC multiplier with a local
/// `x * y`.
///
/// Bits are carried as `GfShare`s whose `share` field is the bit itself, i.e. a degenerate
/// (degree-0) sharing. Multiplication in `GF(2^k)` restricted to the subfield `{0, 1}` *is* the
/// AND function, so a gate evaluates to the right value without a triple, a network, or a peer.
/// This is what lets the adder and the reduction be proved correct exhaustively, offline, with no
/// harness — it exercises the real `build_layer` / `absorb_layer` bookkeeping, the real wire
/// arena and the real plan, and replaces only the one step that would need I/O.
#[cfg(test)]
pub(crate) fn evaluate_in_the_clear<C: HasNetlist>(
    circuit: &C,
    inputs: &[bool],
) -> Result<Vec<bool>, CircuitError> {
    use crate::common::convert::{binary_to_bit, bit_to_binary};
    use crate::common::gf2k::field::Gf256;

    // Deliberately not 0 and not the width, so an accidental "id == index" assumption anywhere
    // would show up as a mismatch rather than passing by luck.
    const TEST_ID: usize = 3;
    const TEST_DEGREE: usize = 2;

    let shares: Vec<GfShare<Gf256>> = inputs
        .iter()
        .map(|b| GfShare::new(bit_to_binary::<Gf256>(*b), TEST_ID, TEST_DEGREE))
        .collect();

    let mut wires = circuit.init(&shares)?;
    for layer in 0..circuit.layers() {
        let and_layer = circuit.build_layer(layer, &mut wires)?;
        let products: Vec<GfShare<Gf256>> = and_layer
            .lhs
            .iter()
            .zip(and_layer.rhs.iter())
            .map(|(l, r)| GfShare::new(l.share * r.share, TEST_ID, TEST_DEGREE))
            .collect();
        circuit.absorb_layer(layer, products, &mut wires)?;
    }

    circuit
        .outputs(&wires)?
        .into_iter()
        .map(|s| binary_to_bit(s.share).map_err(CircuitError::from))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::gf2k::field::Gf256;
    use crate::common::math::goldilocks::GoldilocksField;

    /// `p = 2^64 - 2^32 + 1`.
    const P: u64 = 0xFFFF_FFFF_0000_0001;

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

    /// Deterministic, dependency-free 64-bit stream (xorshift64*), so the sweeps below are
    /// reproducible without pinning a `rand` version.
    struct Xorshift(u64);
    impl Xorshift {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn next_field(&mut self) -> u64 {
            self.next() % P
        }
    }

    /// The 12 values every 64-bit test below sweeps: the arithmetic boundaries of the Goldilocks
    /// reduction, all inside `[0, p)`.
    const FIELD_VECTORS: [u64; 12] = [
        0,
        1,
        2,
        0xFFFF_FFFF,           // 2^32 - 1, == 2^64 - p
        0x1_0000_0000,         // 2^32
        0x1_0000_0001,         // 2^32 + 1
        0x7FFF_FFFF_FFFF_FFFF, // 2^63 - 1
        0x8000_0000_0000_0000, // 2^63
        P - 1,
        P - 2,
        P - 0x1_0000_0000, // p - 2^32
        P - 0x1_0000_0001, // p - 2^32 - 1
    ];

    fn canonical_u64(x: GoldilocksField) -> u64 {
        x.into_bigint().0[0]
    }

    /// One A2B conversion, in the clear: mask `x` with `r`, feed the opened `y` and the bits of
    /// `r` to the circuit, and demand the bits of `x` back.
    fn check_a2b(x: u64, r: u64) {
        assert!(x < P && r < P, "test vectors must be canonical");
        let y_field = GoldilocksField::from(x) - GoldilocksField::from(r);
        let y = canonical_u64(y_field);
        assert_eq!(
            y,
            ((x as u128 + P as u128 - r as u128) % P as u128) as u64,
            "field subtraction and the integer model disagree"
        );

        let circuit = FieldA2BCircuit::<GoldilocksField>::new(y_field).expect("circuit");
        assert!(
            circuit.layers() <= 7,
            "A2B must never exceed 7 AND layers (y = {y:#x})"
        );
        let out = evaluate_in_the_clear(&circuit, &bits_le(r, 64)).expect("eval");
        assert_eq!(out.len(), 64);
        assert_eq!(
            u64_from_bits(&out),
            x,
            "a2b failed for x = {x:#x}, r = {r:#x}, y = {y:#x}"
        );
    }

    #[test]
    fn test_field_a2b_boundary_vectors() {
        for &x in &FIELD_VECTORS {
            for &r in &FIELD_VECTORS {
                check_a2b(x, r);
            }
        }
    }

    #[test]
    fn test_field_a2b_random_sweep() {
        let mut rng = Xorshift(0x9E37_79B9_7F4A_7C15);
        for _ in 0..20000 {
            check_a2b(rng.next_field(), rng.next_field());
        }
        // Random x against each boundary mask, and vice versa.
        for &v in &FIELD_VECTORS {
            check_a2b(v, rng.next_field());
            check_a2b(rng.next_field(), v);
        }
    }

    /// A2B returns the canonical representative in `[0, p)`, **not** two's complement. `-1` is
    /// `p - 1 = 0xFFFF_FFFF_0000_0000`, and a caller wanting a sign bit has to shift first.
    #[test]
    fn test_field_a2b_signed_is_canonical_not_twos_complement() {
        let minus_one = GoldilocksField::from(0u64) - GoldilocksField::from(1u64);
        assert_eq!(canonical_u64(minus_one), P - 1);
        let mut rng = Xorshift(0x1234_5678_9ABC_DEF0);
        for _ in 0..8 {
            let r = rng.next_field();
            let y = canonical_u64(minus_one - GoldilocksField::from(r));
            let circuit =
                FieldA2BCircuit::<GoldilocksField>::new(GoldilocksField::from(y)).expect("circuit");
            let out = evaluate_in_the_clear(&circuit, &bits_le(r, 64)).expect("eval");
            assert_eq!(u64_from_bits(&out), 0xFFFF_FFFF_0000_0000);
            assert_ne!(u64_from_bits(&out), u64::MAX);
        }
    }

    /// The exact budget, which is what the A2B node sizes its triple pool against.
    #[test]
    fn test_field_a2b_gate_budget() {
        assert_eq!(
            FieldA2BCircuit::<GoldilocksField>::max_layers().expect("plan"),
            7,
            "A2B online AND depth on Goldilocks: two concurrent 6-layer adders plus the MUX"
        );
        assert_eq!(
            FieldA2BCircuit::<GoldilocksField>::max_and_count().expect("plan"),
            695,
            "A2B AND count upper bound on Goldilocks (310 + 321 + 64)"
        );

        // Every reachable mask is within budget, and the plan is a pure function of the mask, so
        // rebuilding it gives a bit-identical netlist at every party.
        for &y in &FIELD_VECTORS {
            let a =
                FieldA2BCircuit::<GoldilocksField>::new(GoldilocksField::from(y)).expect("circuit");
            let b =
                FieldA2BCircuit::<GoldilocksField>::new(GoldilocksField::from(y)).expect("circuit");
            assert_eq!(a.netlist(), b.netlist(), "plan is not deterministic in y");
            assert!(a.and_count() <= 695);
            assert!(a.layers() <= 7);
        }
    }

    /// The bound is analytic: it is the sum of two separately-maximised adders, and no admissible
    /// `y` attains it. This pins both halves of that claim — the decomposition `310 + 321 + 64`,
    /// and the fact that the all-ones mask the serial circuit used to take its bound from is now
    /// *rejected*, because `Y = y + (2^64 - p)` would wrap.
    #[test]
    fn test_field_a2b_budget_is_analytic_not_realisable() {
        use prefix::{add_public_constant, PublicPlusSecretAdder};

        // Adder 2 keeps its carry out; adder 1's carry cone is dead.
        let full = PublicPlusSecretAdder::new(vec![true; 64]).expect("adder");
        assert_eq!(full.and_count(), 321);

        let mut builder = Builder::new();
        let x = builder.inputs(64);
        let (sum, _carry) = add_public_constant(&mut builder, &vec![true; 64], &x).expect("adder");
        let sum_only = builder.finish(&x, &sum);
        assert_eq!(
            sum_only.and_count(),
            310,
            "dropping the carry out prunes 11 cells of the all-ones adder"
        );
        assert_eq!(
            sum_only.and_count() + full.and_count() + 64,
            FieldA2BCircuit::<GoldilocksField>::max_and_count().expect("plan"),
            "the bound must be exactly the two adders plus the multiplexer"
        );

        // `y = 2^64 - 1` is not a field element at all, and the bits of `p - 1` are the largest
        // admissible mask; neither reaches the bound.
        let biggest =
            FieldA2BCircuit::<GoldilocksField>::new(GoldilocksField::from(P - 1)).expect("circuit");
        assert!(biggest.and_count() < 695);

        // The dearest admissible mask the module header quotes, two short of the bound. Pinned
        // here so the header cannot drift away from the planner.
        let dearest = FieldA2BCircuit::<GoldilocksField>::new(GoldilocksField::from(
            0xDDD5_D776_7D77_F7D7u64,
        ))
        .expect("circuit");
        assert_eq!(dearest.and_count(), 693);
        assert_eq!(dearest.layers(), 7);
    }

    /// Raw bits above the modulus are rejected rather than silently wrapping the offset (C12).
    #[test]
    fn test_field_a2b_rejects_a_non_canonical_mask() {
        assert!(matches!(
            FieldA2BCircuit::<GoldilocksField>::plan(vec![true; 64], PrefixTopology::default()),
            Err(CircuitError::MaskNotCanonical)
        ));
        assert!(matches!(
            FieldA2BCircuit::<GoldilocksField>::plan(bits_le(P, 64), PrefixTopology::default()),
            Err(CircuitError::MaskNotCanonical)
        ));
        // One below the modulus is the largest admissible mask and must be accepted.
        assert!(FieldA2BCircuit::<GoldilocksField>::plan(
            bits_le(P - 1, 64),
            PrefixTopology::default()
        )
        .is_ok());
        assert!(matches!(
            FieldA2BCircuit::<GoldilocksField>::plan(vec![false; 63], PrefixTopology::default()),
            Err(CircuitError::InputLengthMismatch { .. })
        ));
    }

    /// The offset carry `c2` is the whole reduction decision: `c2 = 1` exactly when `y + r >= p`,
    /// and the low `w` bits of `Y + r` are then `y + r - p` with no second wrap. This replaces the
    /// serial circuit's `(c1, c2) = (1, 1)`-unreachability lemma, which the parallel form does not
    /// need because the first adder's carry out is never formed.
    #[test]
    fn test_field_a2b_offset_carry_decides_the_reduction() {
        let d = (1u128 << 64) - P as u128;
        assert_eq!(d, 0xFFFF_FFFF, "2^64 - p must be 2^32 - 1");

        let mut rng = Xorshift(0xDEAD_BEEF_CAFE_BABE);
        let mut cases: Vec<(u64, u64)> = Vec::new();
        for &x in &FIELD_VECTORS {
            for &r in &FIELD_VECTORS {
                cases.push((x, r));
            }
        }
        for _ in 0..2000 {
            cases.push((rng.next_field(), rng.next_field()));
        }

        for (x, r) in cases {
            let y = ((x as u128 + P as u128 - r as u128) % P as u128) as u64;
            let big_y = y as u128 + d; // Y = y + d, which must fit in 64 bits
            assert!(big_y < 1u128 << 64, "Y wrapped for y = {y:#x}");

            let a = y as u128 + r as u128; // A = y + r over the integers
            let t1 = (a & ((1u128 << 64) - 1)) as u64;
            let sum2 = big_y + r as u128;
            let c2 = sum2 >= 1u128 << 64;
            let t2 = (sum2 & ((1u128 << 64) - 1)) as u64;

            assert_eq!(c2, a >= P as u128, "c2 must fire exactly when y + r >= p");
            assert_eq!(if c2 { t2 } else { t1 }, x, "integer model disagrees");
        }
    }

    /// Dense neighbourhoods of every boundary the Goldilocks reduction turns on, on both the value
    /// and the mask. The cross product of [`FIELD_VECTORS`] hits the boundaries themselves; this
    /// hits the two integers either side of each, which is where an off-by-one in the offset
    /// `Y = y + d` or in the `c2 = 1 <=> y + r >= p` threshold would show up.
    #[test]
    fn test_field_a2b_boundary_neighbourhoods() {
        let centres: [u64; 7] = [
            0,
            0xFFFF_FFFF,           // 2^32 - 1 == 2^64 - p, the offset itself
            0x1_0000_0000,         // 2^32
            0x8000_0000_0000_0000, // 2^63
            P - 0x1_0000_0000,
            P - 1, // the largest field element; the largest admissible mask
            P / 2,
        ];
        let mut points: Vec<u64> = Vec::new();
        for &c in &centres {
            for delta in 0..=4i64 {
                let candidate = (c as i128 + delta as i128 - 2) as i128;
                if (0..P as i128).contains(&candidate) {
                    points.push(candidate as u64);
                }
            }
        }
        points.sort_unstable();
        points.dedup();

        for &x in &points {
            for &r in &points {
                check_a2b(x, r);
            }
        }
    }

    /// A narrow output is a pure pruning of the same plan: the low `l` bits it keeps must be the
    /// low `l` bits the full-width circuit produces. Checked at `l = 33`, the width of the repo's
    /// default `FixedPointPrecision(32, 16)`, and at a few others.
    #[test]
    fn test_field_a2b_narrow_output_matches_low_bits() {
        let mut rng = Xorshift(0x0F1E_2D3C_4B5A_6978);
        for ell in [1usize, 8, 33, 63, 64] {
            for _ in 0..64 {
                let x = rng.next_field();
                let r = rng.next_field();
                let y = canonical_u64(GoldilocksField::from(x) - GoldilocksField::from(r));
                let net = truncated_parallel_plan(y, ell);
                let out = evaluate_in_the_clear(&net, &bits_le(r, 64)).expect("eval");
                assert_eq!(out.len(), ell);
                let mask = if ell == 64 {
                    u64::MAX
                } else {
                    (1u64 << ell) - 1
                };
                assert_eq!(
                    u64_from_bits(&out),
                    x & mask,
                    "l = {ell}: narrow output disagrees for x = {x:#x}, r = {r:#x}"
                );
                assert!(net.layers() <= 7);
            }
        }
    }

    /// Cost and depth, measured rather than asserted from the design note, at both the full field
    /// width and the repo's default fixed-point width.
    ///
    /// `l = 33` is [`crate::common::types::fixed::FixedPointPrecision`]`(32, 16)`'s width. It does
    /// **not** shrink the preprocessing — the mask must stay uniform on `[0, p)` whatever the
    /// value's width, so the edaBit is 64 daBits either way — but a caller that has certified it
    /// needs no high output bits gets a cheaper *circuit*, because backward liveness then prunes
    /// the high cones of **both** parallel adders. The serial chain cannot do that: all 64 bits of
    /// its first adder stay live to feed the second one.
    #[test]
    fn test_field_a2b_measured_cost() {
        let mut rng = Xorshift(0x0123_4567_89AB_CDEF);
        let samples = 4096usize;

        let mut total = 0usize;
        let mut worst = 0usize;
        let mut deepest = 0usize;
        for _ in 0..samples {
            let circuit =
                FieldA2BCircuit::<GoldilocksField>::new(GoldilocksField::from(rng.next_field()))
                    .expect("circuit");
            total += circuit.and_count();
            worst = worst.max(circuit.and_count());
            deepest = deepest.max(circuit.layers());
        }
        let mean = total / samples;
        println!("l=64 parallel: bound 695, max seen {worst}, mean {mean}, depth {deepest}");
        assert_eq!(deepest, 7);
        assert!(worst <= 695);
        assert!(
            (630..=655).contains(&mean),
            "mean AND count over a uniform mask drifted to {mean} (expected ~642)"
        );

        // Narrow output: only the low 33 bits of `x` are read.
        let mut narrow_total = 0usize;
        let mut serial_total = 0usize;
        let mut narrow_depth = 0usize;
        let mut serial_depth = 0usize;
        for _ in 0..samples {
            let y = rng.next_field();
            let narrow = truncated_parallel_plan(y, 33);
            let serial = truncated_serial_plan(y, 33);
            narrow_total += narrow.and_count();
            serial_total += serial.and_count();
            narrow_depth = narrow_depth.max(narrow.layers());
            serial_depth = serial_depth.max(serial.layers());
        }
        let narrow_mean = narrow_total / samples;
        let serial_mean = serial_total / samples;
        println!(
            "l=33 parallel: mean {narrow_mean}, depth {narrow_depth}; \
             l=33 serial: mean {serial_mean}, depth {serial_depth}"
        );
        assert_eq!(narrow_depth, 7);
        assert_eq!(serial_depth, 13);
        assert!(
            narrow_mean < serial_mean,
            "the parallel form must prune further at a narrow output width"
        );
    }

    /// `l`-bit-output A2B on the parallel offset adder: the plan of [`FieldA2BCircuit`] with only
    /// the low `l` outputs declared live. Test scaffolding for the cost measurement above — the
    /// node has no narrow entry point, because a narrow output is only correct when the caller
    /// certifies its value needs no high bits, which the repo's signed encoding does not.
    fn truncated_parallel_plan(y: u64, ell: usize) -> Netlist {
        let y_bits = bits_le(y, 64);
        let reduce = two_pow_w_minus_modulus_bits::<GoldilocksField>();
        let offset = add_bits_le(&y_bits, &reduce).expect("y must be canonical");
        let mut builder = Builder::new();
        let r = builder.inputs(64);
        let (t1, _c1) =
            prefix::add_public_constant(&mut builder, &y_bits, &r).expect("first adder");
        let (t2, c2) = prefix::add_public_constant(&mut builder, &offset, &r).expect("second");
        let out = mux(&mut builder, c2, &t1, &t2).expect("mux");
        builder.finish(&r, &out[..ell])
    }

    /// The same, on the superseded serial `ADD -> ADD -> MUX` chain, for the comparison.
    fn truncated_serial_plan(y: u64, ell: usize) -> Netlist {
        let y_bits = bits_le(y, 64);
        let reduce = two_pow_w_minus_modulus_bits::<GoldilocksField>();
        let mut builder = Builder::new();
        let r = builder.inputs(64);
        let (t1, c1) = prefix::add_public_constant(&mut builder, &y_bits, &r).expect("first adder");
        let (t2, c2) = prefix::add_public_constant(&mut builder, &reduce, &t1).expect("second");
        let c = builder.xor(c1, c2);
        let out = mux(&mut builder, c, &t1, &t2).expect("mux");
        builder.finish(&r, &out[..ell])
    }

    /// The prefix topology is a cost knob and never a semantic one: Brent-Kung computes the same
    /// bits for fewer triples and more rounds, and the default is the minimum-depth point.
    #[test]
    fn test_field_a2b_topology_is_a_cost_knob_only() {
        type C = FieldA2BCircuit<GoldilocksField>;

        let sklansky_ands = C::max_and_count_on(PrefixTopology::Sklansky).expect("plan");
        let sklansky_depth = C::max_layers_on(PrefixTopology::Sklansky).expect("plan");
        let bk_ands = C::max_and_count_on(PrefixTopology::BrentKung).expect("plan");
        let bk_depth = C::max_layers_on(PrefixTopology::BrentKung).expect("plan");
        println!(
            "topologies at l=64: sklansky {sklansky_ands}/{sklansky_depth}, \
             brent-kung {bk_ands}/{bk_depth}"
        );

        assert_eq!(PrefixTopology::default(), PrefixTopology::Sklansky);
        assert_eq!((sklansky_ands, sklansky_depth), (695, 7));
        assert!(bk_ands < sklansky_ands, "Brent-Kung must spend fewer ANDs");
        assert!(bk_depth > sklansky_depth, "... and buy that with rounds");
        assert_eq!(
            C::max_and_count().expect("plan"),
            sklansky_ands,
            "the default must be the minimum-depth point"
        );

        let mut rng = Xorshift(0x5555_AAAA_3333_CCCC);
        for _ in 0..64 {
            let x = rng.next_field();
            let r = rng.next_field();
            let y = GoldilocksField::from(x) - GoldilocksField::from(r);
            for topology in [PrefixTopology::Sklansky, PrefixTopology::BrentKung] {
                let circuit = C::new_on(y, topology).expect("circuit");
                assert_eq!(circuit.topology(), topology);
                let out = evaluate_in_the_clear(&circuit, &bits_le(r, 64)).expect("eval");
                assert_eq!(u64_from_bits(&out), x, "topology {topology:?} disagrees");
            }
        }
    }

    #[test]
    fn test_modulus_overflow_goldilocks() {
        let circuit = ModulusOverflowCircuit::<GoldilocksField>::new().expect("circuit");
        assert!(
            circuit.is_specialised(),
            "Goldilocks is 2^64 - 2^32 + 1 and must take the Solinas path"
        );
        assert_eq!(circuit.width(), 64);
        assert_eq!(circuit.and_count(), 63, "31 + 31 + 1");
        assert_eq!(circuit.layers(), 6, "two depth-5 trees plus the final AND");

        for value in [
            0u64,
            1,
            0xFFFF_FFFF,
            0x1_0000_0000,
            P - 2,
            P - 1, // 0xFFFF_FFFF_0000_0000: top half all ones, bottom half zero -> accept
            P,     // -> reject
            P + 1,
            u64::MAX,
            0xFFFF_FFFF_0000_0002,
        ] {
            let out = evaluate_in_the_clear(&circuit, &bits_le(value, 64)).expect("eval");
            assert_eq!(out.len(), 1);
            assert_eq!(out[0], value >= P, "r >= p for {value:#x}");
        }

        let mut rng = Xorshift(0x0BAD_C0DE_0BAD_C0DE);
        for _ in 0..500 {
            let value = rng.next();
            let out = evaluate_in_the_clear(&circuit, &bits_le(value, 64)).expect("eval");
            assert_eq!(out[0], value >= P, "r >= p for {value:#x}");
        }
    }

    /// The general carry-out comparison must agree with the Solinas specialisation everywhere; it
    /// is the branch any non-Goldilocks modulus would take.
    #[test]
    fn test_modulus_overflow_general_path_agrees() {
        let complement = bits_le(0xFFFF_FFFF, 64); // 2^64 - p
        assert_eq!(solinas_exponent(&complement), Some(32));
        assert_eq!(solinas_exponent(&bits_le(0, 64)), None);
        assert_eq!(solinas_exponent(&bits_le(u64::MAX, 64)), None);
        assert_eq!(solinas_exponent(&bits_le(0b1011, 64)), None);

        let mut builder = Builder::new();
        let r = builder.inputs(64);
        let carry = geq_public_constant(&mut builder, &complement, &r).expect("geq");
        let general = builder.finish(&r, &[carry]);
        let special = ModulusOverflowCircuit::<GoldilocksField>::new().expect("circuit");

        let mut rng = Xorshift(0xFEED_FACE_FEED_FACE);
        let mut values: Vec<u64> = vec![0, 1, P - 1, P, P + 1, u64::MAX, 0xFFFF_FFFF];
        for _ in 0..20000 {
            values.push(rng.next());
        }
        for value in values {
            let bits = bits_le(value, 64);
            let a = evaluate_in_the_clear(&general, &bits).expect("eval");
            let b = evaluate_in_the_clear(&special, &bits).expect("eval");
            assert_eq!(a[0], value >= P, "general path wrong for {value:#x}");
            assert_eq!(
                a, b,
                "the two overflow constructions disagree at {value:#x}"
            );
        }
    }

    /// Liveness must delete the propagate half of every Sklansky cell nobody reads, and must then
    /// collapse the layers that empties out.
    #[test]
    fn test_liveness_prunes_dead_gates_and_layers() {
        // Two independent ANDs, only one of which is an output.
        let mut builder = Builder::new();
        let x = builder.inputs(4);
        let live = builder.and(x[0], x[1]);
        let _dead = builder.and(x[2], x[3]);
        let net = builder.finish(&x, &[live]);
        assert_eq!(net.and_count(), 1, "the dead gate must not cost a triple");
        assert_eq!(net.layers(), 1);

        // A gate whose only consumer is dead, two layers deep, must take its whole layer with it.
        let mut builder = Builder::new();
        let x = builder.inputs(3);
        let keep = builder.and(x[0], x[1]);
        let dead_a = builder.and(x[1], x[2]);
        let _dead_b = builder.and(dead_a, x[0]);
        let net = builder.finish(&x, &[keep]);
        assert_eq!(net.and_count(), 1);
        assert_eq!(net.layers(), 1, "the second layer must be collapsed away");
    }

    /// Constant folding: a public operand costs nothing, in either position.
    #[test]
    fn test_constant_folding_costs_no_triples() {
        let mut builder = Builder::new();
        let x = builder.inputs(2);
        let zero = builder.constant(false);
        let one = builder.constant(true);
        // `x0 AND 0` is the constant 0 and `1 AND x1` is `x1`; neither may reach a layer.
        let a = builder.and(x[0], zero);
        let b = builder.and(one, x[1]);
        let c = builder.xor(a, b);
        let net = builder.finish(&x, &[c]);
        assert_eq!(net.and_count(), 0);
        assert_eq!(net.layers(), 0);
        for lhs in [false, true] {
            for rhs in [false, true] {
                let out = evaluate_in_the_clear(&net, &[lhs, rhs]).expect("eval");
                assert_eq!(out[0], rhs);
            }
        }
    }

    /// Every way the multiplier's answer can be malformed must be a typed error, never a panic and
    /// never a silently wrong wire (C5/C12).
    #[test]
    fn test_absorb_layer_validates_products() {
        let circuit = ModulusOverflowCircuit::<GoldilocksField>::new().expect("circuit");
        let inputs: Vec<GfShare<Gf256>> =
            (0..64).map(|_| GfShare::new(Gf256::one(), 3, 2)).collect();

        // Wrong length.
        let mut wires = circuit.init(&inputs).expect("init");
        let layer = circuit.build_layer(0, &mut wires).expect("layer");
        assert!(!layer.is_empty());
        assert!(matches!(
            circuit.absorb_layer(0, vec![], &mut wires),
            Err(CircuitError::LayerLengthMismatch { .. })
        ));

        // Foreign share id.
        let bad_id: Vec<GfShare<Gf256>> = (0..layer.len())
            .map(|_| GfShare::new(Gf256::zero(), 4, 2))
            .collect();
        assert!(matches!(
            circuit.absorb_layer(0, bad_id, &mut wires),
            Err(CircuitError::IdMismatch { .. })
        ));

        // Wrong degree — e.g. an unreduced degree-2t product.
        let bad_degree: Vec<GfShare<Gf256>> = (0..layer.len())
            .map(|_| GfShare::new(Gf256::zero(), 3, 4))
            .collect();
        assert!(matches!(
            circuit.absorb_layer(0, bad_degree, &mut wires),
            Err(CircuitError::DegreeMismatch { .. })
        ));

        // Absorbing the wrong layer, and building twice without absorbing.
        let good: Vec<GfShare<Gf256>> = (0..layer.len())
            .map(|_| GfShare::new(Gf256::zero(), 3, 2))
            .collect();
        assert!(matches!(
            circuit.absorb_layer(1, good.clone(), &mut wires),
            Err(CircuitError::LayerNotAbsorbed(0))
        ));
        assert!(matches!(
            circuit.build_layer(1, &mut wires),
            Err(CircuitError::LayerNotAbsorbed(0))
        ));
        assert!(matches!(
            circuit.outputs(&wires),
            Err(CircuitError::LayerNotAbsorbed(0))
        ));
        circuit.absorb_layer(0, good, &mut wires).expect("absorb");
        assert!(matches!(
            circuit.absorb_layer(0, vec![], &mut wires),
            Err(CircuitError::NothingToAbsorb)
        ));
        assert!(matches!(
            circuit.build_layer(99, &mut wires),
            Err(CircuitError::LayerOutOfRange(99))
        ));
    }

    /// C5: one evaluation is pinned to a single `(id, degree)`; a mixed input batch is rejected.
    #[test]
    fn test_init_validates_inputs() {
        let circuit = ModulusOverflowCircuit::<GoldilocksField>::new().expect("circuit");

        let short: Vec<GfShare<Gf256>> =
            (0..63).map(|_| GfShare::new(Gf256::zero(), 3, 2)).collect();
        assert!(matches!(
            circuit.init(&short),
            Err(CircuitError::InputLengthMismatch { .. })
        ));

        let mut mixed_id: Vec<GfShare<Gf256>> =
            (0..64).map(|_| GfShare::new(Gf256::zero(), 3, 2)).collect();
        mixed_id[17] = GfShare::new(Gf256::zero(), 5, 2);
        assert!(matches!(
            circuit.init(&mixed_id),
            Err(CircuitError::IdMismatch { .. })
        ));

        let mut mixed_degree: Vec<GfShare<Gf256>> =
            (0..64).map(|_| GfShare::new(Gf256::zero(), 3, 2)).collect();
        mixed_degree[0] = GfShare::new(Gf256::zero(), 3, 7);
        assert!(matches!(
            circuit.init(&mixed_degree),
            Err(CircuitError::DegreeMismatch { .. })
        ));
    }

    /// A public constant materialises as the constant sharing, which every party holds identically
    /// and which is a degree-`t` codeword of that constant.
    #[test]
    fn test_constant_wire_materialises_as_constant_sharing() {
        let zero: BitWire<Gf256> = BitWire::Const(false);
        let one: BitWire<Gf256> = BitWire::Const(true);
        assert_eq!(zero.materialize(6, 3), GfShare::new(Gf256::zero(), 6, 3));
        assert_eq!(one.materialize(6, 3), GfShare::new(Gf256::one(), 6, 3));
        assert!(zero.as_share().is_none());
        assert!(BitWire::Secret(GfShare::new(Gf256::one(), 1, 1))
            .as_share()
            .is_some());
    }
}
