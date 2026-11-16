//! Checks on the circuit plans themselves, independent of any share arithmetic.
//!
//! Two things live here:
//!
//! * **Exhaustive checks on small prime fields.** The plan generator is generic in the field, so
//!   on an 8-bit prime every mask `y` and every `r` can be tried. Two shapes are covered: a
//!   Solinas prime `2^w - 2^m + 1`, which takes the specialised overflow circuit, and a general
//!   prime, which takes the fallback — the path both curve fields take.
//! * **An exporter** for the plans of the BLS12-381 and BN254 scalar fields, consumed by
//!   `formal/netlists/check.py`, which has an SMT solver prove each exported plan correct for
//!   *every* `r`.
//!
//! Both go through `Netlist::to_text` and the interpreter below, never through `GfShare`, so
//! they test the plan as data.

use ark_ff::{Fp64, MontBackend, MontConfig, PrimeField};
use num_bigint::BigUint;
use stoffelcrypto::common::convert::field_bit_width;
use stoffelcrypto::honeybadger::binary_circuits::prefix::PrefixTopology;
use stoffelcrypto::honeybadger::binary_circuits::{
    FieldA2BCircuit, HasNetlist, ModulusOverflowCircuit,
};

/// The scalar field of BLS12-381.
type Bls = ark_bls12_381::Fr;
/// The scalar field of BN254.
type Bn = ark_bn254::Fr;

#[derive(MontConfig)]
#[modulus = "241"]
#[generator = "7"]
pub struct F241Config;
/// `2^8 - 2^4 + 1`: a Solinas prime at 8 bits.
type F241 = Fp64<MontBackend<F241Config, 1>>;

#[derive(MontConfig)]
#[modulus = "251"]
#[generator = "6"]
pub struct F251Config;
/// A general 8-bit prime, not of the Solinas shape.
type F251 = Fp64<MontBackend<F251Config, 1>>;

#[derive(MontConfig)]
#[modulus = "61441"]
#[generator = "17"]
pub struct F61441Config;
/// `2^16 - 2^12 + 1`: a Solinas prime at 16 bits.
type F61441 = Fp64<MontBackend<F61441Config, 1>>;

/// One line of a plan in `Netlist::to_text` form.
enum Op {
    Const(usize, bool),
    Xor(usize, usize, usize),
    XorConst(usize, usize, bool),
    Layer,
    And(usize, usize, usize, Option<usize>),
    End,
}

/// A parsed plan, run on plain bits.
struct Plan {
    arena: usize,
    inputs: Vec<usize>,
    outputs: Vec<usize>,
    ops: Vec<Op>,
}

impl Plan {
    fn parse(text: &str) -> Self {
        let num = |s: &str| s.parse::<usize>().expect("wire index");
        let mut plan = Plan {
            arena: 0,
            inputs: Vec::new(),
            outputs: Vec::new(),
            ops: Vec::new(),
        };
        for line in text.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            match f.as_slice() {
                ["arena", n] => plan.arena = num(n),
                ["inputs", ws @ ..] => plan.inputs = ws.iter().map(|w| num(w)).collect(),
                ["outputs", ws @ ..] => plan.outputs = ws.iter().map(|w| num(w)).collect(),
                ["const", dst, v] => plan.ops.push(Op::Const(num(dst), *v == "1")),
                ["xor", dst, a, b] => plan.ops.push(Op::Xor(num(dst), num(a), num(b))),
                ["xorc", dst, src, v] => plan.ops.push(Op::XorConst(num(dst), num(src), *v == "1")),
                ["layer", _] => plan.ops.push(Op::Layer),
                ["and", dst, lhs, rhs, xor_in] => plan.ops.push(Op::And(
                    num(dst),
                    num(lhs),
                    num(rhs),
                    (*xor_in != "-").then(|| num(xor_in)),
                )),
                ["end"] => plan.ops.push(Op::End),
                [] => {}
                other => panic!("unknown netlist line {other:?}"),
            }
        }
        plan
    }

    /// Runs the plan on a small input: bit `i` of `input` goes to input `i`.
    fn run(&self, input: u64) -> u64 {
        let bits: Vec<bool> = (0..self.inputs.len())
            .map(|i| i < 64 && (input >> i) & 1 == 1)
            .collect();
        self.run_bits(&bits)
            .iter()
            .enumerate()
            .fold(0u64, |acc, (i, bit)| acc | ((*bit as u64) << i))
    }

    /// Runs the plan on any number of input bits.
    fn run_bits(&self, input: &[bool]) -> Vec<bool> {
        let mut wires = vec![false; self.arena];
        for (i, w) in self.inputs.iter().enumerate() {
            wires[*w] = input[i];
        }
        let mut pending: Vec<(usize, bool)> = Vec::new();
        for op in &self.ops {
            match *op {
                Op::Const(dst, v) => wires[dst] = v,
                Op::Xor(dst, a, b) => wires[dst] = wires[a] ^ wires[b],
                Op::XorConst(dst, src, v) => wires[dst] = wires[src] ^ v,
                Op::Layer => pending.clear(),
                // Every AND of a layer reads the wires as they stood when the layer began.
                Op::And(dst, lhs, rhs, xor_in) => {
                    let mut value = wires[lhs] & wires[rhs];
                    if let Some(w) = xor_in {
                        value ^= wires[w];
                    }
                    pending.push((dst, value));
                }
                Op::End => {
                    for (dst, value) in pending.drain(..) {
                        wires[dst] = value;
                    }
                }
            }
        }
        self.outputs.iter().map(|w| wires[*w]).collect()
    }
}

fn modulus<F: PrimeField>() -> u64 {
    F::MODULUS.as_ref()[0]
}

/// Every mask and every `r` below the modulus: the plan must return `(y + r) mod p`.
fn a2b_exhaustive<F: PrimeField>() {
    let p = modulus::<F>();
    for y in 0..p {
        let circuit = FieldA2BCircuit::<F>::new(F::from(y)).expect("plan");
        let plan = Plan::parse(&circuit.netlist().to_text());
        for r in 0..p {
            assert_eq!(plan.run(r), (y + r) % p, "p = {p}, y = {y}, r = {r}");
        }
    }
}

/// Every `w`-bit candidate, including those at or above the modulus.
fn overflow_exhaustive<F: PrimeField>(expect_specialised: bool) {
    let p = modulus::<F>();
    let circuit = ModulusOverflowCircuit::<F>::new().expect("plan");
    assert_eq!(circuit.is_specialised(), expect_specialised);
    let plan = Plan::parse(&circuit.netlist().to_text());
    for r in 0..(1u64 << circuit.width()) {
        assert_eq!(plan.run(r), (r >= p) as u64, "p = {p}, r = {r}");
    }
}

#[test]
fn a2b_plan_is_exact_for_every_mask_and_input_on_a_solinas_prime() {
    a2b_exhaustive::<F241>();
}

#[test]
fn a2b_plan_is_exact_for_every_mask_and_input_on_a_general_prime() {
    a2b_exhaustive::<F251>();
}

/// The mask-as-input plan, on every mask and every input of an 8-bit field. Its inputs are the
/// bits of `r`, then of `y`, then of `Y = y + (2^w - p)`.
fn generic_exhaustive<F: PrimeField>() {
    let p = modulus::<F>();
    let width = F::MODULUS_BIT_SIZE as u64;
    let plan = Plan::parse(
        &FieldA2BCircuit::<F>::generic_plan_on(PrefixTopology::default())
            .expect("plan")
            .to_text(),
    );
    let d = (1u64 << width) - p;
    for y in 0..p {
        for r in 0..p {
            let input = r | (y << width) | ((y + d) << (2 * width));
            assert_eq!(plan.run(input), (y + r) % p, "p = {p}, y = {y}, r = {r}");
        }
    }
}

#[test]
fn the_mask_as_input_plan_is_exact_on_both_8_bit_primes() {
    generic_exhaustive::<F241>();
    generic_exhaustive::<F251>();
}

#[test]
fn overflow_plan_is_exact_for_every_candidate() {
    overflow_exhaustive::<F241>(true);
    overflow_exhaustive::<F251>(false);
    overflow_exhaustive::<F61441>(true);
}

/// Sixteen bits is too wide to try every pair, so: every mask, against the boundary inputs and a
/// spread of others.
#[test]
#[ignore = "about a minute; run explicitly with --ignored"]
fn a2b_plan_is_exact_for_every_mask_on_a_16_bit_solinas_prime() {
    let p = modulus::<F61441>();
    let mut inputs = vec![
        0,
        1,
        2,
        p - 1,
        p - 2,
        p / 2,
        (1 << 12) - 1,
        1 << 12,
        p - (1 << 12),
    ];
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    for _ in 0..24 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        inputs.push(state % p);
    }
    for y in 0..p {
        let circuit = FieldA2BCircuit::<F61441>::new(F61441::from(y)).expect("plan");
        let plan = Plan::parse(&circuit.netlist().to_text());
        for &r in &inputs {
            assert_eq!(plan.run(r), (y + r) % p, "y = {y}, r = {r}");
        }
    }
}

fn modulus_of<F: PrimeField>() -> BigUint {
    F::MODULUS.into()
}

fn bits_le(value: &BigUint, width: usize) -> Vec<bool> {
    (0..width).map(|i| value.bit(i as u64)).collect()
}

fn from_bits(bits: &[bool]) -> BigUint {
    let mut acc = BigUint::from(0u8);
    for (i, bit) in bits.iter().enumerate() {
        acc.set_bit(i as u64, *bit);
    }
    acc
}

/// A deterministic stream of values below `bound`.
struct Stream(u64);
impl Stream {
    fn below(&mut self, bound: &BigUint) -> BigUint {
        let mut acc = BigUint::from(0u8);
        for _ in 0..bound.bits().div_ceil(64) + 1 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            acc = (acc << 64) + BigUint::from(self.0);
        }
        acc % bound
    }
}

/// The exported plans of a curve field, run by the interpreter, on sampled masks and inputs.
fn exported_plans_are_exact_on_sampled_inputs<F: PrimeField>() {
    let p = modulus_of::<F>();
    let w = field_bit_width::<F>();
    let mut stream = Stream(0x0123_4567_89AB_CDEF);
    for _ in 0..40 {
        let (y, r) = (stream.below(&p), stream.below(&p));
        let circuit = FieldA2BCircuit::<F>::new(F::from(y.clone())).unwrap();
        let out = Plan::parse(&circuit.netlist().to_text()).run_bits(&bits_le(&r, w));
        assert_eq!(from_bits(&out), (&y + &r) % &p);
    }
}

#[test]
fn exported_curve_field_plans_are_exact_on_sampled_inputs() {
    exported_plans_are_exact_on_sampled_inputs::<Bls>();
    exported_plans_are_exact_on_sampled_inputs::<Bn>();
}

/// The masks whose plans are exported for the SMT check: the arithmetic boundaries of the
/// reduction, regular bit patterns, single bits, and a seeded random spread.
fn masks<F: PrimeField>(random: usize) -> Vec<BigUint> {
    let p = modulus_of::<F>();
    let w = field_bit_width::<F>();
    let one = BigUint::from(1u8);
    let top = BigUint::from(1u8) << w;
    let d = &top - &p;
    let mut masks = vec![
        BigUint::from(0u8),
        one.clone(),
        BigUint::from(2u8),
        &p - &one,
        &p - BigUint::from(2u8),
        &p >> 1,
        (&top - &one) / BigUint::from(3u8), // 0101..01
        (&top - &one) / BigUint::from(3u8) * BigUint::from(2u8), // 1010..10
        (&top - &one) / BigUint::from(15u8), // 0001 0001 ..
        (&top - &one) / BigUint::from(255u8),
        &d - &one,
        d.clone(),
        &d + &one,
    ];
    for bit in 0..w {
        let single = BigUint::from(1u8) << bit;
        masks.push((&p - &one) ^ &single);
        masks.push(single);
    }
    let mut stream = Stream(0xD1B5_4A32_D192_ED03);
    for _ in 0..random {
        masks.push(stream.below(&p));
    }
    masks.retain(|m| *m < p);
    masks.sort();
    masks.dedup();
    masks
}

/// Writes one field's plans to `dir`, with the modulus beside them so the checker needs no
/// knowledge of the field.
fn export_field<F: PrimeField>(dir: &str, random: usize) -> usize {
    std::fs::create_dir_all(dir).unwrap();
    let p = modulus_of::<F>();
    std::fs::write(format!("{dir}/modulus.txt"), format!("{p:x}\n")).unwrap();

    let overflow = ModulusOverflowCircuit::<F>::new().unwrap();
    std::fs::write(format!("{dir}/overflow.net"), overflow.netlist().to_text()).unwrap();

    // The construction with the mask as inputs: one proof covers every mask.
    let generic = FieldA2BCircuit::<F>::generic_plan_on(PrefixTopology::default()).unwrap();
    std::fs::write(format!("{dir}/generic.net"), generic.to_text()).unwrap();

    let masks = masks::<F>(random);
    for y in &masks {
        let circuit = FieldA2BCircuit::<F>::new(F::from(y.clone())).unwrap();
        std::fs::write(format!("{dir}/a2b_{y:x}.net"), circuit.netlist().to_text()).unwrap();
    }
    masks.len()
}

/// Writes the curve fields' plans to `$NETLIST_DIR/{bls12_381,bn254}` for
/// `formal/netlists/check.py`.
#[test]
#[ignore = "exporter for the SMT check; run with NETLIST_DIR set"]
fn export_curve_field_plans() {
    let dir = std::env::var("NETLIST_DIR").expect("set NETLIST_DIR");
    let random = std::env::var("NETLIST_RANDOM")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200);
    let bls = export_field::<Bls>(&format!("{dir}/bls12_381"), random);
    let bn = export_field::<Bn>(&format!("{dir}/bn254"), random);
    println!("exported {bls} BLS12-381 and {bn} BN254 A2B plans to {dir}");
}
