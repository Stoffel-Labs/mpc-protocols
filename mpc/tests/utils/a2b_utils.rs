#![allow(dead_code)]
//! Trusted-dealer conversion preprocessing and the boundary-value corpus for the A2B tests.
//!
//! `PrssDaBitNode` is deliberately not driven from here — but note the reason has changed, and
//! the old one is no longer true. The dealt protocol could not produce a batch smaller than its
//! bucketing soundness floor (1024 outputs at `B = 5, kappa = 40`), so generating real daBits
//! inside a conversion test was a preprocessing-scale run by construction. PRSS daBits have
//! **soundness error 0 and no floor**, so that argument is gone: a batch of 64 is now perfectly
//! cheap.
//!
//! What survives is the isolation argument, which is the one that actually matters here. These
//! are tests of the *conversion*; dealing its input in the clear is what makes a failure land on
//! A2B rather than on whichever of `PrssDaBitNode`, `RandBit`, PRSS key setup or the `r < p`
//! filter happened to be upstream. Generation has its own tests (`prss_dabit_test.rs`,
//! `edabit_filter_test.rs`). What these helpers produce is what a correct `PrssDaBitNode` plus
//! filter is specified to produce, dealt in the clear: degree-`t` sharings of the *same* bit in
//! both domains, and full-range edaBits whose `r` has already passed the `r < p` filter.
//!
//! The dealing here is honest by construction, so nothing in these files says anything about
//! daBit *generation*; they pin the conversion's arithmetic and its wiring.

use ark_std::rand::rngs::StdRng;
use ark_std::rand::Rng;
use stoffelcrypto::common::convert::{bit_to_binary, canonical_bits, field_bit_width};
use stoffelcrypto::common::gf2k::field::{BinaryField, Gf256};
use stoffelcrypto::common::gf2k::share::GfShare;
use stoffelcrypto::common::math::goldilocks::GoldilocksField;
use stoffelcrypto::common::SecretSharingScheme;
use stoffelcrypto::honeybadger::dabit::{DaBit, EdaBit};
use stoffelcrypto::honeybadger::gf_triple_gen::GfBeaverTriple;
use stoffelcrypto::honeybadger::robust_interpolate::robust_interpolate::RobustShare;

pub type F = GoldilocksField;
pub type K = Gf256;

/// `p = 2^64 - 2^32 + 1`, the Goldilocks modulus.
pub const P: u64 = 0xFFFF_FFFF_0000_0001;

/// The values a full-range A2B has to get right, and the reason each one is here.
///
/// The exact conversion is `x = (y + r) - p * [y + r >= p]` evaluated as two 64-bit additions and
/// a MUX, so the interesting inputs are the ones that sit on a carry boundary of either addition
/// or on the boundary of the conditional reduction. `2^64 - p = 2^32 - 1` is what makes the second
/// addition the reduction, which is why the `2^32` neighbourhood appears three times.
pub fn boundary_values() -> Vec<(&'static str, F)> {
    vec![
        ("zero", F::from(0u64)),
        ("one", F::from(1u64)),
        // The low half of `p` is zero above bit 0, so `2^32 - 1` is the largest value whose bits
        // are entirely inside that half: the widest input for which no reduction can be due.
        ("2^32 - 1", F::from(0xFFFF_FFFFu64)),
        ("2^32", F::from(1u64 << 32)),
        ("2^32 + 1", F::from((1u64 << 32) + 1)),
        // Straddles the 63-bit width bound B2A enforces, from both sides.
        ("2^63 - 1", F::from((1u64 << 63) - 1)),
        ("2^63", F::from(1u64 << 63)),
        ("2^63 + 1", F::from((1u64 << 63) + 1)),
        // `p - 2^32` and its neighbours drive the `c1 = 1` branch of the adder: `y + r` exceeds
        // `2^64` and exactly one subtraction of `p` is due.
        ("p - 1 - 2^32", F::from(P - 1 - (1u64 << 32))),
        ("p - 2^32", F::from(P - (1u64 << 32))),
        ("p - 2", F::from(P - 2)),
        // `-1`. The canonical representative is `p - 1 = 0xFFFF_FFFF_0000_0000`, NOT `u64::MAX`.
        ("p - 1 (= -1)", F::from(0u64) - F::from(1u64)),
    ]
}

/// Uniform field elements, for the batch that is not made of special cases.
pub fn random_values(count: usize, rng: &mut StdRng) -> Vec<F> {
    (0..count)
        .map(|_| {
            let mut candidate: u64 = rng.gen();
            while candidate >= P {
                candidate = rng.gen();
            }
            F::from(candidate)
        })
        .collect()
}

/// Transposes a dealer's per-value share vectors into per-party columns.
fn transpose<T: Clone>(rows: Vec<Vec<T>>, n_parties: usize) -> Vec<Vec<T>> {
    let mut columns: Vec<Vec<T>> = vec![Vec::new(); n_parties];
    for row in rows {
        for (party, share) in row.into_iter().enumerate() {
            columns[party].push(share);
        }
    }
    columns
}

/// Degree-`t` arithmetic sharings of `values`, indexed `[party][value]`.
pub fn deal_field(
    n_parties: usize,
    t: usize,
    values: &[F],
    rng: &mut StdRng,
) -> Vec<Vec<RobustShare<F>>> {
    let rows = values
        .iter()
        .map(|value| RobustShare::compute_shares(*value, n_parties, t, None, rng).unwrap())
        .collect();
    transpose(rows, n_parties)
}

/// Degree-`t` binary sharings of `bits`, indexed `[party][bit]`.
pub fn deal_bits(
    n_parties: usize,
    t: usize,
    bits: &[bool],
    rng: &mut StdRng,
) -> Vec<Vec<GfShare<K>>> {
    let rows = bits
        .iter()
        .map(|bit| GfShare::compute_shares(bit_to_binary::<K>(*bit), n_parties, t, rng).unwrap())
        .collect();
    transpose(rows, n_parties)
}

/// One daBit: the *same* bit shared at degree `t` in both domains, indexed `[party][index]`.
///
/// The two halves share only the party index. `RobustShare::id` indexes the FFT domain and
/// `GfShare::id` indexes `[1, g, g^2, ..]`; the x-coordinates are unrelated, and a daBit ties the
/// domains by value alone — which is exactly what `DaBit::new` checks.
pub fn deal_dabits(
    n_parties: usize,
    t: usize,
    count: usize,
    rng: &mut StdRng,
) -> Vec<Vec<DaBit<F, K>>> {
    let mut per_party: Vec<Vec<DaBit<F, K>>> = vec![Vec::new(); n_parties];
    for _ in 0..count {
        let bit: bool = rng.gen();
        let arith =
            RobustShare::compute_shares(F::from(bit as u64), n_parties, t, None, rng).unwrap();
        let bin = GfShare::compute_shares(bit_to_binary::<K>(bit), n_parties, t, rng).unwrap();
        for party in 0..n_parties {
            per_party[party].push(DaBit::new(arith[party].clone(), bin[party].clone(), t).unwrap());
        }
    }
    per_party
}

/// Full-range edaBits, indexed `[party][index]`.
///
/// `r` is rejection-sampled below `p`, which is precisely the post-condition the modulus-overflow
/// filter establishes: at full width `sum 2^i b_i` equals the integer `r` only when `r < p`, and
/// with `r >= p` the adder's "at most one subtraction of `p`" argument fails outright.
pub fn deal_edabits(
    n_parties: usize,
    t: usize,
    count: usize,
    rng: &mut StdRng,
) -> Vec<Vec<EdaBit<F, K>>> {
    let width = field_bit_width::<F>();
    let mut per_party: Vec<Vec<EdaBit<F, K>>> = vec![Vec::new(); n_parties];
    for _ in 0..count {
        let r = loop {
            let candidate: u64 = rng.gen();
            if candidate < P {
                break candidate;
            }
        };
        let bits = canonical_bits::<F>(F::from(r), width).unwrap();
        let mut per_party_dabits: Vec<Vec<DaBit<F, K>>> = vec![Vec::new(); n_parties];
        for bit in bits {
            let arith =
                RobustShare::compute_shares(F::from(bit as u64), n_parties, t, None, rng).unwrap();
            let bin = GfShare::compute_shares(bit_to_binary::<K>(bit), n_parties, t, rng).unwrap();
            for party in 0..n_parties {
                per_party_dabits[party]
                    .push(DaBit::new(arith[party].clone(), bin[party].clone(), t).unwrap());
            }
        }
        for party in 0..n_parties {
            // `false`: the filter accepted this `r`, which is what the rejection sampling above
            // simulates. `compose_full_width` cannot be called without that opened bit.
            per_party[party]
                .push(EdaBit::compose_full_width(&per_party_dabits[party], false).unwrap());
        }
    }
    per_party
}

/// Degree-`t` GF(2^k) Beaver triples, indexed `[party][index]`.
pub fn deal_gf_triples(
    n_parties: usize,
    t: usize,
    count: usize,
    rng: &mut StdRng,
) -> Vec<Vec<GfBeaverTriple<K>>> {
    let mut per_party: Vec<Vec<GfBeaverTriple<K>>> = vec![Vec::new(); n_parties];
    for _ in 0..count {
        let a = K::random(rng);
        let b = K::random(rng);
        let a_shares = GfShare::compute_shares(a, n_parties, t, rng).unwrap();
        let b_shares = GfShare::compute_shares(b, n_parties, t, rng).unwrap();
        let c_shares = GfShare::compute_shares(a * b, n_parties, t, rng).unwrap();
        for party in 0..n_parties {
            per_party[party].push(GfBeaverTriple::new(
                a_shares[party].clone(),
                b_shares[party].clone(),
                c_shares[party].clone(),
            ));
        }
    }
    per_party
}

/// Reconstructs one bit column from a **quorum** of `2t + 1` shares and returns it as a `bool`.
///
/// Deliberately not every share: the openings A2B performs are degree `t`, where this repo's
/// robust reconstruction genuinely decodes from `2t + 1` of `n`. Passing all `n` would hide a
/// regression that made the output depend on a particular party.
pub fn recover_bit(shares: &[GfShare<K>], n_parties: usize, t: usize) -> bool {
    let (_, value) = GfShare::recover_secret(&shares[0..=2 * t], n_parties, t).unwrap();
    if value == K::one() {
        true
    } else {
        assert_eq!(value, K::zero(), "reconstructed binary share is not a bit");
        false
    }
}

/// Reconstructs an arithmetic value from a quorum of `2t + 1` shares.
pub fn recover_field(shares: &[RobustShare<F>], n_parties: usize, t: usize) -> F {
    let (_, value) = RobustShare::recover_secret(&shares[0..=2 * t], n_parties, t).unwrap();
    value
}

/// The canonical little-endian bit decomposition A2B is specified to return.
pub fn expected_bits(value: F) -> Vec<bool> {
    canonical_bits::<F>(value, field_bit_width::<F>()).unwrap()
}

/// `sum_i 2^i bits[i]` as a `u128`, so an overshoot past `2^64` is visible rather than wrapped.
pub fn recompose_u128(bits: &[bool]) -> u128 {
    bits.iter()
        .enumerate()
        .filter(|(_, set)| **set)
        .map(|(i, _)| 1u128 << i)
        .sum()
}

/// Full-range edaBits for **chosen** masks, indexed `[party][index]`.
///
/// [`deal_edabits`] samples `r` the way the generator does, which exercises whichever branch of
/// the conditional reduction the sample happens to land on. This one lets a test pin a branch:
/// with `y = (x - r) mod p` and `s = y + r` over the integers, `x >= r` gives `s = x` and no
/// reduction, while `x < r` gives `s = x + p`, whose carry out of bit 63 is set exactly when
/// `x >= 2^64 - p = 2^32 - 1`.
///
/// Panics if any `r >= p`, which is the post-condition the modulus-overflow filter establishes and
/// which a caller of this helper is standing in for.
pub fn deal_edabits_from(
    n_parties: usize,
    t: usize,
    masks: &[u64],
    rng: &mut StdRng,
) -> Vec<Vec<EdaBit<F, K>>> {
    let width = field_bit_width::<F>();
    let mut per_party: Vec<Vec<EdaBit<F, K>>> = vec![Vec::new(); n_parties];
    for r in masks {
        assert!(*r < P, "an edabit mask must be below p");
        let bits = canonical_bits::<F>(F::from(*r), width).unwrap();
        let mut per_party_dabits: Vec<Vec<DaBit<F, K>>> = vec![Vec::new(); n_parties];
        for bit in bits {
            let arith =
                RobustShare::compute_shares(F::from(bit as u64), n_parties, t, None, rng).unwrap();
            let bin = GfShare::compute_shares(bit_to_binary::<K>(bit), n_parties, t, rng).unwrap();
            for party in 0..n_parties {
                per_party_dabits[party]
                    .push(DaBit::new(arith[party].clone(), bin[party].clone(), t).unwrap());
            }
        }
        for party in 0..n_parties {
            per_party[party]
                .push(EdaBit::compose_full_width(&per_party_dabits[party], false).unwrap());
        }
    }
    per_party
}
