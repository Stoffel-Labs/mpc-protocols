//! `gf_prss` — CDI05 pseudorandom secret sharing over a binary field, through the crate's public
//! API, across **every** concrete `BinaryField` the crate instantiates.
//!
//! # Phase: PREPROCESSING, and purely local
//!
//! There is no message, no round, no timeout, no broadcast and no abort anywhere in this module:
//! a `GfPrssKeys` turns key material into degree-`t` `GF(2^k)` shares with zero communication, so
//! it cannot smuggle anything onto the asynchronous robust online path. Its *outputs* are
//! preprocessing material — the `K` half of a PRSS daBit, and the `Gf2k` random sharing behind a
//! DN07 double sharing — and the phase discipline attaches to their consumers.
//!
//! # What these tests add over the in-module unit tests
//!
//! `gf_prss.rs` carries a `#[cfg(test)]` suite that runs almost entirely over `Gf256` at
//! `n <= 10`. This file is aimed at the two things that suite cannot reach from the inside:
//!
//! 1. **Every concrete field, and both of its ceilings.** `Gf2p4`, `Gf256`, `Gf2p8` and `Gf2p16`
//!    each have their own party ceiling `|K*| = 2^k - 1` and their own element width `k`. Both are
//!    exercised *at* the boundary, *one past* it, and — for the ceiling that actually binds in
//!    practice — from the `C(n,t)` side, which bites long before the field runs out of points.
//!    `Gf256` and `Gf2p8` are two unrelated instantiations of `GF(2^8)` (different moduli), and
//!    confusing them is a live T1 domain hazard, so both are covered rather than one.
//! 2. **Reconstruction is checked against an independent recomputation.** The expected secret is
//!    rebuilt here from the dealt keys and a *reimplementation* of the documented generator-basis
//!    embedding, so a change to the embedding shows up as a mismatch rather than as two copies of
//!    the same mistake agreeing.
//!
//! Plus one adversarial case the unit suite has no vehicle for: degree-`t` reconstruction of a
//! PRSS sharing under `t` corrupt shares, which is what "these shares get opened robustly" means.
//!
//! Helpers are local to this file rather than in `tests/utils/`: `gf_prss` needs no network, and
//! `tests/utils/mod.rs` is shared with every other integration test.

use ark_std::rand::{rngs::StdRng, RngCore, SeedableRng};
use num_bigint::BigUint;
use stoffelcrypto::common::gf2k::{
    field::{BinaryField, Gf256},
    generic_field::{Gf2p16, Gf2p4, Gf2p8},
    share::GfShare,
};
use stoffelcrypto::common::ProtocolSessionId;
use stoffelcrypto::honeybadger::gf_prss::{
    gf_prss::{extension_degree, max_parties, GfPrssKeys},
    GfPrssError, MAX_UNQUALIFIED_SETS,
};
use stoffelcrypto::honeybadger::prss::{
    prss::{all_tsets, derive_ints_at, held_ranks},
    PRSS_KEY_LEN,
};
use stoffelcrypto::honeybadger::{ProtocolType, SessionId};

/// A PRSS `SessionId`.
///
/// `gf_prss` sends nothing, so this is not a routing key — it is a PRF domain separator whose only
/// contract is that a position is never derived twice under the same one. `GfRansha` is the tag
/// whose semantics fit (a random `GF(2^k)` sharing).
fn sid(exec: u64) -> SessionId {
    SessionId::new(
        ProtocolType::GfRansha,
        SessionId::pack_slot(exec, 0, 0),
        111,
    )
}

/// One key per maximal unqualified set, indexed by rank — what the one-time setup produces before
/// it is split per party. Held centrally here so the tests can recompute the expected secret and
/// model an adversary that knows every key but one.
fn key_family(n: usize, t: usize, seed: u64) -> Vec<[u8; PRSS_KEY_LEN]> {
    let mut rng = StdRng::seed_from_u64(seed);
    (0..all_tsets(n, t).len())
        .map(|_| {
            let mut k = [0u8; PRSS_KEY_LEN];
            rng.fill_bytes(&mut k);
            k
        })
        .collect()
}

fn party_keys(
    n: usize,
    t: usize,
    id: usize,
    family: &[[u8; PRSS_KEY_LEN]],
) -> Vec<(usize, [u8; PRSS_KEY_LEN])> {
    held_ranks(n, t, id)
        .into_iter()
        .map(|rank| (rank, family[rank]))
        .collect()
}

fn build_all<K: BinaryField>(
    n: usize,
    t: usize,
    family: &[[u8; PRSS_KEY_LEN]],
) -> Vec<GfPrssKeys<K>> {
    (0..n)
        .map(|id| GfPrssKeys::<K>::new(id, n, t, &party_keys(n, t, id, family)).unwrap())
        .collect()
}

/// The documented embedding contract, reimplemented from the doc comment rather than imported:
/// the low `bits` derived bits are coordinates along `{1, g, g^2, ...}`, `g = K::generator()`.
///
/// A primitive `g` lies in no proper subfield, so its powers `g^0..g^(k-1)` are a `GF(2)`-basis of
/// `K` and the map is injective on `[0, 2^bits)`. At `bits = 1` its image is `{0, 1}`, exactly the
/// elements `BinaryField::is_bit` accepts.
fn embed_bits<K: BinaryField>(value: &BigUint, bits: usize) -> K {
    let mut acc = K::zero();
    let mut basis = K::one();
    for j in 0..bits {
        if value.bit(j as u64) {
            acc = acc + basis;
        }
        basis = basis * K::generator();
    }
    acc
}

/// The secret a full set of shares must reconstruct to, recomputed straight from the dealt keys:
/// the **XOR** over all `C(n,t)` sets. In characteristic 2 the replicated-to-Shamir sum *is* an
/// XOR, which is what lets a `bits`-wide draw reconstruct to a `bits`-wide secret with no `C(n,t)`
/// multiplicity to budget for — and what ties the two halves of a daBit.
fn expected_secrets<K: BinaryField>(
    family: &[[u8; PRSS_KEY_LEN]],
    session_id: SessionId,
    start: usize,
    count: usize,
    bits: usize,
) -> Vec<K> {
    let mut out = vec![K::zero(); count];
    for key in family {
        let values = derive_ints_at(key, session_id, start, count, bits);
        for (acc, v) in out.iter_mut().zip(&values) {
            *acc = *acc + embed_bits::<K>(v, bits);
        }
    }
    out
}

/// Reconstruct every position of a batch and check it against the independent recomputation.
fn check_reconstruction<K: BinaryField>(n: usize, t: usize, bits: usize, count: usize, exec: u64) {
    let family = key_family(n, t, 7);
    let keys = build_all::<K>(n, t, &family);
    let expected = expected_secrets::<K>(&family, sid(exec), 0, count, bits);

    let per_party: Vec<Vec<GfShare<K>>> = keys
        .iter()
        .map(|k| k.shares_at(sid(exec), 0, count, bits).unwrap())
        .collect();

    for nu in 0..count {
        let shares: Vec<GfShare<K>> = (0..n).map(|id| per_party[id][nu].clone()).collect();
        assert!(
            shares.iter().all(|s| s.degree == t),
            "n={n} t={t}: a share was not labelled degree t"
        );
        assert!(shares.iter().enumerate().all(|(i, s)| s.id == i));

        let (coeffs, secret) = GfShare::recover_secret(&shares, n, t)
            .expect("degree-t reconstruction from all n honest shares");
        assert!(
            coeffs.len() <= t + 1,
            "n={n} t={t}: {} coefficients, expected at most {}",
            coeffs.len(),
            t + 1
        );
        assert_eq!(coeffs[0], secret);
        assert_eq!(
            secret, expected[nu],
            "n={n} t={t} bits={bits}: secret {nu} is not the XOR over all sets"
        );
    }
}

/// Reconstruction over each concrete `BinaryField`, at the full element width and at a narrower
/// one, against the independent recomputation.
///
/// `Gf2p4`'s width ceiling is 4, so `bits = 8` is not available there — the narrow field is the
/// one that catches an embedding that silently assumes a byte.
#[test]
fn shares_reconstruct_as_a_degree_t_sharing_over_every_concrete_field() {
    for (n, t) in [(4usize, 1usize), (7, 2), (10, 3)] {
        check_reconstruction::<Gf2p4>(n, t, 4, 4, 3);
        check_reconstruction::<Gf2p4>(n, t, 1, 4, 3);
        check_reconstruction::<Gf256>(n, t, 8, 4, 3);
        check_reconstruction::<Gf256>(n, t, 3, 4, 3);
        check_reconstruction::<Gf2p8>(n, t, 8, 4, 3);
        check_reconstruction::<Gf2p16>(n, t, 16, 4, 3);
        check_reconstruction::<Gf2p16>(n, t, 8, 4, 3);
    }
}

/// The `K` half of a PRSS daBit. The secret is `XOR_T beta_T`, which is in `{0,1}` **by
/// construction**: there is no dealt value anywhere on this path, so `is_bit` holds with no
/// certification protocol behind it. That is the T3 (value) obligation discharged at zero cost,
/// and any variant that reintroduces a dealt bit has to add a bit-ness check back.
#[test]
fn the_binary_half_of_a_dabit_is_a_bit_by_construction() {
    for (n, t) in [(4usize, 1usize), (7, 2)] {
        let family = key_family(n, t, 11);
        let count = 64;

        // Over three fields at once: the bit-ness is a property of the construction, not of
        // `Gf256`'s hand-written arithmetic.
        let narrow = build_all::<Gf2p4>(n, t, &family);
        let byte = build_all::<Gf256>(n, t, &family);
        let wide = build_all::<Gf2p16>(n, t, &family);

        let expected_narrow = expected_secrets::<Gf2p4>(&family, sid(12), 0, count, 1);
        let expected_byte = expected_secrets::<Gf256>(&family, sid(12), 0, count, 1);
        let expected_wide = expected_secrets::<Gf2p16>(&family, sid(12), 0, count, 1);

        let n_shares = |keys: &[GfPrssKeys<Gf256>], nu: usize| -> Vec<GfShare<Gf256>> {
            (0..n)
                .map(|id| keys[id].bit_shares_at(sid(12), 0, count).unwrap()[nu].clone())
                .collect()
        };

        let mut zeros = 0usize;
        let mut ones = 0usize;
        for nu in 0..count {
            let shares = n_shares(&byte, nu);
            let (_, secret) = GfShare::recover_secret(&shares, n, t).unwrap();
            assert!(
                secret.is_bit(),
                "n={n} t={t}: bit {nu} was not a bit: {secret:?}"
            );
            assert_eq!(secret, expected_byte[nu]);
            if secret.is_zero() {
                zeros += 1;
            } else {
                ones += 1;
            }

            // The *same* keys and the *same* position must give the *same* bit in every field:
            // the bit is a property of the keystream, not of the embedding.
            let narrow_shares: Vec<GfShare<Gf2p4>> = (0..n)
                .map(|id| narrow[id].bit_shares_at(sid(12), 0, count).unwrap()[nu].clone())
                .collect();
            let wide_shares: Vec<GfShare<Gf2p16>> = (0..n)
                .map(|id| wide[id].bit_shares_at(sid(12), 0, count).unwrap()[nu].clone())
                .collect();
            let (_, narrow_secret) = GfShare::recover_secret(&narrow_shares, n, t).unwrap();
            let (_, wide_secret) = GfShare::recover_secret(&wide_shares, n, t).unwrap();
            assert!(narrow_secret.is_bit() && wide_secret.is_bit());
            assert_eq!(narrow_secret, expected_narrow[nu]);
            assert_eq!(wide_secret, expected_wide[nu]);
            assert_eq!(
                narrow_secret == Gf2p4::one(),
                secret == Gf256::one(),
                "n={n} t={t}: position {nu} gave different bits in Gf2p4 and Gf256"
            );
            assert_eq!(
                wide_secret == Gf2p16::one(),
                secret == Gf256::one(),
                "n={n} t={t}: position {nu} gave different bits in Gf2p16 and Gf256"
            );
        }
        assert!(
            zeros > 0 && ones > 0,
            "n={n} t={t}: the bits were constant ({zeros} zero / {ones} one)"
        );
    }
}

/// Each concrete field's two published constants: the party ceiling `|K*| = 2^k - 1` and the
/// element width `k`. These are what every other bound in the module is derived from, so they are
/// pinned per field rather than computed.
#[test]
fn each_concrete_field_reports_its_own_ceilings() {
    assert_eq!(max_parties::<Gf2p4>(), 15);
    assert_eq!(max_parties::<Gf256>(), 255);
    assert_eq!(max_parties::<Gf2p8>(), 255);
    assert_eq!(max_parties::<Gf2p16>(), 65_535);

    assert_eq!(extension_degree::<Gf2p4>().unwrap(), 4);
    assert_eq!(extension_degree::<Gf256>().unwrap(), 8);
    assert_eq!(extension_degree::<Gf2p8>().unwrap(), 8);
    assert_eq!(extension_degree::<Gf2p16>().unwrap(), 16);

    // `MAX_DOMAIN_SIZE = 2^k - 1` for every one of them — the relation `extension_degree` inverts.
    for (points, degree) in [(15usize, 4u32), (255, 8), (65_535, 16)] {
        assert_eq!(points, (1usize << degree) - 1);
    }
}

/// The field ceiling is exactly `|K*|`, not one less and not one more.
///
/// `Gf2p4` is the field where the boundary is reachable in a test: 15 parties is the largest
/// domain it has, and the whole batch is reconstructed there rather than merely constructed.
/// `Gf256` is taken to its own boundary on the construction side (255 parties, 254 keys held),
/// which is as far as the `C(n-1,t)` PRF-stream cost allows a test to go.
#[test]
fn gf_prss_works_at_the_exact_field_ceiling() {
    // Gf2p4, 15 parties — the full field, reconstructed.
    let (n, t) = (15usize, 1usize);
    assert_eq!(n, max_parties::<Gf2p4>());
    check_reconstruction::<Gf2p4>(n, t, 4, 3, 21);

    // Gf256, 255 parties. Every party holds C(254,1) = 254 keys.
    let (n, t) = (255usize, 1usize);
    assert_eq!(n, max_parties::<Gf256>());
    let family = key_family(n, t, 31);
    let keys = GfPrssKeys::<Gf256>::new(0, n, t, &party_keys(n, t, 0, &family))
        .expect("255 parties is exactly the Gf256 ceiling");
    assert_eq!(keys.len(), 254);
    assert_eq!(keys.shares_at(sid(22), 0, 2, 8).unwrap().len(), 2);
}

/// One party past each field's ceiling must be a typed error naming that field's own maximum —
/// never a panic out of the domain builder, and never a silent wrap onto a reused evaluation
/// point (which would hand two parties the same share).
#[test]
fn rejects_a_party_count_one_past_each_field_ceiling() {
    // The key store is never reached: `new` checks the field ceiling before it counts keys, which
    // is what makes the check affordable at `n = 65536`.
    assert!(matches!(
        GfPrssKeys::<Gf2p4>::new(0, 16, 1, &[]),
        Err(GfPrssError::PartyCountExceedsField { n: 16, max: 15 })
    ));
    assert!(matches!(
        GfPrssKeys::<Gf256>::new(0, 256, 1, &[]),
        Err(GfPrssError::PartyCountExceedsField { n: 256, max: 255 })
    ));
    assert!(matches!(
        GfPrssKeys::<Gf2p8>::new(0, 256, 1, &[]),
        Err(GfPrssError::PartyCountExceedsField { n: 256, max: 255 })
    ));
    assert!(matches!(
        GfPrssKeys::<Gf2p16>::new(0, 65_536, 1, &[]),
        Err(GfPrssError::PartyCountExceedsField {
            n: 65_536,
            max: 65_535
        })
    ));

    // And the same `(n, t)` that a narrow field rejects is accepted by a wider one — the ceiling
    // is the field's, not the protocol's.
    let family = key_family(16, 1, 41);
    assert!(matches!(
        GfPrssKeys::<Gf2p4>::new(0, 16, 1, &party_keys(16, 1, 0, &family)),
        Err(GfPrssError::PartyCountExceedsField { .. })
    ));
    assert!(GfPrssKeys::<Gf256>::new(0, 16, 1, &party_keys(16, 1, 0, &family)).is_ok());

    // At exactly the ceiling the field check passes and the next check is reached instead, which
    // is how we know the boundary is `n = |K*|` and not `n < |K*|`.
    assert!(matches!(
        GfPrssKeys::<Gf2p16>::new(0, 65_535, 1, &[]),
        Err(GfPrssError::KeyCountMismatch { .. })
    ));
}

/// The ceiling that actually binds: `C(n,t)` sets to enumerate and `C(n-1,t)` PRF streams to spend
/// per call. It is reached at party counts far below any field's domain size — 3003 streams per
/// party at `n = 16`, 18 564 at `n = 19` — so the field ceiling is the *lesser* constraint in
/// every deployment, and it is the set count that must fail typed rather than out of memory.
#[test]
fn the_unqualified_set_ceiling_bites_long_before_the_field_ceiling() {
    // n = 40 is comfortably inside Gf256's 255 points, but C(40,20) is ~1.4e11.
    assert!(matches!(
        GfPrssKeys::<Gf256>::new(0, 40, 20, &[]),
        Err(GfPrssError::TooManyUnqualifiedSets { n: 40, t: 20, .. })
    ));
    // And inside Gf2p16's 65 535.
    assert!(matches!(
        GfPrssKeys::<Gf2p16>::new(0, 60, 20, &[]),
        Err(GfPrssError::TooManyUnqualifiedSets { .. })
    ));
    assert_eq!(MAX_UNQUALIFIED_SETS, 65_536);

    // Just inside the cap: C(16,5) = 4368 sets, 3003 keys held. Accepted — the cap rejects only
    // what the PRF-stream cost has already made infeasible.
    let (n, t) = (16usize, 5usize);
    let family = key_family(n, t, 51);
    let keys = GfPrssKeys::<Gf256>::new(0, n, t, &party_keys(n, t, 0, &family)).unwrap();
    assert_eq!(keys.len(), 3003);

    // t >= n has no maximal unqualified set at all.
    assert!(matches!(
        GfPrssKeys::<Gf256>::new(0, 4, 4, &[]),
        Err(GfPrssError::ThresholdOutOfRange { n: 4, t: 4 })
    ));
    assert!(matches!(
        GfPrssKeys::<Gf256>::new(4, 4, 1, &[]),
        Err(GfPrssError::PartyOutOfRange { id: 4, n: 4 })
    ));
}

/// A draw wider than the field cannot be embedded injectively, so its "uniformity" would be a
/// fiction and it is rejected per field. `uniform_shares_at` is the same call at exactly `k`.
#[test]
fn a_draw_wider_than_the_field_is_rejected() {
    let (n, t) = (4usize, 1usize);
    let family = key_family(n, t, 61);

    let narrow = build_all::<Gf2p4>(n, t, &family);
    assert!(matches!(
        narrow[0].shares_at(sid(1), 0, 1, 5),
        Err(GfPrssError::WidthExceedsField { bits: 5, degree: 4 })
    ));
    assert!(narrow[0].shares_at(sid(1), 0, 1, 4).is_ok());

    let byte = build_all::<Gf256>(n, t, &family);
    assert!(matches!(
        byte[0].shares_at(sid(1), 0, 1, 9),
        Err(GfPrssError::WidthExceedsField { bits: 9, degree: 8 })
    ));
    assert!(matches!(
        byte[0].shares_at(sid(1), 0, 1, 0),
        Err(GfPrssError::WidthExceedsField { bits: 0, degree: 8 })
    ));

    let wide = build_all::<Gf2p16>(n, t, &family);
    assert!(matches!(
        wide[0].shares_at(sid(1), 0, 1, 17),
        Err(GfPrssError::WidthExceedsField {
            bits: 17,
            degree: 16
        })
    ));
    assert!(wide[0].shares_at(sid(1), 0, 1, 16).is_ok());

    // `uniform_shares_at` is exactly `shares_at` at the field's own width.
    for exec in [71u64, 72] {
        assert_eq!(
            narrow[0].uniform_shares_at(sid(exec), 0, 4).unwrap(),
            narrow[0].shares_at(sid(exec), 0, 4, 4).unwrap()
        );
        assert_eq!(
            wide[0].uniform_shares_at(sid(exec), 0, 4).unwrap(),
            wide[0].shares_at(sid(exec), 0, 4, 16).unwrap()
        );
    }
}

/// A uniform draw must cover the field it claims to be uniform over.
///
/// Exhaustive on `Gf2p4` (16 elements, every one of them must appear) and by coverage on
/// `Gf2p16`, where a draw confined to a subfield — `GF(2^8)` sits inside `GF(2^16)` — would still
/// look random to a glance while carrying half the entropy.
#[test]
fn uniform_draws_cover_the_field_they_claim() {
    let (n, t) = (4usize, 1usize);

    let family = key_family(n, t, 81);
    let secrets = expected_secrets::<Gf2p4>(&family, sid(31), 0, 4096, 4);
    let mut seen = std::collections::HashSet::new();
    for s in &secrets {
        seen.insert(format!("{s:?}"));
    }
    assert_eq!(
        seen.len(),
        16,
        "a Gf2p4 uniform draw covered {} of 16 elements",
        seen.len()
    );

    let wide = expected_secrets::<Gf2p16>(&family, sid(32), 0, 16_384, 16);
    let distinct: std::collections::HashSet<String> =
        wide.iter().map(|s| format!("{s:?}")).collect();
    // 16 384 draws from 65 536 values collide by the birthday bound; ~14 700 distinct is the
    // expectation, and anything an order of magnitude below it means a collapsed subspace.
    assert!(
        distinct.len() > 12_000,
        "a Gf2p16 uniform draw produced only {} distinct values in 16384",
        distinct.len()
    );
}

/// What "these shares get opened" means in the presence of an adversary: a degree-`t` `Gf2k`
/// sharing at `n = 3t+1` is a `[3t+1, t+1]` Reed-Solomon code with minimum distance `2t+1`, so
/// online error correction recovers the secret through `t` wrong shares.
///
/// The corrupt parties here are the **low-indexed** ones. `recover_secret` tries an optimistic
/// interpolation through the first `degree + t + 1` shares by id before falling back to OEC, so
/// corrupting the high-indexed parties would let that optimistic path succeed on an all-honest
/// prefix and the test would pass without ever exercising the correction.
#[test]
fn reconstruction_survives_t_corrupt_shares() {
    for (n, t) in [(4usize, 1usize), (7, 2), (10, 3)] {
        let family = key_family(n, t, 91);
        let keys = build_all::<Gf256>(n, t, &family);
        let expected = expected_secrets::<Gf256>(&family, sid(41), 0, 4, 8);

        for nu in 0..4 {
            let mut shares: Vec<GfShare<Gf256>> = (0..n)
                .map(|id| keys[id].shares_at(sid(41), 0, 4, 8).unwrap()[nu].clone())
                .collect();
            for corrupt in shares.iter_mut().take(t) {
                corrupt.share = corrupt.share + Gf256(0x1f);
            }
            let (_, secret) = GfShare::recover_secret(&shares, n, t)
                .expect("OEC corrects t errors in a degree-t sharing at n = 3t+1");
            assert_eq!(
                secret, expected[nu],
                "n={n} t={t}: {t} corrupt shares changed the reconstructed value"
            );

            // One past the correction radius the guarantee stops, and it must stop *visibly*:
            // either the decode fails or it lands somewhere else, never silently on the right
            // answer. Without this the test above would still pass if correction were a no-op
            // and the corruption were being dropped on the floor somewhere.
            shares[t].share = shares[t].share + Gf256(0x1f);
            match GfShare::recover_secret(&shares, n, t) {
                Err(_) => {}
                Ok((_, wrong)) => assert_ne!(
                    wrong,
                    expected[nu],
                    "n={n} t={t}: {} corrupt shares were corrected, which is past the radius",
                    t + 1
                ),
            }
        }
    }
}

/// The structure that makes PRSS private: the adversary `A` holds `k_T` for every `T != A` — since
/// `|A| = |T| = t`, `A` is contained in `T` only when `T = A` — so its residual uncertainty in
/// every PRSS object is exactly one PRF output.
///
/// Measured by re-dealing with **only** set `A`'s key changed: every party outside `A` sees a
/// different share, and every party inside `A` sees the identical share, because `f^K_A` vanishes
/// on `A`. That is why the members of `A` cannot subtract their own set's contribution out of an
/// opening — and why a daBit drawn twice from one position is a break: `beta_A` cancels in the
/// difference and the XOR of the two secrets falls out.
#[test]
fn a_set_s_own_key_is_invisible_to_that_set_s_members() {
    for (n, t) in [(7usize, 2usize), (10, 3)] {
        let tsets = all_tsets(n, t);
        let a_rank = 0usize;
        let a_set = &tsets[a_rank];

        let family = key_family(n, t, 101);
        let mut flipped = family.clone();
        flipped[a_rank][0] ^= 0xff;

        let before = build_all::<Gf256>(n, t, &family);
        let after = build_all::<Gf256>(n, t, &flipped);

        for id in 0..n {
            let lhs = before[id].shares_at(sid(51), 0, 8, 8).unwrap();
            let rhs = after[id].shares_at(sid(51), 0, 8, 8).unwrap();
            if a_set.contains(&id) {
                assert_eq!(
                    lhs, rhs,
                    "n={n} t={t}: A-member {id}'s share moved when A's own key changed"
                );
            } else {
                assert_ne!(
                    lhs, rhs,
                    "n={n} t={t}: non-member {id}'s share did not move when A's key changed"
                );
            }
        }
    }
}

/// Position-addressing across a *partial* pool, and session separation, at the share level and on
/// a field other than `Gf256`.
///
/// A cursor that rewinds is a security failure rather than a performance one: re-deriving an
/// already-opened position hands the adversary the value in advance (the VERIA-222 class). This
/// module is stateless and position-addressed, so the cursor lives in the caller — what it owes
/// the caller is that position `nu` means the same thing however the range was cut.
#[test]
fn position_addressing_is_stable_and_sessions_do_not_collide() {
    let (n, t) = (7usize, 2usize);
    let family = key_family(n, t, 111);
    let keys = build_all::<Gf2p16>(n, t, &family);

    for k in &keys {
        let whole = k.shares_at(sid(61), 0, 6, 16).unwrap();
        let head = k.shares_at(sid(61), 0, 2, 16).unwrap();
        let tail = k.shares_at(sid(61), 2, 4, 16).unwrap();
        assert_eq!([head, tail].concat(), whole);

        let other = k.shares_at(sid(62), 0, 6, 16).unwrap();
        assert_ne!(other, whole, "two sessions produced one sharing");
    }

    // Every holder of a rank derives the same per-set values — the property PRSS removes the
    // network's ability to police.
    let mut reference: std::collections::HashMap<usize, Vec<BigUint>> =
        std::collections::HashMap::new();
    for k in &keys {
        for (rank, values) in k.derive_set_values(sid(61), 0, 8, 16) {
            match reference.get(&rank) {
                Some(prev) => assert_eq!(*prev, values, "rank {rank} diverged between holders"),
                None => {
                    reference.insert(rank, values);
                }
            }
        }
    }
    assert_eq!(reference.len(), all_tsets(n, t).len());
}
