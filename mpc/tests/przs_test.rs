//! PRZS — degree-`2t` pseudorandom sharings of zero — over the **production** arithmetic field
//! and over `Gf256`, exercised through the crate's public API.
//!
//! # Phase: PREPROCESSING ONLY (synchronous, abort permitted)
//!
//! Nothing in this file is an online-path object. PRZS derivation itself is local — no message,
//! no round, no timeout, no broadcast, no abort — but every sharing it produces is degree `2t`,
//! and a degree-`2t` opening is legal only in preprocessing: at `n = 3t+1` the degree-`2t`
//! evaluation code is `[3t+1, 2t+1]` with unique-decoding radius `⌊t/2⌋ < t`, so an asynchronous
//! party waiting for only `2t+1` honest shares cannot decode robustly. The online A2B/B2A path
//! opens at degree `t` and must stay that way. The masks measured here are the ones that ride
//! `MulPub`, the DN07 degree reduction and the degree-`2t` exact-zero checks.
//!
//! # What these tests add over the in-module unit tests
//!
//! `przs.rs` and `gf_przs.rs` both carry `#[cfg(test)]` suites, and those run over
//! `ark_bls12_381::Fr`. This file is deliberately different in four ways:
//!
//! 1. **The production field.** Every arithmetic test here runs over `GoldilocksField`, which is
//!    what the crate actually deploys: a 64-bit modulus rather than a 255-bit one, a different
//!    FFT domain, and a `MODULUS_BIT_SIZE + 128` PRF draw of a different width. A reduction or
//!    width bug that Bls12-381's headroom hides has nowhere to hide here.
//! 2. **Uniformity is measured, not assumed.** The unit suite establishes *structure* (degree,
//!    vanishing at zero, dimension); this file measures the *distribution* of what the PRF puts
//!    into each coefficient.
//! 3. **The single-coefficient PRZS is built and attacked.** Rather than only asserting that the
//!    real mask spans `t` dimensions, `a_single_coefficient_przs_leaves_a_distinguishing_functional`
//!    constructs the naive form *from the same PRF values*, and exhibits an explicit linear
//!    functional that reads a secret out of a masked opening with probability 1. That is §6.5
//!    error 1 made concrete: the naive form passes every other test in this file.
//! 4. **A real degree-`2t` product is masked and opened**, which is the DN07 / `MulPub` shape the
//!    mask exists for.
//!
//! Helpers are local to this file rather than in `tests/utils/`: PRZS needs no network, and
//! `tests/utils/mod.rs` is shared with every other integration test.

use ark_ff::{AdditiveGroup, Field, PrimeField};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_std::rand::{rngs::StdRng, RngCore, SeedableRng};
use stoffelcrypto::common::gf2k::{
    field::{BinaryField, Gf256},
    get_or_create_gf2k_domain,
    share::GfShare,
};
use stoffelcrypto::common::math::goldilocks::GoldilocksField;
use stoffelcrypto::common::{lagrange_interpolate, ProtocolSessionId, SecretSharingScheme};
use stoffelcrypto::honeybadger::prss::{
    prss::{all_tsets, derive_ints_at, held_ranks},
    PRSS_KEY_LEN,
};
use stoffelcrypto::honeybadger::przs::{
    derive_zero_coeff_ints_at, gf_przs::GfPrzsKeys, przs::PrzsKeys, PrzsDomain, PrzsError,
    ZeroCoeffs,
};
use stoffelcrypto::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelcrypto::honeybadger::{ProtocolType, SessionId};

type F = GoldilocksField;

/// `n = 3t+1` at `t = 1, 2, 3`.
///
/// `t = 1` is kept even though the `t`-coefficient and single-coefficient PRZS forms *coincide*
/// there — it is the configuration a careless suite would stop at, and the one that proves
/// nothing about the form. The dimension and attack tests skip it explicitly and say so.
const CONFIGS: [(usize, usize); 3] = [(4, 1), (7, 2), (10, 3)];

/// A PRZS `SessionId`.
///
/// PRZS sends nothing, so this is not a routing key — it is a PRF domain separator, and its only
/// contract is that a position is never derived twice under the same one. `ZeroSha` is the tag
/// whose semantics fit (a sharing of zero); the protocol owns no wire tag of its own.
fn sid(exec: u64) -> SessionId {
    SessionId::new(ProtocolType::ZeroSha, SessionId::pack_slot(exec, 0, 0), 111)
}

/// Deals one key per maximal unqualified set and hands each party the keys for the sets it is
/// *outside* of — what the one-time PRSS setup produces, reused verbatim by PRZS under its own
/// KDF label.
///
/// Dealing centrally is a total break of the privacy guarantee (the caller sees every key), which
/// is exactly what makes it the right test harness: the adversary in these tests is *supposed* to
/// know every key but one.
fn deal_keys(n: usize, t: usize, seed: u64) -> Vec<Vec<(usize, [u8; PRSS_KEY_LEN])>> {
    let mut rng = StdRng::seed_from_u64(seed);
    let all: Vec<[u8; PRSS_KEY_LEN]> = (0..all_tsets(n, t).len())
        .map(|_| {
            let mut k = [0u8; PRSS_KEY_LEN];
            rng.fill_bytes(&mut k);
            k
        })
        .collect();
    (0..n)
        .map(|id| {
            held_ranks(n, t, id)
                .into_iter()
                .map(|rank| (rank, all[rank]))
                .collect()
        })
        .collect()
}

fn build_f(n: usize, t: usize) -> Vec<PrzsKeys<F>> {
    let dealt = deal_keys(n, t, 7);
    (0..n)
        .map(|id| PrzsKeys::<F>::new(id, n, t, &dealt[id]).unwrap())
        .collect()
}

fn build_k(n: usize, t: usize) -> Vec<GfPrzsKeys<Gf256>> {
    let dealt = deal_keys(n, t, 7);
    (0..n)
        .map(|id| GfPrzsKeys::<Gf256>::new(id, n, t, &dealt[id]).unwrap())
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Linear algebra over either field.
//
// The dimension counts in this file *are* the security property, so they are measured by
// elimination rather than asserted from the construction. `Lin` exists only so the arithmetic and
// binary halves can share one implementation; its methods are prefixed to avoid colliding with
// `ark_ff`'s and `BinaryField`'s inherent `zero`/`one`.
// ---------------------------------------------------------------------------------------------

trait Lin: Copy + PartialEq + std::fmt::Debug {
    fn fzero() -> Self;
    fn fone() -> Self;
    fn fadd(self, other: Self) -> Self;
    fn fsub(self, other: Self) -> Self;
    fn fmul(self, other: Self) -> Self;
    fn finv(self) -> Option<Self>;
    fn fis_zero(self) -> bool {
        self == Self::fzero()
    }
}

impl Lin for F {
    fn fzero() -> Self {
        F::ZERO
    }
    fn fone() -> Self {
        F::ONE
    }
    fn fadd(self, other: Self) -> Self {
        self + other
    }
    fn fsub(self, other: Self) -> Self {
        self - other
    }
    fn fmul(self, other: Self) -> Self {
        self * other
    }
    fn finv(self) -> Option<Self> {
        Field::inverse(&self)
    }
}

impl Lin for Gf256 {
    fn fzero() -> Self {
        Gf256(0)
    }
    fn fone() -> Self {
        Gf256(1)
    }
    fn fadd(self, other: Self) -> Self {
        self + other
    }
    fn fsub(self, other: Self) -> Self {
        // Characteristic 2: subtraction *is* addition. Written out rather than elided so the
        // shared elimination code below is unambiguously correct over both fields.
        self + other
    }
    fn fmul(self, other: Self) -> Self {
        self * other
    }
    fn finv(self) -> Option<Self> {
        BinaryField::inverse(&self)
    }
}

/// Row-reduced echelon form, with zero rows dropped. Returns `(rows, pivot column of each row)`.
fn rref<T: Lin>(rows: &[Vec<T>]) -> (Vec<Vec<T>>, Vec<usize>) {
    let mut m: Vec<Vec<T>> = rows.to_vec();
    let cols = m.first().map(|r| r.len()).unwrap_or(0);
    let mut pivots = Vec::new();
    let mut r = 0usize;
    for c in 0..cols {
        let Some(p) = (r..m.len()).find(|&i| !m[i][c].fis_zero()) else {
            continue;
        };
        m.swap(r, p);
        let inv = m[r][c].finv().expect("nonzero entry is invertible");
        for v in m[r].iter_mut() {
            *v = v.fmul(inv);
        }
        for i in 0..m.len() {
            if i != r && !m[i][c].fis_zero() {
                let factor = m[i][c];
                for k in 0..cols {
                    let sub = m[r][k].fmul(factor);
                    m[i][k] = m[i][k].fsub(sub);
                }
            }
        }
        pivots.push(c);
        r += 1;
        if r == m.len() {
            break;
        }
    }
    m.truncate(r);
    (m, pivots)
}

fn rank<T: Lin>(rows: &[Vec<T>]) -> usize {
    rref(rows).0.len()
}

/// Is `v` in the row space of `rows`?
fn in_span<T: Lin>(rows: &[Vec<T>], v: &[T]) -> bool {
    let before = rank(rows);
    let mut with = rows.to_vec();
    with.push(v.to_vec());
    rank(&with) == before
}

/// A basis of `{ L : rows · L = 0 }`, i.e. of the row space's orthogonal complement under the
/// standard bilinear form. That form is non-degenerate on `T^n`, so such an `L` with `L·v != 0`
/// exists **iff** `v` is outside the row space — which is what makes the attack test's
/// distinguisher exist exactly when privacy fails.
fn null_space<T: Lin>(rows: &[Vec<T>]) -> Vec<Vec<T>> {
    let cols = rows.first().map(|r| r.len()).unwrap_or(0);
    let (reduced, pivots) = rref(rows);
    (0..cols)
        .filter(|c| !pivots.contains(c))
        .map(|free| {
            // `1` in the free coordinate, `-row[free]` in each pivot coordinate.
            let mut v = vec![T::fzero(); cols];
            v[free] = T::fone();
            for (i, &p) in pivots.iter().enumerate() {
                v[p] = T::fzero().fsub(reduced[i][free]);
            }
            v
        })
        .collect()
}

fn dot<T: Lin>(a: &[T], b: &[T]) -> T {
    a.iter()
        .zip(b.iter())
        .fold(T::fzero(), |acc, (x, y)| acc.fadd(x.fmul(*y)))
}

fn vec_add<T: Lin>(a: &[T], b: &[T]) -> Vec<T> {
    a.iter().zip(b.iter()).map(|(x, y)| x.fadd(*y)).collect()
}

fn vec_sub<T: Lin>(a: &[T], b: &[T]) -> Vec<T> {
    a.iter().zip(b.iter()).map(|(x, y)| x.fsub(*y)).collect()
}

// ---------------------------------------------------------------------------------------------
// Arithmetic side — GoldilocksField
// ---------------------------------------------------------------------------------------------

fn f_domain(n: usize) -> GeneralEvaluationDomain<F> {
    GeneralEvaluationDomain::<F>::new(n).unwrap()
}

/// The `n` parties' shares of sharing `nu`, as a plain vector indexed by party.
fn f_mask_vector(keys: &[PrzsKeys<F>], n: usize, session: SessionId, nu: usize) -> Vec<F> {
    (0..n)
        .map(|id| keys[id].zero_shares_at(session, nu, 1).unwrap()[0].share[0])
        .collect()
}

/// The polynomial `n` honest share values lie on, by plain interpolation through every point.
/// No error correction is wanted here: the question is what the shares *are*, not what they
/// would be corrected to.
fn f_sharing_polynomial(n: usize, values: &[F]) -> Vec<F> {
    let domain = f_domain(n);
    let xs: Vec<F> = (0..n).map(|id| domain.element(id)).collect();
    lagrange_interpolate(&xs, values).unwrap().coeffs
}

/// Degree read off the coefficient vector rather than through `DensePolynomial::degree`, which
/// panics on a trailing-zero leading coefficient — the exact case a collapsed mask produces.
fn deg<T: Lin>(coeffs: &[T]) -> usize {
    let mut d = coeffs.len().saturating_sub(1);
    while d > 0 && coeffs[d].fis_zero() {
        d -= 1;
    }
    d
}

#[test]
fn zero_sharings_reconstruct_to_zero_at_degree_2t_on_the_production_field() {
    for (n, t) in CONFIGS {
        let keys = build_f(n, t);
        let count = 4;
        let per_party: Vec<Vec<RobustShare<F>>> = keys
            .iter()
            .map(|k| k.zero_shares_at(sid(3), 0, count).unwrap())
            .collect();

        for nu in 0..count {
            let shares: Vec<RobustShare<F>> = (0..n).map(|id| per_party[id][nu].clone()).collect();
            assert!(
                shares.iter().all(|s| s.degree == 2 * t),
                "n={n} t={t}: a share was not labelled degree 2t"
            );
            assert!(shares.iter().enumerate().all(|(i, s)| s.id == i));

            let (coeffs, secret) = RobustShare::recover_secret(&shares, n, t)
                .expect("degree-2t reconstruction from all n honest shares");
            assert_eq!(secret, F::ZERO, "n={n} t={t}: sharing {nu} was not of zero");
            assert!(
                coeffs.len() <= 2 * t + 1,
                "n={n} t={t}: {} coefficients, expected at most {}",
                coeffs.len(),
                2 * t + 1
            );
            assert_eq!(
                coeffs.first().copied().unwrap_or(F::ZERO),
                F::ZERO,
                "n={n} t={t}: constant term was not zero"
            );
        }
    }
}

/// The other half of "degree `2t`": the sharing must **not** be a degree-`t` object wearing a
/// degree-`2t` label. A mask that collapsed to degree `t` would be a *legal* sharing of zero and
/// would pass the test above, while failing to cover the `t` extra coefficients a degree-`2t`
/// opening exposes — the same leak the single-coefficient form causes by a different route.
///
/// Two independent statements:
///
/// * the interpolant's degree is exactly `2t` (its top coefficient is live); and
/// * relabelling the shares `degree = t` and asking for a degree-`t` reconstruction either fails
///   or returns something nonzero. It can never return zero: a successful degree-`t` decode with
///   `<= t` errors would mean `2t+1` of the `n = 3t+1` points agree with some degree-`t` `g`, and
///   `h - g` would then have `2t+1` roots plus a root at 0, i.e. `2t+2 > deg(h - g)`, forcing
///   `h = g`. Note this also pins that `ShamirShare::degree` is dealer-written metadata (T2):
///   reconstruction believes the label, so the label is not evidence.
#[test]
fn a_przs_mask_is_not_a_degree_t_sharing_of_zero() {
    for (n, t) in CONFIGS {
        let keys = build_f(n, t);
        let count = 8;
        let mut saw_full_degree = false;

        for nu in 0..count {
            let values = f_mask_vector(&keys, n, sid(4), nu);
            let coeffs = f_sharing_polynomial(n, &values);
            assert_eq!(
                coeffs.first().copied().unwrap_or(F::ZERO),
                F::ZERO,
                "n={n} t={t}: sharing {nu} did not vanish at 0"
            );
            assert!(
                deg(&coeffs) <= 2 * t,
                "n={n} t={t}: sharing {nu} had degree {} > 2t",
                deg(&coeffs)
            );
            if deg(&coeffs) == 2 * t {
                saw_full_degree = true;
            }

            let relabelled: Vec<RobustShare<F>> = (0..n)
                .map(|id| RobustShare::new(values[id], id, t))
                .collect();
            match RobustShare::recover_secret(&relabelled, n, t) {
                Err(_) => {}
                Ok((_, secret)) => assert_ne!(
                    secret,
                    F::ZERO,
                    "n={n} t={t}: sharing {nu} decoded as a degree-t sharing of zero — the mask \
                     has collapsed below degree 2t"
                ),
            }
        }

        assert!(
            saw_full_degree,
            "n={n} t={t}: no sampled sharing reached degree 2t — the top coefficients are dead"
        );
    }
}

/// Uniformity of what a party actually holds.
///
/// One party's mask share is `h_nu(x_i)` for a fixed nonzero `x_i`, and `h_nu` ranges over the
/// full `2t`-dimensional space, so the share must be uniform on `F`. The keystream is
/// deterministic, so this is a fixed computation rather than a sampled one: it cannot flake, and
/// the bands only have to be tight enough to catch a degenerate draw (a stuck byte, a collapsed
/// subspace, a reduction that clamps the high bits).
#[test]
fn mask_shares_are_uniform_over_the_production_field() {
    let (n, t) = (4usize, 1usize);
    let keys = build_f(n, t);
    let count = 16_384usize;
    let shares = keys[1].zero_shares_at(sid(17), 0, count).unwrap();
    assert_eq!(shares.len(), count);

    // `BigInt<1>.0[0]` is the canonical (non-Montgomery) 64-bit representative.
    let raw: Vec<u64> = shares
        .iter()
        .map(|s| s.share[0].into_bigint().0[0])
        .collect();

    let mut high = [0usize; 256];
    let mut low = [0usize; 256];
    for v in &raw {
        high[(v >> 56) as usize] += 1;
        low[(v & 0xFF) as usize] += 1;
    }
    let expected = count / 256; // 64
    for (name, hist) in [("high byte", &high), ("low byte", &low)] {
        assert!(
            hist.iter().all(|c| *c > 0),
            "{name}: some bucket was never hit (min {:?})",
            hist.iter().min()
        );
        assert!(
            hist.iter()
                .all(|c| *c >= expected / 4 && *c <= expected * 4),
            "{name}: draw was far from uniform, min={:?} max={:?}, expected ~{expected}",
            hist.iter().min(),
            hist.iter().max()
        );
    }

    let distinct: std::collections::HashSet<u64> = raw.iter().copied().collect();
    assert_eq!(
        distinct.len(),
        count,
        "mask shares repeated within one session — positions are not independent"
    );
}

/// Uniformity at the level that matters for masking: the polynomial's coefficients.
///
/// A degree-`2t` opening reveals the *whole* polynomial, so what has to be uniform is each
/// coefficient `1..=2t` — and what has to be exactly, structurally zero is the constant term, for
/// every single sample rather than for most of them.
#[test]
fn every_mask_coefficient_above_the_constant_term_is_uniform() {
    let (n, t) = (7usize, 2usize);
    let keys = build_f(n, t);
    let count = 1024usize;

    let per_party: Vec<Vec<RobustShare<F>>> = keys
        .iter()
        .map(|k| k.zero_shares_at(sid(18), 0, count).unwrap())
        .collect();

    let mut buckets = vec![[0usize; 16]; 2 * t + 1];
    for nu in 0..count {
        let values: Vec<F> = (0..n).map(|id| per_party[id][nu].share[0]).collect();
        let coeffs = f_sharing_polynomial(n, &values);
        assert_eq!(
            coeffs.first().copied().unwrap_or(F::ZERO),
            F::ZERO,
            "sharing {nu}: constant term was not exactly zero"
        );
        for l in 1..=2 * t {
            let c = coeffs.get(l).copied().unwrap_or(F::ZERO);
            buckets[l][(c.into_bigint().0[0] >> 60) as usize] += 1;
        }
    }

    let expected = count / 16; // 64
    for l in 1..=2 * t {
        assert!(
            buckets[l]
                .iter()
                .all(|c| *c >= expected / 4 && *c <= expected * 4),
            "coefficient {l} was not uniform: {:?}",
            buckets[l]
        );
    }
}

/// The mask must cover the adversary's **entire** residual uncertainty, not merely some of it.
///
/// Fix the adversary `A` — itself a maximal unqualified set, and the only set whose key it does
/// not hold. Given the public constant term of an opened degree-`2t` polynomial and its own `t`
/// evaluations, its residual uncertainty is exactly
///
/// ```text
/// R = { h : deg h <= 2t, h(0) = 0, h|_A = 0 }        dimension t
/// ```
///
/// and privacy needs the reachable mask space to be all of `R`. `R`'s basis is built here from
/// the polynomials `(prod_{m in A}(X - x_m)) · X^l`, `l = 1..t`, evaluated directly — a code path
/// that shares nothing with `PrzsKeys`, so the equality of the two spans is a real cross-check
/// and not a restatement.
#[test]
fn the_mask_covers_the_adversarys_entire_residual_uncertainty() {
    for (n, t) in CONFIGS {
        let keys = build_f(n, t);
        let tsets = all_tsets(n, t);
        let a_rank = 0usize;
        let a_set = &tsets[a_rank];
        let domain = f_domain(n);

        // R, built independently of anything in `przs`.
        let residual: Vec<Vec<F>> = (1..=t)
            .map(|l| {
                (0..n)
                    .map(|j| {
                        let x = domain.element(j);
                        let vanish = a_set
                            .iter()
                            .fold(F::ONE, |acc, m| acc * (x - domain.element(*m)));
                        vanish * x.pow([l as u64])
                    })
                    .collect()
            })
            .collect();
        assert_eq!(rank(&residual), t, "n={n} t={t}: R is not t-dimensional");

        // The mask reachable by varying set A's `t` coefficients and nothing else.
        let reachable = a_only_basis(&keys, &tsets, a_rank, n, t);
        assert_eq!(
            rank(&reachable),
            t,
            "n={n} t={t}: A's reachable mask spans {} dimension(s), not t. Dimension 1 is the \
             single-coefficient form and is a privacy break for t >= 2.",
            rank(&reachable)
        );

        for (l, r) in residual.iter().enumerate() {
            assert!(
                in_span(&reachable, r),
                "n={n} t={t}: residual direction {l} is NOT coverable by the mask"
            );
        }
        for (l, r) in reachable.iter().enumerate() {
            assert!(
                in_span(&residual, r),
                "n={n} t={t}: mask direction {l} escapes R — it would perturb the opened value \
                 or the adversary's own shares"
            );
            for j in a_set {
                assert_eq!(
                    r[*j],
                    F::ZERO,
                    "n={n} t={t}: A's own mask was visible in A-member {j}'s share"
                );
            }
        }
    }
}

/// The `t` basis directions of set `A`'s contribution, as `n`-vectors, assembled through the
/// public `zero_share_from_coefficients` entry point.
fn a_only_basis(
    keys: &[PrzsKeys<F>],
    tsets: &[Vec<usize>],
    a_rank: usize,
    n: usize,
    t: usize,
) -> Vec<Vec<F>> {
    (0..t)
        .map(|l| {
            let mut unit = vec![F::ZERO; t];
            unit[l] = F::ONE;
            let table = a_only_table(tsets.len(), a_rank, &unit, t);
            (0..n)
                .map(|id| keys[id].zero_share_from_coefficients(&table).unwrap().share[0])
                .collect()
        })
        .collect()
}

/// A coefficient table over all `C(n,t)` ranks in which every set but `a_rank` contributes zero.
///
/// Modelling the adversary's view this way is exact: it holds every other key, so it computes
/// every other set's contribution and subtracts it. What is left is this.
fn a_only_table<T: Lin>(
    n_sets: usize,
    a_rank: usize,
    a_coeffs: &[T],
    t: usize,
) -> Vec<(usize, ZeroCoeffs<T>)> {
    (0..n_sets)
        .map(|r| {
            let c = if r == a_rank {
                a_coeffs.to_vec()
            } else {
                vec![T::fzero(); t]
            };
            (r, ZeroCoeffs::from_vec(c, t).unwrap())
        })
        .collect()
}

/// **§6.5 error 1, made concrete.**
///
/// The repo's existing PRSS derives one pseudorandom scalar per unqualified set. A degree-`2t`
/// port of *that* shape — one coefficient instead of `t` — is type-correct, reconstructs to zero,
/// has degree `2t`, is position-addressed, is session-separated, and passes every other test in
/// this file. What it is not is private.
///
/// This test builds it from the *same PRF values* the real mask uses (keeping `a_{A,1}` and
/// discarding `a_{A,2..t}`) and then runs the distinguisher:
///
/// * pick two secret sharings `phi0` and `phi1 = phi0 + d` with `d` in `R`, so they have the same
///   constant term and the same evaluations on `A` — the adversary cannot tell them apart from
///   anything it already holds;
/// * find a linear functional `L` that annihilates every naive mask `A` can produce but not `d`;
/// * observe that `L(opened)` then differs between the two worlds for **every** mask the PRF can
///   produce, at every position. Advantage 1, not `2^-something`.
///
/// Under the real `t`-coefficient mask the same `d` is inside the reachable space, so the map
/// `m -> m - d` is a bijection of the mask space carrying one world's view exactly onto the
/// other's — no functional can separate them.
///
/// Skipped at `t = 1`, where the two forms are the same object.
#[test]
fn a_single_coefficient_przs_leaves_a_distinguishing_functional() {
    for (n, t) in CONFIGS {
        if t == 1 {
            continue;
        }
        let keys = build_f(n, t);
        let tsets = all_tsets(n, t);
        let a_rank = 0usize;
        let domain = f_domain(n);
        let a_set = &tsets[a_rank];

        let reachable = a_only_basis(&keys, &tsets, a_rank, n, t);
        let naive_reachable = vec![reachable[0].clone()];
        assert_eq!(rank(&naive_reachable), 1);

        // `d = f_A(X) · X^t`, the top direction — inside `R`, outside the naive span.
        let d: Vec<F> = (0..n)
            .map(|j| {
                let x = domain.element(j);
                let vanish = a_set
                    .iter()
                    .fold(F::ONE, |acc, m| acc * (x - domain.element(*m)));
                vanish * x.pow([t as u64])
            })
            .collect();
        assert!(
            in_span(&reachable, &d),
            "n={n} t={t}: the real mask does not cover d — the test's premise is wrong"
        );
        assert!(
            !in_span(&naive_reachable, &d),
            "n={n} t={t}: d is inside the single-coefficient span"
        );

        // A functional that kills every naive mask but not `d`.
        let l = null_space(&naive_reachable)
            .into_iter()
            .find(|l| !dot(l, &d).fis_zero())
            .expect("the complement of a 1-dimensional span contains such an L");
        for row in &naive_reachable {
            assert_eq!(dot(&l, row), F::ZERO);
        }

        // Two adversary-indistinguishable secret sharings.
        let mut rng = StdRng::seed_from_u64(99);
        let secret = F::from(123456789u64);
        let phi0: Vec<F> = RobustShare::compute_shares(secret, n, 2 * t, None, &mut rng)
            .unwrap()
            .iter()
            .map(|s| s.share[0])
            .collect();
        let phi1 = vec_add(&phi0, &d);
        assert!(
            phi0.iter().zip(&phi1).any(|(a, b)| a != b),
            "n={n} t={t}: the two worlds are the same sharing"
        );
        for j in a_set {
            assert_eq!(
                phi0[*j], phi1[*j],
                "the two worlds differ in a share the adversary already holds"
            );
        }

        // Real PRF coefficients for set A, position by position.
        let holder = (0..n).find(|j| !a_set.contains(j)).unwrap();
        for nu in 0..16 {
            let coeffs = keys[holder]
                .derived_coefficients(a_rank, sid(41), nu)
                .unwrap();
            assert_eq!(coeffs.len(), t);

            // What the naive implementation would have produced from the same bytes.
            let mut naive = vec![F::ZERO; t];
            naive[0] = coeffs.coefficients()[0];
            let naive_mask: Vec<F> = {
                let table = a_only_table(tsets.len(), a_rank, &naive, t);
                (0..n)
                    .map(|id| keys[id].zero_share_from_coefficients(&table).unwrap().share[0])
                    .collect()
            };
            assert_eq!(
                dot(&l, &naive_mask),
                F::ZERO,
                "n={n} t={t}: L failed to annihilate a naive mask at position {nu}"
            );
            assert_ne!(
                dot(&l, &vec_add(&phi0, &naive_mask)),
                dot(&l, &vec_add(&phi1, &naive_mask)),
                "n={n} t={t}: distinguisher failed at position {nu}"
            );

            // The real mask, from the same position: `m - d` is itself a legal mask, so the two
            // worlds produce exactly the same set of openings.
            let real_mask: Vec<F> = {
                let table = a_only_table(tsets.len(), a_rank, coeffs.coefficients(), t);
                (0..n)
                    .map(|id| keys[id].zero_share_from_coefficients(&table).unwrap().share[0])
                    .collect()
            };
            assert!(
                in_span(&reachable, &vec_sub(&real_mask, &d)),
                "n={n} t={t}: no mask maps world 0 onto world 1 at position {nu}"
            );
            assert_eq!(
                vec_add(&phi0, &real_mask),
                vec_add(&phi1, &vec_sub(&real_mask, &d)),
                "n={n} t={t}: the bijection is not value-preserving at position {nu}"
            );
        }
    }
}

/// The **production** path — `zero_shares_at`, the call every consumer actually makes — must fill
/// the whole `2t`-dimensional space `{ h : deg h <= 2t, h(0) = 0 }`.
///
/// This is deliberately a different entry point from the dimension test above, which drives
/// `zero_share_from_coefficients` with coefficients it chooses itself. A mask assembly that used
/// only the first of each set's `t` derived coefficients would leave that test untouched (it
/// supplies its own coefficients) while collapsing the PRF-driven space to the `t+1` dimensions
/// spanned by `{ f_T(X)·X }` — degree `t+1`, not `2t`. The span is measured here, not inferred.
#[test]
fn the_production_path_fills_the_whole_2t_dimensional_mask_space() {
    for (n, t) in CONFIGS {
        let keys = build_f(n, t);
        let samples = 4 * t + 8;
        let rows: Vec<Vec<F>> = (0..samples)
            .map(|nu| f_mask_vector(&keys, n, sid(52), nu))
            .collect();
        assert_eq!(
            rank(&rows),
            2 * t,
            "n={n} t={t}: PRF-derived masks spanned {} dimensions, expected 2t. A span of t+1 is \
             the single-coefficient assembly.",
            rank(&rows)
        );
    }

    for (n, t) in CONFIGS {
        let keys = build_k(n, t);
        let samples = 4 * t + 8;
        let rows: Vec<Vec<Gf256>> = (0..samples)
            .map(|nu| k_mask_vector(&keys, n, sid(53), nu))
            .collect();
        assert_eq!(
            rank(&rows),
            2 * t,
            "n={n} t={t}: PRF-derived GF masks spanned {} dimensions, expected 2t",
            rank(&rows)
        );
    }
}

/// The shape the mask is actually for: a DN07 / `MulPub` degree-`2t` product, masked and opened.
///
/// **Preprocessing only.** The opening modelled here is degree `2t`, which is legal in the
/// synchronous abort-permitted phase and illegal online.
#[test]
fn masking_a_degree_2t_product_preserves_the_product_and_hides_its_polynomial() {
    for (n, t) in CONFIGS {
        let keys = build_f(n, t);
        let mut rng = StdRng::seed_from_u64(5);
        let x = F::from(7u64);
        let y = F::from(11u64);
        let xs = RobustShare::compute_shares(x, n, t, None, &mut rng).unwrap();
        let ys = RobustShare::compute_shares(y, n, t, None, &mut rng).unwrap();

        let mut previous: Option<Vec<F>> = None;
        for nu in 0..4 {
            let masked: Vec<RobustShare<F>> = (0..n)
                .map(|id| {
                    let prod = xs[id].share_mul(&ys[id]).unwrap();
                    assert_eq!(prod.degree, 2 * t);
                    let mask = keys[id].zero_shares_at(sid(51), nu, 1).unwrap()[0].clone();
                    (prod + mask).unwrap()
                })
                .collect();

            let (_, secret) = RobustShare::recover_secret(&masked, n, t)
                .expect("degree-2t reconstruction of the masked product");
            assert_eq!(secret, x * y, "n={n} t={t}: the mask moved the product");

            let values: Vec<F> = masked.iter().map(|s| s.share[0]).collect();
            let coeffs = f_sharing_polynomial(n, &values);
            assert_eq!(coeffs[0], x * y);
            if let Some(prev) = &previous {
                assert_ne!(
                    prev, &values,
                    "n={n} t={t}: two positions produced the same masked opening"
                );
            }
            previous = Some(values);
        }
    }
}

/// PRZS and PRSS run over the **same keys** and the same `SessionId`s. Only their KDF labels
/// (`STOFFEL-PRZS-v2` vs `STOFFEL-PRSS-v2`) keep the two keystreams apart, and a shared label
/// would make a mask a deterministic function of the value it masks.
///
/// Checked at the derivation level, where the separation actually lives, and at both PRZS
/// domains (`Arithmetic` = `0x02`, `Binary` = `0x03`) so that the arithmetic mask and the binary
/// mask drawn at one position are independent too.
#[test]
fn przs_keystreams_are_separated_from_prss_and_from_each_other() {
    let key = [0x5au8; PRSS_KEY_LEN];
    let session = sid(61);
    let bits = 64;

    let prss = derive_ints_at(&key, session, 0, 8, bits);
    let arith = derive_zero_coeff_ints_at(&key, session, PrzsDomain::Arithmetic, 0, 8, bits);
    let binary = derive_zero_coeff_ints_at(&key, session, PrzsDomain::Binary, 0, 8, bits);

    assert_eq!(prss.len(), 8);
    assert_ne!(prss, arith, "PRZS reused the PRSS keystream");
    assert_ne!(prss, binary, "PRZS binary reused the PRSS keystream");
    assert_ne!(arith, binary, "the two PRZS domains share a keystream");

    // Not merely unequal as vectors: no individual value may coincide either, which is what a
    // partial overlap (a shared prefix, a byte-shifted window) would look like.
    for (i, v) in prss.iter().enumerate() {
        assert_ne!(*v, arith[i]);
        assert_ne!(*v, binary[i]);
        assert_ne!(arith[i], binary[i]);
    }

    assert_eq!(PrzsDomain::Arithmetic.context_tag(), 0x02);
    assert_eq!(PrzsDomain::Binary.context_tag(), 0x03);
}

/// A position's mask must not depend on which range asked for it — a pool topped up later has to
/// land on exactly what the parties that derived the whole range already hold — and two sessions
/// must never share one.
#[test]
fn position_addressing_is_stable_and_sessions_do_not_collide() {
    for (n, t) in CONFIGS {
        for k in &build_f(n, t) {
            let whole = k.zero_shares_at(sid(71), 0, 6).unwrap();
            let head = k.zero_shares_at(sid(71), 0, 2).unwrap();
            let tail = k.zero_shares_at(sid(71), 2, 4).unwrap();
            assert_eq!([head, tail].concat(), whole, "n={n} t={t}");

            let other = k.zero_shares_at(sid(72), 0, 6).unwrap();
            assert_ne!(other, whole, "n={n} t={t}: two sessions produced one mask");
        }
    }
}

/// The `t`-coefficient rule is enforced by the type, at the public boundary: a caller cannot hand
/// a one-coefficient table to a `t = 2` store and have it zero-padded.
#[test]
fn the_public_api_refuses_a_single_coefficient_table() {
    let (n, t) = (7usize, 2usize);
    let keys = build_f(n, t);
    let n_sets = all_tsets(n, t).len();

    let one_each: Vec<(usize, ZeroCoeffs<F>)> = (0..n_sets)
        .map(|r| (r, ZeroCoeffs::from_vec(vec![F::ONE], 1).unwrap()))
        .collect();
    assert!(matches!(
        keys[0].zero_share_from_coefficients(&one_each),
        Err(PrzsError::CoefficientCountMismatch { t: 2, got: 1 })
    ));
    assert!(matches!(
        ZeroCoeffs::<F>::from_vec(vec![F::ONE], 2),
        Err(PrzsError::CoefficientCountMismatch { t: 2, got: 1 })
    ));
    assert!(matches!(
        ZeroCoeffs::<F>::from_vec(vec![], 0),
        Err(PrzsError::DegenerateThreshold)
    ));
}

// ---------------------------------------------------------------------------------------------
// Binary side — Gf256
// ---------------------------------------------------------------------------------------------

fn k_mask_vector(
    keys: &[GfPrzsKeys<Gf256>],
    n: usize,
    session: SessionId,
    nu: usize,
) -> Vec<Gf256> {
    (0..n)
        .map(|id| keys[id].zero_shares_at(session, nu, 1).unwrap()[0].share)
        .collect()
}

fn k_sharing_polynomial(n: usize, values: &[Gf256]) -> Vec<Gf256> {
    let domain = get_or_create_gf2k_domain::<Gf256>(n).unwrap();
    let xs: Vec<Gf256> = (0..n).map(|id| domain.element(id)).collect();
    stoffelcrypto::common::gf2k::poly::lagrange_interpolate(&xs, values)
        .unwrap()
        .coeffs
}

#[test]
fn gf_zero_sharings_reconstruct_to_zero_at_degree_2t() {
    for (n, t) in CONFIGS {
        let keys = build_k(n, t);
        let count = 4;
        for nu in 0..count {
            let shares: Vec<GfShare<Gf256>> = (0..n)
                .map(|id| keys[id].zero_shares_at(sid(83), nu, 1).unwrap()[0].clone())
                .collect();
            assert!(shares.iter().all(|s| s.degree == 2 * t));
            let (coeffs, secret) = GfShare::recover_secret(&shares, n, t)
                .expect("degree-2t reconstruction from all n honest shares");
            assert!(
                secret.is_zero(),
                "n={n} t={t}: sharing {nu} was not of zero"
            );
            assert!(coeffs.len() <= 2 * t + 1);
        }
    }
}

/// The binary twin of `a_przs_mask_is_not_a_degree_t_sharing_of_zero`, and for the same reason:
/// a mask that collapsed to degree `t` would leave the top `t` coefficients of a degree-`2t`
/// opening unmasked.
#[test]
fn a_gf_przs_mask_is_not_a_degree_t_sharing_of_zero() {
    for (n, t) in CONFIGS {
        let keys = build_k(n, t);
        let mut saw_full_degree = false;
        for nu in 0..8 {
            let values = k_mask_vector(&keys, n, sid(84), nu);
            let coeffs = k_sharing_polynomial(n, &values);
            assert!(coeffs.first().copied().unwrap_or(Gf256(0)).is_zero());
            assert!(deg(&coeffs) <= 2 * t);
            if deg(&coeffs) == 2 * t {
                saw_full_degree = true;
            }

            let relabelled: Vec<GfShare<Gf256>> =
                (0..n).map(|id| GfShare::new(values[id], id, t)).collect();
            match GfShare::recover_secret(&relabelled, n, t) {
                Err(_) => {}
                Ok((_, secret)) => assert!(
                    !secret.is_zero(),
                    "n={n} t={t}: sharing {nu} decoded as a degree-t sharing of zero"
                ),
            }
        }
        assert!(
            saw_full_degree,
            "n={n} t={t}: no sampled sharing reached degree 2t"
        );
    }
}

/// Uniformity over `Gf256`: a party's mask share must cover all 256 elements, not a subfield and
/// not a coset. `GF(2^8)` has the proper subfields `GF(2)`, `GF(2^2)` and `GF(2^4)` (2, 4 and 16
/// elements), so a draw that collapsed into one would still look "random" to a glance while
/// masking almost nothing — that is the degenerate case this rules out.
#[test]
fn gf_mask_shares_cover_the_whole_field() {
    let (n, t) = (7usize, 2usize);
    let keys = build_k(n, t);
    let count = 8192usize;
    let shares = keys[2].zero_shares_at(sid(85), 0, count).unwrap();

    let mut histogram = [0usize; 256];
    for s in &shares {
        histogram[s.share.0 as usize] += 1;
    }
    let expected = count / 256; // 32
    assert!(
        histogram.iter().all(|c| *c > 0),
        "some field element was never drawn: min={:?}",
        histogram.iter().min()
    );
    assert!(
        histogram
            .iter()
            .all(|c| *c >= expected / 4 && *c <= expected * 4),
        "draw was far from uniform: min={:?} max={:?}",
        histogram.iter().min(),
        histogram.iter().max()
    );
}

/// The binary side's `t`-coefficient dimension property, with the same distinguisher.
///
/// Nothing about the argument changes in characteristic 2 — the adversary is still a maximal
/// unqualified set holding every key but its own, and its residual uncertainty in an opened
/// degree-`2t` polynomial is still exactly `t`-dimensional. Only the field changes, and with it
/// `f^K_T(X) = prod_{m in T}(X + x_m)/x_m`.
#[test]
fn a_single_coefficient_gf_przs_leaves_a_distinguishing_functional() {
    for (n, t) in CONFIGS {
        if t == 1 {
            continue;
        }
        let keys = build_k(n, t);
        let tsets = all_tsets(n, t);
        let a_rank = 0usize;
        let a_set = &tsets[a_rank];
        let domain = get_or_create_gf2k_domain::<Gf256>(n).unwrap();

        let reachable: Vec<Vec<Gf256>> = (0..t)
            .map(|l| {
                let mut unit = vec![Gf256(0); t];
                unit[l] = Gf256(1);
                let table = a_only_table(tsets.len(), a_rank, &unit, t);
                (0..n)
                    .map(|id| keys[id].zero_share_from_coefficients(&table).unwrap().share)
                    .collect()
            })
            .collect();
        assert_eq!(
            rank(&reachable),
            t,
            "n={n} t={t}: A's reachable GF mask spans {} dimension(s), not t",
            rank(&reachable)
        );
        let naive_reachable = vec![reachable[0].clone()];
        assert_eq!(rank(&naive_reachable), 1);

        // `d = (prod_{m in A}(X + x_m)) · X^t`, in R and outside the naive span.
        let d: Vec<Gf256> = (0..n)
            .map(|j| {
                let x = domain.element(j);
                let vanish = a_set
                    .iter()
                    .fold(Gf256(1), |acc, m| acc * (x + domain.element(*m)));
                let mut pow = Gf256(1);
                for _ in 0..t {
                    pow = pow * x;
                }
                vanish * pow
            })
            .collect();
        assert!(in_span(&reachable, &d));
        assert!(!in_span(&naive_reachable, &d));
        for j in a_set {
            assert!(d[*j].is_zero(), "d did not vanish on A-member {j}");
        }

        let l = null_space(&naive_reachable)
            .into_iter()
            .find(|l| !dot(l, &d).fis_zero())
            .expect("such an L exists exactly because d is outside the naive span");

        let mut rng = StdRng::seed_from_u64(404);
        let phi0: Vec<Gf256> = GfShare::compute_shares(Gf256(0x9c), n, 2 * t, &mut rng)
            .unwrap()
            .iter()
            .map(|s| s.share)
            .collect();
        let phi1 = vec_add(&phi0, &d);

        let holder = (0..n).find(|j| !a_set.contains(j)).unwrap();
        for nu in 0..16 {
            let coeffs = keys[holder]
                .derived_coefficients(a_rank, sid(86), nu)
                .unwrap();
            let mut naive = vec![Gf256(0); t];
            naive[0] = coeffs.coefficients()[0];
            let naive_mask: Vec<Gf256> = {
                let table = a_only_table(tsets.len(), a_rank, &naive, t);
                (0..n)
                    .map(|id| keys[id].zero_share_from_coefficients(&table).unwrap().share)
                    .collect()
            };
            assert!(dot(&l, &naive_mask).is_zero());
            assert_ne!(
                dot(&l, &vec_add(&phi0, &naive_mask)),
                dot(&l, &vec_add(&phi1, &naive_mask)),
                "n={n} t={t}: distinguisher failed at position {nu}"
            );

            let real_mask: Vec<Gf256> = {
                let table = a_only_table(tsets.len(), a_rank, coeffs.coefficients(), t);
                (0..n)
                    .map(|id| keys[id].zero_share_from_coefficients(&table).unwrap().share)
                    .collect()
            };
            assert!(in_span(&reachable, &vec_sub(&real_mask, &d)));
            assert_eq!(
                vec_add(&phi0, &real_mask),
                vec_add(&phi1, &vec_sub(&real_mask, &d))
            );
        }
    }
}
