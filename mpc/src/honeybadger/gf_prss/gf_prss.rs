use std::collections::HashMap;

use num_bigint::BigUint;

use crate::common::gf2k::field::BinaryField;
use crate::common::gf2k::poly::{lagrange_interpolate, Poly};
use crate::common::gf2k::share::GfShare;
use crate::common::gf2k::{get_or_create_gf2k_domain, Gf2kError};
use crate::honeybadger::gf_prss::{GfPrssError, MAX_UNQUALIFIED_SETS};
use crate::honeybadger::prss::prss::{
    all_tsets, bounded_set_count, derive_ints_at, held_ranks, KEY_FAMILY_LABEL,
};
use crate::honeybadger::prss::{PrssError, PrssStream, PrssWindow, PRSS_KEY_LEN};
use crate::honeybadger::SessionId;
use sha2::{Digest, Sha256};

/// The largest party count a domain over `K` can address: `|K*|`, one evaluation point per party.
///
/// 15 for `Gf2p4`, 255 for `Gf256` and `Gf2p8`, 65535 for `Gf2p16`. This is the *field's* ceiling;
/// the `C(n-1, t)` PRF-stream blow-up documented on the module bites long before it.
pub fn max_parties<K: BinaryField>() -> usize {
    K::MAX_DOMAIN_SIZE
}

/// The extension degree `k` of `K = GF(2^k)`, recovered from `K::MAX_DOMAIN_SIZE = 2^k - 1`.
///
/// `BinaryField` exposes no width directly, so this is the only handle on "how many bits does one
/// element of `K` carry" — which is what sizes a uniform draw and bounds [`GfPrssKeys::shares_at`].
///
/// # Errors
/// - [`GfPrssError::IndeterminateExtensionDegree`] if `MAX_DOMAIN_SIZE` is not `2^k - 1` for a `k`
///   this platform can represent. That is exactly the saturating `Gf2k<K, ..>` case at
///   `K >= usize::BITS`, where the constant clamps to `usize::MAX` and the true degree is lost.
///   Failing loudly matters: silently taking 64 there would draw from a proper subspace of `K`
///   while every functional test still passed.
pub fn extension_degree<K: BinaryField>() -> Result<usize, GfPrssError> {
    let order = K::MAX_DOMAIN_SIZE;
    // `usize::MAX` is the saturation marker, and is also all-ones, so it must be rejected first.
    if order == usize::MAX || order == 0 || (order & (order + 1)) != 0 {
        return Err(GfPrssError::IndeterminateExtensionDegree { order });
    }
    Ok(order.count_ones() as usize)
}

/// Rejects an `(n, t)` whose unqualified-set enumeration would be unbounded, *before* allocating
/// it. See [`MAX_UNQUALIFIED_SETS`].
///
/// The counting and the bound both come from `prss`: this module used to carry its own
/// byte-identical `binomial` and its own copy of the number, which is three opportunities for
/// two fields to disagree about what "too many" means.
fn check_set_count(n: usize, t: usize) -> Result<(), GfPrssError> {
    bounded_set_count(n, t)
        .map(|_| ())
        .ok_or(GfPrssError::TooManyUnqualifiedSets {
            n,
            t,
            max: MAX_UNQUALIFIED_SETS,
        })
}

/// The `Gf2k` conversion polynomials, one per unqualified set: `f^K_T(0) = 1` and
/// `f^K_T(x^K_j) = 0` for every `j ∈ T`, of degree `|T|`.
///
/// The binary twin of `build_all_f_polys` (`fpmul/mod.rs`), with `GeneralEvaluationDomain` and
/// `ark_poly`'s Lagrange replaced by [`Gf2kDomain`](crate::common::gf2k::Gf2kDomain) and
/// [`lagrange_interpolate`]. Equivalent to the closed form `Π_{j∈T} (X + x^K_j) / x^K_j` — in
/// characteristic 2 the numerator's `X - x` is `X + x`, and the product at `X = 0` is
/// `Π x^K_j / x^K_j = 1` — and `lagrange_f_poly_matches_the_product_form` pins that.
///
/// The domain is `[1, g, g², ...]`, all nonzero, so `0` is never one of the `t` roots and the
/// `t + 1` interpolation points are always distinct.
pub fn build_all_gf_f_polys<K: BinaryField>(
    n: usize,
    tsets: Vec<Vec<usize>>,
) -> Result<HashMap<Vec<usize>, Poly<K>>, Gf2kError> {
    let domain = get_or_create_gf2k_domain::<K>(n)?;
    tsets
        .into_iter()
        .map(|tset| {
            if tset.iter().any(|j| *j >= n) {
                return Err(Gf2kError::InvalidInput(format!(
                    "unqualified set {tset:?} indexes a party outside n={n}"
                )));
            }
            let xs = std::iter::once(K::zero())
                .chain(tset.iter().map(|j| domain.element(*j)))
                .collect::<Vec<_>>();
            let ys = std::iter::once(K::one())
                .chain(std::iter::repeat(K::zero()).take(tset.len()))
                .collect::<Vec<_>>();
            let poly = lagrange_interpolate(&xs, &ys)?;
            Ok((tset, poly))
        })
        .collect()
}

/// Embeds the low `bits` bits of `value` into `K` along the polynomial basis
/// `{1, g, g², …, g^(bits-1)}`, `g = K::generator()`.
///
/// The `F`-side PRSS embeds a derived integer with `F::from(BigUint)`. `BinaryField` has no such
/// conversion — and no meaningful *integer* interpretation at all — so the port cannot be
/// structural here. What replaces it is the only field-agnostic injection available through the
/// trait: treat the `bits` derived bits as coordinates.
///
/// `{1, g, …, g^(k-1)}` is a basis of `K` over `GF(2)` whenever `g` is primitive, because a
/// primitive element has order `2^k - 1` and so lies in no proper subfield, forcing its minimal
/// polynomial to have degree exactly `k`. Primitivity is a checked property of every concrete
/// field in this repo (`verify_field_and_generator`, and `Gf256`'s generator-order test), and
/// `the_generator_basis_embedding_is_injective` re-checks the consequence that actually
/// matters here — injectivity — exhaustively over `Gf256`.
///
/// Hence: `bits` independent uniform bits embed to a uniform element of the `bits`-dimensional
/// subspace they span, and at `bits = k` to a uniform element of `K`. At `bits = 1` the image is
/// `{0, 1}`, i.e. exactly the elements `BinaryField::is_bit` accepts.
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

/// One party's PRSS key material over a binary field, plus the `Gf2k` conversion coefficient each
/// key is multiplied by.
///
/// `f^K_T(x^K_id)` depends only on the set and this party's evaluation point, never on the
/// session, so it is computed once here rather than per invocation.
#[derive(Clone, Debug)]
pub struct GfPrssKeys<K: BinaryField> {
    id: usize,
    t: usize,
    /// `(rank, key, f^K_T(x^K_id))` for each set this party is outside of, ordered by rank.
    entries: Vec<(usize, [u8; PRSS_KEY_LEN], K)>,
}

impl<K: BinaryField> GfPrssKeys<K> {
    /// Build from the keys this party holds, indexed by rank in `all_tsets`.
    ///
    /// Requires a key for every set the party is outside of — a partial store would silently
    /// produce shares of the wrong secret, since the missing terms just drop out of the sum.
    ///
    /// The rank ordering is the `F`-side `all_tsets` ordering, unchanged: the two domains index
    /// the *same* key family, and a party's `k_T` is one key used by both conversions.
    ///
    /// # Errors
    /// - [`GfPrssError::PartyOutOfRange`], [`GfPrssError::ThresholdOutOfRange`]
    /// - [`GfPrssError::PartyCountExceedsField`] if `n > K::MAX_DOMAIN_SIZE`
    /// - [`GfPrssError::TooManyUnqualifiedSets`] if `C(n, t) > MAX_UNQUALIFIED_SETS`
    /// - [`GfPrssError::KeyCountMismatch`] / [`GfPrssError::MissingKey`] for a partial store
    pub fn new(
        id: usize,
        n: usize,
        t: usize,
        keys: &[(usize, [u8; PRSS_KEY_LEN])],
    ) -> Result<Self, GfPrssError> {
        if id >= n {
            return Err(GfPrssError::PartyOutOfRange { id, n });
        }
        if t >= n {
            return Err(GfPrssError::ThresholdOutOfRange { n, t });
        }
        if n > max_parties::<K>() {
            return Err(GfPrssError::PartyCountExceedsField {
                n,
                max: max_parties::<K>(),
            });
        }
        check_set_count(n, t)?;

        let tsets = all_tsets(n, t);
        let held = held_ranks(n, t, id);
        if keys.len() != held.len() {
            return Err(GfPrssError::KeyCountMismatch {
                expected: held.len(),
                got: keys.len(),
            });
        }

        let my_tsets: Vec<Vec<usize>> = held
            .iter()
            .map(|r| tsets.get(*r).cloned().ok_or(GfPrssError::MissingKey(*r)))
            .collect::<Result<_, _>>()?;
        let polys = build_all_gf_f_polys::<K>(n, my_tsets)?;
        let domain = get_or_create_gf2k_domain::<K>(n)?;
        let x_id = domain.element(id);

        let mut entries = Vec::with_capacity(held.len());
        for rank in held {
            let key = keys
                .iter()
                .find_map(|(r, k)| (*r == rank).then_some(*k))
                .ok_or(GfPrssError::MissingKey(rank))?;
            let tset = tsets.get(rank).ok_or(GfPrssError::MissingKey(rank))?;
            let coeff = polys
                .get(tset)
                .ok_or(GfPrssError::MissingKey(rank))?
                .evaluate(x_id);
            entries.push((rank, key, coeff));
        }

        Ok(Self { id, t, entries })
    }

    /// Number of keys held — `C(n-1, t)`, and the number of PRF streams one call spends.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Never true for a `GfPrssKeys` built by [`Self::new`]: `C(n-1, t) >= 1` for any valid
    /// `n > t`, and `new` rejects a key set that doesn't match the held ranks. Present because
    /// `len` without it is a clippy error under `-D warnings`.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// This party's index.
    pub fn id(&self) -> usize {
        self.id
    }

    /// SHA-256 fingerprint of the `(rank, key)` list this store holds.
    ///
    /// Byte-for-byte the same digest
    /// [`PrssKeys::key_family_id`](crate::honeybadger::prss::prss::PrssKeys::key_family_id)
    /// computes, and deliberately so: `setup_prss_keys` builds the `F` and `K` stores from **one**
    /// key list, so one [`PrssAllocator`](crate::honeybadger::prss::PrssAllocator) — stamped with
    /// the `F` store's fingerprint — governs the positions of both domains. Were the two digests
    /// to differ, every `K`-side window would be refused as a family mismatch and the binary
    /// streams would need a second allocator, which is exactly the cursor fork the allocator
    /// exists to prevent.
    ///
    /// Local and per-party: each party holds a different `C(n-1, t)` subset, so this is not a
    /// cross-party identifier and must never be compared between parties or put on the wire.
    pub fn key_family_id(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(KEY_FAMILY_LABEL);
        h.update((self.id as u64).to_be_bytes());
        h.update((self.t as u64).to_be_bytes());
        h.update((self.entries.len() as u64).to_be_bytes());
        for (rank, key, _) in &self.entries {
            h.update((*rank as u64).to_be_bytes());
            h.update(key);
        }
        h.finalize().into()
    }

    /// The raw per-set values at absolute positions `start .. start + count`, as
    /// `(rank, values)` ordered by rank.
    ///
    /// Exposed so a caller that needs *both* conversions of one daBit seed can see that it is one
    /// derivation: these are byte-for-byte the values the `F`-side `PrssKeys::shares_at` consumes
    /// for the same `(session_id, start, count, bits)`, because `derive_ints_at` is
    /// field-independent.
    pub fn derive_set_values(
        &self,
        session_id: SessionId,
        start: usize,
        count: usize,
        bits: usize,
    ) -> Vec<(usize, Vec<BigUint>)> {
        self.entries
            .iter()
            .map(|(rank, key, _)| (*rank, derive_ints_at(key, session_id, start, count, bits)))
            .collect()
    }

    /// This party's degree-`t` `Gf2k` shares of the pseudorandom values at absolute positions
    /// `start .. start + count`, each drawn from the `bits`-dimensional subspace of `K` spanned by
    /// `{1, g, …, g^(bits-1)}`.
    ///
    /// Purely local: `s_j = Σ_T β_{r_T}(a) · f^K_T(x^K_j)`, with no communication. Every party must
    /// pass the identical `session_id`, `start`, `count` and `bits` — the derivation is
    /// deterministic, so a mismatch on any of them yields shares of *different* secrets that no
    /// message exchange exists to catch.
    ///
    /// **The reconstructed secret is `⊕_T β_T`, not `Σ_T β_T`.** This is the one place where the
    /// binary port is *better* than its arithmetic twin rather than merely parallel: in
    /// characteristic 2 the replicated-to-Shamir sum *is* an XOR, so there is no `C(n,t)`
    /// multiplicity to budget for, and a `bits`-wide draw reconstructs to a `bits`-wide secret.
    /// (The `F` side reconstructs into `[0, C(n,t) · 2^bits)` and callers must size masks against
    /// that.) It is also why the daBit's two halves tie: `⊕_T β_T = (Σ_T β_T) mod 2`.
    ///
    /// # Errors
    /// - [`GfPrssError::WidthExceedsField`] if `bits` is zero or exceeds
    ///   [`extension_degree`]`::<K>()` — a wider draw could not be embedded injectively, so its
    ///   "uniformity" would be a fiction.
    /// - [`GfPrssError::IndeterminateExtensionDegree`] if `K`'s degree is not recoverable.
    pub fn shares_at(
        &self,
        session_id: SessionId,
        start: usize,
        count: usize,
        bits: usize,
    ) -> Result<Vec<GfShare<K>>, GfPrssError> {
        let degree = extension_degree::<K>()?;
        if bits == 0 || bits > degree {
            return Err(GfPrssError::WidthExceedsField { bits, degree });
        }

        let mut shares = vec![GfShare::new(K::zero(), self.id, self.t); count];
        for (_, key, coeff) in &self.entries {
            let values = derive_ints_at(key, session_id, start, count, bits);
            for (share, value) in shares.iter_mut().zip(&values) {
                share.share = share.share + embed_bits::<K>(value, bits) * *coeff;
            }
        }
        Ok(shares)
    }

    /// Degree-`t` `Gf2k` shares of `count` pseudorandom **bits**, the `K` half of a PRSS daBit.
    ///
    /// `shares_at` at `bits = 1`. The secret is `⊕_T β_T ∈ {0, 1} ⊂ K`, so
    /// `BinaryField::is_bit` holds on it **by construction** — there is no dealt value anywhere in
    /// this path, and therefore nothing to certify. That is the T3 (value) obligation of the
    /// share-type analysis discharged at zero cost; any variant that reintroduces a dealt bit
    /// loses it and must add a bit-ness check back.
    ///
    /// The `F`-side twin of this call is `PrssKeys::shares_at(session_id, start, count, 1)`, which
    /// **must** use this exact `session_id`, and which must *not* be the session the Mod2 mask `ψ`
    /// is drawn from (see the module docs).
    pub fn bit_shares_at(
        &self,
        session_id: SessionId,
        start: usize,
        count: usize,
    ) -> Result<Vec<GfShare<K>>, GfPrssError> {
        self.shares_at(session_id, start, count, 1)
    }

    /// The `K` half of a PRSS daBit seed, at exactly the positions a claimed
    /// [`PrssWindow`] names — **the production entry point**.
    ///
    /// `start` and `count` come from the window and not from a caller, and the width is pinned to
    /// 1 by [`Self::bit_shares_at`]. The window's `bits` is asserted rather than used, because a
    /// [`PrssStream::DaBitSeed`] window claimed at any other width would name different bytes than
    /// this call reads (P2) — and `claim_dabit_batch` pins that width to 1, so a mismatch here is
    /// a second minter, not a caller typo.
    ///
    /// This deliberately reads the **same bytes** as
    /// [`PrssKeys::shares_at_in`](crate::honeybadger::prss::prss::PrssKeys::shares_at_in) on the
    /// same window: one draw of `beta_T`, converted in both domains. That aliasing is the daBit's
    /// whole trick and the one legitimate exception to invariant P.
    ///
    /// # Errors
    /// - [`GfPrssError::Prss`] wrapping [`PrssError::WindowStreamMismatch`] if the window names a
    ///   stream other than [`PrssStream::DaBitSeed`], or
    ///   [`PrssError::WindowKeyFamilyMismatch`] if it was claimed against other key material, or
    ///   [`PrssError::StreamWidthMismatch`] if it was claimed at a width other than 1.
    pub fn bit_shares_at_in(&self, window: &PrssWindow) -> Result<Vec<GfShare<K>>, GfPrssError> {
        if window.stream() != PrssStream::DaBitSeed {
            return Err(PrssError::WindowStreamMismatch {
                got: window.stream().name(),
            }
            .into());
        }
        if window.key_family_id() != self.key_family_id() {
            return Err(PrssError::WindowKeyFamilyMismatch.into());
        }
        if window.bits() != 1 {
            return Err(PrssError::StreamWidthMismatch {
                stream: window.stream().name(),
                expected: 1,
                got: window.bits(),
            }
            .into());
        }
        self.bit_shares_at(window.session_id(), window.start(), window.len())
    }

    /// Degree-`t` `Gf2k` shares of `count` values uniform over the whole of `K`.
    ///
    /// `shares_at` at `bits = extension_degree::<K>()`. This is the random sharing behind a
    /// `Gf2k` DN07 double sharing, and it costs zero wire elements.
    pub fn uniform_shares_at(
        &self,
        session_id: SessionId,
        start: usize,
        count: usize,
    ) -> Result<Vec<GfShare<K>>, GfPrssError> {
        self.shares_at(session_id, start, count, extension_degree::<K>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::gf2k::field::Gf256;
    use crate::common::gf2k::generic_field::{Gf2p16, Gf2p4};
    use crate::common::ProtocolSessionId;
    use crate::common::SecretSharingScheme;
    use crate::honeybadger::prss::prss::{binomial, PrssKeys};
    use crate::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
    use crate::honeybadger::ProtocolType;
    use ark_bls12_381::Fr;
    use ark_ff::PrimeField;
    use num_bigint::BigUint;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    fn sid(exec: u64) -> SessionId {
        SessionId::new(
            ProtocolType::PRandInt,
            SessionId::pack_slot(exec, 0, 0),
            111,
        )
    }

    /// One key per maximal unqualified set, indexed by rank — i.e. what the one-time setup
    /// protocol produces, before it is split up per party.
    fn all_dealt(n: usize, t: usize) -> Vec<[u8; PRSS_KEY_LEN]> {
        let mut rng = StdRng::seed_from_u64(7);
        (0..all_tsets(n, t).len()).map(|_| rng.gen()).collect()
    }

    fn deal_keys(n: usize, t: usize) -> Vec<Vec<(usize, [u8; PRSS_KEY_LEN])>> {
        let all = all_dealt(n, t);
        (0..n)
            .map(|id| {
                held_ranks(n, t, id)
                    .into_iter()
                    .map(|rank| (rank, all[rank]))
                    .collect()
            })
            .collect()
    }

    fn build_all<K: BinaryField>(n: usize, t: usize) -> Vec<GfPrssKeys<K>> {
        let dealt = deal_keys(n, t);
        (0..n)
            .map(|id| GfPrssKeys::<K>::new(id, n, t, &dealt[id]).unwrap())
            .collect()
    }

    /// The secret a full set of shares must reconstruct to, computed straight from the dealt keys:
    /// the XOR over **all** `C(n,t)` sets, not just the ones any one party holds.
    fn expected_secrets<K: BinaryField>(
        n: usize,
        t: usize,
        session_id: SessionId,
        start: usize,
        count: usize,
        bits: usize,
    ) -> Vec<K> {
        let all = all_dealt(n, t);
        let mut out = vec![K::zero(); count];
        for key in &all {
            let values = derive_ints_at(key, session_id, start, count, bits);
            for (acc, v) in out.iter_mut().zip(&values) {
                *acc = *acc + embed_bits::<K>(v, bits);
            }
        }
        out
    }

    #[test]
    fn every_party_holds_c_n_minus_1_choose_t_keys() {
        for (n, t, expected) in [(4, 1, 3), (5, 1, 4), (7, 2, 15), (10, 3, 84)] {
            for k in &build_all::<Gf256>(n, t) {
                assert_eq!(k.len(), expected, "n={n} t={t}");
                assert!(!k.is_empty());
            }
        }
    }

    #[test]
    fn extension_degree_matches_each_concrete_field() {
        assert_eq!(extension_degree::<Gf2p4>().unwrap(), 4);
        assert_eq!(extension_degree::<Gf256>().unwrap(), 8);
        assert_eq!(extension_degree::<Gf2p16>().unwrap(), 16);
        assert_eq!(max_parties::<Gf2p4>(), 15);
        assert_eq!(max_parties::<Gf256>(), 255);
        assert_eq!(max_parties::<Gf2p16>(), 65535);
    }

    /// The embedding must be injective on `[0, 2^k)`, which is what makes a `k`-bit uniform draw a
    /// uniform field element. Exhaustive over `Gf256`.
    #[test]
    fn the_generator_basis_embedding_is_injective() {
        let mut seen = std::collections::HashSet::new();
        for v in 0u32..256 {
            let e: Gf256 = embed_bits(&BigUint::from(v), 8);
            assert!(seen.insert(e.0), "embedding collided at {v}");
        }
        assert_eq!(seen.len(), 256);

        // And at bits = 1 the image is exactly the GF(2) subfield the bit-ness predicate accepts.
        assert_eq!(embed_bits::<Gf256>(&BigUint::from(0u8), 1), Gf256::zero());
        assert_eq!(embed_bits::<Gf256>(&BigUint::from(1u8), 1), Gf256::one());
        assert!(embed_bits::<Gf256>(&BigUint::from(1u8), 1).is_bit());
    }

    #[test]
    fn f_poly_is_one_at_zero_and_vanishes_on_its_set() {
        let (n, t) = (10usize, 3usize);
        let domain = get_or_create_gf2k_domain::<Gf256>(n).unwrap();
        let tsets = all_tsets(n, t);
        let polys = build_all_gf_f_polys::<Gf256>(n, tsets.clone()).unwrap();

        for tset in &tsets {
            let poly = &polys[tset];
            assert_eq!(poly.evaluate(Gf256::zero()), Gf256::one(), "f_T(0) != 1");
            assert!(poly.degree() <= t, "deg f_T > t");
            for j in tset {
                assert!(
                    poly.evaluate(domain.element(*j)).is_zero(),
                    "f_T did not vanish at {j}"
                );
            }
        }
    }

    /// The Lagrange build and the closed form `Π_{j∈T} (X + x_j) / x_j` must agree everywhere.
    #[test]
    fn lagrange_f_poly_matches_the_product_form() {
        let (n, t) = (7usize, 2usize);
        let domain = get_or_create_gf2k_domain::<Gf256>(n).unwrap();
        let tsets = all_tsets(n, t);
        let polys = build_all_gf_f_polys::<Gf256>(n, tsets.clone()).unwrap();

        for tset in &tsets {
            let mut product = Poly::<Gf256>::one();
            for j in tset {
                let xj = domain.element(*j);
                let inv = xj.inverse().expect("domain points are nonzero");
                // (X + x_j) / x_j, written as a scaled monomial.
                product = &(&product * &Poly::monomial(xj)) * inv;
            }
            for i in 0..n {
                let x = domain.element(i);
                assert_eq!(
                    polys[tset].evaluate(x),
                    product.evaluate(x),
                    "product form diverged for {tset:?} at party {i}"
                );
            }
        }
    }

    /// The whole point: locally-derived shares must reconstruct as a genuine degree-`t` `Gf2k`
    /// sharing, with no communication anywhere.
    #[test]
    fn shares_reconstruct_as_a_valid_degree_t_sharing() {
        for (n, t) in [(4usize, 1usize), (7, 2), (10, 3)] {
            let keys = build_all::<Gf256>(n, t);
            let count = 4;
            let bits = 8;
            let expected = expected_secrets::<Gf256>(n, t, sid(3), 0, count, bits);

            let per_party: Vec<Vec<GfShare<Gf256>>> = keys
                .iter()
                .map(|k| k.shares_at(sid(3), 0, count, bits).unwrap())
                .collect();

            for i in 0..count {
                let shares: Vec<GfShare<Gf256>> =
                    (0..n).map(|id| per_party[id][i].clone()).collect();
                let (coeffs, secret) =
                    GfShare::recover_secret(&shares, n, t).expect("degree-t reconstruction");
                assert!(
                    coeffs.len() <= t + 1,
                    "n={n} t={t}: {} coefficients, expected at most {}",
                    coeffs.len(),
                    t + 1
                );
                assert_eq!(
                    coeffs[0], secret,
                    "n={n} t={t}: constant term is the secret"
                );
                assert_eq!(
                    secret, expected[i],
                    "n={n} t={t}: secret {i} is not the XOR over all sets"
                );
            }
        }
    }

    /// Reconstruction over a *different* `K`, to pin that nothing depends on `Gf256`'s hand-tuned
    /// implementation. `Gf2p4` also exercises the narrow-field path: `bits` may be at most 4.
    #[test]
    fn shares_reconstruct_over_a_narrow_field() {
        let (n, t) = (7usize, 2usize);
        let keys = build_all::<Gf2p4>(n, t);
        let count = 6;
        let expected = expected_secrets::<Gf2p4>(n, t, sid(11), 0, count, 4);

        let per_party: Vec<Vec<GfShare<Gf2p4>>> = keys
            .iter()
            .map(|k| k.uniform_shares_at(sid(11), 0, count).unwrap())
            .collect();

        for i in 0..count {
            let shares: Vec<GfShare<Gf2p4>> = (0..n).map(|id| per_party[id][i].clone()).collect();
            let (_, secret) = GfShare::recover_secret(&shares, n, t).unwrap();
            assert_eq!(secret, expected[i]);
        }
    }

    /// The `K` half of a daBit: the secret must be a genuine bit of `K`, by construction and with
    /// no certification.
    #[test]
    fn bit_shares_reconstruct_to_a_bit() {
        let (n, t) = (7usize, 2usize);
        let keys = build_all::<Gf256>(n, t);
        let count = 64;
        let expected = expected_secrets::<Gf256>(n, t, sid(12), 0, count, 1);

        let per_party: Vec<Vec<GfShare<Gf256>>> = keys
            .iter()
            .map(|k| k.bit_shares_at(sid(12), 0, count).unwrap())
            .collect();

        let mut zeros = 0usize;
        let mut ones = 0usize;
        for i in 0..count {
            let shares: Vec<GfShare<Gf256>> = (0..n).map(|id| per_party[id][i].clone()).collect();
            let (_, secret) = GfShare::recover_secret(&shares, n, t).unwrap();
            assert!(secret.is_bit(), "bit {i} was not a bit: {secret:?}");
            assert_eq!(secret, expected[i]);
            if secret.is_zero() {
                zeros += 1;
            } else {
                ones += 1;
            }
        }
        // Not a statistical test — just a guard against a derivation that collapsed to a constant.
        assert!(zeros > 0 && ones > 0, "bits were constant: {zeros}/{ones}");
    }

    /// §1.2's tie, end to end: one derivation, two conversions, and the `F`-side integer sum is
    /// congruent mod 2 to the `K`-side XOR. This is the property the whole PRSS-daBit rests on,
    /// and it holds only because both domains consume the same `derive_ints_at` bytes.
    #[test]
    fn the_arithmetic_and_binary_halves_agree_modulo_two() {
        for (n, t) in [(4usize, 1usize), (7, 2)] {
            let dealt = deal_keys(n, t);
            let count = 32;
            let session = sid(21);

            let f_keys: Vec<PrssKeys<Fr>> = (0..n)
                .map(|id| PrssKeys::<Fr>::new(id, n, t, &dealt[id]).unwrap())
                .collect();
            let k_keys: Vec<GfPrssKeys<Gf256>> = (0..n)
                .map(|id| GfPrssKeys::<Gf256>::new(id, n, t, &dealt[id]).unwrap())
                .collect();

            let f_shares: Vec<Vec<RobustShare<Fr>>> = f_keys
                .iter()
                .map(|k| k.shares_at(session, 0, count, 1).unwrap())
                .collect();
            let k_shares: Vec<Vec<GfShare<Gf256>>> = k_keys
                .iter()
                .map(|k| k.bit_shares_at(session, 0, count).unwrap())
                .collect();

            for i in 0..count {
                let fs: Vec<RobustShare<Fr>> = (0..n).map(|id| f_shares[id][i].clone()).collect();
                let ks: Vec<GfShare<Gf256>> = (0..n).map(|id| k_shares[id][i].clone()).collect();

                let (_, s) = RobustShare::recover_secret(&fs, n, t).unwrap();
                let (_, b) = GfShare::recover_secret(&ks, n, t).unwrap();

                let s_int = BigUint::from(s.into_bigint());
                // S is the integer sum of C(n,t) bits, so it never wraps the modulus.
                assert!(s_int <= BigUint::from(all_tsets(n, t).len()));
                let parity = (&s_int % 2u8) == BigUint::from(1u8);
                assert_eq!(
                    parity,
                    b == Gf256::one(),
                    "n={n} t={t}: daBit {i} halves disagree (S={s_int}, b={b:?})"
                );
            }
        }
    }

    /// A uniform draw must cover `K`. `derive_ints_at` is deterministic, so this is a fixed
    /// computation, not a sampled one; the bound is loose enough that only a genuinely broken
    /// embedding (a collapsed subspace, a constant, a stuck byte) can fail it.
    #[test]
    fn uniform_draws_cover_the_whole_field() {
        let (n, t) = (4usize, 1usize);
        let count = 16_384;
        let secrets = expected_secrets::<Gf256>(n, t, sid(31), 0, count, 8);

        let mut histogram = [0usize; 256];
        for s in &secrets {
            histogram[s.0 as usize] += 1;
        }
        assert!(
            histogram.iter().all(|c| *c > 0),
            "some field elements were never drawn"
        );
        // Expected 64 per value; a 4x band around it catches a skewed but non-degenerate draw
        // without being tight enough to flake on a fixed keystream.
        assert!(
            histogram.iter().all(|c| *c >= 16 && *c <= 256),
            "draw was far from uniform: min={:?} max={:?}",
            histogram.iter().min(),
            histogram.iter().max()
        );
    }

    /// Position-addressing, at the share level: a party topping up a half-full pool must land on
    /// exactly what a party that derived the whole range in one go already holds.
    #[test]
    fn topping_up_a_partial_pool_agrees_with_a_full_derivation() {
        for k in &build_all::<Gf256>(4, 1) {
            let whole = k.shares_at(sid(6), 0, 6, 8).unwrap();
            let head = k.shares_at(sid(6), 0, 2, 8).unwrap();
            let tail = k.shares_at(sid(6), 2, 4, 8).unwrap();
            assert_eq!([head, tail].concat(), whole);
        }
    }

    #[test]
    fn distinct_sessions_give_distinct_shares() {
        let keys = build_all::<Gf256>(7, 2);
        let a = keys[0].shares_at(sid(1), 0, 16, 8).unwrap();
        let b = keys[0].shares_at(sid(2), 0, 16, 8).unwrap();
        assert_ne!(a, b);
        assert_eq!(a, keys[0].shares_at(sid(1), 0, 16, 8).unwrap());
    }

    /// Every holder of a rank derives the same per-set values — the property PRSS removes the
    /// network's ability to police, checked on the values this port actually consumes.
    #[test]
    fn per_set_values_agree_across_every_holder() {
        let (n, t) = (7usize, 2usize);
        let keys = build_all::<Gf256>(n, t);

        let mut reference: HashMap<usize, Vec<BigUint>> = HashMap::new();
        for k in &keys {
            for (rank, values) in k.derive_set_values(sid(9), 0, 8, 1) {
                match reference.get(&rank) {
                    Some(prev) => assert_eq!(*prev, values, "rank {rank} diverged"),
                    None => {
                        reference.insert(rank, values);
                    }
                }
            }
        }
        assert_eq!(reference.len(), all_tsets(n, t).len());
    }

    #[test]
    fn rejects_a_partial_key_store() {
        let (n, t) = (7usize, 2usize);
        let dealt = deal_keys(n, t);
        let mut short = dealt[0].clone();
        short.pop();
        assert!(matches!(
            GfPrssKeys::<Gf256>::new(0, n, t, &short),
            Err(GfPrssError::KeyCountMismatch { .. })
        ));
    }

    #[test]
    fn rejects_a_party_out_of_range() {
        let dealt = deal_keys(4, 1);
        assert!(matches!(
            GfPrssKeys::<Gf256>::new(4, 4, 1, &dealt[0]),
            Err(GfPrssError::PartyOutOfRange { .. })
        ));
        assert!(matches!(
            GfPrssKeys::<Gf256>::new(0, 4, 4, &dealt[0]),
            Err(GfPrssError::ThresholdOutOfRange { .. })
        ));
    }

    /// `Gf2p4` has only 15 nonzero elements, so 16 parties cannot be addressed. It must be an
    /// error, never a panic out of the domain builder.
    #[test]
    fn rejects_more_parties_than_the_field_supports() {
        let dealt = deal_keys(16, 1);
        assert!(matches!(
            GfPrssKeys::<Gf2p4>::new(0, 16, 1, &dealt[0]),
            Err(GfPrssError::PartyCountExceedsField { n: 16, max: 15 })
        ));
        // The same (n, t) is fine over a wider field.
        assert!(GfPrssKeys::<Gf256>::new(0, 16, 1, &dealt[0]).is_ok());
    }

    #[test]
    fn rejects_too_many_unqualified_sets() {
        assert!(matches!(
            GfPrssKeys::<Gf2p16>::new(0, 60, 20, &[]),
            Err(GfPrssError::TooManyUnqualifiedSets { .. })
        ));
        assert_eq!(binomial(10, 3), Some(120));
        assert_eq!(binomial(16, 5), Some(4368));
        assert_eq!(binomial(3, 5), Some(0));
    }

    #[test]
    fn rejects_a_width_that_does_not_fit_the_field() {
        let keys = build_all::<Gf256>(4, 1);
        assert!(matches!(
            keys[0].shares_at(sid(1), 0, 1, 9),
            Err(GfPrssError::WidthExceedsField { bits: 9, degree: 8 })
        ));
        assert!(matches!(
            keys[0].shares_at(sid(1), 0, 1, 0),
            Err(GfPrssError::WidthExceedsField { bits: 0, degree: 8 })
        ));

        let narrow = build_all::<Gf2p4>(4, 1);
        assert!(matches!(
            narrow[0].shares_at(sid(1), 0, 1, 5),
            Err(GfPrssError::WidthExceedsField { bits: 5, degree: 4 })
        ));
        assert!(narrow[0].shares_at(sid(1), 0, 1, 4).is_ok());
    }
}
