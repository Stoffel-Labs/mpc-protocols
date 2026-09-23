//! A GF(2^k) Shamir-sharing domain, parallel to the existing `F: FftField` prime-field domain
//! (`common::share`, `honeybadger::robust_interpolate`), intended for arithmetic circuits (e.g.
//! AES) that are naturally expressed over a binary field rather than a large prime field.
//!

pub mod field;
pub mod generic_field;
pub mod poly;
pub mod robust_interpolate;
pub mod share;
pub mod vandermonde;

pub use field::{BinaryField, Gf256, Gf2kDomain};
pub use generic_field::{verify_field_and_generator, Gf2k, Gf2p16, Gf2p4, Gf2p8};
pub use poly::Poly;
pub use share::GfShare;
pub use vandermonde::{apply_vandermonde, make_vandermonde};

use crate::common::share::ShareError;
use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use thiserror::Error;

/// Error type for GF(2^k) field, polynomial, and share operations.
#[derive(Error, Debug)]
pub enum Gf2kError {
    #[error("Polynomial operation failed: {0}")]
    PolynomialOperationError(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Decoding error: {0}")]
    DecodingError(String),

    /// No suitable domain of the requested size exists (i.e. it exceeds
    /// `K::MAX_DOMAIN_SIZE`).
    #[error("No suitable domain found for n={0}")]
    NoSuitableDomain(usize),

    #[error(transparent)]
    ShareError(#[from] ShareError),
}

/// Type-erased memoization map keyed by `(TypeId::of::<K>(), n)`, mirroring
/// `common::DomainCacheMap` on the `F: FftField` side.
type Gf2kCacheMap = HashMap<(TypeId, usize), Box<dyn Any + Send + Sync>>;

/// Upper bound on the number of distinct `(K, n)` entries either GF(2^k) cache will hold.
///
/// A running node uses one binary field and one party count, so this is generous; the bound exists
/// so that a caller sweeping over many `n` — a fuzzer, a test matrix, or a future protocol that
/// derives a sub-domain size from a peer-supplied value — cannot grow the process's resident set
/// without limit. `K::MAX_DOMAIN_SIZE` already bounds each individual entry, so the two together
/// bound the caches absolutely (at most `64 * K::MAX_DOMAIN_SIZE` field elements each).
///
/// Past the bound a value is still computed and returned, just not memoized, so exceeding the cap
/// is a pure performance cliff and never a correctness or availability one. This is deliberately
/// stricter than the `F`-side caches (`common::get_or_create_evaluation_domain`), which are
/// unbounded.
pub const MAX_CACHED_GF2K_DOMAINS: usize = 64;

static GF2K_DOMAIN_CACHE: OnceLock<Mutex<Gf2kCacheMap>> = OnceLock::new();
static GF2K_G0_CACHE: OnceLock<Mutex<Gf2kCacheMap>> = OnceLock::new();

/// Reads a memoized value out of `cache`.
///
/// INVARIANT: a poisoned `Mutex` must never abort an honest party. Every value in these caches is a
/// pure deterministic function of its own key, so a poisoned or contended lock costs at most one
/// recomputation — hence `.lock().ok()?` and never `.lock().unwrap()`, on what is a
/// network-reachable path (every robust reconstruction goes through it).
fn gf2k_cache_get<T: Any + Send + Sync + Clone>(
    cache: &OnceLock<Mutex<Gf2kCacheMap>>,
    key: (TypeId, usize),
) -> Option<T> {
    let guard = cache
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .ok()?;
    guard.get(&key)?.downcast_ref::<T>().cloned()
}

/// Admission rule for both caches: a new key is admitted only while the map is under
/// [`MAX_CACHED_GF2K_DOMAINS`], while refreshing an already-present key is always allowed (it
/// cannot grow the map, and the value is a pure function of the key, so it is the same value
/// regardless).
fn gf2k_cache_admits(len: usize, already_present: bool) -> bool {
    already_present || len < MAX_CACHED_GF2K_DOMAINS
}

/// Stores a memoized value, subject to [`gf2k_cache_admits`].
fn gf2k_cache_insert<T: Any + Send + Sync>(
    cache: &OnceLock<Mutex<Gf2kCacheMap>>,
    key: (TypeId, usize),
    value: T,
) {
    if let Ok(mut guard) = cache.get_or_init(|| Mutex::new(HashMap::new())).lock() {
        if gf2k_cache_admits(guard.len(), guard.contains_key(&key)) {
            guard.insert(key, Box::new(value) as Box<dyn Any + Send + Sync>);
        }
    }
}

/// Returns the canonical [`Gf2kDomain<K>`] of size `n`, memoized across calls.
///
/// The domain is `[1, g, g^2, ..., g^(n-1)]` for `g = K::generator()` — a pure deterministic
/// function of `(K, n)` with no randomness, no interior mutability and no ambient state — so
/// memoizing it is exactly observationally equivalent to rebuilding it, and is therefore
/// correctness- and security-neutral. It was previously rebuilt from scratch (`n` field
/// multiplications, each a bit-serial carry-less multiply) on *every* `recover_secret`,
/// `compute_shares`, `make_vandermonde` and decode call.
///
/// Returns `Gf2kError::NoSuitableDomain` for `n > K::MAX_DOMAIN_SIZE`; a rejected size is never
/// cached.
pub fn get_or_create_gf2k_domain<K: BinaryField>(
    n: usize,
) -> Result<Arc<Gf2kDomain<K>>, Gf2kError> {
    let key = (TypeId::of::<K>(), n);
    if let Some(domain) = gf2k_cache_get::<Arc<Gf2kDomain<K>>>(&GF2K_DOMAIN_CACHE, key) {
        return Ok(domain);
    }
    let domain = Arc::new(Gf2kDomain::<K>::new(n)?);
    gf2k_cache_insert(&GF2K_DOMAIN_CACHE, key, Arc::clone(&domain));
    Ok(domain)
}

/// Returns the memoized `g0(x) = ∏_{i<n} (x - domain.element(i))` for `(K, n)`, if present.
///
/// Like the domain cache, `g0` is a pure deterministic function of `(K, n)`, so memoization is
/// exact. Mirrors `common::get_cached_g0_polynomial`.
pub fn get_cached_gf2k_g0<K: BinaryField>(n: usize) -> Option<Arc<Poly<K>>> {
    gf2k_cache_get::<Arc<Poly<K>>>(&GF2K_G0_CACHE, (TypeId::of::<K>(), n))
}

/// Stores a computed `g0` under `(TypeId::of::<K>(), n)`. Mirrors `common::store_g0_polynomial`.
pub fn store_gf2k_g0<K: BinaryField>(n: usize, g0: Arc<Poly<K>>) {
    gf2k_cache_insert(&GF2K_G0_CACHE, (TypeId::of::<K>(), n), g0);
}

#[cfg(test)]
fn gf2k_cache_len(cache: &OnceLock<Mutex<Gf2kCacheMap>>) -> usize {
    cache
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map(|g| g.len())
        .unwrap_or(0)
}

#[cfg(test)]
fn gf2k_cache_contains(cache: &OnceLock<Mutex<Gf2kCacheMap>>, key: (TypeId, usize)) -> bool {
    cache
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map(|g| g.contains_key(&key))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::robust_interpolate::compute_g0_from_domain;
    use super::*;

    /// The cached domain must be bit-identical to a freshly built one, for every `n` a node could
    /// plausibly use and at both ends of the range.
    #[test]
    fn test_cached_gf2k_domain_matches_fresh() {
        for n in [1usize, 2, 4, 7, 10, 13, 16, 255] {
            let fresh = Gf2kDomain::<Gf256>::new(n).expect("domain must exist");
            let cached = get_or_create_gf2k_domain::<Gf256>(n).expect("domain must exist");
            assert_eq!(cached.len(), n);
            assert_eq!(
                cached.elements(),
                fresh.elements(),
                "cached domain diverged from a freshly built one at n={n}"
            );
        }
    }

    /// A second call must hand back the *same* allocation, i.e. the memoization is live and not a
    /// no-op wrapper. Guarded on the key actually being resident, because the cache is
    /// process-global and capped: if it were full when this key was first requested no insert
    /// happened, and the two `Arc`s would be legitimately distinct.
    #[test]
    fn test_gf2k_domain_is_memoized() {
        let a = get_or_create_gf2k_domain::<Gf256>(9).expect("domain must exist");
        let b = get_or_create_gf2k_domain::<Gf256>(9).expect("domain must exist");
        assert_eq!(a.elements(), b.elements());
        if gf2k_cache_contains(&GF2K_DOMAIN_CACHE, (TypeId::of::<Gf256>(), 9)) {
            assert!(
                Arc::ptr_eq(&a, &b),
                "domain was recomputed despite being resident in the cache"
            );
        }
    }

    /// Distinct binary fields must not collide: the key carries `TypeId::of::<K>()` alongside `n`,
    /// and both fields' domains start `[1, g, ...]` with different generators.
    #[test]
    fn test_gf2k_domain_cache_separates_field_types() {
        let a = get_or_create_gf2k_domain::<Gf256>(8).expect("Gf256 domain must exist");
        let b = get_or_create_gf2k_domain::<Gf2p4>(8).expect("Gf2p4 domain must exist");
        let fresh_a = Gf2kDomain::<Gf256>::new(8).expect("Gf256 domain must exist");
        let fresh_b = Gf2kDomain::<Gf2p4>::new(8).expect("Gf2p4 domain must exist");
        assert_eq!(a.elements(), fresh_a.elements());
        assert_eq!(b.elements(), fresh_b.elements());
    }

    /// An oversized `n` must error exactly as `Gf2kDomain::new` does, and must not be admitted to
    /// the cache — otherwise a rejected size would still cost an entry against the cap. Asserted
    /// per key rather than by cache size, because the cache is process-global and sibling tests
    /// run concurrently against it.
    #[test]
    fn test_gf2k_domain_rejects_and_does_not_cache_oversized() {
        assert!(get_or_create_gf2k_domain::<Gf2p4>(16).is_err());
        assert!(get_or_create_gf2k_domain::<Gf256>(256).is_err());
        assert!(
            !gf2k_cache_contains(&GF2K_DOMAIN_CACHE, (TypeId::of::<Gf2p4>(), 16)),
            "a rejected Gf2p4 domain size was admitted to the cache"
        );
        assert!(
            !gf2k_cache_contains(&GF2K_DOMAIN_CACHE, (TypeId::of::<Gf256>(), 256)),
            "a rejected Gf256 domain size was admitted to the cache"
        );
    }

    /// `g0` from the cache must equal the product recomputed by hand from the same domain.
    #[test]
    fn test_cached_g0_matches_fresh() {
        for n in [1usize, 4, 7, 10, 13] {
            let domain = Gf2kDomain::<Gf256>::new(n).expect("domain must exist");
            let mut expected = Poly::<Gf256>::one();
            for i in 0..n {
                expected = &expected * &Poly::monomial(domain.element(i));
            }
            let got = compute_g0_from_domain::<Gf256>(n).expect("g0 must be computable");
            assert_eq!(got.coeffs, expected.coeffs, "cached g0 diverged at n={n}");
            assert_eq!(got.degree(), n, "g0 must have degree n");
        }
    }

    /// Same liveness check as the domain one: the second lookup must hit the cache.
    #[test]
    fn test_g0_is_memoized() {
        assert!(compute_g0_from_domain::<Gf256>(11).is_ok());
        let a = get_cached_gf2k_g0::<Gf256>(11);
        let b = get_cached_gf2k_g0::<Gf256>(11);
        if gf2k_cache_contains(&GF2K_G0_CACHE, (TypeId::of::<Gf256>(), 11)) {
            let (a, b) = (a.expect("g0 must be cached"), b.expect("g0 must be cached"));
            assert!(
                Arc::ptr_eq(&a, &b),
                "g0 was recomputed despite being resident in the cache"
            );
        }
    }

    /// The admission rule is the whole of the memory bound, so it is tested directly rather than
    /// by filling the process-global map (which would make every sibling test's cache-residency
    /// guard vacuous).
    #[test]
    fn test_gf2k_cache_admission_is_bounded() {
        assert!(gf2k_cache_admits(0, false), "empty cache must admit");
        assert!(
            gf2k_cache_admits(MAX_CACHED_GF2K_DOMAINS - 1, false),
            "cache below the cap must admit"
        );
        assert!(
            !gf2k_cache_admits(MAX_CACHED_GF2K_DOMAINS, false),
            "cache at the cap must refuse a new key"
        );
        assert!(
            gf2k_cache_admits(MAX_CACHED_GF2K_DOMAINS, true),
            "refreshing a resident key cannot grow the map and must be allowed"
        );
    }

    /// A sweep over every size a field admits must return correct values whether or not each one
    /// was memoized — the cap degrades performance, never correctness. `Gf2p4` caps at 15 points,
    /// so this cannot monopolize the shared cache.
    #[test]
    fn test_gf2k_domain_sweep_is_correct_regardless_of_caching() {
        for n in 1..=<Gf2p4 as BinaryField>::MAX_DOMAIN_SIZE {
            let cached = get_or_create_gf2k_domain::<Gf2p4>(n).expect("domain must exist");
            let fresh = Gf2kDomain::<Gf2p4>::new(n).expect("domain must exist");
            assert_eq!(
                cached.elements(),
                fresh.elements(),
                "domain returned for n={n} was wrong"
            );
        }
        assert!(
            gf2k_cache_len(&GF2K_DOMAIN_CACHE) <= MAX_CACHED_GF2K_DOMAINS,
            "domain cache exceeded MAX_CACHED_GF2K_DOMAINS"
        );
    }
}
