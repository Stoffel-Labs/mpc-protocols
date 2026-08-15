use crate::common::ProtocolSessionId;
use crate::honeybadger::{
    fpmul::build_all_f_polys,
    prss::{PrssError, PRSS_KEY_LEN},
    robust_interpolate::robust_interpolate::RobustShare,
    SessionId,
};
use ark_ff::{FftField, PrimeField};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain, Polynomial};
use hmac::{Hmac, Mac};
use itertools::Itertools;
use num_bigint::BigUint;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Fixed label for the KDF, per NIST SP 800-108. Bump the version suffix if the derivation
/// changes in any way — every key's entire output stream depends on it.
const KDF_LABEL: &[u8] = b"STOFFEL-PRSS-v1";

/// All maximal unqualified sets, in the canonical order every party must agree on.
///
/// The ordering *is* the wire format for key indices: a party's key for rank `r` must be the same
/// set as every other party's rank `r`. `Itertools::combinations` yields lexicographic order over
/// ascending indices, which is deterministic across platforms and versions.
pub fn all_tsets(n: usize, t: usize) -> Vec<Vec<usize>> {
    (0..n).combinations(t).collect()
}

/// Ranks of the sets party `id` is *outside* of — the `C(n-1, t)` sets it holds a key for.
pub fn held_ranks(n: usize, t: usize, id: usize) -> Vec<usize> {
    all_tsets(n, t)
        .into_iter()
        .enumerate()
        .filter_map(|(rank, tset)| (!tset.contains(&id)).then_some(rank))
        .collect()
}

/// Canonical, hand-rolled encoding of the PRF input context.
///
/// Deliberately not `serde`/`bincode`: a serialization-format change would silently repoint every
/// derivation, and there is no message exchange left to notice the divergence. Fixed-width
/// big-endian only.
fn context_bytes(session_id: SessionId) -> [u8; 16] {
    let mut ctx = [0u8; 16];
    ctx[0] = session_id
        .calling_protocol()
        .map(|p| p as u8)
        .unwrap_or(0xFF);
    ctx[1..5].copy_from_slice(&session_id.instance_id().to_be_bytes());
    ctx[5..13].copy_from_slice(&session_id.exec_id().to_be_bytes());
    ctx[13] = session_id.sub_id();
    ctx[14] = session_id.round_id();
    // Domain-separator slot, fixed while PRandInt masks are the only consumer. A second consumer
    // takes a different value here; keeping 0x01 for masks leaves their keystream unchanged.
    ctx[15] = 0x01;
    ctx
}

/// Fixed output-length parameter for the KDF.
///
/// SP 800-108 binds a derivation to its requested length. We hold it constant instead, so that
/// the keystream for a given `(key, context)` is one fixed sequence regardless of how many values
/// any particular call asks for. That is what lets masks be addressed by absolute index: two
/// parties requesting different *ranges* still agree on the value at a given position. Feeding
/// the request size in here instead would make a partially-filled pool derive a completely
/// different stream. Still a counter-mode KDF over a PRF, so the security argument is unchanged.
const KDF_L_BITS: u32 = u32::MAX;

/// NIST SP 800-108 counter-mode KDF over HMAC-SHA256:
///
/// ```text
/// block_i = HMAC(key, [i]_4 ‖ Label ‖ 0x00 ‖ Context ‖ [L]_4)
/// ```
///
/// Returns the `count` integers at absolute positions `start .. start + count` of this
/// `(key, context)` stream, each uniform in `[0, 2^bits)`.
///
/// Position-addressed on purpose: the value at index `i` never depends on which range a caller
/// asked for, so a party topping up a half-full pool derives exactly the suffix the others
/// already hold.
///
/// **No rejection sampling** — callers use a power-of-two bound, so masking the top byte is
/// already exact. That matters beyond tidiness: rejection is the one step where two
/// implementations could consume different numbers of bytes and silently produce different
/// values, and PRSS has no message exchange left to catch it.
pub fn derive_ints_at(
    key: &[u8; PRSS_KEY_LEN],
    session_id: SessionId,
    start: usize,
    count: usize,
    bits: usize,
) -> Vec<BigUint> {
    if count == 0 || bits == 0 {
        return Vec::new();
    }

    const BLOCK: usize = 32;
    let width = bits.div_ceil(8);
    let ctx = context_bytes(session_id);

    // Seek to the first block covering byte `start * width`, then discard the partial prefix.
    let byte_offset = start * width;
    let first_block = byte_offset / BLOCK;
    let skip = byte_offset % BLOCK;
    let need = count * width;

    let mut stream = Vec::with_capacity((skip + need).next_multiple_of(BLOCK));
    let mut counter = first_block as u32;
    while stream.len() < skip + need {
        // `new_from_slice` only fails on a bad key length, and PRSS keys are fixed-width.
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(&counter.to_be_bytes());
        mac.update(KDF_LABEL);
        mac.update(&[0x00]);
        mac.update(&ctx);
        mac.update(&KDF_L_BITS.to_be_bytes());
        stream.extend_from_slice(&mac.finalize().into_bytes());
        counter += 1;
    }

    // Mask the top byte down when `bits` is not byte-aligned, so the result is uniform on
    // [0, 2^bits) rather than [0, 2^(8*width)).
    let top_mask: u8 = match bits % 8 {
        0 => 0xFF,
        r => (1u8 << r) - 1,
    };

    stream[skip..skip + need]
        .chunks_exact(width)
        .map(|chunk| {
            let mut bytes = chunk.to_vec();
            // Little-endian, matching the `BigUint::from_bytes_le` the RISS sampler used.
            if let Some(last) = bytes.last_mut() {
                *last &= top_mask;
            }
            BigUint::from_bytes_le(&bytes)
        })
        .collect()
}

/// Domain separator for turning folded RISS values into a PRSS key. Distinct from `KDF_LABEL` so
/// key derivation and keystream generation can never collide.
const KEY_LABEL: &[u8] = b"STOFFEL-PRSS-KEY-v1";

/// Entropy target for a derived key, in bits. The setup sizes its RISS batch to reach this.
pub const PRSS_KEY_ENTROPY_BITS: usize = 256;

/// Folds one unqualified set's RISS values into a 32-byte PRSS key.
///
/// `values` are the `r_T` this party agreed on for set `rank`; each carries at least
/// `k + l` bits unknown to the parties inside `T`, since at least one contributor outside their
/// view is honest. The caller is responsible for supplying enough of them — see
/// [`PRSS_KEY_ENTROPY_BITS`].
///
/// Every field is length-prefixed: `BigUint::to_bytes_be` is variable-width, so concatenating
/// values without lengths would let two different value lists hash to the same key.
pub fn derive_key_from_riss(rank: usize, values: &[BigUint]) -> [u8; PRSS_KEY_LEN] {
    let mut h = Sha256::new();
    h.update(KEY_LABEL);
    h.update((rank as u64).to_be_bytes());
    h.update((values.len() as u32).to_be_bytes());
    for v in values {
        let bytes = v.to_bytes_be();
        h.update((bytes.len() as u32).to_be_bytes());
        h.update(&bytes);
    }
    h.finalize().into()
}

/// One party's PRSS key material, plus the conversion coefficient each key is multiplied by.
///
/// `f_T(x_id)` depends only on the set and this party's evaluation point, never on the session, so
/// it is computed once here instead of rebuilding the Lagrange polynomials per invocation as the
/// RISS path did.
#[derive(Clone, Debug)]
pub struct PrssKeys<F: FftField> {
    id: usize,
    t: usize,
    /// `(rank, key, f_T(x_id))` for each set this party is outside of, ordered by rank.
    entries: Vec<(usize, [u8; PRSS_KEY_LEN], F)>,
}

impl<F: PrimeField> PrssKeys<F> {
    /// Build from the keys this party holds, indexed by rank in [`all_tsets`].
    ///
    /// Requires a key for every set the party is outside of — a partial store would silently
    /// produce shares of the wrong secret, since the missing terms just drop out of the sum.
    pub fn new(
        id: usize,
        n: usize,
        t: usize,
        keys: &[(usize, [u8; PRSS_KEY_LEN])],
    ) -> Result<Self, PrssError> {
        if id >= n {
            return Err(PrssError::PartyOutOfRange { id, n });
        }

        let tsets = all_tsets(n, t);
        let held = held_ranks(n, t, id);
        if keys.len() != held.len() {
            return Err(PrssError::KeyCountMismatch {
                expected: held.len(),
                got: keys.len(),
            });
        }

        let my_tsets: Vec<Vec<usize>> = held.iter().map(|r| tsets[*r].clone()).collect();
        let polys = build_all_f_polys::<F>(n, my_tsets)?;
        let domain = GeneralEvaluationDomain::<F>::new(n)
            .ok_or(crate::common::share::ShareError::NoSuitableDomain(n))?;
        let x_id = domain.element(id);

        let mut entries = Vec::with_capacity(held.len());
        for rank in held {
            let key = keys
                .iter()
                .find_map(|(r, k)| (*r == rank).then_some(*k))
                .ok_or(PrssError::MissingKey(rank))?;
            let coeff = polys[&tsets[rank]].evaluate(&x_id);
            entries.push((rank, key, coeff));
        }

        Ok(Self { id, t, entries })
    }

    /// Number of keys held — `C(n-1, t)`.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// This party's Shamir shares of the masks at absolute positions `start .. start + count`,
    /// each uniform in `[0, 2^bits)`.
    ///
    /// Purely local: `s_j = Σ_T ψ_{r_T}(sid) · f_T(x_j)`, with no communication. Every party must
    /// pass the identical `session_id`, `purpose`, `count` and `bits` — the derivation is
    /// deterministic, so a mismatch on any of them yields shares of *different* secrets that no
    /// message exchange exists to catch.
    ///
    /// The reconstructed secret is the sum over **all** `C(n,t)` sets, so it lies in
    /// `[0, C(n,t) · 2^bits)`, not `[0, 2^bits)`. Callers sizing a mask against the field must
    /// budget for that.
    pub fn shares_at(
        &self,
        session_id: SessionId,
        start: usize,
        count: usize,
        bits: usize,
    ) -> Result<Vec<RobustShare<F>>, PrssError> {
        if bits >= F::MODULUS_BIT_SIZE as usize {
            return Err(PrssError::WidthExceedsField { bits });
        }

        let mut shares = vec![RobustShare::new(F::zero(), self.id, self.t); count];
        for (_, key, coeff) in &self.entries {
            let values = derive_ints_at(key, session_id, start, count, bits);
            for (share, value) in shares.iter_mut().zip(&values) {
                share.share[0] += F::from(value.clone()) * coeff;
            }
        }
        Ok(shares)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::SecretSharingScheme;
    use crate::honeybadger::ProtocolType;
    use ark_bls12_381::Fr;
    use ark_ff::Zero;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    const BITS: usize = 64;

    fn sid(exec: u64) -> SessionId {
        SessionId::new(
            ProtocolType::PRandInt,
            SessionId::pack_slot(exec, 0, 0),
            111,
        )
    }

    /// Deal one key per maximal unqualified set, then hand each party the keys for the sets it is
    /// outside of — i.e. what the one-time setup protocol will produce.
    fn deal_keys(n: usize, t: usize) -> Vec<Vec<(usize, [u8; PRSS_KEY_LEN])>> {
        let mut rng = StdRng::seed_from_u64(7);
        let tsets = all_tsets(n, t);
        let all: Vec<[u8; PRSS_KEY_LEN]> = (0..tsets.len()).map(|_| rng.gen()).collect();
        (0..n)
            .map(|id| {
                held_ranks(n, t, id)
                    .into_iter()
                    .map(|rank| (rank, all[rank]))
                    .collect()
            })
            .collect()
    }

    fn build_all(n: usize, t: usize) -> Vec<PrssKeys<Fr>> {
        let dealt = deal_keys(n, t);
        (0..n)
            .map(|id| PrssKeys::<Fr>::new(id, n, t, &dealt[id]).unwrap())
            .collect()
    }

    #[test]
    fn every_party_holds_c_n_minus_1_choose_t_keys() {
        for (n, t, expected) in [(4, 1, 3), (5, 1, 4), (7, 2, 15), (10, 3, 84)] {
            let keys = build_all(n, t);
            for k in &keys {
                assert_eq!(k.len(), expected, "n={n} t={t}");
            }
            assert_eq!(all_tsets(n, t).len(), (0..n).combinations(t).count());
        }
    }

    /// The property PRSS removes the network's ability to police: two parties holding the same
    /// key must derive byte-identical values for the same session.
    #[test]
    fn derivation_is_bit_exact_across_parties() {
        let n = 7;
        let t = 2;
        let dealt = deal_keys(n, t);

        for rank in 0..all_tsets(n, t).len() {
            let holders: Vec<usize> = (0..n)
                .filter(|id| dealt[*id].iter().any(|(r, _)| *r == rank))
                .collect();
            assert!(!holders.is_empty());

            let reference = {
                let key = dealt[holders[0]]
                    .iter()
                    .find_map(|(r, k)| (*r == rank).then_some(*k))
                    .unwrap();
                derive_ints_at(&key, sid(9), 0, 8, BITS)
            };

            for id in &holders[1..] {
                let key = dealt[*id]
                    .iter()
                    .find_map(|(r, k)| (*r == rank).then_some(*k))
                    .unwrap();
                let got = derive_ints_at(&key, sid(9), 0, 8, BITS);
                assert_eq!(got, reference, "rank {rank} diverged at party {id}");
            }
        }
    }

    #[test]
    fn outputs_respect_the_declared_width() {
        let key = [0x5au8; PRSS_KEY_LEN];
        for bits in [1usize, 7, 8, 63, 64, 100, 128] {
            let bound = BigUint::from(1u8) << bits;
            for v in derive_ints_at(&key, sid(1), 0, 32, bits) {
                assert!(v < bound, "value {v} exceeded 2^{bits}");
            }
        }
    }

    #[test]
    fn distinct_sessions_give_distinct_values() {
        let key = [0x11u8; PRSS_KEY_LEN];
        let a = derive_ints_at(&key, sid(1), 0, 16, BITS);
        let b = derive_ints_at(&key, sid(2), 0, 16, BITS);
        assert_ne!(a, b);
        // ... and a repeated session id repeats the value, which is exactly why callers must
        // never reuse one.
        let a_again = derive_ints_at(&key, sid(1), 0, 16, BITS);
        assert_eq!(a, a_again);
    }

    #[test]
    fn distinct_keys_give_distinct_values() {
        let a = derive_ints_at(&[1u8; PRSS_KEY_LEN], sid(1), 0, 16, BITS);
        let b = derive_ints_at(&[2u8; PRSS_KEY_LEN], sid(1), 0, 16, BITS);
        assert_ne!(a, b);
    }

    /// The whole point: the locally-derived shares must reconstruct as a genuine degree-`t`
    /// Shamir sharing, with no communication anywhere.
    #[test]
    fn shares_reconstruct_as_a_valid_degree_t_sharing() {
        for (n, t) in [(4usize, 1usize), (5, 1), (7, 2)] {
            let keys = build_all(n, t);
            let count = 4;

            let per_party: Vec<Vec<RobustShare<Fr>>> = keys
                .iter()
                .map(|k| k.shares_at(sid(3), 0, count, BITS).unwrap())
                .collect();

            for i in 0..count {
                let shares: Vec<RobustShare<Fr>> =
                    (0..n).map(|id| per_party[id][i].clone()).collect();
                let (coeffs, secret) =
                    RobustShare::recover_secret(&shares, n, t).expect("degree-t reconstruction");
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
                assert!(!secret.is_zero(), "n={n} t={t}: secret {i} was zero");
            }
        }
    }

    /// The reconstructed value sums over all `C(n,t)` sets, so it can exceed `2^bits`. Pin the
    /// real bound so a caller sizing a mask against the field has something to rely on.
    #[test]
    fn reconstructed_secret_respects_the_summed_bound() {
        let (n, t) = (4usize, 1usize);
        let keys = build_all(n, t);
        let count = 8;
        let n_tsets = all_tsets(n, t).len();
        let bound = BigUint::from(n_tsets) << BITS;

        let per_party: Vec<Vec<RobustShare<Fr>>> = keys
            .iter()
            .map(|k| k.shares_at(sid(4), 0, count, BITS).unwrap())
            .collect();

        for i in 0..count {
            let shares: Vec<RobustShare<Fr>> = (0..n).map(|id| per_party[id][i].clone()).collect();
            let (_, secret) = RobustShare::recover_secret(&shares, n, t).unwrap();
            assert!(
                BigUint::from(secret.into_bigint()) < bound,
                "secret exceeded C(n,t)·2^bits"
            );
        }
    }

    /// The property that makes pool top-ups safe: the value at an absolute index never depends
    /// on which range was requested. A party filling 4..8 must land on exactly what a party that
    /// derived 0..8 in one go already holds.
    #[test]
    fn position_addressing_is_range_independent() {
        let key = [0x3cu8; PRSS_KEY_LEN];
        for bits in [8usize, 12, 64, 104] {
            let whole = derive_ints_at(&key, sid(5), 0, 8, bits);
            let head = derive_ints_at(&key, sid(5), 0, 4, bits);
            let tail = derive_ints_at(&key, sid(5), 4, 4, bits);
            assert_eq!([head, tail].concat(), whole, "bits={bits}");

            // Also from an offset that lands mid-block, which is where the skip arithmetic bites.
            let mid = derive_ints_at(&key, sid(5), 3, 2, bits);
            assert_eq!(mid, whole[3..5], "bits={bits} mid-block");
        }
    }

    /// Same property at the share level, which is what `ensure_prandint_shares` relies on when a
    /// party tops up a half-full pool.
    #[test]
    fn topping_up_a_partial_pool_agrees_with_a_full_derivation() {
        let (n, t) = (4usize, 1usize);
        let keys = build_all(n, t);

        for k in &keys {
            let whole = k.shares_at(sid(6), 0, 6, BITS).unwrap();
            let head = k.shares_at(sid(6), 0, 2, BITS).unwrap();
            let tail = k.shares_at(sid(6), 2, 4, BITS).unwrap();
            assert_eq!([head, tail].concat(), whole);
        }
    }

    /// Distinct instances must not share a keystream even though the execution id is now fixed.
    #[test]
    fn distinct_instances_give_distinct_values() {
        let key = [0x77u8; PRSS_KEY_LEN];
        let a = SessionId::new(ProtocolType::PRandInt, SessionId::pack_slot(0, 0, 0), 111);
        let b = SessionId::new(ProtocolType::PRandInt, SessionId::pack_slot(0, 0, 0), 222);
        assert_ne!(
            derive_ints_at(&key, a, 0, 8, BITS),
            derive_ints_at(&key, b, 0, 8, BITS)
        );
    }

    #[test]
    fn rejects_a_partial_key_store() {
        let (n, t) = (7usize, 2usize);
        let dealt = deal_keys(n, t);
        let mut short = dealt[0].clone();
        short.pop();
        assert!(matches!(
            PrssKeys::<Fr>::new(0, n, t, &short),
            Err(PrssError::KeyCountMismatch { .. })
        ));
    }

    #[test]
    fn rejects_a_width_that_does_not_fit_the_field() {
        let keys = build_all(4, 1);
        assert!(matches!(
            keys[0].shares_at(sid(1), 0, 1, Fr::MODULUS_BIT_SIZE as usize),
            Err(PrssError::WidthExceedsField { .. })
        ));
    }
}
