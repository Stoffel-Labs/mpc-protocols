//! PRSS/PRZS **position discipline** — the test the audit said does not exist.
//!
//! # Why this file exists
//!
//! PRSS and PRZS are stateless and position-addressed: `derive_ints_at` seeks to byte
//! `start * ceil(bits/8)` of the `(label, key, context)` keystream and reads from there. Nothing
//! in either primitive remembers what it has already produced, so **"never derive the same
//! position twice" is entirely an obligation on the caller**. Breaking it is a total privacy
//! break — the same pseudorandom value masks two different openings, and the adversary recovers
//! the difference of the two secrets by subtraction.
//!
//! It is also **completely invisible to an all-honest test suite**. Every other test in this repo
//! would still pass with every cursor pinned at zero: the protocols would produce shares that
//! reconstruct to the right answers, degrees would be right, `c == ab` would hold, and the daBits
//! would still be bits. Correctness does not depend on freshness; only privacy does. That is what
//! makes this plan §6.5 error 3 and the VERIA-222 cursor-rewind class, and it is why the property
//! needs a file of its own rather than an assertion bolted onto a protocol test.
//!
//! # What is asserted, and by which of two independent detectors
//!
//! Neither detector alone is sufficient, so this file runs both and they overlap deliberately.
//!
//! 1. **The value ledger** ([`ValueLedger`]) drives the **real production entry points** and
//!    fingerprints every pseudorandom value they derive, as the tuple of all `n` parties' shares
//!    at one position. Any two derivations that land on one position produce *byte-identical*
//!    output, so an exact reuse anywhere behind those entry points shows up as a duplicate
//!    fingerprint — without this file needing to know how the entry point addresses anything.
//!    That is its strength: it observes the thing that actually masks an opening, not a model of
//!    it. Its blind spot is **partial** overlap, where two ranges share some bytes but are not
//!    equal; the values then differ and the ledger sees nothing. A collapsed `beta`/`psi`
//!    separation is exactly that shape — the two draws are 1 bit and `lambda` bits wide, so they
//!    read overlapping bytes without producing a single equal value — and it is caught by the
//!    second detector, not the first.
//! 2. **The interval ledger** ([`IntervalLedger`]) closes that blind spot. It claims from a
//!    [`PrssAllocator`] directly — where `start`, `len`, `bits` and the session are all visible —
//!    flattens each claim to the **byte** interval it will read, and asserts pairwise
//!    disjointness within every keystream. Bytes rather than positions is the whole point: the
//!    same `start` at two widths, or at two strides, reads overlapping bytes, and an
//!    index-keyed ledger would call that disjoint (invariants P2 and P3 in
//!    `honeybadger::prss::window`).
//!
//! Between them the file covers the four consumers the audit named — **daBits** (`beta` and the
//! Mod2 mask `psi`), **`RandBit`** (`[a]`), **the PRZS re-randomisers** (`RandBit`'s degree-`2t`
//! zero sharing, and the PRZS halves of both domains' double sharings) and **GF triples**
//! (`GfDn07Double`) — plus the three dynamic properties: that a retry after an abort **burns** its
//! range rather than rewinding onto it, that concurrent sessions cannot race onto one position,
//! and that the checkers themselves have teeth.
//!
//! # Phase: PREPROCESSING ONLY
//!
//! Every derivation here is local — zero rounds, zero bytes, no network, no timeout, no
//! broadcast, no abort path — which is why this file needs no `FakeNetwork` and starts no
//! `BadFakeNetwork` delay thread. The *sharings* it inspects are a mix of degree `t` and degree
//! `2t`, and the degree-`2t` ones are preprocessing objects: `RandBit` spends its re-randomiser
//! on `MulPub`, and the double sharings are spent on DN07 degree reduction. Nothing in this file
//! is reachable from the online A2B/B2A path, and nothing it adds becomes reachable from it.
//!
//! # Conventions
//!
//! Helpers are local rather than in `tests/utils/`, following `przs_test.rs`: this file needs no
//! network fixture, and `tests/utils/mod.rs` is shared with every other integration test. The
//! arithmetic field is `GoldilocksField`, what the crate actually deploys, so that a width or
//! reduction bug hidden by a 255-bit modulus's headroom has nowhere to hide.
//!
//! # Why the `Gf256` assertions are bounded, and why every seed is a constant
//!
//! A `Gf256` fingerprint is the tuple of `n` parties' shares of a degree-`t` sharing, and a
//! degree-`t` polynomial over `GF(2^8)` is pinned by `t+1` coefficients — so the tuple carries
//! about `(t+1) * 8` bits no matter how many parties are in it, i.e. **32 bits** at `t = 3`. This
//! file therefore keeps the number of `GF` fingerprints in the low hundreds, where the birthday
//! bound is around `300^2 / 2^32 ~= 2e-5`. The arithmetic side has no such constraint: one
//! Goldilocks share is already 64 bits, and the tuple is `64n`.
//!
//! Every RNG here is seeded from a constant, which is what makes that residual bound workable: a
//! chance collision is deterministic, so it recurs on every run instead of appearing as a flake.
//! If a `GF` collision is ever reported, check whether the two provenances in the failure message
//! name genuinely different derivations; if they do not, bump `KEY_SEED` to re-roll every
//! keystream in the file and confirm it moves.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use ark_ff::PrimeField;
use ark_std::rand::{rngs::StdRng, RngCore, SeedableRng};
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use sha2::Sha256;

use stoffelcrypto::common::gf2k::field::Gf256;
use stoffelcrypto::common::math::goldilocks::GoldilocksField;
use stoffelcrypto::common::rbc::rbc::Avid;
use stoffelcrypto::common::ProtocolSessionId;
use stoffelcrypto::honeybadger::dabit::prss_dabit::PSI_SUB_ID;
use stoffelcrypto::honeybadger::dn07::double_share::{
    GfPrssDoubleShareSource, PrssDoubleShareSource,
};
use stoffelcrypto::honeybadger::fpmul::prandint::PRandIntNode;
use stoffelcrypto::honeybadger::gf_prss::gf_prss::GfPrssKeys;
use stoffelcrypto::honeybadger::prss::prss::{
    all_tsets, derive_ints_at, derive_ints_at_domain, derive_uniform_ints_at, held_ranks,
    PrssDomain, PrssKeys,
};
use stoffelcrypto::honeybadger::prss::{PrssAllocator, PrssStream, PRSS_KEY_LEN};
use stoffelcrypto::honeybadger::przs::gf_przs::GfPrzsKeys;
use stoffelcrypto::honeybadger::przs::przs::PrzsKeys;
use stoffelcrypto::honeybadger::przs::{
    derive_zero_coeff_ints_at, PrzsCoefficient, PrzsDomain, PRZS_KDF_LABEL,
    PRZS_REDUCTION_SLACK_BITS,
};
use stoffelcrypto::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelcrypto::honeybadger::{ProtocolType, SessionId};

type F = GoldilocksField;
type K = Gf256;

/// `(n, t)` at `n = 3t+1`. `(10, 3)` is the size the plan's cost table is quoted at; `(7, 2)` is
/// carried alongside because a `t`-strided PRZS layout that happens to be right at one `t` is not
/// evidence about another.
const CONFIGS: [(usize, usize); 2] = [(10, 3), (7, 2)];

/// Instance id for every session in this file. Arbitrary, but fixed: it lands in `ctx16`, so
/// varying it would silently separate keystreams that these tests want to see collide.
const INSTANCE: u32 = 0x0005_0F05;

/// Seed for the dealt key material. Bump it to re-roll every keystream in this file.
const KEY_SEED: u64 = 0x5EED_0F05;

// =================================================================================================
// Fixtures
// =================================================================================================

/// Deals one key per maximal unqualified set and hands each party the keys for the sets it is
/// *outside* of — what the one-time PRSS setup produces.
///
/// Dealing centrally is a total break of the privacy guarantee (the caller sees every key), which
/// is what makes it the right harness here: this file is about whether positions are reused, and
/// the adversary it has in mind is one that already knows the keys.
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

/// One `PrssDoubleShareSource` per party: the `F`-side production source for `RandBit` material
/// and for Beaver-triple material.
fn f_sources(n: usize, t: usize) -> Vec<PrssDoubleShareSource<F>> {
    let dealt = deal_keys(n, t, KEY_SEED);
    (0..n)
        .map(|id| {
            PrssDoubleShareSource::new(
                PrssKeys::<F>::new(id, n, t, &dealt[id]).unwrap(),
                PrzsKeys::<F>::new(id, n, t, &dealt[id]).unwrap(),
            )
            .unwrap()
        })
        .collect()
}

/// One `GfPrssDoubleShareSource` per party, over **the same dealt keys** — which is what
/// `setup_prss_keys` does, and what makes one allocator able to govern both domains.
fn gf_sources(n: usize, t: usize) -> Vec<GfPrssDoubleShareSource<K>> {
    let dealt = deal_keys(n, t, KEY_SEED);
    (0..n)
        .map(|id| {
            GfPrssDoubleShareSource::new(
                GfPrssKeys::<K>::new(id, n, t, &dealt[id]).unwrap(),
                GfPrzsKeys::<K>::new(id, n, t, &dealt[id]).unwrap(),
            )
            .unwrap()
        })
        .collect()
}

/// The bare PRSS stores, for the daBit half.
///
/// `PrssDaBitNode` keeps its stores private and its `generate` needs a network for the Mod2
/// opening, so the daBit derivations are reproduced here from the same public calls `generate`
/// makes — `PrssAllocator::claim_dabit_batch` for the positions, then
/// `PrssKeys::shares_at_in(windows.seed())` for `beta` on the `F` side,
/// `GfPrssKeys::bit_shares_at_in(windows.seed())` for its `K` twin, and
/// `PrssKeys::shares_at_in(windows.psi())` for the Mod2 mask. The **addressing** is therefore not
/// modelled here at all any more: it comes out of the allocator, which is the same object
/// production claims from.
fn f_prss(n: usize, t: usize) -> Vec<PrssKeys<F>> {
    let dealt = deal_keys(n, t, KEY_SEED);
    (0..n)
        .map(|id| PrssKeys::<F>::new(id, n, t, &dealt[id]).unwrap())
        .collect()
}

fn k_prss(n: usize, t: usize) -> Vec<GfPrssKeys<K>> {
    let dealt = deal_keys(n, t, KEY_SEED);
    (0..n)
        .map(|id| GfPrssKeys::<K>::new(id, n, t, &dealt[id]).unwrap())
        .collect()
}

/// One allocator per party, each stamped with that party's own key-family fingerprint.
///
/// The fingerprint is per-party by construction (every party holds a different `C(n-1,t)` subset)
/// because its job is local: "is this window counted against the keys I am about to derive
/// with?". Positions still agree across parties, because every allocator starts at zero and every
/// party claims in the same order — which is the property the lockstep drivers below rely on.
fn f_allocators(sources: &[PrssDoubleShareSource<F>]) -> Vec<PrssAllocator> {
    sources
        .iter()
        .map(|s| PrssAllocator::new(INSTANCE, s.key_family_id()))
        .collect()
}

/// A session id shaped like a daBit parent's, for the **detector self-tests** only.
///
/// Production never builds one of these: `claim_dabit_batch` mints the session inside the window,
/// and nothing derives from a bare `SessionId` on this path any more. It survives here because
/// [`both_detectors_report_a_reuse_that_is_deliberately_introduced`] has to *fabricate* collisions
/// that the real API makes unrepresentable — a detector nobody has seen fail is a detector that
/// might be vacuous.
fn dabit_parent(exec: u64) -> SessionId {
    SessionId::new(
        ProtocolType::DaBit,
        SessionId::pack_slot(exec, 0, 0),
        INSTANCE,
    )
}

/// The `psi` counterpart of [`dabit_parent`], and for the same reason. Carries only the `ctx[13]`
/// half of the real separation; the `ctx[15]` half lives on the window's [`PrssDomain`] and cannot
/// be forged into a `SessionId` at all, which is rather the point of adding it.
fn dabit_psi(exec: u64) -> SessionId {
    SessionId::new(
        ProtocolType::DaBit,
        SessionId::pack_slot(exec, PSI_SUB_ID, 0),
        INSTANCE,
    )
}

/// One allocator per party for the daBit drivers, stamped with that party's `PrssKeys` family.
///
/// Separate from [`f_allocators`] only because the daBit fixtures build the bare stores rather
/// than a [`PrssDoubleShareSource`]; both report the same fingerprint for the same dealt keys.
fn dabit_allocators(stores: &[PrssKeys<F>]) -> Vec<PrssAllocator> {
    stores
        .iter()
        .map(|s| PrssAllocator::new(INSTANCE, s.key_family_id()))
        .collect()
}

/// A representative Mod2 mask width. The exact `lambda` a deployment picks is a leak-budget
/// question and is settled in `DaBitLeakBudget`; for the position question only two things matter,
/// and both are exercised — that `psi` is drawn at a *different width* from `beta` (1 bit), and
/// that it is drawn from a *different session* regardless.
const LAMBDA: usize = 40;

// =================================================================================================
// Detector 1 — the value ledger
// =================================================================================================

/// Fingerprints every derived value and reports any that appears twice.
///
/// The fingerprint of one derivation is the tuple of **all `n` parties'** share values at that
/// position. Using the whole tuple rather than one party's share is both more faithful — a
/// "derivation" in this protocol is a position across all parties — and materially stronger,
/// since it multiplies the entropy the birthday bound is taken over.
///
/// Collisions are *collected* rather than asserted on the spot, so that a failure can name both
/// provenances instead of only the second. That is the difference between "a position was reused"
/// and "`GF triple doubles (przs half) wave 3[2]` reused the position of `edaBit filter wave
/// 1[7]`", and it is the whole diagnostic value of the file.
#[derive(Default)]
struct ValueLedger {
    seen: BTreeMap<String, String>,
    reuse: Vec<(String, String)>,
}

impl ValueLedger {
    fn record(&mut self, provenance: String, fingerprint: String) {
        match self.seen.get(&fingerprint) {
            Some(first) => self.reuse.push((first.clone(), provenance)),
            None => {
                self.seen.insert(fingerprint, provenance);
            }
        }
    }

    /// Records every position of a batch given party-major, i.e. `per_party[party][position]`.
    fn record_batch<T: std::fmt::Debug>(&mut self, provenance: &str, per_party: &[Vec<T>]) {
        assert!(!per_party.is_empty(), "{provenance}: no parties");
        let count = per_party[0].len();
        assert!(count > 0, "{provenance}: empty batch");
        for (party, values) in per_party.iter().enumerate() {
            assert_eq!(
                values.len(),
                count,
                "{provenance}: party {party} produced a different batch length, so the parties \
                 are not deriving the same positions and every other assertion here is moot"
            );
        }
        for pos in 0..count {
            let mut fingerprint = String::new();
            for values in per_party {
                fingerprint.push_str(&format!("{:?}|", values[pos]));
            }
            self.record(format!("{provenance}[{pos}]"), fingerprint);
        }
    }

    fn distinct(&self) -> usize {
        self.seen.len()
    }

    fn assert_no_reuse(&self, what: &str) {
        assert!(
            self.reuse.is_empty(),
            "{what}: {} derivation(s) landed on an already-derived position. Each pair below \
             produced byte-identical pseudorandom output, which means one value masked two \
             different openings:\n{}",
            self.reuse.len(),
            self.reuse
                .iter()
                .map(|(a, b)| format!("  {a}  <-->  {b}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}

// =================================================================================================
// Detector 2 — the interval ledger
// =================================================================================================

/// The SP 800-108 **keystream family** a derivation reads from.
///
/// This, together with `ctx16` (which the session id determines in full), is what actually
/// addresses a keystream. It is deliberately **not** [`PrssStream`]: a `PrssStream` variant is a
/// name this crate gives a consumer, and two different variants can address one and the same
/// keystream — which is precisely invariant P1, and precisely the collision that must be caught.
/// Keying the ledger on the variant instead would make the checker skip the pairs it exists to
/// find; that mistake was in this file until a deliberately reintroduced `beta`/`psi` collision
/// walked straight past it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Keystream {
    /// `derive_ints_at` under `KDF_LABEL`, stride 1. The **mask** family: `PrssKeys::shares_at`
    /// (the daBit seed, the Mod2 mask, a `PRandInt` mask) and *every* `GfPrssKeys` draw, including
    /// `uniform_shares_at` — the binary store has no separate uniform label, because it reaches
    /// `shares_at` for all of them.
    PrssMask,
    /// `derive_uniform_ints_at` under `KDF_LABEL_UNIFORM`, stride 1. A distinct label from
    /// [`Self::PrssMask`], which is what lets `RandBit`'s `[a]` and a daBit seed sit at one
    /// address without colliding.
    PrssUniform,
    /// `derive_zero_coeff_ints_at` in the arithmetic domain (`ctx[15] = 0x02`), stride `t`.
    PrzsArithmetic,
    /// `derive_zero_coeff_ints_at` in the binary domain, stride `t`. A distinct `ctx[15]` from the
    /// arithmetic one, so the two never share a keystream even at one session.
    PrzsBinary,
}

/// One claim, flattened to the byte interval it will actually read.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct Interval {
    /// Half of the keystream address. Ordered first so that sorting groups a keystream together.
    keystream: Keystream,
    /// The other half. `ctx16` is a function of `(tag, instance, exec, sub, round)`, all of which
    /// `SessionId`'s `Debug` prints, so the rendered session stands in for the whole context.
    session: String,
    lo: u128,
    hi: u128,
    /// Diagnostic only, and deliberately **not** part of the keystream identity — see
    /// [`Keystream`].
    stream: PrssStream,
    provenance: String,
}

/// Byte intervals, asserted pairwise disjoint within each `(stream, half, session)` keystream.
///
/// Two intervals on *different* sessions are on different keystreams and may overlap freely —
/// that is the whole point of the fresh-exec scheme, where every claim starts at position 0 of a
/// brand-new keystream.
#[derive(Default)]
struct IntervalLedger {
    intervals: Vec<Interval>,
}

impl IntervalLedger {
    /// Records the byte range `[start, start+count)` positions of one keystream reads, at
    /// `stride` elements of `bits` bits per position.
    #[allow(clippy::too_many_arguments)]
    fn record(
        &mut self,
        provenance: &str,
        stream: PrssStream,
        keystream: Keystream,
        session: SessionId,
        start: usize,
        count: usize,
        bits: usize,
        stride: usize,
    ) {
        let width = (bits.div_ceil(8) * stride) as u128;
        self.intervals.push(Interval {
            keystream,
            session: format!("{session:?}"),
            lo: (start as u128) * width,
            hi: ((start + count) as u128) * width,
            stream,
            provenance: provenance.to_string(),
        });
    }

    fn len(&self) -> usize {
        self.intervals.len()
    }

    /// The number of overlapping pairs, as this checker sees them. Returned rather than asserted
    /// so that the meta-test can require it to be **non**-zero.
    fn overlaps(&self) -> Vec<(Interval, Interval)> {
        let mut sorted = self.intervals.clone();
        sorted.sort();
        let mut out = Vec::new();
        for pair in sorted.windows(2) {
            let (a, b) = (&pair[0], &pair[1]);
            if a.keystream != b.keystream || a.session != b.session {
                continue;
            }
            if a.hi > b.lo {
                out.push((a.clone(), b.clone()));
            }
        }
        out
    }

    fn assert_pairwise_disjoint(&self, what: &str) {
        let overlaps = self.overlaps();
        assert!(
            overlaps.is_empty(),
            "{what}: {} pair(s) of claims read overlapping bytes of one keystream:\n{}",
            overlaps.len(),
            overlaps
                .iter()
                .map(|(a, b)| format!(
                    "  {} ({:?}) bytes [{}, {}) overlaps {} ({:?}) bytes [{}, {}) on keystream \
                     {:?} {}",
                    a.provenance,
                    a.stream,
                    a.lo,
                    a.hi,
                    b.provenance,
                    b.stream,
                    b.lo,
                    b.hi,
                    a.keystream,
                    a.session
                ))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}

// =================================================================================================
// Lockstep drivers over the production entry points
// =================================================================================================

/// Transposes a party-major batch of shares into the values this file fingerprints.
fn f_values(per_party: &[Vec<RobustShare<F>>]) -> Vec<Vec<F>> {
    per_party
        .iter()
        .map(|shares| shares.iter().map(|s| s.share[0]).collect())
        .collect()
}

/// `RandBit`'s two inputs, from every party, through the production entry point.
///
/// Returns `([a] per party, the degree-2t zero re-randomiser per party)`. The two are deliberately
/// kept apart rather than summed: `[a]` is the value whose square gets opened and the zero sharing
/// is the mask that hides it, so they must be independent — and each is its own keystream.
async fn drive_randbit(
    sources: &[PrssDoubleShareSource<F>],
    allocs: &[PrssAllocator],
    count: usize,
) -> (Vec<Vec<F>>, Vec<Vec<F>>) {
    let mut a = Vec::new();
    let mut z = Vec::new();
    for (source, alloc) in sources.iter().zip(allocs) {
        let (ai, zi) = source.randbit_material(alloc, count).await.unwrap();
        a.push(ai);
        z.push(zi);
    }
    (f_values(&a), f_values(&z))
}

/// An `F` Beaver triple's material, from every party, through the production entry point.
///
/// Returns `(a, b, the doubles' PRSS half, the doubles' PRZS half)`. The PRZS half is recovered as
/// `degree_2t - degree_t`, which is exactly the zero sharing the source added: recording the raw
/// `degree_2t` instead would record a value that is a *function of* the PRSS half, and a ledger
/// cannot tell a genuinely fresh PRZS draw from a repeated one through that.
#[allow(clippy::type_complexity)]
async fn drive_f_triples(
    sources: &[PrssDoubleShareSource<F>],
    allocs: &[PrssAllocator],
    count: usize,
) -> (Vec<Vec<F>>, Vec<Vec<F>>, Vec<Vec<F>>, Vec<Vec<F>>) {
    let (mut a, mut b, mut lo, mut hi) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for (source, alloc) in sources.iter().zip(allocs) {
        let m = source.triple_material(alloc, count).await.unwrap();
        a.push(m.a.iter().map(|s| s.share[0]).collect::<Vec<_>>());
        b.push(m.b.iter().map(|s| s.share[0]).collect::<Vec<_>>());
        lo.push(
            m.doubles
                .iter()
                .map(|d| d.degree_t.share[0])
                .collect::<Vec<_>>(),
        );
        hi.push(
            m.doubles
                .iter()
                .map(|d| d.degree_2t.share[0] - d.degree_t.share[0])
                .collect::<Vec<_>>(),
        );
    }
    (a, b, lo, hi)
}

/// `Gf2k` double sharings, from every party, through the production entry point.
///
/// Returns `(the PRSS half, the PRZS half)`. In characteristic 2 subtraction is addition, so the
/// PRZS half is recovered as `degree_2t + degree_t`.
async fn drive_gf_doubles(
    sources: &[GfPrssDoubleShareSource<K>],
    allocs: &[PrssAllocator],
    count: usize,
) -> (Vec<Vec<K>>, Vec<Vec<K>>) {
    let (mut lo, mut hi) = (Vec::new(), Vec::new());
    for (source, alloc) in sources.iter().zip(allocs) {
        let d = source.double_shares(alloc, count).await.unwrap();
        lo.push(d.iter().map(|x| x.degree_t.share).collect::<Vec<_>>());
        hi.push(
            d.iter()
                .map(|x| x.degree_2t.share + x.degree_t.share)
                .collect::<Vec<_>>(),
        );
    }
    (lo, hi)
}

/// One daBit batch's three derivations at exec id `exec`, from every party.
///
/// Returns `(beta on the F side, beta's K twin, the Mod2 mask psi)`. The first two come from one
/// `derive_ints_at` call's bytes converted into two domains — they are **one** derivation, and are
/// fingerprinted as one below for that reason.
#[allow(clippy::type_complexity)]
async fn drive_dabit(
    f: &[PrssKeys<F>],
    k: &[GfPrssKeys<K>],
    allocs: &[PrssAllocator],
    count: usize,
) -> (Vec<Vec<F>>, Vec<Vec<K>>, Vec<Vec<F>>) {
    let mut beta_f = Vec::with_capacity(f.len());
    let mut beta_k = Vec::with_capacity(k.len());
    let mut psi = Vec::with_capacity(f.len());
    for (party, alloc) in allocs.iter().enumerate() {
        // One claim, one exec, both keystreams — exactly `run_dabit_batch`. Every party's
        // allocator starts at zero and claims in the same order, so they agree on the exec with
        // nothing sent.
        let w = alloc.claim_dabit_batch(count, LAMBDA).await.unwrap();
        beta_f.push(
            f[party]
                .shares_at_in(w.seed())
                .unwrap()
                .iter()
                .map(|x| x.share[0])
                .collect::<Vec<_>>(),
        );
        beta_k.push(
            k[party]
                .bit_shares_at_in(w.seed())
                .unwrap()
                .iter()
                .map(|x| x.share)
                .collect::<Vec<_>>(),
        );
        psi.push(
            f[party]
                .shares_at_in(w.psi())
                .unwrap()
                .iter()
                .map(|x| x.share[0])
                .collect::<Vec<_>>(),
        );
    }
    (beta_f, beta_k, psi)
}

/// Fingerprints the daBit seed as the **single derivation it is**: the `F` conversion and the `K`
/// conversion of one `beta_T` draw, recorded together.
///
/// Recording the `K` half on its own would be a weak assertion — a degree-`t` sharing of a *bit*
/// over `GF(2^8)` carries only about `1 + 8t` bits of fingerprint — and recording it separately
/// would also misrepresent the protocol, in which the two halves are two readings of one set of
/// bytes rather than two derivations.
fn record_dabit_seed(
    ledger: &mut ValueLedger,
    provenance: &str,
    beta_f: &[Vec<F>],
    beta_k: &[Vec<K>],
) {
    let count = beta_f[0].len();
    for pos in 0..count {
        let mut fingerprint = String::new();
        for party in beta_f {
            fingerprint.push_str(&format!("{:?}|", party[pos]));
        }
        for party in beta_k {
            fingerprint.push_str(&format!("{:?}|", party[pos]));
        }
        ledger.record(format!("{provenance}[{pos}]"), fingerprint);
    }
}

// =================================================================================================
// The tests
// =================================================================================================

/// **Teeth.** Before trusting a green run of this file, both detectors must be shown to fail on a
/// reuse that is deliberately introduced.
///
/// Without this test a green file would be consistent with fingerprints that never collide and
/// intervals that are never compared — which is precisely the failure mode of a position test,
/// since the property under test is invisible in every other way.
#[test]
fn both_detectors_report_a_reuse_that_is_deliberately_introduced() {
    let (n, t) = (7, 2);
    let stores = f_prss(n, t);

    // -- the value ledger, against an exactly-repeated position ----------------------------------
    // Two draws at the same (session, start, bits) are the literal failure this file exists to
    // catch: `derive_ints_at` is a pure function of those, so the second call re-derives the
    // first's bytes.
    let sid = dabit_parent(0);
    let first: Vec<Vec<F>> = stores
        .iter()
        .map(|s| {
            s.shares_at(sid, 0, 3, 1)
                .unwrap()
                .iter()
                .map(|x| x.share[0])
                .collect()
        })
        .collect();
    let again: Vec<Vec<F>> = stores
        .iter()
        .map(|s| {
            s.shares_at(sid, 0, 3, 1)
                .unwrap()
                .iter()
                .map(|x| x.share[0])
                .collect()
        })
        .collect();

    let mut ledger = ValueLedger::default();
    ledger.record_batch("first batch", &first);
    ledger.record_batch("a rewound retry of the same batch", &again);
    assert_eq!(
        ledger.reuse.len(),
        3,
        "the value ledger failed to notice three re-derived positions; every other assertion in \
         this file that relies on it is therefore worthless"
    );
    assert_eq!(
        ledger.distinct(),
        3,
        "six recordings over three positions must leave three distinct fingerprints"
    );

    // -- the interval ledger, against a PARTIAL overlap -------------------------------------------
    // The case the value ledger provably cannot see: two ranges that share bytes without being
    // equal. Their derived values differ, so no fingerprint collides — and the privacy break is
    // just as total, because the shared bytes still mask two different openings.
    let mut intervals = IntervalLedger::default();
    intervals.record(
        "positions 0..4",
        PrssStream::RandBitA,
        Keystream::PrssUniform,
        sid,
        0,
        4,
        192,
        1,
    );
    intervals.record(
        "positions 2..6",
        PrssStream::RandBitA,
        Keystream::PrssUniform,
        sid,
        2,
        4,
        192,
        1,
    );
    assert_eq!(
        intervals.overlaps().len(),
        1,
        "the interval ledger failed to notice a partial byte overlap"
    );

    // The same two position ranges on two *different* sessions are two different keystreams and
    // must NOT be reported — a checker that flagged them would be unusable against the fresh-exec
    // scheme, where every claim legitimately starts at position zero.
    let mut across_sessions = IntervalLedger::default();
    across_sessions.record(
        "exec 0",
        PrssStream::RandBitA,
        Keystream::PrssUniform,
        dabit_parent(0),
        0,
        4,
        192,
        1,
    );
    across_sessions.record(
        "exec 1",
        PrssStream::RandBitA,
        Keystream::PrssUniform,
        dabit_parent(1),
        0,
        4,
        192,
        1,
    );
    assert!(
        across_sessions.overlaps().is_empty(),
        "two claims on different keystreams were reported as overlapping"
    );

    // -- the interval ledger, against two DIFFERENT streams on ONE keystream --------------------
    // Invariant P1, and the exact shape of a `beta`/`psi` collision: the two consumers have
    // different `PrssStream` names, and that is worth nothing, because a name is not an address.
    // The keystream identity is the SP 800-108 label plus `ctx16`, so a checker keyed on the
    // stream variant skips this pair entirely — which is what an earlier draft of this file did,
    // and why the case is pinned here rather than left to the reader's confidence.
    let mut p1 = IntervalLedger::default();
    p1.record(
        "daBit seed",
        PrssStream::DaBitSeed,
        Keystream::PrssMask,
        dabit_parent(0),
        0,
        8,
        1,
        1,
    );
    p1.record(
        "a Mod2 mask that landed on the seed's session",
        PrssStream::DaBitPsi,
        Keystream::PrssMask,
        dabit_parent(0),
        0,
        8,
        LAMBDA,
        1,
    );
    assert_eq!(
        p1.overlaps().len(),
        1,
        "two different streams on one keystream were not reported — the ledger is keyed on the \
         stream name rather than on the address"
    );

    // The real arrangement, separated by one byte of `ctx16`, must NOT be reported. A checker
    // that flagged this would be crying wolf on correct code.
    let mut separated = IntervalLedger::default();
    separated.record(
        "daBit seed",
        PrssStream::DaBitSeed,
        Keystream::PrssMask,
        dabit_parent(0),
        0,
        8,
        1,
        1,
    );
    separated.record(
        "the Mod2 mask at PSI_SUB_ID",
        PrssStream::DaBitPsi,
        Keystream::PrssMask,
        dabit_psi(0),
        0,
        8,
        LAMBDA,
        1,
    );
    assert!(
        separated.overlaps().is_empty(),
        "the real beta/psi separation was reported as a collision"
    );

    // Nor may two consumers at one address but under different SP 800-108 labels be reported:
    // `RandBit`'s `[a]` (uniform label) and its re-randomiser (PRZS) both address
    // `(RandBit, 0, 0)`, legitimately.
    let mut labelled = IntervalLedger::default();
    labelled.record(
        "RandBit [a]",
        PrssStream::RandBitA,
        Keystream::PrssUniform,
        sid,
        0,
        4,
        192,
        1,
    );
    labelled.record(
        "RandBit re-randomiser",
        PrssStream::RandBitZero,
        Keystream::PrzsArithmetic,
        sid,
        0,
        4,
        192,
        t,
    );
    assert!(
        labelled.overlaps().is_empty(),
        "two keystream families at one address were reported as colliding"
    );

    // And the stride: PRSS reads one element per position, PRZS reads `t`. Positions 0..1 of a
    // stride-`t` stream cover the same bytes as positions 0..t of a stride-1 one, which is
    // invariant P3 — the reason the two halves are tracked apart rather than merged.
    let mut strided = IntervalLedger::default();
    strided.record(
        "PRZS position 0",
        PrssStream::RandBitZero,
        Keystream::PrzsArithmetic,
        sid,
        0,
        1,
        192,
        t,
    );
    strided.record(
        "PRZS position 1",
        PrssStream::RandBitZero,
        Keystream::PrzsArithmetic,
        sid,
        1,
        1,
        192,
        t,
    );
    assert!(
        strided.overlaps().is_empty(),
        "consecutive strided positions must not overlap"
    );
}

/// **The headline.** Every derivation the four production consumers make, across many
/// interleaved batches, lands on a position no other derivation has touched.
///
/// This is the multiset assertion the audit asked for, taken at the observable that actually
/// matters: the pseudorandom value that ends up masking an opening. It drives the real entry
/// points — `randbit_material`, `triple_material`, `double_shares` — so it makes no assumption
/// about how any of them addresses its keystream. If a future refactor pins a cursor, mixes the
/// fresh-exec and cursor schemes on one stream, or gives two consumers one address, the values
/// collide here.
///
/// The interleaving matters as much as the volume. Each wave takes `RandBit` material, then `F`
/// triple material, then `GF` doubles, then a daBit batch, all from **one** allocator per party —
/// so a stream shared between two consumers (as `GfDn07Double` is, by GF triple generation and
/// the edaBit filter) is exercised in the order production would exercise it.
#[tokio::test]
async fn production_derivations_never_repeat_a_position_across_all_four_consumers() {
    for (n, t) in CONFIGS {
        let f_src = f_sources(n, t);
        let gf_src = gf_sources(n, t);
        let f_st = f_prss(n, t);
        let k_st = k_prss(n, t);
        // ONE allocator per party for both domains, which is what `setup_prss_keys` installs:
        // the `F` and `K` stores come from one key list and report the same key family.
        let allocs = f_allocators(&f_src);
        let dabit_allocs = dabit_allocators(&f_st);

        let mut ledger = ValueLedger::default();
        let waves = 8;
        for wave in 0..waves {
            // Deliberately uneven batch sizes: a cursor bug that happens to be masked by a
            // constant stride shows up as soon as the stride varies.
            let count = 1 + wave % 4;

            let (a, z) = drive_randbit(&f_src, &allocs, count).await;
            ledger.record_batch(&format!("RandBit [a] wave {wave}"), &a);
            ledger.record_batch(&format!("RandBit PRZS re-randomiser wave {wave}"), &z);

            let (ta, tb, dlo, dhi) = drive_f_triples(&f_src, &allocs, count).await;
            ledger.record_batch(&format!("F triple [a] wave {wave}"), &ta);
            ledger.record_batch(&format!("F triple [b] wave {wave}"), &tb);
            ledger.record_batch(&format!("F triple double PRSS half wave {wave}"), &dlo);
            ledger.record_batch(&format!("F triple double PRZS half wave {wave}"), &dhi);

            let (glo, ghi) = drive_gf_doubles(&gf_src, &allocs, count).await;
            ledger.record_batch(&format!("GF double PRSS half wave {wave}"), &glo);
            ledger.record_batch(&format!("GF double PRZS half wave {wave}"), &ghi);

            // The daBit batch's exec id comes from `PrssStream::DaBitSeed`'s cursor, one per
            // `claim_dabit_batch`; `wave` is that cursor's output here.
            let (beta_f, beta_k, psi) = drive_dabit(&f_st, &k_st, &dabit_allocs, count).await;
            record_dabit_seed(
                &mut ledger,
                &format!("daBit seed wave {wave}"),
                &beta_f,
                &beta_k,
            );
            ledger.record_batch(&format!("daBit Mod2 mask psi wave {wave}"), &psi);
        }

        ledger.assert_no_reuse(&format!("n={n}, t={t}"));

        // A ledger that recorded nothing would also report no reuse. Pin the count so that a
        // driver quietly returning empty batches cannot pass as a clean run. Ten observables per
        // wave: `RandBit`'s two, the triple's four, the GF double's two, and the daBit's two.
        let expected: usize = (0..waves).map(|w| (1 + w % 4) * 10).sum();
        assert_eq!(
            ledger.distinct(),
            expected,
            "n={n}, t={t}: the ledger saw {} distinct derivations, not the {expected} the drivers \
             should have produced",
            ledger.distinct()
        );
    }
}

/// **A retry after an abort burns its range rather than rewinding onto it.**
///
/// A preprocessing batch may abort, and the tempting recovery is to roll the cursor back so the
/// positions are not "wasted". That is the silent privacy break: the aborted attempt may already
/// have put values on the wire, and re-deriving its range hands the adversary the mask for an
/// opening it has already seen. Positions are cheap and privacy is not.
///
/// The abort is modelled the way it actually happens — the claim succeeds, and the batch dies
/// afterwards — for each of the three production entry points in turn. The assertion is that
/// the retry's values are disjoint from the burned attempt's.
#[tokio::test]
async fn a_retry_after_an_abort_burns_its_range_rather_than_rewinding() {
    let (n, t) = (10, 3);
    let f_src = f_sources(n, t);
    let gf_src = gf_sources(n, t);
    let allocs = f_allocators(&f_src);
    let mut ledger = ValueLedger::default();

    // -- RandBit ---------------------------------------------------------------------------------
    let (a1, z1) = drive_randbit(&f_src, &allocs, 3).await;
    ledger.record_batch("RandBit [a], the attempt that aborted", &a1);
    ledger.record_batch("RandBit re-randomiser, the attempt that aborted", &z1);
    // ... the batch fails here, after the claim and after the derivation. Nothing is rolled back.
    let (a2, z2) = drive_randbit(&f_src, &allocs, 3).await;
    ledger.record_batch("RandBit [a], the retry", &a2);
    ledger.record_batch("RandBit re-randomiser, the retry", &z2);

    // -- F triples -------------------------------------------------------------------------------
    let (ta1, tb1, dlo1, dhi1) = drive_f_triples(&f_src, &allocs, 2).await;
    ledger.record_batch("F triple [a], the attempt that aborted", &ta1);
    ledger.record_batch("F triple [b], the attempt that aborted", &tb1);
    ledger.record_batch("F triple double PRSS half, the attempt that aborted", &dlo1);
    ledger.record_batch("F triple double PRZS half, the attempt that aborted", &dhi1);
    let (ta2, tb2, dlo2, dhi2) = drive_f_triples(&f_src, &allocs, 2).await;
    ledger.record_batch("F triple [a], the retry", &ta2);
    ledger.record_batch("F triple [b], the retry", &tb2);
    ledger.record_batch("F triple double PRSS half, the retry", &dlo2);
    ledger.record_batch("F triple double PRZS half, the retry", &dhi2);

    // -- GF doubles ------------------------------------------------------------------------------
    let (glo1, ghi1) = drive_gf_doubles(&gf_src, &allocs, 2).await;
    ledger.record_batch("GF double PRSS half, the attempt that aborted", &glo1);
    ledger.record_batch("GF double PRZS half, the attempt that aborted", &ghi1);
    let (glo2, ghi2) = drive_gf_doubles(&gf_src, &allocs, 2).await;
    ledger.record_batch("GF double PRSS half, the retry", &glo2);
    ledger.record_batch("GF double PRZS half, the retry", &ghi2);

    ledger.assert_no_reuse("a retry re-derived the range its aborted attempt had already spent");

    // The same, stated as the property rather than as an absence: a retry of a batch of the same
    // size must produce entirely different values.
    assert_ne!(a1, a2, "the RandBit retry re-derived [a]");
    assert_ne!(z1, z2, "the RandBit retry re-derived its re-randomiser");
    assert_ne!(ta1, ta2, "the triple retry re-derived [a]");
    assert_ne!(glo1, glo2, "the GF retry re-derived its PRSS half");

    // A batch that aborts *between* the two claims leaves the two cursors one apart. That is
    // harmless — they are different keystreams and both are still monotone — and it must not
    // wedge the next batch. Claim only the `A` half, drop it, and check the next full batch is
    // still fresh.
    let burned = allocs[0]
        .claim(
            PrssStream::RandBitA,
            4,
            PrssDoubleShareSource::<F>::randbit_a_bits(),
        )
        .await
        .unwrap();
    drop(burned);
    let (a3, _) = drive_randbit(&f_src[..1], &allocs[..1], 4).await;
    let mut after = ValueLedger::default();
    after.record_batch("party 0 [a] before the half-claimed batch", &a2[..1]);
    after.record_batch("party 0 [a] after it", &a3);
    after.assert_no_reuse("a batch that aborted between its two claims rewound the A cursor");
}

/// **Concurrent sessions cannot race onto one position.**
///
/// The hazard a read-derive-then-write cursor has: two tasks read the same cursor value, both
/// derive from it, and both write back — individually monotone, jointly colliding. A cloned
/// `HoneyBadgerMPCNode` shares its allocator through an `Arc` rather than forking it, and the
/// claim is atomic and happens *before* any derivation, so there is nothing to interleave.
///
/// This drives the production entry points concurrently rather than the allocator directly, so
/// what is under test is the whole claim-then-derive path, including the possibility that a
/// consumer derives outside the claim it was handed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_sessions_cannot_race_onto_one_position() {
    let (n, t) = (7, 2);
    let f_src = Arc::new(f_sources(n, t));
    let gf_src = Arc::new(gf_sources(n, t));
    // One allocator per party, shared by every task — the clone shares the cursors.
    let allocs = Arc::new(f_allocators(&f_src));

    let sessions = 12;
    let count = 2;
    let mut tasks = Vec::new();
    for session in 0..sessions {
        let f_src = Arc::clone(&f_src);
        let gf_src = Arc::clone(&gf_src);
        let allocs = Arc::clone(&allocs);
        tasks.push(tokio::spawn(async move {
            // Three different consumers per task, so the tasks contend on every stream rather
            // than lining up politely on one.
            let (a, z) = drive_randbit(&f_src, &allocs, count).await;
            tokio::task::yield_now().await;
            let (ta, tb, dlo, dhi) = drive_f_triples(&f_src, &allocs, count).await;
            tokio::task::yield_now().await;
            let (glo, ghi) = drive_gf_doubles(&gf_src, &allocs, count).await;
            (session, a, z, ta, tb, dlo, dhi, glo, ghi)
        }));
    }

    let mut ledger = ValueLedger::default();
    for task in tasks {
        let (s, a, z, ta, tb, dlo, dhi, glo, ghi) = task.await.unwrap();
        ledger.record_batch(&format!("session {s} RandBit [a]"), &a);
        ledger.record_batch(&format!("session {s} RandBit re-randomiser"), &z);
        ledger.record_batch(&format!("session {s} F triple [a]"), &ta);
        ledger.record_batch(&format!("session {s} F triple [b]"), &tb);
        ledger.record_batch(&format!("session {s} F triple double PRSS half"), &dlo);
        ledger.record_batch(&format!("session {s} F triple double PRZS half"), &dhi);
        ledger.record_batch(&format!("session {s} GF double PRSS half"), &glo);
        ledger.record_batch(&format!("session {s} GF double PRZS half"), &ghi);
    }

    ledger.assert_no_reuse("concurrent sessions raced onto one position");
    assert_eq!(
        ledger.distinct(),
        sessions * count * 8,
        "a concurrent session produced fewer derivations than it claimed"
    );
}

/// **The byte intervals of every stream are pairwise disjoint**, including where a value ledger
/// could not see it.
///
/// Where the value tests drive production and observe outputs, this one claims from the allocator
/// and observes *addresses* — which is the only way to catch a partial overlap. It covers all
/// seven declared streams at the widths and strides production actually uses, taken from the
/// production accessors rather than from literals so that a width change downstream moves this
/// test with it.
///
/// The three invariants at stake, in the vocabulary of `honeybadger::prss::window`:
///
/// * **P1** — two consumers sharing a `ctx16` must partition `start`.
/// * **P2** — two consumers at different widths must differ in `ctx16` or in the label;
///   partitioning `start` is not enough, because the address is a byte.
/// * **P3** — a stride-`t` consumer (PRZS lays a sharing's `t` coefficients out contiguously)
///   must not share a keystream with a stride-1 one.
#[tokio::test]
async fn every_claimed_byte_interval_is_disjoint_within_its_keystream() {
    for (n, t) in CONFIGS {
        let f_src = f_sources(n, t);
        let alloc = PrssAllocator::new(INSTANCE, f_src[0].key_family_id());
        let mut ledger = IntervalLedger::default();

        let a_bits = PrssDoubleShareSource::<F>::randbit_a_bits();
        let z_bits = PrssDoubleShareSource::<F>::randbit_zero_bits();
        let d_bits = PrssDoubleShareSource::<F>::double_bits();
        let g_bits = GfPrssDoubleShareSource::<K>::double_bits().unwrap();
        let gz_bits = <K as PrzsCoefficient>::COEFF_BITS;

        // The PRZS arithmetic width is the reduction-slack one, not the uniform one. They happen
        // to coincide at `PRSS_UNIFORM_SLACK_BITS == PRZS_REDUCTION_SLACK_BITS == 128`; assert it
        // rather than rely on it, because if they ever diverge this file's model of the PRZS
        // interval silently stops matching the store's.
        assert_eq!(
            z_bits,
            F::MODULUS_BIT_SIZE as usize + PRZS_REDUCTION_SLACK_BITS,
            "the PRZS width this file models is not the one the store draws at"
        );

        for wave in 0..6usize {
            let count = 1 + wave % 3;

            let aw = alloc
                .claim(PrssStream::RandBitA, count, a_bits)
                .await
                .unwrap();
            ledger.record(
                &format!("RandBit [a] wave {wave}"),
                aw.stream(),
                Keystream::PrssUniform,
                aw.session_id(),
                aw.start(),
                aw.len(),
                aw.bits(),
                1,
            );

            let zw = alloc
                .claim(PrssStream::RandBitZero, count, z_bits)
                .await
                .unwrap();
            ledger.record(
                &format!("RandBit re-randomiser wave {wave}"),
                zw.stream(),
                Keystream::PrzsArithmetic,
                zw.session_id(),
                zw.start(),
                zw.len(),
                zw.bits(),
                t,
            );

            // One triple window covers three disjoint thirds of one keystream plus that window's
            // PRZS half. Recording the thirds separately is what makes this an assertion about
            // `triple_material_in`'s layout rather than about the claim alone.
            let dw = alloc
                .claim(PrssStream::Dn07Double, 3 * count, d_bits)
                .await
                .unwrap();
            for (third, what) in ["[a]", "[b]", "double"].iter().enumerate() {
                ledger.record(
                    &format!("F triple {what} wave {wave}"),
                    dw.stream(),
                    Keystream::PrssUniform,
                    dw.session_id(),
                    dw.start() + third * count,
                    count,
                    dw.bits(),
                    1,
                );
            }
            ledger.record(
                &format!("F triple double PRZS half wave {wave}"),
                dw.stream(),
                Keystream::PrzsArithmetic,
                dw.session_id(),
                dw.start() + 2 * count,
                count,
                z_bits,
                t,
            );

            let gw = alloc
                .claim(PrssStream::GfDn07Double, count, g_bits)
                .await
                .unwrap();
            ledger.record(
                &format!("GF double PRSS half wave {wave}"),
                gw.stream(),
                Keystream::PrssMask,
                gw.session_id(),
                gw.start(),
                gw.len(),
                gw.bits(),
                1,
            );
            ledger.record(
                &format!("GF double PRZS half wave {wave}"),
                gw.stream(),
                Keystream::PrzsBinary,
                gw.session_id(),
                gw.start(),
                gw.len(),
                gz_bits,
                t,
            );

            // The cursor-scheme stream, which stays on ONE keystream and therefore must tile.
            let mw = alloc
                .claim(PrssStream::PRandIntMask, count, LAMBDA)
                .await
                .unwrap();
            ledger.record(
                &format!("PRandInt mask wave {wave}"),
                mw.stream(),
                Keystream::PrssMask,
                mw.session_id(),
                mw.start(),
                mw.len(),
                mw.bits(),
                1,
            );

            // Both daBit keystreams come out of the *same* allocator as everything else, from
            // one `claim_dabit_batch`. They are recorded here so that they are checked against
            // every other stream rather than only against each other.
            let dw = alloc.claim_dabit_batch(count, LAMBDA).await.unwrap();
            ledger.record(
                &format!("daBit seed wave {wave}"),
                dw.seed().stream(),
                Keystream::PrssMask,
                dw.seed().session_id(),
                dw.seed().start(),
                dw.seed().len(),
                dw.seed().bits(),
                1,
            );
            ledger.record(
                &format!("daBit Mod2 mask wave {wave}"),
                dw.psi().stream(),
                Keystream::PrssMask,
                dw.psi().session_id(),
                dw.psi().start(),
                dw.psi().len(),
                dw.psi().bits(),
                1,
            );
        }

        ledger.assert_pairwise_disjoint(&format!("n={n}, t={t}"));
        // Eleven intervals per wave: `RandBit`'s two, the triple window's three PRSS thirds plus
        // its PRZS half, the GF window's two halves, the PRandInt cursor claim, and the daBit
        // batch's two.
        assert_eq!(
            ledger.len(),
            6 * 11,
            "the interval ledger recorded the wrong number of claims"
        );
    }
}

/// **The daBit seed and its Mod2 mask are independent keystreams** — plan §6.5 error 1.
///
/// If `beta` and `psi` were drawn from one `(key, context, position)`, `psi`'s low bit would equal
/// `beta`, the masked value would be `V = 3*beta + 4*kappa + r'_0`, and `V mod 4` would reveal the
/// daBit with probability about 3/4. The separation is a single byte — `sub_id = 0` against
/// [`PSI_SUB_ID`], landing in `prss::context_bytes`' `ctx[13]`.
///
/// Asserted in the strongest available form: at the **same width and the same positions**, where
/// a shared keystream would make the two draws byte-identical, the values must still differ.
/// Comparing them at their real widths would be a weaker test, since two different widths read
/// different bytes even from one stream and the vectors would differ for the wrong reason.
#[tokio::test]
async fn the_dabit_seed_and_its_mod2_mask_are_independent_keystreams() {
    let (n, t) = (10, 3);
    let stores = f_prss(n, t);
    let dealt = deal_keys(n, t, KEY_SEED);
    let allocs = dabit_allocators(&stores);
    let count = 16;

    for exec in 0..3u64 {
        let w = allocs[0].claim_dabit_batch(count, LAMBDA).await.unwrap();
        let (parent, psi) = (w.seed().session_id(), w.psi().session_id());
        assert_ne!(parent, psi, "the two daBit sessions must differ");
        assert_eq!(psi.sub_id(), PSI_SUB_ID);
        assert_eq!(psi.exec_id(), parent.exec_id());
        assert_eq!(parent.exec_id(), exec, "the seed cursor skipped an exec");
        // The second separator, which `PrssKeys::shares_at_in` reads off the window.
        assert_eq!(w.seed().domain(), PrssDomain::Default);
        assert_eq!(w.psi().domain(), PrssDomain::DaBitPsi);

        // Compared at the **raw keystream**, at equal width and equal positions, where a shared
        // stream would be a byte-for-byte collision. Going through `shares_at_in` instead would
        // compare a 1-bit draw against a lambda-bit one, and the two would differ for the wrong
        // reason.
        for (_, key) in &dealt[0] {
            let beta = derive_ints_at(key, parent, 0, count, LAMBDA);
            let mask = derive_ints_at_domain(key, psi, PrssDomain::DaBitPsi, 0, count, LAMBDA);
            assert_ne!(
                beta, mask,
                "the daBit seed and its Mod2 mask share a keystream at exec {exec}"
            );
            // Each separator on its own: neither byte is load-bearing alone, so losing either one
            // still leaves the two streams apart.
            assert_ne!(
                beta,
                derive_ints_at(key, psi, 0, count, LAMBDA),
                "ctx[13] alone does not separate beta from psi"
            );
            assert_ne!(
                beta,
                derive_ints_at_domain(key, parent, PrssDomain::DaBitPsi, 0, count, LAMBDA),
                "ctx[15] alone does not separate beta from psi"
            );
        }
    }
}

/// **Two daBit batches at different exec ids share no position.**
///
/// The daBit path addresses its positions by `(exec_id, index in batch)` and always starts at
/// index 0, so freshness rests entirely on the exec id advancing. This is the observable
/// consequence of that, over both of the batch's keystreams at once.
#[tokio::test]
async fn two_dabit_batches_at_different_exec_ids_share_no_position() {
    let (n, t) = (10, 3);
    let f_st = f_prss(n, t);
    let k_st = k_prss(n, t);
    let allocs = dabit_allocators(&f_st);

    let mut ledger = ValueLedger::default();
    for exec in 0..6u64 {
        // Varying batch sizes, because the positions always start at 0: a longer batch overlaps
        // the index range of a shorter one, and only the exec id separates them.
        let count = 1 + (exec as usize % 3);
        let (beta_f, beta_k, psi) = drive_dabit(&f_st, &k_st, &allocs, count).await;
        record_dabit_seed(
            &mut ledger,
            &format!("daBit seed at exec {exec}"),
            &beta_f,
            &beta_k,
        );
        ledger.record_batch(&format!("daBit mask at exec {exec}"), &psi);
    }
    ledger.assert_no_reuse("two daBit batches at different exec ids shared a position");

    // And the converse, which is what makes the above meaningful: the same exec reproduces its
    // values exactly. A rewind is now unrepresentable through one allocator — the cursor has no
    // setter and `claim_dabit_batch` only advances — so the rewind is staged the only way it can
    // still happen, through a **second allocator** over the same key family. That is precisely
    // the hazard `setup_prss_keys` avoids by building exactly one.
    let rewound = dabit_allocators(&f_st);
    let a = drive_dabit(&f_st, &k_st, &rewound, 3).await;
    let b = drive_dabit(&f_st, &k_st, &dabit_allocators(&f_st), 3).await;
    assert_eq!(
        a.0, b.0,
        "PRSS is position-addressed, so a second allocator over one key family must reproduce \
         exec 0 — if this ever fails, the derivation has become stateful and this file's whole \
         detection strategy is invalid"
    );
}

/// **Every stream in the map is minted by the allocator, and the daBit pair by one cursor.**
///
/// This replaces the note that used to stand here saying the daBit streams were governed by
/// `SubProtocolCounters::dabit_counter` instead. That counter is gone — deleted, not merely
/// unused — along with `PreprocessingMaterial::prandint_cursor`, because a field that can be read
/// can become a second minter, and two monotone minters on one keystream are individually correct
/// and jointly catastrophic.
///
/// What is pinned here is the shape that replaced them: `DaBitSeed` leads, `DaBitPsi` follows, a
/// direct claim on the follower is refused, and the filter's exec-only burn comes off the leader's
/// cursor so the two drivers' `exec * 2^20 + wave` child blocks stay disjoint.
#[tokio::test]
async fn every_stream_is_minted_by_the_allocator_and_the_dabit_pair_by_one_cursor() {
    // The map still declares both addresses, which is what keeps a future consumer from landing
    // on them by default.
    assert_eq!(
        PrssStream::DaBitSeed.addressing(),
        (ProtocolType::DaBit, 0, 0)
    );
    assert_eq!(
        PrssStream::DaBitPsi.addressing(),
        (ProtocolType::DaBit, PSI_SUB_ID, 0)
    );
    assert!(PrssStream::DaBitSeed.is_fresh_exec());
    assert!(PrssStream::DaBitPsi.is_fresh_exec());

    // Leader / follower. `PRandIntMask` is a leader too, despite being the one cursor-scheme
    // stream: it has a cursor, it just moves `start` rather than `exec_id`.
    for stream in PrssStream::ALL {
        let leader = stream.exec_leader();
        if stream == PrssStream::DaBitPsi {
            assert_eq!(leader, PrssStream::DaBitSeed);
        } else {
            assert_eq!(
                leader,
                stream,
                "{} unexpectedly became a follower",
                stream.name()
            );
        }
    }

    let (n, t) = (7, 2);
    let stores = f_prss(n, t);
    let alloc = PrssAllocator::new(INSTANCE, stores[0].key_family_id());

    // A follower cannot be claimed on its own, by either route. Were it possible, a `psi` window
    // would carry an exec its leader had not burned — and the leader could then issue it again.
    assert!(alloc.claim(PrssStream::DaBitPsi, 4, LAMBDA).await.is_err());
    assert!(alloc.claim_exec(PrssStream::DaBitPsi).await.is_err());

    // The cursor-scheme stream has no exec to burn.
    assert!(alloc.claim_exec(PrssStream::PRandIntMask).await.is_err());

    // One cursor, shared by the generator's batch claim and the filter's exec-only burn. The
    // execs must be strictly increasing across the two, interleaved in any order.
    let mut execs = Vec::new();
    for round in 0..4u64 {
        let w = alloc.claim_dabit_batch(2, LAMBDA).await.unwrap();
        execs.push(w.parent_session().exec_id());
        drop(w);
        let slot = alloc.claim_exec(PrssStream::DaBitSeed).await.unwrap();
        assert_eq!(slot.stream(), PrssStream::DaBitSeed);
        assert_eq!(slot.instance_id(), INSTANCE);
        execs.push(slot.exec_id());
        assert_eq!(execs.len(), 2 * (round as usize + 1));
    }
    assert_eq!(
        execs,
        (0..8u64).collect::<Vec<_>>(),
        "the generator and the filter are not drawing parent execs from one cursor"
    );

    // And a dropped batch burns its exec rather than returning it.
    let before = alloc.claim_dabit_batch(1, LAMBDA).await.unwrap();
    let burned = before.parent_session().exec_id();
    drop(before);
    let after = alloc.claim_dabit_batch(1, LAMBDA).await.unwrap();
    assert_eq!(
        after.parent_session().exec_id(),
        burned + 1,
        "a dropped daBit claim rewound the cursor"
    );
}

/// **A second allocator over one key family re-issues position zero.**
///
/// The reason `HoneyBadgerMPCNode` installs exactly one allocator, alongside the key stores, and
/// never rebuilds it. Two allocators are each perfectly monotone and jointly catastrophic — which
/// is the same shape as the two-counters-on-one-stream hazard above, and the reason the cloned
/// handle in `generate_randbits` shares its cursors through an `Arc` rather than forking them.
#[tokio::test]
async fn a_second_allocator_over_one_key_family_re_issues_position_zero() {
    let (n, t) = (10, 3);
    let src = f_sources(n, t);
    let first = PrssAllocator::new(INSTANCE, src[0].key_family_id());

    let (a1, _) = drive_randbit(&src[..1], std::slice::from_ref(&first), 3).await;

    // A clone shares the cursors: the node's own behaviour, and it stays fresh.
    let cloned = first.clone();
    let (a2, _) = drive_randbit(&src[..1], std::slice::from_ref(&cloned), 3).await;
    assert_ne!(
        a1, a2,
        "a cloned allocator forked its cursors instead of sharing them"
    );

    // A second allocator built over the same key family does not.
    let forked = PrssAllocator::new(INSTANCE, src[0].key_family_id());
    let (a3, _) = drive_randbit(&src[..1], std::slice::from_ref(&forked), 3).await;
    assert_eq!(
        a1, a3,
        "a second allocator over one key family must re-issue position zero — if this ever stops \
         holding, the allocator has acquired hidden global state and the single-allocator \
         discipline is no longer the thing keeping positions disjoint"
    );

    // Stated once more through the detector the rest of the file uses, so the failure message
    // reads the same way as a real reuse would.
    let mut ledger = ValueLedger::default();
    ledger.record_batch("the node's allocator", &a1);
    ledger.record_batch("a second allocator built over the same keys", &a3);
    assert_eq!(
        ledger.reuse.len(),
        3,
        "the forked allocator's re-issued positions were not detected"
    );
}

/// **The PRZS stride this file models is the stride the store uses.**
///
/// The interval ledger multiplies PRZS positions by `t` because `zero_shares_at` maps
/// `(start, count)` to `(start * t, count * t)` coefficients — but `coefficient_window` is
/// `pub(crate)`, so that is a model rather than something this file can read. Verify it from the
/// outside instead: a batch drawn at `(0, m)` must agree, element for element, with `m` separate
/// draws at `(i, 1)`. That is only true if positions are strided uniformly and addressed
/// absolutely, which is exactly the assumption the ledger encodes.
#[test]
fn the_przs_stride_this_file_models_is_the_one_the_store_uses() {
    for (n, t) in CONFIGS {
        let dealt = deal_keys(n, t, KEY_SEED);
        let store = PrzsKeys::<F>::new(0, n, t, &dealt[0]).unwrap();
        let sid = SessionId::new(
            ProtocolType::RandBit,
            SessionId::pack_slot(0, 0, 0),
            INSTANCE,
        );

        let batch = store.zero_shares_at(sid, 0, 5).unwrap();
        for i in 0..5 {
            let single = store.zero_shares_at(sid, i, 1).unwrap();
            assert_eq!(
                batch[i].share[0], single[0].share[0],
                "n={n}, t={t}: PRZS position {i} is not addressed absolutely, so the byte \
                 intervals this file computes do not describe what the store reads"
            );
        }

        // And consecutive positions differ, which is what makes the stride observable at all: a
        // store that ignored `start` would pass the test above trivially.
        assert_ne!(
            batch[0].share[0], batch[1].share[0],
            "n={n}, t={t}: two PRZS positions derived the same value"
        );

        // The same for the PRSS uniform stream the double sharings' other half rides.
        let prss = PrssKeys::<F>::new(0, n, t, &dealt[0]).unwrap();
        let u_batch = prss.uniform_shares_at(sid, 0, 5).unwrap();
        for i in 0..5 {
            let single = prss.uniform_shares_at(sid, i, 1).unwrap();
            assert_eq!(u_batch[i].share[0], single[0].share[0]);
        }
        assert_ne!(u_batch[0].share[0], u_batch[1].share[0]);
    }
}

// =================================================================================================
// The KDF model — for the keystreams the crate deliberately no longer exposes
// =================================================================================================
//
// Everything above observes *production* derivations. The migration test below cannot: the whole
// point of the epoch bump is that the pre-migration keystream is no longer reachable through any
// public entry point, so the only way to ask "could a migrated stream land on a byte the legacy
// counter already spent?" is to re-derive the legacy byte here and check that nothing production
// produces equals it.
//
// That makes this a model, with the usual hazard — a model that has drifted from the
// implementation proves nothing. [`the_kdf_model_in_this_file_reproduces_the_production_
// derivation`] pins it from the other end, and is itself the partial-epoch detector: it rebuilds
// all three labels from the one epoch marker the crate exports and requires all three to
// reproduce their real keystreams.

type ModelHmac = Hmac<Sha256>;

/// SP 800-108's fixed output-length parameter, held constant exactly as both implementations do.
const MODEL_L_BITS: u32 = u32::MAX;

/// The epoch every pre-`PrssAllocator` derivation ran under. The three labels were `v1`; the
/// migration moved all three to the next epoch at once, which is what made every byte a legacy
/// counter had spent unaddressable rather than merely unlikely to be re-addressed.
const LEGACY_EPOCH: &str = "v1";

/// `prss::context_bytes` / `przs::context_bytes`, which are private to their modules.
///
/// Takes the `ctx[15]` tag as a raw byte rather than either domain enum, because it has to be
/// able to express the **legacy** daBit `psi` context — drawn at `PrssDomain::Default`'s `0x01`,
/// since `PrssDomain::DaBitPsi` did not exist before the migration and cannot be constructed to
/// mean anything else now.
fn model_ctx(session_id: SessionId, domain_tag: u8) -> [u8; 16] {
    let mut ctx = [0u8; 16];
    ctx[0] = session_id
        .calling_protocol()
        .map(|p| p as u8)
        .unwrap_or(0xFF);
    ctx[1..5].copy_from_slice(&session_id.instance_id().to_be_bytes());
    ctx[5..13].copy_from_slice(&session_id.exec_id().to_be_bytes());
    ctx[13] = session_id.sub_id();
    ctx[14] = session_id.round_id();
    ctx[15] = domain_tag;
    ctx
}

/// The counter-mode KDF body, with the SP 800-108 `Label` and the raw context as parameters.
///
/// Transcribed from `prss::derive_ints_labelled`; `przs::derive_zero_coeff_ints_at` is the same
/// body at a different label, which is why one model covers both.
fn model_kdf(
    label: &[u8],
    key: &[u8; PRSS_KEY_LEN],
    ctx: [u8; 16],
    start: usize,
    count: usize,
    bits: usize,
) -> Vec<BigUint> {
    if count == 0 || bits == 0 {
        return Vec::new();
    }
    const BLOCK: usize = 32;
    let width = bits.div_ceil(8);
    let byte_offset = start * width;
    let first_block = byte_offset / BLOCK;
    let skip = byte_offset % BLOCK;
    let need = count * width;

    let mut stream = Vec::with_capacity((skip + need).next_multiple_of(BLOCK));
    let mut counter = first_block as u32;
    while stream.len() < skip + need {
        let mut mac = ModelHmac::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(&counter.to_be_bytes());
        mac.update(label);
        mac.update(&[0x00]);
        mac.update(&ctx);
        mac.update(&MODEL_L_BITS.to_be_bytes());
        stream.extend_from_slice(&mac.finalize().into_bytes());
        counter += 1;
    }

    let top_mask: u8 = match bits % 8 {
        0 => 0xFF,
        r => (1u8 << r) - 1,
    };
    stream[skip..skip + need]
        .chunks_exact(width)
        .map(|chunk| {
            let mut bytes = chunk.to_vec();
            if let Some(last) = bytes.last_mut() {
                *last &= top_mask;
            }
            BigUint::from_bytes_le(&bytes)
        })
        .collect()
}

/// The epoch marker the whole key family currently runs under, read off the **one** label the
/// crate exports.
///
/// `KDF_LABEL` and `KDF_LABEL_UNIFORM` are private, which is correct — nothing outside `prss`
/// should be able to pick a label — so the epoch is taken from [`PRZS_KDF_LABEL`] and the other
/// two are reconstructed from it. A partial bump therefore shows up as a *model mismatch* on
/// whichever label was left behind, which is exactly the failure that matters: an epoch that
/// moves on two labels out of three is worse than one that does not move at all, because the
/// stream left behind is the one whose legacy positions are still addressable.
fn current_epoch() -> String {
    let label = std::str::from_utf8(PRZS_KDF_LABEL).expect("the PRZS label is ASCII");
    let (stem, epoch) = label
        .rsplit_once('-')
        .expect("the PRZS label is `<stem>-<epoch>`");
    assert_eq!(
        stem, "STOFFEL-PRZS",
        "the PRZS label stem changed, so the labels this file reconstructs are no longer the \
         ones in use"
    );
    assert!(
        !epoch.is_empty(),
        "the PRZS label carries no epoch suffix, so there is no epoch marker to bump"
    );
    epoch.to_string()
}

fn mask_label(epoch: &str) -> Vec<u8> {
    format!("STOFFEL-PRSS-{epoch}").into_bytes()
}

fn uniform_label(epoch: &str) -> Vec<u8> {
    format!("STOFFEL-PRSS-UNIFORM-{epoch}").into_bytes()
}

fn przs_label(epoch: &str) -> Vec<u8> {
    format!("STOFFEL-PRZS-{epoch}").into_bytes()
}

/// The session id the legacy `prandint_cursor` addressed: `exec_id` pinned to 0, `start` moving.
fn prandint_sid() -> SessionId {
    SessionId::new(
        ProtocolType::PRandInt,
        SessionId::pack_slot(0, 0, 0),
        INSTANCE,
    )
}

/// One position's fingerprint over **all** of a party's keys, so that a one-bit-wide stream still
/// carries `C(n-1, t)` bits of identity rather than one.
///
/// A daBit seed is a single bit: comparing raw draws would report a "collision" between every
/// pair of zeros. Folding every key the party holds is what makes the comparison meaningful at
/// that width, and it is also the honest observable — a party's share is a function of all of
/// them.
fn fold_keys(values: impl Iterator<Item = BigUint>) -> String {
    let mut out = String::new();
    for v in values {
        out.push_str(&format!("{v}|"));
    }
    out
}

/// A legacy position's fingerprint, derived through the model at the legacy epoch.
fn legacy_fingerprint(
    keys: &[(usize, [u8; PRSS_KEY_LEN])],
    label: &[u8],
    session: SessionId,
    domain_tag: u8,
    start: usize,
    bits: usize,
) -> String {
    fold_keys(keys.iter().map(|(_, k)| {
        model_kdf(label, k, model_ctx(session, domain_tag), start, 1, bits)[0].clone()
    }))
}

/// A live position's fingerprint, derived through the **production** entry point.
fn live_mask_fingerprint(
    keys: &[(usize, [u8; PRSS_KEY_LEN])],
    session: SessionId,
    domain: PrssDomain,
    start: usize,
    bits: usize,
) -> String {
    fold_keys(
        keys.iter()
            .map(|(_, k)| derive_ints_at_domain(k, session, domain, start, 1, bits)[0].clone()),
    )
}

// =================================================================================================
// Fixtures for the seven-stream run
// =================================================================================================

/// One `PRandIntNode` per party with PRSS keys installed — the production owner of
/// [`PrssStream::PRandIntMask`], and the only one of the seven consumers that is a node rather
/// than a source.
fn prandint_nodes(n: usize, t: usize) -> Vec<PRandIntNode<F, Avid<SessionId>>> {
    f_prss(n, t)
        .into_iter()
        .enumerate()
        .map(|(id, keys)| {
            let mut node = PRandIntNode::<F, Avid<SessionId>>::new(id, n, t, t + 1).unwrap();
            node.install_prss_keys(keys);
            node
        })
        .collect()
}

/// `PRandInt` masks from every party, through `generate_prss` — which claims from the allocator
/// itself, so nothing here chooses a position.
async fn drive_prandint(
    nodes: &[PRandIntNode<F, Avid<SessionId>>],
    allocs: &[PrssAllocator],
    count: usize,
) -> Vec<Vec<F>> {
    let mut out = Vec::with_capacity(nodes.len());
    for (node, alloc) in nodes.iter().zip(allocs) {
        out.push(node.generate_prss(alloc, count, LAMBDA).await.unwrap());
    }
    f_values(&out)
}

// =================================================================================================
// 1. The multiset, over all seven streams, from one allocator
// =================================================================================================

/// **No position is issued twice anywhere in a full preprocessing run.**
///
/// The headline above covers four consumers off two allocator sets; this one covers **all seven
/// declared streams off a single allocator per party**, which is the shape `setup_prss_keys`
/// actually installs. That difference is the point: two allocator sets cannot collide with each
/// other by construction, so splitting the run across them hides exactly the class of bug where a
/// newly-migrated stream lands on another stream's cursor. Here `PRandIntMask`, `DaBitSeed`,
/// `DaBitPsi`, `RandBitA`, `RandBitZero`, `Dn07Double` and `GfDn07Double` all draw their
/// positions from one `HashMap` of cursors, interleaved, at uneven batch sizes.
///
/// The seventh consumer, the edaBit overflow filter, derives no keystream at all — it spends only
/// the `exec * 2^20 + wave` child-id block an exec names. A value ledger is blind to it, so it is
/// checked in the currency it actually spends: the exec ids it burns must be disjoint from the
/// ones the daBit generator burns, because both mint child sessions from the same block formula.
#[tokio::test]
async fn every_position_in_a_full_preprocessing_run_is_unique_across_all_seven_streams() {
    for (n, t) in CONFIGS {
        let f_src = f_sources(n, t);
        let gf_src = gf_sources(n, t);
        let f_st = f_prss(n, t);
        let k_st = k_prss(n, t);
        let nodes = prandint_nodes(n, t);

        // One allocator per party for everything, which is only legitimate if all four fixtures
        // report the same key family — assert it rather than assume it, because if they ever
        // diverge this test silently degrades into four independent runs that cannot collide.
        for party in 0..n {
            assert_eq!(
                f_src[party].key_family_id(),
                f_st[party].key_family_id(),
                "party {party}: the double-share source and the bare PRSS store disagree on the \
                 key family, so one allocator cannot govern both"
            );
            assert_eq!(
                gf_src[party].key_family_id(),
                f_src[party].key_family_id(),
                "party {party}: the GF source is on a different key family from the F source"
            );
        }
        let allocs = f_allocators(&f_src);

        let mut ledger = ValueLedger::default();
        let mut execs: Vec<u64> = Vec::new();
        let waves = 8usize;

        for wave in 0..waves {
            // Uneven, and deliberately co-prime-ish across the streams: a cursor bug masked by a
            // constant stride surfaces as soon as the stride varies.
            let count = 1 + wave % 4;

            let (a, z) = drive_randbit(&f_src, &allocs, count).await;
            ledger.record_batch(&format!("RandBit [a] wave {wave}"), &a);
            ledger.record_batch(&format!("RandBit PRZS re-randomiser wave {wave}"), &z);

            let (ta, tb, dlo, dhi) = drive_f_triples(&f_src, &allocs, count).await;
            ledger.record_batch(&format!("F triple [a] wave {wave}"), &ta);
            ledger.record_batch(&format!("F triple [b] wave {wave}"), &tb);
            ledger.record_batch(&format!("F triple double PRSS half wave {wave}"), &dlo);
            ledger.record_batch(&format!("F triple double PRZS half wave {wave}"), &dhi);

            let (glo, ghi) = drive_gf_doubles(&gf_src, &allocs, count).await;
            ledger.record_batch(&format!("GF double PRSS half wave {wave}"), &glo);
            ledger.record_batch(&format!("GF double PRZS half wave {wave}"), &ghi);

            // `PRandIntMask` — the one cursor-scheme stream, and the one whose legacy minter
            // (`prandint_cursor`) was deleted rather than left unused.
            let masks = drive_prandint(&nodes, &allocs, count).await;
            ledger.record_batch(&format!("PRandInt mask wave {wave}"), &masks);

            // `DaBitSeed` + `DaBitPsi`, one claim, one exec, two keystreams.
            let (beta_f, beta_k, psi) = drive_dabit(&f_st, &k_st, &allocs, count).await;
            record_dabit_seed(
                &mut ledger,
                &format!("daBit seed wave {wave}"),
                &beta_f,
                &beta_k,
            );
            ledger.record_batch(&format!("daBit Mod2 mask psi wave {wave}"), &psi);

            // The edaBit overflow filter's exec-only burn, taken from the **same** cursor as the
            // batch above. Party 0 stands for the committee: every allocator starts at zero and
            // claims in the same order, which the value ledger has just re-verified by finding
            // every party's batch identical in length.
            let slot = allocs[0].claim_exec(PrssStream::DaBitSeed).await.unwrap();
            execs.push(slot.exec_id());
        }

        ledger.assert_no_reuse(&format!("n={n}, t={t}: full preprocessing run"));

        // A ledger that recorded nothing would also report no reuse. Eleven observables per wave:
        // `RandBit`'s two, the triple's four, the GF double's two, `PRandInt`'s one, the daBit's
        // two.
        let expected: usize = (0..waves).map(|w| (1 + w % 4) * 11).sum();
        assert_eq!(
            ledger.distinct(),
            expected,
            "n={n}, t={t}: the ledger saw {} distinct derivations, not the {expected} the seven \
             streams should have produced",
            ledger.distinct()
        );

        // The filter's execs, against the generator's. One cursor hands out `0 .. 2*waves`; the
        // generator takes the even ones and the filter the odd ones, because they alternate.
        let filter_execs: BTreeSet<u64> = execs.iter().copied().collect();
        assert_eq!(
            filter_execs.len(),
            waves,
            "n={n}, t={t}: the edaBit filter burned an exec twice, so two child-id blocks of \
             `exec * 2^20 + wave` overlap"
        );
        assert_eq!(
            execs,
            (0..waves as u64).map(|w| 2 * w + 1).collect::<Vec<_>>(),
            "n={n}, t={t}: the daBit generator and the edaBit filter are not drawing parent \
             execs from one cursor"
        );
    }
}

// =================================================================================================
// 2. The migration boundary
// =================================================================================================

/// **The model in this file reproduces the production derivation, on all three labels.**
///
/// Two jobs. First, it stops the migration test below from being vacuous: a model that has
/// drifted would fail to reproduce *any* legacy byte, and "no live derivation equals a legacy
/// one" would then hold for the wrong reason.
///
/// Second, and more importantly, it is the **partial-epoch detector**. The three labels
/// (`STOFFEL-PRSS-*`, `STOFFEL-PRSS-UNIFORM-*`, `STOFFEL-PRZS-*`) must move together: `RandBitA`
/// and `Dn07Double` ride the uniform label, `RandBitZero` and both PRZS halves ride the PRZS one,
/// and `PRandIntMask`/`DaBitSeed`/`DaBitPsi` ride the mask one. Leaving any one behind leaves the
/// stream on it still addressable at the positions its legacy counter spent. This test
/// reconstructs all three from the single epoch marker the crate exports and requires each to
/// reproduce its real keystream — so a bump of two out of three fails here, naming the one that
/// was left.
#[test]
fn the_kdf_model_in_this_file_reproduces_the_production_derivation() {
    let epoch = current_epoch();
    assert_ne!(
        epoch, LEGACY_EPOCH,
        "the key family is still on the pre-migration epoch, so every position the legacy \
         `prandint_cursor` and `dabit_counter` spent is addressable again by a zeroed allocator"
    );

    let (n, t) = (10, 3);
    let dealt = deal_keys(n, t, KEY_SEED);
    let key = &dealt[0][0].1;
    let sid = prandint_sid();

    for (start, count, bits) in [(0usize, 4usize, 40usize), (7, 3, 1), (13, 5, 64)] {
        assert_eq!(
            model_kdf(
                &mask_label(&epoch),
                key,
                model_ctx(sid, PrssDomain::Default.context_tag()),
                start,
                count,
                bits
            ),
            derive_ints_at(key, sid, start, count, bits),
            "the PRSS mask label is not `STOFFEL-PRSS-{epoch}` — either the model has drifted or \
             the epoch bump is partial, and a partial epoch is worse than none"
        );
        assert_eq!(
            model_kdf(
                &mask_label(&epoch),
                key,
                model_ctx(sid, PrssDomain::DaBitPsi.context_tag()),
                start,
                count,
                bits
            ),
            derive_ints_at_domain(key, sid, PrssDomain::DaBitPsi, start, count, bits),
            "the daBit psi domain does not read the mask label at `ctx[15] = 0x04`"
        );
        assert_eq!(
            model_kdf(
                &uniform_label(&epoch),
                key,
                model_ctx(sid, PrssDomain::Default.context_tag()),
                start,
                count,
                bits
            ),
            derive_uniform_ints_at(key, sid, start, count, bits),
            "the PRSS uniform label is not `STOFFEL-PRSS-UNIFORM-{epoch}` — the epoch bump left \
             `RandBitA` and `Dn07Double` behind"
        );
        for domain in [PrzsDomain::Arithmetic, PrzsDomain::Binary] {
            assert_eq!(
                model_kdf(
                    &przs_label(&epoch),
                    key,
                    model_ctx(sid, domain.context_tag()),
                    start,
                    count,
                    bits
                ),
                derive_zero_coeff_ints_at(key, sid, domain, start, count, bits),
                "the PRZS label is not `STOFFEL-PRZS-{epoch}` at {domain:?}"
            );
        }
    }
}

/// **A migrated stream cannot issue a position its legacy counter already spent.**
///
/// This is the hazard the migration created and the one no all-honest test could see. Before the
/// `PrssAllocator` landed, `PRandIntMask` took its positions from `PreprocessingMaterial`'s
/// `prandint_cursor` and `DaBitSeed`/`DaBitPsi` from `SubProtocolCounters::dabit_counter`. The
/// allocator's cursors for those three streams had never been advanced, so switching the call
/// sites over without moving the epoch would have re-issued `start = 0` and `exec_id = 0` against
/// bytes those counters had already spent — one pseudorandom value masking two different
/// openings, with nothing on the wire to notice.
///
/// The assertion is taken at the strongest available point: **every** position the legacy
/// counters could plausibly have reached is derived here at the legacy epoch, and **every**
/// position a freshly-zeroed allocator hands out over a wider range is derived through the real
/// production functions. The two sets must not intersect. That is a statement about what is
/// *addressable*, not about what some particular ordering happens to produce — which is why the
/// epoch bump, rather than a seeded cursor, is the right mechanism: no value of any cursor, in
/// any interleaving, under any partial migration, names a legacy byte.
///
/// The live side deliberately covers a **wider** range than the legacy side, so that the test
/// cannot pass merely because the allocator did not get far enough to collide.
#[tokio::test]
async fn no_migrated_stream_can_re_issue_a_position_its_legacy_counter_already_spent() {
    let (n, t) = (10, 3);
    let dealt = deal_keys(n, t, KEY_SEED);
    let keys = &dealt[0];
    let epoch = current_epoch();
    let legacy_mask = mask_label(LEGACY_EPOCH);
    // The legacy `ctx[15]`: `PrssDomain::DaBitPsi` did not exist, so `psi` was drawn at the
    // default tag and separated from `beta` by `ctx[13]` alone.
    let legacy_tag = PrssDomain::Default.context_tag();

    // -- what the legacy counters had already spent -------------------------------------------
    //
    // Ranges chosen well past anything the live side reaches below, so "the live run did not get
    // that far" cannot be why the two sets are disjoint.
    const LEGACY_PRANDINT_POSITIONS: usize = 256;
    const LEGACY_DABIT_EXECS: u64 = 64;
    const LEGACY_DABIT_POSITIONS: usize = 16;

    let mut legacy: BTreeMap<String, String> = BTreeMap::new();
    for start in 0..LEGACY_PRANDINT_POSITIONS {
        legacy.insert(
            legacy_fingerprint(
                keys,
                &legacy_mask,
                prandint_sid(),
                legacy_tag,
                start,
                LAMBDA,
            ),
            format!("legacy prandint_cursor position {start}"),
        );
    }
    for exec in 0..LEGACY_DABIT_EXECS {
        for pos in 0..LEGACY_DABIT_POSITIONS {
            legacy.insert(
                legacy_fingerprint(keys, &legacy_mask, dabit_parent(exec), legacy_tag, pos, 1),
                format!("legacy dabit_counter beta at exec {exec} position {pos}"),
            );
            legacy.insert(
                legacy_fingerprint(keys, &legacy_mask, dabit_psi(exec), legacy_tag, pos, LAMBDA),
                format!("legacy dabit_counter psi at exec {exec} position {pos}"),
            );
        }
    }
    assert!(
        legacy.len()
            >= LEGACY_PRANDINT_POSITIONS + 2 * LEGACY_DABIT_EXECS as usize * LEGACY_DABIT_POSITIONS,
        "the legacy model produced colliding fingerprints, so it is not a faithful model of \
         what those counters spent"
    );

    // -- what a zeroed allocator hands out now -------------------------------------------------
    let f_st = f_prss(n, t);
    let alloc = PrssAllocator::new(INSTANCE, f_st[0].key_family_id());
    let mut collisions: Vec<(String, String)> = Vec::new();
    let mut live = 0usize;

    // `PRandIntMask`, past the legacy cursor's reach.
    let mut claimed = 0usize;
    while claimed < LEGACY_PRANDINT_POSITIONS + 32 {
        let count = 1 + claimed % 7;
        let w = alloc
            .claim(PrssStream::PRandIntMask, count, LAMBDA)
            .await
            .unwrap();
        for i in 0..w.len() {
            let fp =
                live_mask_fingerprint(keys, w.session_id(), w.domain(), w.start() + i, w.bits());
            live += 1;
            if let Some(first) = legacy.get(&fp) {
                collisions.push((
                    first.clone(),
                    format!("live PRandIntMask start {}", w.start() + i),
                ));
            }
        }
        claimed += count;
    }

    // `DaBitSeed` + `DaBitPsi`, past the legacy counter's reach.
    for batch in 0..(LEGACY_DABIT_EXECS + 8) {
        let w = alloc
            .claim_dabit_batch(LEGACY_DABIT_POSITIONS + 4, LAMBDA)
            .await
            .unwrap();
        for (which, window) in [("DaBitSeed", w.seed()), ("DaBitPsi", w.psi())] {
            for i in 0..window.len() {
                let fp = live_mask_fingerprint(
                    keys,
                    window.session_id(),
                    window.domain(),
                    window.start() + i,
                    window.bits(),
                );
                live += 1;
                if let Some(first) = legacy.get(&fp) {
                    collisions.push((
                        first.clone(),
                        format!("live {which} batch {batch} position {i}"),
                    ));
                }
            }
        }
    }

    assert!(
        live > legacy.len(),
        "the live run covered {live} positions against {} legacy ones, so it did not reach far \
         enough to be evidence",
        legacy.len()
    );
    assert!(
        collisions.is_empty(),
        "the epoch bump is not holding: {} live derivation(s) reproduced a byte a legacy counter \
         had already spent. The key family is on epoch `{epoch}` and the legacy epoch is \
         `{LEGACY_EPOCH}`; each pair below is one pseudorandom value masking two different \
         openings:\n{}",
        collisions.len(),
        collisions
            .iter()
            .map(|(a, b)| format!("  {a}  <-->  {b}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// =================================================================================================
// 3. Burn on failure
// =================================================================================================

/// **A failure burns its claimed range; the cursor never goes backwards.**
///
/// The existing retry test models an abort that happens *after* a successful claim. This one
/// covers the rest of the space, because the tempting rewind lives on the error paths:
///
/// * a claim refused **before** the cursor moves (`EmptyClaim`, `StreamWidthMismatch`,
///   `FollowerStream`, `CursorStreamHasNoExec`) must burn **nothing** — and must not rewind
///   either, so the next claim lands exactly one step on, not at zero and not three steps on;
/// * a claim that succeeds and whose batch then dies — a failed Mod2 opening, an exhausted leak
///   budget, a dropped window — must burn its whole range, so the next claim lands strictly
///   beyond it.
///
/// The distinction matters in both directions. Burning on a pre-cursor refusal would let a peer
/// that can provoke refusals exhaust the cursor; *not* burning after a successful claim is the
/// VERIA-222 rewind, which re-derives a mask an opening has already been published under.
///
/// The cursor has no getter — deliberately, since a readable cursor is a cursor something will
/// eventually write — so it is observed the only way production can observe it: through the
/// `exec_id` / `start` of the next window it issues. Every issued position is recorded, and the
/// sequence per stream must be strictly increasing across every step, failures included.
#[tokio::test]
async fn a_failed_claim_burns_its_range_and_never_rewinds_the_cursor() {
    let (n, t) = (10, 3);
    let f_src = f_sources(n, t);
    let f_st = f_prss(n, t);
    let alloc = PrssAllocator::new(INSTANCE, f_src[0].key_family_id());
    let a_bits = PrssDoubleShareSource::<F>::randbit_a_bits();
    let keys = &deal_keys(n, t, KEY_SEED)[0];

    // -- a fresh-exec stream -------------------------------------------------------------------
    let w0 = alloc.claim(PrssStream::RandBitA, 2, a_bits).await.unwrap();
    assert_eq!(w0.session_id().exec_id(), 0);
    drop(w0);

    // Refusals that happen before the cursor is touched. Three of each, so a burn-per-refusal
    // bug shows up as a jump of six rather than of one.
    for _ in 0..3 {
        assert!(
            alloc.claim(PrssStream::RandBitA, 0, a_bits).await.is_err(),
            "a zero-count claim was admitted"
        );
        assert!(
            alloc
                .claim(PrssStream::RandBitA, 2, a_bits + 1)
                .await
                .is_err(),
            "a second width on one stream was admitted"
        );
        assert!(
            alloc.claim(PrssStream::DaBitPsi, 2, LAMBDA).await.is_err(),
            "a follower stream was claimed directly"
        );
        assert!(
            alloc.claim_exec(PrssStream::PRandIntMask).await.is_err(),
            "a cursor-scheme stream was asked for an exec"
        );
    }
    let w1 = alloc.claim(PrssStream::RandBitA, 2, a_bits).await.unwrap();
    assert_eq!(
        w1.session_id().exec_id(),
        1,
        "a refusal that never reached the cursor moved it anyway — a peer that can provoke \
         refusals can now exhaust the stream"
    );

    // A claim that succeeds and then fails downstream. The values are derived first, because that
    // is what makes the rewind a break: the attempt has already put them on the wire.
    let burned_exec = w1.session_id().exec_id();
    let burned: Vec<BigUint> = keys
        .iter()
        .map(|(_, k)| {
            derive_uniform_ints_at(k, w1.session_id(), w1.start(), 1, w1.bits())[0].clone()
        })
        .collect();
    drop(w1); // ... and the batch dies here.

    let w2 = alloc.claim(PrssStream::RandBitA, 2, a_bits).await.unwrap();
    assert!(
        w2.session_id().exec_id() > burned_exec,
        "the cursor went backwards after a failed batch: exec {} was re-issued after {} was \
         burned",
        w2.session_id().exec_id(),
        burned_exec
    );
    let retried: Vec<BigUint> = keys
        .iter()
        .map(|(_, k)| {
            derive_uniform_ints_at(k, w2.session_id(), w2.start(), 1, w2.bits())[0].clone()
        })
        .collect();
    assert_ne!(
        burned, retried,
        "the retry re-derived the range the failed attempt had already spent"
    );

    // -- the cursor-scheme stream, where a rewind is a `start` rewind --------------------------
    let m0 = alloc
        .claim(PrssStream::PRandIntMask, 5, LAMBDA)
        .await
        .unwrap();
    assert_eq!(m0.start(), 0);
    drop(m0); // claimed, never derived from: burned all the same.
    for _ in 0..3 {
        assert!(alloc
            .claim(PrssStream::PRandIntMask, 5, LAMBDA + 1)
            .await
            .is_err());
        assert!(alloc
            .claim(PrssStream::PRandIntMask, 0, LAMBDA)
            .await
            .is_err());
    }
    let m1 = alloc
        .claim(PrssStream::PRandIntMask, 5, LAMBDA)
        .await
        .unwrap();
    assert_eq!(
        m1.start(),
        5,
        "the PRandInt cursor did not advance past a dropped window, or a pre-cursor refusal \
         burned positions"
    );
    drop(m1);
    let m2 = alloc
        .claim(PrssStream::PRandIntMask, 5, LAMBDA)
        .await
        .unwrap();
    assert_eq!(m2.start(), 10, "the PRandInt cursor rewound");
    drop(m2);

    // -- the daBit batch, whose two windows come off one exec ----------------------------------
    //
    // A width mismatch here is checked before the cursor moves, precisely so that a `lambda`
    // disagreement cannot burn execs. Three refusals in a row must therefore leave the next batch
    // at exec 1, not exec 4.
    let d0 = alloc.claim_dabit_batch(4, LAMBDA).await.unwrap();
    assert_eq!(d0.parent_session().exec_id(), 0);
    let opened: Vec<BigUint> = keys
        .iter()
        .map(|(_, k)| {
            derive_ints_at_domain(k, d0.psi().session_id(), d0.psi().domain(), 0, 1, LAMBDA)[0]
                .clone()
        })
        .collect();
    drop(d0); // ... the Mod2 opening fails here, after psi is on the wire.

    for _ in 0..3 {
        assert!(
            alloc.claim_dabit_batch(4, LAMBDA + 1).await.is_err(),
            "a second psi width was admitted"
        );
        assert!(
            alloc.claim_dabit_batch(0, LAMBDA).await.is_err(),
            "an empty daBit batch was admitted"
        );
    }
    let d1 = alloc.claim_dabit_batch(4, LAMBDA).await.unwrap();
    assert_eq!(
        d1.parent_session().exec_id(),
        1,
        "either the daBit cursor rewound onto the failed batch's exec, or a width mismatch \
         burned execs it had promised not to"
    );
    let after: Vec<BigUint> = keys
        .iter()
        .map(|(_, k)| {
            derive_ints_at_domain(k, d1.psi().session_id(), d1.psi().domain(), 0, 1, LAMBDA)[0]
                .clone()
        })
        .collect();
    assert_ne!(
        opened, after,
        "the daBit retry re-derived the Mod2 mask the failed opening had already published under"
    );
    drop(d1);

    // -- and the whole thing, stated as monotonicity over a long adversarial interleaving ------
    //
    // Every step either succeeds (recording the position it issued) or fails (recording nothing).
    // The recorded sequence must be strictly increasing: that is "the cursor never goes
    // backwards" in the only form observable from outside.
    let alloc2 = PrssAllocator::new(INSTANCE, f_st[0].key_family_id());
    let mut execs: Vec<u64> = Vec::new();
    let mut starts: Vec<usize> = Vec::new();

    // Prime both widths first. A stream's width is pinned by its *first* claim, so without this
    // the interleaving's width-mismatch step would be the first claim on `PRandIntMask` and would
    // be accepted — the refusal it is there to provoke has to have something to disagree with.
    let prime_a = alloc2.claim(PrssStream::RandBitA, 1, a_bits).await.unwrap();
    execs.push(prime_a.session_id().exec_id());
    let prime_m = alloc2
        .claim(PrssStream::PRandIntMask, 1, LAMBDA)
        .await
        .unwrap();
    starts.push(prime_m.start());

    for step in 0..40usize {
        match step % 5 {
            0 => {
                assert!(alloc2.claim(PrssStream::RandBitA, 0, a_bits).await.is_err());
            }
            1 => {
                let w = alloc2
                    .claim(PrssStream::RandBitA, 1 + step % 3, a_bits)
                    .await
                    .unwrap();
                execs.push(w.session_id().exec_id());
                // Dropped un-derived on purpose for a third of the steps: a burned range is
                // still burned.
            }
            2 => {
                assert!(alloc2
                    .claim(PrssStream::PRandIntMask, 2, LAMBDA + 1)
                    .await
                    .is_err());
            }
            3 => {
                let w = alloc2
                    .claim(PrssStream::PRandIntMask, 1 + step % 4, LAMBDA)
                    .await
                    .unwrap();
                starts.push(w.start());
            }
            _ => {
                assert!(alloc2.claim_exec(PrssStream::DaBitPsi).await.is_err());
            }
        }
    }
    assert!(
        execs.windows(2).all(|p| p[1] > p[0]),
        "the RandBitA exec sequence is not strictly increasing: {execs:?}"
    );
    assert!(
        starts.windows(2).all(|p| p[1] > p[0]),
        "the PRandInt start sequence is not strictly increasing: {starts:?}"
    );
    assert!(
        execs.len() >= 8 && starts.len() >= 8,
        "the interleaving issued too few positions to be evidence: {} execs, {} starts",
        execs.len(),
        starts.len()
    );
}

// =================================================================================================
// 4. Mutual separation of the streams
// =================================================================================================

/// The keystream family and `ctx[15]` a probe reads under, with the public entry point for each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    Mask(PrssDomain),
    Uniform,
    Przs(PrzsDomain),
}

impl Family {
    fn derive(
        self,
        key: &[u8; PRSS_KEY_LEN],
        sid: SessionId,
        start: usize,
        bits: usize,
    ) -> BigUint {
        match self {
            Family::Mask(domain) => {
                derive_ints_at_domain(key, sid, domain, start, 1, bits)[0].clone()
            }
            Family::Uniform => derive_uniform_ints_at(key, sid, start, 1, bits)[0].clone(),
            Family::Przs(domain) => {
                derive_zero_coeff_ints_at(key, sid, domain, start, 1, bits)[0].clone()
            }
        }
    }
}

/// **No two streams derive the same value at the same index.**
///
/// A reuse *within* a stream and a collision *between* two streams are the same break — one
/// pseudorandom value masking two different openings — and this is the second one. It is not
/// implied by the position tests: every cursor could be perfectly monotone while two streams sit
/// on one `(label, ctx16)`, in which case they tile the *same* keystream and every position
/// either stream issues is issued twice.
///
/// Taken in the strongest available form, for the same reason the `beta`/`psi` test above is:
/// **at the same index, at the same width, on the same key, and at the same `exec_id`**. Every
/// stream's first claim off a fresh allocator is exec 0, so the exec is genuinely shared and the
/// only things left standing between the nine probes are the SP 800-108 label, `ctx[0]`,
/// `ctx[13]` and `ctx[15]`. Comparing at each stream's real width would be a much weaker test,
/// since two different widths read different bytes even out of one stream and the values would
/// differ for the wrong reason.
///
/// Nine probes for seven streams: `Dn07Double` and `GfDn07Double` each ride two keystreams, a
/// PRSS half and a PRZS half, and a collision between the two halves of one double sharing is as
/// bad as any other — the degree-`2t` sharing is `PRSS + PRZS`, so if the halves agreed the mask
/// would be a known multiple of the value it is meant to hide.
#[tokio::test]
async fn no_two_streams_derive_the_same_value_at_the_same_index() {
    for (n, t) in CONFIGS {
        let dealt = deal_keys(n, t, KEY_SEED);
        let f_st = f_prss(n, t);
        let alloc = PrssAllocator::new(INSTANCE, f_st[0].key_family_id());

        // Every session id below comes from a real claim, so nothing here invents an address.
        // Each is that stream's *first* claim, hence exec 0 on every fresh-exec stream.
        let dabits = alloc.claim_dabit_batch(4, LAMBDA).await.unwrap();
        let rb_a = alloc
            .claim(
                PrssStream::RandBitA,
                4,
                PrssDoubleShareSource::<F>::randbit_a_bits(),
            )
            .await
            .unwrap();
        let rb_z = alloc
            .claim(
                PrssStream::RandBitZero,
                4,
                PrssDoubleShareSource::<F>::randbit_zero_bits(),
            )
            .await
            .unwrap();
        let dn07 = alloc
            .claim(
                PrssStream::Dn07Double,
                4,
                PrssDoubleShareSource::<F>::double_bits(),
            )
            .await
            .unwrap();
        let gf = alloc
            .claim(
                PrssStream::GfDn07Double,
                4,
                GfPrssDoubleShareSource::<K>::double_bits().unwrap(),
            )
            .await
            .unwrap();
        let mask = alloc
            .claim(PrssStream::PRandIntMask, 4, LAMBDA)
            .await
            .unwrap();

        let probes: Vec<(&str, PrssStream, Family, SessionId)> = vec![
            (
                "PRandInt mask",
                PrssStream::PRandIntMask,
                Family::Mask(mask.domain()),
                mask.session_id(),
            ),
            (
                "daBit seed beta",
                PrssStream::DaBitSeed,
                Family::Mask(dabits.seed().domain()),
                dabits.seed().session_id(),
            ),
            (
                "daBit Mod2 mask psi",
                PrssStream::DaBitPsi,
                Family::Mask(dabits.psi().domain()),
                dabits.psi().session_id(),
            ),
            (
                "RandBit [a]",
                PrssStream::RandBitA,
                Family::Uniform,
                rb_a.session_id(),
            ),
            (
                "RandBit PRZS re-randomiser",
                PrssStream::RandBitZero,
                Family::Przs(PrzsDomain::Arithmetic),
                rb_z.session_id(),
            ),
            (
                "F double sharing, PRSS half",
                PrssStream::Dn07Double,
                Family::Uniform,
                dn07.session_id(),
            ),
            (
                "F double sharing, PRZS half",
                PrssStream::Dn07Double,
                Family::Przs(PrzsDomain::Arithmetic),
                dn07.session_id(),
            ),
            (
                "GF double sharing, PRSS half",
                PrssStream::GfDn07Double,
                Family::Mask(gf.domain()),
                gf.session_id(),
            ),
            (
                "GF double sharing, PRZS half",
                PrssStream::GfDn07Double,
                Family::Przs(PrzsDomain::Binary),
                gf.session_id(),
            ),
        ];

        // Adding a variant to `PrssStream` without adding a probe here would leave the new stream
        // unchecked against the other six, which is the P1 hazard the enum's exhaustive `match`
        // arms exist to force a decision about. Fail instead.
        let covered: BTreeSet<PrssStream> = probes.iter().map(|(_, s, _, _)| *s).collect();
        assert_eq!(
            covered.len(),
            PrssStream::ALL.len(),
            "n={n}, t={t}: {} of the {} declared streams are probed here; a stream that is not \
             probed is a stream nothing checks for a collision with the others",
            covered.len(),
            PrssStream::ALL.len()
        );
        for stream in PrssStream::ALL {
            assert!(
                covered.contains(&stream),
                "{} has no separation probe",
                stream.name()
            );
        }

        // Every fresh-exec stream's first claim is exec 0, so the exec is genuinely shared across
        // the probes and cannot be what separates them.
        for (what, stream, _, sid) in &probes {
            if stream.is_fresh_exec() {
                assert_eq!(
                    sid.exec_id(),
                    0,
                    "{what}: expected the first claim to be exec 0, so that the comparison below \
                     is at a shared exec rather than separated by one"
                );
            }
        }

        // A common width, so that a collision would be byte-for-byte and a non-collision cannot
        // be blamed on two widths reading different bytes.
        const PROBE_BITS: usize = 64;
        let mut collisions: Vec<String> = Vec::new();
        for index in 0..4usize {
            for (rank, (_, key)) in dealt[0].iter().enumerate() {
                let values: Vec<BigUint> = probes
                    .iter()
                    .map(|(_, _, family, sid)| family.derive(key, *sid, index, PROBE_BITS))
                    .collect();
                for i in 0..probes.len() {
                    for j in (i + 1)..probes.len() {
                        if values[i] == values[j] {
                            collisions.push(format!(
                                "  index {index}, key rank {rank}: `{}` ({:?}) == `{}` ({:?})",
                                probes[i].0, probes[i].2, probes[j].0, probes[j].2
                            ));
                        }
                    }
                }
            }
        }
        assert!(
            collisions.is_empty(),
            "n={n}, t={t}: {} pair(s) of streams derived the same value at the same index, so \
             they share a keystream and every position either of them issues is issued twice:\n{}",
            collisions.len(),
            collisions.join("\n")
        );
    }
}
