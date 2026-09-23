//! Monotone position discipline for PRSS and PRZS — the cursor, as a type.
//!
//! PRSS and PRZS are **stateless and position-addressed**: `derive_ints_at` seeks to byte
//! `start * ceil(bits/8)` of the `(label, key, context)` keystream and reads from there. Nothing
//! in the primitive remembers what it has already produced, so "never derive the same position
//! twice" is entirely an obligation on the caller. Breaking it is a *silent* total privacy break —
//! the same pseudorandom value masks two different openings, the adversary subtracts, and no
//! all-honest test can see it. This is plan §6.5 error 3, and the VERIA-222 cursor-rewind class.
//!
//! Before this module the obligation was discharged by comments and by the happy accident that
//! [`SubProtocolCounter`](crate::honeybadger::SubProtocolCounter) advances *before* the work and
//! is never rolled back. This module makes it a property of the type system instead.
//!
//! # The invariant
//!
//! > **INVARIANT P.** Over the lifetime of a key family `{k_T}`, for every `(label, k_T, ctx16)`
//! > the set of byte intervals ever derived is **pairwise disjoint**.
//!
//! Three consequences worth stating, because each has bitten a design somewhere:
//!
//! * **P1.** Two consumers sharing a `ctx16` must partition `start` *and* agree on `bits`.
//! * **P2.** Two consumers at different `bits` must differ in `ctx16` or in the SP 800-108 label.
//!   Partitioning `start` is **not** sufficient — the address is a byte, not an index, and
//!   `start * ceil(bits/8)` maps two different widths onto overlapping bytes.
//! * **P3.** A consumer whose stride is `t` (PRZS lays a sharing's `t` coefficients out
//!   contiguously) must not share a `ctx16` with one whose stride is 1, even at equal width.
//!
//! # How the types discharge it
//!
//! [`PrssWindow`] is a linear, single-use claim on a half-open range of one keystream. It is not
//! `Clone`, not `Copy`, and has no constructor outside this module: [`PrssAllocator::claim`] is
//! the only issuer, and it advances a monotone cursor **under a lock, before returning**. So:
//!
//! * **Rewinding is unrepresentable.** There is no value of any type that names an
//!   already-issued position.
//! * **Burn-on-error is automatic rather than a discipline.** The cursor moves in `claim`; a
//!   window dropped without being derived from takes its range to the grave. That is the correct
//!   behaviour, not a leak — see the `#[must_use]` note on [`PrssWindow`].
//! * **Concurrency is safe.** [`PrssAllocator`] shares its cursors through an `Arc`, so a cloned
//!   [`HoneyBadgerMPCNode`](crate::honeybadger::HoneyBadgerMPCNode) shares them rather than
//!   forking them. The claim is atomic and happens *before* the derivation, so there is no
//!   read-derive-write window for two clones to interleave in.
//! * **A new consumer must declare itself.** [`PrssStream::addressing`] is an exhaustive `match`
//!   with no wildcard arm, exactly like [`phase_of`](crate::honeybadger::dn07::phase_of): adding
//!   a variant fails to compile until its author says which keystream it lands on.
//!
//! # Restart
//!
//! Positions restart at zero on a process restart — and that is safe **only** because the keys do
//! not survive either. No key store in this crate is `Serialize`, and `setup_prss_keys` gates on
//! an in-memory flag, so a restarted node re-runs RISS and derives under a *fresh key family*.
//! Position 0 under `k_T'` is not position 0 under `k_T`; invariant P is per-key-family, and
//! re-keying discharges it.
//!
//! > **NEGATIVE INVARIANT.** No PRSS/PRZS key store may implement `Serialize`, be written to
//! > disk, or be reconstructed from persisted material, unless a persisted monotone high-water
//! > mark per `(stream, key-family)` is introduced in the *same* change. [`PrssAllocator`] is
//! > zeroed at construction and has no durability; persisting keys without persisting cursors
//! > re-derives every position this node ever opened.
//!
//! [`PrssAllocator::key_family_id`] makes that coupling explicit rather than implied: an
//! allocator is stamped with a fingerprint of the key material it was built alongside, every
//! window carries it, and a consumer checks it before deriving. A node that somehow resumed with
//! an old key family and a zeroed allocator would have to *pass* that check, which it cannot
//! unless keys were persisted — which the invariant above forbids.
//!
//! Note that re-keying is the right answer for *positions* and the wrong answer for the daBit
//! **leak budget**, which is a union bound over all daBits ever produced against one adversary
//! and is currently per-process. That is a separate owner decision and is out of scope here.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::common::ProtocolSessionId;
use crate::honeybadger::prss::prss::PrssDomain;
use crate::honeybadger::prss::PrssError;
use crate::honeybadger::{ProtocolType, SessionId};

/// One keystream family: everything that identifies a PRF output sequence except the position
/// inside it.
///
/// One variant per consumer, and [`Self::addressing`] has no wildcard arm, so a new consumer
/// cannot silently land on an existing stream — its author has to choose.
///
/// **Every variant is claimed through [`PrssAllocator`], with no exception.** That was not always
/// true: [`Self::PRandIntMask`] took its positions from `PreprocessingMaterial`'s
/// `prandint_cursor` and the two daBit streams from `SubProtocolCounters::dabit_counter`. Both of
/// those fields are now **deleted** rather than merely unused — a field that cannot be read
/// cannot become a second minter.
///
/// [`Self::DaBitPsi`] is the one variant with no cursor of its own, and that is not an exemption:
/// it is a *follower*, its `exec_id` minted by [`Self::DaBitSeed`]'s cursor through
/// [`PrssAllocator::claim_dabit_batch`], and [`PrssAllocator::claim`] refuses it outright so it
/// cannot acquire one by the back door. See [`Self::exec_leader`].
///
/// The enum's other job is to be the *map* of every keystream the key family carries: reading it
/// should answer "what else is on these keys?" without grepping.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub enum PrssStream {
    /// `PRandInt` statistical masks. PRSS **mask** label, `exec_id` pinned to 0, moving cursor.
    PRandIntMask,
    /// PRSS-daBit seeds `beta`, width 1, converted in both domains from one draw. `sub_id = 0`.
    ///
    /// **This cursor mints the daBit parent `exec_id` for both drivers** — the generator, which
    /// spends the exec's keystream, and the edaBit modulus-overflow filter, which spends only the
    /// exec's child-id block and derives no PRSS position at all (it burns one through
    /// [`PrssAllocator::claim_exec`]). Both mint children as `parent_exec * 2^20 + wave`, so
    /// drawing every parent exec from this one cursor is what keeps the two drivers' child blocks
    /// disjoint: each exec is handed out once and owns its own block of `2^20` child ids per
    /// child tag. A second minter would hand the filter an exec a daBit batch already owns.
    DaBitSeed,
    /// PRSS-daBit Mod2 mask `psi`, width `lambda`.
    ///
    /// A **follower**: it has no cursor of its own, and [`PrssAllocator::claim`] refuses it. Its
    /// `exec_id` is [`Self::DaBitSeed`]'s, minted once per batch by
    /// [`PrssAllocator::claim_dabit_batch`] — which is what keeps "`psi` derives from the parent
    /// exec" structurally true rather than a coincidence that two independent cursors happen to
    /// maintain.
    ///
    /// Separated from [`Self::DaBitSeed`] by **two** independent bytes, which matters because the
    /// two widths differ (P2) and a merge would be a *partial* overlap producing no equal value
    /// for a ledger to notice: `sub_id = PSI_SUB_ID` in `ctx[13]`, and
    /// [`PrssDomain::DaBitPsi`] (`0x04`) in `ctx[15]`.
    DaBitPsi,
    /// `RandBit`'s `[a]`: **uniform over `F`**, degree `t`. PRSS *uniform* label.
    ///
    /// Not the mask label. `shares_at` sums `beta_T` over the integers into
    /// `[0, C(n,t) * 2^bits)`, which is not uniform on `F`, and `RandBit` takes a square root of
    /// this value.
    RandBitA,
    /// `RandBit`'s degree-`2t` re-randomiser for the `MulPub` opening of `a^2`. PRZS arithmetic
    /// domain, `ctx[15] = 0x02`, stride `t` (P3).
    RandBitZero,
    /// `F`-side DN07 double sharings `([r]_t, [r]_2t)`.
    Dn07Double,
    /// `GF(2^k)`-side DN07 double sharings.
    GfDn07Double,
}

impl PrssStream {
    /// Every variant, for exhaustive tests and for documentation tooling.
    pub const ALL: [PrssStream; 7] = [
        PrssStream::PRandIntMask,
        PrssStream::DaBitSeed,
        PrssStream::DaBitPsi,
        PrssStream::RandBitA,
        PrssStream::RandBitZero,
        PrssStream::Dn07Double,
        PrssStream::GfDn07Double,
    ];

    /// The `(ProtocolType, sub_id, round_id)` triple this stream pins in `ctx16`.
    ///
    /// **Exhaustive on purpose — never add a `_ =>` arm.** The tag lands in `ctx[0]`, the sub and
    /// round bytes in `ctx[13]`/`ctx[14]`; together with the label and `ctx[15]` they are what
    /// separates one stream from another. A wildcard arm would let a new consumer inherit some
    /// existing stream's address by default, which is exactly the P1 violation this module
    /// exists to prevent.
    pub const fn addressing(self) -> (ProtocolType, u8, u8) {
        match self {
            PrssStream::PRandIntMask => (ProtocolType::PRandInt, 0, 0),
            PrssStream::DaBitSeed => (ProtocolType::DaBit, 0, 0),
            // `PSI_SUB_ID`; kept as a literal rather than a use-import so this match stays a
            // `const fn` with no cross-module dependency. The unit tests assert they agree.
            PrssStream::DaBitPsi => (ProtocolType::DaBit, 1, 0),
            // `RandBit` sessions assert `sub_id == 0 && round_id == 0` (`rand_bit.rs`), so both
            // RandBit streams must address `(RandBit, 0, 0)`. They are separated by label
            // (PRSS-uniform vs PRZS) *and* by `ctx[15]` (0x01 vs 0x02), which is what makes two
            // streams at one address legitimate here.
            PrssStream::RandBitA => (ProtocolType::RandBit, 0, 0),
            PrssStream::RandBitZero => (ProtocolType::RandBit, 0, 0),
            PrssStream::Dn07Double => (ProtocolType::Dn07, 0, 0),
            PrssStream::GfDn07Double => (ProtocolType::GfDn07, 0, 0),
        }
    }

    /// The stream whose cursor mints this stream's `exec_id`. Reflexive for a leader.
    ///
    /// **Exhaustive on purpose, no wildcard arm**, exactly like [`Self::addressing`]: a new
    /// follower has to be declared, and a new leader has to say so.
    ///
    /// A follower exists where two keystreams are addressed by *one* logical event — a daBit
    /// batch draws `beta` and `psi` on one `exec_id` — and where giving each its own cursor would
    /// let them drift apart on a partial failure. Two cursors would still be individually
    /// monotone and jointly safe (the two streams differ in `ctx[13]` and `ctx[15]`), but the
    /// structural fact that `psi`'s context *is* the parent's would become an accident.
    pub const fn exec_leader(self) -> PrssStream {
        match self {
            PrssStream::DaBitPsi => PrssStream::DaBitSeed,
            PrssStream::PRandIntMask => PrssStream::PRandIntMask,
            PrssStream::DaBitSeed => PrssStream::DaBitSeed,
            PrssStream::RandBitA => PrssStream::RandBitA,
            PrssStream::RandBitZero => PrssStream::RandBitZero,
            PrssStream::Dn07Double => PrssStream::Dn07Double,
            PrssStream::GfDn07Double => PrssStream::GfDn07Double,
        }
    }

    /// The `ctx[15]` domain byte this stream's **PRSS** draws take.
    ///
    /// **Exhaustive on purpose, no wildcard arm.** Only [`Self::DaBitPsi`] is not
    /// [`PrssDomain::Default`]; see that variant, and [`PrssDomain`], for why one byte of
    /// separation was not enough for it.
    ///
    /// Meaningless for the PRZS half of [`Self::RandBitZero`], [`Self::Dn07Double`] and
    /// [`Self::GfDn07Double`]: those carry their own
    /// [`PrzsDomain`](crate::honeybadger::przs::PrzsDomain) (`0x02`/`0x03`) and never read this.
    pub const fn domain(self) -> PrssDomain {
        match self {
            PrssStream::DaBitPsi => PrssDomain::DaBitPsi,
            PrssStream::PRandIntMask => PrssDomain::Default,
            PrssStream::DaBitSeed => PrssDomain::Default,
            PrssStream::RandBitA => PrssDomain::Default,
            PrssStream::RandBitZero => PrssDomain::Default,
            PrssStream::Dn07Double => PrssDomain::Default,
            PrssStream::GfDn07Double => PrssDomain::Default,
        }
    }

    /// `true` if a batch takes a fresh `exec_id` and always starts at position 0; `false` if it
    /// pins `exec_id = 0` and advances `start`.
    ///
    /// Both schemes satisfy invariant P. They must never be *mixed* on one stream: a fresh-exec
    /// claim at `start = 0` and a cursor claim at `start = 0` on `exec = 0` name the same bytes.
    /// The allocator keeps one cursor per stream and reads this to decide what that cursor means,
    /// so mixing is not expressible.
    pub const fn is_fresh_exec(self) -> bool {
        match self {
            // The only cursor-scheme stream: `prandint.rs` hard-wires `exec_id = 0`.
            PrssStream::PRandIntMask => false,
            PrssStream::DaBitSeed => true,
            PrssStream::DaBitPsi => true,
            PrssStream::RandBitA => true,
            PrssStream::RandBitZero => true,
            PrssStream::Dn07Double => true,
            PrssStream::GfDn07Double => true,
        }
    }

    /// Short name, for error messages. `Debug` would do, but errors cross `thiserror` boundaries
    /// that want a `&'static str`.
    pub const fn name(self) -> &'static str {
        match self {
            PrssStream::PRandIntMask => "PRandIntMask",
            PrssStream::DaBitSeed => "DaBitSeed",
            PrssStream::DaBitPsi => "DaBitPsi",
            PrssStream::RandBitA => "RandBitA",
            PrssStream::RandBitZero => "RandBitZero",
            PrssStream::Dn07Double => "Dn07Double",
            PrssStream::GfDn07Double => "GfDn07Double",
        }
    }
}

/// A half-open, **single-use** claim on `count` positions of one keystream.
///
/// Not `Clone`, not `Copy`, and constructible only by [`PrssAllocator::claim`] (plus a
/// test-only escape hatch that exists so the attack can be written down). Holding one is proof
/// that a monotone cursor was advanced past this range before it was handed out.
///
/// # `#[must_use]`, and why dropping one is correct
///
/// A dropped window's range is **burned**, not returned. That is deliberate: the alternative —
/// rolling the cursor back when a batch fails — is precisely the rewind that re-derives an
/// already-opened position. Positions are cheap (`u64` of them) and privacy is not. The
/// `must_use` is there to make an accidental drop visible, not to suggest one is recoverable.
#[derive(Debug)]
#[must_use = "a claimed PRSS window is burned whether or not it is derived from"]
pub struct PrssWindow {
    session_id: SessionId,
    start: usize,
    count: usize,
    stream: PrssStream,
    bits: usize,
    domain: PrssDomain,
    key_family_id: [u8; 32],
}

impl PrssWindow {
    /// Positions claimed.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Always `false` for a window from [`PrssAllocator::claim`], which rejects `count == 0`.
    /// Present because `len` without it is a clippy error under `-D warnings`.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// First position of the claim.
    pub fn start(&self) -> usize {
        self.start
    }

    /// The keystream this window addresses.
    pub fn stream(&self) -> PrssStream {
        self.stream
    }

    /// Element width, in bits, this window was claimed at. A derivation must use exactly this:
    /// the same `start` at a different width reads different bytes (P2).
    pub fn bits(&self) -> usize {
        self.bits
    }

    /// The `ctx[15]` domain byte this window's derivation must use — [`PrssStream::domain`] of
    /// [`Self::stream`], recorded at the claim so that a derivation cannot pick its own.
    pub fn domain(&self) -> PrssDomain {
        self.domain
    }

    /// Fingerprint of the key family the issuing allocator was built alongside. A consumer
    /// compares it against its own store's before deriving, so a window cannot be spent on keys
    /// it was not counted against.
    pub fn key_family_id(&self) -> [u8; 32] {
        self.key_family_id
    }

    /// The session id carrying this window's `ctx16`.
    ///
    /// Deliberately not a route back into a derivation. Every production derivation entry point
    /// takes a *window* now — `PrssKeys::shares_at_in`, `GfPrssKeys::bit_shares_at_in`,
    /// `PRandIntNode::generate_prss_in`, `PrssDoubleShareSource`'s `*_in` family — so this
    /// accessor exists for those implementations, and for tests that assert on addressing.
    /// Reaching for it in order to call a positional `*_at` primitive is exactly the bypass the
    /// window type exists to close.
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Test-only constructor, so that a test can deliberately build two *overlapping* windows and
    /// demonstrate that position reuse is fatal. Nothing outside `#[cfg(test)]` can do this.
    #[cfg(test)]
    pub(crate) fn for_test(
        stream: PrssStream,
        exec: u64,
        start: usize,
        count: usize,
        bits: usize,
        instance_id: u32,
        key_family_id: [u8; 32],
    ) -> Self {
        let (tag, sub_id, round_id) = stream.addressing();
        Self {
            session_id: SessionId::new(
                tag,
                SessionId::pack_slot(exec, sub_id, round_id),
                instance_id,
            ),
            start,
            count,
            stream,
            bits,
            domain: stream.domain(),
            key_family_id,
        }
    }
}

/// Owns every PRSS/PRZS cursor bound to one key family.
///
/// `Clone` shares the cursors through an `Arc`, which is the whole point: a cloned
/// [`HoneyBadgerMPCNode`](crate::honeybadger::HoneyBadgerMPCNode) must not fork them. Two clones
/// racing on one stream serialise on the mutex and receive disjoint ranges.
#[derive(Clone, Debug)]
pub struct PrssAllocator {
    instance_id: u32,
    key_family_id: [u8; 32],
    /// Per stream: the next value to hand out. For a fresh-exec stream that is the next
    /// `exec_id`; for a cursor stream it is the next `start`. `None` once saturated, so the
    /// allocator hard-errors rather than wrapping onto a position it has already issued — the
    /// same latch `SubProtocolCounter` uses, for the same reason.
    cursors: Arc<Mutex<HashMap<PrssStream, Option<u64>>>>,
    /// Per stream: the width every claim on it must agree on, recorded from the first claim.
    /// This is the P2 guard, and it is why the width is part of the claim rather than of the
    /// derivation call.
    widths: Arc<Mutex<HashMap<PrssStream, usize>>>,
}

impl PrssAllocator {
    /// A fresh allocator, all cursors at zero, bound to the key family `key_family_id`
    /// fingerprints.
    ///
    /// Build exactly one per key family, at the moment the keys are installed. Building a second
    /// one over the same keys forks the cursors and re-issues every position — which is why the
    /// only caller in this crate is `setup_prss_keys`, alongside the key stores themselves.
    pub fn new(instance_id: u32, key_family_id: [u8; 32]) -> Self {
        Self {
            instance_id,
            key_family_id,
            cursors: Arc::new(Mutex::new(HashMap::new())),
            widths: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// The key family this allocator's positions are counted against.
    pub fn key_family_id(&self) -> [u8; 32] {
        self.key_family_id
    }

    /// Claims `count` positions on `stream` at width `bits`, advancing the cursor atomically.
    ///
    /// Never returns an overlapping window and never returns a window twice, including under
    /// concurrent callers on clones of this allocator and including after an error downstream:
    /// the cursor moves here, before any derivation, and there is no path that moves it back.
    ///
    /// # Errors
    /// - [`PrssError::EmptyClaim`] for `count == 0`. A zero-width claim is always a caller bug,
    ///   and admitting it would make "was this position issued?" ambiguous.
    /// - [`PrssError::StreamWidthMismatch`] if `bits` disagrees with this stream's first claim.
    ///   That is the P2 guard: same stream, same `start`, different width reads overlapping
    ///   bytes.
    /// - [`PrssError::CursorExhausted`] on saturation.
    pub async fn claim(
        &self,
        stream: PrssStream,
        count: usize,
        bits: usize,
    ) -> Result<PrssWindow, PrssError> {
        // A follower has no cursor of its own: claiming it directly would hand it an `exec_id`
        // its leader has not burned, i.e. re-address a keystream the leader can still issue.
        // Refused here rather than documented, so that the only way to a `DaBitPsi` window is
        // through `claim_dabit_batch`.
        if stream.exec_leader() != stream {
            return Err(PrssError::FollowerStream {
                stream: stream.name(),
                leader: stream.exec_leader().name(),
            });
        }
        if count == 0 || bits == 0 {
            return Err(PrssError::EmptyClaim {
                stream: stream.name(),
            });
        }

        {
            let mut widths = self.widths.lock().await;
            match widths.get(&stream) {
                Some(&w) if w != bits => {
                    return Err(PrssError::StreamWidthMismatch {
                        stream: stream.name(),
                        expected: w,
                        got: bits,
                    })
                }
                Some(_) => {}
                None => {
                    widths.insert(stream, bits);
                }
            }
        }

        let (tag, sub_id, round_id) = stream.addressing();

        // How far the cursor must move for this claim: one whole keystream for a fresh-exec
        // stream, `count` positions for a cursor stream. `checked_*` throughout — a wrapped
        // cursor aliases an old position, which is the failure this type exists to prevent, and
        // it must fault loudly instead.
        let (exec, start) = if stream.is_fresh_exec() {
            (self.burn_exec(stream).await?, 0usize)
        } else {
            (0u64, self.burn_positions(stream, count).await?)
        };

        Ok(PrssWindow {
            session_id: SessionId::new(
                tag,
                SessionId::pack_slot(exec, sub_id, round_id),
                self.instance_id,
            ),
            start,
            count,
            stream,
            bits,
            domain: stream.domain(),
            key_family_id: self.key_family_id,
        })
    }

    /// Burns one [`PrssStream::DaBitSeed`] `exec_id` and returns **both** of a daBit batch's
    /// windows on it.
    ///
    /// One claim, one exec, two keystreams. `psi` is not claimed from a cursor of its own — its
    /// context is the seed's with `ctx[13]` replaced by [`PSI_SUB_ID`] and `ctx[15]` replaced by
    /// [`PrssDomain::DaBitPsi`] — which is what keeps the daBit generator's "`psi` derives from
    /// the parent exec" structurally true rather than a coincidence maintained by two cursors.
    ///
    /// The seed width is pinned to `1` here rather than taken from the caller: a daBit seed is a
    /// bit, and admitting a parameter would admit a second width on that keystream. `psi_bits` is
    /// the caller's `DaBitLeakBudget::mask_bits`, recorded on the first claim and enforced on
    /// every later one — the P2 guard, which is why both widths are checked **before** the cursor
    /// moves: a width mismatch must not burn an exec.
    ///
    /// # Errors
    /// - [`PrssError::EmptyClaim`] for `count == 0` or `psi_bits == 0`.
    /// - [`PrssError::StreamWidthMismatch`] if either width disagrees with this stream's first
    ///   claim. Raised before the cursor moves.
    /// - [`PrssError::CursorExhausted`] on saturation.
    pub async fn claim_dabit_batch(
        &self,
        count: usize,
        psi_bits: usize,
    ) -> Result<DaBitWindows, PrssError> {
        if count == 0 || psi_bits == 0 {
            return Err(PrssError::EmptyClaim {
                stream: PrssStream::DaBitSeed.name(),
            });
        }

        // Both widths agreed under one lock, and only then inserted. Checking and inserting in
        // two passes inside the same critical section is what makes "either both widths are
        // accepted or neither is recorded" hold.
        let pinned = [
            (PrssStream::DaBitSeed, DABIT_SEED_BITS),
            (PrssStream::DaBitPsi, psi_bits),
        ];
        {
            let mut widths = self.widths.lock().await;
            for (stream, bits) in pinned {
                if let Some(&w) = widths.get(&stream) {
                    if w != bits {
                        return Err(PrssError::StreamWidthMismatch {
                            stream: stream.name(),
                            expected: w,
                            got: bits,
                        });
                    }
                }
            }
            for (stream, bits) in pinned {
                widths.entry(stream).or_insert(bits);
            }
        }

        let exec = self.burn_exec(PrssStream::DaBitSeed).await?;

        let window = |stream: PrssStream, bits: usize| {
            let (tag, sub_id, round_id) = stream.addressing();
            PrssWindow {
                session_id: SessionId::new(
                    tag,
                    SessionId::pack_slot(exec, sub_id, round_id),
                    self.instance_id,
                ),
                start: 0,
                count,
                stream,
                bits,
                domain: stream.domain(),
                key_family_id: self.key_family_id,
            }
        };

        Ok(DaBitWindows {
            seed: window(PrssStream::DaBitSeed, DABIT_SEED_BITS),
            psi: window(PrssStream::DaBitPsi, psi_bits),
        })
    }

    /// Burns one `exec_id` on a fresh-exec stream **without** claiming any derivable position.
    ///
    /// For a consumer that needs the *session-id block* an exec names but derives no PRSS
    /// position from it — the edaBit modulus-overflow filter, which mints its child sessions as
    /// `exec * 2^20 + wave` and reads no keystream. Holding a [`PrssExecSlot`] proves the exec
    /// will never be minted again; holding one gives no way to name a byte.
    ///
    /// # Errors
    /// - [`PrssError::CursorStreamHasNoExec`] for a cursor-scheme stream, which pins `exec_id = 0`
    ///   and has no exec to burn.
    /// - [`PrssError::FollowerStream`] for a stream whose [`PrssStream::exec_leader`] is not
    ///   itself: burning a follower's exec independently is exactly the drift the follower
    ///   relationship exists to prevent.
    /// - [`PrssError::CursorExhausted`] on saturation.
    pub async fn claim_exec(&self, stream: PrssStream) -> Result<PrssExecSlot, PrssError> {
        if !stream.is_fresh_exec() {
            return Err(PrssError::CursorStreamHasNoExec {
                stream: stream.name(),
            });
        }
        if stream.exec_leader() != stream {
            return Err(PrssError::FollowerStream {
                stream: stream.name(),
                leader: stream.exec_leader().name(),
            });
        }
        let exec = self.burn_exec(stream).await?;
        Ok(PrssExecSlot {
            stream,
            exec,
            instance_id: self.instance_id,
        })
    }

    /// Advances a fresh-exec stream's cursor by one and returns the exec it burned.
    ///
    /// The single place a fresh `exec_id` comes from, shared by [`Self::claim`],
    /// [`Self::claim_dabit_batch`] and [`Self::claim_exec`], so that all three consume the *same*
    /// cursor rather than three that happen to agree.
    async fn burn_exec(&self, stream: PrssStream) -> Result<u64, PrssError> {
        let mut cursors = self.cursors.lock().await;
        let slot = cursors.entry(stream).or_insert(Some(0));
        let Some(current) = *slot else {
            return Err(PrssError::CursorExhausted {
                stream: stream.name(),
            });
        };
        let Some(next) = current.checked_add(1) else {
            *slot = None;
            return Err(PrssError::CursorExhausted {
                stream: stream.name(),
            });
        };
        *slot = Some(next);
        Ok(current)
    }

    /// Advances a cursor-scheme stream's cursor by `count` positions and returns the `start` it
    /// burned. The counterpart of [`Self::burn_exec`] for the one scheme that moves `start`
    /// rather than `exec_id`.
    async fn burn_positions(&self, stream: PrssStream, count: usize) -> Result<usize, PrssError> {
        let exhausted = || PrssError::CursorExhausted {
            stream: stream.name(),
        };
        let step = u64::try_from(count).map_err(|_| exhausted())?;

        let mut cursors = self.cursors.lock().await;
        let slot = cursors.entry(stream).or_insert(Some(0));
        let Some(current) = *slot else {
            return Err(exhausted());
        };
        let Some(next) = current.checked_add(step) else {
            *slot = None;
            return Err(exhausted());
        };
        *slot = Some(next);
        drop(cursors);

        usize::try_from(current).map_err(|_| exhausted())
    }
}

/// Width of one [`PrssStream::DaBitSeed`] draw, in bits. A daBit seed is a bit; this is not a
/// parameter anywhere, which is what keeps a second width off that keystream (P2).
const DABIT_SEED_BITS: usize = 1;

/// The two windows one PRSS daBit batch spends, minted from **one** `exec_id`.
///
/// Returned only by [`PrssAllocator::claim_dabit_batch`]. Like [`PrssWindow`] it is single-use and
/// burned on drop: the exec moved when it was handed out and there is no path that moves it back.
#[derive(Debug)]
#[must_use = "a claimed PRSS window is burned whether or not it is derived from"]
pub struct DaBitWindows {
    seed: PrssWindow,
    psi: PrssWindow,
}

impl DaBitWindows {
    /// The seed window: `beta`, width 1, the draw both domains convert.
    pub fn seed(&self) -> &PrssWindow {
        &self.seed
    }

    /// The Mod2 mask window: `psi`, width `lambda`, on the parent's exec with its own `ctx[13]`
    /// and `ctx[15]`.
    pub fn psi(&self) -> &PrssWindow {
        &self.psi
    }

    /// daBits in this batch. Equal for both windows by construction, which is why the consumer
    /// takes its count from here instead of from a parameter — you cannot derive more than you
    /// claimed if the number is not yours to pass.
    pub fn len(&self) -> usize {
        self.seed.len()
    }

    /// Always `false`: `claim_dabit_batch` rejects `count == 0`. Present because `len` without it
    /// is a clippy error under `-D warnings`.
    pub fn is_empty(&self) -> bool {
        self.seed.is_empty()
    }

    /// The `(DaBit, exec, 0, 0)` parent session this batch's child sessions hang off.
    ///
    /// Safe to hand out, unlike [`PrssExecSlot`]: it is the seed window's own session, and the
    /// seed window has already been claimed by whoever holds this.
    pub fn parent_session(&self) -> SessionId {
        self.seed.session_id()
    }
}

/// A burned `exec_id` on a fresh-exec stream, carrying **no** right to derive anything.
///
/// Holding one proves the exec will never be minted again. Holding one gives no way to name a
/// byte — deliberately: there is no `parent_session()` accessor here, because handing back a
/// `SessionId` that a positional `*_at` primitive would accept reopens exactly the door the window
/// type closes. A consumer builds its own child ids from [`Self::exec_id`].
#[derive(Debug)]
#[must_use = "a claimed exec id is burned whether or not it is used"]
pub struct PrssExecSlot {
    stream: PrssStream,
    exec: u64,
    instance_id: u32,
}

impl PrssExecSlot {
    /// The burned `exec_id`.
    pub fn exec_id(&self) -> u64 {
        self.exec
    }

    /// The stream whose cursor burned it.
    pub fn stream(&self) -> PrssStream {
        self.stream
    }

    /// The instance the issuing allocator is bound to.
    pub fn instance_id(&self) -> u32 {
        self.instance_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const PSI_SUB_ID: u8 = 1;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use std::collections::BTreeSet;

    fn family(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    /// One issued claim, flattened to the byte interval it will actually read.
    ///
    /// Keyed on **bytes**, not on positions, because that is where the real hazard lives: the
    /// same `start` at two widths reads overlapping bytes (P2), and an index-keyed ledger would
    /// call that disjoint.
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    struct Interval {
        stream: PrssStream,
        /// `ctx16` is a function of `(tag, instance, exec, sub, round)`; the exec is the only part
        /// that moves, so the session id stands in for the whole context here.
        session: u128,
        lo: u128,
        hi: u128,
    }

    fn interval(w: &PrssWindow, stride: usize) -> Interval {
        let width = w.bits().div_ceil(8) * stride;
        Interval {
            stream: w.stream(),
            session: w.session_id().as_u128(),
            lo: (w.start() as u128) * width as u128,
            hi: ((w.start() + w.len()) as u128) * width as u128,
        }
    }

    /// Every stream's byte intervals must be pairwise disjoint *within one keystream*. Two
    /// intervals on different sessions (different `exec_id`, hence different `ctx16`) are on
    /// different keystreams and may overlap freely.
    fn assert_pairwise_disjoint(mut ledger: Vec<Interval>) {
        ledger.sort();
        for pair in ledger.windows(2) {
            let (a, b) = (&pair[0], &pair[1]);
            if a.stream != b.stream || a.session != b.session {
                continue;
            }
            assert!(
                a.hi <= b.lo,
                "overlapping byte intervals on one keystream: {a:?} and {b:?}"
            );
        }
    }

    #[test]
    fn every_stream_declares_an_address_and_the_shared_ones_are_deliberate() {
        // The two RandBit streams are the only pair that share an address, and they are allowed
        // to because they differ in SP 800-108 label (PRSS-uniform vs PRZS) *and* in `ctx[15]`
        // (0x01 vs 0x02). Every other pair must differ in the address itself. If a future stream
        // lands on an existing address this fails, which is the point: `addressing` compiles for
        // a new variant, so the collision check has to be a test.
        let mut seen: Vec<(PrssStream, (ProtocolType, u8, u8))> = Vec::new();
        for s in PrssStream::ALL {
            let addr = s.addressing();
            for (other, other_addr) in &seen {
                let allowed = matches!(
                    (s, other),
                    (PrssStream::RandBitZero, PrssStream::RandBitA)
                        | (PrssStream::RandBitA, PrssStream::RandBitZero)
                );
                assert!(
                    *other_addr != addr || allowed,
                    "{} and {} share address {addr:?} without a label/domain separator",
                    s.name(),
                    other.name()
                );
            }
            seen.push((s, addr));
        }
        // `DaBitPsi` is separated from `DaBitSeed` by one byte and the two widths differ, so this
        // literal is load-bearing rather than cosmetic.
        assert_eq!(PrssStream::DaBitPsi.addressing().1, PSI_SUB_ID);
        assert_eq!(PrssStream::DaBitSeed.addressing().1, 0);
        // RandBit sessions assert `sub_id == 0 && round_id == 0`.
        assert_eq!(
            PrssStream::RandBitA.addressing(),
            (ProtocolType::RandBit, 0, 0)
        );
        assert_eq!(
            PrssStream::RandBitZero.addressing(),
            (ProtocolType::RandBit, 0, 0)
        );
    }

    #[tokio::test]
    async fn claims_on_one_stream_are_monotone_and_never_overlap() {
        let alloc = PrssAllocator::new(7, family(0xAB));
        let mut ledger = Vec::new();
        let mut rng = StdRng::seed_from_u64(0xC0FFEE);

        // Interleave the two RandBit streams with the cursor-scheme PRandInt stream, and drop
        // roughly a third of the windows without deriving from them — the "batch aborted after
        // the claim" case. A dropped window's range must stay burned.
        for _ in 0..200 {
            let count: usize = rng.gen_range(1, 17);
            let w = alloc.claim(PrssStream::RandBitA, count, 256).await.unwrap();
            if rng.gen_bool(0.34) {
                drop(w);
            } else {
                ledger.push(interval(&w, 1));
            }
            let z = alloc
                .claim(PrssStream::RandBitZero, count, 256)
                .await
                .unwrap();
            ledger.push(interval(&z, 3));
            let m = alloc
                .claim(PrssStream::PRandIntMask, count, 40)
                .await
                .unwrap();
            ledger.push(interval(&m, 1));
        }

        assert_pairwise_disjoint(ledger.clone());

        // The cursor stream is the interesting one: it stays on a single keystream, so its
        // intervals must tile without gaps or repeats.
        let mask: BTreeSet<(u128, u128)> = ledger
            .iter()
            .filter(|i| i.stream == PrssStream::PRandIntMask)
            .map(|i| (i.lo, i.hi))
            .collect();
        assert_eq!(mask.len(), 200, "a cursor claim was issued twice");
        let mut prev = 0u128;
        for (lo, hi) in mask {
            assert_eq!(lo, prev, "the PRandInt cursor rewound or skipped");
            prev = hi;
        }
    }

    #[tokio::test]
    async fn concurrent_clones_share_one_cursor_rather_than_forking_it() {
        // This is the hazard a read-derive-then-write cursor has and this type does not: two
        // clones of a node interleaving read and write both derive the same range. The claim is
        // atomic and precedes every derivation, so there is nothing to interleave.
        let alloc = PrssAllocator::new(9, family(0x11));
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let a = alloc.clone();
            tasks.push(tokio::spawn(async move {
                let mut out = Vec::new();
                for k in 0..25usize {
                    let w = a
                        .claim(PrssStream::PRandIntMask, 1 + k % 5, 40)
                        .await
                        .unwrap();
                    out.push(interval(&w, 1));
                    // Yield between claims so the runtime actually interleaves the tasks.
                    tokio::task::yield_now().await;
                }
                out
            }));
        }
        let mut ledger = Vec::new();
        for t in tasks {
            ledger.extend(t.await.unwrap());
        }
        assert_eq!(ledger.len(), 200);
        assert_pairwise_disjoint(ledger.clone());
        // And nothing was lost: the burned ranges tile [0, total).
        let total: u128 = ledger.iter().map(|i| i.hi - i.lo).sum();
        let max = ledger.iter().map(|i| i.hi).max().unwrap();
        assert_eq!(total, max, "claims on one cursor stream must tile exactly");
    }

    #[tokio::test]
    async fn a_second_width_on_one_stream_is_refused() {
        // P2. `start` is multiplied by `ceil(bits/8)`, so the same stream at two widths reads
        // overlapping bytes no matter how the positions are partitioned.
        // `Dn07Double` rather than `DaBitPsi`: the latter is a follower now and `claim` refuses it
        // outright, which is a different — and stronger — rejection. Its own width guard is
        // exercised through `claim_dabit_batch` in
        // `a_width_mismatch_on_a_dabit_batch_burns_nothing`.
        let alloc = PrssAllocator::new(1, family(0x22));
        let _ = alloc.claim(PrssStream::Dn07Double, 4, 62).await.unwrap();
        let err = alloc
            .claim(PrssStream::Dn07Double, 4, 40)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                PrssError::StreamWidthMismatch {
                    expected: 62,
                    got: 40,
                    ..
                }
            ),
            "expected a width mismatch, got {err:?}"
        );
        // A different stream at that width is fine — it is a different keystream.
        let _ = alloc.claim(PrssStream::PRandIntMask, 4, 40).await.unwrap();
    }

    #[tokio::test]
    async fn an_empty_claim_is_refused() {
        let alloc = PrssAllocator::new(1, family(0x33));
        assert!(matches!(
            alloc.claim(PrssStream::RandBitA, 0, 256).await.unwrap_err(),
            PrssError::EmptyClaim { .. }
        ));
        assert!(matches!(
            alloc.claim(PrssStream::RandBitA, 4, 0).await.unwrap_err(),
            PrssError::EmptyClaim { .. }
        ));
    }

    #[tokio::test]
    async fn a_saturated_cursor_faults_instead_of_wrapping() {
        // Wrapping would alias position 0, which is a position this allocator has already issued.
        // It must latch, exactly as `SubProtocolCounter` does at `u64::MAX`.
        let alloc = PrssAllocator::new(1, family(0x44));
        let huge = usize::try_from(u64::MAX).unwrap_or(usize::MAX);
        let _ = alloc
            .claim(PrssStream::PRandIntMask, huge, 40)
            .await
            .unwrap();
        for _ in 0..2 {
            assert!(matches!(
                alloc
                    .claim(PrssStream::PRandIntMask, 1, 40)
                    .await
                    .unwrap_err(),
                PrssError::CursorExhausted { .. }
            ));
        }
    }

    /// Every stream in the map, claimed through the allocator, with the two daBit streams going
    /// through the one call that mints them. What this proves is that the *allocator* is monotone
    /// and its intervals disjoint — and nothing at all about whether consumers spend what they
    /// claimed. That is the consumers' own tests' job, and `prss_position_test.rs`'s.
    #[tokio::test]
    async fn claims_across_every_stream_are_pairwise_disjoint() {
        const LAMBDA: usize = 40;
        let alloc = PrssAllocator::new(3, family(0x66));
        let t = 3usize;
        let mut ledger = Vec::new();
        let mut rng = StdRng::seed_from_u64(0xBEEF);

        for wave in 0..40 {
            let count: usize = rng.gen_range(1, 9);

            // The four streams with plain cursors, at the widths their consumers use.
            for (stream, bits, stride) in [
                (PrssStream::PRandIntMask, LAMBDA, 1usize),
                (PrssStream::RandBitA, 256, 1),
                (PrssStream::RandBitZero, 256, t),
                (PrssStream::Dn07Double, 256, 1),
                (PrssStream::GfDn07Double, 8, 1),
            ] {
                let w = alloc.claim(stream, count, bits).await.unwrap();
                // A third of the windows are dropped undrived — the "batch aborted after the
                // claim" case. A dropped window's range must stay burned.
                if rng.gen_bool(0.34) {
                    drop(w);
                } else {
                    ledger.push(interval(&w, stride));
                }
            }

            // The daBit pair, from one claim on one exec.
            let d = alloc.claim_dabit_batch(count, LAMBDA).await.unwrap();
            assert_eq!(d.len(), count);
            assert!(!d.is_empty());
            assert_eq!(d.parent_session(), d.seed().session_id());
            assert_eq!(
                d.seed().session_id().exec_id(),
                d.psi().session_id().exec_id()
            );
            ledger.push(interval(d.seed(), 1));
            ledger.push(interval(d.psi(), 1));

            // And the filter's exec-only burn, off the same cursor as the pair above.
            let slot = alloc.claim_exec(PrssStream::DaBitSeed).await.unwrap();
            assert_eq!(slot.stream(), PrssStream::DaBitSeed);
            assert_eq!(slot.instance_id(), 3);
            assert_eq!(
                slot.exec_id(),
                d.seed().session_id().exec_id() + 1,
                "wave {wave}: the filter and the generator are not on one cursor"
            );
            drop(d);
        }

        assert_pairwise_disjoint(ledger);

        // The follower must never acquire a cursor of its own. If this ever fails, some code path
        // has called `claim(DaBitPsi, ..)` and started a second minter on that keystream.
        let cursors = alloc.cursors.lock().await;
        assert!(
            !cursors.contains_key(&PrssStream::DaBitPsi),
            "DaBitPsi grew a cursor: its exec is the leader's to mint"
        );
        // Its *width* is pinned, though, which is what the P2 guard needs.
        drop(cursors);
        let widths = alloc.widths.lock().await;
        assert_eq!(widths.get(&PrssStream::DaBitSeed), Some(&1));
        assert_eq!(widths.get(&PrssStream::DaBitPsi), Some(&LAMBDA));
    }

    /// A follower has no cursor, so neither claim route may hand it one.
    #[tokio::test]
    async fn a_follower_stream_cannot_be_claimed_directly() {
        let alloc = PrssAllocator::new(1, family(0x77));
        assert!(matches!(
            alloc.claim(PrssStream::DaBitPsi, 4, 40).await.unwrap_err(),
            PrssError::FollowerStream {
                stream: "DaBitPsi",
                leader: "DaBitSeed"
            }
        ));
        assert!(matches!(
            alloc.claim_exec(PrssStream::DaBitPsi).await.unwrap_err(),
            PrssError::FollowerStream { .. }
        ));
        // The refusal must not have moved anything: the leader still issues exec 0.
        let w = alloc.claim_dabit_batch(1, 40).await.unwrap();
        assert_eq!(w.parent_session().exec_id(), 0);
    }

    /// A cursor-scheme stream pins `exec_id = 0`, so there is no exec to burn. Handing one out
    /// would name the *same* exec every time, which is the opposite of what a burn means.
    #[tokio::test]
    async fn a_cursor_stream_has_no_exec_to_burn() {
        let alloc = PrssAllocator::new(1, family(0x88));
        assert!(matches!(
            alloc
                .claim_exec(PrssStream::PRandIntMask)
                .await
                .unwrap_err(),
            PrssError::CursorStreamHasNoExec {
                stream: "PRandIntMask"
            }
        ));
        for stream in PrssStream::ALL {
            if stream.is_fresh_exec() && stream.exec_leader() == stream {
                assert!(alloc.claim_exec(stream).await.is_ok(), "{}", stream.name());
            }
        }
    }

    /// The width guard runs **before** the cursor moves, so a mismatched batch cannot burn an
    /// exec. Getting this backwards would make a misconfigured caller silently eat execs.
    #[tokio::test]
    async fn a_width_mismatch_on_a_dabit_batch_burns_nothing() {
        let alloc = PrssAllocator::new(1, family(0x99));
        let first = alloc.claim_dabit_batch(2, 40).await.unwrap();
        assert_eq!(first.parent_session().exec_id(), 0);
        drop(first);

        assert!(matches!(
            alloc.claim_dabit_batch(2, 62).await.unwrap_err(),
            PrssError::StreamWidthMismatch {
                stream: "DaBitPsi",
                expected: 40,
                got: 62
            }
        ));
        assert!(matches!(
            alloc.claim_dabit_batch(0, 40).await.unwrap_err(),
            PrssError::EmptyClaim { .. }
        ));
        assert!(matches!(
            alloc.claim_dabit_batch(2, 0).await.unwrap_err(),
            PrssError::EmptyClaim { .. }
        ));

        // Exec 1, not 4: none of the three refusals above moved the cursor.
        let next = alloc.claim_dabit_batch(2, 40).await.unwrap();
        assert_eq!(next.parent_session().exec_id(), 1);
    }

    /// The `ctx[15]` half of the `beta`/`psi` separation, recorded on the window so a derivation
    /// cannot pick its own.
    #[tokio::test]
    async fn the_mod2_mask_window_carries_its_own_domain() {
        let alloc = PrssAllocator::new(1, family(0xAA));
        let w = alloc.claim_dabit_batch(3, 40).await.unwrap();
        assert_eq!(w.seed().domain(), PrssDomain::Default);
        assert_eq!(w.psi().domain(), PrssDomain::DaBitPsi);
        assert_eq!(w.seed().bits(), 1);
        assert_eq!(w.psi().bits(), 40);
        assert_eq!(w.psi().session_id().sub_id(), PSI_SUB_ID);
        assert_eq!(w.seed().session_id().sub_id(), 0);

        // And every other stream takes the default, by the exhaustive `domain` match.
        for stream in PrssStream::ALL {
            let expected = if stream == PrssStream::DaBitPsi {
                PrssDomain::DaBitPsi
            } else {
                PrssDomain::Default
            };
            assert_eq!(stream.domain(), expected, "{}", stream.name());
        }
    }

    #[tokio::test]
    async fn a_window_carries_the_key_family_it_was_counted_against() {
        let alloc = PrssAllocator::new(1, family(0x55));
        let w = alloc.claim(PrssStream::RandBitA, 1, 256).await.unwrap();
        assert_eq!(w.key_family_id(), family(0x55));
        assert_eq!(alloc.key_family_id(), family(0x55));
    }
}
