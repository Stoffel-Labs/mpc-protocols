//! Damgård–Nielsen degree-reduction multiplication (CRYPTO 2007), over `F` and over `Gf2k`.
//!
//! One multiplication, one degree-`2t` opening, **no Beaver triple**:
//!
//! ```text
//!   input    [x]_t, [y]_t  and a random double sharing  ([r]_t, [r]_2t)
//!   local    [d]_2t = [x]_t · [y]_t  −  [r]_2t            (share_mul, then subtract)
//!   open     d = Open_2t([d]_2t)                          (ONE batched opening, 2t+1 per group)
//!   local    [xy]_t = [r]_t + d
//! ```
//!
//! The same wire step, with the double sharing's own difference `[r]_2t − [r]_t` as the mask,
//! is an **exact-zero check**:
//!
//! ```text
//!   local    [z]_2t = [u]_t · [v]_t  +  ([r]_2t − [r]_t)   (a degree-2t sharing of ZERO)
//!   open     z = Open_2t([z]_2t)
//!   assert   z == 0  for every position, else ABORT
//! ```
//!
//! `u · v = 0` is how bit-ness is certified without a random linear combination and therefore
//! without a soundness error: `[U]·([U]−1)` over `F`, and `[W]·([W]+1)` over `Gf2k` (never `[W]²`,
//! which Frobenius makes a bijection — opening `W²` reveals `W` exactly).
//!
//! # PHASE: PREPROCESSING ONLY — synchronous, abort permitted. **Never online.**
//!
//! This is the whole security precondition of the module and it is not a stylistic preference.
//!
//! The online phase of this repo is **asynchronous and robust with guaranteed output delivery**
//! at `t < n/3`. A degree-`2t` evaluation code at `n = 3t+1` is `[3t+1, 2t+1]` Reed–Solomon with
//! minimum distance `d = n − 2t = t+1`, so its unique-decoding radius is `⌊t/2⌋ < t`.
//! Asynchronously a party may wait only for the `n − t = 2t+1` honest shares plus `e <= t` corrupt
//! ones, and unique decoding then needs `m >= (2t+1) + 2e`, i.e. `n >= 3t+1+e` for every `e <= t`,
//! i.e. **`n >= 4t+1`**. `robust_interpolate`'s own guard is the conservative form of exactly this
//! (`required = degree + t + 1 + r > n`, so OEC never executes at `degree = 2t`). Equivocation
//! closes the last door: batch reconstruction's second round re-broadcasts a codeword of the same
//! code, so one corrupt party can make one honest party decode and another fail — divergence
//! without agreement, recoverable only by a per-gate agreement sub-protocol that would destroy the
//! round count.
//!
//! In **preprocessing** none of that applies. Rounds are synchronous, a silent party is timed out,
//! and abort is licensed. There the same code's distance `t+1 > t` is a *feature*: any weight-`<=t`
//! deviation is a non-codeword, `recover_secret` returns `DecodingError`, and cheating is detected
//! **with probability 1** — no sacrifice, no cut-and-choose, no MAC, no Fiat–Shamir. And a
//! degree-`2t` batch-reconstruction group packs `2t+1` secrets against a degree-`t` group's `t+1`,
//! so the opening is also 1.75–1.80x *cheaper* per secret.
//!
//! ## How online misuse is prevented, structurally
//!
//! 1. **[`PreprocessingSessionId`] is the only thing `init_*` accepts.** A bare [`SessionId`] does
//!    not type-check. Its one constructor classifies the session's `ProtocolType` through
//!    [`phase_of`] and rejects anything that is not preprocessing.
//! 2. **[`phase_of`] is an exhaustive `match` with no wildcard arm.** Adding a variant to
//!    [`ProtocolType`] therefore fails to compile until its author classifies it. A new online
//!    protocol cannot reach DN07 by accident, and cannot be waved through by a `_ =>` arm that
//!    nobody re-read.
//! 3. **The node refuses to exist below the Byzantine bound.** `new` hard-errors for `t == 0` and
//!    for `n < 3t+1`, because below `3t+1` the detect-with-probability-1 guarantee that licenses
//!    the degree-`2t` opening in the first place is gone.
//! 4. **No online node owns one.** `Dn07MulNode` lives in `PreprocessNodes` / `GfPreprocessNodes`;
//!    `Operation`, `GfOperation` and `ConvNodes`' conversion nodes hold no handle to it.
//!
//! What none of that can stop is a caller minting a *preprocessing*-tagged session for work that
//! is really online. That residue is why this section exists in prose as well as in types.
//!
//! # Cost — and a correction to the blueprint's tables
//!
//! ## Units first: `O1`/`O2`/`M1`/`P1` are PAYLOAD figures, and payload is not the wire
//!
//! Every `O`/`M`/`P` figure in this section, everywhere else in this crate, and throughout
//! `scratchpad/a2b-b2a-protocol-performance.md` counts **field elements one party places in a
//! message body**, amortised, with a broadcast charged to all `n` recipients. It is *not* what
//! that party puts on the wire. Measured — by serialising the real message types, in
//! `mpc/tests/conv_cost_model.rs` — one party's actual byte cost is:
//!
//! ```text
//!   GF batch-recon session over m secrets : 2n * (48 + 1 * ceil(m/(t+1)))   2n msgs, 2 rounds
//!   F  batch-recon session over m secrets : 2n * (48 + 8 * ceil(m/(t+1)))   2n msgs, 2 rounds
//!   GF direct open of r multiplications   :  n * (52 + 2 * r)                n msgs, 1 round
//! ```
//!
//! The `48`- and `52`-byte frames are the term the element-counting model has no place for, and
//! they are not a rounding error: framing is **52–54% of a 64-bit A2B's whole traffic at
//! `n >= 7`**, 93–97% of the edaBit filter's DN07 phase, and it is the *entire* gap between the
//! derived and the measured B2A figures (measured / (derived + `2n * 48`) = 0.98x at all four
//! `n`). Two consequences for every per-secret figure quoted below:
//!
//! * a per-secret payload figure is a **marginal** cost. It is honest only with the fixed
//!   `2n * 48` per batch-reconstruction session quoted beside it, and only for a session wide
//!   enough that the fixed part amortises. At the narrow widths the edaBit filter actually runs,
//!   the fixed part *is* the cost.
//! * a **ratio** of two payload figures is not a ratio of wire costs, and is usually much larger.
//!   Where the two differ the wire ratio is given as well.
//!
//! Rounds are counted the same way and were undercounted for the same reason: a batch
//! reconstruction is a **two-round session** (Eval then Reveal), so any protocol whose bill
//! includes a mask opening costs one round more than an opening-count would suggest. A 64-bit A2B
//! is 9 rounds at the direct end and 16 at the batched one — not 8 and not 15 — and B2A is 2, not
//! 1.
//!
//! ## The payload table
//!
//! Payload field elements per party per secret, amortised, at `n = 3t+1`, with
//! `O1 = 2n/(t+1)` (degree-`t` batched opening, robust) and `O2 = 2n/(2t+1)` (degree-`2t` batched
//! opening, detect-and-abort). No framing term — add the model above for a wire cost:
//!
//! ```text
//!                                                    n=4      n=7     n=10     n=13
//!   O1  degree-t batched opening, per secret        4.000    4.667    5.000    5.200
//!   O2  degree-2t batched opening, per secret       2.667    2.800    2.857    2.889
//!
//!   Beaver preprocessing multiplication             12.00    14.00   12.857   13.089
//!     = triple (O2, via this node) + M1 (4n/(t+1))
//!   DN07 preprocessing multiplication (this node)   2.667    2.800    2.857    2.889
//!                              payload ratio         4.00x    4.33x    4.50x    4.60x
//!
//!   Beaver exact-zero check                        16.00    18.67   17.857   18.289
//!     = triple + M1 + one degree-t opening (O1)
//!   DN07 exact-zero check (this node)              2.667    2.800    2.857    2.889
//!                              payload ratio         6.00x    6.67x    6.25x    6.33x
//! ```
//!
//! The blueprint's own cost tables (`scratchpad/a2b-b2a-blueprint.md` §6.2/§6.3, and the numbers
//! `dabit/dabit_gen.rs` quoted from them in its sizing comments before that file was deleted)
//! **undercount**: they price a Beaver multiplication at the *triple alone* and omit the
//! `M1 = 4n/(t+1)` opening that spends it. The rows above are the corrected figures. At `n = 10`
//! the honest blueprint daBit baseline is 1803.3 F elements, not 1263.3, and one 64-bit A2B is
//! 945 KiB/party, not 687 KB. Both of those, and every ratio taken against them, are **payload**
//! (see the units note above); the blueprint's own construction was never built here and so its
//! wire cost cannot be measured. Framing would raise it by more than it raises this one — the
//! blueprint dealt, broadcast and bucketed, so it carried far more *messages* per secret — but by
//! how much is an estimate and is marked as one wherever it is quoted.
//!
//! Two further corrections to the same tables, recorded here because this is where the crate
//! keeps its cost arithmetic and the code that quoted the old figures is gone:
//!
//! * **The A2B circuit.** The blueprint's serial `ADD64 -> ADD64 -> MUX` chain is 626 ANDs at
//!   depth 13. `FieldA2BCircuit` now applies the mod-`p` offset to the *public* operand so the
//!   two additions run in parallel: 695 ANDs at depth 7, averaging 642 over a uniform mask.
//!   +11% on the sizing bound and +7% on the average, for −46% depth.
//! * **Online rounds per AND layer.** The blueprint prices every opening at the batched
//!   `O1 = 2n/(t+1)` and two rounds, in elements. Counted in *bytes*, framing included, a direct
//!   all-to-all degree-`t` opening of a `w`-wide layer costs `n * (52 + 2w)` in one round against
//!   the batched `4n * (48 + ceil(w/(t+1)))` in two, and which is cheaper is a question about `w`
//!   — not, as the blueprint had it, about `t`. See
//!   [`OpeningPolicy`](crate::honeybadger::gf_mul::OpeningPolicy), whose `Auto` decides it per
//!   wave. A 64-bit A2B is 16 message rounds where the blueprint said 28, and 9 wherever its
//!   layers sit below the crossover — 9 and not the plan's 8, because `OpeningPolicy` governs
//!   only the AND layers and A2B's mask opening stays a two-round `BatchReconNode` session.
//!
//! The GF side is the same arithmetic in bytes: a `Gf256` triple from `gf_triple_gen` fed by dealt
//! `GfRanDouSha` double sharings costs `2·P1_K + P3_K + O2 = 18.857` B of payload at `n = 10`;
//! fed by [`double_share::GfPrssDoubleShareSource`] it costs `O2 = 2.857` B, a **6.6x** cut,
//! because PRSS and PRZS put *nothing* on the wire.
//!
//! **Read that 6.6x with two qualifications, both measured.** It is stated against the *fully
//! dealt* baseline, and (a) this tree had already left that baseline — the double sharings were
//! on PRSS before the GF `[a]`/`[b]` were, so what the last change actually replaced was
//! `2·P1_K + O2` = `8.667 / 10.133 / 10.857 / 11.289` B at `n = 4/7/10/13`, an improvement of
//! **3.25x / 3.62x / 3.80x / 3.91x**, which is the figure to quote for this branch; and (b) the
//! fully dealt baseline **cannot be run** above `n = 4` (dealt `GfRanSha` does not complete —
//! `conv_cost_measurement::dealt_gf_random_share_generation_stalls_above_a_batch_size`), so 6.6x
//! is a payload ratio against a path that does not execute, not a measured saving.
//!
//! What *is* measured, end to end and to the byte: the PRSS triple's **marginal** cost is exactly
//! `O2` — `2.667 / 2.800 / 2.857 / 2.889` B/party at `n = 4/7/10/13`, payload and wire marginal
//! alike, since a batched GF element is one byte — on top of a **fixed `2 * n * 48` B/party per
//! batch** of frames, also exact at all four `n`. A 695-triple A2B pool therefore costs
//! `2n*48 + 2.857 * 695` and not `2.857 * 695`; at `n = 13` the frame is a third of it.
//!
//! # Who calls this
//!
//! Both nodes have production callers, and both are preprocessing:
//!
//! * **`Dn07MulNode`** — `F` Beaver triple generation, when PRSS keys are installed
//!   (`HoneyBadgerMPCNode::generate_triples_via_dn07`). `[a]`, `[b]` and the double sharing all
//!   come from [`double_share::PrssDoubleShareSource::triple_material`], so a triple's entire
//!   wire cost is the one degree-`2t` opening. Without PRSS keys the node falls back to
//!   `TripleGenNode` over dealt `RanSha` + `RanDouSha`, which computes the identical algebra
//!   inline.
//! * **`GfDn07MulNode`** — every AND layer of the edaBit modulus-overflow filter
//!   (`dabit::edabit::EdaBitFilterNode`), under the `DaBitGfMul` tag, in place of a `GfMultiply`
//!   spending one `Gf2k` Beaver triple per AND.
//!
//! **[`Dn07MulNode::init_zero_check`](dn07::Dn07MulNode::init_zero_check) and its `Gf` twin have
//! no production caller.** They are not dead by oversight: the bit-ness obligations they were
//! written for belonged to the dealt daBit protocol, and PRSS daBits discharge those by
//! provenance — there is no dealt value left in the stack to certify. They stay because the
//! moment any dealt share re-enters preprocessing, this is the check it needs, and the cost
//! (`6.25x` cheaper than the Beaver form at `n = 10`) is the reason to reach for it rather than
//! rebuild one — `6.25x` being a payload ratio, where the wire ratio is the message count: one
//! `2n`-message degree-`2t` session against a Beaver check's `4n` plus a share of triple
//! generation.
//!
//! # Where the double sharing comes from
//!
//! Anywhere, as long as it is a genuine `([r]_t, [r]_2t)` on one uniform `r`. Two sources exist:
//!
//! * **`ran_dou_sha` / `gf_ran_dou_sha`** — dealt, interactive, perfect privacy, and it is what
//!   `triple_gen` already consumes.
//! * **[`double_share::PrssDoubleShareSource`] / [`double_share::GfPrssDoubleShareSource`]** —
//!   PRSS for `[r]_t` plus PRZS for the degree-`2t` lift, **zero rounds and zero bytes**, at the
//!   price of computational rather than perfect privacy of preprocessing randomness.
//!
//! # One object, two consumptions — why the zero-check mask is not a second draw
//!
//! A zero check needs a uniform mask from `{h : deg h <= 2t, h(0) = 0}`. That is exactly what
//! `[r]_2t − [r]_t` is: the two halves of a double sharing share a constant term, so the
//! difference kills it, and the difference of a uniform degree-`2t` polynomial through `r` and a
//! uniform degree-`t` polynomial through `r` is uniform over that space.
//!
//! So the zero check consumes **a double sharing**, not a separately-drawn zero sharing. That is a
//! deliberate API choice, not a saving: two separate PRZS draws is one more place for two PRF
//! streams to be derived at the same `(session, position)` and silently coincide — the same hazard
//! class as the daBit's `β`/`ψ` collision, which reveals the bit with probability ~3/4. With one
//! object there is no second position to get wrong, and "do not spend a preprocessing item twice"
//! is a rule this repo already has everywhere.
//!
//! # Share-type discipline
//!
//! `ShamirShare::degree` and `GfShare::degree` are **caller-written `usize` metadata** and prove
//! nothing about the polynomial the share lies on. Following `batch_recon.rs:250`, this module
//! *discards* the supplied degree on every double sharing it is handed and substitutes the
//! locally known protocol constants `t` and `2t`. The share *value* is used; the label is not
//! trusted. See [`Dn07Error::ShareIdMismatch`] for the one piece of the label that is checked
//! rather than overwritten, because there is no local constant to substitute for it.
//!
//! # What this module deliberately does not have
//!
//! No timeouts of its own on the wire path, no broadcast, no RBC, and no degree-`t` opening: it
//! owns exactly one `BatchReconNode` pinned at `degree = 2t`, constructed in `new` and never
//! reconfigured. If a future edit makes that degree a parameter, this module's entire security
//! argument has to be rewritten.

use ark_serialize::SerializationError;
use thiserror::Error;
use tokio::sync::oneshot::{channel, Receiver, Sender};

use crate::common::share::ShareError;
use crate::common::ProtocolSessionId;
use crate::honeybadger::batch_recon::BatchReconError;
use crate::honeybadger::gf_batch_recon::GfBatchReconError;
use crate::honeybadger::{ProtocolType, SessionId};

/// Largest number of concurrent DN07 sessions one node admits, across all peers.
pub const MAX_DN07_SESSIONS: usize = 256;

/// Largest number of `2t+1`-wide batch-reconstruction groups a single `init_*` may open.
///
/// Every group contributes one field element to the same eval/reveal message pair, so this bounds
/// the payload of one session. Callers split larger requests against
/// [`dn07::Dn07MulNode::max_batch_size`] rather than reimplementing the `2t+1` arithmetic.
pub const MAX_DN07_GROUPS: usize = 256;

/// Which phase of the protocol a [`ProtocolType`] tag belongs to.
///
/// The distinction is not cosmetic: the online phase is asynchronous and robust with guaranteed
/// output delivery and permits only degree-`t` openings, while preprocessing is synchronous and
/// may abort and therefore also permits degree-`2t` ones. See the [module docs](self).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolPhase {
    /// Synchronous, abort permitted, degree-`2t` openings legal.
    Preprocessing,
    /// Asynchronous, robust, guaranteed output delivery, degree-`t` openings only.
    Online,
    /// A transport tag (`Rbc`, `BatchRecon`, `GfBatchRecon`) or the `None` placeholder. These
    /// never name a *calling* protocol, so a session carrying one is malformed as a DN07 caller
    /// rather than merely mis-phased.
    Transport,
}

/// Classifies a protocol tag into its phase.
///
/// # This match is deliberately exhaustive
///
/// There is no `_ =>` arm and there must never be one. Adding a variant to [`ProtocolType`] breaks
/// this function's compilation until its author decides which phase the new protocol runs in, and
/// that decision is the one the plan names as the single most likely way to break the threat
/// model. A wildcard arm would turn a forced decision into a silent default, which is precisely
/// how a degree-`2t` opening ends up on the asynchronous robust path.
pub const fn phase_of(tag: ProtocolType) -> ProtocolPhase {
    match tag {
        // ---- transport / placeholder ----------------------------------------------------
        ProtocolType::None => ProtocolPhase::Transport,
        ProtocolType::Rbc => ProtocolPhase::Transport,
        ProtocolType::BatchRecon => ProtocolPhase::Transport,
        ProtocolType::GfBatchRecon => ProtocolPhase::Transport,

        // ---- preprocessing: synchronous, abort permitted --------------------------------
        ProtocolType::Randousha => ProtocolPhase::Preprocessing,
        ProtocolType::Ransha => ProtocolPhase::Preprocessing,
        ProtocolType::Triple => ProtocolPhase::Preprocessing,
        ProtocolType::Dousha => ProtocolPhase::Preprocessing,
        ProtocolType::PRandInt => ProtocolPhase::Preprocessing,
        ProtocolType::GfRansha => ProtocolPhase::Preprocessing,
        ProtocolType::RandBit => ProtocolPhase::Preprocessing,
        ProtocolType::ZeroSha => ProtocolPhase::Preprocessing,
        ProtocolType::GfDousha => ProtocolPhase::Preprocessing,
        ProtocolType::GfRandousha => ProtocolPhase::Preprocessing,
        ProtocolType::GfTriple => ProtocolPhase::Preprocessing,
        ProtocolType::DaBit => ProtocolPhase::Preprocessing,
        ProtocolType::DaBitMul => ProtocolPhase::Preprocessing,
        ProtocolType::DaBitOpen => ProtocolPhase::Preprocessing,
        ProtocolType::DaBitGfMul => ProtocolPhase::Preprocessing,
        ProtocolType::DaBitGfOpen => ProtocolPhase::Preprocessing,
        ProtocolType::Dn07 => ProtocolPhase::Preprocessing,
        ProtocolType::GfDn07 => ProtocolPhase::Preprocessing,

        // ---- online: asynchronous, robust, degree-t only --------------------------------
        //
        // Every tag below names work that runs after preprocessing, on a network with no
        // timeouts, against an adversary that must not be able to stall or diverge it. None of
        // them may reach a degree-2t opening, which is the whole reason this classification is a
        // compile-time obligation rather than a comment.
        ProtocolType::Input => ProtocolPhase::Online,
        ProtocolType::Mul => ProtocolPhase::Online,
        ProtocolType::FpMul => ProtocolPhase::Online,
        ProtocolType::Trunc => ProtocolPhase::Online,
        ProtocolType::FpDivConst => ProtocolPhase::Online,
        ProtocolType::GfMul => ProtocolPhase::Online,
        ProtocolType::A2B => ProtocolPhase::Online,
        ProtocolType::A2BGfMul => ProtocolPhase::Online,
        ProtocolType::B2A => ProtocolPhase::Online,
    }
}

/// A [`SessionId`] that has been checked to belong to the preprocessing phase.
///
/// The only way to obtain one is [`PreprocessingSessionId::new`], which classifies the session's
/// calling protocol through [`phase_of`]. `Dn07MulNode::init_mul`, `init_zero_check` and their
/// `Gf` twins accept nothing else, so "this degree-`2t` opening is on a preprocessing session" is
/// a property of the type rather than a review obligation.
///
/// It is a cheap `Copy` wrapper; [`PreprocessingSessionId::get`] unwraps it for the batch-recon
/// child, which is phase-agnostic because it is told its degree at construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PreprocessingSessionId(SessionId);

impl PreprocessingSessionId {
    /// Checks that `session_id` names a preprocessing protocol, and that it is shaped the way
    /// every batch-reconstruction caller in this repo shapes a root session.
    ///
    /// # Errors
    /// - [`Dn07Error::OnlinePhaseForbidden`] if the calling protocol is an online one. This is the
    ///   error that exists to stop the plan's headline mistake.
    /// - [`Dn07Error::MissingCallingProtocol`] if the session carries no calling protocol, or a
    ///   transport tag that never names one.
    /// - [`Dn07Error::MalformedSessionId`] if `sub_id` or `round_id` is non-zero. A DN07 session is
    ///   a root session whose only child is its batch reconstruction; the sub/round bytes are the
    ///   child-minting space and must be free, exactly as `mul_pub::init` requires.
    pub fn new(session_id: SessionId) -> Result<Self, Dn07Error> {
        let Some(tag) = session_id.calling_protocol() else {
            return Err(Dn07Error::MissingCallingProtocol(session_id));
        };
        match phase_of(tag) {
            ProtocolPhase::Preprocessing => {}
            ProtocolPhase::Online => {
                return Err(Dn07Error::OnlinePhaseForbidden {
                    session_id,
                    tag: tag as u8,
                })
            }
            ProtocolPhase::Transport => return Err(Dn07Error::MissingCallingProtocol(session_id)),
        }
        if session_id.sub_id() != 0 || session_id.round_id() != 0 {
            return Err(Dn07Error::MalformedSessionId(session_id));
        }
        Ok(Self(session_id))
    }

    /// The wrapped session id, for handing to the batch-reconstruction child and the store.
    pub fn get(self) -> SessionId {
        self.0
    }
}

#[derive(Debug, Error)]
pub enum Dn07Error {
    #[error("ark serialization: {0:?}")]
    ArkSerialization(#[from] SerializationError),
    #[error("batch recon: {0:?}")]
    BatchRecon(#[from] BatchReconError),
    #[error("gf batch recon: {0:?}")]
    GfBatchRecon(#[from] GfBatchReconError),
    #[error("error operating with the shares: {0:?}")]
    Share(#[from] ShareError),
    /// The single error this module exists to be able to return. See the module docs.
    #[error(
        "session {session_id:?} names online protocol tag {tag}: DN07 opens at degree 2t, which \
         is unreconstructible on the asynchronous robust path at n = 3t+1 (it needs n >= 4t+1). \
         Preprocessing sessions only."
    )]
    OnlinePhaseForbidden { session_id: SessionId, tag: u8 },
    #[error("session {0:?} carries no calling protocol, or carries a transport tag")]
    MissingCallingProtocol(SessionId),
    #[error("session {0:?} must be a root session: sub_id and round_id must both be zero")]
    MalformedSessionId(SessionId),
    #[error(
        "threshold t must be at least 1: at t = 0 a degree-2t sharing is a constant and the \
         opening masks nothing"
    )]
    DegenerateThreshold,
    #[error(
        "n = {n} is below the Byzantine bound 3t+1 = {bound}; below it a degree-2t opening is \
         neither reconstructible nor detect-with-probability-1, so DN07 has no security argument"
    )]
    PartyCountTooSmall { n: usize, bound: usize },
    #[error("{what}: expected {expected} items, got {got}")]
    LengthMismatch {
        what: &'static str,
        expected: usize,
        got: usize,
    },
    #[error("empty input")]
    EmptyInput,
    /// A [`PrssWindow`](crate::honeybadger::prss::PrssWindow) claimed on one keystream was
    /// offered to a consumer that derives from another. Unreachable through the node's own
    /// wiring; it exists so that the window type's guarantee survives a future caller that
    /// wires the two RandBit windows the wrong way round, where the symptom would otherwise be
    /// a silent width/stride collision rather than an error.
    #[error("PRSS window is on stream {got}, but this derivation reads stream {expected}")]
    WrongPrssStream {
        expected: &'static str,
        got: &'static str,
    },
    /// A window issued by an allocator bound to different key material. See
    /// [`PrssKeys::key_family_id`](crate::honeybadger::prss::prss::PrssKeys::key_family_id): the
    /// monotone position count is only meaningful against the key family it was counted for, so
    /// spending a window on another family would restart every position at zero under keys that
    /// have already used them.
    #[error(
        "PRSS window was claimed against a different key family than this source holds: its \
         position count says nothing about what these keys have already derived"
    )]
    KeyFamilyMismatch,
    #[error("batch of {requested} exceeds the per-session maximum of {max}")]
    BatchTooLarge { requested: usize, max: usize },
    #[error(
        "share at index {index} carries id {got}, but this node is party {expected}: a share's \
         id is its evaluation point and there is no local constant to substitute for it"
    )]
    ShareIdMismatch {
        index: usize,
        expected: usize,
        got: usize,
    },
    /// Preprocessing may abort on detected cheating; this is that abort.
    #[error(
        "exact-zero check failed at index {index}: the degree-2t opening returned a non-zero \
         value, so an input was not in the asserted set. Soundness error of this check is 0, so \
         this is a proof of misbehaviour, not a false positive."
    )]
    ZeroCheckFailed { index: usize },
    #[error("session {0:?} was a {1} session; asked for the other outcome")]
    WrongTask(SessionId, &'static str),
    #[error("send error: {0:?}")]
    SendError(SessionId),
    #[error("receive error: {0:?}")]
    ReceiveError(SessionId),
    #[error("timeout: {0:?}")]
    Timeout(SessionId),
    #[error("no such session: {0:?}")]
    NoSuchSession(SessionId),
    #[error("result already received: {0:?}")]
    ResultAlreadyReceived(SessionId),
    #[error("session limit reached")]
    LimitError,
    #[error("channel closed")]
    Abort,
    #[error("payload deserialization: {0}")]
    Deserialization(String),
    #[error("prss: {0}")]
    Prss(String),
    #[error("przs: {0}")]
    Przs(String),
    #[error(
        "key stores disagree: {what} says {left}, but the other says {right}. A double sharing \
         assembled from mismatched stores is a sharing of two different secrets."
    )]
    KeyStoreMismatch {
        what: &'static str,
        left: usize,
        right: usize,
    },
}

/// Lifecycle of one DN07 session. Deliberately two-valued: there is exactly one network round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dn07State {
    Running,
    Finished,
}

/// What the opened degree-`2t` values are for.
///
/// Fixed at `init` and never derived from message data: a session that could be reinterpreted
/// from the wire as the other task would let a peer turn an abort-on-nonzero check into a silent
/// multiplication.
#[derive(Debug, Clone)]
pub enum Dn07Task<S> {
    /// DN07 degree reduction: the opened `d` is added to these degree-`t` shares of `r`.
    Reduce { r_t: Vec<S> },
    /// Exact-zero check: every opened value must be zero.
    ZeroCheck,
}

impl<S> Dn07Task<S> {
    /// Name used in [`Dn07Error::WrongTask`].
    pub fn name(&self) -> &'static str {
        match self {
            Dn07Task::Reduce { .. } => "multiplication",
            Dn07Task::ZeroCheck => "zero-check",
        }
    }
}

/// Result of one DN07 session.
#[derive(Debug, Clone)]
pub enum Dn07Outcome<S> {
    /// Degree-`t` shares of the products, in input order.
    Products(Vec<S>),
    /// Indices whose opened value was not zero. Empty means the check passed.
    ///
    /// Returned rather than thrown so that a caller batching many checks learns *which* positions
    /// failed in one pass; [`dn07::Dn07MulNode::wait_for_zero_check`] converts a non-empty vector
    /// into [`Dn07Error::ZeroCheckFailed`] for callers that only want pass/fail.
    ZeroCheckViolations(Vec<usize>),
}

/// Per-session state, generic over the share type so `F` and `Gf2k` share one definition.
#[derive(Debug)]
pub struct Dn07Store<S> {
    /// Number of real (unpadded) values this session opens. `0` is the "init has not run here
    /// yet" sentinel, never a legal batch size.
    pub k: usize,
    pub state: Dn07State,
    /// `None` until `init_*` runs locally.
    pub task: Option<Dn07Task<S>>,
    pub output_sender: Option<Sender<Dn07Outcome<S>>>,
    pub output_receiver: Option<Receiver<Dn07Outcome<S>>>,
    /// A batch reconstruction can finish before this party reaches `init_*` — a faster quorum
    /// needs only `2t+1` of the `3t+1` parties. The raw bytes are parked rather than decoded,
    /// because decoding needs `k`, which `init_*` has not yet supplied.
    pub pending_batch_recon_payload: Option<Vec<u8>>,
}

impl<S> Dn07Store<S> {
    pub fn new(k: usize) -> Self {
        let (tx, rx) = channel();
        Self {
            k,
            state: Dn07State::Running,
            task: None,
            output_sender: Some(tx),
            output_receiver: Some(rx),
            pending_batch_recon_payload: None,
        }
    }
}

impl<S> Default for Dn07Store<S> {
    fn default() -> Self {
        Self::new(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::ProtocolSessionId;

    fn sid(tag: ProtocolType, sub: u8, round: u8) -> SessionId {
        SessionId::new(tag, SessionId::pack_slot(7, sub, round), 42)
    }

    #[test]
    fn preprocessing_tags_are_admitted() {
        for tag in [
            ProtocolType::Triple,
            ProtocolType::GfTriple,
            ProtocolType::RandBit,
            ProtocolType::DaBitMul,
            ProtocolType::Dn07,
            ProtocolType::GfDn07,
        ] {
            assert!(
                PreprocessingSessionId::new(sid(tag, 0, 0)).is_ok(),
                "{tag:?} should be a preprocessing tag"
            );
        }
    }

    #[test]
    fn online_tags_are_refused() {
        // This is the test that would fail if someone ever routed an online protocol through
        // DN07. Every tag here is on the asynchronous robust path, where a degree-2t opening
        // cannot be reconstructed at n = 3t+1.
        for tag in [
            ProtocolType::Mul,
            ProtocolType::GfMul,
            ProtocolType::A2B,
            ProtocolType::A2BGfMul,
            ProtocolType::B2A,
            ProtocolType::Input,
            ProtocolType::FpMul,
            ProtocolType::Trunc,
            ProtocolType::FpDivConst,
        ] {
            let err = PreprocessingSessionId::new(sid(tag, 0, 0)).unwrap_err();
            assert!(
                matches!(err, Dn07Error::OnlinePhaseForbidden { .. }),
                "{tag:?} must be refused as online, got {err:?}"
            );
        }
    }

    #[test]
    fn transport_tags_are_refused() {
        for tag in [
            ProtocolType::None,
            ProtocolType::Rbc,
            ProtocolType::BatchRecon,
            ProtocolType::GfBatchRecon,
        ] {
            let err = PreprocessingSessionId::new(sid(tag, 0, 0)).unwrap_err();
            assert!(
                matches!(err, Dn07Error::MissingCallingProtocol(_)),
                "{tag:?} must be refused as a transport tag, got {err:?}"
            );
        }
    }

    #[test]
    fn child_session_space_must_be_free() {
        assert!(matches!(
            PreprocessingSessionId::new(sid(ProtocolType::Dn07, 1, 0)).unwrap_err(),
            Dn07Error::MalformedSessionId(_)
        ));
        assert!(matches!(
            PreprocessingSessionId::new(sid(ProtocolType::Dn07, 0, 1)).unwrap_err(),
            Dn07Error::MalformedSessionId(_)
        ));
    }

    #[test]
    fn every_tag_round_trips_through_a_phase() {
        // `phase_of` is exhaustive by construction, so this walks the numeric space instead: any
        // tag `from_u8` admits must classify, and the classification must be stable.
        use crate::common::ProtocolTag;
        let mut seen = 0usize;
        for v in 0u8..=255 {
            if let Some(tag) = ProtocolType::from_u8(v) {
                seen += 1;
                let phase = phase_of(tag);
                assert_eq!(phase, phase_of(tag));
                // A tag that classifies as preprocessing must produce a usable session.
                if phase == ProtocolPhase::Preprocessing {
                    assert!(PreprocessingSessionId::new(sid(tag, 0, 0)).is_ok());
                }
            }
        }
        assert!(
            seen >= 29,
            "expected at least the 29 tags that predate DN07, saw {seen}"
        );
    }

    #[test]
    fn store_starts_empty_and_unassigned() {
        let store = Dn07Store::<
            crate::honeybadger::robust_interpolate::robust_interpolate::RobustShare<
                ark_bls12_381::Fr,
            >,
        >::new(0);
        assert_eq!(store.k, 0);
        assert_eq!(store.state, Dn07State::Running);
        assert!(store.task.is_none());
        assert!(store.pending_batch_recon_payload.is_none());
    }
}

pub mod dn07;
pub mod gf_dn07;
