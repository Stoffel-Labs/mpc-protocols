use bincode::ErrorKind;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use stoffelnet::network_utils::NetworkError;
use thiserror::Error;
use tokio::sync::oneshot::{channel, Receiver, Sender};

use crate::{
    common::{
        gf2k::field::BinaryField,
        gf2k::share::{GfShare, GfShareWire},
        gf2k::Gf2kError,
        share::ShareError,
    },
    honeybadger::{gf_batch_recon::GfBatchReconError, mul::MultProtocolState, SessionId},
};

pub mod gf_multiplication;

/// Error that occurs during the execution of GF(2^k) secure multiplication.
#[derive(Debug, Error)]
pub enum GfMulError {
    #[error("there was an error in the network: {0:?}")]
    NetworkError(#[from] NetworkError),
    #[error("share error: {0:?}")]
    ShareError(#[from] ShareError),
    #[error("inner error: {0:?}")]
    Gf2kError(#[from] Gf2kError),
    #[error("batch reconstruction error: {0:?}")]
    GfBatchReconError(#[from] GfBatchReconError),
    #[error("error while serializing/deserializing bytes: {0:?}")]
    BincodeSerializationError(#[from] Box<ErrorKind>),
    #[error("Duplicate input: {0}")]
    Duplicate(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("no such session ID exists: {0:?}")]
    NoSuchSessionId(SessionId),
    #[error("result already received: {0:?}")]
    ResultAlreadyReceived(SessionId),
    #[error("multiplication {0:?} did not complete in time")]
    Timeout(SessionId),
    #[error("error sending the result: {0:?}")]
    SendError(SessionId),
    #[error("error receiving the result: {0:?}")]
    ReceiveError(SessionId),
    #[error("Channel closed")]
    Abort,
    #[error("Store Limit")]
    LimitError,
}

/// Bytes of envelope on one `GfBatchRecon` `EvalBatch`/`Reveal` message, measured.
///
/// `4` (bincode's `WrappedMessage` discriminant) `+ 16` (`SessionId`, a `u128`) `+ 8`
/// (`sender_id`) `+ 4` (`msg_type`) `+ 16` (two 8-byte length prefixes, because the payload is
/// bincoded twice: once as the inner list and once as the outer `Vec<u8>` that carries it).
/// Itemised and pinned by `conv_cost_model::framing_law_itemised`.
pub const GF_BATCH_RECON_FRAME_BYTES: usize = 48;

/// Bytes of envelope on one direct `GfMult` message, measured: the same inventory without
/// `msg_type` (there is only one kind of direct message) and with a third length prefix, because
/// [`GfMultReconstructionMessage`] carries two runs rather than one.
pub const GF_DIRECT_FRAME_BYTES: usize = 52;

/// Bytes one opened value costs inside a batched payload, measured: a bare `Gf256` element.
pub const BATCHED_BYTES_PER_VALUE: usize = 1;

/// Bytes one multiplication costs on the direct path, measured: its `a-x` element and its `b-y`
/// element, both bare — see [`GfShareWire`], which is what took this from `34` to `2`.
pub const DIRECT_BYTES_PER_MULT: usize = 2;

/// How one wave of `w` Beaver openings was split: what goes to batch reconstruction, what the
/// batch-reconstruction child is actually handed, and what goes directly all-to-all.
///
/// `batched + direct == w`, `padded % (t+1) == 0`, and `padded - batched < t+1` — the last group
/// is filled out with duplicates of the last batched share so that `init_batch_reconstruct_many`,
/// which requires a non-empty multiple of `t+1`, does not force the remainder onto the direct
/// path. `batched == 0` implies `padded == 0`: nothing is ever padded into existence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpeningPlan {
    /// Real values routed through batch reconstruction.
    pub batched: usize,
    /// Values handed to the batch-reconstruction child: [`OpeningPlan::batched`] rounded up to a
    /// whole number of `t+1` groups. The opened values past `batched` are discarded.
    pub padded: usize,
    /// Values sent directly, all-to-all, in one round.
    pub direct: usize,
}

impl OpeningPlan {
    /// Duplicate shares appended to the batched run to fill its last group.
    pub const fn pad(&self) -> usize {
        self.padded - self.batched
    }

    /// Batch-reconstruction groups this plan mints, per opening.
    pub const fn groups(&self, threshold: usize) -> usize {
        self.padded / (threshold + 1)
    }

    /// Sequential message rounds this wave costs: two when anything is batched (the `Reveal`
    /// round cannot start before the `Eval` round completes), one when the whole wave goes direct.
    ///
    /// The two paths run concurrently when a plan uses both, so a mixed plan is two rounds, not
    /// three.
    ///
    /// Keyed on `batched > 0 || padded > 0` and not on either alone. Under every policy shipped
    /// here the two are zero together, so `padded > 0` would read the same — but only by that
    /// coincidence, and a variant that batched without padding (or, absurdly, padded without
    /// batching) would be silently mis-costed by one whole round per AND layer while every
    /// functional test stayed green. Whether a batch-reconstruction session exists at all is the
    /// question; both fields answer it.
    pub const fn rounds(&self) -> usize {
        if self.batched > 0 || self.padded > 0 {
            2
        } else if self.direct > 0 {
            1
        } else {
            0
        }
    }
}

/// How one wave of Beaver openings reaches the wire: packed into batch reconstructions, or sent
/// directly all-to-all in one round.
///
/// # Phase: both, and the threat model does not change either way
///
/// Every opening this policy governs is **degree `t`**. A degree-`t` opening is robust and
/// asynchronous in both phases — [`GfShare::recover_secret`] runs OEC, which corrects `t` errors
/// because `required = degree + t + 1 + r = 2t + 1 + r <= n` is reachable for every `r <= t` at
/// `n >= 3t+1`. So this is a bytes-for-rounds trade and never a change of guarantee: the ONLINE
/// AND layers of [`a2b`](crate::honeybadger::a2b) stay robust with guaranteed output delivery
/// under either variant, and the PREPROCESSING AND layers of the edaBit `r < p` filter keep the
/// abort posture they already had.
///
/// **Never route a degree-`2t` opening this way.** At `degree = 2t` the same guard reads
/// `3t + 1 + r > n`, so OEC never executes and a direct open degrades to detect-and-abort. That
/// is why the policy lives on the multiplier — whose openings are degree-`t` by construction —
/// and not on [`GfBatchReconNode`](crate::honeybadger::gf_batch_recon::gf_batch_recon::GfBatchReconNode),
/// which this crate also instantiates at degree `2t` for DN07 degree reduction. On the direct
/// path the degree is not merely checked but **unrepresentable**: [`GfShareWire`] leaves it off
/// the wire and the receiver stamps its own `threshold`.
///
/// # The cost model, and where every constant in it was measured
///
/// Bytes put on the wire by one party for a wave of `w` multiplications, with a broadcast charged
/// to all `n` recipients — the convention every figure in this crate's cost work uses:
///
/// ```text
/// direct   (1 round) :  n * (52 + 2 * w)                   n  messages: one all-to-all wave
/// batched  (2 rounds): 4n * (48 + ceil(w / (t+1)))         4n messages: a-x and b-y, Eval+Reveal
/// ```
///
/// | constant | value | where it comes from |
/// |---|---|---|
/// | [`GF_DIRECT_FRAME_BYTES`] | 52 | serialised, itemised field by field |
/// | [`GF_BATCH_RECON_FRAME_BYTES`] | 48 | serialised, itemised field by field |
/// | [`DIRECT_BYTES_PER_MULT`] | 2 | one `a-x` + one `b-y` element |
/// | [`BATCHED_BYTES_PER_VALUE`] | 1 | one `Gf256` element per group per message |
///
/// Priced for a one-byte element, which is the `Gf256` this crate instantiates everywhere; a
/// wider `K` scales both payload terms by its element width and moves the crossover down. The
/// model is checked against real `GfMultiply` transcripts — bytes, message counts and rounds — in
/// `mpc/tests/conv_cost_model.rs`.
///
/// # What `Auto` optimises, and the assumption it makes
///
/// ```text
/// Direct  iff  direct_bytes(w)  <=  batched_bytes(w) + round_budget(n)
/// ```
///
/// With the default budget the `n` cancels out of both sides and the whole rule is one integer
/// inequality in the wave width:
///
/// ```text
/// Direct  iff  2w - 4 * ceil(w / (t+1))  <=  236
/// ```
///
/// which resolves to: direct at **every** width at `t = 1` (where it is cheaper outright, by a
/// flat `140n` bytes, `142n` at odd widths), and direct up to `w = 358 / 238 / 198` at
/// `t = 2 / 3 / 4`. Those are exact integers and the boundary is **jagged**, not an interval:
/// `2w - 4*ceil(w/g)` climbs by 2 inside a group and drops by 2 at each group boundary, so at
/// `t = 2` the decision reads direct at 356, batched at 357, direct again at 358, batched from
/// 359. `the_crossover_is_a_staircase_and_not_a_line` pins that, and it is why
/// [`OpeningPolicy::max_rounds_per_wave`] evaluates two candidates instead of one.
///
/// `round_budget` is the single free parameter: **how many bytes per party this deployment will
/// spend to remove one message round.** It is a bandwidth-delay product — a round costs one link
/// latency `L`, the extra bytes cost `bytes / B` at the spare per-party bandwidth `B`, and the
/// two break even at `L * B` — so it is a property of the deployment, not of the protocol, and
/// [`OpeningPolicy::Tuned`] exists to let a deployment state its own.
///
/// **The default is `2n * 48` bytes/party, the framing of exactly one batched round: a round is
/// worth paying for only while it costs less than the round it removes.** The assumption behind
/// that byte-first default is a measured property of this crate rather than a guess about
/// anyone's network — A2B's round count is independent of its batch size (`2 + layers *
/// rounds_per_wave`, whether it converts one value or
/// [`MAX_A2B_CONVERSIONS`](crate::honeybadger::a2b::MAX_A2B_CONVERSIONS) of them) while its bytes
/// are linear in it, so a deployment that pipelines conversions amortises rounds and pays bytes
/// in full. A deployment in the opposite regime — one conversion at a time on a high-latency
/// link — should say so with `Tuned { bytes_per_round: L * B }`; `u32::MAX` means "minimise
/// rounds", `0` means "minimise bytes and never trade".
///
/// # Why the rule this replaces was wrong
///
/// `Auto` used to take [`OpeningPolicy::Direct`] exactly at `t <= 1`, on the derived claim that
/// `O3/O1 = (t+1)/2 <= 1` makes a direct opening free there. End-to-end measurement contradicted
/// it: `n = 4` came in at **86.37 KiB/party** for one 64-bit A2B against `n = 13`'s **64.46** —
/// the most expensive configuration measured — because that model had no term for the 48-byte
/// frame (52–54% of A2B traffic at `n >= 7`) and priced a 17-byte `GfShare` as one element. It
/// was also the wrong *variable*: the crossover is a width, not a threshold. Both defects are
/// fixed — the frame is in the model above, and [`GfShareWire`] took the direct path from 34
/// bytes per multiplication to 2 — and the corrected model's answer at `t <= 1` is that `Direct`
/// is cheaper by a flat `140n` bytes per wave at *every* width. Same disposition as the old rule,
/// for the first time for a reason that survives measurement, and now re-derived at each
/// `(n, t, w)` rather than asserted. The old rule was also wrong in the other direction and
/// silently: it made every wave at `t >= 2` batch, including the `w <= 198` waves an AND layer of
/// a 64-bit conversion actually issues, where the direct path is both cheaper and a round
/// shorter.
///
/// Re-measured end to end after both fixes landed, one 64-bit A2B costs **15.34 / 26.49 / 37.48 /
/// 50.63 KiB/party** at `n = 4/7/10/13` against the 86.37 / 33.50 / 47.43 / 64.46 above, and
/// takes **9 message rounds at every `n`** rather than 9 / 16 / 16 / 16
/// (`conv_cost_measurement::measured_cost_n*` and `measured_rounds_a2b_n*`). The `n = 4` row is
/// the encoding; the `n >= 7` rows are this policy.
///
/// # The remainder: `Auto` never sends one directly
///
/// A wave of `w` values fills `floor(w/(t+1))` groups and leaves `w mod (t+1)` over, and
/// [`OpeningPolicy::Batched`] opens that remainder on the direct path — a whole extra all-to-all
/// wave of `n` messages, each paying its 52-byte frame however few values it carries. `Auto` pads
/// the last group instead: **one extra group costs `4n * 1` bytes against the `n * (52 + 2r)` a
/// direct remainder costs**, so padding wins for every `r >= 1` whenever a batch-reconstruction
/// session is open anyway — and it costs no extra round, because that session was already being
/// opened. The filler is a duplicate of the last batched share, which is information-free: it
/// opens to a value this same wave is already opening. `A2BNode::open_f` and `mul_pub` pad their
/// batch-reconstruction input by the same convention.
///
/// Measured, at `n = 13, t = 4` (`conv_cost_model::crossover_and_layer_n13`, bytes/party):
///
/// | wave | `Batched` | `Auto` | saved |
/// |---|---|---|---|
/// | `w = 256` (255 batched + 1 direct) | 5850 in 65 msgs | 5200 in 52 msgs | **11.1%** |
/// | `w = 384` (380 batched + 4 direct) | 7228 in 65 msgs | 6500 in 52 msgs | **10.1%** |
///
/// In both rows the 13 messages `Auto` removes are the entire direct wave; at `w = 256` that is
/// 11% of the layer's bytes spent on 0.4% of its multiplications. The figure was **31%** when
/// this was first measured, and the difference is not this policy: that measurement predates
/// [`GfShareWire`], when a direct remainder share cost 17 bytes instead of 1. The mechanism is
/// the same and the frame is the same; only the payload shrank.
///
/// # Why this is a policy and not a switch
///
/// The split must be a pure function of quantities every honest party already agrees on — here
/// `(n, t, wave length)` — because two parties that split one wave differently would mint
/// different numbers of child openings and stall each other. It is deliberately **not** a wire
/// field and is never derived from anything a peer sends: a policy a peer could steer is a
/// liveness lever for the adversary. [`OpeningPolicy::Tuned`]'s budget is part of that agreement
/// and must match across parties exactly as the variant does.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OpeningPolicy {
    /// Pack every full `t+1`-chunk into one batch reconstruction and send the sub-`t+1` remainder
    /// directly. Two rounds.
    ///
    /// The incumbent split, kept **exactly** as it was: it is the control the cost model is
    /// measured against, so it is deliberately not given [`OpeningPolicy::Auto`]'s padding. A
    /// deployment that wants the minimum-byte plan wants `Tuned { bytes_per_round: 0 }`, not
    /// this.
    Batched,
    /// Send every value directly, all-to-all, in one round. `n` messages, `n * (52 + 2w)` bytes
    /// per party, and no batch-reconstruction child at all.
    Direct,
    /// The measured cost model at the default exchange rate: `Tuned { bytes_per_round: 2n * 48 }`.
    #[default]
    Auto,
    /// [`OpeningPolicy::Auto`] with the bytes-for-rounds exchange rate set explicitly.
    ///
    /// `bytes_per_round` is bytes **per party** this deployment will spend to remove one message
    /// round; see the type's docs for the bandwidth-delay-product reading of it. Every party must
    /// pass the same number, exactly as every party must pass the same variant.
    Tuned {
        /// Bytes per party a removed round is worth. `0` minimises bytes; `u32::MAX` minimises
        /// rounds.
        bytes_per_round: u32,
    },
}

impl OpeningPolicy {
    /// The default bytes-for-rounds exchange rate: the framing of one batched round, `2n * 48`
    /// bytes per party. See the type's docs for the assumption this encodes.
    pub const fn default_round_budget(n_parties: usize) -> usize {
        2usize
            .saturating_mul(n_parties)
            .saturating_mul(GF_BATCH_RECON_FRAME_BYTES)
    }

    /// Bytes per party this policy will spend to remove one message round.
    pub const fn round_budget(&self, n_parties: usize) -> usize {
        match self {
            OpeningPolicy::Tuned { bytes_per_round } => *bytes_per_round as usize,
            _ => Self::default_round_budget(n_parties),
        }
    }

    /// Bytes one party puts on the wire opening `len` multiplications directly, broadcast charged
    /// to all `n`: `n * (52 + 2 * len)`, in one round.
    pub const fn direct_bytes(n_parties: usize, len: usize) -> usize {
        if len == 0 {
            return 0;
        }
        n_parties.saturating_mul(
            GF_DIRECT_FRAME_BYTES.saturating_add(DIRECT_BYTES_PER_MULT.saturating_mul(len)),
        )
    }

    /// Bytes one party puts on the wire opening `len` multiplications through batch
    /// reconstruction, padded to whole groups: `4n * (48 + ceil(len/(t+1)))`, in two rounds.
    ///
    /// `4n` and not `2n`: a multiplication opens `a-x` **and** `b-y`, two separate sessions, each
    /// costing `2n` messages (`Eval` out, `Reveal` back).
    pub const fn batched_bytes(n_parties: usize, threshold: usize, len: usize) -> usize {
        if len == 0 {
            return 0;
        }
        let group = threshold + 1;
        let groups = len.div_ceil(group);
        4usize.saturating_mul(n_parties).saturating_mul(
            GF_BATCH_RECON_FRAME_BYTES.saturating_add(BATCHED_BYTES_PER_VALUE * groups),
        )
    }

    /// How a wave of `len` openings is split. The one place that decision is made; `init` and
    /// `process` both call it and must agree exactly.
    pub const fn plan(&self, n_parties: usize, threshold: usize, len: usize) -> OpeningPlan {
        let group = threshold + 1;
        if len == 0 {
            return OpeningPlan {
                batched: 0,
                padded: 0,
                direct: 0,
            };
        }
        let all_direct = OpeningPlan {
            batched: 0,
            padded: 0,
            direct: len,
        };
        match self {
            OpeningPolicy::Direct => all_direct,
            OpeningPolicy::Batched => {
                let batched = len - len % group;
                OpeningPlan {
                    batched,
                    padded: batched,
                    direct: len - batched,
                }
            }
            OpeningPolicy::Auto | OpeningPolicy::Tuned { .. } => {
                let direct = Self::direct_bytes(n_parties, len);
                let batched = Self::batched_bytes(n_parties, threshold, len);
                if direct <= batched.saturating_add(self.round_budget(n_parties)) {
                    all_direct
                } else {
                    OpeningPlan {
                        batched: len,
                        padded: len.div_ceil(group) * group,
                        direct: 0,
                    }
                }
            }
        }
    }

    /// The most rounds one wave can cost under this policy, over every wave length up to
    /// `max_wave_len`. What [`A2BNode::message_rounds`](crate::honeybadger::a2b::a2b::A2BNode::message_rounds)
    /// multiplies by the AND-layer count.
    ///
    /// **Two candidates, not a scan, and not `max_wave_len` alone.** The decision turns on the
    /// sign of `f(w) = 2w - 4*ceil(w/g)`, `g = t+1`, which is a staircase: writing `w = qg + r`
    /// with `0 <= r < g` gives `f = q(2g-4) + 2r - 4*[r>0]`, so `f` climbs by `2g-4` per whole
    /// group and, within a group, is largest at `r = 0` (value `0`) or at `r = g-1` (value
    /// `2g-6`). It is therefore **not monotone** — `f(357) = 238` batches at `g = 3` while
    /// `f(358) = 236` goes direct — and evaluating at `max_wave_len` alone is wrong at exactly
    /// those discontinuities. The maximum over `1..=W` is attained at `W` itself or at the top of
    /// the last whole step, `floor(W/g)*g`; every other `w` has a strictly smaller `q`, or the
    /// same `q` and a smaller `2r - 4*[r>0]`. `policy_scan_agrees_with_the_two_candidate_maximum`
    /// checks that against a brute-force scan at every `(n, t)` this crate is stated at.
    pub const fn max_rounds_per_wave(
        &self,
        n_parties: usize,
        threshold: usize,
        max_wave_len: usize,
    ) -> usize {
        if max_wave_len == 0 {
            return 0;
        }
        let step_top = (max_wave_len / (threshold + 1)) * (threshold + 1);
        let at_end = self.plan(n_parties, threshold, max_wave_len).rounds();
        let at_step = if step_top > 0 {
            self.plan(n_parties, threshold, step_top).rounds()
        } else {
            0
        };
        if at_end > at_step {
            at_end
        } else {
            at_step
        }
    }
}

/// Storage for one GF(2^k) multiplication session. Mirrors `MultStorage<F>` field-for-field.
#[derive(Debug)]
pub struct GfMultStorage<K: BinaryField> {
    pub no_of_mul: Option<usize>,
    /// opened `a-x` values reconstructed using batch reconstruction
    pub output_open_mult1: HashMap<u8, Vec<K>>,
    /// opened `b-y` values reconstructed using batch reconstruction
    pub output_open_mult2: HashMap<u8, Vec<K>>,
    pub inputs: (Vec<GfShare<K>>, Vec<GfShare<K>>),
    pub protocol_state: MultProtocolState,
    pub share_mult_from_triple: Vec<GfShare<K>>,
    /// shares for reconstruction using direct point-to-point broadcast: the sub-`t+1` remainder
    /// under [`OpeningPolicy::Batched`], the whole wave under [`OpeningPolicy::Direct`]
    pub received_shares: HashMap<usize, (Vec<GfShare<K>>, Vec<GfShare<K>>)>,
    /// opened `a-x` and `b-y` values reconstructed from the direct-open shares above
    pub openings: Option<(Vec<K>, Vec<K>)>,
    pub output_sender: Option<Sender<Vec<GfShare<K>>>>,
    pub output_receiver: Option<Receiver<Vec<GfShare<K>>>>,
}

impl<K: BinaryField> GfMultStorage<K> {
    pub fn empty() -> Self {
        let (output_sender, output_receiver) = channel();

        Self {
            no_of_mul: None,
            output_open_mult1: HashMap::new(),
            output_open_mult2: HashMap::new(),
            inputs: (Vec::new(), Vec::new()),
            protocol_state: MultProtocolState::NotInitialized,
            share_mult_from_triple: Vec::new(),
            received_shares: HashMap::new(),
            openings: None,
            output_sender: Some(output_sender),
            output_receiver: Some(output_receiver),
        }
    }
}

/// Direct point-to-point opening of a GF(2^k) multiplication's `(a-x)`/`(b-y)` remainder shares
/// (used when the batch size isn't a multiple of `t+1`). Robust interpolation tolerates up to `t`
/// bad shares, so this doesn't need RBC's reliable-broadcast agreement — same trust model as
/// `GfBatchRecon`'s own point-to-point `Eval`/`Reveal` messages.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GfMultMessage {
    pub sender: usize,
    pub session_id: SessionId,
    pub payload: Vec<u8>,
}

impl GfMultMessage {
    pub fn new(sender: usize, session_id: SessionId, payload: Vec<u8>) -> Self {
        Self {
            sender,
            session_id,
            payload,
        }
    }
}

/// Payload of a [`GfMultMessage`] carrying the remainder `(a-x)`/`(b-y)` shares directly.
///
/// The two runs ride as [`GfShareWire`]: bare field elements, with the sender's evaluation index
/// and the opening degree **absent from the wire** rather than shipped and then checked. Both are
/// re-derived by the receiver — the index from the authenticated envelope `sender` that
/// `HoneyBadgerMPCNode` has already matched against the transport party id, the degree from the
/// node's own `threshold`. This is what makes the direct opening path cost `1` byte per share
/// instead of `17`; see [`GfShareWire`] for why the dropped fields were never trustworthy.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "K: BinaryField")]
pub struct GfMultReconstructionMessage<K: BinaryField> {
    pub a_sub_x: GfShareWire<K>,
    pub b_sub_y: GfShareWire<K>,
}

impl<K: BinaryField> GfMultReconstructionMessage<K> {
    /// Builds the message from the sender's own remainder shares.
    ///
    /// `id` is the sender's party id and `degree` the opening degree (the node's `threshold`);
    /// both are asserted against every share and then dropped.
    ///
    /// # Errors
    /// [`ShareError`] if either run is not homogeneous at `(id, degree)`.
    pub fn new(
        a_sub_x: &[GfShare<K>],
        b_sub_y: &[GfShare<K>],
        id: usize,
        degree: usize,
    ) -> Result<Self, ShareError> {
        Ok(Self {
            a_sub_x: GfShareWire::encode(a_sub_x, id, degree)?,
            b_sub_y: GfShareWire::encode(b_sub_y, id, degree)?,
        })
    }

    /// Rebuilds the two runs of shares, stamping the **receiver-derived** `(id, degree)`.
    ///
    /// `id` must be the authenticated sender's party id, `degree` the receiver's own threshold.
    pub fn into_shares(&self, id: usize, degree: usize) -> (Vec<GfShare<K>>, Vec<GfShare<K>>) {
        (
            self.a_sub_x.decode(id, degree),
            self.b_sub_y.decode(id, degree),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::gf2k::field::Gf256;
    use crate::common::ProtocolSessionId;
    use crate::honeybadger::gf_batch_recon::{GfBatchReconMsg, GfBatchReconMsgType};
    use crate::honeybadger::{ProtocolType, WrappedMessage};

    type K = Gf256;

    /// `(n, t)` at the enforced `n >= 3t+1`, for the four party counts the cost model is stated at.
    const PARTIES: [(usize, usize); 4] = [(4, 1), (7, 2), (10, 3), (13, 4)];

    /// The widest wave `A2BNode::mul_k` can issue, `max_mul_pairs_per_session(t)`. Restated rather
    /// than imported so that a change to the chunk cap shows up here as a disagreement instead of
    /// silently moving what these tests are asserting about.
    const fn chunk_cap(threshold: usize) -> usize {
        128 * (threshold + 1)
    }

    fn sid() -> SessionId {
        SessionId::new(ProtocolType::A2BGfMul, SessionId::pack_slot(1, 2, 3), 9)
    }

    /// Serialised length of one `GfBatchRecon` message carrying `values` elements.
    fn batched_msg_len(values: usize) -> usize {
        bincode::serialize(&WrappedMessage::GfBatchRecon(GfBatchReconMsg::new(
            0,
            sid(),
            GfBatchReconMsgType::EvalBatch,
            bincode::serialize(&vec![K::zero(); values]).unwrap(),
        )))
        .unwrap()
        .len()
    }

    /// Serialised length of one direct `GfMult` message carrying `mults` multiplications.
    fn direct_msg_len(mults: usize) -> usize {
        let run: Vec<GfShare<K>> = (0..mults).map(|_| GfShare::new(K::zero(), 0, 1)).collect();
        let body = bincode::serialize(&GfMultReconstructionMessage::new(&run, &run, 0, 1).unwrap())
            .unwrap();
        bincode::serialize(&WrappedMessage::GfMult(GfMultMessage::new(0, sid(), body)))
            .unwrap()
            .len()
    }

    #[test]
    fn the_cost_model_constants_are_the_measured_ones() {
        // THE test of this module. Every figure `Auto` decides on is one of these four constants,
        // and all four are properties of a serialisation that lives somewhere else: the frames
        // move if `WrappedMessage` gains a field or `SessionId` changes width, and the per-value
        // slopes move if the share encoding does. That has already happened once — the direct
        // path shipped a 17-byte `GfShare` per share, i.e. 34 bytes per multiplication, until
        // `GfShareWire` took it to the two bare elements this asserts — and the rule derived from
        // the old number was the exact opposite of the rule derived from this one. So the
        // constants are pinned against the real messages here: an encoding change goes red rather
        // than silently invalidating the policy.
        assert_eq!(
            batched_msg_len(0),
            GF_BATCH_RECON_FRAME_BYTES,
            "GfBatchRecon frame"
        );
        assert_eq!(direct_msg_len(0), GF_DIRECT_FRAME_BYTES, "GfMult frame");
        assert_eq!(
            batched_msg_len(64) - batched_msg_len(0),
            64 * BATCHED_BYTES_PER_VALUE,
            "batched bytes per value"
        );
        assert_eq!(
            direct_msg_len(64) - direct_msg_len(0),
            64 * DIRECT_BYTES_PER_MULT,
            "direct bytes per multiplication"
        );
        // Slopes are slopes, not averages: check a second pair of points.
        assert_eq!(batched_msg_len(7), GF_BATCH_RECON_FRAME_BYTES + 7);
        assert_eq!(direct_msg_len(7), GF_DIRECT_FRAME_BYTES + 7 * 2);
        // And the two whole-message formulas the policy's arithmetic is written in.
        for (n, t) in PARTIES {
            for w in [1usize, 5, 64, 100] {
                let groups = w.div_ceil(t + 1);
                assert_eq!(
                    OpeningPolicy::batched_bytes(n, t, w),
                    4 * n * batched_msg_len(groups),
                    "batched bytes n={n} t={t} w={w}"
                );
                assert_eq!(
                    OpeningPolicy::direct_bytes(n, w),
                    n * direct_msg_len(w),
                    "direct bytes n={n} w={w}"
                );
            }
        }
    }

    #[test]
    fn a_plan_is_always_a_whole_number_of_groups_plus_a_direct_tail() {
        for policy in [
            OpeningPolicy::Batched,
            OpeningPolicy::Direct,
            OpeningPolicy::Auto,
            OpeningPolicy::Tuned { bytes_per_round: 0 },
            OpeningPolicy::Tuned {
                bytes_per_round: u32::MAX,
            },
        ] {
            for (n, t) in PARTIES {
                for len in 0..200usize {
                    let plan = policy.plan(n, t, len);
                    assert_eq!(
                        plan.batched + plan.direct,
                        len,
                        "{policy:?} t={t} len={len}"
                    );
                    assert_eq!(plan.padded % (t + 1), 0, "{policy:?} t={t} len={len}");
                    assert!(plan.padded >= plan.batched, "{policy:?} t={t} len={len}");
                    assert!(plan.pad() < t + 1, "{policy:?} t={t} len={len}");
                    // Nothing is ever padded into existence: no batched values, no session.
                    assert_eq!(
                        plan.batched == 0,
                        plan.padded == 0,
                        "{policy:?} t={t} len={len}"
                    );
                    assert_eq!(plan.groups(t), plan.padded / (t + 1));
                }
            }
        }
    }

    #[test]
    fn batched_is_still_the_incumbent_split() {
        // `Batched` is the control the cost model was measured against, so it must stay exactly
        // what it always was: every full `t+1`-chunk packed, the remainder direct, no padding.
        for (n, t) in PARTIES {
            for len in 0..64usize {
                let plan = OpeningPolicy::Batched.plan(n, t, len);
                assert_eq!(plan.batched, len - len % (t + 1), "t={t} len={len}");
                assert_eq!(plan.padded, plan.batched, "Batched must not pad");
                assert_eq!(plan.direct, len % (t + 1), "t={t} len={len}");
            }
        }
    }

    #[test]
    fn direct_batches_nothing_at_any_width() {
        for (n, t) in PARTIES {
            for len in 0..64usize {
                let plan = OpeningPolicy::Direct.plan(n, t, len);
                assert_eq!(plan.batched, 0);
                assert_eq!(plan.padded, 0);
                assert_eq!(plan.direct, len);
            }
        }
    }

    #[test]
    fn auto_never_sends_a_remainder_directly() {
        // The remainder is the whole of the `n = 13` bleed: 31% of an AND layer's online bytes for
        // 0.8% of its multiplications, because a direct message costs its 52-byte frame however
        // few values it carries, `n` times over. When `Auto` batches, it pads — so its plans are
        // all-batched or all-direct and never the mixture `Batched` ships.
        for (n, t) in PARTIES {
            for len in 1..300usize {
                let plan = OpeningPolicy::Auto.plan(n, t, len);
                assert!(
                    plan.direct == 0 || plan.batched == 0,
                    "Auto split a wave at n={n} t={t} len={len}: {plan:?}"
                );
                if plan.batched > 0 {
                    // Padding is cheaper than the remainder it replaces for every `r`: `4n`
                    // against `n * (52 + 2r)`.
                    let incumbent = OpeningPolicy::Batched.plan(n, t, len);
                    let padded_cost = OpeningPolicy::batched_bytes(n, t, len);
                    let incumbent_cost = OpeningPolicy::batched_bytes(n, t, incumbent.batched)
                        + OpeningPolicy::direct_bytes(n, incumbent.direct);
                    assert!(
                        padded_cost <= incumbent_cost,
                        "padding lost to a direct remainder at n={n} t={t} len={len}"
                    );
                }
            }
        }
    }

    #[test]
    fn auto_takes_the_direct_path_exactly_where_the_measured_model_says_to() {
        // The rule, restated independently of the implementation: with the default budget the
        // comparison `n(52 + 2w) <= 4n(48 + ceil(w/(t+1))) + 2n*48` reduces — `n` cancels — to
        //
        //     2w - 4 * ceil(w / (t+1))  <=  236
        //
        // whose largest solutions are: *every* width at t=1, and 358 / 238 / 198 at t = 2/3/4.
        // These are exact integers, not the smooth approximation `140/(34 - ...)`-style reading
        // of the same inequality: the staircase makes the boundary jagged, and the next test
        // pins that.
        for (n, t) in PARTIES {
            for w in 1..800usize {
                let f = 2 * w as isize - 4 * (w.div_ceil(t + 1)) as isize;
                let want_direct = f <= 236;
                let plan = OpeningPolicy::Auto.plan(n, t, w);
                assert_eq!(
                    plan.direct == w,
                    want_direct,
                    "n={n} t={t} w={w} f={f} plan={plan:?}"
                );
            }
        }

        // t = 1: direct at every width, by a flat `140n` bytes (`142n` at odd widths).
        for w in 1..800usize {
            assert_eq!(OpeningPolicy::Auto.plan(4, 1, w).direct, w, "w={w}");
            let gap = OpeningPolicy::batched_bytes(4, 1, w) as isize
                - OpeningPolicy::direct_bytes(4, w) as isize;
            assert_eq!(gap, if w % 2 == 0 { 140 * 4 } else { 142 * 4 }, "w={w}");
        }

        // The last direct width at each of the other three thresholds.
        for (n, t, last) in [(7usize, 2usize, 358usize), (10, 3, 238), (13, 4, 198)] {
            assert_eq!(OpeningPolicy::Auto.plan(n, t, last).direct, last, "t={t}");
            for w in last + 1..last + 40 {
                assert_eq!(
                    OpeningPolicy::Auto.plan(n, t, w).direct,
                    0,
                    "t={t} w={w} should batch"
                );
            }
        }
    }

    #[test]
    fn the_crossover_is_a_staircase_and_not_a_line() {
        // `f(w) = 2w - 4*ceil(w/g)` falls by 2 at each group boundary and rises by 2 inside a
        // group, so the direct region is not an interval. At `t = 2` the decision reads
        // direct / BATCHED / direct / batched across w = 356..359 — an off-by-one at that
        // discontinuity is exactly what a smooth approximation of the crossover gets wrong, and
        // it is why `max_rounds_per_wave` evaluates two candidates rather than one.
        let auto = OpeningPolicy::Auto;
        assert_eq!(auto.plan(7, 2, 356).direct, 356, "356 is direct");
        assert_eq!(auto.plan(7, 2, 357).direct, 0, "357 batches");
        assert_eq!(auto.plan(7, 2, 358).direct, 358, "358 is direct again");
        assert_eq!(auto.plan(7, 2, 359).direct, 0, "359 batches");
        assert_eq!(auto.plan(7, 2, 360).direct, 0, "360 batches");
    }

    #[test]
    fn rounds_counts_a_batch_reconstruction_session_however_it_was_reached() {
        // Every policy here sets `batched` and `padded` to zero together, so keying `rounds` on
        // either alone reads the same today. This is the case that would not: a plan that batches
        // without padding is one round-trip pair, and a `rounds` keyed on `padded > 0` would call
        // it one round and under-count every AND layer by one.
        let batched_unpadded = OpeningPlan {
            batched: 4,
            padded: 0,
            direct: 0,
        };
        assert_eq!(batched_unpadded.rounds(), 2);
        let padded_only = OpeningPlan {
            batched: 0,
            padded: 4,
            direct: 0,
        };
        assert_eq!(padded_only.rounds(), 2);
        assert_eq!(
            OpeningPlan {
                batched: 0,
                padded: 0,
                direct: 3
            }
            .rounds(),
            1
        );
        assert_eq!(
            OpeningPlan {
                batched: 0,
                padded: 0,
                direct: 0
            }
            .rounds(),
            0
        );
        // A mixed plan is two rounds, not three: the direct wave and the `Eval` round overlap.
        assert_eq!(
            OpeningPlan {
                batched: 4,
                padded: 4,
                direct: 1
            }
            .rounds(),
            2
        );
    }

    #[test]
    fn policy_scan_agrees_with_the_two_candidate_maximum() {
        // `max_rounds_per_wave` evaluates the width itself and the top of the last whole group,
        // on the argument that the staircase's maximum lies at one of the two. The brute-force
        // scan it replaced is kept here as the check on that argument, over every policy, every
        // stated `(n, t)`, and every cap up to the widest wave `mul_k` can issue.
        for policy in [
            OpeningPolicy::Batched,
            OpeningPolicy::Direct,
            OpeningPolicy::Auto,
            OpeningPolicy::Tuned { bytes_per_round: 0 },
            OpeningPolicy::Tuned {
                bytes_per_round: 4096,
            },
            OpeningPolicy::Tuned {
                bytes_per_round: u32::MAX,
            },
        ] {
            for (n, t) in PARTIES {
                for cap in 1..=chunk_cap(t) {
                    let scanned = (1..=cap)
                        .map(|w| policy.plan(n, t, w).rounds())
                        .max()
                        .unwrap();
                    assert_eq!(
                        policy.max_rounds_per_wave(n, t, cap),
                        scanned,
                        "{policy:?} n={n} t={t} cap={cap}"
                    );
                }
            }
        }
    }

    #[test]
    fn the_widest_wave_a2b_can_issue_decides_its_round_count() {
        // What `A2BNode::message_rounds` reads. At `t = 1` no width up to the 256-wide cap ever
        // batches, so an AND layer is one round and a 7-layer conversion is 2 + 7 = 9; above
        // that the cap outruns the crossover (384 > 358, 512 > 238, 640 > 198) and the bound is
        // two rounds a layer, 2 + 14 = 16.
        assert_eq!(
            OpeningPolicy::Auto.max_rounds_per_wave(4, 1, chunk_cap(1)),
            1
        );
        for (n, t) in [(7usize, 2usize), (10, 3), (13, 4)] {
            assert_eq!(
                OpeningPolicy::Auto.max_rounds_per_wave(n, t, chunk_cap(t)),
                2,
                "n={n}"
            );
        }
        for (n, t) in PARTIES {
            assert_eq!(
                OpeningPolicy::Direct.max_rounds_per_wave(n, t, chunk_cap(t)),
                1
            );
            assert_eq!(
                OpeningPolicy::Batched.max_rounds_per_wave(n, t, chunk_cap(t)),
                2
            );
        }
    }

    #[test]
    fn the_budget_is_the_knob_and_its_extremes_are_the_two_fixed_policies() {
        for (n, t) in PARTIES {
            assert_eq!(
                OpeningPolicy::Auto.round_budget(n),
                OpeningPolicy::default_round_budget(n)
            );
            assert_eq!(OpeningPolicy::default_round_budget(n), 2 * n * 48);
            for w in 1..300usize {
                // "Spend anything to save a round" is `Direct` at every width.
                assert_eq!(
                    OpeningPolicy::Tuned {
                        bytes_per_round: u32::MAX
                    }
                    .plan(n, t, w)
                    .direct,
                    w,
                    "n={n} w={w}"
                );
                // "Never trade" is the minimum-byte plan, which is not `Batched` — it is
                // `Batched` with the remainder padded in rather than opened directly.
                let thrifty = OpeningPolicy::Tuned { bytes_per_round: 0 }.plan(n, t, w);
                let direct_cost = OpeningPolicy::direct_bytes(n, w);
                let batched_cost = OpeningPolicy::batched_bytes(n, t, w);
                let chosen = if thrifty.direct == w {
                    direct_cost
                } else {
                    batched_cost
                };
                assert_eq!(
                    chosen,
                    direct_cost.min(batched_cost),
                    "n={n} t={t} w={w} {thrifty:?}"
                );
            }
        }
    }

    #[test]
    fn a_short_wave_still_has_a_plan_under_every_policy() {
        // Fewer than `t+1` values cannot fill a group. `Batched` and `Direct` open them directly;
        // `Auto` is free to pad one group instead, and at these widths it never does, because
        // `4n * 49` is dearer than `n * (52 + 2w)` for every `w <= t <= 4`.
        for (n, t) in PARTIES {
            for len in 1..=t {
                assert_eq!(OpeningPolicy::Batched.plan(n, t, len).direct, len);
                assert_eq!(OpeningPolicy::Direct.plan(n, t, len).direct, len);
                assert_eq!(OpeningPolicy::Auto.plan(n, t, len).direct, len);
            }
        }
        for policy in [
            OpeningPolicy::Batched,
            OpeningPolicy::Direct,
            OpeningPolicy::Auto,
        ] {
            for (n, t) in PARTIES {
                let plan = policy.plan(n, t, 0);
                assert_eq!(plan.batched + plan.padded + plan.direct, 0);
                assert_eq!(plan.rounds(), 0);
            }
        }
    }

    #[test]
    fn auto_is_the_default() {
        assert_eq!(OpeningPolicy::default(), OpeningPolicy::Auto);
    }
}
