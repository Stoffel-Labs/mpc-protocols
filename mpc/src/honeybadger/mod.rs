/// This module contains the implementation of the Robust interpolate protocol presented in
/// Figure 1 in the paper "HoneyBadgerMPC and AsynchroMix: Practical AsynchronousMPC and its
/// Application to Anonymous Communication".
pub mod robust_interpolate;

/// This module contains the implementation of the Batch Reconstruction protocol presented in
/// Figure 2 in the paper "HoneyBadgerMPC and AsynchroMix: Practical AsynchronousMPC and its
/// Application to Anonymous Communication".
pub mod batch_recon;

/// This module contains the implementation of the Batch Reconstruction protocol presented in
/// Figure 3 in the paper "HoneyBadgerMPC and AsynchroMix: Practical AsynchronousMPC and its
/// Application to Anonymous Communication".
pub mod ran_dou_sha;

/// Implementation for the protocol of double share generation.
pub mod double_share;

/// Implements a Beaver triple generation protocol for the HoneyBadgerMPC protocol.
pub mod triple_gen;

// Layered Boolean netlists over `GfShare<K>` — the online circuit layer of A2B.
pub mod binary_circuits;

// Doubly-shared bits (daBits): the cross-domain primitive behind A2B and B2A.
pub mod dabit;

// Arithmetic-to-binary conversion: `[x]_F` to the bit shares of its canonical representative.
pub mod a2b;

// Binary-to-arithmetic conversion: one GF(2^k) opening, no online multiplication.
pub mod b2a;

// daBit / edaBit pools, the conversion-side counterpart of `preprocessing` and `gf_preprocessing`.
pub mod conv_preprocessing;

/// Damgard-Nielsen degree-reduction multiplication and exact-zero check, over `F` and over
/// GF(2^k). **Preprocessing-only**: it opens at degree `2t`, which needs `n >= 4t+1` to be
/// reconstructible on the asynchronous robust online path and is therefore legal here only where
/// rounds are synchronous and abort is permitted.
pub mod dn07;

pub mod fpdiv;
pub mod fpmul;

/// GF(2^k) equivalent of `batch_recon`
pub mod gf_batch_recon;
/// GF(2^k) equivalent of `double_share` (non-robust paired-degree dealing)
pub mod gf_double_share;
/// GF(2^k) equivalent of `mul` (secure Beaver multiplication)
pub mod gf_mul;
/// GF(2^k) equivalent of `preprocessing`
pub mod gf_preprocessing;
/// GF(2^k) equivalent of `prss` (CDI05 pseudorandom secret sharing; preprocessing-only, local)
pub mod gf_prss;
/// GF(2^k) equivalent of `ran_dou_sha` (hyperinvertible-matrix extraction + checksum)
pub mod gf_ran_dou_sha;
/// GF(2^k) equivalent of `share_gen` (RanSha)
pub mod gf_share_gen;
/// GF(2^k) equivalent of `triple_gen` (Beaver triple generation)
pub mod gf_triple_gen;
pub mod input;
/// Catrina-Saxena `Mod2m` at `m = 1`: parity extraction by one degree-`t` opening and zero
/// multiplications. Degree-`t` throughout, so unlike `dn07` it carries no phase restriction of
/// its own; its consumer (PRSS daBit generation) is preprocessing.
pub mod mod2;
pub mod mul;
pub mod mul_pub;
pub mod output;
pub mod preprocessing;
pub mod prss;
/// Pseudorandom zero sharing (CDI05 §4) at degree `2t`, over `F` and over GF(2^k).
/// Preprocessing-only: a degree-`2t` sharing can only be spent by a degree-`2t` opening.
pub mod przs;
pub mod share_gen;
#[cfg(feature = "statistics")]
pub mod statistics;
pub mod zero_share;

use crate::{
    common::{
        convert::ConvertError,
        gf2k::{field::Gf256, share::GfShare},
        rbc::{rbc_store::Msg, RbcError},
        share::ShareError,
        types::{
            fixed::{ClearFixedPoint, FixedPointPrecision, SecretFixedPoint},
            integer::{ClearInt, SecretInt},
            TypeError,
        },
        ConversionPreprocessingProtocol, GfMPCProtocol, GfPreprocessingMPCProtocol, MPCProtocol,
        MPCTypeOps, PreprocessingMPCProtocol, ProtocolSessionId, ProtocolTag, ShamirShare,
        ShareConversionProtocol, RBC,
    },
    honeybadger::{
        a2b::{
            a2b::{A2BNode, MAX_A2B_CONVERSIONS},
            A2BError,
        },
        b2a::{b2a::B2ANode, B2AError},
        batch_recon::{BatchReconError, BatchReconMsg},
        binary_circuits::CircuitError,
        conv_preprocessing::{ConvPreprocMaterial, ConvPreprocessingError},
        dabit::{
            edabit::EdaBitFilterNode,
            prss_dabit::{PrssDaBitKeys, PrssDaBitNode},
            DaBit, DaBitError,
        },
        dn07::{
            dn07::Dn07MulNode,
            double_share::{GfPrssDoubleShareSource, PrssDoubleShareSource},
            gf_dn07::GfDn07MulNode,
            Dn07Error, PreprocessingSessionId, MAX_DN07_SESSIONS,
        },
        double_share::{double_share_generation, DouShaError, DouShaMessage, DoubleShamirShare},
        fpdiv::fpdiv_const::{FPDivConstError, FPDivConstNode},
        fpmul::{
            fpmul::{FPError, FPMulNode},
            prandint::PRandIntNode,
            rand_bit::RandBit,
            PRandIntError, PRandIntMessage, RandBitError, TruncPrError, TruncPrMessage,
        },
        gf_batch_recon::{gf_batch_recon::MAX_GF_BATCH_RECON_SESSIONS, GfBatchReconError},
        gf_double_share::{gf_double_share_generation::GfDoubleShareNode, GfDouShaError},
        gf_mul::{gf_multiplication::GfMultiply, GfMulError},
        gf_preprocessing::GfHoneyBadgerMPCNodePreprocMaterial,
        gf_prss::gf_prss::GfPrssKeys,
        gf_ran_dou_sha::{gf_ran_dou_sha::GfRanDouShaNode, GfRanDouShaError},
        gf_share_gen::{gf_share_gen::GfRanShaNode, GfRanShaError},
        gf_triple_gen::{gf_triple_generation::GfTripleGenNode, GfTripleGenError},
        input::{
            input::{InputClient, InputServer},
            InputError, InputMessage,
        },
        mul::{multiplication::Multiply, MulError, MultMessage},
        mul_pub::MulPubError,
        output::{
            output::{OutputClient, OutputServer},
            OutputError, OutputMessage,
        },
        preprocessing::HoneyBadgerMPCNodePreprocMaterial,
        prss::prss::{PrssKeys, PRSS_KEY_ENTROPY_BITS},
        prss::{PrssAllocator, PrssStream},
        przs::{gf_przs::GfPrzsKeys, przs::PrzsKeys, MAX_PRZS_COEFFS_PER_CALL},
        ran_dou_sha::messages::RanDouShaMessage,
        robust_interpolate::robust_interpolate::Robust,
        share_gen::{share_gen::RanShaNode, RanShaError, RanShaMessage},
        triple_gen::{ShamirBeaverTriple, TripleGenError},
        zero_share::{zero_share::ZeroShaNode, ZeroShaError},
    },
};
use ark_ff::{FftField, PrimeField};
use ark_std::rand::rngs::{OsRng, StdRng};
use ark_std::rand::{Rng, SeedableRng};
use async_trait::async_trait;
use bincode::{ErrorKind, Options};
use double_share_generation::DoubleShareNode;
use ran_dou_sha::{RanDouShaError, RanDouShaNode};
use robust_interpolate::robust_interpolate::RobustShare;
use serde::{Deserialize, Serialize};
use std::{fmt, sync::Arc, time::Instant};
use stoffelnet::network_utils::{ClientId, Network, NetworkError, PartyId};
use thiserror::Error;
use tokio::{sync::Mutex, time::Duration};
use tracing::{info, warn};
use triple_gen::triple_generation::TripleGenNode;

/// Maximum number of bytes accepted from a single network message before deserialization.
/// Rejects payloads that would cause multi-gigabyte allocations via a crafted length prefix.
const MAX_MESSAGE_SIZE: u64 = 10 * 1024 * 1024; // 10 MiB
/// Minimum statistical security parameter
pub const MIN_STATISTICAL_SECURITY: usize = 40;

fn preprocessing_trace_enabled() -> bool {
    std::env::var("HMPC_PREPROCESSING_TRACE")
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn trace_preprocessing_phase(party_id: PartyId, phase: &str, items: usize, started: Instant) {
    if preprocessing_trace_enabled() {
        eprintln!(
            "[hmpc preprocessing] party={} phase={} items={} elapsed_ms={}",
            party_id,
            phase,
            items,
            started.elapsed().as_millis()
        );
    }
}

fn triple_batch_groups_limit() -> usize {
    std::env::var("HMPC_TRIPLE_BATCH_GROUPS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(4096)
}

fn ran_dou_sha_batch_columns_limit() -> usize {
    std::env::var("HMPC_RANDOUSHA_BATCH_COLUMNS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(1536)
}

#[derive(Error, Debug)]
pub enum HoneyBadgerError {
    #[error("network error: {0:?}")]
    NetworkError(#[from] NetworkError),
    #[error("error in share generation: {0:?}")]
    RanShaError(#[from] RanShaError),
    #[error(
        "statistical security parameter {requested} is below the minimum {minimum}: leakage at a \
         TruncPr opening is bounded by 2^-kappa, so this delivers no meaningful privacy"
    )]
    InsufficientStatisticalSecurity { requested: usize, minimum: usize },
    #[error("error in ZeroSha: {0:?}")]
    ZeroShaError(#[from] ZeroShaError),
    #[error("error in MulPub: {0:?}")]
    MulPubError(#[from] MulPubError),
    #[error("error in DN07 preprocessing multiplication: {0:?}")]
    Dn07Error(#[from] Dn07Error),
    #[error("error in Input share generation: {0:?}")]
    InputError(#[from] InputError),
    #[error("error in faulty double share generation: {0:?}")]
    DouShaError(#[from] DouShaError),
    #[error("error in random double share generation: {0:?}")]
    RanDouShaError(#[from] RanDouShaError),
    #[error("there is not enough preprocessing to complete the protocol")]
    NotEnoughPreprocessing,
    #[error("error in triple generation protocol: {0:?}")]
    TripleGenError(#[from] TripleGenError),
    #[error("error in the RBC: {0:?}")]
    RbcError(#[from] RbcError),
    #[error("error in the Mul: {0:?}")]
    MulError(#[from] MulError),
    #[error("error in the Output server: {0:?}")]
    OutputError(#[from] OutputError),
    #[error("error in the Batch Reconstruction: {0:?}")]
    BatchReconError(#[from] BatchReconError),
    #[error("error in random bit generation: {0:?}")]
    RandBitError(#[from] RandBitError),
    #[error("error in Prand bit generation: {0:?}")]
    PRandIntError(#[from] PRandIntError),
    #[error("error in FPMul: {0:?}")]
    FPError(#[from] FPError),
    #[error("error in FPDiv_Const: {0:?}")]
    FPDivConstError(#[from] FPDivConstError),
    #[error("error in Truncation: {0:?}")]
    TruncPrError(#[from] TruncPrError),
    #[error("error in types: {0:?}")]
    TypeError(#[from] TypeError),
    #[error("Already reserved batch")]
    AlreadyReserved,
    /// Error during the serialization using [`bincode`].
    #[error("error during the serialization using bincode: {0:?}")]
    BincodeSerializationError(#[from] Box<ErrorKind>),
    #[error("failed to join spawned task")]
    JoinError,
    #[error("instance ID {0:?} is incorrect")]
    InstanceIdError(u32),
    #[error("output channel closed before result was received")]
    ChannelClosed,
    #[error("Invalid threshold t={0} for n={1}, must satisfy t < ceil(n / 3)")]
    InvalidThreshold(usize, usize),
    #[error("Party size is too large")]
    InvalidPartySize,
    #[error("Party Id is out of bounds")]
    InvalidPartyId,
    #[error("sender {0} is not a member of the {1}-party consensus node set")]
    UnauthorizedSender(PartyId, usize),
    #[error("the protocol cannot be executed any more")]
    LimitError,
    #[error("error in GF(2^k) share generation: {0:?}")]
    GfRanShaError(#[from] GfRanShaError),
    #[error("error in GF(2^k) double share generation: {0:?}")]
    GfDouShaError(#[from] GfDouShaError),
    #[error("error in GF(2^k) random double share generation: {0:?}")]
    GfRanDouShaError(#[from] GfRanDouShaError),
    #[error("error in GF(2^k) batch reconstruction: {0:?}")]
    GfBatchReconError(#[from] GfBatchReconError),
    #[error("error in GF(2^k) triple generation: {0:?}")]
    GfTripleGenError(#[from] GfTripleGenError),
    #[error("error in GF(2^k) multiplication: {0:?}")]
    GfMulError(#[from] GfMulError),
    #[error("share error: {0:?}")]
    ShareError(#[from] ShareError),
    #[error("error in GF(2^k) preprocessing: {0:?}")]
    GfPreprocessingError(#[from] crate::honeybadger::gf_preprocessing::GfPreprocessingError),
    #[error("error in daBit generation: {0:?}")]
    DaBitError(#[from] DaBitError),
    #[error("error in arithmetic-to-binary conversion: {0:?}")]
    A2BError(#[from] A2BError),
    #[error("error in binary-to-arithmetic conversion: {0:?}")]
    B2AError(#[from] B2AError),
    #[error("error in a binary circuit: {0:?}")]
    CircuitError(#[from] CircuitError),
    #[error("error in conversion preprocessing: {0:?}")]
    ConvPreprocessingError(#[from] ConvPreprocessingError),
    #[error("error converting between the arithmetic and binary domains: {0:?}")]
    ConvertError(#[from] ConvertError),
    /// daBit generation excluded so many dealers that a batch cannot be completed. Each
    /// `DaBitOutcome::Partial` costs at least one dealer and at most `t` can ever be excluded, so
    /// exceeding `t + 1` consecutive partial runs is impossible under the threat model — reaching
    /// this means the exclusion logic has a bug, not that an adversary is winning.
    #[error("daBit generation returned a partial batch {attempts} times in a row")]
    DaBitGenerationStalled { attempts: usize },
}

pub struct HoneyBadgerMPCClient<F: FftField, R: RBC> {
    pub id: usize,
    pub input: InputClient<F, R>,
    pub output: OutputClient<F>,
}

// implement manually because derive(Clone) requires R: Clone, which is not needed at all
impl<F, R> Clone for HoneyBadgerMPCClient<F, R>
where
    F: FftField,
    R: RBC,
{
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            input: self.input.clone(),
            output: self.output.clone(),
        }
    }
}

impl<F: FftField, R: RBC<Id = SessionId>> HoneyBadgerMPCClient<F, R> {
    pub fn new(
        id: usize,
        n: usize,
        t: usize,
        instance_id: u32,
        inputs: Vec<F>,
        input_len: usize,
    ) -> Result<Self, HoneyBadgerError> {
        let input = InputClient::new(id, n, t, instance_id, inputs)?;
        let output = OutputClient::new(id, n, t, input_len)?;
        Ok(Self { id, input, output })
    }
    pub async fn process<N: Network + Send + Sync>(
        &mut self,
        sender_id: ClientId,
        raw_msg: Vec<u8>,
        net: Arc<N>,
    ) -> Result<(), HoneyBadgerError> {
        let wrapped: WrappedMessage = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_limit(MAX_MESSAGE_SIZE)
            .deserialize(&raw_msg)?;

        match wrapped {
            WrappedMessage::Input(input_msg) => {
                if sender_id != input_msg.sender_id {
                    return Err(HoneyBadgerError::InvalidPartyId);
                }
                self.input.process(input_msg, net).await?;
            }
            WrappedMessage::Output(output_msg) => {
                if sender_id != output_msg.sender_id {
                    return Err(HoneyBadgerError::InvalidPartyId);
                }
                self.output.process(output_msg).await?
            }
            _ => warn!("Incorrect message type recieved at input"),
        }
        Ok(())
    }
}
/// Information pertaining a HoneyBadgerMPCNode protocol participant.
#[derive(Clone, Debug)]
pub struct HoneyBadgerMPCNode<F: PrimeField, R: RBC> {
    /// ID of the current execution node.
    pub id: PartyId,
    /// Preprocessing material used in the protocol execution.
    pub preprocessing_material: Arc<Mutex<HoneyBadgerMPCNodePreprocMaterial<F>>>,
    // Preprocessing parameters.
    pub params: HoneyBadgerMPCNodeOpts,
    pub preprocess: PreprocessNodes<F, R>,
    pub operations: Operation<F>,
    pub type_ops: TypeOperations<F>,
    pub output: OutputServer,
    pub counters: SubProtocolCounters,
    /// GF(2^k) preprocessing material, parallel to `preprocessing_material` above — fixed to
    /// `Gf256` for now
    pub gf_preprocessing_material: Arc<Mutex<GfHoneyBadgerMPCNodePreprocMaterial<Gf256>>>,
    /// GF(2^k) sub-protocol nodes that feed `gf_preprocessing_material`.
    pub gf_preprocess: GfPreprocessNodes<R>,
    pub gf_operations: GfOperation,
    /// daBit and edaBit pools consumed by the two conversions, parallel to the two pools above.
    pub conv_preprocessing_material: Arc<Mutex<ConvPreprocMaterial<F, Gf256>>>,
    /// Share-conversion nodes: the daBit generator that fills `conv_preprocessing_material`, and
    /// the two conversions that drain it.
    pub conv: ConvNodes<F>,
    /// Shared byte and message counters.  Updated by [`CountingNetwork`] (sends)
    /// and by [`process`] (receives).  Only present with the `statistics` feature.
    #[cfg(feature = "statistics")]
    pub statistics_counters: std::sync::Arc<statistics::NodeStatisticsCounters>,
}

impl<F, R> HoneyBadgerMPCNode<F, R>
where
    F: PrimeField,
    R: RBC<Id = SessionId>,
{
    /// Wraps `inner` in a [`CountingNetwork`] that shares this node's statistics
    /// counters.  Pass the resulting wrapper (or an `Arc` of it) wherever the
    /// protocol accepts `Arc<N>` to automatically record outbound bytes and
    /// message types.  Received bytes and message types are recorded by
    /// [`process`].
    ///
    /// Only available with the `statistics` cargo feature.
    #[cfg(feature = "statistics")]
    pub fn counting_network<N: stoffelnet::network_utils::Network>(
        &self,
        inner: N,
    ) -> statistics::CountingNetwork<N> {
        statistics::CountingNetwork::new(inner, std::sync::Arc::clone(&self.statistics_counters))
    }

    /// Returns a best-effort snapshot of all statistics counters.
    ///
    /// Only available with the `statistics` cargo feature.
    #[cfg(feature = "statistics")]
    pub fn statistics_snapshot(&self) -> statistics::NodeStatisticsSnapshot {
        self.statistics_counters.snapshot()
    }
    /// Establishes this party's PRSS keys by running RISS **once**, then switches PRandInt to
    /// local derivation.
    pub async fn setup_prss_keys<N>(&mut self, network: Arc<N>) -> Result<(), HoneyBadgerError>
    where
        N: Network + Send + Sync + 'static,
    {
        if self.preprocess.prand_int.has_prss_keys() {
            info!("PRSS keys already installed");
            return Ok(());
        }

        // Each folded `r_T` hides at least `k + l` bits from the parties inside `T`, so take as
        // many as the entropy target needs. Sized from the parameters rather than hardcoded:
        // a small `k + l` would otherwise silently yield a low-entropy key.
        let bits_per_value = self.params.mask_bits().max(1);
        let batch_size = PRSS_KEY_ENTROPY_BITS.div_ceil(bits_per_value);

        // The setup session is a real RISS session, so a counter is safe here — a mismatch makes
        // messages fail to assemble and surfaces as a timeout. That is exactly the property the
        // derivation path lacks, which is why its exec id is fixed instead.
        let sessionid = SessionId::new(
            ProtocolType::PRandInt,
            SessionId::pack_slot(self.counters.prand_int_counter.get_next().await?, 0, 0),
            self.params.instance_id,
        );

        self.preprocess
            .prand_int
            .generate_riss(
                sessionid,
                self.params.mask_bits(),
                batch_size,
                network.clone(),
            )
            .await?;

        // Waiting on the share output is how we learn the fold completed; the shares themselves
        // are discarded, only `r_T` matters for keys.
        let _ = self
            .preprocess
            .prand_int
            .wait_for_int_result(sessionid, self.params.timeout)
            .await?;

        let keys = self.preprocess.prand_int.take_riss_keys(sessionid).await?;

        if !self.preprocess.prand_int.clear_store(sessionid).await {
            warn!(?sessionid, "failed to clear PRSS setup session state");
        }

        let n = self.params.n_parties;
        let t = self.params.threshold;
        let prss = PrssKeys::<F>::new(self.id, n, t, &keys).map_err(PRandIntError::from)?;

        // The same key family, read under four different KDF labels and context bytes, also gives
        // DN07 its double sharings for free. Built here rather than lazily at first use so that a
        // mis-parameterised store fails once, loudly, at setup — a PRZS store whose mask is not
        // `t`-dimensional is a privacy break that no functional test can see, and
        // `PrssDoubleShareSource::new` re-asserts that invariant.
        let to_err = |e: Dn07Error| HoneyBadgerError::Dn07Error(e);
        let przs = PrzsKeys::<F>::new(self.id, n, t, &keys)
            .map_err(|e| Dn07Error::Przs(format!("{e:?}")))
            .map_err(to_err)?;
        self.preprocess.dn07_doubles =
            Some(PrssDoubleShareSource::new(prss.clone(), przs).map_err(to_err)?);

        // The cursors that keep every PRSS/PRZS position on this key family monotone. Built here,
        // once, with the family's fingerprint: the count of positions already issued is only
        // meaningful against the keys it was counted for, and stamping it makes that coupling
        // checkable rather than implied. It also pins the restart argument — keys are ephemeral
        // (no store in this crate is `Serialize`, and the gate above is an in-memory flag), so a
        // restarted node re-runs RISS, gets a *fresh* family, and a zeroed allocator is correct.
        // Persisting keys without also persisting these cursors would re-derive every position
        // this node has ever opened; see `prss::window`.
        self.preprocess.prss_alloc = Some(PrssAllocator::new(
            self.params.instance_id,
            prss.key_family_id(),
        ));

        let gf_prss = GfPrssKeys::<Gf256>::new(self.id, n, t, &keys)
            .map_err(|e| Dn07Error::Prss(format!("{e:?}")))
            .map_err(to_err)?;
        let gf_przs = GfPrzsKeys::<Gf256>::new(self.id, n, t, &keys)
            .map_err(|e| Dn07Error::Przs(format!("{e:?}")))
            .map_err(to_err)?;
        self.gf_preprocess.gf_dn07_doubles =
            Some(GfPrssDoubleShareSource::new(gf_prss, gf_przs).map_err(to_err)?);

        // The daBit generator reads the *same* key family from both sides: `beta_T` is one
        // `derive_ints_at` call whose bytes the `F` conversion turns into the integer sum and the
        // `K` conversion turns into the XOR. Two stores built over different keys would produce
        // two unrelated bits and nothing could tell — which is why `PrssDaBitKeys::new`
        // cross-checks them here rather than at first use.
        let dabit_gf_prss = GfPrssKeys::<Gf256>::new(self.id, n, t, &keys)
            .map_err(|e| Dn07Error::Prss(format!("{e:?}")))
            .map_err(to_err)?;
        self.conv.dabit_gen.install_keys(PrssDaBitKeys::new(
            self.id,
            t,
            prss.clone(),
            dabit_gf_prss,
        )?);

        self.preprocess.prand_int.install_prss_keys(prss);
        info!("PRSS key setup complete");
        Ok(())
    }

    pub fn prss_keys_installed(&self) -> bool {
        self.preprocess.prand_int.has_prss_keys()
    }

    /// TruncPr opens `b + r` in the clear, so its privacy rests on one inequality
    /// (Damgård–Thorbek §3.2): a value in `[0, 2^l)` needs a mask drawn from `[0, 2^(l+k))`.
    ///
    /// ```text
    /// mask_bits  >=  value_bits + statistical_security
    /// ```
    ///
    /// `value_bits` is the width of *this* value — taken from the value's own precision, not the
    /// node's, since `SecretFixedPoint::new_with_precision` lets them differ. The pool was sized
    /// once for `max_masked_width(params.precision)`, so this catches both a value carrying a
    /// wider precision than configured and an operation masking something the sizing function
    /// does not account for.
    ///
    /// This used to compare against a configured `params.l`, with `l` and `k` as separate knobs.
    /// Only their sum ever mattered, so splitting them invited one specific misconfiguration:
    /// passing the *precision* into the security slot, which reads plausibly and silently
    /// delivers whatever margin happens to be left over.
    fn check_mask_security(&self, value_bits: usize) -> Result<(), HoneyBadgerError> {
        let mask_bits = self.params.mask_bits();
        let delivered = mask_bits.saturating_sub(value_bits);
        if delivered < self.params.statistical_security {
            return Err(HoneyBadgerError::FPError(
                FPError::InsufficientStatisticalSecurity {
                    delivered,
                    required: self.params.statistical_security,
                    mask_bits,
                    value_bits,
                },
            ));
        }
        Ok(())
    }

    pub async fn debug_store_sizes(&self) -> String {
        let len = self.preprocessing_material.lock().await.length();
        let triples = len.beaver_triples;
        let random_shares = len.random_shr;
        let randbit = len.randbit;
        let prandint = len.prandint;
        let conv = self.conv_preprocessing_material.lock().await.length();
        let dabits = conv.dabits;
        let edabits = conv.edabits;
        format!(
            "material=(triples:{triples},random:{random_shares},randbit:{randbit},prandint:{prandint},dabits:{dabits},edabits:{edabits}) \
             stores=(share_gen:{},dou_sha:{},ran_dou_sha:{},triple:{},triple_batch_recon:{},mul:{},rand_bit:{},rand_bit_mul_pub:{},zero_sha:{},prand_int:{},fpmul_mul:{},fpmul_trunc:{},dabit_mod2:{},edabit:{},edabit_gf_dn07:{},edabit_gf_open:{},a2b:{},a2b_open:{},a2b_gf_mul:{},b2a:{},b2a_gf_open:{},dn07:{},gf_dn07:{})",
            self.preprocess.share_gen.store_len().await,
            self.preprocess.dou_sha.store_len().await,
            self.preprocess.ran_dou_sha.store_len().await,
            self.preprocess.triple_gen.store_len().await,
            self.preprocess.triple_gen.batch_recon_node.store_len().await,
            self.operations.mul.store_len().await,
            self.preprocess.rand_bit.store_len().await,
            self.preprocess.rand_bit.mul_pub.store_len().await,
            self.preprocess.zero_sha.store_len().await,
            self.preprocess.prand_int.store_len().await,
            self.type_ops.fpmul.mult_node.store_len().await,
            self.type_ops.fpmul.trunc_node.store_len().await,
            self.conv.dabit_gen.store_len().await,
            self.conv.edabit.store_len().await,
            self.conv.edabit.gf_dn07.store_len().await,
            self.conv.edabit.gf_open.store_len().await,
            self.conv.a2b.store_len().await,
            self.conv.a2b.open.store_len().await,
            self.conv.a2b.gf_mul.store_len().await,
            self.conv.b2a.store_len().await,
            self.conv.b2a.gf_open.store_len().await,
            self.preprocess.dn07.store_len().await,
            self.gf_preprocess.gf_dn07.store_len().await,
        )
    }
}

#[derive(Clone, Debug)]
pub struct Operation<F: FftField> {
    pub mul: Multiply<F>,
}

#[derive(Clone, Debug)]
pub struct TypeOperations<F: PrimeField> {
    pub fpmul: FPMulNode<F>,
    pub fpdiv_const: FPDivConstNode<F>,
}

#[derive(Clone, Debug)]
pub struct PreprocessNodes<F: PrimeField, R: RBC> {
    // Nodes for subprotocols.
    pub input: InputServer<F, R>,
    pub share_gen: RanShaNode<F, R>,
    pub dou_sha: DoubleShareNode<F>,
    pub ran_dou_sha: RanDouShaNode<F, R>,
    pub triple_gen: TripleGenNode<F>,
    /// Generates PRandInt shares via the distributed RISS protocol.
    pub prand_int: PRandIntNode<F, R>,
    /// Generates RandBit shares directly in `F` (see `ensure_randbit_shares`).
    pub rand_bit: RandBit<F>,
    /// Produces the degree-`2t` zero-sharings that re-randomise RandBit's MulPub opening.
    pub zero_sha: ZeroShaNode<F, R>,
    /// DN07 degree-reduction multiplication and exact-zero check over `F`. Tag: `Dn07`.
    ///
    /// **PREPROCESSING ONLY.** It lives here, and not in [`Operation`], precisely because it
    /// opens at degree `2t`: the online path must have no handle to it. See `honeybadger::dn07`.
    ///
    /// Its production caller is [`Self::generate_triples_via_dn07`], which makes every `F` Beaver
    /// triple from PRSS material in one degree-`2t` opening. `init_zero_check` has no caller; see
    /// the `dn07` module docs for why that is a deliberate state rather than dead code.
    pub dn07: Dn07MulNode<F>,
    /// Non-interactive `([r]_t, [r]_2t)` source for [`PreprocessNodes::dn07`], installed by
    /// `setup_prss_keys` once the PRSS key family exists. `None` until then, and while it is
    /// `None` every DN07 consumer falls back to the dealt `RanDouSha` pool.
    ///
    /// Read by `RandBit` (through `randbit_material`, which takes the two halves *apart*) and by
    /// triple generation (through `triple_material`, which takes `a`, `b` and the pair from three
    /// disjoint position ranges of one window).
    pub dn07_doubles: Option<PrssDoubleShareSource<F>>,
    /// Monotone PRSS/PRZS position cursors for this node's key family, installed by
    /// `setup_prss_keys` next to [`PreprocessNodes::dn07_doubles`] and `None` until then.
    ///
    /// Installed *alongside* the key stores and never rebuilt, because a second allocator over
    /// one key family forks the cursors and re-issues every position. Held here rather than in a
    /// global so that a cloned node shares it — the cursors live behind an `Arc`, so two clones
    /// racing a claim serialise rather than both deriving the same range. See
    /// [`prss::window`](crate::honeybadger::prss::window).
    pub prss_alloc: Option<PrssAllocator>,
}

#[derive(Clone, Debug)]
pub struct GfOperation {
    pub mul: GfMultiply<Gf256>,
}

/// GF(2^k) sub-protocol nodes needed to keep `gf_preprocessing_material` topped up:
/// random-share generation for the triple's `a`/`b`, double-share dealing + RanDouSha for the
/// mask, and triple generation itself.
#[derive(Clone, Debug)]
pub struct GfPreprocessNodes<R: RBC> {
    pub gf_share_gen: GfRanShaNode<Gf256, R>,
    pub gf_dou_sha: GfDoubleShareNode<Gf256>,
    pub gf_ran_dou_sha: GfRanDouShaNode<Gf256, R>,
    pub gf_triple_gen: GfTripleGenNode<Gf256>,
    /// DN07 degree-reduction multiplication and exact-zero check over `Gf256`. Tag: `GfDn07`.
    /// **PREPROCESSING ONLY** — see [`PreprocessNodes::dn07`].
    ///
    /// This instance is reached only through the dispatcher's `GfDn07` arm. The edaBit filter's
    /// AND layers run on a *second* `GfDn07MulNode`, owned by `conv.edabit` under the
    /// `DaBitGfMul` tag: a `GfDn07MulNode` mints its batch-reconstruction child with the parent's
    /// tag, and the dispatcher demuxes on that tag alone, so two nodes of this type must not
    /// share one.
    pub gf_dn07: GfDn07MulNode<Gf256>,
    /// Non-interactive `([r]_t, [r]_2t)` source for [`GfPreprocessNodes::gf_dn07`]. `None` until
    /// `setup_prss_keys` runs; while it is `None`, GF triple generation and the edaBit filter
    /// both use the dealt `GfRanDouSha` pool exactly as before.
    ///
    /// Both consumers claim their positions from [`PreprocessNodes::prss_alloc`], never from a
    /// counter of their own — see `HoneyBadgerMPCNode::gf_prss_doubles`.
    pub gf_dn07_doubles: Option<GfPrssDoubleShareSource<Gf256>>,
}

/// Share-conversion nodes.
///
/// Unlike [`GfPreprocessNodes`] this carries an `F` parameter: `GfPreprocessNodes` gets away
/// without one only because it is `Gf256` on both sides, whereas every one of these nodes
/// straddles the prime field and the binary field at once.
///
/// `Gf256` stays hard-wired on the `K` side, matching the precedent set by
/// `gf_preprocessing_material` and `gf_operations`. Generalising the node over `K` is a separate
/// breaking change and is not needed here: every verification opening in this stack is an
/// *exact-zero* check rather than a random linear combination, so the eight-bit field carries no
/// soundness penalty that a wider one would remove.
///
/// No `R: RBC` any more: the dealt daBit protocol reliably broadcast its dealers' `Deltas`, and
/// PRSS daBits broadcast nothing at all.
#[derive(Clone, Debug)]
pub struct ConvNodes<F: PrimeField> {
    /// Produces the doubly-shared bits both conversions consume. Tags: `DaBit` (the parent batch,
    /// which carries no wire traffic) and `DaBitOpen` (the single Mod2 opening).
    pub dabit_gen: PrssDaBitNode<F, Gf256>,
    /// Composes full-range edaBits and filters the masks that wrap `p`. Tags: `DaBitGfMul` (the
    /// filter's AND layers) and `DaBitGfOpen` (its degree-`t` verdict opening).
    pub edabit: EdaBitFilterNode<F, Gf256>,
    /// Arithmetic to binary. Tags: `A2B` (mask opening) and `A2BGfMul` (AND layers).
    ///
    /// Built on [`OpeningPolicy::Auto`](gf_mul::OpeningPolicy::Auto), which prices each AND
    /// layer's two plans in measured bytes and takes the one-round direct path while it is no
    /// dearer than the two-round batched one plus one round's allowance. For the layer widths a
    /// 64-bit conversion actually issues that is the direct path at every `n` — 9 online rounds
    /// rather than 16, and 9 not 8, since the mask opening this policy does not govern is a
    /// two-round `BatchRecon` session — while the far wider layers of a large batch cross over
    /// and batch, with the last group padded rather than opened directly. Both halves are
    /// degree-`t` and robust; the node has no reason to differ per deployment, and a deployment
    /// with its own bytes-for-rounds exchange rate can build the node through
    /// [`A2BNode::new_with_opening_policy`](a2b::a2b::A2BNode::new_with_opening_policy) with
    /// [`OpeningPolicy::Tuned`](gf_mul::OpeningPolicy::Tuned).
    pub a2b: A2BNode<F, Gf256>,
    /// Binary to arithmetic. Tag: `B2A` (the single `K`-side opening).
    pub b2a: B2ANode<F, Gf256>,
}

#[derive(Clone, Debug)]
pub struct SubProtocolCounter(Arc<Mutex<Option<u64>>>);

impl SubProtocolCounter {
    /// The exec id `get_next` would hand out next, or `None` once the counter has saturated.
    ///
    /// Read-only, and read-only on purpose: there is no setter and there must not be one. Every
    /// counter here addresses either a network session or — through
    /// [`PrssAllocator`](prss::PrssAllocator) — a PRSS position, and rewinding one re-derives a
    /// position that has already been spent. What this accessor is for is the opposite question:
    /// "did that protocol run at all?", which is how a test tells a `TripleGenNode` batch apart
    /// from a `Dn07MulNode` one when both produce identical triples.
    pub async fn peek(&self) -> Option<u64> {
        *self.0.lock().await
    }
}

trait GetNext<T> {
    async fn get_next(&self) -> Result<T, HoneyBadgerError>;
}

impl GetNext<u64> for SubProtocolCounter {
    async fn get_next(&self) -> Result<u64, HoneyBadgerError> {
        let mut counter = self.0.lock().await;

        match &mut *counter {
            None => Err(HoneyBadgerError::LimitError),
            Some(value) => {
                let current = *value;
                // 64-bit exec_id: for all practical workloads this never saturates. Guard the
                // theoretical u64::MAX wrap so the counter faults loudly instead of silently
                // aliasing an old exec_id.
                if *value == u64::MAX {
                    *counter = None;
                } else {
                    *value += 1;
                }
                Ok(current)
            }
        }
    }
}

/// Per sub-protocol there is a counter to increment the exec ID within the
/// session ID and distinguish different executions of the same sub-protocol.
#[derive(Clone, Debug)]
pub struct SubProtocolCounters {
    pub ran_dou_sha_counter: SubProtocolCounter,
    pub ran_sha_counter: SubProtocolCounter,
    pub triple_counter: SubProtocolCounter,
    pub batch_recon_counter: SubProtocolCounter,
    pub dou_sha_counter: SubProtocolCounter,
    pub mul_counter: SubProtocolCounter,
    pub rand_bit_counter: SubProtocolCounter,
    pub prand_int_counter: SubProtocolCounter,
    pub fpmul_counter: SubProtocolCounter,
    pub fpdiv_const_counter: SubProtocolCounter,
    pub zero_sha_counter: SubProtocolCounter,
    pub gf_ran_sha_counter: SubProtocolCounter,
    pub gf_dou_sha_counter: SubProtocolCounter,
    pub gf_ran_dou_sha_counter: SubProtocolCounter,
    pub gf_triple_counter: SubProtocolCounter,
    pub gf_mul_counter: SubProtocolCounter,
    // There is deliberately **no `dabit_counter` here.** daBit-generation parent exec ids, and
    // the edaBit modulus-overflow filter's, are minted by `PrssStream::DaBitSeed`'s cursor inside
    // the node's single `PrssAllocator` — the same value addresses both a session-id block and a
    // PRSS keystream, so it must have exactly one minter. A counter kept here as well would be a
    // second one, and the two would issue the same exec the moment they disagreed. The
    // disjoint-child-block argument that lived in this doc comment now lives on
    // `PrssStream::DaBitSeed`.
    /// Exec ids for A2B parent sessions. A2B derives its own children the same way.
    pub a2b_counter: SubProtocolCounter,
    /// Exec ids for B2A parent sessions.
    pub b2a_counter: SubProtocolCounter,
}

impl SubProtocolCounters {
    pub fn new() -> Self {
        Self {
            ran_dou_sha_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            ran_sha_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            triple_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            batch_recon_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            dou_sha_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            mul_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            rand_bit_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            prand_int_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            fpmul_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            fpdiv_const_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            zero_sha_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            gf_ran_sha_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            gf_dou_sha_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            gf_ran_dou_sha_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            gf_triple_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            gf_mul_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            a2b_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            b2a_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
        }
    }
}

#[derive(Clone, Debug)]
/// Configuration options for the HoneyBadgerMPCNode protocol.
pub struct HoneyBadgerMPCNodeOpts {
    /// Number of parties in the protocol.
    /// Minimum 5 for hbmpc
    pub n_parties: usize,
    /// Upper bound of corrupt parties.
    pub threshold: usize,
    /// Number of random double sharing pairs that need to be generated.
    pub n_triples: usize,
    /// Number of random shares needed.
    /// This is usually = No of inputs + 2 * no of triples
    pub n_random_shares: usize,
    /// Instance ID
    pub instance_id: u32,
    ///Number of RandBit shares
    pub n_randbit: usize,
    ///Number of PrandInt shares
    pub n_prandint: usize,
    /// Number of degree-`2t` zero-sharings to generate. Its own preprocessing material with its
    /// own `ensure_zero_shares` phase, not derived at point of use. `new` seeds it from
    /// `n_randbit` because RandBit's MulPub squaring is the only consumer today (one per bit);
    /// set it directly when another protocol starts drawing from the pool.
    pub n_zero_shares: usize,
    /// Fixed-point precision this node's preprocessing is sized for.
    ///
    /// The mask pool is generated once, before any value exists, so its width has to be decided
    /// here. Operations still check their own value's precision at use time — a value carrying a
    /// wider precision than this is rejected rather than silently under-masked.
    pub precision: FixedPointPrecision,
    /// Statistical security parameter κ: leakage at a TruncPr opening is bounded by `2^-κ`.
    ///
    /// Policy-level and operation-independent — this is Damgård–Thorbek's `k`. The companion
    /// parameter `l` from that paper is *not* configurable: it is the width of the value being
    /// masked, so it is derived from `precision` rather than chosen. Letting it float free of the
    /// value is what silently decouples the configured κ from the delivered one.
    pub statistical_security: usize,
    pub timeout: Duration,
    /// Number of GF(2^k) Beaver triples that need to be generated.
    pub n_gf_triples: usize,
    /// Number of GF(2^k) random shares needed. Same rule of thumb as `n_random_shares`: at least
    /// `2 * n_gf_triples` (the `a`/`b` inputs to every triple), plus any GF(2^k) inputs.
    pub n_gf_random_shares: usize,
    /// Number of loose doubly-shared bits to keep in the conversion pool.
    ///
    /// One per input bit of every B2A call. edaBits are counted separately and are **not** drawn
    /// from this figure — `ensure_edabits` generates its own daBits — so a node doing only A2B can
    /// leave this at zero.
    pub n_dabits: usize,
    /// Number of full-range edaBits to keep in the conversion pool: one per A2B-converted value.
    ///
    /// Each costs `field_bit_width::<F>()` daBits plus one run of the modulus-overflow filter, so
    /// the daBit-generation demand this implies is far larger than `n_dabits`.
    pub n_edabits: usize,
    /// `k`, the number of extra `RandBit`s folded into each daBit's Mod2 mask, or `None` for the
    /// production default `ceil(log2 C(n,t)) - 3`.
    ///
    /// This is **not** a soundness parameter — PRSS daBits have soundness error 0. It trades
    /// `RandBit`s for lifetime capacity: the per-daBit statistical leak is `2^-(lambda+k+1)`, so
    /// a node may produce `Q = 2^(lambda+k+1-kappa)` daBits over its whole life before the union
    /// bound reaches `kappa`. See
    /// [`DaBitLeakBudget`](crate::honeybadger::dabit::prss_dabit::DaBitLeakBudget).
    pub dabit_topup_bits: Option<usize>,
}

impl HoneyBadgerMPCNodeOpts {
    /// Creates a new struct of initialization options for the HoneyBadgerMPCNode protocol.
    pub fn new(
        n_parties: usize,
        threshold: usize,
        n_triples: usize,
        n_random_shares: usize,
        instance_id: u32,
        n_randbit: usize,
        n_prandint: usize,
        precision: FixedPointPrecision,
        statistical_security: usize,
        timeout: Duration,
        n_gf_triples: usize,
        n_gf_random_shares: usize,
    ) -> Result<Self, HoneyBadgerError> {
        //No of parties should not exceed 255
        if n_parties > 255 {
            return Err(HoneyBadgerError::InvalidPartySize);
        }
        if !(threshold < (n_parties + 2) / 3) {
            // ceil(n / 3)
            return Err(HoneyBadgerError::InvalidThreshold(threshold, n_parties));
        }
        // Reject a κ too small to mean anything here, rather than letting it surface later as an
        // undersized mask at the first fixed-point operation.
        if statistical_security < MIN_STATISTICAL_SECURITY {
            return Err(HoneyBadgerError::InsufficientStatisticalSecurity {
                requested: statistical_security,
                minimum: MIN_STATISTICAL_SECURITY,
            });
        }
        Ok(Self {
            n_parties,
            threshold,
            n_triples,
            n_random_shares,
            instance_id,
            n_randbit,
            n_prandint,
            n_zero_shares: n_randbit,
            precision,
            statistical_security,
            timeout,
            n_gf_triples,
            n_gf_random_shares,
            // Seeded here rather than taken positionally: `new` already takes twelve arguments,
            // and the `n_gf_triples` addition churned every test, bench and FFI caller once
            // already. Callers that want conversion preprocessing set it through the mutators.
            n_dabits: 0,
            n_edabits: 0,
            dabit_topup_bits: None,
        })
    }
    pub fn set_timeout(&mut self, secs: u64) {
        self.timeout = Duration::from_secs(secs)
    }

    /// Width of TruncPr's high mask `r''`, in bits: the widest value any supported fixed-point
    /// operation feeds into TruncPr at this precision, plus the statistical margin.
    ///
    /// Damgård–Thorbek §3.2: to mask a value in `[0, 2^l)` the mask must be drawn from
    /// `[0, 2^(l+k))`. Derived, never configured — see [`Self::max_masked_width`].
    pub fn mask_bits(&self) -> usize {
        Self::max_masked_width(self.precision) + self.statistical_security
    }

    /// The widest value any supported fixed-point operation masks at this precision.
    ///
    /// `mul_fixed` and `div_with_const_fixed` both truncate a `2k`-bit product by `f` bits, so
    /// `2k - f` covers both. **A new operation that masks something wider belongs here** —
    /// otherwise `check_mask_security` rejects it at first use rather than under-masking it
    /// silently. Sizing one pool for the widest consumer is deliberate: an over-wide mask costs
    /// only keystream bytes during derivation, while a short one leaks.
    pub fn max_masked_width(precision: FixedPointPrecision) -> usize {
        (2usize * precision.k()).saturating_sub(precision.f())
    }
    /// Override the zero-sharing pool size, which `new` seeds from `n_randbit`.
    pub fn set_n_zero_shares(&mut self, n_zero_shares: usize) {
        self.n_zero_shares = n_zero_shares
    }

    /// Set the loose-daBit pool size, which `new` seeds to zero.
    pub fn set_n_dabits(&mut self, n_dabits: usize) {
        self.n_dabits = n_dabits
    }

    /// Set the full-range edaBit pool size, which `new` seeds to zero.
    pub fn set_n_edabits(&mut self, n_edabits: usize) {
        self.n_edabits = n_edabits
    }

    /// Set the daBit `RandBit` top-up `k`, which `new` seeds to `None` (the production default
    /// `ceil(log2 C(n,t)) - 3`).
    ///
    /// `Some(0)` is the minimum-cost setting: one `RandBit` per daBit, and the `Q` column of
    /// [`DaBitLeakBudget`](crate::honeybadger::dabit::prss_dabit::DaBitLeakBudget) at `k = 0`.
    /// It is correct at `n = 4` (where the default is 0 anyway) and for low-volume deployments.
    ///
    /// The value is validated when the node is built, not here: an out-of-range `k` is a
    /// [`DaBitError::TopUpTooLarge`], never a `warn!` and never a clamp. `k` and `lambda` are one
    /// budget, both consequences of the same no-wrap inequality, so silently adjusting either is
    /// exactly the `l`/`kappa` misconfiguration class this repo has already shipped once.
    pub fn set_dabit_topup_bits(&mut self, topup_bits: Option<usize>) {
        self.dabit_topup_bits = topup_bits
    }
}

#[async_trait]
impl<F, R, N> MPCProtocol<F, RobustShare<F>, N> for HoneyBadgerMPCNode<F, R>
where
    N: Network + Send + Sync + 'static,
    F: PrimeField,
    R: RBC<Id = SessionId>,
{
    type MPCOpts = HoneyBadgerMPCNodeOpts;
    type Error = HoneyBadgerError;

    fn setup(
        id: PartyId,
        params: Self::MPCOpts,
        input_ids: Vec<ClientId>,
    ) -> Result<Self, HoneyBadgerError> {
        if id >= params.n_parties {
            return Err(HoneyBadgerError::InvalidPartyId);
        }
        // Create nodes for preprocessing.
        let dousha_node = DoubleShareNode::new(id, params.n_parties, params.threshold);
        let prand_int_node =
            PRandIntNode::new(id, params.n_parties, params.threshold, params.threshold + 1)?;
        let ran_dou_sha_node =
            RanDouShaNode::new(id, params.n_parties, params.threshold, params.threshold + 1)?;

        let triple_gen_node = TripleGenNode::new(id, params.n_parties, params.threshold)?;
        let mul_node = Multiply::new(id, params.n_parties, params.threshold)?;
        let share_gen =
            RanShaNode::new(id, params.n_parties, params.threshold, params.threshold + 1)?;
        let fpmul_node = FPMulNode::new(id, params.n_parties, params.threshold)?;
        let fpdiv_const_node = FPDivConstNode::new(id, params.n_parties, params.threshold)?;
        let input = InputServer::new(id, params.n_parties, params.threshold, input_ids)?;
        let output = OutputServer::new(id, params.n_parties)?;
        let rand_bit_node = RandBit::new(id, params.n_parties, params.threshold)?;
        let zero_sha_node =
            ZeroShaNode::new(id, params.n_parties, params.threshold, params.threshold + 1)?;

        // GF(2^k) nodes, parallel to the F-domain ones above.
        let gf_dou_sha_node = GfDoubleShareNode::new(id, params.n_parties, params.threshold);
        let gf_ran_dou_sha_node =
            GfRanDouShaNode::new(id, params.n_parties, params.threshold, params.threshold + 1)?;
        let gf_triple_gen_node = GfTripleGenNode::new(id, params.n_parties, params.threshold)?;
        let gf_mul_node = GfMultiply::new(id, params.n_parties, params.threshold)?;
        let gf_share_gen_node =
            GfRanShaNode::new(id, params.n_parties, params.threshold, params.threshold + 1)?;

        // Share-conversion nodes. `Opts::new` already rejects `n_parties > 255`, which coincides
        // with `Gf256::MAX_DOMAIN_SIZE` — the number of distinct evaluation points the binary
        // domain has. Each constructor re-checks it against `K::MAX_DOMAIN_SIZE` so the coupling
        // is explicit rather than a coincidence of two numbers that happen to agree today.
        debug_assert!(
            params.n_parties <= <Gf256 as crate::common::gf2k::field::BinaryField>::MAX_DOMAIN_SIZE
        );
        // The leak budget (`lambda`, `k`, `Q`) is derived and hard-checked here, at construction:
        // an out-of-range `k`, a field too narrow for the mask, or a `(lambda, k)` pair that lets
        // the Mod2 opening wrap `p` all fail once, loudly, rather than silently flipping bits or
        // over-spending the statistical budget batch by batch.
        let dabit_gen_node = PrssDaBitNode::new(
            id,
            params.n_parties,
            params.threshold,
            params.statistical_security,
            params.dabit_topup_bits,
        )?;
        let edabit_node = EdaBitFilterNode::new(id, params.n_parties, params.threshold)?;
        let a2b_node = A2BNode::new(id, params.n_parties, params.threshold)?;
        let b2a_node = B2ANode::new(id, params.n_parties, params.threshold)?;

        // DN07 preprocessing multiplication, `F` and `Gf256`. Both constructors hard-error for
        // `t = 0` and for `n < 3t+1`, which `HoneyBadgerMPCNodeOpts::new`'s `t < (n+2)/3` already
        // guarantees for `t >= 1`; the duplication is deliberate, since `Opts`' fields are public
        // and a struct literal can bypass its constructor.
        let dn07_node = Dn07MulNode::new(id, params.n_parties, params.threshold)?;
        let gf_dn07_node = GfDn07MulNode::new(id, params.n_parties, params.threshold)?;

        Ok(Self {
            id,
            preprocessing_material: Arc::new(
                Mutex::new(HoneyBadgerMPCNodePreprocMaterial::empty()),
            ),
            params,
            preprocess: PreprocessNodes {
                input,
                share_gen,
                dou_sha: dousha_node,
                ran_dou_sha: ran_dou_sha_node,
                triple_gen: triple_gen_node,
                prand_int: prand_int_node,
                rand_bit: rand_bit_node,
                zero_sha: zero_sha_node,
                dn07: dn07_node,
                // Installed by `setup_prss_keys`; until then DN07 consumers use the dealt pools.
                dn07_doubles: None,
                prss_alloc: None,
            },
            operations: Operation { mul: mul_node },
            gf_preprocessing_material: Arc::new(Mutex::new(
                GfHoneyBadgerMPCNodePreprocMaterial::empty(),
            )),
            gf_preprocess: GfPreprocessNodes {
                gf_share_gen: gf_share_gen_node,
                gf_dou_sha: gf_dou_sha_node,
                gf_ran_dou_sha: gf_ran_dou_sha_node,
                gf_triple_gen: gf_triple_gen_node,
                gf_dn07: gf_dn07_node,
                gf_dn07_doubles: None,
            },
            gf_operations: GfOperation { mul: gf_mul_node },
            conv_preprocessing_material: Arc::new(Mutex::new(ConvPreprocMaterial::empty())),
            conv: ConvNodes {
                dabit_gen: dabit_gen_node,
                edabit: edabit_node,
                a2b: a2b_node,
                b2a: b2a_node,
            },
            type_ops: TypeOperations {
                fpmul: fpmul_node,
                fpdiv_const: fpdiv_const_node,
            },
            output,
            counters: SubProtocolCounters::new(),
            #[cfg(feature = "statistics")]
            statistics_counters: std::sync::Arc::new(statistics::NodeStatisticsCounters::default()),
        })
    }

    async fn mul(
        &mut self,
        x: Vec<RobustShare<F>>,
        y: Vec<RobustShare<F>>,
        network: Arc<N>,
    ) -> Result<Vec<RobustShare<F>>, Self::Error> {
        // Both lists must have the same length.
        assert_eq!(x.len(), y.len());
        if x.is_empty() {
            return Ok(Vec::new());
        }

        let no_triples = {
            let store = self.preprocessing_material.lock().await;
            store.length().beaver_triples
        };
        if no_triples < x.len() {
            //Run preprocessing
            let mut rng = StdRng::from_rng(OsRng).unwrap();
            self.run_preprocessing(network.clone(), &mut rng).await?;
        }
        let max_pairs_per_session = max_mul_pairs_per_session(self.params.threshold);
        let mut result = Vec::with_capacity(x.len());

        // Issue ALL sessions first, then await their results. Sessions are independent (distinct
        // session ids, distinct triples, distinct `mult_storage` entries), so their network rounds
        // overlap during the awaits instead of running strictly back-to-back. Under realistic
        // network latency this turns the per-session 2-round critical path from additive (2·k
        // rounds for k sessions) into the max (~2 rounds), and it is correctness-preserving.
        // Results are still collected in session order, so the output ordering matches the input.
        let mut session_ids = Vec::new();
        for (x_chunk, y_chunk) in x
            .chunks(max_pairs_per_session)
            .zip(y.chunks(max_pairs_per_session))
        {
            // Extract preprocessing triples for this protocol session.
            let beaver_triples = self
                .preprocessing_material
                .lock()
                .await
                .take_beaver_triples(x_chunk.len())?;

            let session_id = SessionId::new(
                ProtocolType::Mul,
                SessionId::pack_slot(self.counters.mul_counter.get_next().await?, 0, 0),
                self.params.instance_id,
            );

            // Call the mul function.
            self.operations
                .mul
                .init(
                    session_id,
                    x_chunk.to_vec(),
                    y_chunk.to_vec(),
                    beaver_triples,
                    network.clone(),
                )
                .await?;

            session_ids.push(session_id);
        }

        // Collect each session's result as it completes (all sessions' rounds overlap here).
        // Every session is cleared regardless of outcome — a timed-out session must not be
        // left dangling in the store just because an earlier `?` would have skipped over it.
        let mut first_err = None;
        for session_id in &session_ids {
            match self
                .operations
                .mul
                .wait_for_result(*session_id, self.params.timeout)
                .await
            {
                Ok(mut chunk_result) => result.append(&mut chunk_result),
                Err(e) if first_err.is_none() => first_err = Some(HoneyBadgerError::from(e)),
                Err(_) => {}
            }
        }

        for session_id in &session_ids {
            if !self.operations.mul.clear_store(*session_id).await {
                warn!(
                    ?session_id,
                    "failed to clear completed multiplication protocol state"
                );
            }
        }

        if let Some(e) = first_err {
            return Err(e);
        }

        Ok(result)
    }

    async fn rand(&mut self, network: Arc<N>) -> Result<RobustShare<F>, Self::Error> {
        let no_rand = {
            let store = self.preprocessing_material.lock().await;
            store.length().random_shr
        };
        if no_rand == 0 {
            //Run preprocessing
            let mut rng = StdRng::from_rng(OsRng).unwrap();
            self.run_preprocessing(network.clone(), &mut rng).await?;
        }
        // Extract the preprocessing triple.
        let rand_value = self
            .preprocessing_material
            .lock()
            .await
            .take_random_shares(1)?;
        Ok(rand_value[0].clone())
    }

    async fn process(
        &mut self,
        sender_id: PartyId,
        raw_msg: Vec<u8>,
        net: Arc<N>,
    ) -> Result<(), Self::Error> {
        let wrapped: WrappedMessage = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_limit(MAX_MESSAGE_SIZE)
            .deserialize(&raw_msg)?;

        #[cfg(feature = "statistics")]
        {
            self.statistics_counters
                .bytes_received
                .fetch_add(raw_msg.len() as u64, std::sync::atomic::Ordering::Relaxed);
            statistics::record_received(&wrapped, &self.statistics_counters.received);
        }

        let is_client_input_broadcast = match &wrapped {
            WrappedMessage::Rbc(m) => {
                m.msg_type.is_dealer_message()
                    && m.session_id.calling_protocol() == Some(ProtocolType::Input)
                    && m.session_id.exec_id() == 0
                    && m.session_id.round_id() == 0
            }
            _ => false,
        };
        if !is_client_input_broadcast && sender_id >= self.params.n_parties {
            warn!(
                "Rejecting message from sender {}: not a member of the {}-party node set",
                sender_id, self.params.n_parties
            );
            return Err(HoneyBadgerError::UnauthorizedSender(
                sender_id,
                self.params.n_parties,
            ));
        }
        // A client input broadcast must actually come from client id space: a consensus
        // node's own id must never be treated as an authenticated client, even transiently.
        if is_client_input_broadcast && sender_id < self.params.n_parties {
            warn!(
                "Rejecting client input broadcast: sender {} is a consensus node id, not a client id",
                sender_id
            );
            return Err(HoneyBadgerError::UnauthorizedSender(
                sender_id,
                self.params.n_parties,
            ));
        }

        match wrapped {
            WrappedMessage::Rbc(rbc_msg) => {
                if sender_id != rbc_msg.sender_id {
                    return Err(HoneyBadgerError::InvalidPartyId);
                }
                if rbc_msg.session_id.instance_id() != self.params.instance_id {
                    return Err(HoneyBadgerError::InstanceIdError(
                        rbc_msg.session_id.instance_id(),
                    ));
                }
                if rbc_msg.msg_type.is_dealer_message() {
                    let expected_dealer = rbc_msg.session_id.sub_id() as usize;
                    if rbc_msg.sender_id != expected_dealer {
                        warn!(
                            "Rejecting dealer message: sender {} is not expected dealer {} for session {:?}",
                            rbc_msg.sender_id, expected_dealer, rbc_msg.session_id
                        );
                        return Err(HoneyBadgerError::InvalidPartyId);
                    }
                }

                match rbc_msg.session_id.calling_protocol() {
                    Some(ProtocolType::Randousha) => {
                        self.preprocess
                            .ran_dou_sha
                            .rbc
                            .process(rbc_msg, net)
                            .await?;
                        self.preprocess.ran_dou_sha.drain_rbc_output().await?;
                    }
                    Some(ProtocolType::Ransha) => {
                        self.preprocess.share_gen.rbc.process(rbc_msg, net).await?;
                        self.preprocess.share_gen.drain_rbc_output().await?;
                    }
                    Some(ProtocolType::Input) => {
                        self.preprocess.input.rbc.process(rbc_msg, net).await?;
                        self.preprocess.input.drain_rbc_output().await?;
                    }
                    Some(ProtocolType::ZeroSha) => {
                        self.preprocess.zero_sha.rbc.process(rbc_msg, net).await?;
                        self.preprocess.zero_sha.drain_rbc_output().await?;
                    }
                    Some(ProtocolType::PRandInt) => {
                        self.preprocess
                            .prand_int
                            .rbc
                            .process(rbc_msg, net.clone())
                            .await?;
                        self.preprocess.prand_int.drain_rbc_output(net).await?;
                    }
                    Some(ProtocolType::GfRansha) => {
                        self.gf_preprocess
                            .gf_share_gen
                            .rbc
                            .process(rbc_msg, net)
                            .await?;
                        self.gf_preprocess.gf_share_gen.drain_rbc_output().await?;
                    }
                    Some(ProtocolType::GfRandousha) => {
                        self.gf_preprocess
                            .gf_ran_dou_sha
                            .rbc
                            .process(rbc_msg, net)
                            .await?;
                        self.gf_preprocess.gf_ran_dou_sha.drain_rbc_output().await?;
                    }
                    _ => {
                        warn!(
                            "Unknown protocol ID in session ID: {:?} in RBC",
                            rbc_msg.session_id
                        );
                    }
                }
            }

            WrappedMessage::RanSha(rs_msg) => {
                if sender_id != rs_msg.sender_id {
                    return Err(HoneyBadgerError::InvalidPartyId);
                }
                if rs_msg.session_id.instance_id() != self.params.instance_id {
                    return Err(HoneyBadgerError::InstanceIdError(
                        rs_msg.session_id.instance_id(),
                    ));
                }
                self.preprocess.share_gen.process(rs_msg, net).await?;
            }
            WrappedMessage::Dousha(ds_msg) => {
                if sender_id != ds_msg.sender_id {
                    return Err(HoneyBadgerError::InvalidPartyId);
                }
                if ds_msg.session_id.instance_id() != self.params.instance_id {
                    return Err(HoneyBadgerError::InstanceIdError(
                        ds_msg.session_id.instance_id(),
                    ));
                }
                self.preprocess.dou_sha.process(ds_msg).await?;
            }
            WrappedMessage::RanDouSha(rds_msg) => {
                if sender_id != rds_msg.sender_id {
                    return Err(HoneyBadgerError::InvalidPartyId);
                }
                if rds_msg.session_id.instance_id() != self.params.instance_id {
                    return Err(HoneyBadgerError::InstanceIdError(
                        rds_msg.session_id.instance_id(),
                    ));
                }
                self.preprocess.ran_dou_sha.process(rds_msg, net).await?;
            }
            WrappedMessage::BatchRecon(batch_msg) => {
                if sender_id != batch_msg.sender_id {
                    return Err(HoneyBadgerError::InvalidPartyId);
                }
                if batch_msg.session_id.instance_id() != self.params.instance_id {
                    return Err(HoneyBadgerError::InstanceIdError(
                        batch_msg.session_id.instance_id(),
                    ));
                }
                match batch_msg.session_id.calling_protocol() {
                    Some(ProtocolType::Mul) => {
                        self.operations
                            .mul
                            .batch_recon
                            .process(batch_msg, net)
                            .await?;
                        self.operations.mul.drain_batch_recon_output().await?
                    }
                    Some(ProtocolType::Triple) => {
                        self.preprocess
                            .triple_gen
                            .batch_recon_node
                            .process(batch_msg, net)
                            .await?;
                        self.preprocess
                            .triple_gen
                            .drain_batch_recon_output()
                            .await?
                    }
                    Some(ProtocolType::RandBit) => {
                        self.preprocess
                            .rand_bit
                            .mul_pub
                            .batch_recon
                            .process(batch_msg, net)
                            .await?;
                        self.preprocess
                            .rand_bit
                            .mul_pub
                            .drain_batch_recon_output()
                            .await?;
                    }
                    // DN07 preprocessing multiplication / exact-zero check. Its child opens at
                    // degree `2t`, which is legal here only because `Dn07` is a preprocessing tag
                    // — `dn07::phase_of` is the exhaustive classification that says so.
                    Some(ProtocolType::Dn07) => {
                        self.preprocess
                            .dn07
                            .batch_recon
                            .process(batch_msg, net)
                            .await?;
                        self.preprocess.dn07.drain_batch_recon_output().await?;
                    }
                    Some(ProtocolType::FpMul) => {
                        self.type_ops
                            .fpmul
                            .mult_node
                            .batch_recon
                            .process(batch_msg, net)
                            .await?;
                        self.type_ops
                            .fpmul
                            .mult_node
                            .drain_batch_recon_output()
                            .await?;
                    }
                    // The daBit's single Mod2 opening. Degree `t`, robust, no abort — see
                    // `honeybadger::mod2`. `ProtocolType::DaBitMul` is retired with the dealt
                    // daBit protocol and is deliberately not routed anywhere.
                    Some(ProtocolType::DaBitOpen) => {
                        self.conv
                            .dabit_gen
                            .mod2
                            .open
                            .process(batch_msg, net)
                            .await?;
                        self.conv.dabit_gen.drain_open_output().await?;
                    }
                    Some(ProtocolType::A2B) => {
                        self.conv.a2b.open.process(batch_msg, net).await?;
                        self.conv.a2b.drain_open_output().await?;
                    }
                    _ => {
                        warn!(
                            "Unknown protocol ID in session ID: {:?} at Batch reconstruction",
                            batch_msg.session_id
                        );
                    }
                }
            }
            WrappedMessage::PRandInt(prand_message) => {
                if sender_id != prand_message.sender_id {
                    return Err(HoneyBadgerError::InvalidPartyId);
                }
                if prand_message.session_id.instance_id() != self.params.instance_id {
                    return Err(HoneyBadgerError::InstanceIdError(
                        prand_message.session_id.instance_id(),
                    ));
                }
                self.preprocess.prand_int.process(prand_message).await?;
            }
            WrappedMessage::Mult(mult_msg) => {
                if sender_id != mult_msg.sender {
                    return Err(HoneyBadgerError::InvalidPartyId);
                }
                if mult_msg.session_id.instance_id() != self.params.instance_id {
                    return Err(HoneyBadgerError::InstanceIdError(
                        mult_msg.session_id.instance_id(),
                    ));
                }
                match mult_msg.session_id.calling_protocol() {
                    Some(ProtocolType::Mul) => {
                        self.operations
                            .mul
                            .process(mult_msg.sender, mult_msg.session_id, mult_msg.payload)
                            .await?;
                    }
                    Some(ProtocolType::FpMul) => {
                        self.type_ops
                            .fpmul
                            .mult_node
                            .process(mult_msg.sender, mult_msg.session_id, mult_msg.payload)
                            .await?;
                    }
                    _ => {
                        warn!(
                            "Unknown protocol ID in session ID: {:?} for direct Mult open",
                            mult_msg.session_id
                        );
                    }
                }
            }
            WrappedMessage::Trunc(trunc_msg) => {
                if sender_id != trunc_msg.sender_id {
                    return Err(HoneyBadgerError::InvalidPartyId);
                }
                if trunc_msg.session_id.instance_id() != self.params.instance_id {
                    return Err(HoneyBadgerError::InstanceIdError(
                        trunc_msg.session_id.instance_id(),
                    ));
                }
                match trunc_msg.session_id.calling_protocol() {
                    Some(ProtocolType::FpMul) => {
                        self.type_ops.fpmul.trunc_node.process(trunc_msg).await?;
                    }
                    Some(ProtocolType::FpDivConst) => {
                        self.type_ops
                            .fpdiv_const
                            .trunc_node
                            .process(trunc_msg)
                            .await?;
                    }
                    _ => {
                        warn!(
                            "Unknown protocol ID in session ID: {:?} for direct Trunc open",
                            trunc_msg.session_id
                        );
                    }
                }
            }
            WrappedMessage::ZeroSha(zs_msg) => {
                if sender_id != zs_msg.sender_id {
                    return Err(HoneyBadgerError::InvalidPartyId);
                }
                if zs_msg.session_id.instance_id() != self.params.instance_id {
                    return Err(HoneyBadgerError::InstanceIdError(
                        zs_msg.session_id.instance_id(),
                    ));
                }
                self.preprocess.zero_sha.process(zs_msg, net).await?;
            }
            WrappedMessage::Input(_) => warn!("Incorrect message recieved at process function"),
            WrappedMessage::Output(_) => warn!("Incorrect message recieved at process function"),
            WrappedMessage::GfRansha(rs_msg) => {
                if sender_id != rs_msg.sender_id {
                    return Err(HoneyBadgerError::InvalidPartyId);
                }
                if rs_msg.session_id.instance_id() != self.params.instance_id {
                    return Err(HoneyBadgerError::InstanceIdError(
                        rs_msg.session_id.instance_id(),
                    ));
                }
                self.gf_preprocess.gf_share_gen.process(rs_msg, net).await?;
            }
            WrappedMessage::GfDousha(ds_msg) => {
                if sender_id != ds_msg.sender_id {
                    return Err(HoneyBadgerError::InvalidPartyId);
                }
                if ds_msg.session_id.instance_id() != self.params.instance_id {
                    return Err(HoneyBadgerError::InstanceIdError(
                        ds_msg.session_id.instance_id(),
                    ));
                }
                self.gf_preprocess.gf_dou_sha.process(ds_msg).await?;
            }
            WrappedMessage::GfRanDouSha(rds_msg) => {
                if sender_id != rds_msg.sender_id {
                    return Err(HoneyBadgerError::InvalidPartyId);
                }
                if rds_msg.session_id.instance_id() != self.params.instance_id {
                    return Err(HoneyBadgerError::InstanceIdError(
                        rds_msg.session_id.instance_id(),
                    ));
                }
                self.gf_preprocess
                    .gf_ran_dou_sha
                    .process(rds_msg, net)
                    .await?;
            }
            WrappedMessage::GfBatchRecon(batch_msg) => {
                if sender_id != batch_msg.sender_id {
                    return Err(HoneyBadgerError::InvalidPartyId);
                }
                if batch_msg.session_id.instance_id() != self.params.instance_id {
                    return Err(HoneyBadgerError::InstanceIdError(
                        batch_msg.session_id.instance_id(),
                    ));
                }
                match batch_msg.session_id.calling_protocol() {
                    Some(ProtocolType::GfMul) => {
                        self.gf_operations
                            .mul
                            .batch_recon
                            .process(batch_msg, net)
                            .await?;
                        self.gf_operations.mul.drain_batch_recon_output().await?
                    }
                    Some(ProtocolType::GfTriple) => {
                        self.gf_preprocess
                            .gf_triple_gen
                            .batch_recon_node
                            .process(batch_msg, net)
                            .await?;
                        self.gf_preprocess
                            .gf_triple_gen
                            .drain_batch_recon_output()
                            .await?
                    }
                    Some(ProtocolType::GfDn07) => {
                        self.gf_preprocess
                            .gf_dn07
                            .batch_recon
                            .process(batch_msg, net)
                            .await?;
                        self.gf_preprocess
                            .gf_dn07
                            .drain_batch_recon_output()
                            .await?;
                    }
                    // The edaBit modulus-overflow filter's AND layers and its degree-`t` verdict
                    // opening. Both tags kept their discriminants when the dealt daBit protocol
                    // that first owned them was deleted.
                    // The edaBit filter's AND layers, as DN07 degree reductions. This child
                    // opens at degree `2t`, which is legal because `DaBitGfMul` is a
                    // **preprocessing** tag — `dn07::phase_of` is the exhaustive classification
                    // that says so, and `PreprocessingSessionId::new` is what enforces it at the
                    // one place a session reaches `init_mul`.
                    Some(ProtocolType::DaBitGfMul) => {
                        self.conv
                            .edabit
                            .gf_dn07
                            .batch_recon
                            .process(batch_msg, net)
                            .await?;
                        self.conv.edabit.drain_gf_dn07_output().await?;
                    }
                    Some(ProtocolType::DaBitGfOpen) => {
                        self.conv.edabit.gf_open.process(batch_msg, net).await?;
                        self.conv.edabit.drain_gf_open_output().await?;
                    }
                    Some(ProtocolType::A2BGfMul) => {
                        self.conv
                            .a2b
                            .gf_mul
                            .batch_recon
                            .process(batch_msg, net)
                            .await?;
                        self.conv.a2b.drain_gf_mul_output().await?;
                    }
                    Some(ProtocolType::B2A) => {
                        self.conv.b2a.gf_open.process(batch_msg, net).await?;
                        self.conv.b2a.drain_gf_open_output().await?;
                    }
                    _ => {
                        warn!(
                            "Unknown protocol ID in session ID: {:?} at GF(2^k) Batch reconstruction",
                            batch_msg.session_id
                        );
                    }
                }
            }
            WrappedMessage::GfMult(mult_msg) => {
                if sender_id != mult_msg.sender {
                    return Err(HoneyBadgerError::InvalidPartyId);
                }
                if mult_msg.session_id.instance_id() != self.params.instance_id {
                    return Err(HoneyBadgerError::InstanceIdError(
                        mult_msg.session_id.instance_id(),
                    ));
                }
                match mult_msg.session_id.calling_protocol() {
                    Some(ProtocolType::GfMul) => {
                        self.gf_operations
                            .mul
                            .process(mult_msg.sender, mult_msg.session_id, mult_msg.payload)
                            .await?;
                    }
                    // No `DaBitGfMul` arm: the edaBit filter's AND layers are DN07 degree
                    // reductions, which put nothing but a batch reconstruction on the wire. A
                    // `GfMult` bearing that tag is a peer running the retired Beaver filter, and
                    // falls through to the warning below rather than being routed anywhere.
                    Some(ProtocolType::A2BGfMul) => {
                        self.conv
                            .a2b
                            .gf_mul
                            .process(mult_msg.sender, mult_msg.session_id, mult_msg.payload)
                            .await?;
                    }
                    _ => {
                        warn!(
                            "Unknown protocol ID in session ID: {:?} for direct GF(2^k) Mult open",
                            mult_msg.session_id
                        );
                    }
                }
            }
            // UNREACHABLE by design. This variant belonged to the dealt daBit protocol, which
            // PRSS daBits replaced; nothing sends one any more. The variant itself stays because
            // `WrappedMessage` is an unversioned `bincode` enum whose variant *order* is the wire
            // format — deleting it would silently renumber every variant after it, i.e. re-label
            // A2B traffic as B2A traffic on an upgraded peer. Receiving one is therefore a peer
            // sending retired traffic: it is dropped with a warning, never routed.
            WrappedMessage::DaBit(dabit_msg) => {
                warn!(
                    ?sender_id,
                    session_id = ?dabit_msg.session_id,
                    "dropping a message for the retired dealt daBit protocol"
                );
            }
        }

        Ok(())
    }
}

#[async_trait]
impl<F, N, R> MPCTypeOps<F, RobustShare<F>, N> for HoneyBadgerMPCNode<F, R>
where
    F: PrimeField,
    N: Network + Send + Sync + 'static,
    R: RBC<Id = SessionId>,
{
    type Error = HoneyBadgerError;
    type Sfix = SecretFixedPoint<F, RobustShare<F>>;
    type Sint = SecretInt<F, RobustShare<F>>;
    type Cfix = ClearFixedPoint<F>;
    type Cint = ClearInt<F>;

    /// Fixed-point addition: x + y
    async fn add_fixed(
        &self,
        x: Vec<Self::Sfix>,
        y: Vec<Self::Sfix>,
    ) -> Result<Vec<Self::Sfix>, Self::Error> {
        if x.len() != y.len() {
            return Err(HoneyBadgerError::FPError(FPError::IncompatiblePrecision));
        }
        Ok(x.into_iter()
            .zip(y)
            .map(|(a, b)| a + b)
            .collect::<Result<Vec<_>, _>>()?)
    }

    /// Fixed-point subtraction: x - y
    async fn sub_fixed(
        &self,
        x: Vec<Self::Sfix>,
        y: Vec<Self::Sfix>,
    ) -> Result<Vec<Self::Sfix>, Self::Error> {
        if x.len() != y.len() {
            return Err(HoneyBadgerError::FPError(FPError::IncompatiblePrecision));
        }

        Ok(x.into_iter()
            .zip(y)
            .map(|(a, b)| a - b)
            .collect::<Result<Vec<_>, _>>()?)
    }

    /// Fixed-point multiplication with truncation for fixed precision
    async fn mul_fixed(
        &mut self,
        x: SecretFixedPoint<F, RobustShare<F>>,
        y: SecretFixedPoint<F, RobustShare<F>>,
        net: Arc<N>,
    ) -> Result<SecretFixedPoint<F, RobustShare<F>>, Self::Error> {
        if x.precision() != y.precision() {
            return Err(HoneyBadgerError::FPError(FPError::IncompatiblePrecision));
        }
        self.check_mask_security(HoneyBadgerMPCNodeOpts::max_masked_width(*x.precision()))?;

        let (no_rand_bit, no_rand_int) = {
            let store = self.preprocessing_material.lock().await;
            (store.length().randbit, store.length().prandint)
        };
        if no_rand_bit < x.precision().f() || no_rand_int == 0 {
            //Run preprocessing
            let mut rng = StdRng::from_rng(OsRng).unwrap();
            self.run_preprocessing(net.clone(), &mut rng).await?;
        }
        // Extract the preprocessing triple.
        let beaver_triples = self
            .preprocessing_material
            .lock()
            .await
            .take_beaver_triples(1)?;
        let r_bits = self
            .preprocessing_material
            .lock()
            .await
            .take_randbit_shares(x.precision().f())?;
        let r_int = self
            .preprocessing_material
            .lock()
            .await
            .take_prandint_shares(1)?;

        let session_id = SessionId::new(
            ProtocolType::FpMul,
            SessionId::pack_slot(self.counters.fpmul_counter.get_next().await?, 0, 0),
            self.params.instance_id,
        );

        // Call the fpmul function
        self.type_ops
            .fpmul
            .init(
                x,
                y,
                beaver_triples[0].clone(),
                r_bits,
                r_int[0].clone(),
                self.params.timeout,
                session_id,
                net,
            )
            .await
            .map_err(HoneyBadgerError::from)
    }

    async fn div_with_const_fixed(
        &mut self,
        x: SecretFixedPoint<F, RobustShare<F>>,
        y: ClearFixedPoint<F>,
        net: Arc<N>,
    ) -> Result<SecretFixedPoint<F, RobustShare<F>>, Self::Error> {
        // 1. Precision check ---------------------------------------------
        if x.precision() != y.precision() {
            return Err(HoneyBadgerError::FPDivConstError(
                FPDivConstError::IncompatiblePrecision,
            ));
        }

        // `fpdiv_const` multiplies the secret by a public f-scaled reciprocal and feeds the
        // resulting 2k-bit value into TruncPr, so it needs the same mask margin as `mul_fixed`.
        self.check_mask_security(HoneyBadgerMPCNodeOpts::max_masked_width(*x.precision()))?;

        // 2. Check preprocessing inventory --------------------------------
        let (no_rand_bit, no_rand_int) = {
            let store = self.preprocessing_material.lock().await;
            (store.length().randbit, store.length().prandint)
        };

        // Need f random bits and 1 random integer for truncation
        if no_rand_bit < x.precision().f() || no_rand_int == 0 {
            // Run full preprocessing if insufficient
            let mut rng = StdRng::from_rng(OsRng).unwrap();
            self.run_preprocessing(net.clone(), &mut rng).await?;
        }

        // 3. Pull preprocessing randomness --------------------------------
        let r_bits = self
            .preprocessing_material
            .lock()
            .await
            .take_randbit_shares(x.precision().f())?;

        let r_int = self
            .preprocessing_material
            .lock()
            .await
            .take_prandint_shares(1)?;

        // 4. Prepare SessionId --------------------------------------------
        let session_id = SessionId::new(
            ProtocolType::FpDivConst,
            SessionId::pack_slot(self.counters.fpdiv_const_counter.get_next().await?, 0, 0),
            self.params.instance_id,
        );

        // 5. Call the division node ---------------------------------------
        self.type_ops
            .fpdiv_const
            .init(
                x,
                y,
                r_bits,
                r_int[0].clone(),
                self.params.timeout,
                session_id,
                net.clone(),
            )
            .await
            .map_err(HoneyBadgerError::from)
    }

    /// Integer addition (int8/16/32/64)
    async fn add_int(
        &self,
        x: Vec<Self::Sint>,
        y: Vec<Self::Sint>,
    ) -> Result<Vec<Self::Sint>, Self::Error> {
        if x.len() != y.len() {
            return Err(HoneyBadgerError::FPError(FPError::IncompatiblePrecision));
        }

        let mut out = Vec::with_capacity(x.len());
        for (a, b) in x.into_iter().zip(y.into_iter()) {
            // Local addition of shares
            let sum = (a + b)?;
            out.push(sum);
        }
        Ok(out)
    }

    /// Integer addition (int8/16/32/64)
    async fn sub_int(
        &self,
        x: Vec<Self::Sint>,
        y: Vec<Self::Sint>,
    ) -> Result<Vec<Self::Sint>, Self::Error> {
        if x.len() != y.len() {
            return Err(HoneyBadgerError::FPError(FPError::IncompatiblePrecision));
        }
        let mut out = Vec::with_capacity(x.len());
        for (a, b) in x.into_iter().zip(y.into_iter()) {
            // Local addition of shares
            let sum = (a - b)?;
            out.push(sum);
        }
        Ok(out)
    }

    /// Integer multiplication (int8/16/32/64)
    async fn mul_int(
        &mut self,
        x: Vec<Self::Sint>,
        y: Vec<Self::Sint>,
        net: Arc<N>,
    ) -> Result<Vec<Self::Sint>, Self::Error> {
        if x.len() != y.len() {
            return Err(HoneyBadgerError::FPError(FPError::IncompatiblePrecision));
        }

        let bitlen_x = x
            .first()
            .map(|v| v.bit_length())
            .ok_or(HoneyBadgerError::FPError(FPError::IncompatiblePrecision))?;

        let x_ok = x.iter().all(|v| v.bit_length() == bitlen_x);
        if !x_ok {
            return Err(HoneyBadgerError::FPError(FPError::IncompatiblePrecision));
        }

        let bitlen_y = y
            .first()
            .map(|v| v.bit_length())
            .ok_or(HoneyBadgerError::FPError(FPError::IncompatiblePrecision))?;

        let y_ok = y.iter().all(|v| v.bit_length() == bitlen_y);
        if !y_ok {
            return Err(HoneyBadgerError::FPError(FPError::IncompatiblePrecision));
        }

        if bitlen_x != bitlen_y {
            return Err(HoneyBadgerError::FPError(FPError::IncompatiblePrecision));
        }

        let bitlen = bitlen_x;

        let a: Vec<ShamirShare<F, 1, Robust>> = x.iter().map(|s| s.share().clone()).collect();
        let b: Vec<ShamirShare<F, 1, Robust>> = y.iter().map(|s| s.share().clone()).collect();

        // Perform secure Beaver multiplication
        let result = self.mul(a, b, net).await?;
        let output = result
            .into_iter()
            .map(|share| SecretInt::new(share, bitlen))
            .collect();
        Ok(output)
    }
}

#[async_trait]
impl<F, R, N> PreprocessingMPCProtocol<F, RobustShare<F>, N> for HoneyBadgerMPCNode<F, R>
where
    N: Network + Send + Sync + 'static,
    F: PrimeField,
    R: RBC<Id = SessionId>,
{
    /// Runs preprocessing to produce Random shares and Beaver triples.
    /// Steps:
    /// 1. Ensure enough random shares are available (per `n_random_shares`).
    /// 2. Generate double shares if missing.
    /// 3. Generate RanDouSha pairs if missing.
    /// 4. Generate Beaver triples from all the above (per `n_triples`).
    /// 5. Generate RandBit shares, drawing directly from the triple/random-share pool filled by
    ///    steps 1-4 (one of each per RandBit output) -- `n_triples`/`n_random_shares` must be
    ///    sized to cover this demand too, or this step errors with `NotEnoughPreprocessing`.
    /// 6. Generate PRandInt shares via the RISS protocol (self-contained; doesn't draw from the
    ///    triple/random-share pool).
    async fn run_preprocessing<G>(
        &mut self,
        network: Arc<N>,
        rng: &mut G,
    ) -> Result<(), Self::Error>
    where
        N: 'async_trait,
        G: Rng + Send,
    {
        // ------------------------
        // Step 0. Establish PRSS keys (once)
        // ------------------------
        // Idempotent, and safe to run here rather than as a separate call by the application:
        // every party reaches `run_preprocessing` together, so the setup's RISS session runs in
        // lockstep — and RISS is loud if it does not.
        if !self.preprocess.prand_int.has_prss_keys() {
            let phase_start = Instant::now();
            self.setup_prss_keys(network.clone()).await?;
            trace_preprocessing_phase(self.id, "prss_setup", 1, phase_start);
        }

        // Get how many triples and random shares are already available
        let (no_of_triples_avail, no_of_random_shares_avail) = {
            let store = self.preprocessing_material.lock().await;
            (store.length().beaver_triples, store.length().random_shr)
        };

        // Desired total counts from protocol parameters
        let mut no_of_triples = self.params.n_triples;
        let mut no_of_random_shares = self.params.n_random_shares;
        // Each triple batch produces (2t + 1) triples at a time
        let group_size = 2 * self.params.threshold + 1;
        let total_triples_to_generate = if no_of_triples_avail >= no_of_triples {
            no_of_triples = 0;
            0
        } else {
            ((no_of_triples - no_of_triples_avail + group_size - 1) / group_size) * group_size
        };

        let total_random_shares_to_generate = if total_triples_to_generate > 0 {
            // Always add 2× per triple group
            let baseline = if no_of_random_shares_avail < no_of_random_shares {
                no_of_random_shares - no_of_random_shares_avail
            } else {
                no_of_random_shares = 0;
                0
            };
            baseline + 2 * total_triples_to_generate
        } else if no_of_random_shares_avail < no_of_random_shares {
            no_of_random_shares - no_of_random_shares_avail
        } else {
            no_of_random_shares = 0;
            0
        };

        // On the DN07 triple path a triple's `[a]` and `[b]` come from PRSS, so the
        // `2 x per triple` term of the figure above buys nothing and is not dealt. The loose
        // pool's *own* target is untouched, which is why the residual pool after preprocessing is
        // the same size on both paths and the accounting assertions in the node tests do not move.
        let random_shares_to_generate = if self.f_triples_use_dn07() {
            total_random_shares_to_generate.saturating_sub(2 * total_triples_to_generate)
        } else {
            total_random_shares_to_generate
        };

        if no_of_triples == 0 && no_of_random_shares == 0 {
            info!("There are enough Random shares and Beaver triples");
            // return Ok(());
        } else {
            // ------------------------
            // Step 1. Ensure random shares
            // ------------------------
            let phase_start = Instant::now();
            self.ensure_random_shares(network.clone(), rng, random_shares_to_generate)
                .await?;
            trace_preprocessing_phase(
                self.id,
                "random_shares",
                random_shares_to_generate,
                phase_start,
            );
            info!("Random share generation done");

            // ------------------------
            // Steps 2 and 3. Beaver triples
            // ------------------------
            //
            // Two paths to the same object. `TripleGenNode` over dealt `RanSha` + `RanDouSha` is
            // the original and is what a deployment that never establishes PRSS keys takes;
            // `Dn07MulNode` over PRSS material is the same algebra — `TripleGenNode::init` already
            // computes `[a][b] - [r]_2t`, opens it at degree `2t` and adds `[r]_t` — with `a`, `b`
            // and `r` derived instead of dealt, which removes everything from a triple's bill
            // except that one opening.
            if self.f_triples_use_dn07() {
                let phase_start = Instant::now();
                self.generate_triples_via_dn07(total_triples_to_generate, network.clone())
                    .await?;
                trace_preprocessing_phase(
                    self.id,
                    "triples_dn07",
                    total_triples_to_generate,
                    phase_start,
                );
                info!("Beaver triple generation done (DN07 degree reduction over PRSS material)");
                Ok::<(), HoneyBadgerError>(())
            } else {
                let mut triple_counter = self.counters.triple_counter.get_next().await?;

                // ------------------------
                // Step 2. Ensure RanDouSha pair
                // ------------------------
                let phase_start = Instant::now();
                let ran_dou_sha_pair = self
                    .ensure_ran_dou_sha_pair(network.clone(), rng, total_triples_to_generate)
                    .await?;
                trace_preprocessing_phase(
                    self.id,
                    "randousha",
                    total_triples_to_generate,
                    phase_start,
                );
                info!("Randousha pair generation done");

                // ------------------------
                // Step 3. Generate triples
                // ------------------------

                // Take random shares for triples
                let random_shares_a = self
                    .preprocessing_material
                    .lock()
                    .await
                    .take_random_shares(total_triples_to_generate)?;
                let random_shares_b = self
                    .preprocessing_material
                    .lock()
                    .await
                    .take_random_shares(total_triples_to_generate)?;

                let mut round_id = 0u8;
                let mut group_index = 0;
                let total_groups = total_triples_to_generate / group_size;
                let phase_start = Instant::now();
                let max_batch_groups = triple_batch_groups_limit();

                // Build the full (session id, slice range) list up front. TripleGen sessions are
                // independent — distinct session ids, disjoint input slices (taken once above), and
                // disjoint Beaver randomness — so issuing every session's init before awaiting any result
                // lets their 2-round reconstructions overlap instead of running strictly back-to-back.
                // This mirrors the already-shipped mul pipelining (mod.rs `mul`) and is threat-model
                // neutral: it is purely a scheduling change (when results are awaited). Per-session
                // t-fault tolerance, the deterministic session-id sequence, and the protocol logic are
                // all unchanged.
                let mut sessions: Vec<(SessionId, usize, usize)> = Vec::new();
                while group_index < total_groups {
                    let batch_groups = (total_groups - group_index).min(max_batch_groups);
                    let share_start = group_index * group_size;
                    let share_end = share_start + batch_groups * group_size;
                    let sessionid = SessionId::new(
                        ProtocolType::Triple,
                        SessionId::pack_slot(triple_counter, 0, round_id),
                        self.params.instance_id,
                    );
                    sessions.push((sessionid, share_start, share_end));
                    if round_id == 255 {
                        triple_counter = self.counters.triple_counter.get_next().await?;
                        round_id = 0;
                    } else {
                        round_id += 1;
                    }
                    group_index += batch_groups;
                }

                // Phase 1 — issue every session's init_batch (sequential awaits; every session's round-1
                // messages are now in flight and processed concurrently by the other nodes).
                for (sessionid, share_start, share_end) in &sessions {
                    self.preprocess
                        .triple_gen
                        .init_batch(
                            random_shares_a[*share_start..*share_end].to_vec(),
                            random_shares_b[*share_start..*share_end].to_vec(),
                            ran_dou_sha_pair[*share_start..*share_end].to_vec(),
                            *sessionid,
                            network.clone(),
                        )
                        .await?;
                }

                // Phase 2 — collect each result as it completes (all sessions' rounds overlap here).
                for (sessionid, _, _) in &sessions {
                    let result = self
                        .preprocess
                        .triple_gen
                        .wait_for_result(*sessionid, self.params.timeout)
                        .await;
                    if !self.preprocess.triple_gen.clear_store(*sessionid).await {
                        warn!(
                            sessionid = ?sessionid,
                            "failed to clear triple generation protocol state"
                        );
                    }
                    self.preprocessing_material
                        .lock()
                        .await
                        .add(Some(result?), None, None, None);
                }
                trace_preprocessing_phase(
                    self.id,
                    "triples",
                    total_triples_to_generate,
                    phase_start,
                );
                Ok::<(), HoneyBadgerError>(())
            }?;
        }
        // ------------------------
        // Step 5. Generate zero shares (degree-2t zero-sharings)
        // ------------------------
        //
        // Skipped entirely once `RandBit` takes its re-randomiser from PRZS, because `RandBit`'s
        // dealt path is the **only** consumer of this pool — `generate_randbits` holds the sole
        // `take_zero_shares` call in the crate, and `n_zero_shares` defaults to `n_randbit` for
        // exactly that reason. Running `ZeroSha` here anyway would put a full dealt protocol on
        // the wire and then discard every share it produced, which is the difference between
        // `RandBit` *being* priced at one degree-`2t` opening and merely being *able* to be.
        //
        // A deployment that declined PRSS keys reaches the `else` and is unchanged. If a second
        // consumer of the zero-share pool is ever added, this gate must move to that consumer's
        // demand rather than being deleted: the pool is still perfectly good, it just has nobody
        // to serve here.
        if self.randbit_uses_prss() {
            info!("Zero share generation skipped: RandBit re-randomises from PRZS");
        } else {
            let phase_start = Instant::now();
            self.ensure_zero_shares(network.clone(), rng, self.params.n_zero_shares)
                .await?;
            trace_preprocessing_phase(
                self.id,
                "zero_shares",
                self.params.n_zero_shares,
                phase_start,
            );
            info!("Zero share generation done");
        }

        // ------------------------
        // Step 6. Generate Random bits
        // ------------------------
        let phase_start = Instant::now();
        self.ensure_randbit_shares(network.clone()).await?;
        trace_preprocessing_phase(self.id, "randbit", self.params.n_randbit, phase_start);
        info!("RandBit share generation done");

        // ------------------------
        // Step 7. Generate Random Int
        // ------------------------
        let phase_start = Instant::now();
        self.ensure_prandint_shares().await?;
        trace_preprocessing_phase(self.id, "prandint", self.params.n_prandint, phase_start);
        info!("PrandInt share generation done");

        Ok(())
    }
}
impl<F, R> HoneyBadgerMPCNode<F, R>
where
    F: PrimeField,
    R: RBC<Id = SessionId>,
{
    /// Ensure we have enough random shares by repeatedly running ShareGen if needed.
    async fn ensure_random_shares<G, N>(
        &mut self,
        network: Arc<N>,
        rng: &mut G,
        needed: usize,
    ) -> Result<(), HoneyBadgerError>
    where
        N: Network + Send + Sync + 'static,
        G: Rng + Send,
    {
        // Outputs in batches of (n-2t)
        let output_per_column = self.params.n_parties - 2 * self.params.threshold;
        let columns_needed = (needed + output_per_column - 1) / output_per_column;
        let max_columns_per_run = 2048usize;
        let run = (columns_needed + max_columns_per_run - 1) / max_columns_per_run;
        let mut round_id = 0u8;
        let mut ran_sha_counter = self.counters.ran_sha_counter.get_next().await?;

        // Build the full (session id, batch size) list up front. ShareGen sessions are independent
        // (distinct session ids and fresh per-session randomness), so pipelining their inits before
        // awaiting results lets the 3-round sessions overlap. Threat-model neutral, mirroring the
        // mul pipelining: a pure scheduling change (when results are awaited); per-session t-fault
        // tolerance and the deterministic session-id sequence are unchanged. `rng` still advances
        // sequentially during the init phase, exactly as before.
        let mut sessions: Vec<(SessionId, usize)> = Vec::with_capacity(run);
        for i in 0..run {
            info!("Random share generation run {}", i);
            let columns_remaining = columns_needed - i * max_columns_per_run;
            let batch_size = columns_remaining.min(max_columns_per_run);
            let sessionid = SessionId::new(
                ProtocolType::Ransha,
                SessionId::pack_slot(ran_sha_counter, 0, round_id),
                self.params.instance_id,
            );
            sessions.push((sessionid, batch_size));
            if round_id == 255 {
                ran_sha_counter = self.counters.ran_sha_counter.get_next().await.unwrap();
                round_id = 0;
            } else {
                round_id += 1;
            }
        }

        // Phase 1 — issue every ShareGen init (sequential awaits; rng advances in order).
        for (sessionid, batch_size) in &sessions {
            self.preprocess
                .share_gen
                .init_batch(*sessionid, *batch_size, rng, network.clone())
                .await?;
        }

        // Phase 2 — collect each result as it completes (sessions' rounds overlap here).
        for (sessionid, _) in &sessions {
            // Clear the store whether wait_for_result succeeds or times out — otherwise a
            // session that never completes (e.g. a Byzantine peer withholding shares) leaks
            // its slot in the SessionStore forever, since nothing else ever retires it.
            let result = self
                .preprocess
                .share_gen
                .wait_for_result(*sessionid, self.params.timeout)
                .await;
            if !self.preprocess.share_gen.clear_store(*sessionid).await {
                warn!(
                    sessionid = ?sessionid,
                    "failed to clear share generation protocol state"
                );
            }
            let output = result?;
            self.preprocessing_material
                .lock()
                .await
                .add(None, Some(output), None, None);
        }
        Ok(())
    }

    /// Ensure we have a RanDouSha pair available, generating double shares if needed.
    async fn ensure_ran_dou_sha_pair<G, N>(
        &mut self,
        network: Arc<N>,
        rng: &mut G,
        needed: usize,
    ) -> Result<Vec<DoubleShamirShare<F>>, HoneyBadgerError>
    where
        N: Network + Send + Sync + 'static,
        G: Rng + Send,
    {
        let mut pair = Vec::new();

        // Each batched column produces (t + 1) double shares.
        let output_per_column = self.params.threshold + 1;
        let columns_needed = (needed + output_per_column - 1) / output_per_column;
        let max_columns_per_run = ran_dou_sha_batch_columns_limit();
        let run = (columns_needed + max_columns_per_run - 1) / max_columns_per_run;
        let mut round_id = 0u8;
        let mut ran_dou_sha_counter = self.counters.ran_dou_sha_counter.get_next().await?;

        // Build the (session id, batch size) list up front. Each iteration runs a DoubleShare
        // session (1 round) whose output feeds the RanDouSha session (2 rounds) under the SAME
        // session id but a SEPARATE protocol node (disjoint storage). Across iterations the sessions
        // are independent — distinct session ids, fresh randomness, disjoint output columns — so we
        // pipeline in two phases: run every DoubleShare session with overlapping rounds, then run
        // every RanDouSha session with overlapping rounds. The per-iteration data dependency
        // (DoubleShare(i) -> RanDouSha(i)) is preserved: RanDouSha(i) still consumes exactly
        // DoubleShare(i)'s output, collected in session order. Threat-model neutral, mirroring the
        // mul pipelining: only when results are awaited changes; per-session t-fault tolerance, the
        // deterministic session-id sequence, and protocol logic are unchanged.
        let mut sessions: Vec<(SessionId, usize)> = Vec::with_capacity(run);
        for i in 0..run {
            let columns_remaining = columns_needed - i * max_columns_per_run;
            let batch_size = columns_remaining.min(max_columns_per_run);
            let sessionid = SessionId::new(
                ProtocolType::Randousha,
                SessionId::pack_slot(ran_dou_sha_counter, 0, round_id),
                self.params.instance_id,
            );
            sessions.push((sessionid, batch_size));
            if round_id == 255 {
                ran_dou_sha_counter = self.counters.ran_dou_sha_counter.get_next().await.unwrap();
                round_id = 0;
            } else {
                round_id += 1;
            }
        }

        // Phase 1 — DoubleShare for every session, pipelined (rng advances sequentially, as before).
        // 1a: issue all DoubleShare inits.
        for (sessionid, batch_size) in &sessions {
            self.preprocess
                .dou_sha
                .init_batch(*sessionid, *batch_size, rng, network.clone())
                .await?;
        }
        // 1b: collect every DoubleShare output (rounds overlap here), in session order.
        let mut all_double_shares: Vec<Vec<DoubleShamirShare<F>>> =
            Vec::with_capacity(sessions.len());
        for (sessionid, _) in &sessions {
            // Clear regardless of outcome — a timed-out session must not linger forever.
            let result = self
                .preprocess
                .dou_sha
                .wait_for_result(*sessionid, self.params.timeout)
                .await;
            if !self.preprocess.dou_sha.clear_store(*sessionid).await {
                warn!(
                    sessionid = ?sessionid,
                    "failed to clear double share protocol state"
                );
            }
            all_double_shares.push(result?);
        }

        // Phase 2 — RanDouSha for every session, pipelined, each fed by its own DoubleShare output.
        // 2a: transform inputs and issue all RanDouSha inits.
        let mut rds_sessions: Vec<SessionId> = Vec::with_capacity(sessions.len());
        for ((sessionid, batch_size), double_shares) in
            sessions.iter().zip(all_double_shares.into_iter())
        {
            let mut shares_deg_t_by_batch = Vec::with_capacity(*batch_size);
            let mut shares_deg_2t_by_batch = Vec::with_capacity(*batch_size);
            for double_share_batch in double_shares.chunks_exact(self.params.n_parties) {
                let (shares_deg_t, shares_deg_2t) = double_share_batch
                    .iter()
                    .cloned()
                    .map(|d| (d.degree_t, d.degree_2t))
                    .unzip();
                shares_deg_t_by_batch.push(shares_deg_t);
                shares_deg_2t_by_batch.push(shares_deg_2t);
            }
            self.preprocess
                .ran_dou_sha
                .init_batch(
                    shares_deg_t_by_batch,
                    shares_deg_2t_by_batch,
                    *sessionid,
                    network.clone(),
                )
                .await?;
            rds_sessions.push(*sessionid);
        }
        // 2b: collect every RanDouSha output (rounds overlap here), in session order.
        for sessionid in &rds_sessions {
            // Clear regardless of outcome — a timed-out session must not linger forever.
            let result = self
                .preprocess
                .ran_dou_sha
                .wait_for_result(*sessionid, self.params.timeout)
                .await;
            if !self.preprocess.ran_dou_sha.clear_store(*sessionid).await {
                warn!(
                    sessionid = ?sessionid,
                    "failed to clear RanDouSha protocol state"
                );
            }
            pair.extend(result?);
        }
        Ok(pair)
    }

    /// Ensure the pool holds at least `target` degree-`2t` zero-sharings.
    async fn ensure_zero_shares<G, N>(
        &mut self,
        network: Arc<N>,
        rng: &mut G,
        target: usize,
    ) -> Result<(), HoneyBadgerError>
    where
        G: Rng + Send,
        N: Network + Send + Sync + 'static,
    {
        let no_have = {
            let store = self.preprocessing_material.lock().await;
            store.length().zero_shares
        };
        if no_have >= target {
            return Ok(());
        }
        let missing = target - no_have;
        let out_per_call = self.params.n_parties - 2 * self.params.threshold;
        let batch_size = missing.div_ceil(out_per_call);
        let zsha_session = SessionId::new(
            ProtocolType::ZeroSha,
            SessionId::pack_slot(self.counters.zero_sha_counter.get_next().await?, 0, 0),
            self.params.instance_id,
        );
        self.preprocess
            .zero_sha
            .init_batch(zsha_session, batch_size, rng, network.clone())
            .await?;
        let result = self
            .preprocess
            .zero_sha
            .wait_for_result(zsha_session, self.params.timeout)
            .await;
        if !self.preprocess.zero_sha.clear_store(zsha_session).await {
            warn!(?zsha_session, "failed to clear ZeroSha protocol state");
        }
        let shares = result?;
        self.preprocessing_material
            .lock()
            .await
            .add_zero_shares(shares);
        Ok(())
    }

    /// GF(2^k) analogue of `ensure_random_shares`. Simplified to a single session — no multi-run
    /// pipelining across a `max_columns_per_run` cap, since the GF track doesn't need that scale
    /// yet;
    async fn ensure_gf_random_shares<G, N>(
        &mut self,
        network: Arc<N>,
        rng: &mut G,
        needed: usize,
    ) -> Result<(), HoneyBadgerError>
    where
        N: Network + Send + Sync + 'static,
        G: Rng + Send,
    {
        if needed == 0 {
            return Ok(());
        }
        let sessionid = SessionId::new(
            ProtocolType::GfRansha,
            SessionId::pack_slot(self.counters.gf_ran_sha_counter.get_next().await?, 0, 0),
            self.params.instance_id,
        );
        self.gf_preprocess
            .gf_share_gen
            .init_batch(sessionid, needed, rng, network)
            .await?;
        let result = self
            .gf_preprocess
            .gf_share_gen
            .wait_for_result(sessionid, self.params.timeout)
            .await;
        if !self.gf_preprocess.gf_share_gen.clear_store(sessionid).await {
            warn!(
                ?sessionid,
                "failed to clear GF(2^k) share generation protocol state"
            );
        }
        self.gf_preprocessing_material
            .lock()
            .await
            .add(None, Some(result?));
        Ok(())
    }

    /// GF(2^k) analogue of `ensure_ran_dou_sha_pair`. Same simplification as
    /// `ensure_gf_random_shares` — one DoubleShare session and one RanDouSha session, not a
    /// pipelined run.
    async fn ensure_gf_ran_dou_sha_pair<G, N>(
        &mut self,
        network: Arc<N>,
        rng: &mut G,
        needed: usize,
    ) -> Result<
        Vec<crate::honeybadger::gf_double_share::GfDoubleShamirShare<Gf256>>,
        HoneyBadgerError,
    >
    where
        N: Network + Send + Sync + 'static,
        G: Rng + Send,
    {
        if needed == 0 {
            return Ok(Vec::new());
        }
        let output_per_column = self.params.threshold + 1;
        let columns_needed = needed.div_ceil(output_per_column);

        let dou_sha_session = SessionId::new(
            ProtocolType::GfDousha,
            SessionId::pack_slot(self.counters.gf_dou_sha_counter.get_next().await?, 0, 0),
            self.params.instance_id,
        );
        self.gf_preprocess
            .gf_dou_sha
            .init_batch(dou_sha_session, columns_needed, rng, network.clone())
            .await?;
        let double_shares = self
            .gf_preprocess
            .gf_dou_sha
            .wait_for_result(dou_sha_session, self.params.timeout)
            .await;
        if !self
            .gf_preprocess
            .gf_dou_sha
            .clear_store(dou_sha_session)
            .await
        {
            warn!(
                ?dou_sha_session,
                "failed to clear GF(2^k) double share protocol state"
            );
        }
        let double_shares = double_shares?;

        let mut shares_deg_t_by_batch = Vec::with_capacity(columns_needed);
        let mut shares_deg_2t_by_batch = Vec::with_capacity(columns_needed);
        for chunk in double_shares.chunks_exact(self.params.n_parties) {
            let (shares_deg_t, shares_deg_2t) = chunk
                .iter()
                .cloned()
                .map(|d| (d.degree_t, d.degree_2t))
                .unzip();
            shares_deg_t_by_batch.push(shares_deg_t);
            shares_deg_2t_by_batch.push(shares_deg_2t);
        }

        let rds_session = SessionId::new(
            ProtocolType::GfRandousha,
            SessionId::pack_slot(self.counters.gf_ran_dou_sha_counter.get_next().await?, 0, 0),
            self.params.instance_id,
        );
        self.gf_preprocess
            .gf_ran_dou_sha
            .init_batch(
                shares_deg_t_by_batch,
                shares_deg_2t_by_batch,
                rds_session,
                network,
            )
            .await?;
        let result = self
            .gf_preprocess
            .gf_ran_dou_sha
            .wait_for_result(rds_session, self.params.timeout)
            .await;
        if !self
            .gf_preprocess
            .gf_ran_dou_sha
            .clear_store(rds_session)
            .await
        {
            warn!(
                ?rds_session,
                "failed to clear GF(2^k) RanDouSha protocol state"
            );
        }
        Ok(result?)
    }

    /// Generate RandBit shares by running RandBit directly in the node's field `F`.
    ///
    /// RandBit used to route through a Goldilocks small-field RandBit run followed by a
    /// RISS-based field-conversion step (`PRandIntNode::generate_riss`), whose only reason for
    /// existing was to additionally produce a `Gf256` view of the bit -- a view nothing
    /// downstream ever consumed (`mul_fixed`/`div_with_const_fixed` both discarded it). Running
    /// RandBit directly in `F` produces the same `RobustShare<F>` bit shares without that detour,
    /// and shares its random-share pool with the rest of the node instead of requiring a
    /// dedicated small-field preprocessing pipeline.
    async fn ensure_randbit_shares<N>(&mut self, network: Arc<N>) -> Result<(), HoneyBadgerError>
    where
        N: Network + Send + Sync + 'static,
    {
        // How many shares are already present?
        let no_shares = {
            let store = self.preprocessing_material.lock().await;
            store.length().randbit
        };

        if no_shares >= self.params.n_randbit {
            info!("There are enough RandBit shares");
            return Ok(());
        }

        // Computing the amount of needed shares. MulPub pads its last `2t+1`-wide group
        // internally, so the count no longer has to be a multiple of anything.
        let total_to_generate = self.params.n_randbit.saturating_sub(no_shares);
        self.generate_randbits(total_to_generate, network).await
    }

    /// Tops the RandBit pool up to at least `target`, generating the random shares and degree-`2t`
    /// zero sharings the run needs rather than assuming them.
    ///
    /// The `ensure_randbit_shares` sizing discipline — "the configuration accounts for this
    /// demand; an under-sized one surfaces as `NotEnoughPreprocessing`" — is deliberately *not*
    /// what this does, for the same reason `ensure_edabits` tops up its own GF triples: a daBit
    /// batch's RandBit demand is `outputs * (1 + k)`, a figure only the leak budget knows, so a
    /// caller cannot have sized `n_randbit` for it.
    async fn ensure_randbit_shares_at_least<N, G>(
        &mut self,
        target: usize,
        network: Arc<N>,
        rng: &mut G,
    ) -> Result<(), HoneyBadgerError>
    where
        N: Network + Send + Sync + 'static,
        G: Rng + Send,
    {
        let have = {
            let store = self.preprocessing_material.lock().await;
            store.length().randbit
        };
        if have >= target {
            return Ok(());
        }
        let missing = target - have;

        // One random share (RandBit's `a` input) and one degree-`2t` zero sharing per output bit.
        //
        // Both come from PRSS + PRZS once `setup_prss_keys` has run, at zero rounds and zero
        // bytes, so there is nothing to top up and the two interactive pools are not touched at
        // all. That is the whole cost saving: a RandBit's bill drops to its one `MulPub`
        // degree-`2t` opening (`O2`), which is what the plan's `19.286` F elem/daBit at
        // `n = 10, k = 4` is priced on.
        //
        // `19.286` is **payload** — F elements in a message body, no framing. Measured end to
        // end, the whole conversion-preprocessing `BatchRecon` phase for one 64-bit A2B is
        // 4 224 / 8 176 / 11 664 / 16 904 B/party at `n = 4/7/10/13`
        // (`conv_cost_measurement::measured_cost_n*`), of which 768 / 1 344 / 1 872 / 2 448 is the
        // 48-byte envelope. Divided over 64 daBits that is 66 / 128 / 182 / 264 B/daBit on the
        // wire against the payload model's 53 / 105 / 154 / 226. See `honeybadger::dn07` for the
        // units rule: a payload figure is a marginal cost and needs its `2n * 48` beside it.
        //
        // When PRSS keys were never established the dealt `RanSha` + `ZeroSha` path runs exactly
        // as before. The choice is all-or-nothing across parties because PRSS key setup is: RISS
        // either completes for everyone or for no one — the same argument `ensure_gf_triples`
        // relies on, and for the same reason it is safe to branch on a purely local flag here.
        if !self.randbit_uses_prss() {
            let have_random = {
                let store = self.preprocessing_material.lock().await;
                store.length().random_shr
            };
            if have_random < missing {
                self.ensure_random_shares(network.clone(), rng, missing - have_random)
                    .await?;
            }
            self.ensure_zero_shares(network.clone(), rng, missing)
                .await?;
        }

        self.generate_randbits(missing, network).await
    }

    /// Whether `RandBit` draws `[a]` and its re-randomiser from PRSS/PRZS rather than from the
    /// dealt `RanSha`/`ZeroSha` pools.
    ///
    /// Both halves are required: the source derives the shares, the allocator issues the
    /// positions, and deriving without a monotone position is the failure this whole mechanism
    /// exists to prevent. `setup_prss_keys` installs the two together, so a split is unreachable;
    /// requiring both here means a future refactor that separates them falls back to the dealt
    /// path instead of silently reusing position zero.
    fn randbit_uses_prss(&self) -> bool {
        self.preprocess.dn07_doubles.is_some() && self.preprocess.prss_alloc.is_some()
    }

    /// The generation loop shared by [`Self::ensure_randbit_shares`] and
    /// [`Self::ensure_randbit_shares_at_least`].
    ///
    /// Two sources for the same two inputs, chosen by [`Self::randbit_uses_prss`]:
    ///
    /// * **PRSS + PRZS** once `setup_prss_keys` has run. `[a]` is a degree-`t` sharing of a value
    ///   uniform over `F` from the PRSS *uniform* keystream, and the re-randomiser is an
    ///   independent degree-`2t` sharing of zero from PRZS. Zero rounds, zero bytes, and neither
    ///   interactive pool is touched. This is not
    ///   [`PrssDoubleShareSource::double_shares_at`]: that returns one secret at two degrees,
    ///   whereas RandBit needs the PRSS half and the PRZS half taken **apart** — see
    ///   [`PrssDoubleShareSource::randbit_material`].
    /// * **Dealt `RanSha` + `ZeroSha`** otherwise, drawn from the shared pools in pool order,
    ///   unchanged. `ensure_randbit_shares_at_least` tops those pools up first; the
    ///   `ensure_randbit_shares` entry point does not, so an under-sized `n_random_shares` /
    ///   `n_zero_shares` still surfaces as `NotEnoughPreprocessing` here.
    ///
    /// The PRSS positions are issued by [`PrssAllocator::claim`], which advances a monotone
    /// cursor under a lock *before* anything is derived. A chunk that then fails burns its range
    /// rather than rewinding onto it, and there is no value of any type naming an already-issued
    /// position — re-deriving one would hand the adversary the mask for an opening it has already
    /// seen. Every honest party claims in the same order because every party runs this loop over
    /// the same chunk sequence, exactly as they already agree on `rand_bit_counter`.
    ///
    /// Note that RandBit may return **fewer** outputs than inputs: it drops any input whose
    /// square opens to zero, at probability `~1/|F|`. Those positions are burned by the attempt,
    /// which is correct. The pool simply ends up one bit short and the next top-up refills it;
    /// this is pre-existing behaviour and is not changed here.
    async fn generate_randbits<N>(
        &mut self,
        total_to_generate: usize,
        network: Arc<N>,
    ) -> Result<(), HoneyBadgerError>
    where
        N: Network + Send + Sync + 'static,
    {
        // MulPub sends a whole session's groups in one batch-reconstruction message per
        // recipient, so it caps how much a single `init` may open. Ask it rather than
        // recomputing the group arithmetic here.
        let mut max_per_session = self.preprocess.rand_bit.mul_pub.max_batch_size();

        // Cloned out of `self` so the per-chunk claim does not hold a borrow across the
        // `&mut self` calls further down the loop body. Both are cheap handles: the allocator's
        // cursors live behind an `Arc`, so the clone *shares* them rather than forking them,
        // which is what keeps two concurrent clones of this node from claiming one range twice.
        let prss_randbit = match (
            self.preprocess.dn07_doubles.as_ref(),
            self.preprocess.prss_alloc.as_ref(),
        ) {
            (Some(source), Some(alloc)) => Some((source.clone(), alloc.clone())),
            // Matches `randbit_uses_prss`: both halves or neither. A source without an allocator
            // could still derive, at position zero, every single time.
            _ => None,
        };

        if prss_randbit.is_some() {
            // PRZS lays a sharing's `t` coefficients out contiguously and refuses a call needing
            // more than `MAX_PRZS_COEFFS_PER_CALL` of them. Not binding at small `t` — 21845 at
            // `t = 3` against MulPub's 1792 — but at `t >= 37` it would be, and the symptom would
            // be a spurious `BatchTooLarge` from a batch MulPub was perfectly happy with.
            let przs_cap = MAX_PRZS_COEFFS_PER_CALL / self.params.threshold.max(1);
            max_per_session = max_per_session.min(przs_cap).max(1);
        }

        for chunk in chunk_sizes(total_to_generate, max_per_session) {
            let (random_shares_a, zero_shares) = match prss_randbit.as_ref() {
                Some((source, alloc)) => source.randbit_material(alloc, chunk).await?,
                None => {
                    let random_shares_a = self
                        .preprocessing_material
                        .lock()
                        .await
                        .take_random_shares(chunk)?;

                    let zero_shares = self
                        .preprocessing_material
                        .lock()
                        .await
                        .take_zero_shares(chunk)?;
                    (random_shares_a, zero_shares)
                }
            };

            let session_id = SessionId::new(
                ProtocolType::RandBit,
                SessionId::pack_slot(self.counters.rand_bit_counter.get_next().await?, 0, 0),
                self.params.instance_id,
            );

            self.preprocess
                .rand_bit
                .init(
                    random_shares_a,
                    zero_shares,
                    session_id,
                    self.params.timeout,
                    network.clone(),
                )
                .await?;

            let result = self
                .preprocess
                .rand_bit
                .wait_for_result(session_id, self.params.timeout)
                .await;

            if !self.preprocess.rand_bit.clear_store(session_id).await {
                warn!(?session_id, "failed to clear RandBit protocol state");
            }

            self.preprocessing_material
                .lock()
                .await
                .add(None, None, Some(result?), None);
        }

        Ok(())
    }

    /// Tops the PRandInt mask pool up to `n_prandint`, deriving locally from PRSS keys.
    ///
    /// No network: the keys were established once by [`Self::setup_prss_keys`], and every mask
    /// after that is a local PRF evaluation. Positions come from
    /// [`PrssStream::PRandIntMask`](prss::PrssStream::PRandIntMask)'s cursor inside the node's
    /// single [`PrssAllocator`](prss::PrssAllocator) — never from pool depth, which shrinks as
    /// shares are consumed and would eventually rewind the PRF onto a mask an already-completed
    /// `TruncPr` opened under. The cursor advances under a lock inside the claim, before anything
    /// is derived, and there is no path that moves it back; a batch that fails after claiming
    /// burns its range, which is correct rather than a leak. See [`prss::window`].
    ///
    /// The claim order is what every honest party agrees on, not a number on the wire: each party
    /// runs the same top-up sequence, so their cursors track each other. A cursor that drifted
    /// between parties would silently yield shares of different secrets, with no message exchange
    /// left to catch it.
    async fn ensure_prandint_shares(&mut self) -> Result<(), HoneyBadgerError> {
        let no_shares = {
            let store = self.preprocessing_material.lock().await;
            store.length().prandint
        };

        if no_shares >= self.params.n_prandint {
            info!("There are enough PRandInt shares");
            return Ok(());
        }

        let missing = self.params.n_prandint.saturating_sub(no_shares);
        info!("PRandInt share generation");

        let bits = self.params.mask_bits();
        // Cloned rather than borrowed: `generate_prss` is `&self` on the node's own sub-store, and
        // holding a borrow of `self.preprocess` across it would conflict. The clone shares the
        // cursors through an `Arc` — that is the whole point of `PrssAllocator: Clone` — so this
        // is the same allocator, not a fork of it.
        let alloc = self
            .preprocess
            .prss_alloc
            .as_ref()
            .ok_or(HoneyBadgerError::NotEnoughPreprocessing)?
            .clone();
        let output = self
            .preprocess
            .prand_int
            .generate_prss(&alloc, missing, bits)
            .await?;
        self.preprocessing_material
            .lock()
            .await
            .add(None, None, None, Some(output));
        Ok(())
    }
}

#[async_trait]
impl<F, R, N> GfMPCProtocol<Gf256, GfShare<Gf256>, N> for HoneyBadgerMPCNode<F, R>
where
    N: Network + Send + Sync + 'static,
    F: PrimeField,
    R: RBC<Id = SessionId>,
{
    type Error = HoneyBadgerError;

    /// Local GF(2^k) addition — no network round, mirroring how `+` on `GfShare` itself is free.
    fn gf_add(
        &self,
        x: Vec<GfShare<Gf256>>,
        y: Vec<GfShare<Gf256>>,
    ) -> Result<Vec<GfShare<Gf256>>, HoneyBadgerError> {
        x.into_iter()
            .zip(y)
            .map(|(a, b)| (a + b).map_err(HoneyBadgerError::from))
            .collect()
    }

    /// Local GF(2^k) subtraction — no network round, mirroring how `-` on `GfShare` itself is
    /// free.
    fn gf_sub(
        &self,
        x: Vec<GfShare<Gf256>>,
        y: Vec<GfShare<Gf256>>,
    ) -> Result<Vec<GfShare<Gf256>>, HoneyBadgerError> {
        x.into_iter()
            .zip(y)
            .map(|(a, b)| (a - b).map_err(HoneyBadgerError::from))
            .collect()
    }

    /// GF(2^k) analogue of `mul` — Beaver multiplication over `Gf256`, drawing triples from
    /// `gf_preprocessing_material` (topping it up via `run_gf_preprocessing` if short).
    ///
    /// Chunked against `max_gf_mul_pairs_per_session` and pipelined at `gf_mul_pipeline_depth`,
    /// the same shape `mul` uses, with one addition: the depth cap.
    /// `mul` issues every chunk at once, which is safe at the batch sizes it sees; A2B drives this
    /// entry point with AND layers of thousands of gates, and past `MAX_GF_BATCH_RECON_SESSIONS /
    /// n` concurrent openings a peer's `Eval` messages start being rejected by its own per-peer
    /// quota and the openings silently never complete. Each wave is awaited **and cleared** before
    /// the next is issued, which is also what keeps the 200-slot channel inside `GfMultiply` from
    /// filling — a channel this node cannot resize, since `GfMultiply::new` builds it internally.
    ///
    /// This was previously a single un-chunked session. A2B cannot ship on that: one AND layer
    /// over a batch of `m` values is up to `64 * m` gates, which overruns both the per-session
    /// figure and, eventually, `MAX_MESSAGE_SIZE`.
    async fn gf_mul(
        &mut self,
        x: Vec<GfShare<Gf256>>,
        y: Vec<GfShare<Gf256>>,
        network: Arc<N>,
    ) -> Result<Vec<GfShare<Gf256>>, HoneyBadgerError>
    where
        N: 'async_trait,
    {
        assert_eq!(x.len(), y.len());
        if x.is_empty() {
            return Ok(Vec::new());
        }

        let no_triples = {
            let store = self.gf_preprocessing_material.lock().await;
            store.length().beaver_triples
        };
        if no_triples < x.len() {
            let mut rng = StdRng::from_rng(OsRng).unwrap();
            self.run_gf_preprocessing(network.clone(), &mut rng).await?;
        }

        let per_session = max_gf_mul_pairs_per_session(self.params.threshold);
        let depth = gf_mul_pipeline_depth(self.params.n_parties);
        let mut result = Vec::with_capacity(x.len());
        let mut offset = 0usize;

        while offset < x.len() {
            let wave_end = offset
                .saturating_add(per_session.saturating_mul(depth))
                .min(x.len());
            let mut first_err: Option<HoneyBadgerError> = None;
            let mut issued = Vec::new();

            // Issue this wave's sessions. They are independent — distinct session ids, distinct
            // triples, distinct storage entries — so their network rounds overlap during the
            // awaits below instead of running strictly back to back.
            let mut cursor = offset;
            while cursor < wave_end {
                let end = (cursor + per_session).min(wave_end);
                // Not `?`: sessions issued earlier in this wave are already live, and returning
                // here would leave them resident. Record the failure and fall through to the
                // await-and-clear below (C7).
                let beaver_triples = match self
                    .gf_preprocessing_material
                    .lock()
                    .await
                    .take_beaver_triples(end - cursor)
                {
                    Ok(triples) => triples,
                    Err(e) => {
                        if first_err.is_none() {
                            first_err = Some(e.into());
                        }
                        break;
                    }
                };

                let session_id = SessionId::new(
                    ProtocolType::GfMul,
                    SessionId::pack_slot(self.counters.gf_mul_counter.get_next().await?, 0, 0),
                    self.params.instance_id,
                );

                match self
                    .gf_operations
                    .mul
                    .init(
                        session_id,
                        x[cursor..end].to_vec(),
                        y[cursor..end].to_vec(),
                        beaver_triples,
                        network.clone(),
                    )
                    .await
                {
                    Ok(()) => issued.push(session_id),
                    Err(e) if first_err.is_none() => first_err = Some(e.into()),
                    Err(_) => {}
                }
                cursor = end;
            }

            // Results are collected in session order, so the output ordering matches the input.
            // Every session is cleared regardless of outcome — a timed-out session must not be
            // left dangling in the store just because an earlier `?` would have skipped over it.
            for session_id in &issued {
                match self
                    .gf_operations
                    .mul
                    .wait_for_result(*session_id, self.params.timeout)
                    .await
                {
                    Ok(mut chunk) => result.append(&mut chunk),
                    Err(e) if first_err.is_none() => first_err = Some(e.into()),
                    Err(_) => {}
                }
            }
            for session_id in &issued {
                if !self.gf_operations.mul.clear_store(*session_id).await {
                    warn!(
                        ?session_id,
                        "failed to clear GF(2^k) multiplication protocol state"
                    );
                }
            }

            if let Some(e) = first_err {
                return Err(e);
            }
            offset = wave_end;
        }

        Ok(result)
    }
}

#[async_trait]
impl<F, R, N> GfPreprocessingMPCProtocol<Gf256, GfShare<Gf256>, N> for HoneyBadgerMPCNode<F, R>
where
    N: Network + Send + Sync + 'static,
    F: PrimeField,
    R: RBC<Id = SessionId>,
{
    /// GF(2^k) analogue of `run_preprocessing`, producing random shares and Beaver triples only
    async fn run_gf_preprocessing<G>(
        &mut self,
        network: Arc<N>,
        rng: &mut G,
    ) -> Result<(), HoneyBadgerError>
    where
        N: 'async_trait,
        G: Rng + Send,
    {
        let (no_of_triples_avail, no_of_random_shares_avail) = {
            let store = self.gf_preprocessing_material.lock().await;
            let len = store.length();
            (len.beaver_triples, len.random_shr)
        };

        let mut no_of_triples = self.params.n_gf_triples;
        let mut no_of_random_shares = self.params.n_gf_random_shares;
        let group_size = 2 * self.params.threshold + 1;
        let total_triples_to_generate = if no_of_triples_avail >= no_of_triples {
            no_of_triples = 0;
            0
        } else {
            (no_of_triples - no_of_triples_avail).div_ceil(group_size) * group_size
        };

        // All three of a GF triple's inputs come from one source, not two. See the block comment
        // below; the only thing this flag changes *here* is whether the triples' `[a]` and `[b]`
        // have to be dealt as `GfRanSha`, which is the whole of the remaining cost gap.
        let triples_from_prss = self.gf_dn07_uses_prss();

        let total_random_shares_to_generate = if total_triples_to_generate > 0 {
            let baseline = if no_of_random_shares_avail < no_of_random_shares {
                no_of_random_shares - no_of_random_shares_avail
            } else {
                no_of_random_shares = 0;
                0
            };
            if triples_from_prss {
                // `[a]` and `[b]` are derived, so the `2 x GfRanSha` per triple this used to add
                // is not dealt at all. Only a caller's own `n_gf_random_shares` request remains —
                // that pool is spent elsewhere and is not this path's to elide.
                baseline
            } else {
                baseline + 2 * total_triples_to_generate
            }
        } else if no_of_random_shares_avail < no_of_random_shares {
            no_of_random_shares - no_of_random_shares_avail
        } else {
            no_of_random_shares = 0;
            0
        };

        if no_of_triples == 0 && no_of_random_shares == 0 {
            info!("There is enough GF(2^k) random shares and Beaver triples");
            return Ok(());
        }

        self.ensure_gf_random_shares(network.clone(), rng, total_random_shares_to_generate)
            .await?;

        // A GF triple's **whole input set** — `[a]_t`, `[b]_t` and the `([r]_t, [r]_2t)` its
        // degree reduction consumes. Two sources, same objects:
        //
        // * **PRSS + PRZS** once `setup_prss_keys` has run — `O2 = 2n/(2t+1)` bytes per triple,
        //   the single degree-`2t` opening and nothing else, because none of the three inputs
        //   goes on the wire at all. Costs computational rather than perfect privacy of
        //   preprocessing randomness, under the same PRF assumption `PRandInt` already carries.
        // * **`GfRanSha` x2 + `GfRanDouSha`** otherwise — dealt, interactive, perfect privacy.
        //   This is the path a caller that runs `run_gf_preprocessing` without ever establishing
        //   PRSS keys takes, and it is unchanged.
        //
        // The doubles alone came from PRSS before this change while `[a]` and `[b]` were still
        // dealt, which left a GF triple costing `2 x R1 + O2` instead of `O2` — a 3.3-3.9x
        // overcharge on every one of the ~695 triples an A2B spends. The `F` side never had it:
        // `generate_triples_via_dn07` has always taken all three from
        // `PrssDoubleShareSource::triple_material`. This is that asymmetry closed, against the
        // same template.
        //
        // Why PRSS-derived operands are safe where dealt ones would not be: `gf_triple_gen`'s
        // reduction opens `[a][b] - [r]_2t` at degree `2t`, which imposes no codeword constraint
        // on the honest sub-word at `n = 3t+1`. A dealer who deals `a` at degree `t+1` makes the
        // product degree `2t+1`, the opening still succeeds, and the dealer recovers the honest
        // `b` in the clear. Every input here is a deterministic function of keys held by
        // `n - t >= 2t+1` parties with nothing dealt anywhere, so a corrupt party's only freedom
        // is to lie at the opening — which the `[3t+1, 2t+1]` code's distance `t+1` detects with
        // probability 1. The dealt fallback keeps its own operands off a degree-`2t` opening's
        // critical path the same way it always did: `GfRanSha` is verified at dealing.
        //
        // The choice is all-or-nothing across parties because PRSS key setup is: RISS either
        // completes for everyone or for no one. Were it ever to split, the mismatch is *detected*
        // rather than silent — parties deriving different `r` send shares that lie on no common
        // degree-`2t` polynomial, and the `[3t+1, 2t+1]` code's distance `t+1` makes that a
        // non-codeword, so `recover_secret` aborts.
        //
        // The PRSS positions come from the node's single [`PrssAllocator`], never from a counter
        // of this call site's own. That is not a tidiness preference: `PrssStream::GfDn07Double`
        // is one keystream shared with the edaBit modulus-overflow filter, and two independent
        // monotone counters on one stream collide — re-deriving an `[r]` that has already masked a
        // degree-`2t` opening, which is a total privacy break that no all-honest test detects.
        // This call site used `gf_ran_dou_sha_counter` before the filter became a second consumer,
        // which was monotone and sufficient while it was the *only* consumer; it is not any more.
        // See [`Self::gf_prss_doubles`].
        if total_triples_to_generate == 0 {
            return Ok(());
        }

        let (random_shares_a, random_shares_b, ran_dou_sha_pair) = if triples_from_prss {
            // One claim per chunk on the node's single `PrssAllocator`, covering all three inputs
            // — never a counter of this call site's own. See `Self::gf_prss_triple_material`.
            let material = self
                .gf_prss_triple_material(total_triples_to_generate)
                .await?;
            (material.a, material.b, material.doubles)
        } else {
            let mut pair = self
                .ensure_gf_ran_dou_sha_pair(network.clone(), rng, total_triples_to_generate)
                .await?;
            // `ensure_gf_ran_dou_sha_pair` may over-produce (ceil-rounded to a whole column) —
            // only the exact multiple-of-`group_size` prefix `GfTripleGenNode::init_batch`
            // requires.
            pair.truncate(total_triples_to_generate);
            let a = self
                .gf_preprocessing_material
                .lock()
                .await
                .take_random_shares(total_triples_to_generate)?;
            let b = self
                .gf_preprocessing_material
                .lock()
                .await
                .take_random_shares(total_triples_to_generate)?;
            (a, b, pair)
        };

        let session_id = SessionId::new(
            ProtocolType::GfTriple,
            SessionId::pack_slot(self.counters.gf_triple_counter.get_next().await?, 0, 0),
            self.params.instance_id,
        );
        self.gf_preprocess
            .gf_triple_gen
            .init_batch(
                random_shares_a,
                random_shares_b,
                ran_dou_sha_pair,
                session_id,
                network,
            )
            .await?;
        let result = self
            .gf_preprocess
            .gf_triple_gen
            .wait_for_result(session_id, self.params.timeout)
            .await;
        if !self
            .gf_preprocess
            .gf_triple_gen
            .clear_store(session_id)
            .await
        {
            warn!(
                ?session_id,
                "failed to clear GF(2^k) triple generation protocol state"
            );
        }
        self.gf_preprocessing_material
            .lock()
            .await
            .add(Some(result?), None);
        Ok(())
    }
}

/// edaBit candidates composed and filtered in one
/// [`EdaBitFilterNode::compose_edabits`](dabit::edabit::EdaBitFilterNode::compose_edabits) call.
///
/// The filter's round count is already independent of the batch size — every candidate runs the
/// same public netlist, so they share each AND layer's multiplication — so a larger batch buys
/// only a little more amortisation of six rounds, while the resident wire arenas and the daBits
/// the batch must be handed grow linearly.
const MAX_EDABIT_COMPOSE_BATCH: usize = 256;

impl<F, R> HoneyBadgerMPCNode<F, R>
where
    F: PrimeField,
    R: RBC<Id = SessionId>,
{
    /// `true` when `F` Beaver triples are made by **DN07 degree reduction over PRSS material**
    /// rather than by `TripleGenNode` over dealt `RanSha` + `RanDouSha`.
    ///
    /// Both halves or neither, for the reason [`Self::randbit_uses_prss`] gives.
    pub fn f_triples_use_dn07(&self) -> bool {
        self.preprocess.dn07_doubles.is_some() && self.preprocess.prss_alloc.is_some()
    }

    /// `count` `F` Beaver triples, each one DN07 degree reduction and **nothing else**.
    ///
    /// ```text
    ///   [a]_t, [b]_t, ([r]_t, [r]_2t)   PRSS + PRZS, zero rounds, zero bytes
    ///   [d]_2t = [a][b] - [r]_2t        local
    ///   d = Open_2t([d]_2t)             ONE batched degree-2t opening, 2t+1 secrets per group
    ///   [ab]_t = [r]_t + d              local
    /// ```
    ///
    /// Against the dealt path — `2 x RanSha` for `a` and `b`, one `RanDouSha` for the mask, and
    /// the same degree-`2t` opening, which `TripleGenNode::init_batch` performs inline — this
    /// removes everything except the opening. At `n = 10, t = 3` that is `O2 = 2.857` field
    /// elements per triple against `2 x 4.000 + RanDouSha + 2.857`. Payload, and **marginal**:
    /// the measured wire bill of a batch is `2n * 48 + O2 * triples`, the fixed term being the
    /// per-message frame (`honeybadger::dn07`, units note).
    ///
    /// # What is *not* different
    ///
    /// The algebra. `TripleGenNode::init` already computes `[a][b] - [r]_2t`, opens it at degree
    /// `2t` through a `BatchReconNode` pinned at `2t`, and adds `[r]_t`: it *is* DN07, written
    /// inline. That is why this path is a re-sourcing rather than a new protocol, and why the two
    /// produce interchangeable triples. What changes is where `a`, `b` and `r` come from — and
    /// with them, whether a `Dn07MulNode` has a production caller at all.
    ///
    /// # Why PRSS-derived operands are safe here and dealt ones would not be
    ///
    /// [`Dn07MulNode::init_mul`] opens at degree `2t`, which imposes no codeword constraint on
    /// the honest sub-word at `n = 3t+1`: a dealer who deals `a` at degree `t+1` makes the product
    /// degree `2t+1`, the opening still succeeds, and the dealer recovers the honest `b` in the
    /// clear. Every operand here is PRSS-derived — a deterministic function of keys held by
    /// `n - t >= 2t+1` parties, with nothing dealt anywhere — so a corrupt party's only freedom is
    /// to lie at the opening, which the `[3t+1, 2t+1]` code's distance `t+1` detects with
    /// probability 1.
    ///
    /// # What this costs, and it is not nothing
    ///
    /// A Beaver triple made this way has **computationally** private `a` and `b`, under HMAC-
    /// SHA256 as a PRF, where a dealt `RanSha` pair is perfectly private. Those masks are spent
    /// by the *online* `mul`, so this is the first place a PRSS assumption reaches an online
    /// operand rather than only preprocessing randomness. It is the same trade the `Gf2k` side
    /// already makes — `gf_triple_gen` has taken its double sharings from
    /// `GfPrssDoubleShareSource` since before this change, and those triples are spent online by
    /// A2B — and the same assumption `PRandInt` has always carried. A deployment that wants
    /// perfect privacy declines PRSS key setup and gets `TripleGenNode` unchanged; there is no
    /// third option, and pretending otherwise is how a cost table becomes a security claim.
    ///
    /// # Phase
    ///
    /// PREPROCESSING, and the sessions are tagged [`ProtocolType::Dn07`] rather than
    /// [`ProtocolType::Triple`]: the dispatcher demuxes `BatchRecon` on the calling protocol, and
    /// `Triple` routes to `triple_gen`'s own reconstruction node. The tag is classified
    /// `Preprocessing` by `dn07::phase_of`, and [`PreprocessingSessionId::new`] is what turns that
    /// classification into a value `init_mul` will accept.
    async fn generate_triples_via_dn07<N>(
        &mut self,
        count: usize,
        network: Arc<N>,
    ) -> Result<(), HoneyBadgerError>
    where
        N: Network + Send + Sync + 'static,
    {
        if count == 0 {
            return Ok(());
        }
        let source = match self.preprocess.dn07_doubles.as_ref() {
            Some(source) => source.clone(),
            None => return Err(HoneyBadgerError::NotEnoughPreprocessing),
        };
        let alloc = match self.preprocess.prss_alloc.as_ref() {
            Some(alloc) => alloc.clone(),
            None => return Err(HoneyBadgerError::NotEnoughPreprocessing),
        };

        // Two ceilings on one session: PRZS spends `t` coefficients per double sharing and bounds
        // the total per call, and DN07 bounds one session's opening at `MAX_DN07_GROUPS` groups of
        // `2t+1`. Neither is binding at the thresholds this repo runs; taking the `min` means a
        // change to either constant cannot silently produce a `BatchTooLarge` from in here.
        let przs_cap = (MAX_PRZS_COEFFS_PER_CALL / self.params.threshold.max(1)).max(1);
        let chunk = przs_cap.min(self.preprocess.dn07.max_batch_size()).max(1);
        // And a third ceiling, on how many sessions are in flight at once: `Dn07MulNode` admits
        // `MAX_DN07_SESSIONS / n` sessions per initiator, this node included. Issuing more than
        // that before awaiting any would have the node reject its own sessions and then block
        // forever waiting for their results. `n_triples` is a caller-supplied figure, so this is
        // reachable rather than theoretical.
        let in_flight = (MAX_DN07_SESSIONS / self.params.n_parties.max(1)).max(1);

        let mut triples = Vec::with_capacity(count);
        let mut produced = 0usize;

        while produced < count {
            // Phase 0 — claim and derive this wave's material. Each claim burns its own window,
            // so a failure anywhere below leaves positions burned rather than rewound.
            let mut pending = Vec::new();
            let mut issued = produced;
            while issued < count && pending.len() < in_flight {
                let take = (count - issued).min(chunk);
                let material = source.triple_material(&alloc, take).await?;
                // The exec id here names a *network session*; the exec id inside the window above
                // names a *PRF context*. Both live under `ProtocolType::Dn07` and neither can
                // reach the other: nothing derives PRSS from a wire session id, and nothing routes
                // a message by a window's.
                let session_id = SessionId::new(
                    ProtocolType::Dn07,
                    SessionId::pack_slot(self.counters.triple_counter.get_next().await?, 0, 0),
                    self.params.instance_id,
                );
                pending.push((session_id, material));
                issued += take;
            }

            // Phase 1 — issue the wave's openings so their rounds overlap instead of running back
            // to back. Same shape as the `TripleGenNode` pipelining this replaces.
            let mut first_err: Option<HoneyBadgerError> = None;
            let mut live = Vec::with_capacity(pending.len());
            for (session_id, material) in &pending {
                let outcome = match PreprocessingSessionId::new(*session_id) {
                    Ok(pre_sid) => {
                        self.preprocess
                            .dn07
                            .init_mul(
                                pre_sid,
                                material.a.clone(),
                                material.b.clone(),
                                material.doubles.clone(),
                                network.clone(),
                            )
                            .await
                    }
                    Err(e) => Err(e),
                };
                match outcome {
                    // Not `?`: sessions issued earlier in this wave are already live, and
                    // returning here would leave them and their children resident.
                    Ok(()) => live.push(*session_id),
                    Err(e) if first_err.is_none() => first_err = Some(e.into()),
                    Err(_) => {}
                }
            }

            // Phase 2 — collect. `clear_store` on every exit path, including the failure one: an
            // abandoned DN07 session holds an entry here and one in its batch-reconstruction
            // child.
            for (session_id, material) in &pending {
                if live.contains(session_id) {
                    match self
                        .preprocess
                        .dn07
                        .wait_for_products(*session_id, self.params.timeout)
                        .await
                    {
                        Ok(products) if products.len() == material.a.len() => {
                            for ((a, b), mult) in material
                                .a
                                .iter()
                                .zip(material.b.iter())
                                .zip(products.into_iter())
                            {
                                triples.push(ShamirBeaverTriple::new(a.clone(), b.clone(), mult));
                            }
                        }
                        Ok(products) => {
                            if first_err.is_none() {
                                first_err =
                                    Some(HoneyBadgerError::Dn07Error(Dn07Error::LengthMismatch {
                                        what: "DN07 triple products",
                                        expected: material.a.len(),
                                        got: products.len(),
                                    }));
                            }
                        }
                        Err(e) if first_err.is_none() => first_err = Some(e.into()),
                        Err(_) => {}
                    }
                }
                if !self.preprocess.dn07.clear_store(*session_id).await {
                    warn!(?session_id, "failed to clear DN07 triple generation state");
                }
            }

            if let Some(e) = first_err {
                return Err(e);
            }
            produced = issued;
        }

        self.preprocessing_material
            .lock()
            .await
            .add(Some(triples), None, None, None);
        Ok(())
    }

    /// `true` when `Gf2k` DN07 double sharings come from PRSS + PRZS rather than from dealt
    /// `GfRanDouSha`.
    ///
    /// Both halves or neither, for the reason [`Self::randbit_uses_prss`] gives: a source without
    /// an allocator would derive at position zero every single time.
    pub fn gf_dn07_uses_prss(&self) -> bool {
        self.gf_preprocess.gf_dn07_doubles.is_some() && self.preprocess.prss_alloc.is_some()
    }

    /// `needed` `Gf2k` double sharings `([r]_t, [r]_2t)` from PRSS + PRZS — **zero rounds, zero
    /// bytes** — with every position claimed from this node's one [`PrssAllocator`].
    ///
    /// # This is the only way to reach [`PrssStream::GfDn07Double`]
    ///
    /// That stream is shared by every `Gf2k` DN07 consumer: GF triple generation and the edaBit
    /// modulus-overflow filter. Each of them running its own monotone counter would be
    /// individually monotone and jointly colliding, and a collision re-derives an `[r]` that has
    /// already masked a degree-`2t` opening — the total privacy break that no all-honest test can
    /// see. Funnelling both through one allocator is what makes disjointness structural rather
    /// than a convention two call sites have to keep agreeing on.
    ///
    /// Chunked against `MAX_PRZS_COEFFS_PER_CALL / t`, because PRZS spends `t` coefficients per
    /// sharing and bounds the total per call. Each chunk burns its own exec id; positions are
    /// never rewound, including when a later chunk fails.
    async fn gf_prss_doubles(
        &self,
        needed: usize,
    ) -> Result<
        Vec<crate::honeybadger::gf_double_share::GfDoubleShamirShare<Gf256>>,
        HoneyBadgerError,
    > {
        let (source, alloc) = match (
            self.gf_preprocess.gf_dn07_doubles.as_ref(),
            self.preprocess.prss_alloc.as_ref(),
        ) {
            (Some(source), Some(alloc)) => (source, alloc),
            _ => return Err(HoneyBadgerError::NotEnoughPreprocessing),
        };
        let cap = (MAX_PRZS_COEFFS_PER_CALL / self.params.threshold.max(1)).max(1);
        let mut out = Vec::with_capacity(needed);
        while out.len() < needed {
            let take = (needed - out.len()).min(cap);
            out.extend(source.double_shares(alloc, take).await?);
        }
        Ok(out)
    }

    /// A GF Beaver triple's **whole** input set for `needed` triples — `[a]_t`, `[b]_t` and one
    /// `([r]_t, [r]_2t)` each — from PRSS + PRZS, **zero rounds, zero bytes**, with every position
    /// claimed from this node's one [`PrssAllocator`].
    ///
    /// The `Gf2k` twin of what `generate_triples_via_dn07` gets from
    /// [`PrssDoubleShareSource::triple_material`](dn07::double_share::PrssDoubleShareSource::triple_material),
    /// and the thing that closes the GF triple's cost gap: `[a]` and `[b]` used to be dealt
    /// `GfRanSha` while only the doubles were derived, which priced a triple at `2 x R1 + O2`
    /// rather than `O2`.
    ///
    /// # It shares [`Self::gf_prss_doubles`]'s stream, and that is the point
    ///
    /// [`PrssStream::GfDn07Double`] is one keystream with three consumers now — GF triple `a`/`b`,
    /// GF triple doubles, and the edaBit modulus-overflow filter's doubles. A claim here of
    /// `3 * take` positions and a claim there of `take` come off the same monotone cursor, so they
    /// cannot overlap. Introducing a counter of this call site's own would make two individually
    /// monotone, jointly colliding sequences, and a collision re-derives an `[r]` that has already
    /// masked a degree-`2t` opening — the total privacy break no all-honest test detects.
    ///
    /// # Chunking, and burned ranges
    ///
    /// Chunked against `MAX_PRZS_COEFFS_PER_CALL / t`, on the *triple* count rather than the
    /// window width: PRZS spends `t` coefficients per double sharing and only the window's last
    /// third derives any. Each chunk burns its own exec id, and a chunk that fails leaves its
    /// range spent rather than rewinding onto it — including when an earlier chunk already
    /// succeeded, whose positions stay burned too.
    ///
    /// # Phase
    ///
    /// PREPROCESSING, and structurally so: the window addresses `(GfDn07, 0, 0)` and
    /// `triple_material_in` puts it through `PreprocessingSessionId::new`, which rejects an online
    /// tag. Nothing this returns is reachable from A2B or B2A, which spend finished triples at
    /// degree `t`.
    async fn gf_prss_triple_material(
        &self,
        needed: usize,
    ) -> Result<dn07::double_share::GfTripleMaterial<Gf256>, HoneyBadgerError> {
        let (source, alloc) = match (
            self.gf_preprocess.gf_dn07_doubles.as_ref(),
            self.preprocess.prss_alloc.as_ref(),
        ) {
            (Some(source), Some(alloc)) => (source, alloc),
            _ => return Err(HoneyBadgerError::NotEnoughPreprocessing),
        };
        let cap = (MAX_PRZS_COEFFS_PER_CALL / self.params.threshold.max(1)).max(1);
        let mut a = Vec::with_capacity(needed);
        let mut b = Vec::with_capacity(needed);
        let mut doubles = Vec::with_capacity(needed);
        while a.len() < needed {
            let take = (needed - a.len()).min(cap);
            let chunk = source.triple_material(alloc, take).await?;
            if chunk.a.len() != take || chunk.b.len() != take || chunk.doubles.len() != take {
                return Err(HoneyBadgerError::NotEnoughPreprocessing);
            }
            a.extend(chunk.a);
            b.extend(chunk.b);
            doubles.extend(chunk.doubles);
        }
        Ok(dn07::double_share::GfTripleMaterial { a, b, doubles })
    }
}

impl<F, R> HoneyBadgerMPCNode<F, R>
where
    F: PrimeField,
    R: RBC<Id = SessionId>,
{
    /// Bits per converted value: `ceil(log2 p)`, 64 on Goldilocks.
    fn conv_bit_width() -> usize {
        crate::common::convert::field_bit_width::<F>()
    }

    /// Runs exactly one PRSS daBit batch of `outputs` daBits.
    ///
    /// Material comes **explicitly** out of the shared `RandBit` pool, in pool order — the
    /// `ensure_randbit_shares` discipline, and also what makes the material agree across parties,
    /// since every party drains its own pool identically. This does not top that pool up itself,
    /// so an undersized configuration surfaces as `NotEnoughPreprocessing` here rather than
    /// silently generating more preprocessing underneath a caller who asked for a fixed amount;
    /// [`Self::ensure_dabits_at_least`] is the layer that tops up.
    ///
    /// There is **no batch-size floor**. The dealt protocol had one, because its cross-domain
    /// check was bucketed and `M^-(B-1)` only reaches `kappa` for large `M`. PRSS daBits have
    /// soundness error 0 and no bucket, so a batch of one is exactly as sound as a batch of 2048.
    /// What replaced the floor is a lifetime *ceiling*, enforced inside
    /// [`PrssDaBitNode::generate`](dabit::prss_dabit::PrssDaBitNode::generate).
    async fn run_dabit_batch<N>(
        &mut self,
        outputs: usize,
        network: Arc<N>,
    ) -> Result<Vec<DaBit<F, Gf256>>, HoneyBadgerError>
    where
        N: Network + Send + Sync + 'static,
    {
        let per_dabit = self.conv.dabit_gen.rand_bits_per_dabit();
        let needed = outputs
            .checked_mul(per_dabit)
            .ok_or(HoneyBadgerError::LimitError)?;
        let rand_bits = self
            .preprocessing_material
            .lock()
            .await
            .take_randbit_shares(needed)?;

        // One claim, one exec, both of the batch's keystreams: `beta` at width 1 and the Mod2
        // mask `psi` at `lambda`, on the same `exec_id`, from the node's single `PrssAllocator`.
        // The exec is the high half of every PRSS position this batch derives, so it must never be
        // rewound — including after a failure. `claim_dabit_batch` advances the cursor under a
        // lock before returning and there is no path that moves it back, which is what makes
        // burn-never-rewind a property of the type rather than a discipline.
        let alloc = self
            .preprocess
            .prss_alloc
            .as_ref()
            .ok_or(HoneyBadgerError::NotEnoughPreprocessing)?
            .clone();
        let windows = alloc
            .claim_dabit_batch(outputs, self.conv.dabit_gen.mask_bits())
            .await
            .map_err(DaBitError::from)?;
        // Captured before `generate` consumes the windows; it is the seed window's own session.
        let session_id = windows.parent_session();

        let dabits = self
            .conv
            .dabit_gen
            .generate(windows, rand_bits, self.params.timeout, network)
            .await;

        // Cleared before the `?`, on every exit path: `generate` clears its own Mod2 session, but
        // an error raised before it reached the opening leaves nothing to clear and this is
        // cheap and idempotent.
        self.conv.dabit_gen.clear_store(session_id).await;

        Ok(dabits?)
    }

    /// Tops the loose daBit pool up to at least `target`.
    ///
    /// Unlike the dealt protocol this has no soundness floor to round up to, so it asks for
    /// exactly what is missing (capped by one Mod2 session's ceiling) and loops.
    async fn ensure_dabits_at_least<N, G>(
        &mut self,
        target: usize,
        network: Arc<N>,
        rng: &mut G,
    ) -> Result<(), HoneyBadgerError>
    where
        N: Network + Send + Sync + 'static,
        G: Rng + Send,
    {
        let per_batch = self.conv.dabit_gen.max_batch_size();
        let per_dabit = self.conv.dabit_gen.rand_bits_per_dabit();
        loop {
            let have = self
                .conv_preprocessing_material
                .lock()
                .await
                .length()
                .dabits;
            if have >= target {
                return Ok(());
            }
            let outputs = (target - have).min(per_batch);

            // Each daBit consumes `1 + k` RandBits. Topped up here rather than assumed, the same
            // way `ensure_edabits` tops up the GF triples its filter needs — a daBit batch that
            // failed for want of RandBits would burn its PRSS range for nothing.
            //
            // `+ n_randbit`: the fixed-point path's own reserve is in the same pool, and this
            // batch drains it in pool order, so asking only for what this batch needs would let
            // daBit generation quietly eat what `mul_fixed` was sized for.
            let needed_bits = outputs
                .checked_mul(per_dabit)
                .and_then(|n| n.checked_add(self.params.n_randbit))
                .ok_or(HoneyBadgerError::LimitError)?;
            self.ensure_randbit_shares_at_least(needed_bits, network.clone(), rng)
                .await?;

            let dabits = self.run_dabit_batch(outputs, network.clone()).await?;
            if dabits.is_empty() {
                // `generate` returns exactly `outputs` daBits or an error, so an empty vector
                // would mean the loop can never make progress.
                return Err(HoneyBadgerError::NotEnoughPreprocessing);
            }
            self.conv_preprocessing_material
                .lock()
                .await
                .add(Some(dabits), None);
        }
    }

    /// Tops the full-range edaBit pool up to `params.n_edabits`.
    ///
    /// Each edaBit costs `ceil(log2 p)` daBits — generated here rather than taken from whatever
    /// the loose pool happens to hold, so that topping up edaBits never quietly empties the pool
    /// B2A draws from — plus one run of the modulus-overflow filter. A candidate whose composed
    /// mask is not below `p` is dropped together with **all** of its daBits, at a rate of
    /// `(2^32 - 1)/2^64 ≈ 2^-32`, so the loop simply runs again.
    async fn ensure_edabits<N, G>(
        &mut self,
        network: Arc<N>,
        rng: &mut G,
    ) -> Result<(), HoneyBadgerError>
    where
        N: Network + Send + Sync + 'static,
        G: Rng + Send,
    {
        let width = Self::conv_bit_width();
        if width == 0 {
            return Err(HoneyBadgerError::DaBitError(DaBitError::ZeroWidth));
        }
        let per_candidate = EdaBitFilterNode::<F, Gf256>::gf_doubles_per_edabit()?;

        loop {
            let have = self
                .conv_preprocessing_material
                .lock()
                .await
                .length()
                .edabits;
            if have >= self.params.n_edabits {
                return Ok(());
            }
            let candidates = (self.params.n_edabits - have).min(MAX_EDABIT_COMPOSE_BATCH);

            // The daBits this batch consumes are on top of whatever the loose pool already owes
            // its own target, so ask for both at once and take only this batch's share.
            let reserved = self.params.n_dabits;
            let needed = candidates
                .checked_mul(width)
                .and_then(|n| n.checked_add(reserved))
                .ok_or(HoneyBadgerError::LimitError)?;
            self.ensure_dabits_at_least(needed, network.clone(), rng)
                .await?;

            let dabits = self
                .conv_preprocessing_material
                .lock()
                .await
                .take_dabits(candidates * width)?;

            // One `([r]_t, [r]_2t)` per AND, where the filter used to spend one GF(2^k) Beaver
            // triple per AND. Same count, two changes of kind:
            //
            // * making one costs **nothing** on the PRSS path, against a triple's `18.857` bytes
            //   of payload from dealt `GfRanDouSha` or `2.857` from a PRSS-fed `gf_triple_gen`;
            //   and
            // * spending one costs the `O2 = 2.857`-byte degree-`2t` opening alone, against a
            //   Beaver multiplication's `M1 = 4n/(t+1) = 10.0` bytes of degree-`t` openings.
            //
            // All four figures are payload. On the wire this filter's layers are narrow enough
            // that framing is 93-97% of the phase, so the realised saving is the message count —
            // `2n` per layer instead of `4n` plus a share of triple generation, about **2.1x**
            // rather than 4.5x. `edabit.rs`'s module docs carry the measured breakdown.
            //
            // Net at `n = 10`: `12.857 -> 2.857` payload bytes per AND, **4.5x**, and the filter no longer
            // draws on the GF triple pool at all — which is why `run_gf_preprocessing` is not
            // called here any more. A2B still consumes GF triples online and still tops that pool
            // up on its own path.
            let doubles_needed = candidates
                .checked_mul(per_candidate)
                .ok_or(HoneyBadgerError::LimitError)?;
            // Dealt `GfRanDouSha` is the fallback for a deployment that never establishes PRSS
            // keys, exactly as it is for GF triple generation. DN07 does not care which source a
            // double sharing came from — it needs a genuine `([r]_t, [r]_2t)` on one uniform `r`,
            // and both produce that. What DN07 *does* care about is that its **operands** were
            // never dealt, and those are daBit bits and earlier layers' outputs either way.
            let doubles = if self.gf_dn07_uses_prss() {
                self.gf_prss_doubles(doubles_needed).await?
            } else {
                let mut dealt = self
                    .ensure_gf_ran_dou_sha_pair(network.clone(), rng, doubles_needed)
                    .await?;
                // `ensure_gf_ran_dou_sha_pair` ceil-rounds to a whole column; the filter's length
                // check is exact.
                if dealt.len() < doubles_needed {
                    return Err(HoneyBadgerError::NotEnoughPreprocessing);
                }
                dealt.truncate(doubles_needed);
                dealt
            };

            // Same monotone cursor as a daBit *parent* session, deliberately: both drivers mint
            // their children as `parent_exec * 2^20 + wave`, so one cursor is what keeps their
            // child blocks disjoint. A second minter would hand this filter an exec that a daBit
            // batch already owns.
            //
            // `claim_exec`, not `claim_dabit_batch`: this filter spends the exec's child-id block
            // and derives **no PRSS position**, so what it needs is a burned exec id carrying no
            // right to name a byte. That is exactly what `PrssExecSlot` is.
            let alloc = self
                .preprocess
                .prss_alloc
                .as_ref()
                .ok_or(HoneyBadgerError::NotEnoughPreprocessing)?
                .clone();
            let slot = alloc
                .claim_exec(PrssStream::DaBitSeed)
                .await
                .map_err(DaBitError::from)?;

            // `compose_edabits` clears its own session on every exit path.
            let edabits = self
                .conv
                .edabit
                .compose_edabits(slot, dabits, doubles, self.params.timeout, network.clone())
                .await?;

            if edabits.is_empty() {
                // Only reachable if every candidate in the batch wrapped `p` — probability
                // `2^-32` per candidate — or if `candidates` was zero, which the loop guard
                // excludes. Erroring rather than looping keeps this from spinning.
                return Err(HoneyBadgerError::NotEnoughPreprocessing);
            }
            self.conv_preprocessing_material
                .lock()
                .await
                .add(None, Some(edabits));
        }
    }
}

#[async_trait]
impl<F, R, N> ShareConversionProtocol<F, Gf256, RobustShare<F>, GfShare<Gf256>, N>
    for HoneyBadgerMPCNode<F, R>
where
    N: Network + Send + Sync + 'static,
    F: PrimeField,
    R: RBC<Id = SessionId>,
{
    type Error = HoneyBadgerError;

    /// Converts arithmetic sharings to the bit sharings of their canonical representatives.
    ///
    /// Consumes one full-range edaBit and `A2BNode::gf_triples_per_conversion()` GF(2^k) triples
    /// per value, and **zero** `F` triples. Cost is one degree-`t` opening in `F` plus one
    /// multiplication wave per AND layer of the circuit — on Goldilocks **9 message rounds**
    /// (`2` for the mask opening's `BatchReconNode` round trip, then one round for each of the 7
    /// AND layers, which `OpeningPolicy::Auto` opens directly at the widths a conversion issues),
    /// rising to 16 if every layer batches. *Independent of the batch size*, because every value
    /// in a batch shares each layer's wave. A previous version of this line said "14 sequential
    /// openings", which conflated openings with rounds and dropped the mask opening besides; see
    /// [`A2BNode::message_rounds`](a2b::a2b::A2BNode::message_rounds).
    ///
    /// Privacy is perfect: `y = x - r mod p` with `r` uniform on `[0, p)` and independent of `x`
    /// is exactly uniform on `Z_p`. There is no statistical parameter on this path and no
    /// `check_mask_security` call, which is why `max_masked_width` is deliberately not extended.
    ///
    /// The output bits are those of the representative in `[0, p)`, **not** two's complement:
    /// `-1` comes back as `p - 1 = 0xFFFF_FFFF_0000_0000`.
    async fn a2b(
        &mut self,
        x: Vec<RobustShare<F>>,
        network: Arc<N>,
    ) -> Result<Vec<Vec<GfShare<Gf256>>>, HoneyBadgerError>
    where
        N: 'async_trait,
    {
        if x.is_empty() {
            return Ok(Vec::new());
        }

        let per_conversion = A2BNode::<F, Gf256>::gf_triples_per_conversion()?;

        // Top the pools up only if short, the shape `mul` already uses. If they are still short
        // afterwards the `take_*` calls below surface `NotEnoughPreprocessing` rather than
        // silently converting fewer values.
        let short_edabits = {
            let store = self.conv_preprocessing_material.lock().await;
            store.length().edabits < x.len()
        };
        if short_edabits {
            let mut rng = StdRng::from_rng(OsRng).unwrap();
            self.run_conversion_preprocessing(network.clone(), &mut rng)
                .await?;
        }
        let needed_triples = per_conversion
            .checked_mul(x.len())
            .ok_or(HoneyBadgerError::LimitError)?;
        let short_triples = {
            let store = self.gf_preprocessing_material.lock().await;
            store.length().beaver_triples < needed_triples
        };
        if short_triples {
            let mut rng = StdRng::from_rng(OsRng).unwrap();
            self.run_gf_preprocessing(network.clone(), &mut rng).await?;
        }

        let mut result: Vec<Vec<GfShare<Gf256>>> = Vec::with_capacity(x.len());
        let mut sessions = Vec::new();
        let mut first_err: Option<HoneyBadgerError> = None;

        // Chunked at `MAX_A2B_CONVERSIONS`: each conversion carries its own netlist and wire
        // arena, because the circuit plan depends on that conversion's own opened mask and so is
        // shared with nothing. The round count does not improve past one chunk anyway.
        for chunk in x.chunks(MAX_A2B_CONVERSIONS) {
            // Not `?`: sessions issued for earlier chunks are already live, and returning here
            // would leave them and their recorded children resident (C7).
            let material = {
                let edabits = self
                    .conv_preprocessing_material
                    .lock()
                    .await
                    .take_edabits(chunk.len());
                let gf_triples = self
                    .gf_preprocessing_material
                    .lock()
                    .await
                    .take_beaver_triples(per_conversion * chunk.len());
                match (edabits, gf_triples) {
                    (Ok(edabits), Ok(gf_triples)) => Ok((edabits, gf_triples)),
                    (Err(e), _) => Err(HoneyBadgerError::from(e)),
                    (_, Err(e)) => Err(HoneyBadgerError::from(e)),
                }
            };
            let (edabits, gf_triples) = match material {
                Ok(material) => material,
                Err(e) => {
                    first_err = Some(e);
                    break;
                }
            };

            let session_id = SessionId::new(
                ProtocolType::A2B,
                SessionId::pack_slot(self.counters.a2b_counter.get_next().await?, 0, 0),
                self.params.instance_id,
            );
            sessions.push(session_id);

            match self
                .conv
                .a2b
                .init(
                    session_id,
                    chunk.to_vec(),
                    edabits,
                    gf_triples,
                    self.params.timeout,
                    network.clone(),
                )
                .await
            {
                Ok(()) => match self
                    .conv
                    .a2b
                    .wait_for_result(session_id, self.params.timeout)
                    .await
                {
                    Ok(mut bits) => result.append(&mut bits),
                    Err(e) => {
                        first_err = Some(e.into());
                        break;
                    }
                },
                Err(e) => {
                    first_err = Some(e.into());
                    break;
                }
            }
        }

        // Every issued session is cleared regardless of outcome — a failed chunk must not leave
        // its own session, or its recorded children, resident just because an earlier `?` would
        // have skipped the cleanup (C7).
        for session_id in &sessions {
            if !self.conv.a2b.clear_store(*session_id).await {
                warn!(?session_id, "failed to clear A2B protocol state");
            }
        }
        if let Some(e) = first_err {
            return Err(e);
        }
        Ok(result)
    }

    /// Converts binary sharings back to arithmetic ones.
    ///
    /// One degree-`t` GF(2^k) opening, zero online multiplications, zero `F` communication, and
    /// one daBit per input bit. Privacy is perfect: `c_i = x_i XOR r_i` with `r_i` a uniform,
    /// single-use daBit is exactly uniform on `{0,1}`.
    ///
    /// Defaults to the unchecked variant, whose precondition is that each input share holds a bit.
    /// That is structural when the bits came out of [`Self::a2b`], and violating it is *detected*
    /// here in practice — the opened `c_i` then leaves `GF(2)` — though the detection leans on the
    /// daBit's binary half being well formed rather than proving anything about the input.
    /// `B2ANode::b2a_checked` proves it unconditionally for one extra AND layer.
    async fn b2a(
        &mut self,
        bits: Vec<Vec<GfShare<Gf256>>>,
        network: Arc<N>,
    ) -> Result<Vec<RobustShare<F>>, HoneyBadgerError>
    where
        N: 'async_trait,
    {
        if bits.is_empty() {
            return Ok(Vec::new());
        }

        // Widths are validated here, *before* any daBit leaves the pool: `B2ANode` would reject
        // an over-wide value too, but only after this node had already drained the pads for it,
        // and a drained daBit is gone (the pools are drain-only by design).
        let width_bound = b2a::b2a::max_width::<F>();
        let mut total = 0usize;
        for (value, value_bits) in bits.iter().enumerate() {
            let width = value_bits.len();
            if width == 0 {
                return Err(HoneyBadgerError::B2AError(B2AError::ZeroWidth { value }));
            }
            if width > width_bound {
                return Err(HoneyBadgerError::B2AError(B2AError::WidthTooLarge {
                    value,
                    width,
                    max: width_bound,
                }));
            }
            total = total
                .checked_add(width)
                .ok_or(HoneyBadgerError::LimitError)?;
        }

        let short = {
            let store = self.conv_preprocessing_material.lock().await;
            store.length().dabits < total
        };
        if short {
            let mut rng = StdRng::from_rng(OsRng).unwrap();
            self.run_conversion_preprocessing(network.clone(), &mut rng)
                .await?;
        }
        let dabits = self
            .conv_preprocessing_material
            .lock()
            .await
            .take_dabits(total)?;

        let session_id = SessionId::new(
            ProtocolType::B2A,
            SessionId::pack_slot(self.counters.b2a_counter.get_next().await?, 0, 0),
            self.params.instance_id,
        );

        // One session for the whole batch: `B2ANode` chunks and depth-caps its own opening
        // internally, and the conversion stays a single round for any batch up to
        // `max_mul_pairs_per_session(t) * conv_pipeline_depth(n)` bits.
        let started = self
            .conv
            .b2a
            .b2a(
                session_id,
                bits,
                dabits,
                self.params.timeout,
                network.clone(),
            )
            .await;
        let result = match started {
            Ok(()) => self
                .conv
                .b2a
                .wait_for_result(session_id, self.params.timeout)
                .await
                .map_err(HoneyBadgerError::from),
            Err(e) => Err(HoneyBadgerError::from(e)),
        };
        if !self.conv.b2a.clear_store(session_id).await {
            warn!(?session_id, "failed to clear B2A protocol state");
        }
        result
    }
}

#[async_trait]
impl<F, R, N> ConversionPreprocessingProtocol<F, Gf256, RobustShare<F>, GfShare<Gf256>, N>
    for HoneyBadgerMPCNode<F, R>
where
    N: Network + Send + Sync + 'static,
    F: PrimeField,
    R: RBC<Id = SessionId>,
{
    /// Fills the edaBit pool to `n_edabits` and the loose daBit pool to `n_dabits`.
    ///
    /// edaBits first: composing one consumes `ceil(log2 p)` daBits, so topping the loose pool up
    /// beforehand would only see it drained again. Both phases draw their `F` and GF(2^k)
    /// material from the ordinary preprocessing pools; neither tops *those* up beyond the GF
    /// triples the filter needs, so an undersized `n_random_shares` / `n_triples` /
    /// `n_gf_random_shares` surfaces as `NotEnoughPreprocessing` rather than as a silent extra
    /// preprocessing run.
    ///
    /// # Liveness
    ///
    /// daBit generation waits for **all** `n` dealers' `Deltas`, so one crashed party stalls it —
    /// exactly as `share_gen`, `gf_share_gen`, `zero_share` and `double_share_generation` already
    /// do today. Closing that gap needs agreement on a core set of `>= 2t+1` contributors, which
    /// exists nowhere in this repo; this work inherits the posture rather than worsening it. The
    /// two *conversions* themselves are async-live and robust given well-formed preprocessing.
    async fn run_conversion_preprocessing<G>(
        &mut self,
        network: Arc<N>,
        rng: &mut G,
    ) -> Result<(), HoneyBadgerError>
    where
        N: 'async_trait,
        G: Rng + Send,
    {
        let started = Instant::now();
        self.ensure_edabits(network.clone(), rng).await?;
        let produced = self.conv_preprocessing_material.lock().await.length();
        trace_preprocessing_phase(self.id, "edabits", produced.edabits, started);

        let started = Instant::now();
        self.ensure_dabits_at_least(self.params.n_dabits, network, rng)
            .await?;
        let produced = self.conv_preprocessing_material.lock().await.length();
        trace_preprocessing_phase(self.id, "dabits", produced.dabits, started);
        Ok(())
    }
}

fn chunk_sizes(total: usize, max_chunk_size: usize) -> impl Iterator<Item = usize> {
    let max_chunk_size = max_chunk_size.max(1);
    (0..total)
        .step_by(max_chunk_size)
        .map(move |start| (total - start).min(max_chunk_size))
}

pub(crate) fn max_mul_pairs_per_session(threshold: usize) -> usize {
    // Mul child sessions encode batch-reconstruction children in sub_id.
    // Each batch-reconstruction chunk uses two child ids: one for a - x and one for b - y.
    128 * threshold.saturating_add(1)
}

/// GF(2^k) counterpart of [`max_mul_pairs_per_session`].
///
/// The same figure, and for the same reason: `GfMultiply` has the identical child-session shape
/// (one batch-reconstruction session for all `a - x`, one for all `b - y`, encoded in `sub_id`)
/// and emits one field element per slot in a single eval/reveal message pair. A `Gf256` element is
/// one byte against a Goldilocks element's eight, so this is if anything conservative — it is kept
/// equal so the two tracks cannot drift apart silently.
pub(crate) fn max_gf_mul_pairs_per_session(threshold: usize) -> usize {
    max_mul_pairs_per_session(threshold)
}

/// Concurrent `GfMultiply` sessions the node-level `gf_mul` will have in flight at once.
///
/// `GfBatchReconNode::get_or_create_store` admits with `initiator_id = msg.sender_id` under a
/// `MAX_GF_BATCH_RECON_SESSIONS / n` **per-peer** quota, and each `GfMultiply` session opens two
/// batch-reconstruction children — hence the halving. Past this depth a given peer's `Eval`
/// messages start being rejected and those openings silently never complete.
///
/// Capping the depth is deliberately the lever here rather than raising the quota: the quota is a
/// DoS bound, and it also happens to bound the 200-slot `mpsc` backlog inside `GfMultiply`, whose
/// `send().await` runs inline on the single message-handling path, so a full channel stalls the
/// whole node.
pub(crate) fn gf_mul_pipeline_depth(n_parties: usize) -> usize {
    (MAX_GF_BATCH_RECON_SESSIONS / n_parties.max(1) / 2).max(1)
}

/// Used for routing messages to respective sub-protocols.
///
/// # Wire-format contract
///
/// This enum is serialized by `bincode` **without a version tag**, so two things are the wire
/// format and neither can change silently:
///
/// 1. **The variant order**, which is the discriminant. New variants go at the very end, never
///    in the middle; a retired one stays in place rather than being removed. See
///    [`WrappedMessage::DaBit`], which is kept unreachable for exactly this reason.
/// 2. **The byte shape of each variant's payload.** A peer that agrees on the discriminant but
///    disagrees on the payload shape mis-parses rather than failing to decode.
///
/// ## Breaking changes on this branch, against `main`
///
/// This branch is already a deliberate wire reset against `main` and does not interoperate with
/// it. Two independent breaks, recorded together so neither is discovered on a network:
///
/// * **Discriminants.** [`ProtocolType`] 10, 15, 16, 17 and 18 name different protocols than on
///   `main` (`PRandBit` → `GfRansha`, `TripleSmallField` → `ZeroSha`, `RanShaSmallField` →
///   `GfBatchRecon`, `RanDouShaSmallField` → `GfDousha`, `DouShaSmallField` → `GfRandousha`),
///   and `WrappedMessage` itself is rewritten from position 8 onward. The retired protocols have
///   no code left in the tree. A `main` node and a node from this branch will **mis-route** each
///   other's traffic rather than reject it.
/// * **Share payload shape** (this change). The two direct point-to-point openings —
///   [`WrappedMessage::Mult`] and [`WrappedMessage::GfMult`] — used to carry whole share structs:
///   a `GfShare<K>` serialised to `element + id: usize + degree: usize` = 17 bytes for one byte
///   of secret, a `ShamirShare<F, 1, P>` to 24 for eight. They now carry
///   [`GfShareWire`](crate::common::gf2k::share::GfShareWire) /
///   [`ShamirShareWire`](crate::common::ShamirShareWire): **bare field elements only**, one `u64`
///   count per run. `id` and `degree` are absent from the wire and are re-derived by the receiver
///   from the authenticated envelope `sender` and its own `threshold`; they are not merely
///   smaller, they are unrepresentable, so a peer can no longer state either. Exact sizes, with
///   `m` shares per run:
///
///   | payload | before | after |
///   |---|---|---|
///   | `GfMultReconstructionMessage` (GF(2^8)) | `16 + 34m` | `16 + 2m` |
///   | `ReconstructionMessage` (Goldilocks) | `16 + 48m` | `16 + 16m` |
///
///   An old-format body reaching a new node is **rejected**, not misread: the count prefix and
///   the locally-derived expected share count disagree. A new-format body reaching an old node is
///   likewise refused. Nothing else moved — every other variant's payload is byte-identical, and
///   `BatchReconMsg` / `GfBatchReconMsg` already carried bare elements and are untouched.
///
/// ## What still carries a whole share struct, and why it was left
///
/// The conversion above covers the two openings on the A2B/B2A critical path. Five payloads
/// still ship `element + id + degree` per share and were **deliberately not converted** — all
/// are off that path, none is measured in the conversion cost model, and converting them would
/// churn their hand-built test payloads for no measurable byte:
///
/// | payload | per share | why it was left |
/// |---|---|---|
/// | [`WrappedMessage::Trunc`] ([`TruncPrMessage`]) | 24 B for 8 | `fpmul`, not a conversion path; one share per message, so the 16 B rides a 52 B frame |
/// | [`WrappedMessage::Dousha`] (`DouShaPayload`) | 48 B per `(t, 2t)` pair | `F` dealt double sharing, superseded by DN07/PRSS on this branch |
/// | [`WrappedMessage::GfRansha`] (`GfRanShaPayload`) | 17 B for 1 | dealt GF path; per-A2B traffic went `1390 -> 0` when PRSS keys landed |
/// | [`WrappedMessage::GfDousha`] (`GfDouShaPayload`) | 34 B per pair | same |
/// | [`WrappedMessage::GfRanDouSha`] (`GfReconstructionMessage`) | 34 B per pair | same |
///
/// The last three are the **perfect-privacy fallback**: a deployment that declines PRSS key
/// setup is their only caller, and they are then un-amortised at 17–34 bytes per byte of secret.
/// That fallback is not currently viable above `n = 4` for an unrelated liveness reason, so the
/// encoding is not costing anyone bytes today — but anyone who fixes that must re-measure it
/// before quoting a cost, and converting these is the same mechanical change made here.
///
/// [`WrappedMessage::DaBit`]'s `MaskShares` blob also still names `Vec<RobustShare<F>>` /
/// `Vec<GfShare<K>>`: that variant is unreachable and its shape is frozen as part of the
/// discriminant contract above.
#[derive(Serialize, Deserialize, Debug)]
pub enum WrappedMessage {
    RanDouSha(RanDouShaMessage),
    Rbc(Msg<SessionId>),
    BatchRecon(BatchReconMsg),
    Input(InputMessage),
    RanSha(RanShaMessage),
    Dousha(DouShaMessage),
    Output(OutputMessage),
    PRandInt(PRandIntMessage),
    /// Direct point-to-point opening of a multiplication's `(a - x)`/`(b - y)` remainder shares
    /// (used when the batch size isn't a multiple of `t + 1`). Robust interpolation tolerates up
    /// to `t` bad shares, so this doesn't need RBC's reliable-broadcast agreement — same trust
    /// model as `BatchRecon`'s point-to-point `Eval`/`Reveal` messages.
    Mult(MultMessage),
    /// Direct point-to-point opening of a TruncPr share of `(b + r)`. Same rationale as `Mult`.
    Trunc(TruncPrMessage),
    ZeroSha(zero_share::ZeroShaMessage),
    /// GF(2^k) equivalent of `RanSha`, see `gf_share_gen`.
    GfRansha(gf_share_gen::GfRanShaMessage),
    /// GF(2^k) equivalent of `BatchRecon`, see `gf_batch_recon`.
    GfBatchRecon(gf_batch_recon::GfBatchReconMsg),
    /// GF(2^k) equivalent of `Dousha`, see `gf_double_share`.
    GfDousha(gf_double_share::GfDouShaMessage),
    /// GF(2^k) equivalent of `RanDouSha`, see `gf_ran_dou_sha`.
    GfRanDouSha(gf_ran_dou_sha::GfRanDouShaMessage),
    /// GF(2^k) equivalent of `Mult`, see `gf_mul`.
    GfMult(gf_mul::GfMultMessage),
    /// **UNREACHABLE.** The dealt daBit protocol's point-to-point mask shares and RBC'd deltas.
    /// PRSS daBits replaced it and put nothing of their own on the wire; the dispatcher drops this
    /// variant with a warning instead of routing it.
    ///
    /// APPEND-ONLY: this enum is serialized by `bincode` without a version tag, so the *order* of
    /// these variants is the wire format. New variants go at the very end, never in the middle —
    /// and a retired one stays in place rather than being removed, which is why this is still
    /// here.
    DaBit(dabit::DaBitMessage),
}

impl WrappedMessage {
    pub fn rbc_wrap(msg: Msg<SessionId>) -> Result<Vec<u8>, RbcError> {
        let wrapped = WrappedMessage::Rbc(msg);
        Ok(bincode::serialize(&wrapped)?)
    }
}

//-----------------Session-ID-----------------
//Used for re-routing inter-protocol messages
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ProtocolType {
    None = 0,
    Randousha = 1,
    Ransha = 2,
    Input = 3,
    Rbc = 4,
    Triple = 5,
    BatchRecon = 6,
    Dousha = 7,
    Mul = 8,
    PRandInt = 9,
    GfRansha = 10,
    RandBit = 11,
    FpMul = 12,
    Trunc = 13,
    FpDivConst = 14,
    ZeroSha = 15,
    GfBatchRecon = 16,
    GfDousha = 17,
    GfRandousha = 18,
    GfTriple = 19,
    GfMul = 20,
    /// `PrssDaBitNode` and `EdaBitFilterNode` parent sessions.
    ///
    /// Carries **no wire traffic of its own**: PRSS daBit generation is local plus one Mod2
    /// opening, which routes under [`Self::DaBitOpen`]. The `WrappedMessage::DaBit` variant it
    /// once named is retained unreachable for wire-format stability.
    DaBit = 21,
    /// **RETIRED** with the dealt daBit protocol's `F`-side XOR fold, bit-ness products and
    /// bucket XORs.
    ///
    /// Reserved, never reused and never renumbered: this enum is `#[repr(u8)]` and `from_u8` is a
    /// wire contract, so re-pointing 22 at a different protocol would silently re-route an
    /// upgraded peer's traffic. It is classified in `dn07::phase_of` like every other tag and is
    /// routed nowhere.
    DaBitMul = 22,
    /// `Mod2Node::open` — the daBit's single degree-`t` `F`-side opening of
    /// `c = S + 2r'' + r'_0`.
    DaBitOpen = 23,
    /// `EdaBitFilterNode::gf_mul` — the AND layers of the modulus-overflow (`r < p`) filter.
    DaBitGfMul = 24,
    /// `EdaBitFilterNode::gf_open` — the degree-`t` `K`-side opening of the overflow verdict.
    DaBitGfOpen = 25,
    /// `A2BNode::open` — the degree-`t` opening of the arithmetic mask `y = x - r`.
    A2B = 26,
    /// `A2BNode::gf_mul` — one session per AND layer/chunk of the A2B circuit.
    A2BGfMul = 27,
    /// `B2ANode::gf_open` — the single degree-`t` `K`-side opening of `c_i = x_i XOR r_i`.
    B2A = 28,
    /// `Dn07MulNode` — the `F`-side degree-`2t` opening behind a DN07 preprocessing
    /// multiplication or exact-zero check. **Preprocessing only**; see `honeybadger::dn07`.
    Dn07 = 29,
    /// `GfDn07MulNode` — the `K`-side twin of [`ProtocolType::Dn07`]. **Preprocessing only.**
    GfDn07 = 30,
}

impl ProtocolTag for ProtocolType {
    #[inline]
    fn to_u8(self) -> u8 {
        self as u8
    }

    #[inline]
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::None),
            1 => Some(Self::Randousha),
            2 => Some(Self::Ransha),
            3 => Some(Self::Input),
            4 => Some(Self::Rbc),
            5 => Some(Self::Triple),
            6 => Some(Self::BatchRecon),
            7 => Some(Self::Dousha),
            8 => Some(Self::Mul),
            9 => Some(Self::PRandInt),
            10 => Some(Self::GfRansha),
            11 => Some(Self::RandBit),
            12 => Some(Self::FpMul),
            13 => Some(Self::Trunc),
            14 => Some(Self::FpDivConst),
            15 => Some(Self::ZeroSha),
            16 => Some(Self::GfBatchRecon),
            17 => Some(Self::GfDousha),
            18 => Some(Self::GfRandousha),
            19 => Some(Self::GfTriple),
            20 => Some(Self::GfMul),
            21 => Some(Self::DaBit),
            22 => Some(Self::DaBitMul),
            23 => Some(Self::DaBitOpen),
            24 => Some(Self::DaBitGfMul),
            25 => Some(Self::DaBitGfOpen),
            26 => Some(Self::A2B),
            27 => Some(Self::A2BGfMul),
            28 => Some(Self::B2A),
            29 => Some(Self::Dn07),
            30 => Some(Self::GfDn07),
            _ => None,
        }
    }
}

/// A session denotes the execution of a subprotocol in an instance.
/// The session ID uniquely identifies a given session.
/// As such, it consists of
///
/// - instance ID: binds the session to the instance
/// - protocol/caller ID: denotes the subprotocol that is being executed; if a subprotocol calls
///   another, then this will usually contain the calling subprotocols ID, hence also caller ID
/// - execution ID: differentiates between multiple execution of the same subprotocol
///
/// A message has either been sent over the wire between nodes (e.g., SEND messages in the AVID
/// protocol) or is only used locally (e.g., a MultMessage reconstructed via batch reconstruction
/// and passed to some handler).
/// Some subprotocols do not have their own messages (e.g., FPMul), since they entirely rely on subprotocols.
/// While such subprotocols may be called by other subprotocols, in the context of unique
/// identification of messages we assume that such subprotocols are never called.
/// Within a session, all messages for a given receiver are uniquely identified.
/// (Globally, this is not the case, e.g., SEND messages with different destinations in the AVID
/// protocol cannot be told apart unless the payload differs.)
/// In general, a message in a subprotocol that does not call any other subprotocls is identified by
///   - sender ID: the node ID of the sending node (not needed for locally used messages)
///   - message type: the type of the message within the subprotocol
///   - message ID: distinguishes between messages of the same type from the same sender
/// If a subprotocol does call another subprotocol, which has its own messages, the caller needs
/// to distinguish between such subprotocols (if different ones are called) and between different
/// executions of the same subprotocol (if the same is executed multiple times).
///
/// Hence, for a message that is sent in a subprotocol with `n` nested subprotocol calls, each of
/// which has their own messages, in general, the unique ID of that message is
///
/// instance ID/
/// protocol ID 0/execution ID 0/
/// protocol ID 1/execution ID 1/
/// ...
/// protocol ID n/execution ID n/
/// sender ID/message type/message ID
///
/// However, in the particular case of HoneyBadgerMPC, `n` is at most 2.
/// Protocol ID 0 is the caller ID.
/// Execution ID 0 is simply the execution ID.
///
/// instance ID/
/// caller ID/execution ID/
/// protocol ID 1/execution ID 1/
/// protocol ID 2/execution ID 2/
/// sender ID/message type/message ID
///
/// If n=1, then protocol and execution IDs 2 vanish.
/// This is still quit generic and we use a more specific layout instead:
///
/// protocol ID n/
/// instance ID/
/// caller ID/execution ID/
/// sub ID/round ID/
/// sender ID/message type
///
/// Instance, caller, execution, and sender IDs and message types map one-to-one between the two.
/// Some subprotocols do not have a message type.
/// Execution ID 1 for n=1 and protocol ID 1 and execution ID 1 and 2 for n=2 and sometimes the
/// message type map to the sub ID and round ID.
/// The message ID is not used, since we do not have any subprotocols, where a node sends multiple
/// messages of the same type to one other node.
///
/// The session ID itself consists of
///   - instance ID
///   - caller ID
///   - execution ID
///   - sub ID
///   - round ID
/// The sender ID is a separate field within a message.
/// Protocol ID n is sent as a tag to process a message directly from the network (see
/// `WrappedMessage`).
///
/// In the following, we show the mapping from protocol and execution IDs to the sub ID, round ID,
/// and the message type.
///
/// Random Double Sharing (n=2):
///   - round ID = execution ID 1
///   - sub ID = execution ID 2
/// Random Sharing (n=2):
///   - round ID = execution ID 1
///   - sub ID = execution ID 2
/// Input (n=1):
///   - round ID = 0
///   - sub ID = execution ID 1
/// Multiplication (n=1):
///   - round ID = execution ID 1
///   - sub ID = message type
/// Double Sharing (n=1):
///   - round ID = execution ID 1
///   - sub ID = 0
/// RBC (n=0):
///   - does not set its own values
/// Batch Reconstruction (n=0):
///   - does not set its own values
/// Fixed-Point Multiplication (n=2):
///   - calls multiplication once and truncation once
/// Truncation (n=1):
///   - round ID = execution ID 1
///   - sub ID = 0
/// RandBit (n=2):
///   - calls multiplication once, so no execution ID 1 needed
///   - round ID = execution ID 2
/// PRandInt (n=1):
///   - round ID = execution ID 1
///   - sub ID = 0

#[derive(PartialOrd, Ord, Clone, Serialize, Deserialize, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(u128);

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let caller = ((self.0 >> 112) & 0xFF) as u8;
        let exec_id = self.exec_id();
        let sub_id = self.sub_id();
        let round_id = self.round_id();
        let instance_id = self.instance_id();

        write!(
            f,
            "[caller={},exec_id={},sub_id={},round_id={},instance_id={}]",
            caller, exec_id, sub_id, round_id, instance_id
        )
    }
}

impl ProtocolSessionId for SessionId {
    type Protocol = ProtocolType;

    /// `slot` is the 80-bit field (round|sub|exec) produced by [`SessionId::pack_slot`].
    fn new(protocol: ProtocolType, slot: u128, instance_id: u32) -> Self {
        // Layout (128 bits): instance_id[0..32] round_id[32..40] sub_id[40..48]
        // exec_id[48..112] caller[112..120] reserved[120..128].
        let slot_mask: u128 = (1u128 << 80) - 1; // round+sub+exec = 8+8+64 bits
        let value = (((protocol as u128) & 0xFF) << 112)
            | (((slot & slot_mask) as u128) << 32)
            | (instance_id as u128);

        SessionId(value)
    }
    fn calling_protocol(self) -> Option<ProtocolType> {
        let val = ((self.0 >> 112) & 0xFF) as u8;
        ProtocolType::from_u8(val)
    }

    fn slot(self) -> u128 {
        (self.0 >> 32) & ((1u128 << 80) - 1)
    }

    fn dealer_id(self) -> u8 {
        self.sub_id()
    }

    fn instance_id(self) -> u32 {
        self.0 as u32
    }

    fn as_u128(self) -> u128 {
        self.0
    }
    /// # Safety
    /// Caller must ensure the raw value is well-formed.
    unsafe fn from_u128(id: u128) -> Self {
        SessionId(id)
    }
}

impl SessionId {
    /// Execution id — widened to 64 bits (bits 48..112) so back-to-back sessions do not wrap.
    pub fn exec_id(self) -> u64 {
        // Bits 48..112 = 64 bits; `as u64` takes the low 64 bits of the shifted value.
        (self.0 >> 48) as u64
    }

    pub fn sub_id(self) -> u8 {
        ((self.0 >> 40) & 0xFF) as u8
    }

    pub fn round_id(self) -> u8 {
        ((self.0 >> 32) & 0xFF) as u8
    }

    /// Pack the flexible field: exec_id at the top of the 80-bit slot, sub_id and round_id below.
    #[inline]
    pub fn pack_slot(exec_id: u64, sub_id: u8, round_id: u8) -> u128 {
        ((exec_id as u128) << 16) | ((sub_id as u128) << 8) | (round_id as u128)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::honeybadger::dabit::prss_dabit::DaBitLeakBudget;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    #[test]
    fn test_session_id_debug_format() {
        let caller = ProtocolType::from_u8(5u8).unwrap();
        let exec_id = 42u64;
        let sub_id = 7u8;
        let round_id = 3u8;
        let instance_id = 0xDEADBEEF;

        let session_id = SessionId::new(
            caller,
            SessionId::pack_slot(exec_id, sub_id, round_id),
            instance_id,
        );
        let debug_str = format!("{:?}", session_id);

        assert_eq!(
            debug_str,
            "[caller=5,exec_id=42,sub_id=7,round_id=3,instance_id=3735928559]"
        );
    }

    #[test]
    fn test_session_id() {
        let caller = ProtocolType::Triple;
        let exec_id = 42u64;
        let sub_id = 7u8;
        let round_id = 3u8;
        let instance_id = 0xDEADBEEF;

        let session_id = SessionId::new(
            caller,
            SessionId::pack_slot(exec_id, sub_id, round_id),
            instance_id,
        );

        assert_eq!(session_id.calling_protocol().unwrap(), caller);
        assert_eq!(session_id.exec_id(), exec_id);
        assert_eq!(session_id.sub_id(), sub_id);
        assert_eq!(session_id.round_id(), round_id);
        assert_eq!(session_id.instance_id(), instance_id);

        let session_id2 = SessionId::new(
            session_id.calling_protocol().unwrap(),
            SessionId::pack_slot(
                session_id.exec_id(),
                session_id.sub_id(),
                session_id.round_id(),
            ),
            session_id.instance_id(),
        );

        assert_eq!(session_id, session_id2);
    }

    #[tokio::test]
    async fn test_subprotocol_counter_limit_error() {
        // exec_id is 64-bit; the counter only faults at u64::MAX (effectively never reachable).
        let counter = SubProtocolCounter(Arc::new(Mutex::new(Some(u64::MAX))));
        // First call should return u64::MAX
        let val = counter.get_next().await;
        assert_eq!(val.unwrap(), u64::MAX);

        // Second call should return error (None) — the counter saturated.
        let err = counter.get_next().await;
        assert!(matches!(err, Err(HoneyBadgerError::LimitError)));
    }
    #[test]
    fn test_max_mul_pairs_per_session_tracks_child_session_space() {
        assert_eq!(max_mul_pairs_per_session(0), 128);
        assert_eq!(max_mul_pairs_per_session(1), 256);
        assert_eq!(max_mul_pairs_per_session(2), 384);
        assert_eq!(max_mul_pairs_per_session(3), 512);
    }

    /// Every tag in the enum must round-trip through `from_u8`.
    ///
    /// A variant present in `ProtocolType` but missing from `from_u8` does not fail loudly: it
    /// resolves to `None` and every message carrying it lands in a dispatch `_ => warn!("Unknown
    /// protocol ID")` arm and is silently dropped, so the protocol simply never completes. This
    /// pins the two halves together for the eight conversion tags as well as the twenty-one that
    /// came before them.
    #[test]
    fn every_protocol_tag_round_trips_through_from_u8() {
        let all = [
            ProtocolType::None,
            ProtocolType::Randousha,
            ProtocolType::Ransha,
            ProtocolType::Input,
            ProtocolType::Rbc,
            ProtocolType::Triple,
            ProtocolType::BatchRecon,
            ProtocolType::Dousha,
            ProtocolType::Mul,
            ProtocolType::PRandInt,
            ProtocolType::GfRansha,
            ProtocolType::RandBit,
            ProtocolType::FpMul,
            ProtocolType::Trunc,
            ProtocolType::FpDivConst,
            ProtocolType::ZeroSha,
            ProtocolType::GfBatchRecon,
            ProtocolType::GfDousha,
            ProtocolType::GfRandousha,
            ProtocolType::GfTriple,
            ProtocolType::GfMul,
            ProtocolType::DaBit,
            ProtocolType::DaBitMul,
            ProtocolType::DaBitOpen,
            ProtocolType::DaBitGfMul,
            ProtocolType::DaBitGfOpen,
            ProtocolType::A2B,
            ProtocolType::A2BGfMul,
            ProtocolType::B2A,
            ProtocolType::Dn07,
            ProtocolType::GfDn07,
        ];
        for tag in all {
            assert_eq!(
                ProtocolType::from_u8(tag.to_u8()),
                Some(tag),
                "tag {tag:?} does not round-trip"
            );
        }
        // Every assigned discriminant is covered, with no gap in the middle.
        for value in 0u8..=30 {
            assert!(
                ProtocolType::from_u8(value).is_some(),
                "discriminant {value} is unmapped"
            );
        }
        // The first unassigned discriminant stays unmapped, so a stale peer emitting it degrades
        // to the "unknown protocol ID" warning rather than being routed somewhere. Move this
        // number when a tag is added, and add the tag to `all` above in the same edit — the two
        // together are what keep `from_u8` and the enum from drifting apart.
        assert!(ProtocolType::from_u8(31).is_none());
    }

    /// The GF(2^k) multiplication track's chunking figures.
    ///
    /// `max_gf_mul_pairs_per_session` tracks its `F`-domain counterpart exactly — `GfMultiply` has
    /// the identical child-session shape — and the pipeline depth halves the per-peer
    /// batch-reconstruction quota because each multiplication session opens two children.
    #[test]
    fn gf_mul_chunking_figures_track_the_existing_quotas() {
        for threshold in 0..8 {
            assert_eq!(
                max_gf_mul_pairs_per_session(threshold),
                max_mul_pairs_per_session(threshold)
            );
        }
        assert_eq!(
            gf_mul_pipeline_depth(10),
            MAX_GF_BATCH_RECON_SESSIONS / 10 / 2
        );
        // Never zero, at any party count, including the degenerate ones.
        assert!(gf_mul_pipeline_depth(0) >= 1);
        assert!(gf_mul_pipeline_depth(usize::MAX) >= 1);
        assert_eq!(gf_mul_pipeline_depth(MAX_GF_BATCH_RECON_SESSIONS + 1), 1);
    }

    fn conv_opts(n: usize, t: usize, topup: Option<usize>) -> HoneyBadgerMPCNodeOpts {
        let mut params = HoneyBadgerMPCNodeOpts::new(
            n,
            t,
            1,
            1,
            0,
            0,
            0,
            FixedPointPrecision::new(32, 16),
            MIN_STATISTICAL_SECURITY,
            Duration::from_secs(1),
            0,
            0,
        )
        .unwrap();
        params.set_dabit_topup_bits(topup);
        params
    }

    /// The daBit `RandBit` top-up defaults to "unset" and is validated when the node is built,
    /// never clamped at the setter. `k` and `lambda` are one budget.
    #[test]
    fn the_dabit_topup_parameter_defaults_to_the_production_setting() {
        let params = conv_opts(10, 3, None);
        assert_eq!(params.dabit_topup_bits, None);
        let budget = DaBitLeakBudget::new::<crate::common::math::goldilocks::GoldilocksField>(
            10,
            3,
            params.statistical_security,
            params.dabit_topup_bits,
        )
        .unwrap();
        // C(10,3) = 120, ceil = 7, so the production default is k = 4 and lambda = 55.
        assert_eq!(budget.topup_bits, 4);
        assert_eq!(budget.mask_bits, 55);
        assert!(budget.max_dabits >= 1 << 20);
    }

    /// An out-of-range top-up is a hard error at node construction, never a `warn!` and never a
    /// clamp — the `l`/`kappa` misconfiguration class this repo has already shipped once.
    #[test]
    fn an_out_of_range_dabit_topup_is_refused_when_the_node_is_built() {
        type F = crate::common::math::goldilocks::GoldilocksField;
        // C(10,3) = 120, ceil = 7, so k <= 6.
        assert!(DaBitLeakBudget::new::<F>(10, 3, MIN_STATISTICAL_SECURITY, Some(6)).is_ok());
        let err = DaBitLeakBudget::new::<F>(10, 3, MIN_STATISTICAL_SECURITY, Some(7)).unwrap_err();
        assert!(
            matches!(
                err,
                DaBitError::TopUpTooLarge {
                    requested: 7,
                    max: 6
                }
            ),
            "unexpected error: {err:?}"
        );
    }
}
