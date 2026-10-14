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

pub mod bitwise;
pub mod comparison;
pub mod fpdiv;
pub mod fpmul;
pub mod input;
pub mod mul;
pub mod mul_pub;
pub mod output;
pub mod preprocessing;
pub mod prss;
pub mod rand_inv_pair;
pub mod share_gen;
#[cfg(feature = "statistics")]
pub mod statistics;
pub mod zero_share;

use crate::{
    common::{
        rbc::{rbc_store::Msg, RbcError},
        types::{
            fixed::{ClearFixedPoint, FixedPointPrecision, SecretFixedPoint},
            integer::{ClearInt, SecretInt},
            TypeError,
        },
        MPCProtocol, MPCTypeOps, PreprocessingMPCProtocol, ProtocolSessionId, ProtocolTag,
        ShamirShare, RBC,
    },
    honeybadger::{
        batch_recon::{BatchReconError, BatchReconMsg},
        bitwise::{
            kor_cs::KOrCSPrep, pre_mulc::PreMulCOfflineNode, KOrCLError, KOrCSError, KOrClMessage,
            Mod2Error, Mod2Message, PreMod2mError, PreMod2mMessage, PreMulCError, PreMulCPrep,
        },
        comparison::{eqz::EQZNode, ltz::LTZNode, EQZError, EqzMessage, LTZError},
        double_share::{double_share_generation, DouShaError, DouShaMessage, DoubleShamirShare},
        fpdiv::fpdiv::{FpDivError, FpDivNode},
        fpdiv::fpdiv_const::{FPDivConstError, FPDivConstNode},
        fpmul::{
            fpmul::{FPError, FPMulNode},
            prandint::PRandIntNode,
            rand_bit::RandBit,
            PRandIntError, PRandIntMessage, RandBitError, TruncPrError, TruncPrMessage,
        },
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
        preprocessing::{
            demand_for_eqz, demand_for_fpdiv, demand_for_fpdiv_const, demand_for_fpmul,
            demand_for_ltz, demand_for_mul, demand_for_rand, HoneyBadgerMPCNodePreprocMaterial,
            PreprocDemand,
        },
        prss::prss::{PrssKeys, PRSS_KEY_ENTROPY_BITS},
        ran_dou_sha::messages::RanDouShaMessage,
        rand_inv_pair::{
            rand_inv_pair::{RandInvPairNode, RandInvPairPrep},
            RandInvPairError,
        },
        robust_interpolate::robust_interpolate::Robust,
        share_gen::{share_gen::RanShaNode, RanShaError, RanShaMessage},
        triple_gen::TripleGenError,
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
    #[error("error in FpDiv: {0:?}")]
    FpDivError(#[from] FpDivError),
    #[error("error in PreMod2m: {0:?}")]
    PreMod2mError(#[from] PreMod2mError),
    #[error("error in Mod2: {0:?}")]
    Mod2Error(#[from] Mod2Error),
    #[error("error in PreMulC: {0:?}")]
    PreMulCError(#[from] PreMulCError),
    #[error("error in LTZ: {0:?}")]
    LTZError(#[from] LTZError),
    #[error("error in EQZ: {0:?}")]
    EQZError(#[from] EQZError),
    #[error("error in RandInvPair: {0:?}")]
    RandInvPairError(#[from] RandInvPairError),
    #[error("error in KOrCS: {0:?}")]
    KOrCSError(#[from] KOrCSError),
    #[error("error in KOrCL: {0:?}")]
    KOrCLError(#[from] KOrCLError),
    #[error("share error: {0:?}")]
    ShareError(#[from] crate::common::share::ShareError),
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
    #[error("session id {0:?} uses reserved bits: not a canonically constructed session id")]
    InvalidSessionId(SessionId),
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
        if id < n || id > u8::MAX as usize {
            return Err(InputError::InvalidClientId(id, n).into());
        }
        let input = InputClient::new(id, n, t, instance_id, inputs)?;
        let output = OutputClient::new(id, n, t, instance_id, input_len)?;
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
                self.input.process(sender_id, input_msg, net).await?;
            }
            WrappedMessage::Output(output_msg) => {
                self.output.process(sender_id, output_msg).await?
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

        let keys = PrssKeys::<F>::new(self.id, self.params.n_parties, self.params.threshold, &keys)
            .map_err(PRandIntError::from)?;
        self.preprocess.prand_int.install_prss_keys(keys);
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
        format!(
            "material=(triples:{triples},random:{random_shares},randbit:{randbit},prandint:{prandint}) \
             stores=(share_gen:{},dou_sha:{},ran_dou_sha:{},triple:{},triple_batch_recon:{},mul:{},rand_bit:{},rand_bit_mul_pub:{},zero_sha:{},prand_int:{},fpmul_mul:{},fpmul_trunc:{})",
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
    pub fpdiv: FpDivNode<F>,
    pub ltz: LTZNode<F>,
    pub eqz: EQZNode<F>,
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
    /// PreMulC's offline (preprocessing) phase: generates the correlated
    /// (w, z, r) from fresh random shares,
    /// zero-sharings, and Beaver triples.
    pub premulc_offline: PreMulCOfflineNode<F>,
    /// Produces the ([r], [r^-1]) pairs consumed by EQZ's KOrCS.
    pub rand_inv_pair: RandInvPairNode<F>,
}

#[derive(Clone, Debug)]
pub struct SubProtocolCounter(Arc<Mutex<Option<u64>>>);

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
    pub fpdiv_counter: SubProtocolCounter,
    pub premulc_off_counter: SubProtocolCounter,
    pub ltz_counter: SubProtocolCounter,
    pub eqz_counter: SubProtocolCounter,
    pub rand_inv_pair_counter: SubProtocolCounter,
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
            fpdiv_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            zero_sha_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            premulc_off_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            ltz_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            eqz_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
            rand_inv_pair_counter: SubProtocolCounter(Arc::new(Mutex::new(Some(0)))),
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
    /// Identifies one execution of the whole n-party protocol — not a per-client id.
    /// Must be identical across all n servers and every client participating in this
    /// execution (multiple clients computing together share one value), checked against
    /// it on every direct Input/Output message. Every new execution, including a retry
    /// after a prior one failed or aborted, must use a value that was never used before:
    /// reusing a dead run's id would let a message still in flight from that run be
    /// accepted as belonging to the new one.
    pub instance_id: u32,
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
    /// Planned online workload, declared up front as `(bit_width, count)` so the
    /// offline phase can generate everything in bulk.
    ///
    /// HoneyBadger is preprocessing-based — the online path should only *draw*
    /// material, never generate it. Declaring the workload here lets
    /// `run_preprocessing` derive every raw pool size (via `PreprocDemand`)
    /// instead of each call site recomputing it. Multiple entries are allowed,
    /// so a node can serve mixed widths (int8 and int64) in one program.
    pub ltz_ops: Vec<(usize, usize)>,
    /// Planned `eqz_int`/`eq_int` workload as `(bit_width, count)`.
    pub eqz_ops: Vec<(usize, usize)>,
    /// Planned `div_fixed` workload as `(k, f, count)`.
    pub fpdiv_ops: Vec<(usize, usize, usize)>,
    /// Planned secure multiplications — `mul` calls, plus one per element of
    /// each `mul_int`/`mul_fixed` batch.
    pub mul_ops: usize,
    /// Planned `mul_fixed` workload as `(f, count)`.
    pub fpmul_ops: Vec<(usize, usize)>,
    /// Planned `div_with_const_fixed` workload as `(f, count)`.
    pub fpdiv_const_ops: Vec<(usize, usize)>,
    /// Planned raw random-share draws: `rand` calls and input masks.
    pub rand_ops: usize,
    /// Material to generate on top of what the declared operations imply.
    ///
    /// The declarations above are the normal way to size preprocessing. This is
    /// the one escape hatch, for the cases that genuinely aren't an operation —
    /// benchmarking generation throughput, or reserving stock for a consumer
    /// that draws from `preprocessing_material` directly (the input protocol
    /// hands its masks to `InputServer::init`, so the embedder pulls those
    /// itself). It is the same `PreprocDemand` the model uses internally, so
    /// there is still exactly one vocabulary for "material needed".
    pub extra_demand: PreprocDemand,
}

impl HoneyBadgerMPCNodeOpts {
    /// Creates a new struct of initialization options for the HoneyBadgerMPCNode protocol.
    pub fn new(
        n_parties: usize,
        threshold: usize,
        instance_id: u32,
        precision: FixedPointPrecision,
        statistical_security: usize,
        timeout: Duration,
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
            instance_id,
            precision,
            statistical_security,
            timeout,
            ltz_ops: Vec::new(),
            eqz_ops: Vec::new(),
            fpdiv_ops: Vec::new(),
            mul_ops: 0,
            fpmul_ops: Vec::new(),
            fpdiv_const_ops: Vec::new(),
            rand_ops: 0,
            extra_demand: PreprocDemand::default(),
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

    /// Declares `count` planned `ltz_int` calls at bit width `bit_len`
    /// (`gtz`/`lez`/`gez`/`lt`/`gt`/`le`/`ge` each cost one LTZ too).
    ///
    /// Accumulates, so calling it repeatedly with different widths provisions
    /// for all of them.
    pub fn add_ltz_ops(&mut self, bit_len: usize, count: usize) {
        self.ltz_ops.push((bit_len, count));
    }

    /// Declares `count` planned `eqz_int`/`eq_int` calls at bit width `bit_len`.
    pub fn add_eqz_ops(&mut self, bit_len: usize, count: usize) {
        self.eqz_ops.push((bit_len, count));
    }

    /// Declares `count` planned `div_fixed` calls at precision `(k, f)`.
    pub fn add_fpdiv_ops(&mut self, k: usize, f: usize, count: usize) {
        self.fpdiv_ops.push((k, f, count));
    }

    /// Declares `count` planned secure multiplications (one Beaver triple each).
    /// A `mul_int`/`mul` batch of `n` elements counts as `n`.
    pub fn add_mul_ops(&mut self, count: usize) {
        self.mul_ops += count;
    }

    /// Declares `count` planned `mul_fixed` calls at fractional precision `f`.
    pub fn add_fpmul_ops(&mut self, f: usize, count: usize) {
        self.fpmul_ops.push((f, count));
    }

    /// Declares `count` planned `div_with_const_fixed` calls at precision `f`.
    pub fn add_fpdiv_const_ops(&mut self, f: usize, count: usize) {
        self.fpdiv_const_ops.push((f, count));
    }

    /// Declares `count` planned raw random-share draws (`rand`, input masks).
    pub fn add_rand_ops(&mut self, count: usize) {
        self.rand_ops += count;
    }

    /// Total raw material implied by every declared operation.
    ///
    /// This is the single place operations are translated into pool sizes;
    /// `run_preprocessing` adds it on top of the explicitly-configured
    /// declared operations.
    pub fn declared_demand(&self) -> PreprocDemand {
        let mut total = PreprocDemand::default();
        for &(bit_len, count) in &self.ltz_ops {
            if bit_len >= 3 && count > 0 {
                total.add(&demand_for_ltz(bit_len).scaled(count));
            }
        }
        for &(bit_len, count) in &self.eqz_ops {
            if bit_len >= 1 && count > 0 {
                total.add(&demand_for_eqz(bit_len).scaled(count));
            }
        }
        for &(k, f, count) in &self.fpdiv_ops {
            if k >= 3 && count > 0 {
                total.add(&demand_for_fpdiv(k, f).scaled(count));
            }
        }
        for &(f, count) in &self.fpmul_ops {
            if count > 0 {
                total.add(&demand_for_fpmul(f).scaled(count));
            }
        }
        for &(f, count) in &self.fpdiv_const_ops {
            if count > 0 {
                total.add(&demand_for_fpdiv_const(f).scaled(count));
            }
        }
        total.add(&demand_for_mul(self.mul_ops));
        total.add(&demand_for_rand(self.rand_ops));
        total.add(&self.extra_demand);
        total
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
        let fpdiv_node = FpDivNode::new(id, params.n_parties, params.threshold)?;
        let ltz_node = LTZNode::new(id, params.n_parties, params.threshold)?;
        let eqz_node = EQZNode::new(id, params.n_parties, params.threshold)?;
        let rand_inv_pair_node = RandInvPairNode::new(id, params.n_parties, params.threshold)?;
        let premulc_offline_node = PreMulCOfflineNode::new(id, params.n_parties, params.threshold)?;
        let input = InputServer::new(
            id,
            params.n_parties,
            params.threshold,
            params.instance_id,
            input_ids,
        )?;
        let output = OutputServer::new(id, params.n_parties, params.instance_id)?;
        let rand_bit_node = RandBit::new(id, params.n_parties, params.threshold)?;
        let zero_sha_node =
            ZeroShaNode::new(id, params.n_parties, params.threshold, params.threshold + 1)?;

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
                premulc_offline: premulc_offline_node,
                rand_inv_pair: rand_inv_pair_node,
            },
            operations: Operation { mul: mul_node },
            type_ops: TypeOperations {
                fpmul: fpmul_node,
                fpdiv_const: fpdiv_const_node,
                fpdiv: fpdiv_node,
                ltz: ltz_node,
                eqz: eqz_node,
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

        if let WrappedMessage::Rbc(m) = &wrapped {
            if !m.session_id.is_canonical() {
                return Err(HoneyBadgerError::InvalidSessionId(m.session_id));
            }
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
        if is_client_input_broadcast
            && !self
                .preprocess
                .input
                .status_receiver
                .borrow()
                .contains_key(&sender_id)
        {
            warn!(
                "Rejecting client input broadcast: sender {} is not a registered input client",
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
                    _ => {
                        warn!(
                            "Unknown protocol ID in session ID: {:?} in RBC",
                            rbc_msg.session_id
                        );
                    }
                }
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
                    Some(ProtocolType::PreMulCOff) => {
                        self.preprocess
                            .premulc_offline
                            .mul
                            .process(mult_msg.sender, mult_msg.session_id, mult_msg.payload)
                            .await?;
                    }
                    Some(ProtocolType::FpDivMulA) | Some(ProtocolType::FpDivMulB) => {
                        self.type_ops
                            .fpdiv
                            .mul
                            .process(mult_msg.sender, mult_msg.session_id, mult_msg.payload)
                            .await?;
                    }
                    Some(ProtocolType::LTZBitMul) => {
                        self.type_ops
                            .ltz
                            .pre_mod2m
                            .pre_bitlt
                            .mul
                            .process(mult_msg.sender, mult_msg.session_id, mult_msg.payload)
                            .await?;
                    }
                    Some(ProtocolType::LTZ) => {
                        self.type_ops
                            .ltz
                            .pre_mod2m
                            .pre_bitlt
                            .suf_mul_inv
                            .inner
                            .mul
                            .process(mult_msg.sender, mult_msg.session_id, mult_msg.payload)
                            .await?;
                    }
                    Some(ProtocolType::KOr1) | Some(ProtocolType::KOr2) => {
                        self.type_ops
                            .eqz
                            .kor_cl
                            .kor_cs
                            .mul
                            .process(mult_msg.sender, mult_msg.session_id, mult_msg.payload)
                            .await?;
                    }
                    Some(ProtocolType::PreBitMul3) => {
                        self.type_ops
                            .fpdiv
                            .app_rec
                            .bit_dec
                            .pre_mod2m
                            .pre_bitlt
                            .mul
                            .process(mult_msg.sender, mult_msg.session_id, mult_msg.payload)
                            .await?;
                    }
                    Some(ProtocolType::PreBitMul)
                    | Some(ProtocolType::PreBitMul1)
                    | Some(ProtocolType::PreBitMul2) => {
                        self.type_ops
                            .fpdiv
                            .app_rec
                            .mul
                            .process(mult_msg.sender, mult_msg.session_id, mult_msg.payload)
                            .await?;
                    }
                    Some(ProtocolType::SufOr) => {
                        self.type_ops
                            .fpdiv
                            .app_rec
                            .suf_or
                            .inner
                            .mul
                            .process(mult_msg.sender, mult_msg.session_id, mult_msg.payload)
                            .await?;
                    }
                    Some(ProtocolType::FpDiv) => {
                        // BitDec's nested SufMulInv's embedded Multiply.
                        self.type_ops
                            .fpdiv
                            .app_rec
                            .bit_dec
                            .pre_mod2m
                            .pre_bitlt
                            .suf_mul_inv
                            .inner
                            .mul
                            .process(mult_msg.sender, mult_msg.session_id, mult_msg.payload)
                            .await?;
                    }
                    _ => {
                        warn!(
                            "Unknown protocol ID in session ID: {:?} in Mult",
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
                    Some(ProtocolType::FpDivTrunc) => {
                        self.type_ops.fpdiv.trunc.process(trunc_msg).await?;
                    }
                    Some(ProtocolType::FpDiv) => {
                        // AppRec's own final TruncPr reveal.
                        self.type_ops.fpdiv.app_rec.trunc.process(trunc_msg).await?;
                    }
                    _ => {
                        warn!(
                            "Unknown protocol ID in session ID: {:?} in Trunc",
                            trunc_msg.session_id
                        );
                    }
                }
            }
            WrappedMessage::Mod2(mod2_msg) => {
                if sender_id != mod2_msg.sender {
                    return Err(HoneyBadgerError::InvalidPartyId);
                }
                if mod2_msg.session_id.instance_id() != self.params.instance_id {
                    return Err(HoneyBadgerError::InstanceIdError(
                        mod2_msg.session_id.instance_id(),
                    ));
                }
                match mod2_msg.session_id.calling_protocol() {
                    Some(ProtocolType::LTZ) => {
                        self.type_ops
                            .ltz
                            .pre_mod2m
                            .pre_bitlt
                            .mod2
                            .process(mod2_msg)
                            .await?;
                    }
                    Some(ProtocolType::FpDiv) => {
                        self.type_ops
                            .fpdiv
                            .app_rec
                            .bit_dec
                            .pre_mod2m
                            .pre_bitlt
                            .mod2
                            .process(mod2_msg)
                            .await?;
                    }
                    _ => {
                        warn!(
                            "Unknown protocol ID in session ID: {:?} in Mod2",
                            mod2_msg.session_id
                        );
                    }
                }
            }
            WrappedMessage::PreMod2m(pre_mod2m_msg) => {
                if sender_id != pre_mod2m_msg.sender {
                    return Err(HoneyBadgerError::InvalidPartyId);
                }
                if pre_mod2m_msg.session_id.instance_id() != self.params.instance_id {
                    return Err(HoneyBadgerError::InstanceIdError(
                        pre_mod2m_msg.session_id.instance_id(),
                    ));
                }
                match pre_mod2m_msg.session_id.calling_protocol() {
                    Some(ProtocolType::LTZ) => {
                        self.type_ops.ltz.pre_mod2m.process(pre_mod2m_msg).await?;
                    }
                    Some(ProtocolType::FpDiv) => {
                        // BitDec's own PreMod2m reveal.
                        self.type_ops
                            .fpdiv
                            .app_rec
                            .bit_dec
                            .pre_mod2m
                            .process(pre_mod2m_msg)
                            .await?;
                    }
                    _ => {
                        warn!(
                            "Unknown protocol ID in session ID: {:?} in PreMod2m",
                            pre_mod2m_msg.session_id
                        );
                    }
                }
            }
            WrappedMessage::KOrCl(kor_cl_msg) => {
                if sender_id != kor_cl_msg.sender {
                    return Err(HoneyBadgerError::InvalidPartyId);
                }
                if kor_cl_msg.session_id.instance_id() != self.params.instance_id {
                    return Err(HoneyBadgerError::InstanceIdError(
                        kor_cl_msg.session_id.instance_id(),
                    ));
                }
                match kor_cl_msg.session_id.calling_protocol() {
                    Some(ProtocolType::EQZ) => {
                        self.type_ops.eqz.kor_cl.process(kor_cl_msg).await?;
                    }
                    _ => {
                        warn!(
                            "Unknown protocol ID in session ID: {:?} in KOrCl",
                            kor_cl_msg.session_id
                        );
                    }
                }
            }
            WrappedMessage::Eqz(eqz_msg) => {
                if sender_id != eqz_msg.sender {
                    return Err(HoneyBadgerError::InvalidPartyId);
                }
                if eqz_msg.session_id.instance_id() != self.params.instance_id {
                    return Err(HoneyBadgerError::InstanceIdError(
                        eqz_msg.session_id.instance_id(),
                    ));
                }
                match eqz_msg.session_id.calling_protocol() {
                    Some(ProtocolType::EQZ) => {
                        self.type_ops.eqz.process(eqz_msg).await?;
                    }
                    _ => {
                        warn!(
                            "Unknown protocol ID in session ID: {:?} in Eqz",
                            eqz_msg.session_id
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
                    Some(ProtocolType::PreMulCOff) if batch_msg.session_id.round_id() == 0 => {
                        self.preprocess
                            .premulc_offline
                            .mul_pub
                            .batch_recon
                            .process(batch_msg, net)
                            .await?;
                        self.preprocess
                            .premulc_offline
                            .mul_pub
                            .drain_batch_recon_output()
                            .await?;
                    }
                    Some(ProtocolType::PreMulCOff) => {
                        self.preprocess
                            .premulc_offline
                            .mul
                            .batch_recon
                            .process(batch_msg, net)
                            .await?;
                        self.preprocess
                            .premulc_offline
                            .mul
                            .drain_batch_recon_output()
                            .await?;
                    }
                    Some(ProtocolType::FpDivMulA) | Some(ProtocolType::FpDivMulB) => {
                        self.type_ops
                            .fpdiv
                            .mul
                            .batch_recon
                            .process(batch_msg, net)
                            .await?;
                        self.type_ops.fpdiv.mul.drain_batch_recon_output().await?;
                    }
                    Some(ProtocolType::PreBitMul3) => {
                        self.type_ops
                            .fpdiv
                            .app_rec
                            .bit_dec
                            .pre_mod2m
                            .pre_bitlt
                            .mul
                            .batch_recon
                            .process(batch_msg, net)
                            .await?;
                        self.type_ops
                            .fpdiv
                            .app_rec
                            .bit_dec
                            .pre_mod2m
                            .pre_bitlt
                            .mul
                            .drain_batch_recon_output()
                            .await?;
                    }
                    Some(ProtocolType::LTZBitMul) => {
                        self.type_ops
                            .ltz
                            .pre_mod2m
                            .pre_bitlt
                            .mul
                            .batch_recon
                            .process(batch_msg, net)
                            .await?;
                        self.type_ops
                            .ltz
                            .pre_mod2m
                            .pre_bitlt
                            .mul
                            .drain_batch_recon_output()
                            .await?;
                    }
                    Some(ProtocolType::LTZ) => {
                        // round 0 = SufMulInv's own reveal, round 1 = its
                        // inner Multiply's — mirrors the FpDiv arm below.
                        let round = batch_msg.session_id.round_id();
                        if round == 0 {
                            self.type_ops
                                .ltz
                                .pre_mod2m
                                .pre_bitlt
                                .suf_mul_inv
                                .inner
                                .batch_recon
                                .process(batch_msg, net)
                                .await?;
                            self.type_ops
                                .ltz
                                .pre_mod2m
                                .pre_bitlt
                                .suf_mul_inv
                                .inner
                                .drain_batch_recon_output()
                                .await?;
                        } else if round == 1 {
                            self.type_ops
                                .ltz
                                .pre_mod2m
                                .pre_bitlt
                                .suf_mul_inv
                                .inner
                                .mul
                                .batch_recon
                                .process(batch_msg, net)
                                .await?;
                            self.type_ops
                                .ltz
                                .pre_mod2m
                                .pre_bitlt
                                .suf_mul_inv
                                .inner
                                .mul
                                .drain_batch_recon_output()
                                .await?;
                        } else {
                            warn!("unexpected LTZ BatchRecon round_id {round}");
                        }
                    }
                    Some(ProtocolType::KOr1) | Some(ProtocolType::KOr2) => {
                        self.type_ops
                            .eqz
                            .kor_cl
                            .kor_cs
                            .mul
                            .batch_recon
                            .process(batch_msg, net)
                            .await?;
                        self.type_ops
                            .eqz
                            .kor_cl
                            .kor_cs
                            .mul
                            .drain_batch_recon_output()
                            .await?;
                    }
                    Some(ProtocolType::EQZ) => {
                        // KOrCS's own d_j openings (its Multiply rounds carry
                        // the KOr1/KOr2 tags handled above).
                        self.type_ops
                            .eqz
                            .kor_cl
                            .kor_cs
                            .batch_recon
                            .process(batch_msg, net)
                            .await?;
                        self.type_ops
                            .eqz
                            .kor_cl
                            .kor_cs
                            .drain_batch_recon_output()
                            .await?;
                    }
                    Some(ProtocolType::RandInvPair) => {
                        self.preprocess
                            .rand_inv_pair
                            .mul_pub
                            .batch_recon
                            .process(batch_msg, net)
                            .await?;
                        self.preprocess
                            .rand_inv_pair
                            .mul_pub
                            .drain_batch_recon_output()
                            .await?;
                    }
                    Some(ProtocolType::PreBitMul)
                    | Some(ProtocolType::PreBitMul1)
                    | Some(ProtocolType::PreBitMul2) => {
                        self.type_ops
                            .fpdiv
                            .app_rec
                            .mul
                            .batch_recon
                            .process(batch_msg, net)
                            .await?;
                        self.type_ops
                            .fpdiv
                            .app_rec
                            .mul
                            .drain_batch_recon_output()
                            .await?;
                    }
                    Some(ProtocolType::SufOr) => {
                        if batch_msg.session_id.round_id() == 0 {
                            self.type_ops
                                .fpdiv
                                .app_rec
                                .suf_or
                                .inner
                                .batch_recon
                                .process(batch_msg, net)
                                .await?;
                            self.type_ops
                                .fpdiv
                                .app_rec
                                .suf_or
                                .inner
                                .drain_batch_recon_output()
                                .await?;
                        } else {
                            self.type_ops
                                .fpdiv
                                .app_rec
                                .suf_or
                                .inner
                                .mul
                                .batch_recon
                                .process(batch_msg, net)
                                .await?;
                            self.type_ops
                                .fpdiv
                                .app_rec
                                .suf_or
                                .inner
                                .mul
                                .drain_batch_recon_output()
                                .await?;
                        }
                    }
                    Some(ProtocolType::FpDiv) => {
                        let round = batch_msg.session_id.round_id();
                        if round == 0 {
                            self.type_ops
                                .fpdiv
                                .app_rec
                                .bit_dec
                                .pre_mod2m
                                .pre_bitlt
                                .suf_mul_inv
                                .inner
                                .batch_recon
                                .process(batch_msg, net)
                                .await?;
                            self.type_ops
                                .fpdiv
                                .app_rec
                                .bit_dec
                                .pre_mod2m
                                .pre_bitlt
                                .suf_mul_inv
                                .inner
                                .drain_batch_recon_output()
                                .await?;
                        } else if round == 1 {
                            self.type_ops
                                .fpdiv
                                .app_rec
                                .bit_dec
                                .pre_mod2m
                                .pre_bitlt
                                .suf_mul_inv
                                .inner
                                .mul
                                .batch_recon
                                .process(batch_msg, net)
                                .await?;
                            self.type_ops
                                .fpdiv
                                .app_rec
                                .bit_dec
                                .pre_mod2m
                                .pre_bitlt
                                .suf_mul_inv
                                .inner
                                .mul
                                .drain_batch_recon_output()
                                .await?;
                        } else {
                            warn!("unexpected FpDiv BatchRecon round_id {round}");
                        }
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

    /// Fixed-point division with a secret divisor: x / y, plus a flag
    /// indicating whether y was zero (output is only meaningful when the
    /// flag is false).
    async fn div_fixed(
        &mut self,
        x: SecretFixedPoint<F, RobustShare<F>>,
        y: SecretFixedPoint<F, RobustShare<F>>,
        net: Arc<N>,
    ) -> Result<(SecretFixedPoint<F, RobustShare<F>>, RobustShare<F>), Self::Error> {
        if x.precision() != y.precision() {
            return Err(HoneyBadgerError::FPError(FPError::IncompatiblePrecision));
        }
        let k = x.precision().k();
        let f = x.precision().f();

        // Top up if the pool is short. Sizing lives in `PreprocDemand` and is
        // applied by `run_preprocessing` from the declared workload
        // (`add_fpdiv_ops`); FpDiv needs two PreMulC bundles at pk = k-1.
        let need = demand_for_fpdiv(k, f);
        let pk = k - 1;
        let mut rng = StdRng::from_rng(OsRng).unwrap();
        let short = {
            let store = self.preprocessing_material.lock().await;
            let len = store.length();
            len.beaver_triples < need.triples
                || len.random_shr < need.random_shares
                || len.randbit < need.randbit
                || len.prandint < need.prandint
                || store.premulc_len(pk) < 2
        };
        if short {
            self.run_preprocessing(net.clone(), &mut rng).await?;
        }

        let prep = {
            let mut store = self.preprocessing_material.lock().await;
            let bitdec_suf_mul_inv_prep = store.take_premulc_prep(pk)?;
            let sufor_prep = store.take_premulc_prep(pk)?;
            store.build_fpdiv_prep(k, f, bitdec_suf_mul_inv_prep, sufor_prep)?
        };

        let session_id = SessionId::new(
            ProtocolType::FpDiv,
            SessionId::pack_slot(self.counters.fpdiv_counter.get_next().await?, 0, 0),
            self.params.instance_id,
        );

        let (c, z) = self
            .type_ops
            .fpdiv
            .init(
                x.value().clone(),
                y.value().clone(),
                x.precision().k(),
                x.precision().f(),
                prep,
                session_id,
                net.clone(),
                self.params.timeout,
            )
            .await
            .map_err(HoneyBadgerError::from)?;

        Ok((c, z))
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
    /// x<0 Integer comparison (int8/16/32/64)
    async fn ltz_int(&mut self, x: Self::Sint, net: Arc<N>) -> Result<Self::Sint, Self::Error> {
        let k = x.bit_length();
        let bit = self.ltz_on_share(x.share().clone(), k, net).await?;
        Ok(SecretInt::new(bit, k))
    }
    async fn gtz_int(&mut self, x: Self::Sint, net: Arc<N>) -> Result<Self::Sint, Self::Error> {
        let k = x.bit_length();
        let neg_x = (x * ClearInt::new(-F::one(), k))?;
        self.ltz_int(neg_x, net).await
    }

    async fn lez_int(&mut self, x: Self::Sint, net: Arc<N>) -> Result<Self::Sint, Self::Error> {
        let k = x.bit_length();
        let neg_x = (x * ClearInt::new(-F::one(), k))?;
        let ltz = self.ltz_int(neg_x, net).await?;
        let k2 = ltz.bit_length();
        let neg_ltz = (ltz * ClearInt::new(-F::one(), k2))?;
        Ok((neg_ltz + ClearInt::new(F::one(), k2))?)
    }

    async fn gez_int(&mut self, x: Self::Sint, net: Arc<N>) -> Result<Self::Sint, Self::Error> {
        let ltz = self.ltz_int(x, net).await?;
        let k = ltz.bit_length();
        let neg_ltz = (ltz * ClearInt::new(-F::one(), k))?;
        Ok((neg_ltz + ClearInt::new(F::one(), k))?)
    }

    async fn lt_int(
        &mut self,
        a: Self::Sint,
        b: Self::Sint,
        net: Arc<N>,
    ) -> Result<Self::Sint, Self::Error> {
        self.ltz_int((a - b)?, net).await
    }

    async fn gt_int(
        &mut self,
        a: Self::Sint,
        b: Self::Sint,
        net: Arc<N>,
    ) -> Result<Self::Sint, Self::Error> {
        self.ltz_int((b - a)?, net).await
    }

    async fn le_int(
        &mut self,
        a: Self::Sint,
        b: Self::Sint,
        net: Arc<N>,
    ) -> Result<Self::Sint, Self::Error> {
        let ltz = self.ltz_int((b - a)?, net).await?;
        let k = ltz.bit_length();
        Ok(((ltz * ClearInt::new(-F::one(), k))? + ClearInt::new(F::one(), k))?)
    }

    async fn ge_int(
        &mut self,
        a: Self::Sint,
        b: Self::Sint,
        net: Arc<N>,
    ) -> Result<Self::Sint, Self::Error> {
        let ltz = self.ltz_int((a - b)?, net).await?;
        let k = ltz.bit_length();
        Ok(((ltz * ClearInt::new(-F::one(), k))? + ClearInt::new(F::one(), k))?)
    }
    async fn eqz_int(&mut self, x: Self::Sint, net: Arc<N>) -> Result<Self::Sint, Self::Error> {
        let k = x.bit_length();
        let bit = self.eqz_on_share(x.share().clone(), k, net).await?;
        Ok(SecretInt::new(bit, k))
    }

    async fn eq_int(
        &mut self,
        a: Self::Sint,
        b: Self::Sint,
        net: Arc<N>,
    ) -> Result<Self::Sint, Self::Error> {
        self.eqz_int((a - b)?, net).await
    }

    // ── Fixed-point comparison ────────────────────────────────────────────────
    //
    // Each of these is the corresponding integer comparison run on the
    // underlying scaled integer: at a shared precision (k, f), `a < b` holds
    // exactly when the stored k-bit integers compare that way. The result bit is
    // scaled by `2^f` on the way out so `true` reads as `1.0`.

    async fn ltz_fixed(&mut self, x: Self::Sfix, net: Arc<N>) -> Result<Self::Sfix, Self::Error> {
        let precision = *x.precision();
        let bit = self
            .ltz_on_share(x.value().clone(), precision.k(), net)
            .await?;
        Ok(SecretFixedPoint::from_bit(bit, precision)?)
    }

    async fn gtz_fixed(&mut self, x: Self::Sfix, net: Arc<N>) -> Result<Self::Sfix, Self::Error> {
        let precision = *x.precision();
        let neg = (x.value().clone() * (-F::one()))?;
        let bit = self.ltz_on_share(neg, precision.k(), net).await?;
        Ok(SecretFixedPoint::from_bit(bit, precision)?)
    }

    async fn lez_fixed(&mut self, x: Self::Sfix, net: Arc<N>) -> Result<Self::Sfix, Self::Error> {
        // x <= 0  <=>  not (x > 0)  <=>  not ltz(-x)
        let precision = *x.precision();
        let neg = (x.value().clone() * (-F::one()))?;
        let bit = self.ltz_on_share(neg, precision.k(), net).await?;
        let bit = ((bit * (-F::one()))? + F::one())?; // NOT
        Ok(SecretFixedPoint::from_bit(bit, precision)?)
    }

    async fn gez_fixed(&mut self, x: Self::Sfix, net: Arc<N>) -> Result<Self::Sfix, Self::Error> {
        let precision = *x.precision();
        let bit = self
            .ltz_on_share(x.value().clone(), precision.k(), net)
            .await?;
        let bit = ((bit * (-F::one()))? + F::one())?; // NOT
        Ok(SecretFixedPoint::from_bit(bit, precision)?)
    }

    async fn lt_fixed(
        &mut self,
        a: Self::Sfix,
        b: Self::Sfix,
        net: Arc<N>,
    ) -> Result<Self::Sfix, Self::Error> {
        let diff = (a - b)?;
        let precision = *diff.precision();
        let bit = self
            .ltz_on_share(diff.value().clone(), precision.k() + 1, net)
            .await?;
        Ok(SecretFixedPoint::from_bit(bit, precision)?)
    }

    async fn gt_fixed(
        &mut self,
        a: Self::Sfix,
        b: Self::Sfix,
        net: Arc<N>,
    ) -> Result<Self::Sfix, Self::Error> {
        let diff = (b - a)?;
        let precision = *diff.precision();
        let bit = self
            .ltz_on_share(diff.value().clone(), precision.k() + 1, net)
            .await?;
        Ok(SecretFixedPoint::from_bit(bit, precision)?)
    }

    async fn le_fixed(
        &mut self,
        a: Self::Sfix,
        b: Self::Sfix,
        net: Arc<N>,
    ) -> Result<Self::Sfix, Self::Error> {
        // a <= b  <=>  not (b < a)
        let diff = (b - a)?;
        let precision = *diff.precision();
        let bit = self
            .ltz_on_share(diff.value().clone(), precision.k() + 1, net)
            .await?;
        let bit = ((bit * (-F::one()))? + F::one())?; // NOT
        Ok(SecretFixedPoint::from_bit(bit, precision)?)
    }

    async fn ge_fixed(
        &mut self,
        a: Self::Sfix,
        b: Self::Sfix,
        net: Arc<N>,
    ) -> Result<Self::Sfix, Self::Error> {
        let diff = (a - b)?;
        let precision = *diff.precision();
        let bit = self
            .ltz_on_share(diff.value().clone(), precision.k() + 1, net)
            .await?;
        let bit = ((bit * (-F::one()))? + F::one())?; // NOT
        Ok(SecretFixedPoint::from_bit(bit, precision)?)
    }

    async fn eqz_fixed(
        &mut self,
        x: Self::Sfix,
        tol_bits: usize,
        net: Arc<N>,
    ) -> Result<Self::Sfix, Self::Error> {
        // The two comparisons inside evaluate `x -/+ 2^tol_bits`, one bit wider
        // than `x` itself.
        let precision = *x.precision();
        let bit = self
            .abs_below_pow2(x.value().clone(), precision.k() + 1, tol_bits, net)
            .await?;
        Ok(SecretFixedPoint::from_bit(bit, precision)?)
    }

    async fn eq_fixed(
        &mut self,
        a: Self::Sfix,
        b: Self::Sfix,
        tol_bits: usize,
        net: Arc<N>,
    ) -> Result<Self::Sfix, Self::Error> {
        // `a - b` spans one more bit than either operand, and the comparisons
        // inside add one more on top of that.
        let diff = (a - b)?;
        let precision = *diff.precision();
        let bit = self
            .abs_below_pow2(diff.value().clone(), precision.k() + 2, tol_bits, net)
            .await?;
        Ok(SecretFixedPoint::from_bit(bit, precision)?)
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

        // What the declared workload needs, and what that leaves to generate
        // once the pools are accounted for. Both are computed by the demand
        // model rather than here — see `PreprocDemand::to_generate` for the two
        // wrinkles it folds in (TripleGen's `2t+1` group rounding, and the 2
        // random shares each generated triple consumes).
        let demand = self.params.declared_demand();
        let plan = {
            let store = self.preprocessing_material.lock().await;
            demand.to_generate(&store.length(), self.params.threshold)
        };
        let group_size = 2 * self.params.threshold + 1;
        let total_triples_to_generate = plan.triples;
        let total_random_shares_to_generate = plan.random_shares;

        if plan.is_empty() {
            info!("There are enough Random shares and Beaver triples");
            // return Ok(());
        } else {
            let mut triple_counter = self.counters.triple_counter.get_next().await?;

            // ------------------------
            // Step 1. Ensure random shares
            // ------------------------
            let phase_start = Instant::now();
            self.ensure_random_shares(network.clone(), rng, total_random_shares_to_generate)
                .await?;
            trace_preprocessing_phase(
                self.id,
                "random_shares",
                total_random_shares_to_generate,
                phase_start,
            );
            info!("Random share generation done");

            // ------------------------
            // Step 2. Ensure RanDouSha pair
            // ------------------------
            let phase_start = Instant::now();
            let ran_dou_sha_pair = self
                .ensure_ran_dou_sha_pair(network.clone(), rng, total_triples_to_generate)
                .await?;
            trace_preprocessing_phase(self.id, "randousha", total_triples_to_generate, phase_start);
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
            trace_preprocessing_phase(self.id, "triples", total_triples_to_generate, phase_start);
        }
        // ------------------------
        // Step 5. Generate zero shares (degree-2t zero-sharings)
        // ------------------------
        let phase_start = Instant::now();
        self.ensure_zero_shares(network.clone(), rng, demand.zero_shares)
            .await?;
        trace_preprocessing_phase(self.id, "zero_shares", demand.zero_shares, phase_start);
        info!("Zero share generation done");

        // ------------------------
        // Step 6. Generate Random bits
        // ------------------------
        let phase_start = Instant::now();
        self.ensure_randbit_shares(network.clone(), demand.randbit)
            .await?;
        trace_preprocessing_phase(self.id, "randbit", demand.randbit, phase_start);
        info!("RandBit share generation done");

        // ------------------------
        // Step 7. Generate Random Int
        // ------------------------
        let phase_start = Instant::now();
        self.ensure_prandint_shares(demand.prandint).await?;
        trace_preprocessing_phase(self.id, "prandint", demand.prandint, phase_start);
        info!("PrandInt share generation done");

        // ------------------------
        // Step 8. Generate PreMulC preprocessing bundles
        // ------------------------
        let phase_start = Instant::now();
        self.ensure_premulc_shares(network.clone()).await?;
        trace_preprocessing_phase(
            self.id,
            "premulc",
            demand.premulc.values().sum(),
            phase_start,
        );
        info!("PreMulC prep generation done");

        // ------------------------
        // Step 9. Generate ([r], [r^-1]) pairs for EQZ's KOrCS
        // ------------------------
        let phase_start = Instant::now();
        self.ensure_rand_inv_pairs(network.clone(), demand.rand_inv_pairs)
            .await?;
        trace_preprocessing_phase(
            self.id,
            "rand_inv_pairs",
            demand.rand_inv_pairs,
            phase_start,
        );
        info!("RandInvPair generation done");

        Ok(())
    }
}
impl<F, R> HoneyBadgerMPCNode<F, R>
where
    F: PrimeField,
    R: RBC<Id = SessionId>,
{
    /// LTZ over a raw share: returns a share of 1 if `x < 0`, else 0.
    ///
    /// `k` is the signed width the operand is known to occupy. Shared by the
    /// integer and fixed-point entry points, which differ only in where `k`
    /// comes from and how the resulting bit is wrapped.
    pub(crate) async fn ltz_on_share<N>(
        &mut self,
        x: RobustShare<F>,
        k: usize,
        net: Arc<N>,
    ) -> Result<RobustShare<F>, HoneyBadgerError>
    where
        N: Network + Send + Sync + 'static,
        Self: PreprocessingMPCProtocol<F, RobustShare<F>, N, Error = HoneyBadgerError>,
    {
        if k < 3 {
            return Err(HoneyBadgerError::LTZError(LTZError::InvalidInput(format!(
                "k must be >= 3 (got {k}); PreMod2m requires m = k-1 >= 2"
            ))));
        }
        // LTZ runs PreMod2m(a, k, m = k-1); its inner PreBitLT operates on m
        // bits and needs one PreMulC bundle sized at exactly pk = m.
        let m = k - 1;
        let pk = m;

        // Top up if the pool is short, mirroring `mul`. The sizing itself lives
        // in `PreprocDemand` and is applied by `run_preprocessing` from the
        // declared workload (`add_ltz_ops`) — nothing is computed or configured
        // here, so the online path stays a pure draw whenever the offline phase
        // was provisioned correctly.
        let need = demand_for_ltz(k);
        let short = {
            let store = self.preprocessing_material.lock().await;
            let len = store.length();
            len.beaver_triples < need.triples
                || len.randbit < need.randbit
                || len.prandint < need.prandint
                || store.premulc_len(pk) < 1
        };
        if short {
            let mut rng = StdRng::from_rng(OsRng).unwrap();
            self.run_preprocessing(net.clone(), &mut rng).await?;
        }

        let prep = {
            let mut store = self.preprocessing_material.lock().await;
            let suf_mul_inv_prep = store.take_premulc_prep(pk)?;
            store.build_premod2m_prep(m, suf_mul_inv_prep)?
        };

        let session = SessionId::new(
            ProtocolType::LTZ,
            SessionId::pack_slot(self.counters.ltz_counter.get_next().await?, 0, 0),
            self.params.instance_id,
        );

        Ok(self
            .type_ops
            .ltz
            .run(x, k, prep, session, net, self.params.timeout)
            .await?)
    }

    /// EQZ over a raw share: returns a share of 1 if `x == 0` (mod 2^k), else 0.
    pub(crate) async fn eqz_on_share<N>(
        &mut self,
        x: RobustShare<F>,
        k: usize,
        net: Arc<N>,
    ) -> Result<RobustShare<F>, HoneyBadgerError>
    where
        N: Network + Send + Sync + 'static,
        Self: PreprocessingMPCProtocol<F, RobustShare<F>, N, Error = HoneyBadgerError>,
    {
        if k == 0 {
            return Err(HoneyBadgerError::EQZError(EQZError::LengthError));
        }
        let m = (k as u32).ilog2() as usize + 1;

        // Top up if short — see the note in `ltz_on_share`. EQZ needs no PreMulC
        // bundle; its derived material is the ([r],[r^-1]) pairs KOrCS consumes.
        let need = demand_for_eqz(k);
        let short = {
            let store = self.preprocessing_material.lock().await;
            let len = store.length();
            len.beaver_triples < need.triples
                || len.randbit < need.randbit
                || len.prandint < need.prandint
                || len.rand_inv_pairs < need.rand_inv_pairs
        };
        if short {
            let mut rng = StdRng::from_rng(OsRng).unwrap();
            self.run_preprocessing(net.clone(), &mut rng).await?;
        }

        let (eqz_prandm, kor_cl_prandm, kor_cs_prep) = {
            let mut store = self.preprocessing_material.lock().await;
            let rand_inv_pairs = store.take_rand_inv_pairs(m)?;
            let triples_round1 = store.take_beaver_triples(m.saturating_sub(1))?;
            let triples_round2 = store.take_beaver_triples(m)?;
            let eqz_prandm = store.take_prandm_prep(k)?;
            let kor_cl_prandm = store.take_prandm_prep(m)?;
            (
                eqz_prandm,
                kor_cl_prandm,
                KOrCSPrep {
                    rand_inv_pairs,
                    triples_round1,
                    triples_round2,
                },
            )
        };

        let session = SessionId::new(
            ProtocolType::EQZ,
            SessionId::pack_slot(self.counters.eqz_counter.get_next().await?, 0, 0),
            self.params.instance_id,
        );

        Ok(self
            .type_ops
            .eqz
            .run(
                x,
                k,
                eqz_prandm,
                kor_cl_prandm,
                kor_cs_prep,
                session,
                net,
                self.params.timeout,
            )
            .await?)
    }

    /// `|x| < 2^p` for a raw share, as a 0/1 share.
    ///
    /// Two-sided by construction: `(x - 2^p < 0) AND (-x - 2^p < 0)`. The AND
    /// is free — see below — so the cost is exactly two LTZ calls.
    /// `k` is the width the two LTZ calls run at, so it must cover `x - 2^p`:
    /// one bit wider than `x`'s own width. The tolerance is a power of two
    /// because that is the natural notion for fixed-point — "equal once the low
    /// `p` bits are ignored".
    pub(crate) async fn abs_below_pow2<N>(
        &mut self,
        x: RobustShare<F>,
        k: usize,
        p: usize,
        net: Arc<N>,
    ) -> Result<RobustShare<F>, HoneyBadgerError>
    where
        N: Network + Send + Sync + 'static,
        Self: PreprocessingMPCProtocol<F, RobustShare<F>, N, Error = HoneyBadgerError>,
    {
        if p + 1 >= k {
            return Err(HoneyBadgerError::LTZError(LTZError::InvalidInput(format!(
                "tolerance exponent p={p} needs p+1 < k (k={k})"
            ))));
        }

        let two_p = F::from(2u64).pow([p as u64]);
        let neg_x = (x.clone() * (-F::one()))?;

        // x < 2^p
        let below = self.ltz_on_share((x - two_p)?, k, net.clone()).await?;
        // -x < 2^p, i.e. x > -2^p
        let above = self.ltz_on_share((neg_x - two_p)?, k, net.clone()).await?;

        // The two half-lines `x < 2^p` and `x > -2^p` overlap, so their
        // indicators are never both 0: that would need `2^p <= x <= -2^p`, i.e.
        // `2^{p+1} <= 0`. The sum is therefore 1 or 2 and the intersection is
        // `below + above - 1` — no multiplication, no triple, no extra round.
        Ok(((below + above)? - F::one())?)
    }

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

    /// Generate RandBit shares by running RandBit directly in the node's field `F`.
    ///
    /// RandBit used to route through a Goldilocks small-field RandBit run followed by a
    /// RISS-based field-conversion step (`PRandIntNode::generate_riss`), whose only reason for
    /// existing was to additionally produce a `Gf256` view of the bit -- a view nothing
    /// downstream ever consumed (`mul_fixed`/`div_with_const_fixed` both discarded it). Running
    /// RandBit directly in `F` produces the same `RobustShare<F>` bit shares without that detour,
    /// and shares its random-share pool with the rest of the node instead of requiring a
    /// dedicated small-field preprocessing pipeline.
    async fn ensure_randbit_shares<N>(
        &mut self,
        network: Arc<N>,
        target: usize,
    ) -> Result<(), HoneyBadgerError>
    where
        N: Network + Send + Sync + 'static,
    {
        // How many shares are already present?
        let no_shares = {
            let store = self.preprocessing_material.lock().await;
            store.length().randbit
        };

        if no_shares >= target {
            info!("There are enough RandBit shares");
            return Ok(());
        }

        // Computing the amount of needed shares. MulPub pads its last `2t+1`-wide group
        // internally, so the count no longer has to be a multiple of anything.
        let total_to_generate = target.saturating_sub(no_shares);

        // MulPub sends a whole session's groups in one batch-reconstruction message per
        // recipient, so it caps how much a single `init` may open. Ask it rather than
        // recomputing the group arithmetic here.
        let max_per_session = self.preprocess.rand_bit.mul_pub.max_batch_size();

        for chunk in chunk_sizes(total_to_generate, max_per_session) {
            // One random share (RandBit's `a` input) and one degree-`2t` zero-sharing
            // (re-randomising the MulPub opening) per output bit, both drawn from the shared
            // pools. Sizing (`n_random_shares`/`n_zero_shares`) is expected to already account
            // for this demand; this does not top either pool up itself, so an under-sized config
            // surfaces as `NotEnoughPreprocessing` here instead of silently generating more.
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

    /// Tops the PRandInt mask pool up to the declared target, deriving locally from PRSS keys.
    ///
    /// No network: the keys were established once by [`Self::setup_prss_keys`], and every mask
    /// after that is a local PRF evaluation. Masks are addressed by `prandint_cursor` — the total
    /// number ever generated — rather than by current pool depth: depth shrinks as shares are
    /// consumed, and deriving from it would eventually rewind the PRF position and hand out a
    /// mask some earlier, already-opened operation already used. The cursor only advances, so a
    /// position is never issued twice. Nor is it a per-invocation counter reset on retry — it is
    /// driven purely by how much has been generated so far, which every honest party computes
    /// identically; a counter that drifted between parties would silently yield shares of
    /// different secrets, with no message exchange left to catch it.
    async fn ensure_prandint_shares(&mut self, target: usize) -> Result<(), HoneyBadgerError> {
        let no_shares = {
            let store = self.preprocessing_material.lock().await;
            store.length().prandint
        };

        if no_shares >= target {
            info!("There are enough PRandInt shares");
            return Ok(());
        }

        let missing = target.saturating_sub(no_shares);
        info!("PRandInt share generation");

        let bits = self.params.mask_bits();
        let cursor = {
            let store = self.preprocessing_material.lock().await;
            store.prandint_cursor()
        };
        let output = self.preprocess.prand_int.generate_prss_at(
            self.params.instance_id,
            cursor,
            missing,
            bits,
        )?;
        self.preprocessing_material
            .lock()
            .await
            .add(None, None, None, Some(output));
        Ok(())
    }

    /// Ensure the `rand_inv_pairs` pool has `target` ([r], [r^-1]) pairs ready,
    /// generating the shortfall via RandInvPairNode (one MulPub round).
    async fn ensure_rand_inv_pairs<N>(
        &mut self,
        network: Arc<N>,
        target: usize,
    ) -> Result<(), HoneyBadgerError>
    where
        N: Network + Send + Sync + 'static,
    {
        let no_have = {
            let store = self.preprocessing_material.lock().await;
            store.length().rand_inv_pairs
        };
        if no_have >= target {
            return Ok(());
        }
        let missing = target - no_have;

        // Each pair consumes two fresh random shares (r, r') and one zero-sharing
        // to mask the MulPub reveal of r·r'.
        let r_shares = self
            .preprocessing_material
            .lock()
            .await
            .take_random_shares(missing)?;
        let r_prime_shares = self
            .preprocessing_material
            .lock()
            .await
            .take_random_shares(missing)?;
        let zero_shares = self
            .preprocessing_material
            .lock()
            .await
            .take_zero_shares(missing)?;

        let session = SessionId::new(
            ProtocolType::RandInvPair,
            SessionId::pack_slot(self.counters.rand_inv_pair_counter.get_next().await?, 0, 0),
            self.params.instance_id,
        );
        self.preprocess
            .rand_inv_pair
            .run(
                RandInvPairPrep {
                    r_shares,
                    r_prime_shares,
                    zero_shares,
                },
                session,
                network,
                self.params.timeout,
            )
            .await?;
        let pairs = self
            .preprocess
            .rand_inv_pair
            .wait_for_result(session, self.params.timeout)
            .await?;
        self.preprocess.rand_inv_pair.clear_store(session).await;
        self.preprocessing_material
            .lock()
            .await
            .add_rand_inv_pairs(pairs);
        Ok(())
    }

    /// Tops up every PreMulC bundle pool the declared workload calls for.
    async fn ensure_premulc_shares<N>(&mut self, network: Arc<N>) -> Result<(), HoneyBadgerError>
    where
        N: Network + Send + Sync + 'static,
    {
        // Bundles are width-specific, so targets are tracked per `pk`. A node
        // serving FpDiv at k=16 and LTZ on an int8 needs stock at both pk=15
        // and pk=7 simultaneously, which is why this is a map rather than a
        // single (count, size) setting.
        for (pk, target) in self.params.declared_demand().premulc {
            self.ensure_premulc_shares_at(pk, target, network.clone())
                .await?;
        }
        Ok(())
    }

    /// Tops the pool up to `target` PreMulC bundles sized at exactly `pk`.
    async fn ensure_premulc_shares_at<N>(
        &mut self,
        pk: usize,
        target: usize,
        network: Arc<N>,
    ) -> Result<(), HoneyBadgerError>
    where
        N: Network + Send + Sync + 'static,
    {
        if pk == 0 || target == 0 {
            return Ok(());
        }
        let no_have = {
            let store = self.preprocessing_material.lock().await;
            store.premulc_len(pk)
        };
        if no_have >= target {
            info!("There are enough PreMulC preps at pk={pk}");
            return Ok(());
        }
        let missing = target - no_have;
        let total = missing * pk;

        let mut r_pool = self
            .preprocessing_material
            .lock()
            .await
            .take_random_shares(total)?;
        let mut s_pool = self
            .preprocessing_material
            .lock()
            .await
            .take_random_shares(total)?;
        let mut u_zero_pool = self
            .preprocessing_material
            .lock()
            .await
            .take_zero_shares(total)?;

        let mut premulc_sessions = Vec::with_capacity(missing);
        for _ in 0..missing {
            let r: Vec<_> = r_pool.drain(0..pk).collect();
            let s: Vec<_> = s_pool.drain(0..pk).collect();
            let u_zero_shares: Vec<_> = u_zero_pool.drain(0..pk).collect();
            let v_triples = self
                .preprocessing_material
                .lock()
                .await
                .take_beaver_triples(pk - 1)?;
            let premulc_session = SessionId::new(
                ProtocolType::PreMulCOff,
                SessionId::pack_slot(self.counters.premulc_off_counter.get_next().await?, 0, 0),
                self.params.instance_id,
            );
            let gen_result = self
                .preprocess
                .premulc_offline
                .generate_preprocessing(
                    r,
                    s,
                    u_zero_shares,
                    v_triples,
                    premulc_session,
                    network.clone(),
                    self.params.timeout,
                )
                .await;
            if gen_result.is_err() {
                if let Err(e) = self
                    .preprocess
                    .premulc_offline
                    .clear_store(premulc_session)
                    .await
                {
                    warn!("PreMulC preprocessing: failed to clear store for session {premulc_session:?}: {e:?}");
                }
            }
            gen_result?;
            premulc_sessions.push(premulc_session);
        }
        for premulc_session in premulc_sessions {
            let result = self
                .preprocess
                .premulc_offline
                .wait_for_preprocessing(premulc_session, self.params.timeout)
                .await;
            if let Err(e) = self
                .preprocess
                .premulc_offline
                .clear_store(premulc_session)
                .await
            {
                warn!("PreMulC preprocessing: failed to clear store for session {premulc_session:?}: {e:?}");
            }
            let (w, z, r_out) = result?;
            let triples = self
                .preprocessing_material
                .lock()
                .await
                .take_beaver_triples(pk)?;
            self.preprocessing_material
                .lock()
                .await
                .add_premulc_prep(PreMulCPrep {
                    w,
                    z,
                    r: r_out,
                    triples,
                });
        }

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

///Used for routing messages to respective sub-protocols
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
    Mod2(Mod2Message),
    PreMod2m(PreMod2mMessage),
    KOrCl(KOrClMessage),
    Eqz(EqzMessage),
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
    RandBit = 11,
    FpMul = 12,
    Trunc = 13,
    FpDivConst = 14,
    ZeroSha = 15,
    PreMulCOff = 16,
    FpDiv = 17,
    PreBitMul = 18,
    PreBitMul1 = 19,
    PreBitMul2 = 20,
    PreBitMul3 = 21,
    SufOr = 22,
    FpDivTrunc = 23,
    FpDivMulA = 24,
    FpDivMulB = 25,
    /// KOrCS's own Round 1 Multiply ([tmp_j] = [r_{j-1}^{-1}]·[a]).
    KOr1 = 26,
    /// KOrCS's own Round 2 Multiply ([d_j] = [tmp_j]·[r_j]).
    KOr2 = 27,
    /// EQZ's own top-level tag. Unlike FpDiv/PreMod2m, EQZ's dependency
    /// chain (KOrCL, KOrCS) reconstructs its parent-session tag dynamically
    /// from the incoming message rather than hardcoding one, so EQZ is free
    /// to use its own dedicated tag instead of reusing FpDiv.
    EQZ = 28,
    /// LTZ's own top-level tag. Now that PreMod2mNode::drain_rbc_output
    /// reads its parent-session tag dynamically instead of hardcoding
    /// FpDiv, LTZ (built on PreMod2m) can use its own tag too.
    LTZ = 29,
    /// RandInvPair's own preprocessing tag: generates the ([r], [r^-1]) pairs
    /// KOrCS consumes, via a single MulPub reveal.
    RandInvPair = 30,
    /// PreBitLT's Phase-4 Multiply when reached via LTZ rather than FpDiv.
    /// PreBitLT keys this round on a standalone tag (not the parent's), so
    /// LTZ and FpDiv would otherwise collide at the same exec_id — both
    /// counters start at 0. See `PreBitLTNode::init`.
    LTZBitMul = 31,
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
            11 => Some(Self::RandBit),
            12 => Some(Self::FpMul),
            13 => Some(Self::Trunc),
            14 => Some(Self::FpDivConst),
            15 => Some(Self::ZeroSha),
            16 => Some(Self::PreMulCOff),
            17 => Some(Self::FpDiv),
            18 => Some(Self::PreBitMul),
            19 => Some(Self::PreBitMul1),
            20 => Some(Self::PreBitMul2),
            21 => Some(Self::PreBitMul3),
            22 => Some(Self::SufOr),
            23 => Some(Self::FpDivTrunc),
            24 => Some(Self::FpDivMulA),
            25 => Some(Self::FpDivMulB),
            26 => Some(Self::KOr1),
            27 => Some(Self::KOr2),
            28 => Some(Self::EQZ),
            29 => Some(Self::LTZ),
            30 => Some(Self::RandInvPair),
            31 => Some(Self::LTZBitMul),
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

    /// Rejects aliases of an otherwise-identical session id that differ only in the reserved
    /// bits (120..128). Those bits are never set by [`SessionId::new`] and never read by any
    /// accessor, but `SessionId` derives `Eq`/`Hash`/`Serialize` over the raw `u128` — so an
    /// attacker-supplied value with a nonzero reserved byte hashes and compares as a distinct
    /// session id while presenting identical protocol/round/sub/exec/instance fields to every
    /// check. Left unchecked, this lets a single logical session be re-admitted up to 256 times,
    /// each consuming a separate slot against session-count caps. Call this on every session id
    /// that arrives over the network, before it is used for routing or admission.
    pub fn is_canonical(self) -> bool {
        (self.0 >> 120) == 0
    }

    pub fn round_id(self) -> u8 {
        ((self.0 >> 32) & 0xFF) as u8
    }

    /// Pack the flexible field: exec_id at the top of the 80-bit slot, sub_id and round_id below.
    #[inline]
    pub fn pack_slot(exec_id: u64, sub_id: u8, round_id: u8) -> u128 {
        ((exec_id as u128) << 16) | ((sub_id as u128) << 8) | (round_id as u128)
    }

    /// The 8 bits above `caller` (120..128)
    pub fn extra_bits(self) -> u8 {
        (self.0 >> 120) as u8
    }

    /// Returns a copy of this `SessionId` with its extra bits (120..128)
    /// set to `extra_bits`, leaving every other field unchanged.
    pub fn with_extra_bits(self, extra_bits: u8) -> Self {
        SessionId((self.0 & !(0xFFu128 << 120)) | ((extra_bits as u128) << 120))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn test_session_id_canonicality() {
        let session_id = SessionId::new(
            ProtocolType::Input,
            SessionId::pack_slot(0, 3, 0),
            0xDEADBEEF,
        );
        assert!(session_id.is_canonical());

        // Every one of the 256 reserved-byte values aliases the same protocol/round/sub/exec/
        // instance fields as `session_id` while being a distinct `u128`, hash, and equality key.
        // Only the all-zero reserved byte (already covered above) is canonical.
        for reserved in 1..=u8::MAX {
            let alias =
                unsafe { SessionId::from_u128(session_id.as_u128() | ((reserved as u128) << 120)) };
            assert_ne!(alias.as_u128(), session_id.as_u128());
            assert_ne!(alias, session_id);
            assert_eq!(alias.calling_protocol(), session_id.calling_protocol());
            assert_eq!(alias.exec_id(), session_id.exec_id());
            assert_eq!(alias.sub_id(), session_id.sub_id());
            assert_eq!(alias.round_id(), session_id.round_id());
            assert_eq!(alias.instance_id(), session_id.instance_id());
            assert!(!alias.is_canonical());
        }
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
}
