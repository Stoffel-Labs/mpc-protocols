//! Benchmark instrumentation for HoneyBadgerMPC.
//!
//! Enabled only with the `benchmark` cargo feature. Provides:
//!
//! - [`NodeBenchmarkCounters`] – shared atomic counters for bytes sent/received and
//!   message counts, broken down by subprotocol and message type.
//! - [`NodeBenchmarkSnapshot`] – a consistent, non-atomic copy of the counters.
//! - [`CountingNetwork`] – a [`Network`] wrapper that automatically records outbound
//!   bytes and classifies messages by subprotocol and type. Pair with
//!   [`HoneyBadgerMPCNode::counting_network`] so the node and the network share the
//!   same [`Arc<NodeBenchmarkCounters>`].
//!
//! # Usage
//!
//! ```ignore
//! let inner_net = FakeNetwork::new(id, inner);
//! let counting_net = Arc::new(node.counting_network(inner_net));
//!
//! // protocol loop …
//! let (sender, raw) = counting_net.receive_raw().await?;
//! node.process(sender, raw, counting_net.clone()).await?;
//!
//! let snap = node.benchmark_snapshot();
//! println!("bytes sent: {}", snap.bytes_sent);
//! println!("RanSha share msgs sent: {}", snap.sent.ran_sha.share);
//! ```

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use async_trait::async_trait;
use stoffelnet::network_utils::{ClientId, Network, NetworkError, PartyId, VerifiedOrdering};

use bincode::Options;

use crate::honeybadger::WrappedMessage;

const RELAX: Ordering = Ordering::Relaxed;

// ── per-subprotocol message-type counters ─────────────────────────────────────

/// RBC message counts (Bracha + AVID sub-types).
#[derive(Debug, Default)]
pub struct RbcMsgCounts {
    pub bracha_init: AtomicU64,
    pub bracha_echo: AtomicU64,
    pub bracha_ready: AtomicU64,
    pub avid_send: AtomicU64,
    pub avid_echo: AtomicU64,
    pub avid_ready: AtomicU64,
    pub other: AtomicU64,
}

/// RanSha message counts.
#[derive(Debug, Default)]
pub struct RanShaMsgCounts {
    pub share: AtomicU64,
    pub reconstruct: AtomicU64,
    pub output: AtomicU64,
}

/// DouSha message counts.
#[derive(Debug, Default)]
pub struct DouShaMsgCounts {
    pub share: AtomicU64,
    pub shares: AtomicU64,
}

/// RanDouSha message counts.
#[derive(Debug, Default)]
pub struct RanDouShaMsgCounts {
    pub reconstruct: AtomicU64,
    pub reconstruct_batch: AtomicU64,
    pub output: AtomicU64,
}

/// Batch-reconstruction message counts.
#[derive(Debug, Default)]
pub struct BatchReconMsgCounts {
    pub eval: AtomicU64,
    pub reveal: AtomicU64,
    pub eval_batch: AtomicU64,
    pub reveal_batch: AtomicU64,
}

/// All subprotocol message counts for one direction (sent or received).
#[derive(Debug, Default)]
pub struct DirectionalMsgCounts {
    pub rbc: RbcMsgCounts,
    pub ran_sha: RanShaMsgCounts,
    pub dou_sha: DouShaMsgCounts,
    pub ran_dou_sha: RanDouShaMsgCounts,
    pub batch_recon: BatchReconMsgCounts,
    pub input: AtomicU64,
    pub output: AtomicU64,
    pub prand_bit_d: AtomicU64,
}

// ── top-level counters ────────────────────────────────────────────────────────

/// Atomic per-node counters for bytes and messages.
///
/// Held behind an `Arc` and shared between [`HoneyBadgerMPCNode`] (which updates
/// receive-side counters in `process()`) and [`CountingNetwork`] (which updates
/// send-side counters on `send` / `broadcast`).
///
/// All counters use `Relaxed` ordering and are not read-consistent across fields;
/// use [`NodeBenchmarkSnapshot`] for a best-effort snapshot.
#[derive(Debug, Default)]
pub struct NodeBenchmarkCounters {
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub sent: DirectionalMsgCounts,
    pub received: DirectionalMsgCounts,
}

impl NodeBenchmarkCounters {
    pub fn snapshot(&self) -> NodeBenchmarkSnapshot {
        NodeBenchmarkSnapshot {
            bytes_sent: self.bytes_sent.load(RELAX),
            bytes_received: self.bytes_received.load(RELAX),
            sent: DirectionalMsgSnapshot::from(&self.sent),
            received: DirectionalMsgSnapshot::from(&self.received),
        }
    }

    /// Record `n_recipients` outbound sends of `data`.
    ///
    /// Increments `bytes_sent` by `data.len() * n_recipients`.  If `data`
    /// deserializes as a [`WrappedMessage`] the per-subprotocol sent counter is
    /// incremented once (the message type, not multiplied by n_recipients).
    /// Non-MPC bytes (handshake frames, client-set-sync, etc.) silently
    /// contribute only to the byte total.
    ///
    /// Designed to be called from a type-erased send hook in the transport
    /// layer where the caller does not know the message type.
    pub fn record_outbound(&self, data: &[u8], n_recipients: u64) {
        self.bytes_sent
            .fetch_add(data.len() as u64 * n_recipients, RELAX);
        if let Ok(msg) = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .deserialize::<WrappedMessage>(data)
        {
            record_received(&msg, &self.sent);
        }
    }
}

// ── snapshot (non-atomic, for reporting) ─────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct RbcMsgSnapshot {
    pub bracha_init: u64,
    pub bracha_echo: u64,
    pub bracha_ready: u64,
    pub avid_send: u64,
    pub avid_echo: u64,
    pub avid_ready: u64,
    pub other: u64,
}

impl From<&RbcMsgCounts> for RbcMsgSnapshot {
    fn from(c: &RbcMsgCounts) -> Self {
        Self {
            bracha_init: c.bracha_init.load(RELAX),
            bracha_echo: c.bracha_echo.load(RELAX),
            bracha_ready: c.bracha_ready.load(RELAX),
            avid_send: c.avid_send.load(RELAX),
            avid_echo: c.avid_echo.load(RELAX),
            avid_ready: c.avid_ready.load(RELAX),
            other: c.other.load(RELAX),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RanShaMsgSnapshot {
    pub share: u64,
    pub reconstruct: u64,
    pub output: u64,
}

impl From<&RanShaMsgCounts> for RanShaMsgSnapshot {
    fn from(c: &RanShaMsgCounts) -> Self {
        Self {
            share: c.share.load(RELAX),
            reconstruct: c.reconstruct.load(RELAX),
            output: c.output.load(RELAX),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DouShaMsgSnapshot {
    pub share: u64,
    pub shares: u64,
}

impl From<&DouShaMsgCounts> for DouShaMsgSnapshot {
    fn from(c: &DouShaMsgCounts) -> Self {
        Self {
            share: c.share.load(RELAX),
            shares: c.shares.load(RELAX),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RanDouShaMsgSnapshot {
    pub reconstruct: u64,
    pub reconstruct_batch: u64,
    pub output: u64,
}

impl From<&RanDouShaMsgCounts> for RanDouShaMsgSnapshot {
    fn from(c: &RanDouShaMsgCounts) -> Self {
        Self {
            reconstruct: c.reconstruct.load(RELAX),
            reconstruct_batch: c.reconstruct_batch.load(RELAX),
            output: c.output.load(RELAX),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct BatchReconMsgSnapshot {
    pub eval: u64,
    pub reveal: u64,
    pub eval_batch: u64,
    pub reveal_batch: u64,
}

impl From<&BatchReconMsgCounts> for BatchReconMsgSnapshot {
    fn from(c: &BatchReconMsgCounts) -> Self {
        Self {
            eval: c.eval.load(RELAX),
            reveal: c.reveal.load(RELAX),
            eval_batch: c.eval_batch.load(RELAX),
            reveal_batch: c.reveal_batch.load(RELAX),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DirectionalMsgSnapshot {
    pub rbc: RbcMsgSnapshot,
    pub ran_sha: RanShaMsgSnapshot,
    pub dou_sha: DouShaMsgSnapshot,
    pub ran_dou_sha: RanDouShaMsgSnapshot,
    pub batch_recon: BatchReconMsgSnapshot,
    pub input: u64,
    pub output: u64,
    pub prand_bit_d: u64,
}

impl From<&DirectionalMsgCounts> for DirectionalMsgSnapshot {
    fn from(c: &DirectionalMsgCounts) -> Self {
        Self {
            rbc: RbcMsgSnapshot::from(&c.rbc),
            ran_sha: RanShaMsgSnapshot::from(&c.ran_sha),
            dou_sha: DouShaMsgSnapshot::from(&c.dou_sha),
            ran_dou_sha: RanDouShaMsgSnapshot::from(&c.ran_dou_sha),
            batch_recon: BatchReconMsgSnapshot::from(&c.batch_recon),
            input: c.input.load(RELAX),
            output: c.output.load(RELAX),
            prand_bit_d: c.prand_bit_d.load(RELAX),
        }
    }
}

/// A consistent (best-effort) snapshot of [`NodeBenchmarkCounters`].
#[derive(Debug, Clone, Default)]
pub struct NodeBenchmarkSnapshot {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub sent: DirectionalMsgSnapshot,
    pub received: DirectionalMsgSnapshot,
}

// ── message classification ────────────────────────────────────────────────────

/// Classify and count a received `WrappedMessage` into the `received` counters.
pub(crate) fn record_received(msg: &WrappedMessage, counts: &DirectionalMsgCounts) {
    use crate::common::rbc::rbc_store::{GenericMsgType, MsgType, MsgTypeAvid};
    use crate::honeybadger::{
        batch_recon::BatchReconMsgType,
        double_share::DouShaPayload,
        ran_dou_sha::messages::RanDouShaPayload,
        share_gen::RanShaMessageType,
    };

    match msg {
        WrappedMessage::Rbc(m) => {
            let c = &counts.rbc;
            match &m.msg_type {
                GenericMsgType::Bracha(t) => match t {
                    MsgType::Init => c.bracha_init.fetch_add(1, RELAX),
                    MsgType::Echo => c.bracha_echo.fetch_add(1, RELAX),
                    MsgType::Ready => c.bracha_ready.fetch_add(1, RELAX),
                    MsgType::Unknown(_) => c.other.fetch_add(1, RELAX),
                },
                GenericMsgType::Avid(t) => match t {
                    MsgTypeAvid::Send => c.avid_send.fetch_add(1, RELAX),
                    MsgTypeAvid::Echo => c.avid_echo.fetch_add(1, RELAX),
                    MsgTypeAvid::Ready => c.avid_ready.fetch_add(1, RELAX),
                    MsgTypeAvid::Unknown(_) => c.other.fetch_add(1, RELAX),
                },
                _ => c.other.fetch_add(1, RELAX),
            };
        }
        WrappedMessage::RanSha(m) => {
            let c = &counts.ran_sha;
            match m.msg_type {
                RanShaMessageType::ShareMessage => c.share.fetch_add(1, RELAX),
                RanShaMessageType::ReconstructMessage => c.reconstruct.fetch_add(1, RELAX),
                RanShaMessageType::OutputMessage => c.output.fetch_add(1, RELAX),
            };
        }
        WrappedMessage::Dousha(m) => {
            let c = &counts.dou_sha;
            match &m.payload {
                DouShaPayload::Share(_) => c.share.fetch_add(1, RELAX),
                DouShaPayload::Shares(_) => c.shares.fetch_add(1, RELAX),
            };
        }
        WrappedMessage::RanDouSha(m) => {
            let c = &counts.ran_dou_sha;
            match &m.payload {
                RanDouShaPayload::Reconstruct(_) => c.reconstruct.fetch_add(1, RELAX),
                RanDouShaPayload::ReconstructBatch(_) => c.reconstruct_batch.fetch_add(1, RELAX),
                RanDouShaPayload::Output(_) => c.output.fetch_add(1, RELAX),
            };
        }
        WrappedMessage::BatchRecon(m) => {
            let c = &counts.batch_recon;
            match m.msg_type {
                BatchReconMsgType::Eval => c.eval.fetch_add(1, RELAX),
                BatchReconMsgType::Reveal => c.reveal.fetch_add(1, RELAX),
                BatchReconMsgType::EvalBatch => c.eval_batch.fetch_add(1, RELAX),
                BatchReconMsgType::RevealBatch => c.reveal_batch.fetch_add(1, RELAX),
            };
        }
        WrappedMessage::Input(_) => {
            counts.input.fetch_add(1, RELAX);
        }
        WrappedMessage::Output(_) => {
            counts.output.fetch_add(1, RELAX);
        }
        WrappedMessage::PRandBitD(_) => {
            counts.prand_bit_d.fetch_add(1, RELAX);
        }
    }
}

/// Classify a single outbound `send()` call into the `sent` counters.
///
/// Deserializes the message and delegates to `record_received`, so
/// classification stays in sync with the actual types automatically.
pub(crate) fn record_sent(data: &[u8], counts: &DirectionalMsgCounts) {
    let msg: WrappedMessage = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .deserialize(data)
        .expect("CountingNetwork::send received bytes that are not a WrappedMessage");
    record_received(&msg, counts);
}

// ── CountingNetwork ──────────────────────────────────────────────────────────

/// A [`Network`] wrapper that records outbound bytes and classifies messages by
/// subprotocol and message type into a shared [`NodeBenchmarkCounters`].
///
/// Inbound bytes are counted by [`HoneyBadgerMPCNode::process`]; the two share
/// the same [`Arc<NodeBenchmarkCounters>`] instance so all stats are reported
/// through a single [`NodeBenchmarkSnapshot`].
pub struct CountingNetwork<N: Network> {
    inner: N,
    counters: Arc<NodeBenchmarkCounters>,
}

impl<N: Network> CountingNetwork<N> {
    pub fn new(inner: N, counters: Arc<NodeBenchmarkCounters>) -> Self {
        Self { inner, counters }
    }

    pub fn counters(&self) -> Arc<NodeBenchmarkCounters> {
        Arc::clone(&self.counters)
    }
}

#[async_trait]
impl<N: Network + Send + Sync> Network for CountingNetwork<N> {
    type NodeType = N::NodeType;
    type NetworkConfig = N::NetworkConfig;

    async fn send(&self, recipient: PartyId, message: &[u8]) -> Result<usize, NetworkError> {
        self.counters
            .bytes_sent
            .fetch_add(message.len() as u64, RELAX);
        record_sent(message, &self.counters.sent);
        self.inner.send(recipient, message).await
    }

    async fn broadcast(&self, message: &[u8]) -> Result<usize, NetworkError> {
        let n = self.inner.party_count() as u64;
        self.counters
            .bytes_sent
            .fetch_add(message.len() as u64 * n, RELAX);
        record_sent(message, &self.counters.sent);
        self.inner.broadcast(message).await
    }

    async fn send_to_client(
        &self,
        client: ClientId,
        message: &[u8],
    ) -> Result<usize, NetworkError> {
        self.inner.send_to_client(client, message).await
    }

    fn parties(&self) -> Vec<&Self::NodeType> {
        self.inner.parties()
    }

    fn parties_mut(&mut self) -> Vec<&mut Self::NodeType> {
        self.inner.parties_mut()
    }

    fn config(&self) -> &Self::NetworkConfig {
        self.inner.config()
    }

    fn node(&self, id: PartyId) -> Option<&Self::NodeType> {
        self.inner.node(id)
    }

    fn node_mut(&mut self, id: PartyId) -> Option<&mut Self::NodeType> {
        self.inner.node_mut(id)
    }

    fn clients(&self) -> Vec<ClientId> {
        self.inner.clients()
    }

    fn is_client_connected(&self, client: ClientId) -> bool {
        self.inner.is_client_connected(client)
    }

    fn local_party_id(&self) -> PartyId {
        self.inner.local_party_id()
    }

    fn party_count(&self) -> usize {
        self.inner.party_count()
    }

    fn verified_ordering(&self) -> Option<VerifiedOrdering> {
        self.inner.verified_ordering()
    }
}
