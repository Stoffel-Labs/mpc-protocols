//! Statistics instrumentation for AvssMPC.
//!
//! Enabled only with the `statistics` cargo feature. Mirrors
//! [`crate::honeybadger::statistics`], adapted to AVSS's message shape:
//!
//! - [`NodeStatisticsCounters`] – shared atomic counters for bytes sent/received and
//!   message counts, broken down by subprotocol and message type.
//! - [`NodeStatisticsSnapshot`] – a consistent, non-atomic copy of the counters.
//! - [`CountingNetwork`] – a [`Network`] wrapper that automatically records outbound
//!   bytes and classifies messages by subprotocol and type. Pair with
//!   [`AvssMPCNode::counting_network`] so the node and the network share the
//!   same [`Arc<NodeStatisticsCounters>`].
//!
//! Unlike HoneyBadger, AVSS's `Avss`, `Mul`, `Input`, and `Output` messages are
//! flat structs (no per-round submessage variants), so only RBC gets a
//! Bracha/AVID breakdown; the rest are single counters.
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
//! let snap = node.statistics_snapshot();
//! println!("bytes sent: {}", snap.bytes_sent);
//! println!("RBC bracha_echo msgs sent: {}", snap.sent.rbc.bracha_echo);
//! ```

use std::fmt;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use async_trait::async_trait;
use stoffelnet::network_utils::{ClientId, Network, NetworkError, PartyId, VerifiedOrdering};

use bincode::Options;

use crate::avss_mpc::AvssWrappedMessage;

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

/// All subprotocol message counts for one direction (sent or received).
#[derive(Debug, Default)]
pub struct DirectionalMsgCounts {
    pub rbc: RbcMsgCounts,
    /// Dealer share-distribution messages (`AvssWrappedMessage::Avss`).
    pub avss: AtomicU64,
    /// Multiplication protocol messages (`AvssWrappedMessage::Mul`).
    pub mul: AtomicU64,
    /// Client input messages (`AvssWrappedMessage::Input`).
    pub input: AtomicU64,
    /// Client output messages (`AvssWrappedMessage::Output`).
    pub output: AtomicU64,
}

// ── top-level counters ────────────────────────────────────────────────────────

/// Atomic per-node counters for bytes and messages.
///
/// Held behind an `Arc` and shared between [`AvssMPCNode`] (which updates
/// receive-side counters in `process()`) and [`CountingNetwork`] (which updates
/// send-side counters on `send` / `broadcast`).
///
/// All counters use `Relaxed` ordering and are not read-consistent across fields;
/// use [`NodeStatisticsSnapshot`] for a best-effort snapshot.
#[derive(Debug, Default)]
pub struct NodeStatisticsCounters {
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub sent: DirectionalMsgCounts,
    pub received: DirectionalMsgCounts,
}

impl NodeStatisticsCounters {
    pub fn snapshot(&self) -> NodeStatisticsSnapshot {
        NodeStatisticsSnapshot {
            bytes_sent: self.bytes_sent.load(RELAX),
            bytes_received: self.bytes_received.load(RELAX),
            sent: DirectionalMsgSnapshot::from(&self.sent),
            received: DirectionalMsgSnapshot::from(&self.received),
        }
    }

    /// Record `n_recipients` outbound sends of `data`.
    ///
    /// Increments `bytes_sent` by `data.len() * n_recipients`.  If `data`
    /// deserializes as an [`AvssWrappedMessage`] the per-subprotocol sent
    /// counter is incremented once (the message type, not multiplied by
    /// n_recipients). Non-MPC bytes (handshake frames, client-set-sync, etc.)
    /// silently contribute only to the byte total.
    ///
    /// Designed to be called from a type-erased send hook in the transport
    /// layer where the caller does not know the message type.
    pub fn record_outbound(&self, data: &[u8], n_recipients: u64) {
        self.bytes_sent
            .fetch_add(data.len() as u64 * n_recipients, RELAX);
        if let Ok(msg) = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .deserialize::<AvssWrappedMessage>(data)
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
pub struct DirectionalMsgSnapshot {
    pub rbc: RbcMsgSnapshot,
    pub avss: u64,
    pub mul: u64,
    pub input: u64,
    pub output: u64,
}

impl From<&DirectionalMsgCounts> for DirectionalMsgSnapshot {
    fn from(c: &DirectionalMsgCounts) -> Self {
        Self {
            rbc: RbcMsgSnapshot::from(&c.rbc),
            avss: c.avss.load(RELAX),
            mul: c.mul.load(RELAX),
            input: c.input.load(RELAX),
            output: c.output.load(RELAX),
        }
    }
}

/// A consistent (best-effort) snapshot of [`NodeStatisticsCounters`].
#[derive(Debug, Clone, Default)]
pub struct NodeStatisticsSnapshot {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub sent: DirectionalMsgSnapshot,
    pub received: DirectionalMsgSnapshot,
}

impl fmt::Display for NodeStatisticsSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fmt_bytes = |b: u64| -> String {
            if b >= 1_000_000_000 {
                format!("{:.2} GB", b as f64 / 1e9)
            } else if b >= 1_000_000 {
                format!("{:.2} MB", b as f64 / 1e6)
            } else if b >= 1_000 {
                format!("{:.2} KB", b as f64 / 1e3)
            } else {
                format!("{} B", b)
            }
        };

        macro_rules! row {
            ($label:expr, $s:expr, $r:expr) => {
                writeln!(f, "│ {:<37} │ {:>8} │ {:>8} │", $label, $s, $r)?
            };
        }

        writeln!(f, "┌───────────────────────────────────────┬──────────┬──────────┐")?;
        row!("Metric", "  Sent  ", "Received");
        writeln!(f, "├───────────────────────────────────────┼──────────┼──────────┤")?;
        row!("Bytes", fmt_bytes(self.bytes_sent), fmt_bytes(self.bytes_received));
        writeln!(f, "├───────────────────────────────────────┼──────────┼──────────┤")?;
        row!("RBC", "", "");
        let s = &self.sent.rbc;
        let r = &self.received.rbc;
        row!("  bracha_init",       s.bracha_init,       r.bracha_init);
        row!("  bracha_echo",       s.bracha_echo,       r.bracha_echo);
        row!("  bracha_ready",      s.bracha_ready,      r.bracha_ready);
        row!("  avid_send",         s.avid_send,         r.avid_send);
        row!("  avid_echo",         s.avid_echo,         r.avid_echo);
        row!("  avid_ready",        s.avid_ready,        r.avid_ready);
        row!("  other",             s.other,             r.other);
        writeln!(f, "├───────────────────────────────────────┼──────────┼──────────┤")?;
        row!("Avss (share dist.)", self.sent.avss,   self.received.avss);
        row!("Mul",                self.sent.mul,    self.received.mul);
        row!("Input",              self.sent.input,  self.received.input);
        row!("Output",             self.sent.output, self.received.output);
        write!(f,  "└───────────────────────────────────────┴──────────┴──────────┘")
    }
}

impl fmt::Display for NodeStatisticsCounters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.snapshot(), f)
    }
}

// ── message classification ────────────────────────────────────────────────────

/// Classify and count a received `AvssWrappedMessage` into the `received` counters.
pub(crate) fn record_received(msg: &AvssWrappedMessage, counts: &DirectionalMsgCounts) {
    use crate::common::rbc::rbc_store::{GenericMsgType, MsgType, MsgTypeAvid};

    match msg {
        AvssWrappedMessage::Rbc(m) => {
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
        AvssWrappedMessage::Avss(_) => {
            counts.avss.fetch_add(1, RELAX);
        }
        AvssWrappedMessage::Mul(_) => {
            counts.mul.fetch_add(1, RELAX);
        }
        AvssWrappedMessage::Input(_) => {
            counts.input.fetch_add(1, RELAX);
        }
        AvssWrappedMessage::Output(_) => {
            counts.output.fetch_add(1, RELAX);
        }
    }
}

/// Classify a single outbound `send()` call into the `sent` counters.
///
/// Deserializes the message and delegates to `record_received`, so
/// classification stays in sync with the actual types automatically.
pub(crate) fn record_sent(data: &[u8], counts: &DirectionalMsgCounts) {
    let msg: AvssWrappedMessage = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .deserialize(data)
        .expect("CountingNetwork::send received bytes that are not an AvssWrappedMessage");
    record_received(&msg, counts);
}

// ── CountingNetwork ──────────────────────────────────────────────────────────

/// A [`Network`] wrapper that records outbound bytes and classifies messages by
/// subprotocol and message type into a shared [`NodeStatisticsCounters`].
///
/// Inbound bytes are counted by [`AvssMPCNode::process`]; the two share
/// the same [`Arc<NodeStatisticsCounters>`] instance so all stats are reported
/// through a single [`NodeStatisticsSnapshot`].
pub struct CountingNetwork<N: Network> {
    inner: N,
    counters: Arc<NodeStatisticsCounters>,
}

impl<N: Network> CountingNetwork<N> {
    pub fn new(inner: N, counters: Arc<NodeStatisticsCounters>) -> Self {
        Self { inner, counters }
    }

    pub fn counters(&self) -> Arc<NodeStatisticsCounters> {
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
