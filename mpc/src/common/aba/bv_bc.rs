//! Implementation of Crain's BV-Broadcast taken from ["Practical Asynchronous Distributed Key Generation"](https://eprint.iacr.org/2021/1591.pdf), Appendix B, Algorithm 3.
//!
//! BV-Broadcast ("binary value broadcast") sits at the bottom of Crain's ABA stack: it feeds
//! [`SbvBroadcast`](super::sbv_bc::SbvBroadcast), which in turn feeds [`CrainAba`](super::CrainAba).
//! Each party inputs a single bit and, rather than agreeing on one output, obtains a growing set
//! `bin_values` of bits, with the defining guarantee that a value only enters `bin_values` if it was
//! the input of at least one honest party. This is what prevents a Byzantine minority from injecting
//! a bit that no honest party ever proposed.
//!
//! With `n` parties, of which at most `t` are Byzantine (`n >= 3t + 1`), a party with input `v` runs:
//!
//! ```text
//! 1: bin_values <- {}
//! 2: send BVAL(v) to all
//! 3: return bin_values                             // not necessarily final when returned
//! 4: upon receiving BVAL(v) do
//! 5:   if BVAL(v) received from t + 1 different nodes then
//! 6:     send BVAL(v) to all (if haven't done already)
//! 7:   if BVAL(v) received from 2t + 1 different nodes then
//! 8:     bin_values <- bin_values U {v}
//! ```
//!
//! The two thresholds carry the whole argument, and both are counted over *distinct senders* of the
//! same value:
//!
//! - `t + 1` distinct senders means at least one of them is honest, so echoing `v` cannot amplify a
//!   value that only Byzantine parties proposed.
//! - `2t + 1` distinct senders means at least `t + 1` of them are honest, so every honest party
//!   eventually reaches its own `t + 1` echo threshold and adds `v` too. The sets held by honest
//!   parties therefore converge.
//!
//! Note that step 3 returns while the protocol is still running, and `bin_values` keeps filling as
//! messages arrive. That is why [`BvBroadcast::init`] hands back a [`watch::Receiver`] rather than a
//! snapshot: the caller observes the set as it grows. SBV-Broadcast's step 2 is literally
//! `wait until bin_values != {}`, which becomes a single `wait_for` on that receiver.
//!
//! Because a `watch` channel retains its current value, a receiver obtained at any time immediately
//! sees everything accumulated so far. Subscribing therefore never races against message handling —
//! [`BvBroadcast::subscribe_to_bin_values`] can be called before, during, or after `init`.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use bincode::ErrorKind;
use serde::{Deserialize, Serialize};
use stoffelnet::network_utils::{Network, NetworkError};
use tokio::sync::{watch, Mutex};

use crate::{avss_mpc::AvssSessionId, common::aba::TaggedMessage, honeybadger::WrappedMessage};

/// Errors that can arise while running BV-Broadcast.
#[derive(thiserror::Error, Debug)]
pub enum BvBroadcastError {
    /// The network failed while sending or broadcasting a `BVAL` message.
    #[error("there was an error in the network: {0:?}")]
    NetworkError(#[from] NetworkError),

    /// A message reached `BvBroadcast::process` with a payload other than
    /// [`TaggedMessage::Binary`]. BV-Broadcast only speaks `BVAL`; the `Aux` and `AuxSet` tags
    /// belong to the SBV-Broadcast and ABA layers above it.
    #[error("unknown message type: {0:?}")]
    UnknownMessageType(TaggedMessage),

    /// A `BVAL` message could not be encoded into bytes before being put on the wire.
    #[error("error while serializing the object into bytes: {0:?}")]
    SerializationError(#[from] Box<ErrorKind>),
}

/// A `BVAL(v)` message, the only kind of message BV-Broadcast sends (steps 2 and 6).
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct BvBroadcastMessage<I> {
    /// ID of the sending party. The thresholds count *distinct senders* of a value, not messages,
    /// so this is what makes a repeated `BVAL` from one party count only once.
    pub sender_id: usize,
    /// Session this broadcast instance belongs to. Each session carries its own `bin_values`.
    pub session_id: I,
    /// Round of the enclosing ABA being served. Crain's ABA runs one BV-Broadcast per round.
    pub round_id: usize,
    /// The broadcast bit. Always [`TaggedMessage::Binary`] for BV-Broadcast.
    pub payload: TaggedMessage,
}

impl BvBroadcastMessage<AvssSessionId> {
    /// Creates a `BVAL` message for the given session and round.
    pub fn new(
        sender_id: usize,
        session_id: AvssSessionId,
        round_id: usize,
        payload: TaggedMessage,
    ) -> Self {
        Self {
            sender_id,
            session_id,
            round_id,
            payload,
        }
    }
}

/// State of a single BV-Broadcast instance, i.e. of one session.
#[derive(Default, Debug)]
struct BvBroadcastStore {
    /// Whether this party has already echoed a bit at step 6, implementing the paper's "if haven't
    /// done already" guard. The first coordinate signals if the party has already sent a 0, the
    /// second coordinate signals if the party has already sent a 1.
    bit_sent: (bool, bool),
    /// Whether the instance has finished, after which incoming messages are ignored.
    protocol_ended: bool,
    /// The `(sender_id, value)` pairs seen so far, from which both thresholds are counted. Storing
    /// the sender alongside the value is what makes those counts range over *different* parties, as
    /// steps 5 and 7 require: a malicious party repeating the same `BVAL` collapses into a single
    /// pair, and so cannot inflate the count for a value on its own.
    recv_bin_values: HashSet<(usize, u8)>,
    bin_values_tx: watch::Sender<HashSet<u8>>,
}

/// A party running BV-Broadcast, able to serve many concurrent sessions.
pub struct BvBroadcast<I> {
    /// ID of this party.
    id: usize,
    /// Total number of parties, `n`.
    n_parties: usize,
    /// Maximum number of Byzantine parties tolerated, `t`. The protocol assumes `n >= 3t + 1`.
    threshold: usize,
    /// State per session. The `usize` is the ID of the party whose message opened the session.
    store: Arc<Mutex<HashMap<I, Arc<Mutex<BvBroadcastStore>>>>>,
}

/// Wraps a `BVAL` message and serializes it for the wire, so the receiving AVSS node's dispatcher
/// can route it back to BV-Broadcast.
fn encode_message_bv_broadcast_avss(
    m: BvBroadcastMessage<AvssSessionId>,
) -> Result<Vec<u8>, BvBroadcastError> {
    let wrapped = WrappedMessage::BvBroadcast(m);
    let bytes = bincode::serialize(&wrapped)?;
    Ok(bytes)
}

impl BvBroadcast<AvssSessionId> {
    /// Returns a receiver watching `bin_values` for `session_id`, creating the session state if this
    /// is the first thing to touch it.
    ///
    /// Safe to call at any point: `watch` retains the current value, so a late subscriber sees
    /// everything already accumulated, and an early one sees the set fill as `BVAL` messages arrive.
    pub async fn subscribe_to_bin_values(
        &self,
        session_id: AvssSessionId,
    ) -> watch::Receiver<HashSet<u8>> {
        self.get_or_create_store(session_id)
            .await
            .lock()
            .await
            .bin_values_tx
            .subscribe()
    }

    /// Creates a BV-Broadcast party with ID `id`, among `n_parties` parties tolerating `threshold`
    /// Byzantine ones, reporting sessions whose `bin_values` changed on `output`.
    pub fn new(id: usize, n_parties: usize, threshold: usize) -> Self {
        Self {
            id,
            store: Arc::new(Mutex::new(HashMap::new())),
            n_parties,
            threshold,
        }
    }

    /// Returns the state for `session_id`, creating it on first use and recording `sender_id` as the
    /// party that opened the session.
    async fn get_or_create_store(&self, session_id: AvssSessionId) -> Arc<Mutex<BvBroadcastStore>> {
        let store_lock = {
            let mut store = self.store.lock().await;
            store
                .entry(session_id)
                .or_insert_with(|| Arc::new(Mutex::new(BvBroadcastStore::default())))
                .clone()
        };

        store_lock
    }

    /// Starts BV-Broadcast for `session_id` with input bit `v`, sending `BVAL(v)` to every party
    /// (step 2) and returning a receiver watching `bin_values` (step 3).
    ///
    /// As in the paper, this returns before the protocol has finished: the set behind the receiver
    /// has not necessarily reached its final value, and is typically still empty here. Callers wait
    /// on it rather than treating its current contents as the outcome.
    ///
    /// The receiver comes from [`Self::subscribe_to_bin_values`], so it observes the session's
    /// existing channel. Replacing that channel here would discard any value `binary_handle` had
    /// already recorded — and since step 8 fires on an exact `2t + 1` count, a discarded value would
    /// never be re-added.
    pub async fn init<N>(
        &self,
        session_id: AvssSessionId,
        round_id: usize,
        v: u8,
        network: Arc<N>,
    ) -> Result<watch::Receiver<HashSet<u8>>, BvBroadcastError>
    where
        N: Network + Send + Sync,
    {
        for pid in 0..self.n_parties {
            let enc_bit = encode_message_bv_broadcast_avss(BvBroadcastMessage::new(
                self.id,
                session_id,
                round_id,
                TaggedMessage::Binary(v),
            ))?;
            network.send(pid, &enc_bit).await?;
        }

        Ok(self.subscribe_to_bin_values(session_id).await)
    }

    /// Handles an incoming `BVAL` message (steps 4 to 8): records the sender against the value, then
    /// echoes that value once `t + 1` distinct parties have sent it (steps 5 and 6), and adds it to
    /// `bin_values` once `2t + 1` have (steps 7 and 8).
    ///
    /// The `bit_sent` guard sits inside the echo branch, matching the paper's "if haven't done
    /// already": it suppresses only the resend, not the counting, so a value keeps accruing senders
    /// toward the second threshold after it has been echoed. The guard is still needed there because
    /// a repeated `BVAL` from one sender leaves the count unchanged and would otherwise re-fire the
    /// echo.
    ///
    /// Messages are dropped when the session has already ended, and when `sender_id` falls outside
    /// `0..n_parties`, which an adversary is free to make up. A `Binary` payload carrying anything
    /// other than 0 or 1 is rejected with [`BvBroadcastError::UnknownMessageType`].
    pub async fn binary_handle<N>(
        &self,
        message: BvBroadcastMessage<AvssSessionId>,
        network: Arc<N>,
    ) -> Result<(), BvBroadcastError>
    where
        N: Network + Send + Sync,
    {
        // The message can come from an adversary that is not in the range of valid parties. In that
        // case, we just ignore the message.
        if message.sender_id >= self.n_parties {
            return Ok(());
        }

        // Extracts the bit received
        let recv_bit = match message.payload {
            TaggedMessage::Binary(0) => 0,
            TaggedMessage::Binary(1) => 1,
            _ => return Err(BvBroadcastError::UnknownMessageType(message.payload)),
        };

        let store = self.get_or_create_store(message.session_id).await;
        {
            let guard = store.lock().await;
            if guard.protocol_ended {
                return Ok(());
            }
        }

        if let TaggedMessage::Binary(recv_v) = message.payload {
            let should_broadcast = {
                let mut store_guard = store.lock().await;
                store_guard
                    .recv_bin_values
                    .insert((message.sender_id, recv_v));
                let n_recv_v = store_guard
                    .recv_bin_values
                    .iter()
                    .filter(|(_, v)| *v == recv_v)
                    .count();

                // If the bit was already sent, then we dont send it anymore and just return.
                let sent_bit_guard = if recv_bit == 0 {
                    store_guard.bit_sent.0
                } else {
                    store_guard.bit_sent.1
                };

                let should_broadcast = n_recv_v >= self.threshold + 1 && !sent_bit_guard;

                if should_broadcast {
                    if recv_bit == 0 {
                        store_guard.bit_sent.0 = true;
                    } else {
                        store_guard.bit_sent.1 = true;
                    }
                }

                // Check if bin values can be filled.
                if n_recv_v >= 2 * self.threshold + 1 {
                    store_guard.bin_values_tx.send_modify(|set| {
                        set.insert(recv_v);
                    });
                }

                should_broadcast
            };

            if should_broadcast {
                let enc_bit = encode_message_bv_broadcast_avss(BvBroadcastMessage::new(
                    self.id,
                    message.session_id,
                    message.round_id,
                    TaggedMessage::Binary(recv_v),
                ))?;
                network.broadcast(&enc_bit).await?;
            }
        }

        Ok(())
    }

    /// Entry point for messages routed to this BV-Broadcast instance, dispatching on the payload tag
    /// (step 4).
    ///
    /// Only [`TaggedMessage::Binary`] is accepted; any other tag yields
    /// [`BvBroadcastError::UnknownMessageType`].
    pub async fn process<N>(
        &self,
        message: BvBroadcastMessage<AvssSessionId>,
        network: Arc<N>,
    ) -> Result<(), BvBroadcastError>
    where
        N: Network + Send + Sync,
    {
        match message.payload {
            TaggedMessage::Binary(_) => self.binary_handle(message, network).await?,
            unk_msg => return Err(BvBroadcastError::UnknownMessageType(unk_msg)),
        }
        Ok(())
    }
}
