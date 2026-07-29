//! Implementation of Crain's SBV-Broadcast taken from ["Practical Asynchronous Distributed Key Generation"](https://eprint.iacr.org/2021/1591.pdf), Appendix B, Algorithm 4.
//!
//! SBV-Broadcast ("synchronized binary value broadcast") is the middle layer of Crain's ABA stack:
//! it runs on top of [`BvBroadcast`] and feeds [`CrainAba`](super::CrainAba). Where BV-Broadcast
//! yields a set `bin_values` of values that at least one honest party proposed, SBV-Broadcast adds a
//! round of `AUX` messages and returns a *pair*: a `view` that is a subset of `bin_values` witnessed
//! by a quorum, alongside `bin_values` itself.
//!
//! With `n` parties, of which at most `t` are Byzantine (`n >= 3t + 1`), a party with input `v`
//! runs:
//!
//! ```text
//! 1: bin_values <- BV_Broadcast(v)
//! 2: wait until bin_values != {}
//! 3: send AUX(w) for w in bin_values to all
//! 4: wait until exists a set view such that (i) view subset of bin_values; and
//!    (ii) contained in AUX(.) messages received from n - t nodes;
//! 5: return (view, bin_values)
//! ```
//!
//! The `n - t` quorum in step 4 is what the whole layer rests on, and it counts **distinct
//! parties**. Any two quorums of `n - t` parties out of `n` overlap in at least
//! `2(n - t) - n = n - 2t >= t + 1` parties, so at least one *honest* party is in both. That shared
//! honest witness is what stops two honest parties from ending up with contradictory singleton
//! views, which is the property Algorithm 5 relies on when it tests `view = {w}`.
//!
//! Two details of step 4 are easy to get wrong, and both are load-bearing:
//!
//! - The count must be over distinct senders, not over received messages. An honest party whose
//!   `bin_values` is `{0, 1}` legitimately sends **two** `AUX` messages (step 3), so counting
//!   messages would clear the quorum bar at roughly half the required parties and collapse the
//!   intersection argument above.
//! - Step 4 asks for the *existence* of a qualifying `view`, so `AUX` values outside `bin_values`
//!   are filtered out rather than treated as disqualifying. Requiring every received `AUX` to lie in
//!   `bin_values` would let a single Byzantine `AUX` block the condition indefinitely.
//!
//! # Waiting on a set that fills asynchronously
//!
//! Steps 2 and 4 both wait on state that other tasks mutate. `bin_values` is watched through the
//! [`watch::Receiver`](tokio::sync::watch::Receiver) handed back by [`BvBroadcast::init`], so step 2
//! is a single `wait_for` rather than a poll loop.
//!
//! Step 4's condition depends on *both* `bin_values` and the received `AUX` messages, so it is
//! re-evaluated from two places: [`SbvBroadcast::aux_handle`] when an `AUX` arrives, and the task
//! spawned by [`SbvBroadcast::init`] when `bin_values` grows. Either can be the one that completes
//! the condition, so both must check; whichever gets there first emits the single output, which
//! `check_if_output_sent_and_update` arbitrates.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use bincode::ErrorKind;
use serde::{Deserialize, Serialize};
use stoffelnet::network_utils::{Network, NetworkError, PartyId};
use tokio::sync::{
    watch::{self, error::RecvError},
    Mutex,
};

use crate::{
    avss_mpc::{AvssSessionId, AvssWrappedMessage},
    common::aba::{
        bv_bc::{BvBroadcast, BvBroadcastError},
        BinValue, Tag, TaggedMessage,
    },
};

/// Errors that can arise while running SBV-Broadcast.
#[derive(thiserror::Error, Debug)]
pub enum SbvBroadcastError {
    #[error("error while serializing the object into bytes: {0:?}")]
    SerializationError(#[from] Box<ErrorKind>),
    /// The network failed while broadcasting an `AUX` message.
    #[error("there was an error in the network: {0:?}")]
    NetworkError(#[from] NetworkError),

    /// The underlying BV-Broadcast (step 1) failed.
    #[error("there was an error in the BV-Broadcast protocol: {0:?}")]
    BvBroadcastError(#[from] BvBroadcastError),

    /// Waiting on `bin_values` failed because BV-Broadcast dropped the sending half of the channel,
    /// which happens when the session state is torn down.
    #[error("there was an error in the watcher receiver: {0:?}")]
    RecvError(#[from] RecvError),

    /// Currently unreachable: the `bin_values` receiver is obtained on demand from
    /// [`BvBroadcast::subscribe_to_bin_values`], which always succeeds, so there is no longer a
    /// window in which a handler can find it missing.
    #[error("the watcher for the bin values has not been initialized")]
    NoWatcher,

    /// A message reached [`SbvBroadcast::aux_handle`] with a payload that was not
    /// [`TaggedMessage::Aux`] carrying 0 or 1. SBV-Broadcast only speaks `AUX`; `Binary` belongs to
    /// BV-Broadcast below and `AuxSet` to the ABA layer above.
    #[error("unknown message type: {0:?}")]
    UnknownMessageType(TaggedMessage),
}

/// An `AUX(w)` message, the only kind of message SBV-Broadcast sends (step 3).
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SbvBroadcastMessage<I> {
    /// ID of the sending party. Step 4's quorum counts *distinct parties*, so this is what keeps a
    /// party that sends both `AUX(0)` and `AUX(1)` from counting twice.
    pub sender_id: usize,
    /// Session this broadcast instance belongs to.
    pub session_id: I,
    /// Distinguishes concurrent SBV-Broadcast instances within one session — what §2.1 calls the
    /// instance's TAG. It is forwarded unchanged to the [`BvBroadcast`] underneath, so the two
    /// layers of one instance share it, and `(session_id, tag)` is what keys the per-instance state.
    pub tag: Tag,
    /// The broadcast value. Always [`TaggedMessage::Aux`] for SBV-Broadcast.
    pub payload: TaggedMessage,
}

impl SbvBroadcastMessage<AvssSessionId> {
    /// Creates an `AUX` message for the instance `(session_id, tag)`.
    pub fn new(
        sender_id: usize,
        session_id: AvssSessionId,
        tag: Tag,
        payload: TaggedMessage,
    ) -> Self {
        Self {
            sender_id,
            session_id,
            tag,
            payload,
        }
    }
}

/// Wraps an `AUX` message and serializes it for the wire, so the receiving AVSS node's dispatcher
/// can route it back to SBV-Broadcast.
fn encode_message_sbv_broadcast_avss(
    m: SbvBroadcastMessage<AvssSessionId>,
) -> Result<Vec<u8>, SbvBroadcastError> {
    let wrapped = AvssWrappedMessage::SbvBroadcast(m);
    let bytes = bincode::serialize(&wrapped)?;
    Ok(bytes)
}

/// A party running SBV-Broadcast, able to serve many concurrent instances.
pub struct SbvBroadcast<I> {
    /// ID of this party.
    id: usize,
    /// Total number of parties, `n`.
    n_parties: usize,
    /// Maximum number of Byzantine parties tolerated, `t`. The protocol assumes `n >= 3t + 1`.
    threshold: usize,
    /// The BV-Broadcast layer beneath this one, providing step 1.
    pub bv_broadcast: BvBroadcast<I>,
    /// State per instance, keyed by `(session_id, tag)` for the same reason as
    /// [`BvBroadcast`]'s store: one session may run many instances of the abstraction.
    store: Arc<Mutex<HashMap<(AvssSessionId, Tag), Arc<Mutex<SbvStorage>>>>>,
}

/// Whether step 4's condition holds yet.
#[derive(Clone)]
pub enum ProtocolOutputState {
    /// No `view` satisfies step 4 yet. More `AUX` messages, or a larger `bin_values`, may change
    /// that, so the condition is re-checked on both.
    Pending,
    /// Step 4 is satisfied and the pair of step 5 is ready.
    Ready(SbvOutput),
}

/// The `(view, bin_values)` pair returned by step 5.
#[derive(Clone)]
pub struct SbvOutput {
    /// Instance within that session this output belongs to. Every instance reports on one shared
    /// channel, and a caller running several of them per session — as Crain's ABA does — needs both
    /// this and `session_id` to tell whose result just arrived.
    pub tag: Tag,
    /// The values of step 4: a subset of `bin_values` witnessed by `AUX` messages from `n - t`
    /// distinct parties. A set rather than a list, because the ABA layer above tests it for set
    /// equality (`view = {w}`, `view = {v, bottom}`).
    pub view: HashSet<BinValue>,
}

/// State of a single SBV-Broadcast instance, i.e. of one session.
pub struct SbvStorage {
    /// Whether the single step 5 output has been emitted. Claimed atomically by
    /// `check_if_output_sent_and_update`, since two independent paths can find the condition
    /// satisfied.
    output_sent: bool,
    /// The `(sender_id, value)` pairs from received `AUX` messages. Pairing the value with its
    /// sender is what lets step 4 count *distinct parties*: a party legitimately sends one `AUX` per
    /// element of its `bin_values`, so counting messages would overcount the quorum.
    recv_aux: HashSet<(PartyId, BinValue)>,
    output_tx: watch::Sender<ProtocolOutputState>,
}

impl SbvStorage {
    /// Creates the state for a session that has not yet received or sent anything.
    pub fn empty() -> Self {
        Self {
            output_sent: false,
            recv_aux: HashSet::new(),
            output_tx: watch::Sender::new(ProtocolOutputState::Pending),
        }
    }
}

impl SbvBroadcast<AvssSessionId> {
    pub async fn subscribe_to_output(
        &self,
        session_id: AvssSessionId,
        tag: Tag,
    ) -> watch::Receiver<ProtocolOutputState> {
        self.get_or_create_store(session_id, tag)
            .await
            .lock()
            .await
            .output_tx
            .subscribe()
    }

    /// Creates an SBV-Broadcast party with ID `id`, among `n_parties` parties tolerating `threshold`
    /// Byzantine ones, delivering each session's step 5 result on `output_tx`.
    ///
    /// This also creates the [`BvBroadcast`] instance underneath, which shares the same parameters.
    pub fn new(id: usize, n_parties: usize, threshold: usize) -> Self {
        Self {
            id,
            n_parties,
            threshold,
            bv_broadcast: BvBroadcast::new(id, n_parties, threshold),
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Returns the state for the instance `(session_id, tag)`, creating it on first use.
    async fn get_or_create_store(
        &self,
        session_id: AvssSessionId,
        tag: Tag,
    ) -> Arc<Mutex<SbvStorage>> {
        let store_lock = {
            let mut store = self.store.lock().await;
            store
                .entry((session_id, tag))
                .or_insert_with(|| Arc::new(Mutex::new(SbvStorage::empty())))
                .clone()
        };

        store_lock
    }

    /// Starts SBV-Broadcast for the instance `(session_id, tag)` with input `v`, covering steps 1
    /// to 3: it runs BV-Broadcast, waits for `bin_values` to become non-empty, and broadcasts one
    /// `AUX(w)` per value in it.
    ///
    /// Returns as soon as the `AUX` messages are away. Step 4 is not waited on here — the result
    /// arrives later on `output_sender`, emitted by whichever of the two checkers sees the condition
    /// hold first.
    ///
    /// Before returning, this spawns the task that re-evaluates step 4 whenever `bin_values` grows.
    /// That task is one of the two triggers; [`Self::aux_handle`] is the other. Both are needed,
    /// since the condition depends on `bin_values` and on the received `AUX` messages, and either
    /// can be the last to change.
    ///
    /// Note that `bin_values` is cloned out of the watch channel before the broadcast loop. Holding
    /// the [`Ref`](tokio::sync::watch::Ref) across an `.await` would keep a read lock on the channel
    /// and block BV-Broadcast's writes, deadlocking outright on a single-threaded runtime.
    pub async fn init<N>(
        &self,
        session_id: AvssSessionId,
        tag: Tag,
        v: BinValue,
        network: Arc<N>,
    ) -> Result<(), SbvBroadcastError>
    where
        N: Network + Send + Sync,
    {
        let mut bin_values_watcher = self
            .bv_broadcast
            .init(session_id, tag, v, network.clone())
            .await?;
        bin_values_watcher
            .wait_for(|bin_set| !bin_set.is_empty())
            .await?;
        {
            let bin_values = bin_values_watcher.borrow().clone();
            for element in bin_values {
                let message =
                    SbvBroadcastMessage::new(self.id, session_id, tag, TaggedMessage::Aux(element));
                let enc_message = encode_message_sbv_broadcast_avss(message)?;
                network.broadcast(&enc_message).await?;
            }
        }

        // Starts a task to check if bin_values change and it meets the condition to
        tokio::spawn({
            let storage = self.get_or_create_store(session_id, tag).await.clone();
            let n_parties = self.n_parties;
            let threshold = self.threshold;
            async move {
                while let Ok(()) = bin_values_watcher.changed().await {
                    let bin_values = bin_values_watcher.borrow().clone();
                    let check_result = {
                        let storage_guard = storage.lock().await;
                        check_bin_value_match(
                            n_parties,
                            threshold,
                            tag,
                            bin_values,
                            &storage_guard.recv_aux,
                        )
                    };
                    match check_result {
                        ProtocolOutputState::Ready(output) => {
                            if check_if_output_sent_and_update(storage.clone()).await {
                                storage
                                    .lock()
                                    .await
                                    .output_tx
                                    .send_replace(ProtocolOutputState::Ready(output));
                            }
                        }
                        ProtocolOutputState::Pending => {}
                    }
                }
            }
        });

        Ok(())
    }

    /// Handles an incoming `AUX` message: records `(sender_id, value)` and re-evaluates step 4.
    ///
    /// This is one of the two places the condition is checked — the other being the task spawned by
    /// [`Self::init`], which fires when `bin_values` grows. An `AUX` arriving here may be the event
    /// that completes the quorum, so the check cannot wait for `bin_values` to change again.
    ///
    /// Messages are dropped when `sender_id` falls outside `0..n_parties`, which an adversary is
    /// free to make up. That guard matters more here than in BV-Broadcast: because step 4 counts
    /// distinct senders toward `n - t`, a single party forging sender IDs could otherwise reach the
    /// quorum on its own.
    ///
    /// An `AUX` payload carrying anything other than 0 or 1 is rejected with
    /// [`SbvBroadcastError::UnknownMessageType`].
    pub async fn aux_handle(
        &self,
        session_id: AvssSessionId,
        message: SbvBroadcastMessage<AvssSessionId>,
    ) -> Result<(), SbvBroadcastError> {
        if message.sender_id >= self.n_parties {
            return Ok(());
        }

        // Extracts the bit received
        let recv_bit = match message.payload {
            TaggedMessage::Aux(v) => v,
            _ => return Err(SbvBroadcastError::UnknownMessageType(message.payload)),
        };

        let storage = self.get_or_create_store(session_id, message.tag).await;
        storage
            .lock()
            .await
            .recv_aux
            .insert((message.sender_id, recv_bit));

        let bin_values = self
            .bv_broadcast
            .subscribe_to_bin_values(session_id, message.tag)
            .await
            .borrow()
            .clone();

        let check_result = {
            let storage_guard = storage.lock().await;
            check_bin_value_match(
                self.n_parties,
                self.threshold,
                message.tag,
                bin_values,
                &storage_guard.recv_aux,
            )
        };
        match check_result {
            ProtocolOutputState::Ready(output) => {
                if check_if_output_sent_and_update(storage.clone()).await {
                    storage
                        .lock()
                        .await
                        .output_tx
                        .send_replace(ProtocolOutputState::Ready(output));
                }
            }
            ProtocolOutputState::Pending => {}
        }

        Ok(())
    }
}

/// Atomically claims the right to emit this session's single step 5 output.
///
/// Returns `true` if the caller won the claim and must send, `false` if another path already did.
///
/// The read and the write happen under one guard on purpose. Two paths evaluate step 4
/// independently — [`SbvBroadcast::aux_handle`] and the task spawned by [`SbvBroadcast::init`] — and
/// both can find the condition satisfied at nearly the same moment. Checking the flag, releasing the
/// lock, sending, and only then setting it would let both observe `false` while a send is in flight
/// and emit twice, which the ABA layer above cannot absorb: it expects one `(view, bin_values)` per
/// session.
///
/// The send itself is deliberately left to the caller, so the channel is never awaited while the
/// lock is held.
async fn check_if_output_sent_and_update(store: Arc<Mutex<SbvStorage>>) -> bool {
    let mut guard = store.lock().await;
    if guard.output_sent {
        false
    } else {
        guard.output_sent = true;
        true
    }
}

/// Evaluates step 4 against the `AUX` messages received so far and the given `bin_values`.
///
/// Returns [`ProtocolOutputState::Ready`] with the step 5 pair once some `view` satisfies both
/// clauses, and [`ProtocolOutputState::Pending`] otherwise. It is called on every `AUX` arrival and
/// on every change to `bin_values`, so `Pending` simply means "not yet" — the same state may satisfy
/// the condition on a later call.
///
/// The two clauses map onto the code as follows:
///
/// - *(i) `view` is a subset of `bin_values`* — the received pairs are **filtered** to those whose
///   value lies in `bin_values`. Filtering rather than requiring every received `AUX` to qualify is
///   what implements the paper's "there exists a set `view`": a Byzantine `AUX` carrying a value
///   outside `bin_values` is ignored instead of blocking the condition forever.
/// - *(ii) contained in `AUX` messages received from `n - t` nodes* — the surviving pairs are
///   projected onto their senders and **counted as a set**. Counting pairs would overcount, since a
///   party sends one `AUX` per element of its `bin_values` and so contributes two pairs whenever
///   that set is `{0, 1}`.
fn check_bin_value_match(
    n_parties: usize,
    threshold: usize,
    tag: Tag,
    bin_values: HashSet<BinValue>,
    potential_view: &HashSet<(usize, BinValue)>,
) -> ProtocolOutputState {
    // Compute the AUX received elements that are in bin_values.
    let matches_in_view: HashSet<(usize, BinValue)> = potential_view
        .iter()
        .filter(|(_, value)| bin_values.contains(value))
        .copied()
        .collect();

    let senders: HashSet<usize> = matches_in_view
        .clone()
        .iter()
        .copied()
        .map(|(pid, _)| pid)
        .collect();
    if senders.len() >= n_parties - threshold {
        let view = matches_in_view
            .iter()
            .map(|(_, value)| value)
            .copied()
            .collect();
        ProtocolOutputState::Ready(SbvOutput { tag, view })
    } else {
        ProtocolOutputState::Pending
    }
}
