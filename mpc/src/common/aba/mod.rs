//! Implementation of Crain's binary Byzantine consensus taken from ["Two More Algorithms for
//! Randomized Signature-Free Asynchronous Binary Byzantine Consensus with t < n/3 and O(n^2)
//! Messages and O(1) Round Expected Termination"](https://arxiv.org/abs/2002.08765), Figure 3.
//!
//! This is the top of the stack: it runs on [`SbvBroadcast`](sbv_bc::SbvBroadcast), which runs on
//! [`BvBroadcast`](bv_bc::BvBroadcast). With `n` parties of which at most `t` are Byzantine
//! (`n >= 3t + 1`) and a weak common coin, a party proposing `v` runs:
//!
//! ```text
//! 01: est <- v; r <- 0;
//! repeat forever
//! 02:   r <- r + 1;
//! 03:   (view[r, 0], bin_values[r]) <- SBV_broadcast stage[r, 0](est);
//! 04:   broadcast auxset[r](view[r, 0]);
//! 05:   wait until (exists a set view[r, 1] such that its values (i) belong to bin_values[r] and
//!                   (ii) come from auxset[r]() messages received from n - t distinct processes);
//! 06:   if (view[r, 1] = {w})
//! 07:     then est <- w
//! 08:     else est <- bottom
//! 09:   end if
//! 10:   (view[r, 2], _) <- SBV_broadcast stage[r, 1](est);
//! 11:   s <- random();
//! 12:   case (view[r, 2] = {v} and v != bottom) then est <- v; decide(v) if not yet done
//! 13:        (view[r, 2] = {v, bottom})         then est <- v
//! 14:        (view[r, 2] = {bottom})            then est <- s
//! 15:   end case
//! end repeat.
//! ```
//!
//! # The two SBV-Broadcast calls
//!
//! Each round invokes SBV-Broadcast twice, under the tags `stage[r, 0]` and `stage[r, 1]`, which is
//! what [`Tag`] carries. The first runs on binary estimates only (Lemma 2); the second may also
//! carry `⊥` from line 08, so the alphabet of the layers below is [`BinValue`] rather than a bare
//! bit. Widening it is safe because Lemma 6 bounds what non-faulty processes feed into
//! `stage[r, 1]` to at most `{v, ⊥}` for a single binary `v` — never all three at once, which is
//! what would leave BV-Broadcast's `2t + 1` threshold unreachable for one of them.
//!
//! # Waiting on line 05
//!
//! Line 05's condition depends on two things that fill asynchronously and independently: the
//! `AUXSET[r]` messages received, and `bin_values[r]`, which BV-Broadcast keeps growing after
//! line 03 has already returned. Either can be the change that satisfies the condition, so it is
//! re-evaluated from both — [`CrainAba::aux_set_handler`] on each `AUXSET` arrival, and a task
//! spawned by [`CrainAba::init`] on each growth of `bin_values`. Both funnel into
//! [`settle_view`], which publishes the first qualifying `view[r, 1]` on a latching
//! [`watch`] channel and ignores every later one, so the round's view is fixed exactly once.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use async_trait::async_trait;
use bincode::ErrorKind;
use itertools::Itertools;
use rand::Rng;
use serde::{Deserialize, Serialize};
use stoffelnet::network_utils::{Network, NetworkError};
use tokio::sync::{watch, Mutex};

use crate::{
    avss_mpc::{AvssSessionId, AvssWrappedMessage},
    common::aba::sbv_bc::{ProtocolOutputState, SbvBroadcast, SbvBroadcastError},
};

pub mod bv_bc;
pub mod sbv_bc;

/// The alphabet of the ABA stack: the two binary values, plus the `⊥` of line 08.
#[derive(Copy, PartialOrd, Ord, Clone, Eq, PartialEq, Debug, Serialize, Deserialize, Hash)]
pub enum BinValue {
    One,
    Zero,
    /// The paper's `⊥`, produced by line 08 when `view[r, 1]` is not a singleton.
    Empty,
}

impl BinValue {
    /// Whether this is one of the two binary values, as opposed to `⊥`.
    fn is_binary(&self) -> bool {
        !matches!(self, BinValue::Empty)
    }
}

/// Whether line 05's condition holds yet, for one round.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ViewState {
    /// No set satisfies both clauses of line 05 yet. More `AUXSET[r]` messages, or a larger
    /// `bin_values[r]`, may change that, so the condition is re-checked on both.
    Pending,
    /// Line 05 is satisfied and `view[r, 1]` is fixed for this round.
    Ready(HashSet<BinValue>),
}

/// An `AUXSET[r](view)` message, the only kind of message this layer sends (line 04).
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct CrainAbaMessage<I> {
    /// ID of the sending party. Line 05 counts *distinct processes*, so this is what a duplicate
    /// `AUXSET` is deduplicated against.
    pub sender_id: usize,
    /// Session this broadcast instance belongs to.
    pub session_id: I,
    /// The `stage[r, 0]` tag of the round that produced the enclosed view.
    ///
    /// Line 04 broadcasts `view[r, 0]`, the output of `SBV_broadcast stage[r, 0]`, and line 05
    /// tests it against `bin_values[r]`, which is that same instance's set. Carrying the tag rather
    /// than a bare round number is what lets the receiver find the right `bin_values` to check
    /// against; `stage` is therefore always 0 here, and [`CrainAba::aux_set_handler`] rejects
    /// anything else.
    pub tag: Tag,
    /// The broadcast set. Always [`TaggedMessage::AuxSet`] at this layer.
    pub payload: TaggedMessage,
}

fn encode_message_crain_aba_avss(
    m: CrainAbaMessage<AvssSessionId>,
) -> Result<Vec<u8>, CrainAbaError> {
    let wrapped = AvssWrappedMessage::CrainAba(m);
    let bytes = bincode::serialize(&wrapped)?;
    Ok(bytes)
}

/// The payload of a message at any layer of the ABA stack.
///
/// Variants carry *content only*. Which instance of an abstraction a message belongs to is never
/// encoded here: it lives in the enclosing message struct, as a [`Tag`] for the BV- and
/// SBV-Broadcast layers and as a plain round number for `AUXSET`. Keeping the discriminator in one
/// place is what stops the key a message routes by and the value it is interpreted against from
/// drifting apart.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TaggedMessage {
    /// `AUX(w)`, sent by SBV-Broadcast at its step 3.
    Aux(BinValue),
    /// `B_VAL(v)`, sent by BV-Broadcast at its steps 2 and 6.
    Binary(BinValue),
    /// `AUXSET[r](view)`, broadcast by Crain's ABA at line 04 of Figure 3.
    ///
    /// Carries `view[r, 0]`, which by Lemma 2 holds only binary values — never
    /// [`BinValue::Empty`]. The round `r` is the tag of this message, so it belongs to the
    /// envelope rather than here.
    AuxSet(HashSet<BinValue>),
}

/// Identifies one instance of the BV- or SBV-Broadcast abstraction within a session.
///
/// This is what §2.1 calls the instance's TAG: an abstraction may be invoked many times inside one
/// session, and the tag is what keeps those invocations' state apart. Crain's ABA invokes
/// SBV-Broadcast twice per round, so its tag is the paper's `STAGE[r, b]` — carried here with the
/// two indices kept separate rather than folded into one number.
#[derive(Serialize, Deserialize, Hash, PartialEq, Eq, Debug, Clone, Copy)]
pub struct Tag {
    /// The ABA round r.
    pub round: usize,
    /// A binary value denoting the ABA stage.
    ///
    /// A `stage` of 0 means `STAGE[r, 0]`, and a `stage` of 1 means `STAGE[r, 1]`.
    pub stage: u8,
}

#[derive(thiserror::Error, Debug)]
pub enum CrainAbaError {
    #[error("error while serializing the object into bytes: {0:?}")]
    SerializationError(#[from] Box<ErrorKind>),
    #[error("error while executing the SBV-Broadcast protocol: {0:?}")]
    SbvError(#[from] SbvBroadcastError),
    #[error("there was an error in the watcher receiver: {0:?}")]
    RecvError(#[from] watch::error::RecvError),
    #[error("the output from SBV broadcast is not ready")]
    MissingSbvOutput,
    #[error("there was an error in the network: {0:?}")]
    NetworkError(#[from] NetworkError),

    /// A message reached [`CrainAba::aux_set_handler`] with a payload that was not
    /// [`TaggedMessage::AuxSet`]. This layer only speaks `AUXSET`; `Binary` belongs to
    /// BV-Broadcast and `Aux` to SBV-Broadcast underneath it.
    #[error("unknown message type: {0:?}")]
    UnknownMessageType(TaggedMessage),

    /// Line 05 reported itself satisfied but produced no view. Unreachable:
    /// [`settle_view`] only ever publishes [`ViewState::Ready`].
    #[error("the view for line 05 is not ready")]
    MissingView,

    /// `view[r, 2]` matched none of the three cases of lines 12 to 14.
    ///
    /// The paper's `case` has no fallthrough because Lemma 6 rules the remaining shapes out:
    /// non-faulty processes feed `stage[r, 1]` at most `{v, ⊥}` for one binary `v`, so
    /// BV-Broadcast's validity property keeps `{0, 1}` and `{0, 1, ⊥}` out of `view[r, 2]`.
    /// Reaching this means an invariant below has broken, which is worth surfacing rather than
    /// silently leaving `est` unchanged.
    #[error("view_i[r, 2] was {0:?}, which no case of lines 12 to 14 covers")]
    UnexpectedView(HashSet<BinValue>),

    /// The main loop ended without a decision. Unreachable: the loop only exits after a round that
    /// began with the decision already in place.
    #[error("the consensus loop ended without a decision")]
    NoDecision,
}

/// The weak common coin of §2, invoked as `random()` at line 11.
///
/// A weak common coin returns a binary value at every non-faulty process such that, with
/// probability at least `1/d` for a known constant `d >= 2`, *all* non-faulty processes get the
/// same value; with the remaining probability the values may differ arbitrarily. Its output for
/// round `r` must stay unpredictable until at least one non-faulty process reaches line 11 of that
/// round, or a Byzantine adversary could steer estimates against it.
///
/// Only *termination* rests on the coin: Lemma 10's expected `O(1)` rounds comes from that constant
/// probability of agreement. Safety does not — Lemmas 5 to 9 never mention `random()` — so a coin
/// that agrees rarely makes the algorithm slow, never wrong.
#[async_trait]
pub trait CommonCoin: Send + Sync {
    /// Returns the coin for `round` of `session_id`. Always one of [`BinValue::Zero`] or
    /// [`BinValue::One`], never [`BinValue::Empty`].
    async fn flip(&self, session_id: AvssSessionId, round: usize) -> BinValue;
}

/// A stand-in for [`CommonCoin`] that flips a *local* coin, sharing nothing between parties.
///
/// This is **not** a common coin. Non-faulty processes agree only with probability `2^-(n-t)` in a
/// round rather than a constant one, so expected termination degrades from `O(1)` rounds to
/// exponential in `n`. Safety is untouched for the reason given on [`CommonCoin`], which is what
/// makes this usable to exercise the algorithm end to end while a real coin is wired up.
pub struct LocalCoin;

#[async_trait]
impl CommonCoin for LocalCoin {
    async fn flip(&self, _session_id: AvssSessionId, _round: usize) -> BinValue {
        if rand::thread_rng().gen::<bool>() {
            BinValue::One
        } else {
            BinValue::Zero
        }
    }
}

pub struct CrainAbaStore {
    /// Current round of the protocol.
    round: usize,
    /// Current estimation of the agreed bit.
    est: BinValue,
    /// `view_i[]` from Figure 3, keyed by `(round, index)` with `index` in `0..=2` as in §3.2.
    ///
    /// The index is *not* a [`Tag`]: there are three slots per round but only two SBV-Broadcast
    /// instances, because the middle one comes from the ABA's own `AUXSET` round rather than from
    /// SBV-Broadcast. Slot 0 comes from `STAGE[r,0]` (line 03), slot 1 from the round's `AUXSET[r]`
    /// messages (line 05), and slot 2 from `STAGE[r,1]` (line 10).
    view: HashMap<(usize, u8), HashSet<BinValue>>,
    /// The `AUXSET[r]` sets received, keyed by round and then by sender.
    ///
    /// Keying the inner map by sender is what makes line 05's `(n - t)` range over *distinct
    /// processes*: a party that broadcasts several `AUXSET[r]` messages occupies one entry, and
    /// [`CrainAba::aux_set_handler`] keeps the first, so its contribution can never change once
    /// counted.
    recv_aux_set: HashMap<usize, HashMap<usize, HashSet<BinValue>>>,
    /// Latching channel carrying `view_i[r, 1]` for each round, written by [`settle_view`] and read
    /// by the main loop at line 05.
    ///
    /// One channel per round rather than one per session: the loop waits on each round in turn, and
    /// a shared channel would let round `r + 1`'s view overwrite `r`'s before the loop observed it.
    view_1_tx: HashMap<usize, watch::Sender<ViewState>>,
    decision: Decision,
}

impl CrainAbaStore {
    pub fn empty() -> Self {
        Self {
            round: 0,
            est: BinValue::Zero,
            view: HashMap::new(),
            recv_aux_set: HashMap::new(),
            view_1_tx: HashMap::new(),
            decision: Decision::Pending,
        }
    }

    /// Returns the `view[r, 1]` channel for `round`, creating it on first use.
    ///
    /// Created on demand from either side, because an `AUXSET[r]` message can arrive before the
    /// main loop reaches round `r`. Since `watch` retains its current value, a receiver taken later
    /// still observes a view published earlier, so subscribing never races against delivery.
    fn view_1_channel(&mut self, round: usize) -> &watch::Sender<ViewState> {
        self.view_1_tx
            .entry(round)
            .or_insert_with(|| watch::Sender::new(ViewState::Pending))
    }
}

/// A node running Crain's ABA, able to serve many concurrent sessions.
pub struct CrainAba<I> {
    /// ID of this party.
    id: usize,
    /// Total number of parties, `n`.
    n_parties: usize,
    /// Maximum number of Byzantine parties tolerated, `t`. The protocol assumes `n >= 3t + 1`.
    threshold: usize,
    /// State per session.
    store: Arc<Mutex<HashMap<I, Arc<Mutex<CrainAbaStore>>>>>,
    /// The SBV-Broadcast layer beneath this one, providing lines 03 and 10.
    sbv_broadcast: SbvBroadcast<I>,
    /// The `random()` of line 11.
    coin: Arc<dyn CommonCoin>,
}

/// Whether `decide()` has fired for a session.
#[derive(Clone, Copy, Debug)]
pub enum Decision {
    Ready(BinValue),
    Pending,
}

impl CrainAba<AvssSessionId> {
    /// Creates an ABA party with ID `id`, among `n_parties` parties tolerating `threshold`
    /// Byzantine ones. This also creates the [`SbvBroadcast`] instance underneath, which shares the
    /// same parameters.
    pub fn new(id: usize, n_parties: usize, threshold: usize, coin: Arc<dyn CommonCoin>) -> Self {
        let sbv_broadcast = SbvBroadcast::new(id, n_parties, threshold);
        Self {
            id,
            n_parties,
            threshold,
            store: Arc::new(Mutex::new(HashMap::new())),
            sbv_broadcast,
            coin,
        }
    }

    async fn get_or_create_store(&self, session_id: AvssSessionId) -> Arc<Mutex<CrainAbaStore>> {
        let store_lock = {
            let mut store = self.store.lock().await;
            store
                .entry(session_id)
                .or_insert_with(|| Arc::new(Mutex::new(CrainAbaStore::empty())))
                .clone()
        };

        store_lock
    }

    /// Returns a receiver watching `view[r, 1]` for `round` of `session_id`.
    ///
    /// Safe to call at any point: `watch` retains the current value, so a caller that subscribes
    /// after the view was settled still sees it.
    async fn subscribe_to_view_1(
        &self,
        session_id: AvssSessionId,
        round: usize,
    ) -> watch::Receiver<ViewState> {
        let storage = self.get_or_create_store(session_id).await;
        let mut guard = storage.lock().await;
        guard.view_1_channel(round).subscribe()
    }

    /// The decision reached for `session_id` so far, if any.
    pub async fn decision(&self, session_id: AvssSessionId) -> Decision {
        self.get_or_create_store(session_id)
            .await
            .lock()
            .await
            .decision
    }

    /// Runs `propose(v)` for `session_id`: line 01 followed by the loop of lines 02 to 15,
    /// returning the decided value.
    ///
    /// # Termination
    ///
    /// Reaching `decide(v)` at line 12 does not license leaving the loop at the end of that round.
    /// Lemma 8 is what makes stopping safe, and it is a statement about the round *after* the one
    /// that decided: a process deciding `v` in round `r` had `view[r, 2] = {v}`, which by
    /// SBV-Uniformity forces every non-faulty process to enter round `r + 1` with `est = v`, and
    /// from there `v` is the only value any of them can ever decide. So a process that decides in
    /// `r` runs `r + 1` to completion — carrying its own `AUXSET` and both `SBV_broadcast` calls,
    /// which the others are still waiting on — and only then stops. The loop therefore exits at the
    /// end of the first round that *began* with a decision already in place, which is one full
    /// round later than the decision itself.
    pub async fn init<N>(
        &self,
        v: BinValue,
        session_id: AvssSessionId,
        network: Arc<N>,
    ) -> Result<BinValue, CrainAbaError>
    where
        N: Send + Sync + Network,
    {
        let store = self.get_or_create_store(session_id).await;

        // Line 01.
        {
            let mut store_guard = store.lock().await;
            store_guard.est = v;
            store_guard.round = 0;
        }

        loop {
            let (round, est, decided_before_round) = {
                // Line 02.
                let mut store_guard = store.lock().await;
                store_guard.round += 1;
                (
                    store_guard.round,
                    store_guard.est,
                    matches!(store_guard.decision, Decision::Ready(_)),
                )
            };

            let tag_first_stage = Tag { round, stage: 0 };
            let tag_second_stage = Tag { round, stage: 1 };

            // Line 03. Subscribing before `init` is not strictly required — the output channel
            // latches — but it keeps the wait independent of how fast the instance completes.
            let mut sbv_output_watcher = self
                .sbv_broadcast
                .subscribe_to_output(session_id, tag_first_stage)
                .await;
            self.sbv_broadcast
                .init(session_id, tag_first_stage, est, network.clone())
                .await?;
            let view_0 = wait_for_sbv_view(&mut sbv_output_watcher).await?;
            store.lock().await.view.insert((round, 0), view_0.clone());

            // Line 04.
            let message = CrainAbaMessage {
                session_id,
                sender_id: self.id,
                tag: tag_first_stage,
                payload: TaggedMessage::AuxSet(view_0),
            };
            let bytes_message = encode_message_crain_aba_avss(message)?;
            network.broadcast(&bytes_message).await?;

            // Line 05. The condition on view_i[r_i, 1] may hold because of two reasons: (1) a
            // modification on the bin_values, or (2) a modification in the received AUXSET
            // messages. Hence we need to check for both potential modification triggers. Trigger
            // (2) is `aux_set_handler`; the task below is trigger (1).
            let mut view_1_watcher = self.subscribe_to_view_1(session_id, round).await;
            tokio::spawn({
                let n_parties = self.n_parties;
                let threshold = self.threshold;
                let storage = store.clone();
                let mut bin_values_watcher = self
                    .sbv_broadcast
                    .bv_broadcast
                    .subscribe_to_bin_values(session_id, tag_first_stage)
                    .await;
                async move {
                    // The check comes before the first `changed()` on purpose. `changed()` only
                    // reports growth from this point on, and every `AUXSET` that arrived before
                    // this task existed was checked against whatever `bin_values` held at the time
                    // — which may since have grown. Checking up front covers both gaps.
                    loop {
                        let bin_values = bin_values_watcher.borrow().clone();
                        if settle_view(n_parties, threshold, round, storage.clone(), bin_values)
                            .await
                        {
                            return;
                        }
                        if bin_values_watcher.changed().await.is_err() {
                            return;
                        }
                    }
                }
            });

            let view_1 = {
                let state = view_1_watcher
                    .wait_for(|state| matches!(state, ViewState::Ready(_)))
                    .await?;
                match &*state {
                    ViewState::Ready(view) => view.clone(),
                    ViewState::Pending => return Err(CrainAbaError::MissingView),
                }
            };
            store.lock().await.view.insert((round, 1), view_1.clone());

            // Lines 06 to 09.
            let est_second_stage = match singleton(&view_1) {
                Some(w) => w,
                None => BinValue::Empty,
            };
            store.lock().await.est = est_second_stage;

            // Line 10.
            let mut sbv_output_watcher = self
                .sbv_broadcast
                .subscribe_to_output(session_id, tag_second_stage)
                .await;
            self.sbv_broadcast
                .init(
                    session_id,
                    tag_second_stage,
                    est_second_stage,
                    network.clone(),
                )
                .await?;
            let view_2 = wait_for_sbv_view(&mut sbv_output_watcher).await?;
            store.lock().await.view.insert((round, 2), view_2.clone());

            // Line 11. Sampled unconditionally, even in the rounds that do not read it: the coin
            // is only unpredictable while fewer than t + 1 non-faulty processes have asked for it,
            // so skipping the call in some rounds would leak timing about which branch was taken.
            let coin = self.coin.flip(session_id, round).await;

            // Lines 12 to 15.
            let (new_est, decided) = match singleton(&view_2) {
                // Line 12: view[r, 2] = {v} with v != bottom.
                Some(w) if w.is_binary() => (w, Some(w)),
                // Line 14: view[r, 2] = {bottom}.
                Some(_) => (coin, None),
                None => match pair_with_empty(&view_2) {
                    // Line 13: view[r, 2] = {v, bottom}.
                    Some(w) => (w, None),
                    None => return Err(CrainAbaError::UnexpectedView(view_2)),
                },
            };

            {
                let mut store_guard = store.lock().await;
                store_guard.est = new_est;
                // "decide(v) if not yet done": a later round may re-enter line 12 with the same
                // value, and by Lemma 9 it can only be the same value, but the decision is still
                // recorded once.
                if let (Some(w), Decision::Pending) = (decided, store_guard.decision) {
                    store_guard.decision = Decision::Ready(w);
                }
            }

            if decided_before_round {
                break;
            }
        }

        let decision = store.lock().await.decision;
        match decision {
            Decision::Ready(w) => Ok(w),
            Decision::Pending => Err(CrainAbaError::NoDecision),
        }
    }

    /// Handles an incoming `AUXSET[r]` message: records it against its sender and re-evaluates
    /// line 05.
    ///
    /// This is one of the two places line 05 is checked — the other being the task spawned by
    /// [`Self::init`], which fires when `bin_values[r]` grows. An `AUXSET` arriving here may be the
    /// message that completes the `(n - t)` quorum, so the check cannot wait for `bin_values` to
    /// change again.
    pub async fn aux_set_handler(
        &self,
        session_id: AvssSessionId,
        message: CrainAbaMessage<AvssSessionId>,
    ) -> Result<(), CrainAbaError> {
        if message.sender_id >= self.n_parties {
            return Ok(());
        }

        let recv_view = match message.payload {
            TaggedMessage::AuxSet(view) => view,
            payload => return Err(CrainAbaError::UnknownMessageType(payload)),
        };

        // `AUXSET[r]` reports the output of stage[r, 0]; any other stage is malformed.
        if message.tag.stage != 0 {
            return Ok(());
        }

        if recv_view.is_empty() || !recv_view.iter().all(BinValue::is_binary) {
            return Ok(());
        }

        let round = message.tag.round;
        let storage = self.get_or_create_store(session_id).await;
        {
            let mut storage_guard = storage.lock().await;
            storage_guard
                .recv_aux_set
                .entry(round)
                .or_default()
                .entry(message.sender_id)
                .or_insert(recv_view);
        }

        // Cloned out of the watch channel rather than held: keeping the `Ref` across the `.await`
        // below would block BV-Broadcast's writes to the same channel.
        let bin_values = self
            .sbv_broadcast
            .bv_broadcast
            .subscribe_to_bin_values(session_id, message.tag)
            .await
            .borrow()
            .clone();

        settle_view(self.n_parties, self.threshold, round, storage, bin_values).await;

        Ok(())
    }

    /// Entry point for messages routed to this ABA instance, dispatching on the payload tag.
    ///
    /// Only [`TaggedMessage::AuxSet`] is accepted; the other two tags belong to the layers below
    /// and reach them through their own entry points.
    pub async fn process(
        &self,
        session_id: AvssSessionId,
        message: CrainAbaMessage<AvssSessionId>,
    ) -> Result<(), CrainAbaError> {
        match message.payload {
            TaggedMessage::AuxSet(_) => self.aux_set_handler(session_id, message).await,
            unk_msg => Err(CrainAbaError::UnknownMessageType(unk_msg)),
        }
    }
}

/// Returns the only element of `set`, or `None` if it does not hold exactly one.
fn singleton(set: &HashSet<BinValue>) -> Option<BinValue> {
    let mut values = set.iter();
    match (values.next(), values.next()) {
        (Some(only), None) => Some(*only),
        _ => None,
    }
}

/// Returns `v` if `set` is `{v, ⊥}` for a binary `v`, matching line 13's case.
fn pair_with_empty(set: &HashSet<BinValue>) -> Option<BinValue> {
    if set.len() != 2 || !set.contains(&BinValue::Empty) {
        return None;
    }
    set.iter().copied().find(BinValue::is_binary)
}

/// Blocks until the SBV-Broadcast instance behind `watcher` produces its step 4 view.
///
/// The `Ref` that `wait_for` hands back holds a read lock on the watch channel, which blocks
/// `send_replace` on the sending side. It is cloned out and dropped here so that it never spans an
/// `.await` in the caller.
async fn wait_for_sbv_view(
    watcher: &mut watch::Receiver<ProtocolOutputState>,
) -> Result<HashSet<BinValue>, CrainAbaError> {
    let state = watcher
        .wait_for(|output| matches!(output, ProtocolOutputState::Ready(_)))
        .await?;
    match &*state {
        ProtocolOutputState::Ready(output) => Ok(output.view.clone()),
        ProtocolOutputState::Pending => Err(CrainAbaError::MissingSbvOutput),
    }
}

/// Re-evaluates line 05 for `round` and publishes `view[r, 1]` if it now holds.
///
/// Returns whether the round's view is settled — by this call or by an earlier one. Callers use
/// that to stop watching for further changes.
///
/// The first qualifying view wins and every later one is ignored. Both triggers can find the
/// condition satisfied at nearly the same moment, and they can compute *different* views if
/// `bin_values` grew between them, so the round's view has to be pinned the first time it is
/// derived rather than left to the last writer. The check and the write happen under one guard for
/// the same reason.
async fn settle_view(
    n_parties: usize,
    threshold: usize,
    round: usize,
    storage: Arc<Mutex<CrainAbaStore>>,
    bin_values: HashSet<BinValue>,
) -> bool {
    let mut storage_guard = storage.lock().await;

    if matches!(
        *storage_guard.view_1_channel(round).borrow(),
        ViewState::Ready(_)
    ) {
        return true;
    }

    let view_state = match storage_guard.recv_aux_set.get(&round) {
        Some(recv_aux) => view_from_aux_sets(n_parties, threshold, recv_aux, &bin_values),
        None => ViewState::Pending,
    };

    match view_state {
        ViewState::Ready(view) => {
            storage_guard
                .view_1_channel(round)
                .send_replace(ViewState::Ready(view));
            true
        }
        ViewState::Pending => false,
    }
}

/// Evaluates line 05 of Figure 3 over the `AUXSET` sets received in one round.
///
/// Line 05 asks for a set whose values *(i)* belong to `bin_values_i[r]` and *(ii)* come from
/// `AUXSET[r]()` messages received from `(n - t)` distinct processes. Read together, and as Section
/// 3.2 spells out in prose, that means: choose a quorum of `n - t` distinct senders whose values all
/// lie in `bin_values`, and let the view be the *union* of the sets that quorum sent. A sender
/// contributes its set whole — `(ii)` never licenses taking one value out of a sender's set and
/// leaving the other behind.
fn view_from_aux_sets(
    n_parties: usize,
    threshold: usize,
    recv_aux: &HashMap<usize, HashSet<BinValue>>,
    bin_values: &HashSet<BinValue>,
) -> ViewState {
    let mut candidates: Vec<HashSet<BinValue>> = bin_values
        .iter()
        .copied()
        .powerset()
        .filter(|subset| !subset.is_empty())
        .map(|subset| subset.into_iter().collect())
        .collect();
    candidates.sort_by_key(|candidate| candidate.len());

    for candidate in candidates {
        let n_covered = recv_aux
            .values()
            .filter(|aux_set| aux_set.is_subset(&candidate))
            .count();
        if n_covered >= n_parties - threshold {
            return ViewState::Ready(candidate);
        }
    }

    ViewState::Pending
}

#[cfg(test)]
mod tests {
    use super::*;

    const N_PARTIES: usize = 4;
    const THRESHOLD: usize = 1;

    /// Builds `recv_aux_set[r]`, assigning sender IDs `0..K` in order.
    fn aux_sets<const K: usize>(sets: [&[BinValue]; K]) -> HashMap<usize, HashSet<BinValue>> {
        sets.into_iter()
            .enumerate()
            .map(|(sender, values)| (sender, values.iter().copied().collect()))
            .collect()
    }

    fn set(values: &[BinValue]) -> HashSet<BinValue> {
        values.iter().copied().collect()
    }

    fn check(recv_aux: &HashMap<usize, HashSet<BinValue>>, bin_values: &[BinValue]) -> ViewState {
        view_from_aux_sets(N_PARTIES, THRESHOLD, recv_aux, &set(bin_values))
    }

    #[test]
    fn pending_below_quorum() {
        // Two senders, but n - t = 3 are required.
        let recv_aux = aux_sets([&[BinValue::Zero], &[BinValue::Zero]]);
        assert_eq!(
            check(&recv_aux, &[BinValue::Zero]),
            ViewState::Pending,
            "n - t senders are needed, not merely a majority"
        );
    }

    #[test]
    fn ignores_sender_outside_bin_values() {
        // The fourth sender's value is not in bin_values, so it cannot be part of any quorum; the
        // other three still clear it on their own.
        let recv_aux = aux_sets([
            &[BinValue::Zero],
            &[BinValue::Zero],
            &[BinValue::Zero],
            &[BinValue::One],
        ]);
        assert_eq!(
            check(&recv_aux, &[BinValue::Zero]),
            ViewState::Ready(set(&[BinValue::Zero]))
        );
    }

    #[test]
    fn unions_differing_sets_across_the_quorum() {
        // No three senders agree on a singleton, but all four are subsets of {0, 1}.
        let recv_aux = aux_sets([
            &[BinValue::Zero],
            &[BinValue::One],
            &[BinValue::Zero],
            &[BinValue::One],
        ]);
        assert_eq!(
            check(&recv_aux, &[BinValue::Zero, BinValue::One]),
            ViewState::Ready(set(&[BinValue::Zero, BinValue::One])),
            "the view is the union over a quorum, not a value that a quorum agreed on"
        );
    }

    #[test]
    fn single_bivalent_sender_forces_a_bivalent_view() {
        // §3.2: once a process has sent AUXSET({0, 1}), any n - t of these messages contains one of
        // them, so no singleton can clear the quorum. Only three senders exist, so the bivalent one
        // is in every quorum.
        let recv_aux = aux_sets([
            &[BinValue::Zero],
            &[BinValue::Zero],
            &[BinValue::Zero, BinValue::One],
        ]);
        assert_eq!(
            check(&recv_aux, &[BinValue::Zero, BinValue::One]),
            ViewState::Ready(set(&[BinValue::Zero, BinValue::One]))
        );
    }

    #[test]
    fn no_singleton_when_senders_straddle_both_values() {
        // Reaching {0} would need three senders whose sets are subsets of {0}; only two are.
        let recv_aux = aux_sets([&[BinValue::Zero], &[BinValue::Zero], &[BinValue::One]]);
        assert_eq!(
            check(&recv_aux, &[BinValue::Zero]),
            ViewState::Pending,
            "the third sender's value is outside the candidate, so it cannot join the quorum"
        );
    }

    #[test]
    fn prefers_the_smallest_valid_view() {
        // {0, 1} is also justified by these four senders, but {0} is justified by three of them and
        // is what line 06 needs to see.
        let recv_aux = aux_sets([
            &[BinValue::Zero],
            &[BinValue::Zero],
            &[BinValue::Zero],
            &[BinValue::Zero, BinValue::One],
        ]);
        assert_eq!(
            check(&recv_aux, &[BinValue::Zero, BinValue::One]),
            ViewState::Ready(set(&[BinValue::Zero]))
        );
    }

    #[test]
    fn waits_when_the_union_escapes_bin_values() {
        // Three senders would form a quorum, but their union is {0, 1} while bin_values is {0}.
        // Truncating to {0} here is what would break Agreement against a process whose bin_values
        // had already grown.
        let recv_aux = aux_sets([
            &[BinValue::Zero],
            &[BinValue::One],
            &[BinValue::Zero, BinValue::One],
        ]);
        assert_eq!(check(&recv_aux, &[BinValue::Zero]), ViewState::Pending);
    }

    #[test]
    fn resolves_once_bin_values_catches_up() {
        // The same messages as above, re-checked after BV-Broadcast added 1 to bin_values.
        let recv_aux = aux_sets([
            &[BinValue::Zero],
            &[BinValue::One],
            &[BinValue::Zero, BinValue::One],
        ]);
        assert_eq!(
            check(&recv_aux, &[BinValue::Zero, BinValue::One]),
            ViewState::Ready(set(&[BinValue::Zero, BinValue::One]))
        );
    }

    #[test]
    fn singleton_matches_only_one_element_sets() {
        assert_eq!(singleton(&set(&[BinValue::Zero])), Some(BinValue::Zero));
        assert_eq!(singleton(&set(&[])), None);
        assert_eq!(singleton(&set(&[BinValue::Zero, BinValue::Empty])), None);
    }

    #[test]
    fn pair_with_empty_matches_line_13() {
        assert_eq!(
            pair_with_empty(&set(&[BinValue::One, BinValue::Empty])),
            Some(BinValue::One)
        );
        assert_eq!(pair_with_empty(&set(&[BinValue::Empty])), None);
        assert_eq!(
            pair_with_empty(&set(&[BinValue::Zero, BinValue::One])),
            None,
            "a bivalent view is ruled out by Lemma 6 and must not be read as line 13's case"
        );
    }
}
