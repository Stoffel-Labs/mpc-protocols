//! GF(2^k) equivalent of `Multiply` (`honeybadger::mul::multiplication`), a direct structural
//! port. Secure multiplication (Beaver, Section 2.2 of the HoneyBadgerMPC paper): given a triple
//! `(a, b, a*b)` and shares `[x]`, `[y]`, compute `d = a-x`, `e = b-y`, open both, then
//! `[xy] = [a*b] - d*e - d*[y] - e*[x]`.
//!
//! Opening happens two ways: batch reconstruction (via [`GfBatchReconNode`]) over two rounds at
//! `4n * (48 + ceil(w/(t+1)))` bytes per party for a wave of `w`, and direct point-to-point
//! broadcast over one at `n * (52 + 2w)`, reconstructed robustly via `GfShare::recover_secret`
//! (tolerating up to `t` bad shares among the received ones, so no RBC agreement is needed here
//! either).
//!
//! Which one a given wave takes is [`OpeningPolicy`], not a fixed rule. Historically the split
//! was hard-wired — full `t+1`-chunks batched, the sub-`t+1` remainder direct — and that is still
//! [`OpeningPolicy::Batched`]. The default is [`OpeningPolicy::Auto`], which evaluates the two
//! costs above at this wave's own width and takes the direct path while it is no more expensive
//! than the batched one plus one round's allowance; when it does batch, it pads the last group
//! rather than sending a remainder directly. Both paths open at degree `t` and both are robust
//! and asynchronous; see [`OpeningPolicy`] for the model, for where each of its constants was
//! measured, and for why a degree-`2t` opening must never be routed this way.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use bincode::Options;
use itertools::izip;
use serde::de::DeserializeOwned;
use stoffelnet::network_utils::{Network, PartyId};
use tokio::sync::mpsc::Receiver;
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};
use tracing::{error, info, warn};

use crate::common::gf2k::field::BinaryField;
use crate::common::gf2k::share::GfShare;
use crate::common::gf2k::Gf2kError;
use crate::common::session_store::{Admission, SessionStore};
use crate::honeybadger::gf_batch_recon::gf_batch_recon::GfBatchReconNode;
use crate::honeybadger::gf_batch_recon::GfBatchReconError;
use crate::honeybadger::gf_mul::{
    GfMulError, GfMultMessage, GfMultReconstructionMessage, GfMultStorage, OpeningPlan,
    OpeningPolicy,
};
use crate::honeybadger::gf_triple_gen::GfBeaverTriple;
use crate::honeybadger::mul::MultProtocolState;
use crate::honeybadger::{ProtocolSessionId, SessionId, WrappedMessage};

/// Bounded by the payload's own byte length, matching `bincode::serialize`'s fixint encoding —
/// see `gf_share_gen::gf_share_gen::deser_bounded` for why `with_fixint_encoding` is required.
fn deser_bounded<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, GfMulError> {
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(bytes.len() as u64)
        .deserialize(bytes)?)
}

fn concat_sorted<K: BinaryField>(map: &HashMap<u8, Vec<K>>) -> Vec<K> {
    let mut keys: Vec<_> = map.keys().cloned().collect();
    keys.sort_unstable();

    let total_len: usize = keys.iter().map(|k| map[k].len()).sum();

    let mut out = Vec::with_capacity(total_len);
    for k in keys {
        out.extend_from_slice(&map[&k]);
    }
    out
}

// requires that GfMultiply::init has been called before and all chunks and remainder shares have
// been received
//
// `batched` is [`OpeningPlan::batched`] — the number of *real* values in the batched run. The
// batch-reconstruction child was handed `padded >= batched` of them, the tail being duplicates
// that fill the last `t+1` group, and it opens every one it was given. Those duplicates are
// dropped here, before the directly-opened values are appended, so the concatenation is the
// wave's own order: batched values first, direct remainder after.
fn finalize_mul<K: BinaryField>(
    storage: &GfMultStorage<K>,
    batched: usize,
) -> Result<Vec<GfShare<K>>, GfMulError> {
    assert!(storage.openings.is_some()); // always ensured by the caller

    let openings = storage.openings.as_ref().unwrap();

    let mut concatenated_mult1: Vec<K> = concat_sorted(&storage.output_open_mult1);
    concatenated_mult1.truncate(batched);
    concatenated_mult1.extend(openings.0.clone());

    let mut concatenated_mult2: Vec<K> = concat_sorted(&storage.output_open_mult2);
    concatenated_mult2.truncate(batched);
    concatenated_mult2.extend(openings.1.clone());

    let expected_len = storage.share_mult_from_triple.len();
    if concatenated_mult1.len() != expected_len
        || concatenated_mult2.len() != expected_len
        || storage.inputs.0.len() != expected_len
        || storage.inputs.1.len() != expected_len
    {
        return Err(GfMulError::InvalidInput(
            "Inconsistent lengths in finalize_mul".to_string(),
        ));
    }

    let mut shares_mult = Vec::with_capacity(expected_len);
    for (triple_mult, input_a, input_b, d, e) in izip!(
        &storage.share_mult_from_triple,
        &storage.inputs.0,
        &storage.inputs.1,
        concatenated_mult1,
        concatenated_mult2,
    ) {
        let de = d * e;
        // d * [y]
        let d_times_y = (input_b.clone() * d)?;
        // e * [x]
        let e_times_x = (input_a.clone() * e)?;
        // [xy] = [a*b] - d*e - d*[y] - e*[x]
        let share = (triple_mult.clone() - de)?;
        let share2 = (share - d_times_y)?;
        let share3 = (share2 - e_times_x)?;
        shares_mult.push(share3);
    }

    Ok(shares_mult)
}

fn reconstruct_remainder<K: BinaryField>(
    received_shares: &HashMap<usize, (Vec<GfShare<K>>, Vec<GfShare<K>>)>,
    share_len: usize,
    n: usize,
    t: usize,
) -> Result<(Vec<K>, Vec<K>), Gf2kError> {
    let mut a_sub_x: Vec<K> = Vec::new();
    let mut b_sub_y: Vec<K> = Vec::new();
    let mut a_shares = vec![vec![]; share_len];
    let mut b_shares = vec![vec![]; share_len];

    for (id, (a, b)) in received_shares.iter() {
        if a.len() != share_len || b.len() != share_len {
            warn!(
                "Node {} did not send right number of shares to reconstruct (sent {} for a-x and \
                 {} for b-y)",
                id,
                a.len(),
                b.len()
            );
            continue;
        }

        for i in 0..share_len {
            a_shares[i].push(a[i].clone());
            b_shares[i].push(b[i].clone());
        }
    }
    for i in 0..share_len {
        let required = t + 1;
        if a_shares[i].len() < required || b_shares[i].len() < required {
            return Err(Gf2kError::InvalidInput(
                "Insufficient valid shares for reconstruction".to_string(),
            ));
        }
        let a = GfShare::recover_secret(&a_shares[i], n, t)?;
        let b = GfShare::recover_secret(&b_shares[i], n, t)?;

        a_sub_x.push(a.1);
        b_sub_y.push(b.1);
    }

    Ok((a_sub_x, b_sub_y))
}

#[derive(Clone, Debug)]
pub struct GfMultiply<K: BinaryField> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    pub mult_storage:
        Arc<Mutex<SessionStore<SessionId, (usize, Instant, Arc<Mutex<GfMultStorage<K>>>)>>>,
    pub batch_recon: GfBatchReconNode<K>,
    pub batch_output: Arc<Mutex<Receiver<SessionId>>>,
    /// Whether a wave of `(a-x)`/`(b-y)` openings is packed into a two-round batch reconstruction
    /// or sent directly all-to-all in one round. See [`OpeningPolicy`]: it is a bytes-for-rounds
    /// trade at a fixed degree `t`, never a change of threat model, and it is a pure function of
    /// `(self.n, self.t, wave length)` so every honest party splits identically.
    policy: OpeningPolicy,
}

const MAX_GF_MUL_SESSIONS: usize = 1024;

impl<K: BinaryField> GfMultiply<K> {
    pub fn new(id: PartyId, n: usize, threshold: usize) -> Result<Self, GfMulError> {
        Self::new_with_policy(id, n, threshold, OpeningPolicy::default())
    }

    /// [`GfMultiply::new`] under an explicit [`OpeningPolicy`].
    ///
    /// The policy is a **public deployment parameter**: every party must select the same one, for
    /// the same reason every party must select the same prefix-adder topology. A split policy is
    /// *detected* rather than silent — the parties that batched are waiting on a batch-recon
    /// session the parties that went direct never opened — but it is a configuration error, and a
    /// stall rather than a wrong answer.
    pub fn new_with_policy(
        id: PartyId,
        n: usize,
        threshold: usize,
        policy: OpeningPolicy,
    ) -> Result<Self, GfMulError> {
        let (batch_sender, batch_receiver) = tokio::sync::mpsc::channel(200);
        let batch_recon = GfBatchReconNode::<K>::new(id, n, threshold, threshold, batch_sender)?;
        Ok(Self {
            id,
            n,
            t: threshold,
            mult_storage: Arc::new(Mutex::new(SessionStore::with_default_cap())),
            batch_recon,
            batch_output: Arc::new(Mutex::new(batch_receiver)),
            policy,
        })
    }

    /// The opening policy in force. Read it rather than re-deriving the split anywhere else: the
    /// one place the prefix length is computed is [`OpeningPolicy::batched_prefix`], and `init`
    /// and `process` must agree on it exactly.
    pub fn opening_policy(&self) -> OpeningPolicy {
        self.policy
    }

    /// How this node splits a wave of `len` openings. The one place the split is decided; every
    /// other site calls this so `init` and `process` cannot drift apart.
    fn plan(&self, len: usize) -> OpeningPlan {
        self.policy.plan(self.n, self.t, len)
    }

    pub async fn drain_batch_recon_output(&mut self) -> Result<(), GfMulError> {
        loop {
            let id = {
                let mut rx = self.batch_output.lock().await;
                match rx.try_recv() {
                    Ok(id) => id,
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        return Err(GfMulError::Abort);
                    }
                }
            };
            let output = match self.batch_recon.get_store(id).await {
                Ok(output) => output,
                Err(GfBatchReconError::InvalidInput(msg)) if msg.contains("does not exist") => {
                    warn!(
                        session_id = ?id,
                        "ignoring stale batch-recon output for cleared/finished multiplication session"
                    );
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            self.process(self.id, id, output).await?;
        }
        Ok(())
    }

    pub async fn clear_store(&self, session_id: SessionId) -> bool {
        let no_of_batch = {
            let store = self.mult_storage.lock().await;
            match store.get(&session_id) {
                Some(storage) => {
                    let storage = storage.2.lock().await;
                    // Via `plan`, not `no_of_mul / (t+1)`: under `OpeningPolicy::Direct` no
                    // batch-recon child was ever minted, and under a padding policy the child was
                    // minted for a *padded* count. Cleaning up a session that does not exist is
                    // how a store leak gets mistaken for a store that was tidied.
                    self.plan(storage.no_of_mul.unwrap_or(0)).groups(self.t)
                }
                None => return false,
            }
        };

        // Batched batch-recon: clear the single a-x session (sub_id 0) and b-y session (sub_id 1),
        // only when there were full (t+1)-chunks.
        if no_of_batch > 0 {
            let session_id1 = SessionId::new(
                session_id.calling_protocol().unwrap(),
                SessionId::pack_slot(session_id.exec_id(), 0, 1),
                session_id.instance_id(),
            );
            self.batch_recon.clear_store(session_id1).await;

            let session_id2 = SessionId::new(
                session_id.calling_protocol().unwrap(),
                SessionId::pack_slot(session_id.exec_id(), 1, 1),
                session_id.instance_id(),
            );
            self.batch_recon.clear_store(session_id2).await;
        }

        let mut store = self.mult_storage.lock().await;
        store.retire(session_id)
    }

    pub async fn store_len(&self) -> usize {
        self.mult_storage.lock().await.len()
    }

    /// Starts or completes a multiplication session. Deliberately re-entrant, same rationale as
    /// `Multiply::init`: network outputs for child batch-recon sessions or direct-open messages
    /// may arrive before the local caller invokes `init`, so this records inputs/triples first,
    /// then checks whether enough openings are already buffered to finish immediately.
    pub async fn init<N: Network + Send + Sync>(
        &mut self,
        session_id: SessionId,
        x: Vec<GfShare<K>>,
        y: Vec<GfShare<K>>,
        beaver_triples: Vec<GfBeaverTriple<K>>,
        network: Arc<N>,
    ) -> Result<(), GfMulError> {
        info!(party = self.id, "Initializing GfMultiply");
        if x.len() != y.len() || x.len() != beaver_triples.len() {
            return Err(GfMulError::InvalidInput(
                "Length of x and y vectors and Beaver triples must match".to_string(),
            ));
        }

        assert!(session_id.calling_protocol().is_some());
        assert_eq!(session_id.sub_id(), 0);
        assert_eq!(session_id.round_id(), 0);

        let no_of_mul = x.len();
        // The one place the batched/direct split is decided. `process` re-derives it from the
        // same `(policy, n, t, no_of_mul)` and must reach the same answer, so both call `plan`.
        let plan = self.plan(no_of_mul);
        let share_len = plan.direct;
        let no_of_batch = plan.groups(self.t);

        let storage_bind = match self.get_or_create_mult_storage(session_id, self.id).await {
            Some(s) => s,
            None => return Ok(()),
        };
        let mut storage = storage_bind.lock().await;

        // Batch reconstruction is batched: one session for all a-x values (dealer/sub_id 0) and
        // one for all b-y values (dealer/sub_id 1). When `no_of_batch == 0` - either because the
        // wave is shorter than `t+1`, or because the policy sent all of it direct - everything
        // goes through the direct-open path and these are vacuously satisfied.
        let have_batch_recon1 = no_of_batch == 0 || storage.output_open_mult1.contains_key(&0u8);
        let have_batch_recon2 = no_of_batch == 0 || storage.output_open_mult2.contains_key(&1u8);

        storage.no_of_mul = Some(no_of_mul);
        storage.inputs = (x.clone(), y.clone());
        storage.share_mult_from_triple = beaver_triples.iter().map(|t| t.mult.clone()).collect();
        if share_len == 0 {
            storage.openings = Some((vec![], vec![]));
        }

        if storage.received_shares.len() >= 2 * self.t + 1 && storage.openings.is_none() {
            // `share_len != 0`, since some honest nodes have sent us their shares
            info!("Received enough messages with shares to try reconstruction");

            match reconstruct_remainder(&storage.received_shares, share_len, self.n, self.t) {
                Ok(openings) => {
                    info!("Reconstruction succeeded");
                    storage.openings = Some(openings);
                }
                Err(e) => error!("Reconstruction in init failed: {e}"), // could fail if shares corrupt
            };
        }

        if have_batch_recon1 && have_batch_recon2 && storage.openings.is_some() {
            let shares_mult = finalize_mul(&storage, plan.batched)?;

            storage.protocol_state = MultProtocolState::Finished;
            if let Some(sender) = storage.output_sender.take() {
                sender
                    .send(shares_mult)
                    .map_err(|_| GfMulError::SendError(session_id))?;
            }
            info!("Multiplication completed at node {}", self.id);

            return Ok(());
        }

        let a_sub_x = x
            .iter()
            .zip(beaver_triples.iter())
            .map(|(x, triple)| triple.a.clone() - x.clone())
            .collect::<Result<Vec<GfShare<K>>, crate::common::share::ShareError>>()?;
        let b_sub_y = y
            .iter()
            .zip(beaver_triples.iter())
            .map(|(y, triple)| triple.b.clone() - y.clone())
            .collect::<Result<Vec<GfShare<K>>, crate::common::share::ShareError>>()?;

        // `plan.batched` by construction: `plan.direct` is the rest of the same split.
        let (a_batched, remaining_a) = a_sub_x.split_at(plan.batched);
        let (b_batched, remaining_b) = b_sub_y.split_at(plan.batched);

        // `init_batch_reconstruct_many` takes a non-empty multiple of `t+1`, so a plan whose
        // batched run ends mid-group fills it out with duplicates of that run's last share —
        // exactly as `A2BNode::open_f` and `mul_pub` pad theirs. A duplicate is information-free:
        // it opens to a value this same wave is already opening, and it is a genuine degree-`t`
        // sharing, so the group stays decodable by the same OEC bound as the rest. The padding is
        // a function of `(policy, n, t, len)` alone, so every honest party appends the same count
        // and `finalize_mul` drops the same tail.
        let mut a_full = a_batched.to_vec();
        let mut b_full = b_batched.to_vec();
        for _ in 0..plan.pad() {
            // `plan.pad() > 0` implies `plan.batched > 0`, so both runs are non-empty here.
            a_full.push(a_batched[plan.batched - 1].clone());
            b_full.push(b_batched[plan.batched - 1].clone());
        }
        debug_assert_eq!(a_full.len(), plan.padded);
        debug_assert_eq!(b_full.len(), plan.padded);

        let need_direct_open = storage.openings.is_none();

        drop(storage);

        // Initiate batch reconstruction for ALL a-x values in one batched session and ALL b-y
        // values in another (each (t+1)-chunk encoded within the single session via the
        // Vandermonde transform).
        if !have_batch_recon1 && !a_full.is_empty() {
            let session_id1 = SessionId::new(
                session_id.calling_protocol().unwrap(),
                SessionId::pack_slot(session_id.exec_id(), 0, 1),
                session_id.instance_id(),
            );
            self.batch_recon
                .init_batch_reconstruct_many(&a_full, session_id1, Arc::clone(&network))
                .await?;
        }

        if !have_batch_recon2 && !b_full.is_empty() {
            let session_id2 = SessionId::new(
                session_id.calling_protocol().unwrap(),
                SessionId::pack_slot(session_id.exec_id(), 1, 1),
                session_id.instance_id(),
            );
            self.batch_recon
                .init_batch_reconstruct_many(&b_full, session_id2, Arc::clone(&network))
                .await?;
        }

        // Broadcast the remaining (< t+1) values directly, point-to-point. Robust interpolation
        // in `process` tolerates up to `t` bad shares among the received ones, so this doesn't
        // need RBC's reliable-broadcast agreement.
        if need_direct_open {
            // `self.id` and `self.t` are this node's own; `new` asserts every remainder share
            // matches them and then drops both from the wire, so what goes out is bare field
            // elements. The receiver re-derives the pair rather than reading it.
            let reconst_message =
                GfMultReconstructionMessage::new(remaining_a, remaining_b, self.id, self.t)?;
            let bytes_rec_message = bincode::serialize(&reconst_message)?;

            let sessionid = SessionId::new(
                session_id.calling_protocol().unwrap(),
                SessionId::pack_slot(session_id.exec_id(), self.id as u8, 2),
                session_id.instance_id(),
            );

            let mult_msg = GfMultMessage::new(self.id, sessionid, bytes_rec_message);
            let wrapped = WrappedMessage::GfMult(mult_msg);
            let bytes_wrapped = bincode::serialize(&wrapped)?;

            network.broadcast(&bytes_wrapped).await?;
        }

        Ok(())
    }

    /// Receives opened values from batch reconstruction (round 1, local-only) or remainder shares
    /// for direct reconstruction (round 2, from the network). If `init` has been called, also
    /// tries to finish the multiplication.
    pub async fn process(
        &self,
        sender: usize,
        sid: SessionId,
        payload: Vec<u8>,
    ) -> Result<(), GfMulError> {
        let calling_proto = match sid.calling_protocol() {
            Some(proto) => proto,
            None => {
                return Err(GfMulError::InvalidInput(format!(
                    "Unknown calling protocol in session ID {sid:?}"
                )));
            }
        };

        let session_id = SessionId::new(
            calling_proto,
            SessionId::pack_slot(sid.exec_id(), 0, 0),
            sid.instance_id(),
        );

        let storage_bind = match self.get_or_create_mult_storage(session_id, sender).await {
            Some(s) => s,
            None => return Ok(()),
        };
        let mut storage = storage_bind.lock().await;

        if storage.protocol_state == MultProtocolState::Finished {
            return Ok(());
        }

        if sid.round_id() == 1 {
            // Round-1 payloads are this node's own batch-recon output, delivered only via the
            // local `drain_batch_recon_output` -> `process(self.id, ...)` call. They must never
            // be accepted from the network: unlike round-2 shares, they carry no quorum/degree
            // check, so a forged one would be taken as the final reconstructed value verbatim.
            if sender != self.id {
                return Err(GfMulError::InvalidInput(
                    "Round 1 (batch-recon output) messages must originate locally".to_string(),
                ));
            }
            let open: Vec<K> = deser_bounded(&payload)?;
            let dealer_id = sid.sub_id();
            let (target_map, label) = if dealer_id % 2 == 0 {
                (&mut storage.output_open_mult1, "a-x")
            } else {
                (&mut storage.output_open_mult2, "b-y")
            };

            // Late/duplicate batch-recon delivery: the opened values are final, so a duplicate
            // cannot change the reconstructed result. Ignore it instead of erroring.
            if target_map.contains_key(&dealer_id) {
                warn!(
                    self_id = self.id,
                    dealer_id, "ignoring duplicate batch-recon opening in process"
                );
                return Ok(());
            }

            info!(
                self_id = self.id,
                "Received opened {} values for session_id: {:?} and round {:?}",
                label,
                session_id,
                dealer_id
            );

            target_map.insert(dealer_id, open);
        } else if sid.round_id() == 2 {
            info!(
                self_id = self.id,
                "Received shares for direct reconstruction for session_id: {:?}", session_id
            );
            // Late/duplicate delivery from a dealer we already have shares from. Benign: each
            // dealer's shares are counted once, so a duplicate cannot change the result.
            if storage.received_shares.contains_key(&sender) {
                warn!(
                    self_id = self.id,
                    sender, "ignoring duplicate remainder shares from dealer in process"
                );
                return Ok(());
            }

            let open_message: GfMultReconstructionMessage<K> = deser_bounded(&payload)?;
            // Locally-derived expected size, not the sender's claim. Once `init` has run this
            // node knows exactly how many values the direct path carries, and a peer that claims
            // a different number is rejected outright rather than parked in its slot to be
            // skipped later by `reconstruct_remainder`. It matters more under
            // `OpeningPolicy::Direct`, where the direct path carries the whole wave instead of a
            // sub-`t+1` tail: a wrong-length message would otherwise occupy that sender's one
            // slot, and the duplicate guard above would then drop the correct message behind it.
            // Before `init` the expected length is not yet known, and `reconstruct_remainder`'s
            // own length check remains the backstop for anything buffered until then.
            if let Some(no_of_mul) = storage.no_of_mul {
                let expected = self.plan(no_of_mul).direct;
                if open_message.a_sub_x.len() != expected || open_message.b_sub_y.len() != expected
                {
                    return Err(GfMulError::InvalidInput(format!(
                        "Sender {sender} sent {}/{} direct-open shares, expected {expected} of each",
                        open_message.a_sub_x.len(),
                        open_message.b_sub_y.len()
                    )));
                }
            }
            // Evaluation index and degree are DERIVED, not read: `sender` is the transport
            // party id that `HoneyBadgerMPCNode::process_message` has already matched against
            // the envelope's `sender` field, and `self.t` is this session's opening degree.
            // Neither is on the wire, so neither can be claimed — this replaces the pair of
            // `share.id != sender` / `share.degree != self.t` rejections that the old encoding
            // needed, and is strictly stronger: the inconsistency is now unrepresentable rather
            // than caught.
            let (a_sub_x, b_sub_y) = open_message.into_shares(sender, self.t);
            storage.received_shares.insert(sender, (a_sub_x, b_sub_y));
        }

        let Some(no_of_mul) = storage.no_of_mul else {
            // init not called yet: buffer-only mode
            return Ok(());
        };
        let plan = self.plan(no_of_mul);
        let share_len = plan.direct;
        let no_of_batch = plan.groups(self.t);

        if storage.received_shares.len() >= 2 * self.t + 1 && storage.openings.is_none() {
            // `share_len != 0`, since some honest nodes have sent us their shares.
            //
            // **Re-attempt on every arrival, never abort.** This is the ONLINE path and it must
            // stay robust: with `e` corrupt shares among the first `2t+1` received, OEC needs
            // `m >= (t+1) + 2e` points and so fails outright for `e > t/2` — it only succeeds once
            // the later honest shares land, at `m = 3t+1 = (t+1) + 2t`, which is exactly
            // reachable. A failed partial decode is therefore the *expected* intermediate state
            // under attack, not an error, so it is logged and retried on the next arrival rather
            // than propagated. `init` has always done this; propagating here would have turned a
            // recoverable wave into a surfaced protocol error, and does so far more often now
            // that `OpeningPolicy::Direct` can route a whole wave through this path.
            info!("Received enough messages with shares to try reconstruction");
            match reconstruct_remainder(&storage.received_shares, share_len, self.n, self.t) {
                Ok(openings) => {
                    info!("Reconstruction succeeded");
                    storage.openings = Some(openings);
                }
                Err(e) => warn!(
                    self_id = self.id,
                    received = storage.received_shares.len(),
                    "direct-open reconstruction not yet decodable, retrying on next arrival: {e}"
                ),
            }
        }

        // With batched batch-recon, completion needs the single a-x result (dealer 0) and the
        // single b-y result (dealer 1). When there are no full chunks, all values come through
        // the remainder path, so only `openings` is required.
        let batch_done = no_of_batch == 0
            || (storage.output_open_mult1.contains_key(&0u8)
                && storage.output_open_mult2.contains_key(&1u8));
        if !batch_done || storage.openings.is_none() {
            return Ok(());
        }

        let shares_mult = finalize_mul(&storage, plan.batched)?;

        storage.protocol_state = MultProtocolState::Finished;
        if let Some(sender) = storage.output_sender.take() {
            let _ = sender.send(shares_mult);
        }
        info!("Multiplication completed at node {}", self.id);

        Ok(())
    }

    pub async fn get_or_create_mult_storage(
        &self,
        session_id: SessionId,
        initiator_id: usize,
    ) -> Option<Arc<Mutex<GfMultStorage<K>>>> {
        match self.mult_storage.lock().await.get_or_admit(
            session_id,
            initiator_id,
            MAX_GF_MUL_SESSIONS,
            MAX_GF_MUL_SESSIONS / self.n,
            || Arc::new(Mutex::new(GfMultStorage::empty())),
        ) {
            Admission::Got(arc) => Some(arc),
            Admission::Retired => None,
            Admission::Rejected => {
                warn!("GfMul session limit reached");
                None
            }
        }
    }

    pub async fn wait_for_result(
        &self,
        session_id: SessionId,
        duration: Duration,
    ) -> Result<Vec<GfShare<K>>, GfMulError> {
        let output_receiver = {
            let mult_storage = self.mult_storage.lock().await;
            let storage_bind = match mult_storage.get(&session_id) {
                Some((_, _, arc)) => arc,
                None => return Err(GfMulError::NoSuchSessionId(session_id)),
            };
            let mut storage = storage_bind.lock().await;

            storage
                .output_receiver
                .take()
                .ok_or(GfMulError::ResultAlreadyReceived(session_id))?
        };

        match timeout(duration, output_receiver).await {
            Err(_) => Err(GfMulError::Timeout(session_id)),
            Ok(Err(_)) => Err(GfMulError::ReceiveError(session_id)),
            Ok(Ok(mul_shares)) => Ok(mul_shares),
        }
    }
}
