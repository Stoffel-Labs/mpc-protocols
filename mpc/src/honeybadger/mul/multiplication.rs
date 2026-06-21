use crate::{
    common::{
        rbc::RbcError, share::ShareError, utils::deser_bounded_vec, ProtocolSessionId,
        SecretSharingScheme, ShamirShare, RBC,
    },
    honeybadger::{
        batch_recon::{batch_recon::BatchReconNode, BatchReconError},
        mul::{
            concat_sorted, InterpolateError, MulError, MultMessage, MultProtocolState, MultStorage,
            ReconstructionMessage,
        },
        robust_interpolate::robust_interpolate::{Robust, RobustShare},
        triple_gen::ShamirBeaverTriple,
        SessionId, WrappedMessage, MAX_MESSAGE_SIZE,
    },
};
use ark_ff::FftField;
use ark_serialize::CanonicalSerialize;
use bincode::Options;
use itertools::izip;
use std::{
    collections::HashMap,
    ops::{Mul, Sub},
    sync::Arc,
};
use stoffelnet::network_utils::{Network, PartyId};
use tokio::sync::{
    mpsc::{self, Receiver},
    Mutex,
};
use tokio::time::{timeout, Duration};
use tracing::{error, info, warn};

/// Secret multiplication is explained in Section 2.2 of the paper.
/// Assume that we want to multiply two t-shares x and y. We take a Beaver triple
/// (a, b, a*b) and
///
/// 1. calculate a - x and b - y and open these values
/// 2. calculate x*y = a*b - (a - x)(b - y) - (a - x)y - (b - y)x; a - x and b - y have been
///    opened, a*b is part of the Beaver triple and x and y are known shares
///
/// Opening in step (1) happens using batch reconstruction and also RBC.
/// The former is used for chunks of t + 1 shares and the remainder of these, if any, is
/// reconstructed using the latter.
/// For example, if `n = 10` and `t = 3`, then 10 multiplications would be performed by running
/// batch reconstruction four times: on two chunks each of size 4 for `a - x` and `b - y`,
/// respectively. In addition, each node would run RBC once for the remaining values, which are two
/// values of `a - x` and `b - y`, respectively. While batch reconstruction takes care of the
/// distribution of the shares and their reconstruction at the same time, the nodes need to
/// manually reconstruct the shares received via RBC.
///
/// The storage per multiplication is accessed by `Multiply::init` and `open_mult_handler` and is protected by
/// a mutex.

// requires that Multiply::init has been called before and all chunks and shares via RBC have been
// received
fn finalize_mul<F: FftField>(storage: &MultStorage<F>) -> Result<Vec<RobustShare<F>>, MulError> {
    assert!(storage.openings.is_some()); // always ensured by the caller

    let openings = storage.openings.as_ref().unwrap();

    let mut concatenated_mult1: Vec<F> = concat_sorted(&storage.output_open_mult1);
    concatenated_mult1.extend(openings.0.clone());

    let mut concatenated_mult2: Vec<F> = concat_sorted(&storage.output_open_mult2);
    concatenated_mult2.extend(openings.1.clone());

    let expected_len = storage.share_mult_from_triple.len();
    if concatenated_mult1.len() != expected_len
        || concatenated_mult2.len() != expected_len
        || storage.inputs.0.len() != expected_len
        || storage.inputs.1.len() != expected_len
    {
        return Err(MulError::InvalidInput(
            "Inconsistent lengths in finalize_mul".to_string(),
        ));
    }
    let mut shares_mult = Vec::with_capacity(storage.share_mult_from_triple.len());
    for (triple_mult, input_a, input_b, subtraction_a, subtraction_b) in izip!(
        &storage.share_mult_from_triple,
        &storage.inputs.0,
        &storage.inputs.1,
        concatenated_mult1,
        concatenated_mult2,
    ) {
        //(a−x)(b−y)
        let mult_subs = subtraction_a * subtraction_b;
        //(a−x)[y]_t
        let mult_sub_a_y = input_b.clone().mul(subtraction_a)?;
        //(b−y)[x]_t
        let mult_sub_b_x = input_a.clone().mul(subtraction_b)?;
        //[xy]_t
        let share = triple_mult.clone().sub(mult_subs)?;
        let share2: ShamirShare<F, 1, Robust> = (share - mult_sub_a_y)?;
        let share3 = (share2 - mult_sub_b_x)?;
        shares_mult.push(share3);
    }

    Ok(shares_mult)
}

fn reconstruct_rbc<F: FftField>(
    received_shares: &HashMap<PartyId, (Vec<RobustShare<F>>, Vec<RobustShare<F>>)>,
    share_len: usize,
    n: usize,
    t: usize,
) -> Result<(Vec<F>, Vec<F>), InterpolateError> {
    let mut a_sub_x: Vec<F> = Vec::new();
    let mut b_sub_y: Vec<F> = Vec::new();
    let mut a_shares = vec![vec![]; share_len];
    let mut b_shares = vec![vec![]; share_len];

    for (id, (a, b)) in received_shares.iter() {
        if a.len() != share_len || b.len() != share_len {
            warn!("Node {} did not send right number of shares to reconstruct using RBC (sent {} for a-x and {} for b-y)", id, a.len(), b.len());
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
            return Err(InterpolateError::InvalidInput(
                "Insufficient valid shares for reconstruction".to_string(),
            ));
        }
        let a = RobustShare::recover_secret(&a_shares[i], n, t)?;
        let b = RobustShare::recover_secret(&b_shares[i], n, t)?;

        a_sub_x.push(a.1);
        b_sub_y.push(b.1);
    }

    Ok((a_sub_x, b_sub_y))
}

#[derive(Clone, Debug)]
pub struct Multiply<F: FftField, R: RBC> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    pub mult_storage: Arc<Mutex<HashMap<SessionId, Arc<Mutex<MultStorage<F>>>>>>,
    pub batch_recon: BatchReconNode<F>,
    pub batch_output: Arc<Mutex<Receiver<SessionId>>>,
    pub rbc: R,
    pub rbc_output: Arc<Mutex<Receiver<SessionId>>>,
}

impl<F: FftField, R: RBC<Id = SessionId>> Multiply<F, R> {
    pub fn new(id: PartyId, n: usize, threshold: usize) -> Result<Self, MulError> {
        let (rbc_sender, rbc_receiver) = mpsc::channel(200);
        let (batch_sender, batch_receiver) = tokio::sync::mpsc::channel(200);
        let batch_recon = BatchReconNode::<F>::new(id, n, threshold, threshold, batch_sender)?;
        let rbc = R::new(
            id,
            n,
            threshold,
            threshold + 1,
            rbc_sender,
            Arc::new(WrappedMessage::rbc_wrap),
        )?;
        Ok(Self {
            id,
            n,
            t: threshold,
            mult_storage: Arc::new(Mutex::new(HashMap::new())),
            batch_recon,
            batch_output: Arc::new(Mutex::new(batch_receiver)),
            rbc,
            rbc_output: Arc::new(Mutex::new(rbc_receiver)),
        })
    }

    pub async fn drain_rbc_output(&mut self) -> Result<(), MulError> {
        loop {
            let id = {
                let mut rx = self.rbc_output.lock().await;
                match rx.try_recv() {
                    Ok(id) => id,
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        return Err(MulError::Abort);
                    }
                }
            };

            let output = match self.rbc.get_store(id).await {
                Ok(output) => output,
                Err(RbcError::Internal(msg)) if msg.contains("does not exist") => {
                    warn!(
                        session_id = ?id,
                        "ignoring stale RBC output for cleared/finished multiplication session"
                    );
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            let msg: MultMessage = bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .allow_trailing_bytes()
                .with_limit(MAX_MESSAGE_SIZE)
                .deserialize(&output)?;
            let authenticated_sender = id.sub_id() as usize;
            if msg.sender != authenticated_sender {
                warn!(
                    "Dropping 
                RBC output: inner sender {} does not match session's designated sender {}",
                    msg.sender,
                    id.sub_id()
                );
                continue;
            }
            if msg.session_id.exec_id() != id.exec_id()
                || msg.session_id.instance_id() != id.instance_id()
            {
                warn!("Dropping RBC output: inner session_id does not match RBC session metadata");
                continue;
            }
            if msg.session_id.round_id() != id.round_id() || msg.session_id.sub_id() != id.sub_id()
            {
                warn!("Dropping RBC output: inner session metadata does not match RBC session metadata");
                continue;
            }

            if id.round_id() != 2 {
                warn!("Dropping RBC output: unexpected round_id for Mul RBC message");
                continue;
            }
            match self
                .open_mult_handler(authenticated_sender, msg.session_id, msg.payload)
                .await
            {
                Ok(()) => {}
                Err(e) => {
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    pub async fn drain_batch_recon_output(&mut self) -> Result<(), MulError> {
        loop {
            let id = {
                let mut rx = self.batch_output.lock().await;
                match rx.try_recv() {
                    Ok(id) => id,
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        return Err(MulError::Abort);
                    }
                }
            };
            let output = match self.batch_recon.get_store(id).await {
                Ok(output) => output,
                Err(BatchReconError::InvalidInput(msg)) if msg.contains("does not exist") => {
                    warn!(
                        session_id = ?id,
                        "ignoring stale batch-recon output for cleared/finished multiplication session"
                    );
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            match self.open_mult_handler(self.id, id, output).await {
                Ok(()) => {}
                Err(e) => {
                    return Err(e);
                }
            }
        }
        Ok(())
    }
    pub async fn clear_store(&self, session_id: SessionId) -> Result<(), MulError> {
        let no_of_batch = {
            let store = self.mult_storage.lock().await;
            match store.get(&session_id) {
                Some(storage) => {
                    let storage = storage.lock().await;
                    storage.no_of_mul.unwrap_or(0) / (self.t + 1)
                }
                None => return Err(MulError::ClearStoreError(session_id)),
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

        for party_id in 0..self.n {
            let rbc_session_id = SessionId::new(
                session_id.calling_protocol().unwrap(),
                SessionId::pack_slot(session_id.exec_id(), party_id as u8, 2),
                session_id.instance_id(),
            );
            self.rbc.clear_session(rbc_session_id).await;
        }

        let mut store = self.mult_storage.lock().await;
        store
            .remove(&session_id)
            .map(|_| ())
            .ok_or(MulError::ClearStoreError(session_id))
    }

    pub async fn store_len(&self) -> usize {
        self.mult_storage.lock().await.len()
    }

    /// Starts or completes a multiplication session.
    ///
    /// This method is deliberately re-entrant. Network outputs for child BatchRecon or RBC sessions
    /// may arrive before the local caller invokes `init`, so the method first records the caller's
    /// inputs and triples, then checks whether enough openings are already buffered to finish the
    /// multiplication immediately. If not, it computes this party's `(a - x)` and `(b - y)` shares
    /// only for the missing chunks and starts the child protocols for those chunks.
    ///
    /// Child protocol initiation happens after the multiplication storage lock is released. That
    /// avoids holding the lock while performing network work; the tradeoff is that another task may
    /// finish a child opening in the gap, causing a harmless duplicate child initiation that is
    /// filtered by the normal duplicate checks.
    pub async fn init<N: Network + Send + Sync>(
        &mut self,
        session_id: SessionId,
        x: Vec<RobustShare<F>>,
        y: Vec<RobustShare<F>>,
        beaver_triples: Vec<ShamirBeaverTriple<F>>,
        network: Arc<N>,
    ) -> Result<(), MulError> {
        info!(party = self.id, "Initializing multiplication");
        if x.len() != y.len() || x.len() != beaver_triples.len() {
            return Err(MulError::InvalidInput(
                "Length of x and y vectors and Beaver triples must match".to_string(),
            ));
        }

        assert!(session_id.calling_protocol().is_some());
        assert_eq!(session_id.sub_id(), 0);
        assert_eq!(session_id.round_id(), 0);

        let no_of_mul = x.len();
        let no_of_batch = no_of_mul / (self.t + 1);
        let share_len = x.len() % (self.t + 1);

        // 1.
        let storage_bind = self.get_or_create_mult_storage(session_id).await?;
        let mut storage = storage_bind.lock().await;

        // 2. Batch reconstruction is batched: one session for all a-x values (dealer/sub_id 0)
        //    and one for all b-y values (dealer/sub_id 1). When there are no full (t+1)-chunks
        //    (no_of_batch == 0, i.e. N < t+1), everything goes through RBC and these are vacuously
        //    satisfied.
        let have_batch_recon1 =
            no_of_batch == 0 || storage.output_open_mult1.contains_key(&0u8);
        let have_batch_recon2 =
            no_of_batch == 0 || storage.output_open_mult2.contains_key(&1u8);

        // 3.
        storage.no_of_mul = Some(no_of_mul);
        storage.inputs = (x.clone(), y.clone());
        storage.share_mult_from_triple = beaver_triples
            .iter()
            .map(|triple| triple.mult.clone())
            .collect();
        if share_len == 0 {
            storage.openings = Some((vec![], vec![]));
        }

        // 4.
        if storage.received_shares.len() >= 2 * self.t + 1 && storage.openings.is_none() {
            // `share_len != 0`, since some honest nodes have sent us their shares
            info!("Received enough messages with shares to try reconstruction using RBC");

            match reconstruct_rbc(&storage.received_shares, share_len, self.n, self.t) {
                Ok(openings) => {
                    info!("Reconstruction succeeded");
                    storage.openings = Some(openings);
                }
                Err(e) => error!("Reconstruction in init failed: {e}"), // could fail if shares corrupt
            };
        }

        // 5.
        if have_batch_recon1 && have_batch_recon2 && storage.openings.is_some() {
            let shares_mult = finalize_mul(&storage)?;

            storage.protocol_state = MultProtocolState::Finished;
            if let Some(sender) = storage.output_sender.take() {
                sender
                    .send(shares_mult)
                    .map_err(|_| MulError::SendError(session_id))?;
            }
            info!("Multiplication completed at node {}", self.id);

            return Ok(());
        }

        // 6.
        let a_sub_x = x
            .iter()
            .zip(beaver_triples.iter())
            .map(|(x, triple)| triple.a.clone() - x.clone())
            .collect::<Result<Vec<RobustShare<F>>, ShareError>>()?;
        let b_sub_y = y
            .iter()
            .zip(beaver_triples.iter())
            .map(|(y, triple)| triple.b.clone() - y.clone())
            .collect::<Result<Vec<RobustShare<F>>, ShareError>>()?;

        let split_at = a_sub_x.len() - share_len;
        let (a_full, remaining_a) = a_sub_x.split_at(split_at);
        let (b_full, remaining_b) = b_sub_y.split_at(split_at);

        let need_rbc = storage.openings.is_none();

        // 7.
        drop(storage);

        // 8. Initiate batch reconstruction for ALL a-x values in one batched session and ALL b-y
        //    values in another (each (t+1)-chunk encoded within the single session via the
        //    Vandermonde transform). This collapses 2*no_of_batch sessions -> 2 sessions, cutting
        //    message volume from O(N*n^2) to O(n^2). Correctness is unchanged: each secret is still
        //    reconstructed by the same robust `recover_secret` path with t-fault tolerance.
        if !have_batch_recon1 && !a_full.is_empty() {
            let session_id1 = SessionId::new(
                session_id.calling_protocol().unwrap(),
                SessionId::pack_slot(session_id.exec_id(), 0, 1),
                session_id.instance_id(),
            );
            self.batch_recon
                .init_batch_reconstruct_many(a_full, session_id1, Arc::clone(&network))
                .await?;
        }

        if !have_batch_recon2 && !b_full.is_empty() {
            let session_id2 = SessionId::new(
                session_id.calling_protocol().unwrap(),
                SessionId::pack_slot(session_id.exec_id(), 1, 1),
                session_id.instance_id(),
            );
            self.batch_recon
                .init_batch_reconstruct_many(b_full, session_id2, Arc::clone(&network))
                .await?;
        }

        // 9.
        if need_rbc {
            // Reconstruct < t+1 values
            let reconst_message =
                ReconstructionMessage::new(remaining_a.to_vec(), remaining_b.to_vec());
            let mut bytes_rec_message = Vec::new();
            reconst_message.serialize_compressed(&mut bytes_rec_message)?;

            let sessionid = SessionId::new(
                session_id.calling_protocol().unwrap(),
                SessionId::pack_slot(session_id.exec_id(), self.id as u8, 2),
                session_id.instance_id(),
            );

            let wrapped = MultMessage::new(self.id, sessionid, bytes_rec_message);
            let bytes_wrapped = bincode::serialize(&wrapped)?;

            self.rbc
                .init(bytes_wrapped, sessionid, Arc::clone(&network))
                .await?;
        }

        Ok(())
    }

    // 1. Take storage lock
    // 2. Store the a-x, b-y values opened through batch reconstruction in the appropriate slot
    // 3. Get the number of multiplications or return if `init` has not been called yet
    // 4. Reconstruct from RBC-sent shares if enough have been received and needed
    // 5. Return if not all openings are available
    // 5. Perform the multiplication and return if all openings are available
    // 6. Otherwise, compute all local (a - x)- and (b - y)-shares
    //
    // `open_mult_handler` mainly serves to receive opened values from batch reconstruction
    // or shares from RBC, from which openings will be manually reconstructed.
    // If `init` has been called, then it can also try to perform the multiplication.
    pub async fn open_mult_handler(
        &self,
        sender: usize,
        sid: SessionId,
        payload: Vec<u8>,
    ) -> Result<(), MulError> {
        let calling_proto = match sid.calling_protocol() {
            Some(proto) => proto,
            None => {
                return Err(MulError::InvalidInput(format!(
                    "Unknown calling protocol in session ID {:?}",
                    sid
                )));
            }
        };

        let session_id = SessionId::new(
            calling_proto,
            SessionId::pack_slot(sid.exec_id(), 0, 0),
            sid.instance_id(),
        );

        // 1.
        let storage_bind = self.get_or_create_mult_storage(session_id).await?;
        let mut storage = storage_bind.lock().await;

        if storage.protocol_state == MultProtocolState::Finished {
            return Ok(());
        }

        // 2.
        if sid.round_id() == 1 {
            // Batched batch-recon: one session returns ALL a-x (dealer 0) or ALL b-y (dealer 1)
            // values for the mul session. Bound the deserialization by the session capacity (not
            // self.n) — the opened vector can hold up to `max_mul_pairs_per_session` values.
            let open: Vec<F> = deser_bounded_vec(
                &mut payload.as_slice(),
                crate::honeybadger::max_mul_pairs_per_session(self.t),
            )?;
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
                    dealer_id, "ignoring duplicate batch-recon opening in open_mult_handler"
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
                "Received shares for reconstruction using RBC for session_id: {:?}", session_id
            );
            // Late/duplicate RBC delivery from a dealer we already have shares from. Benign:
            // RBC agreement delivers one value per dealer and reconstruction counts each dealer
            // once, so a duplicate cannot change the result. Ignore it instead of erroring.
            if storage.received_shares.contains_key(&sender) {
                warn!(
                    self_id = self.id,
                    sender, "ignoring duplicate RBC shares from dealer in open_mult_handler"
                );
                return Ok(());
            }

            let mut r = payload.as_slice();
            let a_sub_x = deser_bounded_vec::<RobustShare<F>>(&mut r, self.n)?;
            let b_sub_y = deser_bounded_vec::<RobustShare<F>>(&mut r, self.n)?;
            let open_message = ReconstructionMessage { a_sub_x, b_sub_y };
            for share in open_message
                .a_sub_x
                .iter()
                .chain(open_message.b_sub_y.iter())
            {
                if share.id != sender {
                    return Err(MulError::InvalidInput(format!(
                        "Invalid share id from sender {}",
                        sender
                    )));
                }
                if share.degree != self.t {
                    return Err(MulError::InvalidInput(format!(
                        "Invalid share degree from sender {}",
                        sender
                    )));
                }
            }
            storage
                .received_shares
                .insert(sender, (open_message.a_sub_x, open_message.b_sub_y));
        }

        // 3.
        let Some(no_of_mul) = storage.no_of_mul else {
            // init not called yet: buffer-only mode
            return Ok(());
        };
        let no_of_batch = no_of_mul / (self.t + 1);
        let share_len = no_of_mul % (self.t + 1);

        // 4.
        if storage.received_shares.len() >= 2 * self.t + 1 && storage.openings.is_none() {
            // `share_len != 0`, since some honest nodes have sent us their shares
            info!("Received enough messages with shares to try reconstruction using RBC");
            let openings = reconstruct_rbc(&storage.received_shares, share_len, self.n, self.t)?;

            info!("Reconstruction succeeded");
            storage.openings = Some(openings);
        }

        // 5. With batched batch-recon, completion needs the single a-x result (dealer 0) and the
        //    single b-y result (dealer 1). When there are no full chunks (no_of_batch == 0), all
        //    values come through RBC, so only `openings` is required.
        let batch_done = no_of_batch == 0
            || (storage.output_open_mult1.contains_key(&0u8)
                && storage.output_open_mult2.contains_key(&1u8));
        if !batch_done || storage.openings.is_none() {
            return Ok(());
        }

        // 6.
        let shares_mult = finalize_mul(&storage)?;

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
    ) -> Result<Arc<Mutex<MultStorage<F>>>, MulError> {
        let mut storage = self.mult_storage.lock().await;

        Ok(storage
            .entry(session_id)
            .or_insert(Arc::new(Mutex::new(MultStorage::empty())))
            .clone())
    }

    pub async fn wait_for_result(
        &self,
        session_id: SessionId,
        duration: Duration,
    ) -> Result<Vec<RobustShare<F>>, MulError> {
        // scoped because self.mult_storage and storage locks must not be held anymore
        // when receiving afterwards
        let output_receiver = {
            let mult_storage = self.mult_storage.lock().await;
            let storage_bind = match mult_storage.get(&session_id) {
                Some(value) => value,
                None => return Err(MulError::NoSuchSessionId(session_id)),
            };
            let mut storage = storage_bind.lock().await;

            storage
                .output_receiver
                .take()
                .ok_or(MulError::ResultAlreadyReceived(session_id))?
        };

        match timeout(duration, output_receiver).await {
            Err(_) => Err(MulError::Timeout(session_id)),
            Ok(Err(_)) => Err(MulError::ReceiveError(session_id)),
            Ok(Ok(mul_shares)) => Ok(mul_shares),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{
        common::{rbc::rbc::Avid, SecretSharingScheme},
        honeybadger::{
            robust_interpolate::robust_interpolate::RobustShare, ProtocolType, WrappedMessage,
        },
    };
    use ark_bls12_381::Fr;
    use ark_ff::UniformRand;
    use ark_std::test_rng;
    use rand::{prelude::SliceRandom, thread_rng};
    use stoffelmpc_network::fake_network::{FakeInnerNetwork, FakeNetwork, FakeNetworkConfig};
    use tokio::{
        sync::mpsc::{self, Receiver},
        time::{sleep, Duration, Instant},
    };

    async fn construct_input_mul(
        n_parties: usize,
        n_triples: usize,
        threshold: usize,
    ) -> (
        (Vec<Fr>, Vec<Fr>, Vec<Fr>),
        Vec<Vec<ShamirBeaverTriple<Fr>>>,
    ) {
        let mut rng = test_rng();
        let mut secrets_a = Vec::new();
        let mut secrets_b = Vec::new();
        let mut secrets_c = Vec::new();
        let mut per_party_triples: Vec<Vec<ShamirBeaverTriple<Fr>>> = vec![Vec::new(); n_parties];

        for _i in 0..n_triples {
            // sample secrets a,b
            let a_secret = Fr::rand(&mut rng);
            let b_secret = Fr::rand(&mut rng);
            let c_secret = a_secret * b_secret;

            // make robust shares for each secret (length == n_parties)
            let shares_a =
                RobustShare::compute_shares(a_secret, n_parties, threshold, None, &mut rng)
                    .expect("share a creation failed");
            let shares_b =
                RobustShare::compute_shares(b_secret, n_parties, threshold, None, &mut rng)
                    .expect("share b creation failed");
            let shares_c =
                RobustShare::compute_shares(c_secret, n_parties, threshold, None, &mut rng)
                    .expect("share c creation failed");

            // push the secrets to the vectors
            secrets_a.push(a_secret);
            secrets_b.push(b_secret);
            secrets_c.push(c_secret);

            // For each party, create their per-party ShamirBeaverTriple and push it
            for pid in 0..n_parties {
                let triple = ShamirBeaverTriple {
                    a: shares_a[pid].clone(),
                    b: shares_b[pid].clone(),
                    mult: shares_c[pid].clone(),
                };
                per_party_triples[pid].push(triple);
            }
        }
        ((secrets_a, secrets_b, secrets_c), per_party_triples)
    }
    fn fan_in_inboxes(inboxes: Vec<Receiver<Vec<u8>>>) -> Receiver<(usize, Vec<u8>)> {
        let (tx, rx) = mpsc::channel(300);

        for (from, mut rx_i) in inboxes.into_iter().enumerate() {
            let tx_i = tx.clone();
            tokio::spawn(async move {
                while let Some(msg) = rx_i.recv().await {
                    // ignore send errors (receiver dropped)
                    let _ = tx_i.send((from, msg)).await;
                }
            });
        }

        rx
    }
    /// `2t+1` nodes send random shares to the client, which reconstructs the random value and
    /// broadcasts the masked input. Some node, which is not one of the `2t+1` has not sent its
    /// random share and receives the masked input before even having called `InputServer::init`.
    #[tokio::test]
    async fn test_init_last() {
        let n = 10;
        let t = 3;
        let node_id = 0;
        let no_of_mul = 10;
        let session_id = SessionId::new(ProtocolType::Mul, SessionId::pack_slot(123, 0, 0), 111);
        let mut rng = test_rng();

        // 1. Generate Beaver triples
        let ((secrets_a, secrets_b, _), beaver_triples) =
            construct_input_mul(n, no_of_mul, t).await;
        let mult_from_triple: Vec<_> = beaver_triples[node_id]
            .iter()
            .map(|triple| triple.mult.clone())
            .collect();

        // 2. Prepare inputs for multiplication
        let mut x_values = Vec::new();
        let mut y_values = Vec::new();
        let mut x_inputs_per_node = vec![Vec::new(); n];
        let mut y_inputs_per_node = vec![Vec::new(); n];

        for _i in 0..no_of_mul {
            let x_value = Fr::rand(&mut rng);
            x_values.push(x_value);
            let y_value = Fr::rand(&mut rng);
            y_values.push(y_value);

            let shares_x = RobustShare::compute_shares(x_value, n, t, None, &mut rng).unwrap();
            let shares_y = RobustShare::compute_shares(y_value, n, t, None, &mut rng).unwrap();

            for p in 0..n {
                x_inputs_per_node[p].push(shares_x[p].clone());
                y_inputs_per_node[p].push(shares_y[p].clone());
            }
        }

        // 3. Generate correct openings and shares
        let correct_a_sub_x = secrets_a
            .clone()
            .iter()
            .zip(x_values.clone())
            .map(|(a, x)| *a - x)
            .collect::<Vec<_>>();
        let correct_b_sub_y = secrets_b
            .clone()
            .iter()
            .zip(y_values.clone())
            .map(|(b, y)| *b - y)
            .collect::<Vec<_>>();

        let mut correct_shares = Vec::with_capacity(mult_from_triple.len());
        for (triple_mult, input_a, input_b, subtraction_a, subtraction_b) in izip!(
            &mult_from_triple,
            &x_inputs_per_node[node_id],
            &y_inputs_per_node[node_id],
            &correct_a_sub_x,
            &correct_b_sub_y
        ) {
            //(a−x)(b−y)
            let mult_subs = subtraction_a * subtraction_b;
            //(a−x)[y]_t
            let mult_sub_a_y = input_b
                .clone()
                .mul(*subtraction_a)
                .expect("multiplication failed");
            //(b−y)[x]_t
            let mult_sub_b_x = input_a
                .clone()
                .mul(*subtraction_b)
                .expect("multiplication failed");
            //[xy]_t
            let share = triple_mult
                .clone()
                .sub(mult_subs)
                .expect("subtraction failed");
            let share2: ShamirShare<Fr, 1, Robust> =
                (share - mult_sub_a_y).expect("subtraction failed");
            let share3 = (share2 - mult_sub_b_x).expect("subtraction failed");
            correct_shares.push(share3);
        }

        let config = FakeNetworkConfig::new(500);
        let (inner, mut receivers, _) = FakeInnerNetwork::new(n, None, config);
        let network: Vec<_> = (0..n)
            .map(|id| Arc::new(FakeNetwork::new(id, inner.clone())))
            .collect();

        let mut nodes: Vec<_> = (0..n)
            .map(|i| Multiply::<Fr, Avid<SessionId>>::new(i, n, t).unwrap())
            .collect();

        // all but one node call init
        for i in 0..nodes.len() {
            if i == node_id {
                continue;
            }

            let mut node = nodes[i].clone();
            let network = network.clone();
            let x_inputs_per_node = x_inputs_per_node[i].clone();
            let y_inputs_per_node = y_inputs_per_node[i].clone();
            let beaver_triples = beaver_triples[i].clone();

            tokio::spawn(async move {
                assert!(node
                    .init(
                        session_id,
                        x_inputs_per_node,
                        y_inputs_per_node,
                        beaver_triples,
                        network[i].clone()
                    )
                    .await
                    .is_ok());
            });
        }

        // run RBC for masked input and eventually process it
        for (i, node) in nodes.iter_mut().enumerate() {
            let network = network.clone();
            let mut node = node.clone();
            let receiver = receivers.remove(0);
            let mut merged_rx = fan_in_inboxes(receiver);
            tokio::spawn(async move {
                while let Some(raw_msg) = merged_rx.recv().await {
                    let wrapped: WrappedMessage =
                        bincode::deserialize(&raw_msg.1).expect("deserialization error");

                    match wrapped {
                        WrappedMessage::BatchRecon(batchrecon_msg) => {
                            node.batch_recon
                                .process(batchrecon_msg, network[i].clone())
                                .await
                                .unwrap();
                            let _ = node.drain_batch_recon_output().await;
                        }
                        WrappedMessage::Rbc(rbc_msg) => {
                            match node.rbc.process(rbc_msg, network[i].clone()).await {
                                Ok(()) => {}
                                Err(e) => {
                                    panic!("unexpected error during RBC: {e}");
                                }
                            }
                            let _ = node.drain_rbc_output().await;
                        }
                        _ => {
                            panic!();
                        }
                    };
                }
            });
        }

        // wait for left out node to receive messages and calculate result
        let timeout_duration = Duration::from_secs(10);
        let start = Instant::now();

        loop {
            let storage_bind = nodes[node_id]
                .get_or_create_mult_storage(session_id)
                .await
                .unwrap();
            let storage = storage_bind.lock().await;

            // Batched batch-recon: a single a-x result (key 0) and a single b-y result (key 1).
            let has_mult1_keys = storage.output_open_mult1.contains_key(&0u8);
            let has_mult2_keys = storage.output_open_mult2.contains_key(&1u8);
            let has_enough_shares = storage.received_shares.len() >= 2 * t + 1;

            if has_mult1_keys && has_mult2_keys && has_enough_shares {
                // Condition met, verify remaining assertion and continue
                assert!(storage.openings.is_none());
                break;
            }

            drop(storage);

            if start.elapsed() > timeout_duration {
                panic!("Timeout waiting for storage to be populated");
            }

            sleep(Duration::from_millis(50)).await;
        }

        // so now we call init...
        assert!(nodes[node_id]
            .init(
                session_id,
                x_inputs_per_node[node_id].clone(),
                y_inputs_per_node[node_id].clone(),
                beaver_triples[node_id].clone(),
                network[node_id].clone()
            )
            .await
            .is_ok());

        let storage_bind = nodes[node_id]
            .get_or_create_mult_storage(session_id)
            .await
            .unwrap();
        let storage = storage_bind.lock().await;

        // openings via RBC should be there now
        assert!(storage.openings.is_some());

        drop(storage);

        // ...and obtain the result
        let mut real_shares = None;
        match nodes[node_id]
            .wait_for_result(session_id, Duration::from_millis(5))
            .await
        {
            Err(MulError::ResultAlreadyReceived(_)) => {
                info!("already received result");
            }
            Err(e) => {
                panic!("unexpected error during waiting: {e}");
            }
            Ok(shares) => {
                real_shares = Some(shares);
            }
        }

        // 8. Check that shares are correct
        assert!(real_shares.is_some());
        for (real_share, correct_share) in real_shares.unwrap().into_iter().zip(correct_shares) {
            assert_eq!(real_share.degree, t);
            assert_eq!(real_share.id, node_id);
            assert_eq!(real_share.share[0], correct_share.share[0]);
        }
    }

    // 1. Generate Beaver triples
    // 2. Prepare inputs for multiplication
    // 3. Generate correct openings and shares
    // 4. Create node
    // 5. Generate messages
    // 6. Shuffle messages
    // 7. Make node handle messages
    // 8. Check that shares are correct
    #[tokio::test]
    async fn test_open_mult_handler() {
        let n_parties = 10;
        let t = 3;
        let node_id = 0;
        let no_of_mul = 10;
        let split_at = no_of_mul - no_of_mul % (t + 1);
        let session_id = SessionId::new(ProtocolType::Mul, SessionId::pack_slot(123, 0, 0), 111);
        let mut rng = test_rng();

        // 1. Generate Beaver triples
        let ((secrets_a, secrets_b, _), beaver_triples) =
            construct_input_mul(n_parties, no_of_mul, t).await;
        let mult_from_triple: Vec<_> = beaver_triples[node_id]
            .iter()
            .map(|triple| triple.mult.clone())
            .collect();

        // 2. Prepare inputs for multiplication
        let mut x_values = Vec::new();
        let mut y_values = Vec::new();
        let mut x_inputs_per_node = vec![Vec::new(); n_parties];
        let mut y_inputs_per_node = vec![Vec::new(); n_parties];

        for _i in 0..no_of_mul {
            let x_value = Fr::rand(&mut rng);
            x_values.push(x_value);
            let y_value = Fr::rand(&mut rng);
            y_values.push(y_value);

            let shares_x =
                RobustShare::compute_shares(x_value, n_parties, t, None, &mut rng).unwrap();
            let shares_y =
                RobustShare::compute_shares(y_value, n_parties, t, None, &mut rng).unwrap();

            for p in 0..n_parties {
                x_inputs_per_node[p].push(shares_x[p].clone());
                y_inputs_per_node[p].push(shares_y[p].clone());
            }
        }

        // 3. Generate correct openings and shares
        let correct_a_sub_x = secrets_a
            .clone()
            .iter()
            .zip(x_values.clone())
            .map(|(a, x)| *a - x)
            .collect::<Vec<_>>();
        let correct_b_sub_y = secrets_b
            .clone()
            .iter()
            .zip(y_values.clone())
            .map(|(b, y)| *b - y)
            .collect::<Vec<_>>();

        let mut correct_shares = Vec::with_capacity(mult_from_triple.len());
        for (triple_mult, input_a, input_b, subtraction_a, subtraction_b) in izip!(
            &mult_from_triple,
            &x_inputs_per_node[node_id],
            &y_inputs_per_node[node_id],
            &correct_a_sub_x,
            &correct_b_sub_y
        ) {
            //(a−x)(b−y)
            let mult_subs = subtraction_a * subtraction_b;
            //(a−x)[y]_t
            let mult_sub_a_y = input_b
                .clone()
                .mul(*subtraction_a)
                .expect("multiplication failed");
            //(b−y)[x]_t
            let mult_sub_b_x = input_a
                .clone()
                .mul(*subtraction_b)
                .expect("multiplication failed");
            //[xy]_t
            let share = triple_mult
                .clone()
                .sub(mult_subs)
                .expect("subtraction failed");
            let share2: ShamirShare<Fr, 1, Robust> =
                (share - mult_sub_a_y).expect("subtraction failed");
            let share3 = (share2 - mult_sub_b_x).expect("subtraction failed");
            correct_shares.push(share3);
        }

        // 4. Create node
        let mul_node = Multiply::<Fr, Avid<SessionId>>::new(node_id, n_parties, t).unwrap();

        let storage_bind = mul_node
            .get_or_create_mult_storage(session_id)
            .await
            .unwrap();
        let mut storage = storage_bind.lock().await;
        storage.inputs = (
            x_inputs_per_node[node_id].clone(),
            y_inputs_per_node[node_id].clone(),
        );
        storage.share_mult_from_triple = beaver_triples[node_id]
            .iter()
            .map(|triple| triple.mult.clone())
            .collect();
        storage.no_of_mul = Some(correct_a_sub_x.len());
        drop(storage);

        // 5. Generate messages
        let mut mul_msgs = Vec::new();

        let open_a_sub_x = correct_a_sub_x.clone()[0..split_at].to_vec();
        let open_b_sub_y = correct_b_sub_y.clone()[0..split_at].to_vec();

        // using batch reconstruction — batched: one a-x session (sub_id 0) carrying ALL a-x
        // values and one b-y session (sub_id 1) carrying ALL b-y values, matching what
        // `init_batch_reconstruct_many` produces in the real flow.
        if !open_a_sub_x.is_empty() {
            let session_id_a = SessionId::new(
                ProtocolType::Mul,
                SessionId::pack_slot(session_id.exec_id(), 0, 1),
                session_id.instance_id(),
            );
            let mut a_bytes = Vec::new();
            open_a_sub_x
                .serialize_compressed(&mut a_bytes)
                .expect("serialization failed");
            mul_msgs.push(MultMessage::new(node_id, session_id_a, a_bytes));

            let session_id_b = SessionId::new(
                ProtocolType::Mul,
                SessionId::pack_slot(session_id.exec_id(), 1, 1),
                session_id.instance_id(),
            );
            let mut b_bytes = Vec::new();
            open_b_sub_y
                .serialize_compressed(&mut b_bytes)
                .expect("serialization failed");
            mul_msgs.push(MultMessage::new(node_id, session_id_b, b_bytes));
        }

        // using RBC
        for i in 0..n_parties {
            if i == node_id {
                continue;
            }

            let shared_a_sub_x = x_inputs_per_node[i][split_at..]
                .iter()
                .zip(beaver_triples[i][split_at..].iter())
                .map(|(x, triple)| triple.a.clone() - x.clone())
                .collect::<Result<Vec<RobustShare<Fr>>, ShareError>>()
                .expect("share subtraction failed");
            let shared_b_sub_y = y_inputs_per_node[i][split_at..]
                .iter()
                .zip(beaver_triples[i][split_at..].iter())
                .map(|(y, triple)| triple.b.clone() - y.clone())
                .collect::<Result<Vec<RobustShare<Fr>>, ShareError>>()
                .expect("share subtraction failed");

            if shared_a_sub_x.len() > 0 && shared_b_sub_y.len() > 0 {
                let rec_msg =
                    ReconstructionMessage::new(shared_a_sub_x.to_vec(), shared_b_sub_y.to_vec());
                let mut bytes_rec_msg = Vec::new();
                rec_msg
                    .serialize_compressed(&mut bytes_rec_msg)
                    .expect("serialization failed");

                let shared_session_id = SessionId::new(
                    ProtocolType::Mul,
                    SessionId::pack_slot(session_id.exec_id(), mul_node.id as u8, 2),
                    session_id.instance_id(),
                );

                mul_msgs.push(MultMessage::new(i, shared_session_id, bytes_rec_msg));
            }
        }

        // 6. Shuffle messages
        mul_msgs.shuffle(&mut thread_rng());

        // 7. Make node handle messages
        for msg in mul_msgs {
            let result = mul_node
                .open_mult_handler(msg.sender, msg.session_id, msg.payload)
                .await;
            match result {
                Ok(()) => {}
                Err(MulError::Duplicate(e)) => {
                    panic!("duplicate detected: {e}")
                }
                Err(e) => {
                    panic!("unexpected error during processing: {e}");
                }
            }
        }

        let real_shares = match mul_node
            .wait_for_result(session_id, Duration::from_millis(1))
            .await
        {
            Err(MulError::ResultAlreadyReceived(_)) => {
                panic!("already received result");
            }
            Err(e) => {
                panic!("unexpected error during waiting: {e}");
            }
            Ok(shares) => Some(shares),
        };

        // 8. Check that shares are correct
        assert!(real_shares.is_some());
        for (real_share, correct_share) in real_shares.unwrap().into_iter().zip(correct_shares) {
            assert_eq!(real_share.degree, t);
            assert_eq!(real_share.id, node_id);
            assert_eq!(real_share.share[0], correct_share.share[0]);
        }
    }

    /// Regression test for the mul pipelining / RBC late-output race.
    ///
    /// `drain_rbc_output` reads session ids the RBC queued on delivery, then calls
    /// `rbc.get_store(id)`. After a pipelined mul finishes, `mul()` calls
    /// `clear_store`, which removes the round-2 RBC sessions. An id queued just
    /// before the clear becomes stale: its session is gone, so `get_store` returns
    /// "Session ID does not exist". Previously that propagated as a fatal
    /// `MulError::RbcError` (crashing the node's message loop under workloads like
    /// `aes-unoptimized.stflb`); it must now be ignored as harmless late traffic.
    ///
    /// The post-clear state (stale id in the drain queue, RBC session absent) is
    /// reproduced directly rather than by driving a full network, which is enough
    /// to cover the fixed branch.
    #[tokio::test]
    async fn test_drain_rbc_output_ignores_cleared_session() {
        let n = 10;
        let t = 3;
        let node_id = 0;
        // Odd count not divisible by t + 1 so the RBC remainder path is active.
        let no_of_mul = 5;
        let session_id = SessionId::new(ProtocolType::Mul, SessionId::pack_slot(7, 0, 0), 111);

        let mut node = Multiply::<Fr, Avid<SessionId>>::new(node_id, n, t).unwrap();

        // Swap in a drain queue we control so we can inject a stale id. (The real
        // queue is fed by RBC delivery; here we only need the post-clear state.)
        let (stale_tx, stale_rx) = mpsc::channel(200);
        node.rbc_output = Arc::new(Mutex::new(stale_rx));

        // `clear_store` needs a mult_storage entry; create one for this session.
        {
            let storage = node.get_or_create_mult_storage(session_id).await.unwrap();
            storage.lock().await.no_of_mul = Some(no_of_mul);
        }

        // A round-2 RBC id for this party, as would be queued on RBC delivery.
        let stale_id = SessionId::new(
            ProtocolType::Mul,
            SessionId::pack_slot(session_id.exec_id(), node_id as u8, 2),
            session_id.instance_id(),
        );
        stale_tx.send(stale_id).await.unwrap();

        // The mul finished: `clear_store` removes the round-2 RBC sessions (a
        // no-op here since none ran) and the mult_storage entry. The queued id is
        // now stale.
        node.clear_store(session_id).await.unwrap();

        // Without the fix: Err(MulError::RbcError("Session ID does not exist")).
        // With the fix: the stale output is dropped and drain succeeds.
        assert!(
            node.drain_rbc_output().await.is_ok(),
            "drain_rbc_output must ignore stale outputs for cleared sessions"
        );
        // Draining an empty queue afterwards must also be fine.
        assert!(node.drain_rbc_output().await.is_ok());
    }

    /// Same race as above, but on the batch-reconstruction output queue.
    /// `drain_batch_recon_output` must also ignore ids whose session was cleared
    /// by `clear_store` instead of propagating "Session ID does not exist".
    #[tokio::test]
    async fn test_drain_batch_recon_output_ignores_cleared_session() {
        let n = 10;
        let t = 3;
        let node_id = 0;
        // no_of_batch = 5 / (t + 1) = 1 > 0, so `clear_store` clears the
        // round-1 batch-recon sessions (sub_id 0 and 1).
        let no_of_mul = 5;
        let session_id = SessionId::new(ProtocolType::Mul, SessionId::pack_slot(9, 0, 0), 222);

        let mut node = Multiply::<Fr, Avid<SessionId>>::new(node_id, n, t).unwrap();

        let (stale_tx, stale_rx) = mpsc::channel(200);
        node.batch_output = Arc::new(Mutex::new(stale_rx));

        {
            let storage = node.get_or_create_mult_storage(session_id).await.unwrap();
            storage.lock().await.no_of_mul = Some(no_of_mul);
        }

        // A round-1 batch-recon id (sub_id 0 = a-x values), as queued on delivery.
        let stale_id = SessionId::new(
            ProtocolType::Mul,
            SessionId::pack_slot(session_id.exec_id(), 0, 1),
            session_id.instance_id(),
        );
        stale_tx.send(stale_id).await.unwrap();

        node.clear_store(session_id).await.unwrap();

        assert!(
            node.drain_batch_recon_output().await.is_ok(),
            "drain_batch_recon_output must ignore stale outputs for cleared sessions"
        );
    }

    /// Regression test for the "Duplicate" symptom of the mul late-message race.
    ///
    /// A late/duplicate RBC delivery can hand the same dealer to `open_mult_handler` twice.
    /// Previously that returned a fatal `MulError::Duplicate`; it must now be idempotent
    /// (return `Ok(())`) — RBC agreement delivers one value per dealer and reconstruction counts
    /// each dealer once, so a duplicate cannot change the result.
    #[tokio::test]
    async fn test_open_mult_handler_ignores_duplicate_rbc_sender() {
        let n = 10;
        let t = 3;
        let node_id = 0;
        let session_id = SessionId::new(ProtocolType::Mul, SessionId::pack_slot(7, 0, 0), 111);

        let mul_node = Multiply::<Fr, Avid<SessionId>>::new(node_id, n, t).unwrap();

        // Seed the session: init has run, and dealer 3 has already delivered its RBC shares.
        {
            let storage = mul_node
                .get_or_create_mult_storage(session_id)
                .await
                .unwrap();
            let mut s = storage.lock().await;
            s.no_of_mul = Some(5);
            s.received_shares.insert(3, (Vec::new(), Vec::new()));
        }

        // A late/duplicate round-2 delivery from dealer 3.
        let dup_sid = SessionId::new(
            ProtocolType::Mul,
            SessionId::pack_slot(session_id.exec_id(), 3, 2),
            session_id.instance_id(),
        );

        // Pre-fix: Err(MulError::Duplicate(...)). Post-fix: idempotent Ok(()).
        let result = mul_node.open_mult_handler(3, dup_sid, Vec::new()).await;
        assert!(
            result.is_ok(),
            "duplicate RBC delivery must be tolerated: {result:?}"
        );

        // No double-insert: dealer 3 still has exactly one entry.
        let storage = mul_node
            .get_or_create_mult_storage(session_id)
            .await
            .unwrap();
        let s = storage.lock().await;
        assert!(s.received_shares.contains_key(&3));
        assert_eq!(s.received_shares.len(), 1);
    }
}
