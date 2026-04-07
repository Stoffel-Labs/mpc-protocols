use crate::avss_mpc::mul::{
    MulError, MultMessage, MultProtocolState, MultStorage, ReconstructionMessage,
};
use crate::avss_mpc::triple_gen::BeaverTriple;
use crate::avss_mpc::{AvssSessionId, AvssWrappedMessage};
use crate::common::share::feldman::FeldmanShamirShare;
use crate::common::{share::ShareError, RBC};
use crate::common::{ProtocolSessionId, SecretSharingScheme};
use ark_ec::CurveGroup;
use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use itertools::izip;
use std::{collections::HashMap, sync::Arc};
use stoffelnet::network_utils::{Network, PartyId};
use tokio::sync::mpsc::Receiver;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{timeout, Duration};
use tracing::{info, warn};

#[derive(Clone, Debug)]
pub struct Multiply<F: FftField, R: RBC, G: CurveGroup<ScalarField = F>> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    pub mult_storage: Arc<Mutex<HashMap<AvssSessionId, Arc<Mutex<MultStorage<F, G>>>>>>,
    pub rbc: R,
    pub rbc_output: Arc<Mutex<Receiver<AvssSessionId>>>,
}

impl<F: FftField, R: RBC<Id = AvssSessionId>, G: CurveGroup<ScalarField = F>> Multiply<F, R, G> {
    pub fn new(id: PartyId, n: usize, threshold: usize) -> Result<Self, MulError> {
        let (rbc_sender, rbc_receiver) = mpsc::channel(200);
        let rbc = R::new(
            id,
            n,
            threshold,
            threshold + 1,
            rbc_sender,
            Arc::new(AvssWrappedMessage::rbc_wrap),
        )?;
        Ok(Self {
            id,
            n,
            t: threshold,
            mult_storage: Arc::new(Mutex::new(HashMap::new())),
            rbc,
            rbc_output: Arc::new(Mutex::new(rbc_receiver)),
        })
    }
    pub async fn clear_store(&self, session_id: AvssSessionId) -> bool {
        self.rbc.clear_store().await;
        let mut store = self.mult_storage.lock().await;
        store.remove(&session_id).is_some()
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

            let output = self.rbc.get_store(id).await?;
            let msg: MultMessage = bincode::deserialize(&output)?;

            match self.open_mult_handler(msg).await {
                Ok(()) => {}
                Err(e) => {
                    return Err(e);
                }
            }
        }
        Ok(())
    }
    pub async fn init<N: Network + Send + Sync>(
        &mut self,
        session_id: AvssSessionId,
        x: Vec<FeldmanShamirShare<F, G>>,
        y: Vec<FeldmanShamirShare<F, G>>,
        beaver_triples: Vec<BeaverTriple<F, G>>,
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
        let storage_bind = self.get_or_create_mult_storage(session_id).await;
        let mut storage = storage_bind.lock().await;

        storage.no_of_mul = Some(no_of_mul);
        storage.inputs = (x.clone(), y.clone());
        storage.share_mult_from_triple = beaver_triples
            .iter()
            .map(|triple| triple.c.clone())
            .collect();
        drop(storage);
        if self
            .try_finalize_mul(session_id, storage_bind.clone())
            .await?
        {
            return Ok(());
        }
        let a_sub_x = x
            .iter()
            .zip(beaver_triples.iter())
            .map(|(x, triple)| triple.a.clone() - x.clone())
            .collect::<Result<Vec<FeldmanShamirShare<F, G>>, ShareError>>()?;
        let b_sub_y = y
            .iter()
            .zip(beaver_triples.iter())
            .map(|(y, triple)| triple.b.clone() - y.clone())
            .collect::<Result<Vec<FeldmanShamirShare<F, G>>, ShareError>>()?;

        let reconst_message = ReconstructionMessage::new(a_sub_x.to_vec(), b_sub_y.to_vec());
        let mut bytes_rec_message = Vec::new();
        reconst_message.serialize_compressed(&mut bytes_rec_message)?;

        let rbc_sessionid = AvssSessionId::new(
            session_id.calling_protocol().unwrap(),
            AvssSessionId::pack_slot24(session_id.exec_id(), 0, self.id as u8),
            session_id.instance_id(),
        );

        let wrapped = MultMessage::new(self.id, session_id, bytes_rec_message);
        let bytes_wrapped = bincode::serialize(&wrapped)?;

        self.rbc
            .init(bytes_wrapped, rbc_sessionid, Arc::clone(&network))
            .await?;

        Ok(())
    }

    pub async fn open_mult_handler(&self, msg: MultMessage) -> Result<(), MulError> {
        let storage_bind = self.get_or_create_mult_storage(msg.session_id).await;
        let mut storage = storage_bind.lock().await;
        if storage.protocol_state == MultProtocolState::Finished {
            return Ok(());
        }
        info!(
            self_id = self.id,
            "Received shares for reconstruction using RBC for session_id: {:?}", msg.session_id
        );
        if storage.received_shares.contains_key(&msg.sender) {
            return Err(MulError::Duplicate(format!(
                "Already received shares for reconstruction using RBC from {} in open handler inside AVSS multiplication",
                msg.sender
            )));
        }

        let open_message: ReconstructionMessage<F, G> =
            CanonicalDeserialize::deserialize_compressed(msg.payload.as_slice())?;

        storage
            .received_shares
            .insert(msg.sender, (open_message.a_sub_x, open_message.b_sub_y));
        drop(storage);
        let _ = self.try_finalize_mul(msg.session_id, storage_bind).await?;
        info!("Multiplication completed at node {}", self.id);

        Ok(())
    }

    pub async fn process(&mut self, message: MultMessage) -> Result<(), MulError> {
        self.open_mult_handler(message).await?;
        Ok(())
    }

    pub async fn get_or_create_mult_storage(
        &self,
        session_id: AvssSessionId,
    ) -> Arc<Mutex<MultStorage<F, G>>> {
        let mut storage = self.mult_storage.lock().await;

        // should never occur, since only exec ID changes for different runs
        assert!(storage.len() <= 256);

        storage
            .entry(session_id)
            .or_insert(Arc::new(Mutex::new(MultStorage::empty())))
            .clone()
    }

    pub async fn wait_for_result(
        &self,
        session_id: AvssSessionId,
        duration: Duration,
    ) -> Result<Vec<FeldmanShamirShare<F, G>>, MulError> {
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
    async fn try_finalize_mul(
        &self,
        session_id: AvssSessionId,
        storage_bind: Arc<Mutex<MultStorage<F, G>>>,
    ) -> Result<bool, MulError> {
        // -------- Phase 1: Check readiness --------
        let should_finalize = {
            let mut storage = storage_bind.lock().await;

            if storage.protocol_state == MultProtocolState::Finished {
                return Ok(true);
            }

            if storage.no_of_mul.is_none() {
                return Ok(false);
            }

            reconstruct_if_ready(&mut storage, self.t, self.n)?;

            storage.openings.is_some()
        };

        if !should_finalize {
            return Ok(false);
        }

        // -------- Phase 2: Compute outside lock --------
        let shares_mult = {
            let storage = storage_bind.lock().await;
            finalize_mul(&storage)?
        };

        // -------- Phase 3: Commit + send --------
        let sender = {
            let mut storage = storage_bind.lock().await;

            if storage.protocol_state == MultProtocolState::Finished {
                return Ok(true);
            }

            storage.protocol_state = MultProtocolState::Finished;

            storage
                .output_sender
                .take()
                .ok_or(MulError::SendError(session_id))?
        };

        sender
            .send(shares_mult)
            .map_err(|_| MulError::SendError(session_id))?;

        Ok(true)
    }
}

fn reconstruct_if_ready<F: FftField, G: CurveGroup<ScalarField = F>>(
    storage: &mut MultStorage<F, G>,
    t: usize,
    n: usize,
) -> Result<(), MulError> {
    if storage.received_shares.len() >= 2 * t + 1 && storage.openings.is_none() {
        let no_of_mul = storage.no_of_mul.unwrap();

        let mut a_sub_x = Vec::new();
        let mut b_sub_y = Vec::new();
        let mut a_shares = vec![vec![]; no_of_mul];
        let mut b_shares = vec![vec![]; no_of_mul];

        for (_, (a, b)) in storage.received_shares.iter() {
            if a.len() != no_of_mul || b.len() != no_of_mul {
                warn!("Did not recieve the right number of shares to reconstruct using RBC (sent for a-x and for b-y)");
                continue;
            }
            for i in 0..no_of_mul {
                a_shares[i].push(a[i].clone());
                b_shares[i].push(b[i].clone());
            }
        }

        for i in 0..no_of_mul {
            let a = FeldmanShamirShare::recover_secret(&a_shares[i], n, t)?;
            let b = FeldmanShamirShare::recover_secret(&b_shares[i], n, t)?;
            a_sub_x.push(a.1);
            b_sub_y.push(b.1);
        }
        info!("Reconstruction succeeded");

        storage.openings = Some((a_sub_x, b_sub_y));
    }
    Ok(())
}
fn finalize_mul<F: FftField, G: CurveGroup<ScalarField = F>>(
    storage: &MultStorage<F, G>,
) -> Result<Vec<FeldmanShamirShare<F, G>>, MulError> {
    assert!(storage.openings.is_some()); // always ensured by the caller

    let openings = storage.openings.as_ref().unwrap();
    let expected_len = storage.share_mult_from_triple.len();
    if storage.inputs.0.len() != expected_len || storage.inputs.1.len() != expected_len {
        return Err(MulError::InvalidInput(
            "Inconsistent lengths in finalize_mul".to_string(),
        ));
    }
    let mut shares_mult = Vec::with_capacity(expected_len);
    for (triple_mult, input_a, input_b, subtraction_a, subtraction_b) in izip!(
        &storage.share_mult_from_triple,
        &storage.inputs.0,
        &storage.inputs.1,
        openings.0.clone(),
        openings.1.clone(),
    ) {
        //(a−x)(b−y)
        let mult_subs = subtraction_a * subtraction_b;
        //(a−x)[y]_t
        let mult_sub_a_y = (input_b.clone() * subtraction_a)?;
        //(b−y)[x]_t
        let mult_sub_b_x = (input_a.clone() * subtraction_b)?;
        //[xy]_t
        let share = (triple_mult.clone() - mult_subs)?;
        let share2: FeldmanShamirShare<F, G> = (share - mult_sub_a_y)?;
        let share3 = (share2 - mult_sub_b_x)?;
        shares_mult.push(share3);
    }

    Ok(shares_mult)
}
