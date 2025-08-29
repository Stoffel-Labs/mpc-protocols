use crate::{
    common::{share::ShareError, SecretSharingScheme, ShamirShare, RBC},
    honeybadger::{
        batch_recon::batch_recon::BatchReconNode,
        mul::{MulError, MultMessage, MultProtocolState, MultStorage, ReconstructionMessage},
        robust_interpolate::robust_interpolate::{Robust, RobustShare},
        triple_gen::ShamirBeaverTriple,
        ProtocolType, SessionId, WrappedMessage,
    },
};
use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use itertools::izip;
use std::{
    collections::HashMap,
    ops::{Mul, Sub},
    sync::Arc,
};
use stoffelnet::network_utils::{Network, PartyId};
use tokio::sync::{mpsc::Sender, Mutex};
use tracing::info;

#[derive(Clone, Debug)]
pub struct Multiply<F: FftField, R: RBC> {
    pub id: usize,
    pub n: usize,
    pub threshold: usize,
    pub mult_storage: Arc<Mutex<HashMap<SessionId, Arc<Mutex<MultStorage<F>>>>>>,
    pub sender_finished_mults: Sender<SessionId>,
    pub batch_recon: BatchReconNode<F>,
    pub rbc: R,
}

impl<F: FftField, R: RBC> Multiply<F, R> {
    pub fn new(
        id: PartyId,
        n: usize,
        threshold: usize,
        output_sender: Sender<SessionId>,
    ) -> Result<Self, MulError> {
        let batch_recon = BatchReconNode::<F>::new(id, n, threshold)?;
        let rbc = R::new(id, n, threshold, threshold + 1)?;
        Ok(Self {
            id,
            n,
            threshold,
            mult_storage: Arc::new(Mutex::new(HashMap::new())),
            sender_finished_mults: output_sender,
            batch_recon,
            rbc,
        })
    }

    pub async fn init<N: Network>(
        &mut self,
        session_id: SessionId,
        x: Vec<RobustShare<F>>,
        y: Vec<RobustShare<F>>,
        beaver_triples: Vec<ShamirBeaverTriple<F>>,
        network: Arc<N>,
    ) -> Result<(), MulError>
    where
        N: Network + Send + Sync,
    {
        info!(party = self.id, "Initializing multiplication");
        if x.len() != y.len() || x.len() != beaver_triples.len() {
            return Err(MulError::InvalidInput("Incorrect input lenght".to_string()));
        }
        let storage_bind = self.get_or_create_mult_storage(session_id).await;
        let mut storage = storage_bind.lock().await;
        storage.inputs = (x.clone(), y.clone());
        storage.share_mult_from_triple = beaver_triples
            .iter()
            .map(|triple| triple.mult.clone())
            .collect();

        // Compute a - x and b - y.
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

        let t = self.threshold;
        let split_at = a_sub_x.len() - (a_sub_x.len() % (t + 1));
        let (a_full, remaining_a) = a_sub_x.split_at(split_at);
        let (b_full, remaining_b) = b_sub_y.split_at(split_at);
        storage.no_of_mul = Some(a_sub_x.len());
        drop(storage);

        for (i, (chunk_a, chunk_b)) in a_full.chunks(t + 1).zip(b_full.chunks(t + 1)).enumerate() {
            let session_id1 = SessionId::new(
                ProtocolType::Mul,
                1,
                (2 * i) as u8,
                session_id.instance_id(),
            );
            let session_id2 = SessionId::new(
                ProtocolType::Mul,
                1,
                (2 * i + 1) as u8,
                session_id.instance_id(),
            );

            // Executes the batch reconstruction to reconstruct the messages.
            self.batch_recon
                .init_batch_reconstruct(&chunk_a, session_id1, Arc::clone(&network))
                .await?;

            self.batch_recon
                .init_batch_reconstruct(&chunk_b, session_id2, Arc::clone(&network))
                .await?;
        }

        //Reconstruct < t+1 values
        if remaining_a.len() > 0 && remaining_b.len() > 0 {
            let reconst_message =
                ReconstructionMessage::new(remaining_a.to_vec(), remaining_b.to_vec());
            let mut bytes_rec_message = Vec::new();
            reconst_message.serialize_compressed(&mut bytes_rec_message)?;

            let sessionid = SessionId::new(
                ProtocolType::Mul,
                2,
                self.id as u8,
                session_id.instance_id(),
            );

            let wrapped =
                WrappedMessage::Mul(MultMessage::new(self.id, sessionid, bytes_rec_message));
            let bytes_wrapped = bincode::serialize(&wrapped)?;

            self.rbc
                .init(bytes_wrapped, sessionid, Arc::clone(&network))
                .await?;
        }
        Ok(())
    }

    pub async fn open_mult_handler(
        &self,
        msg: MultMessage,
    ) -> Result<Option<Vec<RobustShare<F>>>, MulError> {
        let session_id = SessionId::new(ProtocolType::Mul, 0, 0, msg.session_id.instance_id());

        let storage_bind = self.get_or_create_mult_storage(session_id).await;
        let mut storage = storage_bind.lock().await;
        let mul_len = storage.no_of_mul.ok_or(MulError::InvalidInput(format!(
            "No. of multiplications not set for node {}",
            self.id
        )))?;
        let share_len = mul_len % (self.threshold + 1);

        // Store the values in the appropriate slot
        if msg.session_id.sub_id() == 1 {
            let open: Vec<F> =
                CanonicalDeserialize::deserialize_compressed(msg.payload.as_slice())?;
            if msg.session_id.round_id() % 2 == 0 {
                if storage
                    .output_open_mult1
                    .contains_key(&msg.session_id.round_id())
                {
                    return Err(MulError::Duplicate(format!(
                        "Already received from {}",
                        msg.sender
                    )));
                }
                info!(
                    self_id = self.id,
                    "Received first open message for session_id: {:?} and round {:?}",
                    session_id,
                    msg.session_id.round_id()
                );
                storage
                    .output_open_mult1
                    .insert(msg.session_id.round_id(), open);
            } else {
                if storage
                    .output_open_mult2
                    .contains_key(&msg.session_id.round_id())
                {
                    return Err(MulError::Duplicate(format!(
                        "Already received from {}",
                        msg.sender
                    )));
                }
                info!(
                    self_id = self.id,
                    "Received second open message for session_id: {:?} and round {:?}",
                    session_id,
                    msg.session_id.round_id()
                );
                storage
                    .output_open_mult2
                    .insert(msg.session_id.round_id(), open);
            }
        } else if msg.session_id.sub_id() == 2 {
            info!(
                self_id = self.id,
                "Received shares for reconstruction for session_id: {:?}", session_id
            );
            if storage.received_shares.contains_key(&msg.sender) {
                return Err(MulError::Duplicate(format!(
                    "Already received from {}",
                    msg.sender
                )));
            }
            let open_message: ReconstructionMessage<F> =
                CanonicalDeserialize::deserialize_compressed(msg.payload.as_slice())?;

            if open_message.a_sub_x.len() != share_len || open_message.b_sub_x.len() != share_len {
                return Err(MulError::InvalidInput(
                    "Not enough shares to reconstruct the opening".to_string(),
                ));
            }
            storage
                .received_shares
                .insert(msg.sender, (open_message.a_sub_x, open_message.b_sub_x));
        }

        let mut a_sub_x: Vec<F> = Vec::new();
        let mut b_sub_x: Vec<F> = Vec::new();
        if mul_len % (self.threshold + 1) != 0 {
            if storage.received_shares.len() >= 2 * self.threshold + 1 {
                info!("Received enough shares to reconstruct");
                let mut a_shares = vec![vec![]; share_len];
                let mut b_shares = vec![vec![]; share_len];
                for (_, (a, b)) in storage.received_shares.iter() {
                    for i in 0..share_len {
                        a_shares[i].push(a[i].clone());
                        b_shares[i].push(b[i].clone());
                    }
                }
                for i in 0..share_len {
                    let a = RobustShare::recover_secret(&a_shares[i], self.n)?;
                    let b = RobustShare::recover_secret(&b_shares[i], self.n)?;

                    a_sub_x.push(a.1);
                    b_sub_x.push(b.1);
                }
            }
        }

        let no_of_batch = mul_len / (self.threshold + 1);
        if storage.output_open_mult1.len() != no_of_batch
            || storage.output_open_mult2.len() != no_of_batch
            || a_sub_x.len() != share_len
            || b_sub_x.len() != share_len
        {
            return Err(MulError::WaitForOk);
        }

        let mut concatenated_mult1: Vec<F> = self.concat_sorted(&storage.output_open_mult1);
        concatenated_mult1.extend(a_sub_x);

        let mut concatenated_mult2: Vec<F> = self.concat_sorted(&storage.output_open_mult2);
        concatenated_mult2.extend(b_sub_x);

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
            let mult_sub_a_y = input_b.clone().mul(subtraction_a.clone())?;
            //(b−y)[x]_t
            let mult_sub_b_x = input_a.clone().mul(subtraction_b.clone())?;
            //[xy]_t
            let share = triple_mult.clone().sub(mult_subs)?;
            let share2: ShamirShare<F, 1, Robust> = (share - mult_sub_a_y)?;
            let share3 = (share2 - mult_sub_b_x)?;
            shares_mult.push(share3);
        }

        storage.protocol_output = shares_mult.clone();
        storage.protocol_state = MultProtocolState::Finished;
        self.sender_finished_mults.send(session_id).await?;

        Ok(Some(shares_mult))
    }

    pub async fn process(&mut self, message: MultMessage) -> Result<(), MulError> {
        self.open_mult_handler(message).await?;
        Ok(())
    }

    async fn get_or_create_mult_storage(
        &self,
        session_id: SessionId,
    ) -> Arc<Mutex<MultStorage<F>>> {
        let mut storage = self.mult_storage.lock().await;
        storage
            .entry(session_id)
            .or_insert(Arc::new(Mutex::new(MultStorage::empty())))
            .clone()
    }

    fn concat_sorted(&self, map: &HashMap<u8, Vec<F>>) -> Vec<F> {
        // collect and sort keys
        let mut keys: Vec<_> = map.keys().cloned().collect();
        keys.sort_unstable();

        // pre-compute total size to reserve capacity
        let total_len: usize = keys.iter().map(|k| map[k].len()).sum();

        // build result with exact capacity
        let mut out = Vec::with_capacity(total_len);
        for k in keys {
            out.extend_from_slice(&map[&k]);
        }
        out
    }
}
