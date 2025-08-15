use crate::{
    common::{share::ShareError, ShamirShare},
    honeybadger::{
        batch_recon::batch_recon::BatchReconNode,
        mul::{MulError, MultMessage, MultProtocolState, MultStorage},
        robust_interpolate::robust_interpolate::{Robust, RobustShare},
        triple_gen::ShamirBeaverTriple,
        ProtocolType, SessionId,
    },
};
use ark_ff::FftField;
use ark_serialize::CanonicalDeserialize;
use itertools::izip;
use std::{
    collections::HashMap,
    ops::{Mul, Sub},
    sync::Arc,
};
use stoffelmpc_network::{Network, PartyId};
use tokio::sync::{mpsc::Sender, Mutex};
use tracing::info;

#[derive(Clone, Debug)]
pub struct Multiply<F: FftField> {
    pub id: usize,
    pub n: usize,
    pub threshold: usize,
    pub mult_storage: Arc<Mutex<HashMap<SessionId, Arc<Mutex<MultStorage<F>>>>>>,
    pub sender_finished_mults: Sender<SessionId>,
    pub batch_recon: BatchReconNode<F>,
}

impl<F: FftField> Multiply<F> {
    pub fn new(
        id: PartyId,
        n: usize,
        threshold: usize,
        output_sender: Sender<SessionId>,
    ) -> Result<Self, MulError> {
        let batch_recon = BatchReconNode::<F>::new(id, n, threshold)?;
        Ok(Self {
            id,
            n,
            threshold,
            mult_storage: Arc::new(Mutex::new(HashMap::new())),
            sender_finished_mults: output_sender,
            batch_recon,
        })
    }

    pub async fn init<N: Network>(
        &self,
        session_id: SessionId,
        x: Vec<RobustShare<F>>,
        y: Vec<RobustShare<F>>,
        beaver_triples: Vec<ShamirBeaverTriple<F>>,
        network: Arc<N>,
    ) -> Result<(), MulError> {
        {
            let storage_bind = self.get_or_create_mult_storage(session_id).await;
            let mut storage = storage_bind.lock().await;
            storage.inputs = (x.clone(), y.clone());
            storage.share_mult_from_triple = beaver_triples
                .iter()
                .map(|triple| triple.mult.clone())
                .collect();
        }

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

        let session_id1 = SessionId::new(ProtocolType::MulOne, session_id.context_id());
        let session_id2 = SessionId::new(ProtocolType::MulTwo, session_id.context_id());

        // Executes the batch reconstruction to reconstruct the messages.
        self.batch_recon
            .init_batch_reconstruct(&a_sub_x, session_id1, Arc::clone(&network))
            .await?;

        self.batch_recon
            .init_batch_reconstruct(&b_sub_y, session_id2, Arc::clone(&network))
            .await?;

        Ok(())
    }

    pub async fn open_mult_handler(
        &self,
        msg: MultMessage,
    ) -> Result<Option<Vec<RobustShare<F>>>, MulError> {
        //Get back original session id,Im assuming the protocol type is Mul here, it could be different
        let session_id = SessionId::new(ProtocolType::Mul, msg.session_id.context_id());
        let open_message: Vec<F> =
            CanonicalDeserialize::deserialize_compressed(msg.payload.as_slice())?;

        let storage_bind = self.get_or_create_mult_storage(session_id).await;
        let mut storage = storage_bind.lock().await;

        // Store the values in the appropriate slot
        match msg.session_id.protocol().unwrap() {
            ProtocolType::MulOne => {
                info!(
                    self_id = self.id,
                    "Received first open message for session_id: {:?}", session_id
                );
                storage.output_open_mult.0 = Some(open_message);
            }
            ProtocolType::MulTwo => {
                info!(
                    self_id = self.id,
                    "Received second open message for session_id: {:?}", session_id
                );
                storage.output_open_mult.1 = Some(open_message);
            }
            _ => return Ok(None),
        }

        // If both results aren't ready yet, return early
        if storage.output_open_mult.0.is_none() || storage.output_open_mult.1.is_none() {
            return Ok(None);
        }

        // SAFETY: Both slots are filled, unwrap is safe
        let mut shares_mult = Vec::with_capacity(storage.share_mult_from_triple.len());
        for (triple_mult, input_a, input_b, subtraction_a, subtraction_b) in izip!(
            &storage.share_mult_from_triple,
            &storage.inputs.0,
            &storage.inputs.1,
            storage.output_open_mult.0.as_ref().unwrap(),
            storage.output_open_mult.1.as_ref().unwrap(),
        ) {
            //(a−x)(b−y)
            let mult_subs = *subtraction_a * subtraction_b;
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
}
