use crate::common::utils::deser_bounded_vec;
use crate::common::{ProtocolSessionId, RBC};
use crate::honeybadger::batch_recon::batch_recon::BatchReconNode;
use crate::honeybadger::fpmul::{ProtocolState, RandBitError, RandBitStorage};
use crate::honeybadger::mul::concat_sorted;
use crate::honeybadger::mul::multiplication::Multiply;
use crate::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use crate::honeybadger::triple_gen::ShamirBeaverTriple;
use crate::honeybadger::SessionId;
use ark_ff::FftField;
use itertools::izip;
use std::collections::HashMap;
use std::ops::{Add, Mul};
use std::sync::Arc;
use stoffelnet::network_utils::{Network, PartyId};
use tokio::sync::mpsc::Receiver;
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};

/// Represents the random bit generation protocol.
///
/// # Output
///
/// If `t + 1` random elements are provided, then the protocol will return `t + 1` random bits. The
/// number of random elements is limited by the amount of shared elements that the batch
/// reconstruction protocol can reconstruct. (Updated to generate multiples of (t+1))
///
/// # Assumptions
///
/// This protocol is based on the secure multiplication protocol and the generation of random shared
/// values. Hence, the protocol assumes that you provide one multiplication triple to execute the
/// secure multiplication protocol and the share of a random value.
///
/// If the underlying sharing scheme implements the ideal arithmetic black box functionality, then
/// this protocol is secure.
#[derive(Clone, Debug)]
pub struct RandBit<F, R>
where
    F: FftField,
    R: RBC,
{
    /// The ID of the node.
    pub id: PartyId,
    /// The number of parties participating in the protocol.
    pub n_parties: usize,
    /// The threshold of corrupted parties.
    pub threshold: usize,
    /// Storage for the protocol.
    pub storage: Arc<Mutex<HashMap<SessionId, Arc<Mutex<RandBitStorage<F>>>>>>,
    /// Node to execute a secure multiplication.
    pub mult_node: Multiply<F, R>,
    /// Batch reconstruction node to reconstruct `a^2 mod p`.
    pub batch_recon: BatchReconNode<F>,
    pub batch_output: Arc<Mutex<Receiver<SessionId>>>,
}

impl<F, R> RandBit<F, R>
where
    F: FftField,
    R: RBC<Id = SessionId>,
{
    pub fn new(id: PartyId, n_parties: usize, threshold: usize) -> Result<Self, RandBitError> {
        let (batch_sender, batch_receiver) = tokio::sync::mpsc::channel(200);
        let batch_recon_node =
            BatchReconNode::new(id, n_parties, threshold, threshold, batch_sender)?;
        let mult_node = Multiply::new(id, n_parties, threshold)?;
        Ok(Self {
            id,
            n_parties,
            threshold,
            storage: Arc::new(Mutex::new(HashMap::new())),
            mult_node,
            batch_recon: batch_recon_node,
            batch_output: Arc::new(Mutex::new(batch_receiver)),
        })
    }

    pub async fn clear_store(&self, session_id: SessionId) -> Result<(), RandBitError> {
        self.mult_node.clear_store(session_id).await?;
        self.batch_recon.clear_entire_store().await;
        let mut store = self.storage.lock().await;
        store
            .remove(&session_id)
            .map(|_| ())
            .ok_or(RandBitError::ClearStoreError(session_id))
    }

    pub async fn get_or_create_storage(
        &self,
        session_id: SessionId,
    ) -> Result<Arc<Mutex<RandBitStorage<F>>>, RandBitError> {
        let mut storage = self.storage.lock().await;

        // only exec ID changes between different runs
        if storage.len() >= 256 && !storage.contains_key(&session_id) {
            return Err(RandBitError::LimitError(
                "Maximum number of concurrent sessions (256) exceeded".to_string(),
            ));
        }
        Ok(storage
            .entry(session_id)
            .or_insert(Arc::new(Mutex::new(RandBitStorage::empty())))
            .clone())
    }

    pub async fn drain_batch_recon_output(&mut self) -> Result<(), RandBitError> {
        loop {
            let id = {
                let mut rx = self.batch_output.lock().await;
                match rx.try_recv() {
                    Ok(id) => id,
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        return Err(RandBitError::Abort);
                    }
                }
            };

            let output = self.batch_recon.get_store(id).await?;
            match self.square_reconstruction_handler(id, output).await {
                Ok(()) => {}
                Err(e) => {
                    return Err(e);
                }
            }
        }
        Ok(())
    }
    pub async fn wait_for_result(
        &self,
        session_id: SessionId,
        duration: Duration,
    ) -> Result<Vec<RobustShare<F>>, RandBitError> {
        let output_receiver = {
            let storage = self.storage.lock().await;
            let storage_bind = match storage.get(&session_id) {
                Some(value) => value,
                None => return Err(RandBitError::NoSuchSessionId(session_id)),
            };
            let mut storage = storage_bind.lock().await;

            storage
                .output_receiver
                .take()
                .ok_or(RandBitError::ResultAlreadyReceived(session_id))?
        };

        match timeout(duration, output_receiver).await {
            Err(_) => Err(RandBitError::Timeout(session_id)),
            Ok(Err(_)) => Err(RandBitError::ReceiveError(session_id)),
            Ok(Ok(shares)) => Ok(shares),
        }
    }
    async fn try_finalize(&self, session_id: SessionId) -> Result<bool, RandBitError> {
        // ---- phase 1: decide + extract under lock ----
        let (a_share_array, a_square_array) = {
            let storage_bind = self.get_or_create_storage(session_id).await?;
            let storage = storage_bind.lock().await;

            if storage.protocol_state == ProtocolState::Finished {
                return Ok(true);
            }

            let Some(a_share_array) = storage.a_share.clone() else {
                // init not called yet
                return Ok(false);
            };

            let batch_size = a_share_array.len() / (self.threshold + 1);
            if storage.output_open.len() != batch_size {
                return Ok(false);
            }

            let a_square_array: Vec<F> = concat_sorted(&storage.output_open);
            (a_share_array, a_square_array)
        };

        // ---- phase 2: compute outside lock ----
        for a_square in &a_square_array {
            if *a_square == F::zero() {
                return Err(RandBitError::ZeroSquare);
            }
        }

        let mut b_inv_array = Vec::with_capacity(a_square_array.len());
        for a_square in &a_square_array {
            let b = a_square.sqrt().ok_or(RandBitError::SquareRoot)?;
            let b_inv = b.inverse().ok_or(RandBitError::Inverse)?;
            b_inv_array.push(b_inv);
        }

        let mut c_share_array = Vec::with_capacity(a_share_array.len());
        for (a_share, b_inv) in izip!(&a_share_array, &b_inv_array) {
            c_share_array.push(a_share.clone().mul(*b_inv)?);
        }

        let two_inv = (F::one() + F::one()).inverse().unwrap();
        let mut d_share_array = Vec::with_capacity(c_share_array.len());
        for c_share in &c_share_array {
            d_share_array.push(c_share.clone().add(F::one())?.mul(two_inv)?);
        }

        // ---- phase 3: commit + send under lock (once) ----
        let storage_bind = self.get_or_create_storage(session_id).await?;
        let mut storage = storage_bind.lock().await;

        if storage.protocol_state == ProtocolState::Finished {
            return Ok(true);
        }

        storage.protocol_state = ProtocolState::Finished;
        storage.protocol_output = Some(d_share_array.clone());

        let sender = storage.output_sender.take().unwrap();

        sender
            .send(d_share_array)
            .map_err(|_| RandBitError::SendError(session_id))?;

        Ok(true)
    }

    pub async fn init<N>(
        &mut self,
        a: Vec<RobustShare<F>>,
        mult_triple: Vec<ShamirBeaverTriple<F>>,
        session_id: SessionId,
        duration: Duration,
        network: Arc<N>,
    ) -> Result<(), RandBitError>
    where
        N: Network + Send + Sync + 'static,
    {
        if a.len() % (self.threshold + 1) != 0 {
            return Err(RandBitError::Incompatible);
        }

        // Multiply opens two BatchRecon sessions per (t + 1)-sized chunk using an 8-bit sub_id.
        // Keep RandBit batches below both the child session limit and the point where a single
        // multiplication round overwhelms the local network executor.
        if a.len() / (self.threshold + 1) > 64 {
            return Err(RandBitError::ShareLimitError(a.len()));
        }

        assert!(session_id.calling_protocol().is_some());
        assert_eq!(session_id.sub_id(), 0);
        assert_eq!(session_id.round_id(), 0);

        // Mark the protocol as initialized.
        {
            let storage_bind = self.get_or_create_storage(session_id).await?;
            let mut storage = storage_bind.lock().await;
            storage.protocol_state = ProtocolState::Initialized;
            storage.a_share = Some(a.clone());
        }
        if self.try_finalize(session_id).await? {
            return Ok(());
        }
        // Step 2: Execute the multiplication to obtain a^2 mod p.
        let a_copy = a.clone();
        self.mult_node
            .init(session_id, a, a_copy, mult_triple, network.clone())
            .await?;

        let a_square_share = self.mult_node.wait_for_result(session_id, duration).await?;

        tracing::info!("Multiplication at Rand_bit done: {0:?}", self.id);

        for (i, chunk) in a_square_share.chunks(self.threshold + 1).enumerate() {
            let session_id_batch = SessionId::new(
                session_id.calling_protocol().unwrap(),
                SessionId::pack_slot24(session_id.exec_id(), i as u8, 0),
                session_id.instance_id(),
            );
            self.batch_recon
                .init_batch_reconstruct(chunk, session_id_batch, network.clone())
                .await?;
        }

        Ok(())
    }

    async fn square_reconstruction_handler(
        &self,
        sid: SessionId,
        payload: Vec<u8>,
    ) -> Result<(), RandBitError> {
        tracing::info!(
            "Rand_bit reconstruction msg received at node: {0:?}",
            self.id
        );

        let calling_proto = match sid.calling_protocol() {
            Some(proto) => proto,
            None => {
                return Err(RandBitError::NoSuchSessionId(sid));
            }
        };

        let session_id = SessionId::new(
            calling_proto,
            SessionId::pack_slot24(sid.exec_id(), 0, 0),
            sid.instance_id(),
        );
        let storage_bind = self.get_or_create_storage(session_id).await?;
        let mut storage = storage_bind.lock().await;
        if storage.protocol_state == ProtocolState::Finished {
            return Ok(());
        }

        let open: Vec<F> = deser_bounded_vec(&mut payload.as_slice(), self.n_parties)?;
        let dealer_id = sid.sub_id();
        if storage.output_open.contains_key(&dealer_id) {
            return Err(RandBitError::Duplicate(format!(
                "Already received for {}",
                dealer_id
            )));
        }
        storage.output_open.insert(dealer_id, open);
        // If not initialized, data is stored but can't finalize yet.
        // init() will check for stored data and finalize if ready.
        if storage.a_share.is_none() {
            return Ok(());
        }
        drop(storage);
        let _done = self.try_finalize(session_id).await?;
        return Ok(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::rbc::rbc::Avid;
    use ark_bls12_381::Fr;

    #[tokio::test]
    async fn test_randbit_storage_limit() {
        let node = RandBit::<Fr, Avid<SessionId>>::new(0, 5, 1).unwrap();

        // Fill up storage to the limit (256 sessions)
        for i in 0u8..=255 {
            let session_id = SessionId::new(
                crate::honeybadger::ProtocolType::RandBit,
                SessionId::pack_slot24(i, 0, 0),
                111,
            );
            let _ = node.get_or_create_storage(session_id).await;
        }

        // The 257th session should fail
        let session_id = SessionId::new(
            crate::honeybadger::ProtocolType::RandBit,
            SessionId::pack_slot24(0, 1, 0),
            111,
        );
        let result = node.get_or_create_storage(session_id).await;
        assert!(
            matches!(result, Err(RandBitError::LimitError(_))),
            "Should error on exceeding storage limit"
        );
    }
}
