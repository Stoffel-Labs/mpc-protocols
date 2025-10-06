use crate::common::RBC;
use crate::honeybadger::batch_recon::batch_recon::BatchReconNode;
use crate::honeybadger::fpmul::{ProtocolState, RandBitError, RandBitMessage, RandBitStorage};
use crate::honeybadger::mul::multiplication::Multiply;
use crate::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use crate::honeybadger::triple_gen::ShamirBeaverTriple;
use crate::honeybadger::{ProtocolType, SessionId};
use ark_ff::FftField;
use ark_serialize::CanonicalDeserialize;
use itertools::izip;
use std::collections::HashMap;
use std::ops::{Add, Mul};
use std::sync::Arc;
use stoffelnet::network_utils::{Network, PartyId};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::Mutex;

/// Represents the random bit generation protocol.
///
/// # Output
///
/// If `t + 1` random elements are provided, then the protocol will return `t + 1` random bits. The
/// number of random elements is limited by the amount of shared elements that the batch
/// reconstruction protocol can reconstruct.
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
    /// Channel to send session ID of the current session once the protocol finishes its execution.
    pub output_channel: Sender<SessionId>,
    /// Node to execute a secure multiplication.
    pub mult_node: Multiply<F, R>,
    /// Channel to receive the session ID of the secure multiplication protocol.
    pub mult_output: Arc<Mutex<Receiver<SessionId>>>,
    /// Batch reconstruction node to reconstruct `a^2 mod p`.
    pub batch_recon: BatchReconNode<F>,
}

impl<F, R> RandBit<F, R>
where
    F: FftField,
    R: RBC,
{
    pub fn new(
        id: PartyId,
        n_parties: usize,
        threshold: usize,
        protocol_output: Sender<SessionId>,
        shared_mult_node: Multiply<F, R>,
        shared_mult_receiver: Arc<Mutex<Receiver<SessionId>>>,
    ) -> Result<Self, RandBitError> {
        let batch_recon_node = BatchReconNode::new(id, n_parties, threshold)?;

        Ok(Self {
            id,
            n_parties,
            threshold,
            storage: Arc::new(Mutex::new(HashMap::new())),
            output_channel: protocol_output,
            mult_node: shared_mult_node,
            mult_output: shared_mult_receiver,
            batch_recon: batch_recon_node,
        })
    }

    pub async fn get_or_crate_storage(
        &self,
        session_id: SessionId,
    ) -> Arc<Mutex<RandBitStorage<F>>> {
        let mut storage = self.storage.lock().await;
        storage
            .entry(session_id)
            .or_insert(Arc::new(Mutex::new(RandBitStorage::empty())))
            .clone()
    }

    pub async fn init<N>(
        &mut self,
        a: Vec<RobustShare<F>>,
        mult_triple: Vec<ShamirBeaverTriple<F>>,
        session_id: SessionId,
        network: Arc<N>,
    ) -> Result<(), RandBitError>
    where
        N: Network + Send + Sync + 'static,
    {
        // Mark the protocol as initialized.
        {
            let storage_bind = self.get_or_crate_storage(session_id).await;
            let mut storage = storage_bind.lock().await;
            storage.protocol_state = ProtocolState::Initialized;
            storage.a_share = Some(a.clone());
        }

        // Step 2: Execute the multiplication to obtain a^2 mod p.
        let a_copy = a.clone();
        let session_id_mult = SessionId::new(ProtocolType::Mul, 0, 0, session_id.instance_id());

        self.mult_node
            .init(session_id_mult, a, a_copy, mult_triple, network.clone())
            .await?;

        let a_square_share =
            if let Some(session_id_finished_mult) = self.mult_output.lock().await.recv().await {
                if session_id_finished_mult == session_id_mult {
                    self.mult_node
                        .mult_storage
                        .lock()
                        .await
                        .remove(&session_id_finished_mult)
                        .ok_or(RandBitError::SquareMult)?
                        .lock()
                        .await
                        .protocol_output
                        .clone()
                } else {
                    return Err(RandBitError::SquareMult);
                }
            } else {
                return Err(RandBitError::SquareMult);
            };

        self.batch_recon
            .init_batch_reconstruct(&a_square_share, session_id, network.clone())
            .await?;

        Ok(())
    }

    async fn square_reconstruction_handler(
        &self,
        message: RandBitMessage,
    ) -> Result<Vec<RobustShare<F>>, RandBitError> {
        tracing::info!(
            "Rand_bit reconstruction msg received from node: {0:?}",
            message.sender
        );

        let a_square_array: Vec<F> =
            CanonicalDeserialize::deserialize_compressed(message.payload.as_slice())?;

        // Step 4.
        for a_square in &a_square_array {
            if *a_square == F::zero() {
                return Err(RandBitError::ZeroSquare);
            }
        }

        // Step 5.
        let mut b_array = Vec::new();
        for a_square in &a_square_array {
            let b = a_square.sqrt().ok_or(RandBitError::SquareRoot)?;
            b_array.push(b);
        }

        // Step 6.
        let mut b_inv_array = Vec::new();
        for b in &b_array {
            let b_inv = b.inverse().ok_or(RandBitError::Inverse)?;
            b_inv_array.push(b_inv);
        }

        let a_share_array = self
            .get_or_crate_storage(message.session_id)
            .await
            .lock()
            .await
            .a_share
            .clone()
            .ok_or(RandBitError::NotInitialized)?;

        let mut c_share_array = Vec::new();
        for (a_share, b_inv) in izip!(&a_share_array, &b_inv_array) {
            let c_share = a_share.clone().mul(b_inv.clone())?;
            c_share_array.push(c_share);
        }

        // Step 7.
        // SAFETY: we can unwrap as the field cannot have characteristic 2.
        let two_inv = (F::one() + F::one()).inverse().unwrap();
        let mut d_share_array = Vec::new();
        for c_share in &c_share_array {
            let d = c_share.clone().add(F::one())?.mul(two_inv)?;
            d_share_array.push(d);
        }

        // Mark the protocol as finished.
        {
            let storage_bind = self.get_or_crate_storage(message.session_id).await;
            let mut storage = storage_bind.lock().await;
            storage.protocol_state = ProtocolState::Finished;
            storage.protocol_output = Some(d_share_array.clone());
        }

        // You send the current session ID as finished to the sender channel.
        self.output_channel.send(message.session_id).await?;

        Ok(d_share_array)
    }

    pub async fn process(&mut self, message: RandBitMessage) -> Result<(), RandBitError> {
        self.square_reconstruction_handler(message).await?;
        Ok(())
    }
}
