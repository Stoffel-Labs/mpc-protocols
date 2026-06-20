use super::*;
use crate::{
    common::{
        share::{apply_vandermonde, make_vandermonde},
        utils::deser_bounded_vec,
        SecretSharingScheme,
    },
    honeybadger::{robust_interpolate::robust_interpolate::RobustShare, WrappedMessage},
};
use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use futures::lock::Mutex;
use std::sync::Arc;
use std::{collections::HashMap, marker::PhantomData};
use stoffelnet::network_utils::Network;
use tokio::sync::mpsc::Sender;
use tracing::{debug, error, info, warn};

/// --------------------------BatchRecPub--------------------------
///
/// Goal: Publicly reconstruct t+1 secret-shared values [x₁, ..., x_{t+1}]
///       in a robust way, tolerating up to t faulty parties.
///
/// 1. Encode the secret shares into n public shares [y₁, ..., yₙ]
///    using a Vandermonde matrix.
///
/// 2. Each party sends its share yᵢ to all others (Round 1).
///
/// 3. Parties robustly interpolate the received y-values
///    to reconstruct the clear yᵢ, then broadcast them (Round 2).
///
/// 4. Using the reconstructed y-values, parties robustly
///    interpolate to recover the original secrets [x₁, ..., x_{t+1}].

#[derive(Clone, Debug)]
pub struct BatchReconNode<F: FftField> {
    pub id: usize, // This node's unique identifier
    pub n: usize,  // Total number of nodes/shares
    pub t: usize,
    pub degree: usize,
    pub store: Arc<Mutex<HashMap<SessionId, Arc<Mutex<BatchReconStore<F>>>>>>, // Number of malicious parties
    pub output_sender: Sender<SessionId>,
}

impl<F: FftField> BatchReconNode<F> {
    /// Creates a new `Node` instance.
    pub fn new(
        id: usize,
        n: usize,
        t: usize,
        degree: usize,
        output_sender: Sender<SessionId>,
    ) -> Result<Self, BatchReconError> {
        let store = Arc::new(Mutex::new(HashMap::new()));
        Ok(Self {
            id,
            n,
            t,
            degree,
            store,
            output_sender,
        })
    }

    pub async fn clear_entire_store(&self) {
        let mut store = self.store.lock().await;
        store.clear();
    }

    pub async fn clear_store(&self, session_id: SessionId) -> bool {
        let mut store = self.store.lock().await;
        store.remove(&session_id).is_some()
    }

    pub async fn store_len(&self) -> usize {
        self.store.lock().await.len()
    }

    pub async fn get_store(&self, session_id: SessionId) -> Result<Vec<u8>, BatchReconError> {
        let store = self.store.lock().await;

        let output_store = store.get(&session_id).ok_or_else(|| {
            BatchReconError::InvalidInput("Session ID does not exist".to_string())
        })?;

        let store_lock = output_store.lock().await;

        if store_lock.secrets.is_none() {
            return Err(BatchReconError::InvalidInput(
                "Batch reconstruction has not terminated".to_string(),
            ));
        }

        Ok(store_lock.secrets.clone().unwrap())
    }

    /// Initiates the batch reconstruction protocol for a given node.
    ///
    /// Each party computes its `y_j_share` for all `j` and sends it to party `P_j`.
    pub async fn init_batch_reconstruct<N: Network>(
        &self,
        shares: &[RobustShare<F>], // this party's shares of x_0 to x_t
        session_id: SessionId,
        net: Arc<N>,
    ) -> Result<(), BatchReconError> {
        if shares.len() < self.degree + 1 {
            return Err(BatchReconError::InvalidInput(
                "too little shares to start batch reconstruct".to_string(),
            ));
        }
        let vandermonde = make_vandermonde::<F>(self.n, self.degree)?;
        let y_shares = apply_vandermonde(&vandermonde, &shares[..(self.degree + 1)])?;

        info!(
            id = self.id,
            "initialized batch reconstruction with Vandermonde transform"
        );

        for (j, y_j_share) in y_shares.into_iter().enumerate() {
            info!(from = self.id, to = j, "Sending y_j shares ");

            let mut payload = Vec::new();
            y_j_share.share[0].serialize_compressed(&mut payload)?;
            let msg = BatchReconMsg::new(self.id, session_id, BatchReconMsgType::Eval, payload);
            //Wrap the msg in global enum
            let wrapped = WrappedMessage::BatchRecon(msg);
            //Send share y_j to each Party j
            let encoded_msg =
                bincode::serialize(&wrapped).map_err(BatchReconError::SerializationError)?;

            let _ = net.send(j, &encoded_msg).await?;
        }
        Ok(())
    }

    /// Initiates multiple independent batch reconstructions under one protocol session.
    ///
    /// `shares` is interpreted as consecutive chunks of `degree + 1` secrets. Each chunk uses the
    /// same Vandermonde transform as `init_batch_reconstruct`, but all evaluations for a recipient
    /// are sent in a single message and all reveals are broadcast in a single message.
    pub async fn init_batch_reconstruct_many<N: Network>(
        &self,
        shares: &[RobustShare<F>],
        session_id: SessionId,
        net: Arc<N>,
    ) -> Result<(), BatchReconError> {
        let batch_width = self.degree + 1;
        if shares.is_empty() || shares.len() % batch_width != 0 {
            return Err(BatchReconError::InvalidInput(
                "batched shares must be a non-empty multiple of degree + 1".to_string(),
            ));
        }

        let vandermonde = make_vandermonde::<F>(self.n, self.degree)?;
        let mut y_shares_by_recipient = vec![Vec::new(); self.n];

        for chunk in shares.chunks_exact(batch_width) {
            let y_shares = apply_vandermonde(&vandermonde, chunk)?;
            for (recipient, y_j_share) in y_shares.into_iter().enumerate() {
                y_shares_by_recipient[recipient].push(y_j_share.share[0]);
            }
        }

        info!(
            id = self.id,
            groups = shares.len() / batch_width,
            "initialized batched batch reconstruction with Vandermonde transform"
        );

        for (j, values) in y_shares_by_recipient.into_iter().enumerate() {
            let mut payload = Vec::new();
            values.serialize_compressed(&mut payload)?;
            let msg =
                BatchReconMsg::new(self.id, session_id, BatchReconMsgType::EvalBatch, payload);
            let wrapped = WrappedMessage::BatchRecon(msg);
            let encoded_msg =
                bincode::serialize(&wrapped).map_err(BatchReconError::SerializationError)?;

            let _ = net.send(j, &encoded_msg).await?;
        }
        Ok(())
    }

    /// Handles incoming `Msg`s for the batch reconstruction protocol.
    ///
    /// This function processes `Eval` messages (first round) and `Reveal` messages (second round)
    /// to collectively reconstruct the original secrets.
    pub async fn batch_recon_handler<N: Network>(
        &mut self,
        msg: BatchReconMsg,
        net: Arc<N>,
    ) -> Result<(), BatchReconError> {
        match msg.msg_type {
            BatchReconMsgType::Eval => {
                debug!(
                    self_id = self.id,
                    from = msg.sender_id,
                    "Received Eval message"
                );
                let sender_id = msg.sender_id;
                let val = F::deserialize_compressed(msg.payload.as_slice())
                    .map_err(|e| BatchReconError::ArkDeserialization(e))?;

                // Lock the session store to update the session state.
                let Some(session_store) = self.get_or_create_store(msg.session_id).await? else {
                    return Ok(()); // late message for an already-terminated session — dropped
                };
                // Lock the session-specific store to access or update the session state.
                let mut store = session_store.lock().await;

                // Store the received evaluation share if it's from a new sender.
                if !store.evals_received.iter().any(|s| s.id == sender_id) {
                    store
                        .evals_received
                        .push(RobustShare::new(val, sender_id, self.degree));
                }
                // Check if we have enough evaluation shares and haven't already computed our `y_j`.
                if store.evals_received.len() >= self.degree + self.t + 1 && store.y_j.is_none() {
                    info!(
                        self_id = self.id,
                        "Enough Evals collected, interpolating y_j"
                    );

                    // Attempt to interpolate the polynomial and get our specific `y_j` value.
                    match RobustShare::recover_secret(&store.evals_received, self.n, self.t) {
                        Ok((_, value)) => {
                            store.y_j = Some(RobustShare {
                                share: [value],
                                id: self.id,
                                degree: self.degree,
                                _sharetype: PhantomData,
                            });
                            drop(store);
                            info!(node = self.id, "Broadcasting y_j value: {:?}", value);

                            let mut payload = Vec::new();
                            value
                                .serialize_compressed(&mut payload)
                                .map_err(|e| BatchReconError::ArkSerialization(e))?;
                            let new_msg = BatchReconMsg::new(
                                self.id,
                                msg.session_id,
                                BatchReconMsgType::Reveal,
                                payload,
                            );

                            //Wrap the msg in global enum
                            let wrapped = WrappedMessage::BatchRecon(new_msg);
                            // Broadcast our computed `y_j` to all other parties.
                            let encoded = bincode::serialize(&wrapped)
                                .map_err(BatchReconError::SerializationError)?;
                            let _ = net
                                .broadcast(&encoded)
                                .await
                                .map_err(|e| BatchReconError::NetworkError(e))?;
                        }
                        Err(e) => {
                            warn!(self_id = self.id, "Interpolation of y_j failed: {:?}", e);
                            return Err(BatchReconError::InterpolateError(e));
                        }
                    }
                }
                Ok(())
            }
            BatchReconMsgType::Reveal => {
                debug!(
                    self_id = self.id,
                    from = msg.sender_id,
                    "Received Reveal message"
                );
                let sender_id = msg.sender_id;
                let y_j = F::deserialize_compressed(msg.payload.as_slice())
                    .map_err(|e| BatchReconError::ArkDeserialization(e))?;

                // Lock the session store to update the session state.
                let Some(session_store) = self.get_or_create_store(msg.session_id).await? else {
                    return Ok(()); // late message for an already-terminated session — dropped
                };
                // Lock the session-specific store to access or update the session state.
                let mut store = session_store.lock().await;

                // Store the received revealed `y_j` value if it's from a new sender.
                if !store.reveals_received.iter().any(|s| s.id == sender_id) {
                    store
                        .reveals_received
                        .push(RobustShare::new(y_j, sender_id, self.degree));
                }
                // Check if we have enough revealed `y_j` values and haven't already reconstructed the secrets.
                if store.reveals_received.len() >= self.degree + self.t + 1
                    && store.secrets.is_none()
                {
                    info!(
                        self_id = self.id,
                        "Enough Reveals collected, interpolating secrets"
                    );
                    // Attempt to interpolate the polynomial whose coefficients are the original secrets.
                    match RobustShare::recover_secret(&store.reveals_received, self.n, self.t) {
                        Ok((poly, _)) => {
                            let mut result = poly;
                            // Resize the coefficient vector to `t + 1` to get all secrets.
                            result.resize(self.degree + 1, F::zero());
                            let mut bytes_message = Vec::new();
                            result.serialize_compressed(&mut bytes_message)?;

                            store.secrets = Some(bytes_message);
                            drop(store);
                            info!(self_id = self.id, "Secrets successfully reconstructed");

                            self.output_sender
                                .send(msg.session_id)
                                .await
                                .map_err(|_| BatchReconError::SendError)?;
                        }
                        Err(e) => {
                            error!(
                                self_id = self.id, error = ?e,
                                "Final secrets interpolation failed "
                            );
                            return Err(BatchReconError::InterpolateError(e));
                        }
                    }
                }
                Ok(())
            }
            BatchReconMsgType::EvalBatch => {
                debug!(
                    self_id = self.id,
                    from = msg.sender_id,
                    "Received EvalBatch message"
                );
                let sender_id = msg.sender_id;
                let values = deser_bounded_vec(&mut msg.payload.as_slice(), msg.payload.len())
                    .map_err(BatchReconError::ArkDeserialization)?;

                if values.is_empty() {
                    return Err(BatchReconError::InvalidInput(
                        "empty EvalBatch payload".to_string(),
                    ));
                }

                let Some(session_store) = self.get_or_create_store(msg.session_id).await? else {
                    return Ok(()); // late message for an already-terminated session — dropped
                };
                let mut store = session_store.lock().await;

                if let Some((_, existing)) = store.batch_evals_received.first() {
                    if existing.len() != values.len() {
                        return Err(BatchReconError::InvalidInput(
                            "inconsistent EvalBatch width".to_string(),
                        ));
                    }
                }

                if !store
                    .batch_evals_received
                    .iter()
                    .any(|(id, _)| *id == sender_id)
                {
                    store.batch_evals_received.push((sender_id, values));
                }

                if store.batch_evals_received.len() >= self.degree + self.t + 1
                    && store.y_j_batch.is_none()
                {
                    let batch_len = store.batch_evals_received[0].1.len();
                    let evals_by_sender = store.batch_evals_received.clone();
                    let mut y_j_values = Vec::with_capacity(batch_len);

                    for idx in 0..batch_len {
                        let shares: Vec<_> = evals_by_sender
                            .iter()
                            .map(|(sender_id, vals)| {
                                RobustShare::new(vals[idx], *sender_id, self.degree)
                            })
                            .collect();
                        let (_, value) = RobustShare::recover_secret(&shares, self.n, self.t)?;
                        y_j_values.push(value);
                    }

                    store.y_j_batch = Some(y_j_values.clone());
                    drop(store);

                    let mut payload = Vec::new();
                    y_j_values.serialize_compressed(&mut payload)?;
                    let new_msg = BatchReconMsg::new(
                        self.id,
                        msg.session_id,
                        BatchReconMsgType::RevealBatch,
                        payload,
                    );

                    let wrapped = WrappedMessage::BatchRecon(new_msg);
                    let encoded = bincode::serialize(&wrapped)
                        .map_err(BatchReconError::SerializationError)?;
                    let _ = net.broadcast(&encoded).await?;
                }
                Ok(())
            }
            BatchReconMsgType::RevealBatch => {
                debug!(
                    self_id = self.id,
                    from = msg.sender_id,
                    "Received RevealBatch message"
                );
                let sender_id = msg.sender_id;
                let values = Vec::<F>::deserialize_compressed(msg.payload.as_slice())
                    .map_err(BatchReconError::ArkDeserialization)?;

                if values.is_empty() {
                    return Err(BatchReconError::InvalidInput(
                        "empty RevealBatch payload".to_string(),
                    ));
                }

                let Some(session_store) = self.get_or_create_store(msg.session_id).await? else {
                    return Ok(()); // late message for an already-terminated session — dropped
                };
                let mut store = session_store.lock().await;

                if let Some((_, existing)) = store.batch_reveals_received.first() {
                    if existing.len() != values.len() {
                        return Err(BatchReconError::InvalidInput(
                            "inconsistent RevealBatch width".to_string(),
                        ));
                    }
                }

                if !store
                    .batch_reveals_received
                    .iter()
                    .any(|(id, _)| *id == sender_id)
                {
                    store.batch_reveals_received.push((sender_id, values));
                }

                if store.batch_reveals_received.len() >= self.degree + self.t + 1
                    && store.secrets.is_none()
                {
                    let batch_len = store.batch_reveals_received[0].1.len();
                    let reveals_by_sender = store.batch_reveals_received.clone();
                    let mut result = Vec::with_capacity(batch_len * (self.degree + 1));

                    for idx in 0..batch_len {
                        let shares: Vec<_> = reveals_by_sender
                            .iter()
                            .map(|(sender_id, vals)| {
                                RobustShare::new(vals[idx], *sender_id, self.degree)
                            })
                            .collect();
                        let (mut poly, _) = RobustShare::recover_secret(&shares, self.n, self.t)?;
                        poly.resize(self.degree + 1, F::zero());
                        result.extend(poly);
                    }

                    let mut bytes_message = Vec::new();
                    result.serialize_compressed(&mut bytes_message)?;

                    store.secrets = Some(bytes_message);
                    drop(store);

                    self.output_sender
                        .send(msg.session_id)
                        .await
                        .map_err(|_| BatchReconError::SendError)?;
                }
                Ok(())
            }
        }
    }
    pub async fn process<N: Network>(
        &mut self,
        msg: BatchReconMsg,
        net: Arc<N>,
    ) -> Result<(), BatchReconError> {
        self.batch_recon_handler(msg, net).await?;
        Ok(())
    }

    pub async fn get_or_create_store(
        &self,
        session_id: SessionId,
    ) -> Result<Option<Arc<Mutex<BatchReconStore<F>>>>, BatchReconError> {
        let store_lock = {
            let mut storage = self.store.lock().await;

            storage
                .entry(session_id)
                .or_insert_with(|| Arc::new(Mutex::new(BatchReconStore::empty())))
                .clone()
        };

        {
            let store_guard = store_lock.lock().await;
            if store_guard.secrets.is_some() {
                // Session already terminated: this is a late/duplicate message. Drop it — the
                // reconstructed secrets are final, so a redundant message cannot change the result.
                // Restores liveness that the hard-error path removed; does not alter reconstruction
                // correctness or t-fault tolerance. (Wrapping/ID-reuse replay is a separate concern.)
                debug!(
                    self_id = self.id,
                    ?session_id,
                    "dropping late message for already-terminated batch-recon session"
                );
                return Ok(None);
            }
        }

        Ok(Some(store_lock))
    }
}
