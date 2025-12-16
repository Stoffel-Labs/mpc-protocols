use super::*;
use crate::{
    common::{
        share::{apply_vandermonde, make_vandermonde},
        SecretSharingScheme,
    },
    honeybadger::{
        fpmul::{PRandBitDMessage, PRandMessageType, RandBitMessage},
        mul::MultMessage,
        robust_interpolate::robust_interpolate::RobustShare,
        triple_gen::TripleGenMessage,
        ProtocolType, WrappedMessage,
    },
};
use ark_ff::FftField;
use ark_serialize::CanonicalSerialize;
use futures::lock::Mutex;
use std::sync::Arc;
use std::{collections::HashMap, marker::PhantomData};
use stoffelnet::network_utils::Network;
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
    pub store: Arc<Mutex<HashMap<SessionId, Arc<Mutex<BatchReconStore<F>>>>>>, // Number of malicious parties
}

impl<F: FftField> BatchReconNode<F> {
    /// Creates a new `Node` instance.
    pub fn new(id: usize, n: usize, t: usize) -> Result<Self, BatchReconError> {
        let store = Arc::new(Mutex::new(HashMap::new()));
        Ok(Self { id, n, t, store })
    }

    pub async fn clear_entire_store(&self) {
        let mut store = self.store.lock().await;
        store.clear();
    }

    pub async fn clear_store(&self, session_id: SessionId) -> bool {
        let mut store = self.store.lock().await;
        store.remove(&session_id).is_some()
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
        if shares.len() < self.t + 1 {
            return Err(BatchReconError::InvalidInput(
                "too little shares to start batch reconstruct".to_string(),
            ));
        }
        let vandermonde = make_vandermonde::<F>(self.n, self.t)?;
        let y_shares = apply_vandermonde(&vandermonde, &shares[..(self.t + 1)])?;

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

    /// Handles incoming `Msg`s for the batch reconstruction protocol.
    ///
    /// This function processes `Eval` messages (first round) and `Reveal` messages (second round)
    /// to collectively reconstruct the original secrets.
    pub async fn batch_recon_handler<N: Network>(
        &mut self,
        msg: BatchReconMsg,
        net: Arc<N>,
    ) -> Result<(), BatchReconError> {
        let calling_proto = match msg.session_id.calling_protocol() {
            Some(proto) => proto,
            None => {
                return Err(BatchReconError::InvalidInput(
                    "Unknown calling protocol".to_string(),
                ));
            }
        };

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
                let session_store = self.get_or_create_store(msg.session_id).await;
                // Lock the session-specific store to access or update the session state.
                let mut store = session_store.lock().await;

                // Store the received evaluation share if it's from a new sender.
                if !store.evals_received.iter().any(|s| s.id == sender_id) {
                    store
                        .evals_received
                        .push(RobustShare::new(val, sender_id, self.t));
                }
                // Check if we have enough evaluation shares and haven't already computed our `y_j`.
                if store.evals_received.len() >= 2 * self.t + 1 && store.y_j.is_none() {
                    info!(
                        self_id = self.id,
                        "Enough Evals collected, interpolating y_j"
                    );

                    // Attempt to interpolate the polynomial and get our specific `y_j` value.
                    match RobustShare::recover_secret(&store.evals_received, self.n) {
                        Ok((_, value)) => {
                            store.y_j = Some(RobustShare {
                                share: [value],
                                id: self.id,
                                degree: self.t,
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
                let session_store = self.get_or_create_store(msg.session_id).await;
                // Lock the session-specific store to access or update the session state.
                let mut store = session_store.lock().await;

                // Store the received revealed `y_j` value if it's from a new sender.
                if !store.reveals_received.iter().any(|s| s.id == sender_id) {
                    store
                        .reveals_received
                        .push(RobustShare::new(y_j, sender_id, self.t));
                }
                // Check if we have enough revealed `y_j` values and haven't already reconstructed the secrets.
                if store.reveals_received.len() >= 2 * self.t + 1 && store.secrets.is_none() {
                    info!(
                        self_id = self.id,
                        "Enough Reveals collected, interpolating secrets"
                    );
                    // Attempt to interpolate the polynomial whose coefficients are the original secrets.
                    match RobustShare::recover_secret(&store.reveals_received, self.n) {
                        Ok((poly, _)) => {
                            let mut result = poly;
                            // Resize the coefficient vector to `t + 1` to get all secrets.
                            result.resize(self.t + 1, F::zero());
                            store.secrets = Some(result.clone());
                            info!(self_id = self.id, "Secrets successfully reconstructed");

                            // Send the finalization message back to the triple generation or the
                            // multiplication protocol.
                            match calling_proto {
                                ProtocolType::Triple => {
                                    let mut bytes_message = Vec::new();
                                    result.serialize_compressed(&mut bytes_message)?;
                                    let triple_gen_generic_msg =
                                        WrappedMessage::Triple(TripleGenMessage::new(
                                            self.id,
                                            msg.session_id,
                                            bytes_message,
                                        ));
                                    let bytes_generic_msg =
                                        bincode::serialize(&triple_gen_generic_msg)?;
                                    net.send(self.id, &bytes_generic_msg).await?;
                                }
                                ProtocolType::Mul | ProtocolType::FpMul => {
                                    let mut bytes_message = Vec::new();
                                    result.serialize_compressed(&mut bytes_message)?;
                                    let mult_generic_msg = WrappedMessage::Mul(MultMessage::new(
                                        self.id,
                                        msg.session_id,
                                        bytes_message,
                                    ));
                                    let bytes_generic_msg = bincode::serialize(&mult_generic_msg)?;
                                    net.send(self.id, &bytes_generic_msg).await?;
                                }
                                ProtocolType::RandBit => {
                                    let mut bytes_message = Vec::new();
                                    result.serialize_compressed(&mut bytes_message)?;
                                    if msg.session_id.sub_id() == 0 {
                                        let rand_generic_msg =
                                            WrappedMessage::RandBit(RandBitMessage::new(
                                                self.id,
                                                msg.session_id,
                                                bytes_message,
                                            ));
                                        let bytes_generic_msg =
                                            bincode::serialize(&rand_generic_msg)?;
                                        net.send(self.id, &bytes_generic_msg).await?;
                                    } else {
                                        let mult_generic_msg =
                                            WrappedMessage::Mul(MultMessage::new(
                                                self.id,
                                                msg.session_id,
                                                bytes_message,
                                            ));
                                        let bytes_generic_msg =
                                            bincode::serialize(&mult_generic_msg)?;
                                        net.send(self.id, &bytes_generic_msg).await?;
                                    }
                                }
                                ProtocolType::PRandBit => {
                                    let mut bytes_message = Vec::new();
                                    result.serialize_compressed(&mut bytes_message)?;
                                    let mult_generic_msg =
                                        WrappedMessage::PRandBit(PRandBitDMessage::new(
                                            self.id,
                                            PRandMessageType::OutputMessage,
                                            msg.session_id,
                                            vec![],
                                            vec![],
                                            bytes_message,
                                        ));
                                    let bytes_generic_msg = bincode::serialize(&mult_generic_msg)?;
                                    net.send(self.id, &bytes_generic_msg).await?;
                                }
                                _ => return Ok(()),
                            }
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
    ) -> Arc<Mutex<BatchReconStore<F>>> {
        let mut storage = self.store.lock().await;
        storage
            .entry(session_id)
            .or_insert(Arc::new(Mutex::new(BatchReconStore::empty())))
            .clone()
    }
}
