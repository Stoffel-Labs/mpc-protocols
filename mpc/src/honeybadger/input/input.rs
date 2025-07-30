use crate::common::{SecretSharingScheme, RBC};
use crate::honeybadger::input::InputMessage;
use crate::honeybadger::input::{InputError, InputMessageType};
use crate::honeybadger::robust_interpolate::robust_interpolate::RobustShamirShare;
use crate::honeybadger::WrappedMessage;
use ark_ff::FftField;
use ark_serialize::CanonicalSerialize;
use std::collections::HashMap;
use std::sync::Arc;
use stoffelmpc_network::Network;
use tokio::sync::Mutex;

pub struct Input<F: FftField, R: RBC> {
    pub id: usize,
    pub n_parties: usize,
    pub rbc: R,
    /// For each input index, the local share of r_i
    pub local_mask_shares: Arc<Mutex<HashMap<usize, Vec<RobustShamirShare<F>>>>>,
    /// For each input index, the result: share of m_i
    pub input_shares: Arc<Mutex<HashMap<usize, Vec<RobustShamirShare<F>>>>>,
}

impl<F: FftField, R: RBC> Input<F, R> {
    pub fn new(id: usize, n_parties: usize, t: usize) -> Result<Self, InputError> {
        let rbc = RBC::new(id, n_parties, t, t + 1)?;
        Ok(Self {
            id,
            n_parties,
            rbc,
            local_mask_shares: Arc::new(Mutex::new(HashMap::new())),
            input_shares: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Called by each server to send its share of `r_i` to the client.
    pub async fn init<N: Network>(
        &self,
        client_id: usize,
        shares: Vec<RobustShamirShare<F>>,
        input_len: usize,
        net: Arc<N>,
    ) -> Result<(), InputError> {
        if shares.len() != input_len {
            return Err(InputError::InvalidInput(
                "Incorrect number of shares".to_string(),
            ));
        }
        //Store the local shares
        {
            let mut share_store = self.local_mask_shares.lock().await;
            share_store.insert(client_id, shares.clone());
        }
        let mut payload = Vec::new();
        shares
            .serialize_compressed(&mut payload)
            .map_err(InputError::ArkSerialization)?;
        let msg = InputMessage::new(self.id, InputMessageType::MaskShare, payload);
        //wrap it in protocol wide enum
        let wrapped = WrappedMessage::Input(msg);
        let bytes = bincode::serialize(&wrapped).map_err(InputError::SerializationError)?;
        //Send to the client
        net.send(client_id, &bytes)
            .await
            .map_err(InputError::NetworkError)?;

        Ok(())
    }

    /// Called by each server: receives masked m_i, subtracts r_i to get share of m_i.
    pub async fn input_handler(&mut self, msg: InputMessage) -> Result<(), InputError> {
        //handler for server
        //accepts the m+r values and then subtracts the r' local share from it to get m' shares
        // and stores it
        let masked_input: Vec<F> =
            ark_serialize::CanonicalDeserialize::deserialize_compressed(msg.payload.as_slice())
                .map_err(InputError::ArkDeserialization)?;
        let local_share_store = self.local_mask_shares.lock().await;
        let local_shares = match local_share_store.get(&msg.sender_id) {
            Some(s) => s,
            None => {
                return Err(InputError::InvalidInput(
                    "local shares not available".to_string(),
                ))
            }
        };
        let input_shares: Vec<RobustShamirShare<F>> = masked_input
            .iter()
            .zip(local_shares)
            .map(|(a, b)| RobustShamirShare::new(*a - b.share[0], b.id, b.degree))
            .collect();
        drop(local_share_store); // release lock early
        let mut input_store = self.input_shares.lock().await;
        input_store.insert(msg.sender_id, input_shares);
        Ok(())
    }

    /// Process any message (used for both client and server roles).
    pub async fn process<N: Network + Send + Sync>(
        &mut self,
        msg: InputMessage,
    ) -> Result<(), InputError> {
        match msg.msg_type {
            InputMessageType::MaskShare => {
                return Err(InputError::InvalidInput(
                    "Incorrect message type".to_string(),
                ))
            }
            InputMessageType::MaskedInput => self.input_handler(msg).await,
        }
    }
}

pub struct InputClient<F: FftField, R: RBC> {
    pub client_id: usize,
    pub n: usize,
    pub t: usize,
    pub rbc: R,
    pub inputs: Arc<Mutex<Vec<F>>>,
    pub received_shares: Arc<Mutex<HashMap<usize, Vec<RobustShamirShare<F>>>>>,
}

impl<F: FftField, R: RBC> InputClient<F, R> {
    pub fn new(id: usize, n: usize, t: usize, inputs: Vec<F>) -> Result<Self, InputError> {
        let rbc = RBC::new(id, n, t, t + 1)?;
        Ok(Self {
            client_id: id,
            n,
            t,
            rbc,
            inputs: Arc::new(Mutex::new(inputs)),
            received_shares: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub async fn init_handler<N: Network + Send + Sync>(
        &self,
        msg: InputMessage,
        net: Arc<N>,
    ) -> Result<(), InputError> {
        let shares: Vec<RobustShamirShare<F>> =
            ark_serialize::CanonicalDeserialize::deserialize_compressed(msg.payload.as_slice())
                .map_err(InputError::ArkDeserialization)?;
        let inputs = self.inputs.lock().await;
        let input_len = inputs.len();
        drop(inputs);
        if shares.len() != input_len {
            return Err(InputError::InvalidInput(
                "Mismatch in input and share length".to_string(),
            ));
        }
        let mut share_store = self.received_shares.lock().await;
        if share_store.contains_key(&msg.sender_id) {
            return Err(InputError::Duplicate(format!(
                "Already received from {}",
                msg.sender_id
            )));
        }
        share_store.insert(msg.sender_id, shares.clone());
        let mut r_shares = vec![vec![]; input_len];
        let mut masks = vec![];
        let mut output = vec![];
        if share_store.len() >= 2 * self.t + 1 {
            for (_, r_share) in share_store.iter() {
                for i in 0..input_len {
                    r_shares[i].push(r_share[i].clone());
                }
            }
        }
        for recon in r_shares {
            let secret = RobustShamirShare::recover_secret(&recon)
                .map_err(|e| InputError::InterpolateError(e))?;
            masks.push(secret.1);
        }
        let inputs = self.inputs.lock().await;
        for (i, r) in masks.iter().enumerate() {
            output.push(inputs[i] + r);
        }

        let mut payload = Vec::new();
        output
            .serialize_compressed(&mut payload)
            .map_err(InputError::ArkSerialization)?;
        let msg = InputMessage::new(self.client_id, InputMessageType::MaskedInput, payload);
        //wrap it in protocol wide enum
        let wrapped = WrappedMessage::Input(msg);
        let bytes = bincode::serialize(&wrapped).map_err(InputError::SerializationError)?;
        //Broadcast to servers
        self.rbc.init(bytes, self.client_id, net).await?;
        Ok(())
    }

    /// Process any message (used for both client and server roles).
    pub async fn process<N: Network + Send + Sync>(
        &mut self,
        msg: InputMessage,
        net: Arc<N>,
    ) -> Result<(), InputError> {
        match msg.msg_type {
            InputMessageType::MaskedInput => {
                return Err(InputError::InvalidInput(
                    "Incorrect message type".to_string(),
                ))
            }
            InputMessageType::MaskShare => self.init_handler(msg, net).await,
        }
    }
}
