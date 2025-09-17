use crate::common::SecretSharingScheme;
use crate::honeybadger::output::{OutputError, OutputMessage};
use crate::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use crate::honeybadger::WrappedMessage;
use ark_ff::FftField;
use ark_serialize::CanonicalSerialize;
use std::collections::HashMap;
use std::sync::Arc;
use stoffelnet::network_utils::Network;
use tokio::sync::Mutex;
use tracing::info;

#[derive(Clone, Debug)]
pub struct OutputServer {
    pub id: usize,
    pub n: usize,
}

impl OutputServer {
    pub fn new(id: usize, n: usize) -> Result<Self, OutputError> {
        Ok(Self { id, n })
    }

    /// Called by each server to send its share of `r_i` to the client.
    pub async fn init<N: Network, F: FftField>(
        &self,
        client_id: usize,
        shares: Vec<RobustShare<F>>,
        input_len: usize,
        net: Arc<N>,
    ) -> Result<(), OutputError> {
        if shares.len() != input_len {
            return Err(OutputError::InvalidInput(
                "Incorrect number of shares".to_string(),
            ));
        }

        let mut payload = Vec::new();
        shares.serialize_compressed(&mut payload)?;
        let msg = OutputMessage::new(self.id, payload);
        let wrapped = WrappedMessage::Output(msg);
        let bytes = bincode::serialize(&wrapped)?;

        //Send to the client
        net.send_to_client(client_id, &bytes).await?;
        info!(
            "Server {} sent output share to client {}",
            self.id, client_id
        );

        Ok(())
    }
}
pub struct OutputClient<F: FftField> {
    pub client_id: usize,
    pub n: usize,
    pub t: usize,
    pub input_len: usize,
    pub output: Option<F>,
    pub output_shares: Arc<Mutex<HashMap<usize, Vec<RobustShare<F>>>>>,
}

impl<F: FftField> OutputClient<F> {
    pub fn new(id: usize, n: usize, t: usize, input_len: usize) -> Result<Self, OutputError> {
        Ok(Self {
            client_id: id,
            n,
            t,
            input_len,
            output: None,
            output_shares: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub async fn output_handler(&mut self, msg: OutputMessage) -> Result<(), OutputError> {
        let shares: Vec<RobustShare<F>> =
            ark_serialize::CanonicalDeserialize::deserialize_compressed(msg.payload.as_slice())?;

        if shares.len() != self.input_len {
            return Err(OutputError::InvalidInput(
                "Mismatch in input and share length".to_string(),
            ));
        }

        let mut share_store = self.output_shares.lock().await;
        if share_store.contains_key(&msg.sender_id) {
            return Err(OutputError::Duplicate(format!(
                "Already received from {}",
                msg.sender_id
            )));
        }
        share_store.insert(msg.sender_id, shares.clone());
        info!("Received Output share from server {}", msg.sender_id);

        let mut r_shares = vec![vec![]; self.input_len];
        if share_store.len() >= 2 * self.t + 1 {
            info!("Received enough shares to reconstruct");
            for (_, r_share) in share_store.iter() {
                for i in 0..self.input_len {
                    r_shares[i].push(r_share[i].clone());
                }
            }

            for output in r_shares {
                let secret = RobustShare::recover_secret(&output, self.n)?;
                self.output = Some(secret.1);
            }
        }
        Ok(())
    }

    /// Process any message (used for both client and server roles).
    pub async fn process(&mut self, msg: OutputMessage) -> Result<(), OutputError> {
        self.output_handler(msg).await?;
        Ok(())
    }
}
