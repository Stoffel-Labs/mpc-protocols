use crate::common::SecretSharingScheme;
use crate::honeybadger::output::{OutputError, OutputMessage};
use crate::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use crate::honeybadger::WrappedMessage;
use ark_ff::FftField;
use ark_serialize::CanonicalSerialize;
use std::collections::HashMap;
use std::sync::Arc;
use stoffelnet::network_utils::Network;
use tokio::sync::{watch::{channel, Sender, Receiver}};
use tokio::time::{Duration, timeout};
use tracing::info;

/// Conveys the output to the clients. This happens by each node sending their output shares
/// to the desired client, which then reconstructs the output using robust interpolation.
/// `OutputServer` is the server-side component, which sends shares to the client.
/// `OutputClient` is the client-side component, which collects shares and reconstructs the output.
/// Each client has their own `OutputClient` and `OutputServer::init` is called once per client
/// with the shares intended for that client, so sending different outputs to different clients is
/// supported.
///
/// To make waiting for output and checking its availability thread-safe, the `tokio::sync::watch`
/// primitive is used for synchronization.

#[derive(Clone, Debug)]
pub struct OutputServer {
    pub id: usize,
    pub n: usize,
}

impl OutputServer {
    pub fn new(id: usize, n: usize) -> Result<Self, OutputError> {
        Ok(Self { id, n })
    }

    /// Called by each server to send its output shares to the client.
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

        net.send_to_client(client_id, &bytes).await?;
        info!(
            "Server {} sent output share to client {}",
            self.id, client_id
        );

        Ok(())
    }
}

pub struct OutputClientData<F: FftField> {
    pub output: Option<Vec<F>>,
    pub output_shares: HashMap<usize, Vec<RobustShare<F>>>,
}

#[derive(Clone)]
pub struct OutputClient<F: FftField> {
    pub client_id: usize,
    pub n: usize,
    pub t: usize,
    pub input_len: usize,
    output_sender: Sender<OutputClientData<F>>,
    output_receiver: Receiver<OutputClientData<F>>
}

impl<F: FftField> OutputClient<F> {
    pub fn new(id: usize, n: usize, t: usize, input_len: usize) -> Result<Self, OutputError> {
        let (output_sender, output_receiver) = channel(
            OutputClientData::<F> {
                output: None,
                output_shares: HashMap::new()
            }
        );

        Ok(Self {
            client_id: id,
            n,
            t,
            input_len,
            output_sender, output_receiver
        })
    }

    /// Handles shares sent by a node to this client.
    ///
    /// 1. Parse the received message into shares and check if the length matches.
    /// 2. Return if shares from this sender have already been received. This means that the sender
    ///    is not honest assuming that sender IDs are authenticated.
    /// 3. Add the received shares.
    /// 4. If the output has not been reconstructed yet and enough shares have been received,
    ///    attempt to reconstruct the output using robust interpolation.
    pub async fn output_handler(&mut self, msg: OutputMessage) -> Result<(), OutputError> {
        // 1.
        let shares: Vec<RobustShare<F>> =
            ark_serialize::CanonicalDeserialize::deserialize_compressed(msg.payload.as_slice())?;

        if shares.len() != self.input_len {
            return Err(OutputError::InvalidInput(
                "Mismatch in input and share length".to_string(),
            ));
        }

        let mut already_recvd = false;
        let mut recovery_err = None;

        self.output_sender.send_if_modified(|output_data| {
            let share_store = &mut output_data.output_shares;

            // 2.
            if share_store.contains_key(&msg.sender_id) {
                already_recvd = true;
                return false;
            }
            // 3.
            share_store.insert(msg.sender_id, shares.clone());
            info!("Received Output share from server {}", msg.sender_id);

            let mut r_shares = vec![vec![]; self.input_len];
            // 4.
            if output_data.output.is_none() && share_store.len() >= 2 * self.t + 1 {
                info!("Received enough shares to reconstruct");
                for (_, r_share) in share_store.iter() {
                    for i in 0..self.input_len {
                        r_shares[i].push(r_share[i].clone());
                    }
                }

                let mut output = Vec::new();

                for output_elem in r_shares {
                    let secret = match RobustShare::recover_secret(&output_elem, self.n) {
                        Ok(secret) => secret,
                        Err(e) => {
                            recovery_err = Some(e);
                            return false;
                        }
                    };
                    output.push(secret.1);
                }
                output_data.output = Some(output);
                return true;
            }

            false
        });
        
        if already_recvd {
            return Err(OutputError::Duplicate(format!(
                "Already received from {}",
                msg.sender_id
            )));
        }
        if let Some(err) = recovery_err {
            return Err(OutputError::InterpolateError(err));
        }

        Ok(())
    }

    /// Waits for the output to be reconstructed. If this does not happen within the specified
    /// duration, it returns before.
    pub async fn wait_for_output(&mut self, duration: Duration) -> Result<Vec<F>, OutputError> {
        let output_future = self.output_receiver.wait_for(|output_data| {
            output_data.output.is_some()
        });

        match timeout(duration, output_future).await {
            Err(elapsed_err) => Err(OutputError::Timeout(elapsed_err)),
            Ok(Err(recv_err)) => Err(OutputError::WaitingError(recv_err)),
            Ok(Ok(output_data)) => Ok(output_data.output.as_ref().unwrap().clone())
        }
    }

    /// Returns the output if it has already been reconstructed, otherwise returns None.
    pub fn get_output(&self) -> Option<Vec<F>> {
        let output_data = self.output_receiver.borrow();

        output_data.output.clone()
    }

    /// Process any message (used for both client and server roles).
    pub async fn process(&mut self, msg: OutputMessage) -> Result<(), OutputError> {
        self.output_handler(msg).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::UniformRand;
    use ark_std::test_rng;
    use crate::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
    use crate::honeybadger::output::OutputMessage;
    use tokio::time::Duration;

    #[tokio::test]
    async fn test_get_output() {
        let n = 5;
        let t = 1;
        let input_len = 1;
        let client_id = 7;
        let mut rng = test_rng();

        let mut client = OutputClient::<Fr>::new(client_id, n, t, input_len).unwrap();
        let secret = Fr::rand(&mut rng);

        // Use RobustShare::compute_shares to generate shares for the secret
        let shares_vec = RobustShare::compute_shares(secret, n, t, None, &mut rng).unwrap();

        // Send only 2 shares (less than 2t+1 = 3)
        for i in 0..2 {
            let mut payload = Vec::new();
            vec![shares_vec[i].clone()].serialize_compressed(&mut payload).unwrap();
            let msg = OutputMessage::new(i, payload);
            client.output_handler(msg).await.unwrap();
        }

        // get_output should return None since not enough shares have been received
        assert_eq!(client.get_output(), None);

        // Now send one more share (total 3, which is 2t+1)
        let mut payload = Vec::new();
        vec![shares_vec[2].clone()].serialize_compressed(&mut payload).unwrap();
        let msg = OutputMessage::new(2, payload);
        client.output_handler(msg).await.unwrap();

        // get_output should now return Some(secret)
        assert_eq!(client.get_output(), Some(vec![secret]));
    }

    #[tokio::test]
    async fn test_wait_for_output() {
        let n = 5;
        let t = 1;
        let input_len = 1;
        let client_id = 7;
        let mut rng = test_rng();

        let mut client = OutputClient::<Fr>::new(client_id, n, t, input_len).unwrap();
        let secret = Fr::rand(&mut rng);

        // Use RobustShare::compute_shares to generate shares for the secret
        let shares_vec = RobustShare::compute_shares(secret, n, t, None, &mut rng).unwrap();

        // Send only 2 shares (less than 2t+1 = 3)
        for i in 0..2 {
            let mut payload = Vec::new();
            vec![shares_vec[i].clone()].serialize_compressed(&mut payload).unwrap();
            let msg = OutputMessage::new(i, payload);
            client.output_handler(msg).await.unwrap();
        }

        // Call wait_for_output (should fail)
        let result = client.wait_for_output(Duration::from_millis(10)).await;
        assert!(result.is_err(), "Expected timeout error when only 2 shares are sent");

        // Now send one more share (total 3, which is 2t+1)
        let mut payload = Vec::new();
        vec![shares_vec[2].clone()].serialize_compressed(&mut payload).unwrap();
        let msg = OutputMessage::new(2, payload);
        client.output_handler(msg).await.unwrap();

        // Now, call wait_for_output again (should succeed)
        let result2 = client.wait_for_output(Duration::from_millis(10)).await;
        assert!(result2.is_ok(), "Expected output to be reconstructed after enough shares");
        assert_eq!(result2.unwrap(), vec![secret]);
    }
}
