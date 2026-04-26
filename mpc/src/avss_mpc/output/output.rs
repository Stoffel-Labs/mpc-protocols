use crate::avss_mpc::output::{AvssOutputError, AvssOutputMessage};
use crate::avss_mpc::AvssWrappedMessage;
use crate::common::share::avss::verify_feldman;
use crate::common::share::feldman::FeldmanShamirShare;
use crate::common::SecretSharingScheme;
use ark_ec::CurveGroup;
use ark_ff::FftField;
use ark_serialize::CanonicalSerialize;
use std::collections::HashMap;
use std::sync::Arc;
use stoffelnet::network_utils::Network;
use tokio::sync::watch::{channel, Receiver, Sender};
use tokio::time::{timeout, Duration};
use tracing::info;

/// Conveys the output to the clients. Each node sends their output FeldmanShamirShares
/// to the desired client, which then verifies Feldman commitments and reconstructs
/// the output using Lagrange interpolation (needs t+1 valid shares).
///
/// `AvssOutputServer` is the server-side component, which sends shares to the client.
/// `AvssOutputClient` is the client-side component, which collects shares and reconstructs.

#[derive(Clone, Debug)]
pub struct AvssOutputServer {
    pub id: usize,
    pub n: usize,
}

impl AvssOutputServer {
    pub fn new(id: usize, n: usize) -> Result<Self, AvssOutputError> {
        Ok(Self { id, n })
    }

    /// Called by each server to send its output shares to the client.
    pub async fn init<N: Network, F: FftField, G: CurveGroup<ScalarField = F>>(
        &self,
        client_id: usize,
        shares: Vec<FeldmanShamirShare<F, G>>,
        input_len: usize,
        net: Arc<N>,
    ) -> Result<(), AvssOutputError> {
        if shares.len() != input_len {
            return Err(AvssOutputError::InvalidInput(
                "Incorrect number of shares".to_string(),
            ));
        }

        let mut payload = Vec::new();
        shares.serialize_compressed(&mut payload)?;
        let msg = AvssOutputMessage::new(self.id, payload);
        let wrapped = AvssWrappedMessage::Output(msg);
        let bytes = bincode::serialize(&wrapped)?;

        net.send_to_client(client_id, &bytes).await?;
        info!(
            "Server {} sent output share to client {}",
            self.id, client_id
        );

        Ok(())
    }
}

pub struct AvssOutputClientData<F: FftField, G: CurveGroup<ScalarField = F>> {
    pub output: Option<Vec<F>>,
    pub output_shares: HashMap<usize, Vec<FeldmanShamirShare<F, G>>>,
}

#[derive(Clone)]
pub struct AvssOutputClient<F: FftField, G: CurveGroup<ScalarField = F>> {
    pub client_id: usize,
    pub n: usize,
    pub t: usize,
    pub input_len: usize,
    output_sender: Sender<AvssOutputClientData<F, G>>,
    output_receiver: Receiver<AvssOutputClientData<F, G>>,
}

impl<F: FftField, G: CurveGroup<ScalarField = F>> AvssOutputClient<F, G> {
    pub fn new(id: usize, n: usize, t: usize, input_len: usize) -> Result<Self, AvssOutputError> {
        let (output_sender, output_receiver) = channel(AvssOutputClientData::<F, G> {
            output: None,
            output_shares: HashMap::new(),
        });

        Ok(Self {
            client_id: id,
            n,
            t,
            input_len,
            output_sender,
            output_receiver,
        })
    }

    /// Handles shares sent by a node to this client.
    ///
    /// 1. Parse the received message into FeldmanShamirShares and check length.
    /// 2. Verify Feldman commitments on each share.
    /// 3. Return if shares from this sender have already been received.
    /// 4. Add the received shares.
    /// 5. If the output has not been reconstructed yet and enough verified shares have
    ///    been received (t+1), reconstruct the output.
    pub async fn output_handler(&mut self, msg: AvssOutputMessage) -> Result<(), AvssOutputError> {
        // 1.
        let shares: Vec<FeldmanShamirShare<F, G>> =
            ark_serialize::CanonicalDeserialize::deserialize_compressed(msg.payload.as_slice())?;

        if shares.len() != self.input_len {
            return Err(AvssOutputError::InvalidInput(
                "Mismatch in input and share length".to_string(),
            ));
        }

        // 2. Verify Feldman commitments and degree
        for share in &shares {
            if share.feldmanshare.degree != self.t {
                return Err(AvssOutputError::InvalidInput(format!(
                    "Invalid share degree from server {}",
                    msg.sender_id
                )));
            }
            if !verify_feldman(share.clone()) {
                return Err(AvssOutputError::VerificationFailed(format!(
                    "Feldman verification failed for share from server {}",
                    msg.sender_id
                )));
            }
        }

        let mut already_recvd = false;
        let mut recovery_err = None;

        self.output_sender.send_if_modified(|output_data| {
            let share_store = &mut output_data.output_shares;

            // 3.
            if share_store.contains_key(&msg.sender_id) {
                already_recvd = true;
                return false;
            }
            // 4.
            share_store.insert(msg.sender_id, shares.clone());
            info!("Received Output share from server {}", msg.sender_id);

            // 5. For Feldman shares, group by commitment fingerprint per output position,
            //    reconstruct only from a consistent group of t+1 shares.
            if output_data.output.is_none() && share_store.len() >= self.t + 1 {
                let mut consistent_groups: Vec<Option<Vec<FeldmanShamirShare<F, G>>>> =
                    vec![None; self.input_len];

                for i in 0..self.input_len {
                    let mut by_commitment: HashMap<Vec<u8>, Vec<FeldmanShamirShare<F, G>>> =
                        HashMap::new();
                    for (_, shares) in share_store.iter() {
                        let share = &shares[i];
                        let mut key = Vec::new();
                        if share.commitments.serialize_compressed(&mut key).is_err() {
                            return false;
                        }
                        by_commitment.entry(key).or_default().push(share.clone());
                    }
                    match by_commitment.into_values().find(|g| g.len() >= self.t + 1) {
                        Some(group) => consistent_groups[i] = Some(group),
                        None => return false, // not enough consistent shares yet
                    }
                }

                info!("Received enough consistent shares to reconstruct output");
                let mut output = Vec::new();
                for group in consistent_groups.into_iter().flatten() {
                    let secret =
                        match FeldmanShamirShare::<F, G>::recover_secret(&group, self.n, self.t) {
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
            return Err(AvssOutputError::Duplicate(format!(
                "Already received from {}",
                msg.sender_id
            )));
        }
        if let Some(err) = recovery_err {
            return Err(AvssOutputError::ShareError(err));
        }

        Ok(())
    }

    /// Waits for the output to be reconstructed. If this does not happen within the specified
    /// duration, it returns before.
    pub async fn wait_for_output(&mut self, duration: Duration) -> Result<Vec<F>, AvssOutputError> {
        let output_future = self
            .output_receiver
            .wait_for(|output_data| output_data.output.is_some());

        match timeout(duration, output_future).await {
            Err(elapsed_err) => Err(AvssOutputError::Timeout(elapsed_err)),
            Ok(Err(recv_err)) => Err(AvssOutputError::WaitingError(recv_err)),
            Ok(Ok(output_data)) => Ok(output_data.output.as_ref().unwrap().clone()),
        }
    }

    /// Returns the output if it has already been reconstructed, otherwise returns None.
    pub fn get_output(&self) -> Option<Vec<F>> {
        let output_data = self.output_receiver.borrow();
        output_data.output.clone()
    }

    /// Process any message (used for both client and server roles).
    pub async fn process(&mut self, msg: AvssOutputMessage) -> Result<(), AvssOutputError> {
        self.output_handler(msg).await?;
        Ok(())
    }
}
