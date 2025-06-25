use std::{
    marker::PhantomData,
    ops::{Add, Mul},
};

use super::*;
use crate::{
    common::{share::ShareError, SecretSharingScheme, ShamirShare},
    honeybadger::robust_interpolate::{robust_interpolate::RobustShamirShare, *},
};
use ark_ff::FftField;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use std::sync::Arc;
use stoffelmpc_network::Network;
use tracing::{debug, info, warn};
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

#[derive(Clone)]
pub struct BatchReconNode<F: FftField> {
    pub id: usize,                                   // This node's unique identifier
    pub n: usize,                                    // Total number of nodes/shares
    pub t: usize,                                    // Number of malicious parties
    pub evals_received: Vec<RobustShamirShare<F>>,   // Stores (sender_id, eval_share) messages
    pub reveals_received: Vec<RobustShamirShare<F>>, // Stores (sender_id, y_j_value) messages
    pub y_j: Option<RobustShamirShare<F>>, // The interpolated y_j value for this node's index
    pub secrets: Option<Vec<F>>, // The finally reconstructed original secrets (polynomial coefficients)
}

impl<F: FftField> BatchReconNode<F> {
    /// Creates a new `Node` instance.
    pub fn new(id: usize, n: usize, t: usize) -> Result<Self, BatchReconError> {
        if !(t < (n + 2) / 3) {
            // ceil(n / 3)
            return Err(BatchReconError::InvalidInput(format!(
                "Invalid t: must satisfy 0 <= t < n / 3 (t={}, n={})",
                t, n
            )));
        }
        Ok(Self {
            id,
            n,
            t,
            evals_received: vec![],
            reveals_received: vec![],
            y_j: None,
            secrets: None,
        })
    }

    /// Initiates the batch reconstruction protocol for a given node.
    ///
    /// Each party computes its `y_j_share` for all `j` and sends it to party `P_j`.
    pub async fn init_batch_reconstruct<N: Network>(
        &self,
        shares: &[RobustShamirShare<F>], // this party's shares of x_0 to x_t
        net: &Arc<N>,
    ) -> Result<(), BatchReconError> {
        if shares.len() < self.t + 1 {
            return Err(BatchReconError::InvalidInput(
                "Too little shares to start batch reconstruct".to_string(),
            ));
        }
        let vandermonde = make_vandermonde::<F>(self.n, self.t)?;
        let y_shares = apply_vandermonde(&vandermonde, &shares[..(self.t + 1)])?;

        info!(
            id = self.id,
            "Initialized batch reconstruction with Vandermonde transform"
        );

        for (j, y_j_share) in y_shares.into_iter().enumerate() {
            info!(from = self.id, to = j, "Sending y_j shares ");

            let mut payload = Vec::new();
            y_j_share.share[0]
                .serialize_compressed(&mut payload)
                .map_err(|e| BatchReconError::ArkSerialization(e))?;
            let msg = BatchReconMsg::new(self.id, BatchReconMsgType::Eval, payload);

            //Send share y_j to each Party j
            let encoded_msg =
                bincode::serialize(&msg).map_err(BatchReconError::SerializationError)?;

            let _ = net
                .send(j + 1, &encoded_msg)
                .await
                .map_err(|e| BatchReconError::NetworkError(e))?;
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
        net: &Arc<N>,
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

                // Store the received evaluation share if it's from a new sender.
                if !self.evals_received.iter().any(|s| s.id == sender_id) {
                    self.evals_received
                        .push(RobustShamirShare::new(val, sender_id, self.t));
                }
                // Check if we have enough evaluation shares and haven't already computed our `y_j`.
                if self.evals_received.len() >= 2 * self.t + 1 && self.y_j.is_none() {
                    info!(
                        self_id = self.id,
                        "Enough Evals collected, interpolating y_j"
                    );

                    // Attempt to interpolate the polynomial and get our specific `y_j` value.
                    match RobustShamirShare::recover_secret(&self.evals_received.clone()) {
                        Ok((_, value)) => {
                            self.y_j = Some(RobustShamirShare {
                                share: [value],
                                id: self.id,
                                degree: self.t,
                                _sharetype: PhantomData,
                            });
                            info!(node = self.id, "Broadcasting y_j value: {:?}", value);

                            let mut payload = Vec::new();
                            value
                                .serialize_compressed(&mut payload)
                                .map_err(|e| BatchReconError::ArkSerialization(e))?;
                            let new_msg =
                                BatchReconMsg::new(self.id, BatchReconMsgType::Reveal, payload);

                            // Broadcast our computed `y_j` to all other parties.
                            let encoded = bincode::serialize(&new_msg)
                                .map_err(BatchReconError::SerializationError)?;
                            let _ = net
                                .broadcast(&encoded)
                                .await
                                .map_err(|e| BatchReconError::NetworkError(e))?;
                        }
                        Err(e) => {
                            warn!(self_id = self.id, "Interpolation of y_j failed: {:?}", e);
                            return Err(BatchReconError::Inner(e));
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

                // Store the received revealed `y_j` value if it's from a new sender.
                if !self.reveals_received.iter().any(|s| s.id == sender_id) {
                    self.reveals_received
                        .push(RobustShamirShare::new(y_j, sender_id, self.t));
                }
                // Check if we have enough revealed `y_j` values and haven't already reconstructed the secrets.
                if self.reveals_received.len() >= 2 * self.t + 1 && self.secrets.is_none() {
                    info!(
                        self_id = self.id,
                        "Enough Reveals collected, interpolating secrets"
                    );
                    // Attempt to interpolate the polynomial whose coefficients are the original secrets.
                    match RobustShamirShare::recover_secret(&self.reveals_received.clone()) {
                        Ok((poly, _)) => {
                            let mut result = poly;
                            // Resize the coefficient vector to `t + 1` to get all secrets.
                            result.resize(self.t + 1, F::zero());
                            self.secrets = Some(result);
                            info!(self_id = self.id, "Secrets successfully reconstructed");
                        }
                        Err(e) => {
                            warn!(
                                self_id = self.id, error = ?e,
                                "Final secrets interpolation failed "
                            );
                            return Err(BatchReconError::Inner(e));
                        }
                    }
                }
                Ok(())
            }
        }
    }
    pub async fn process<N: Network>(
        &mut self,
        raw_msg: Vec<u8>,
        net: &Arc<N>,
    ) -> Result<(), BatchReconError> {
        let msg: BatchReconMsg =
            bincode::deserialize(&raw_msg).map_err(|e| BatchReconError::SerializationError(e))?;

        self.batch_recon_handler(msg, net).await?;
        Ok(())
    }
}

/// Creates a Vandermonde matrix `V` of size `n x (t+1)`.
/// Each row `j` contains powers of `domain.element(j)`: `[1, alpha_j, alpha_j^2, ..., alpha_j^t]`.
pub fn make_vandermonde<F: FftField>(n: usize, t: usize) -> Result<Vec<Vec<F>>, InterpolateError> {
    let domain =
        GeneralEvaluationDomain::<F>::new(n).ok_or(InterpolateError::NoSuitableDomain(n))?;
    let mut matrix = vec![vec![F::zero(); t + 1]; n];

    for j in 0..n {
        let alpha_j = domain.element(j);
        let mut pow = F::one();
        for k in 0..=t {
            matrix[j][k] = pow;
            pow *= alpha_j;
        }
    }

    Ok(matrix)
}

/// Computes the matrix-vector product: `V * shares`.
/// This effectively evaluates a polynomial (defined by `shares` as coefficients)
/// at the domain elements corresponding to the Vandermonde matrix rows.
pub fn apply_vandermonde<F: FftField, P>(
    vandermonde: &[Vec<F>],
    shares: &[ShamirShare<F, 1, P>],
) -> Result<Vec<ShamirShare<F, 1, P>>, InterpolateError>
where
    ShamirShare<F, 1, P>: Clone
        + Mul<F, Output = Result<ShamirShare<F, 1, P>, ShareError>>
        + Add<ShamirShare<F, 1, P>, Output = Result<ShamirShare<F, 1, P>, ShareError>>,
{
    let share_len = shares.len();
    for (_, row) in vandermonde.iter().enumerate() {
        if row.len() != share_len {
            return Err(InterpolateError::InvalidInput(
                "Incorrect matrix length".to_string(),
            ));
        }
    }
    vandermonde
        .iter()
        .map(|row| {
            let mut acc = (shares[0].clone() * row[0])?;
            for (a, b) in row.iter().zip(shares.iter()).skip(1) {
                let term = (b.clone() * *a)?;
                acc = (acc + term)?
            }
            Ok(acc)
        })
        .collect()
}