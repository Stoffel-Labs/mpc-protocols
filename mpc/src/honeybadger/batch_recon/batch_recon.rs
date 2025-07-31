use std::{
    marker::PhantomData,
    ops::{Add, Mul},
};

use super::*;
use crate::{
    common::{
        share::{apply_vandermonde, make_vandermonde, ShareError},
        SecretSharingScheme, ShamirShare,
    },
    honeybadger::robust_interpolate::*,
};
use ark_ff::FftField;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
// use std::sync::Arc;
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
    pub async fn init_batch_reconstruct(
        &self,
        shares: &[RobustShamirShare<F>], // this party's shares of x_0 to x_t
                                         //net: &Arc<N>,
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
            let _encoded_msg =
                bincode::serialize(&msg).map_err(BatchReconError::SerializationError)?;

            // let _ = net
            //     .send(j + 1, &encoded_msg)
            //     .await
            //     .map_err(|e| BatchReconError::NetworkError(e))?;
        }
        Ok(())
    }

    /// Handles incoming `Msg`s for the batch reconstruction protocol.
    ///
    /// This function processes `Eval` messages (first round) and `Reveal` messages (second round)
    /// to collectively reconstruct the original secrets.
    pub async fn batch_recon_handler(
        &mut self,
        msg: BatchReconMsg,
        //net: &Arc<N>,
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
                            let _encoded = bincode::serialize(&new_msg)
                                .map_err(BatchReconError::SerializationError)?;

                            // TODO: Implement the network.
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
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use crate::common::SecretSharingScheme;
    use ark_bls12_381::Fr;
    use ark_ff::{FftField, Zero};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_std::test_rng;

    use crate::{
        common::share::{apply_vandermonde, make_vandermonde},
        honeybadger::{
            batch_recon::{BatchReconMsg, BatchReconMsgType},
            robust_interpolate::RobustShamirShare,
        },
    };

    /// Generate secret shares where each secret is shared independently using a random polynomial
    /// with that secret as the constant term (f(0) = secret), and evaluated using FFT-based domain.
    pub fn generate_independent_shares<F: FftField>(
        secrets: &[F],
        t: usize,
        n: usize,
    ) -> Vec<Vec<RobustShamirShare<F>>> {
        let mut rng = test_rng();
        let mut shares = vec![
            vec![
                RobustShamirShare {
                    share: [F::zero()],
                    id: 0,
                    degree: t,
                    _sharetype: PhantomData
                };
                secrets.len()
            ];
            n
        ];
        for (j, secret) in secrets.iter().enumerate() {
            // Call gen_shares to create 'n' shares for the current 'secret'
            let ids: Vec<usize> = (0..n).collect();
            let secret_shares =
                RobustShamirShare::compute_shares(*secret, n, t, Some(&ids), &mut rng).unwrap();
            for i in 0..n {
                shares[i][j] = secret_shares[i].clone(); // Party i receives evaluation of f_j at α_i
            }
        }

        shares
    }

    #[test]
    fn test_batch_reconstruct_sequential() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_test_writer()
            .try_init();

        let t = 1;
        let n = 4;
        let secrets: Vec<Fr> = vec![Fr::from(3u64), Fr::from(4u64)];
        assert_eq!(secrets.len(), t + 1);

        // Step 0: Generate shares
        let shares = generate_independent_shares(&secrets, t, n);

        // Simulate network inboxes: inboxes[j] = list of Msgs received by party j
        let mut inboxes: Vec<Vec<BatchReconMsg>> = vec![vec![]; n];

        // === Step 1: Each party computes y_j_share for all j and sends to P_j
        let vandermonde = make_vandermonde::<Fr>(n, t).expect("apply_vandermonde failed");
        for i in 0..n {
            let y_shares =
                apply_vandermonde(&vandermonde, &shares[i]).expect("apply_vandermonde failed");

            for j in 0..n {
                let mut payload = Vec::new();
                y_shares[j]
                    .share
                    .serialize_compressed(&mut payload)
                    .expect("serialization should not fail");
                let msg = BatchReconMsg::new(i, BatchReconMsgType::Eval, payload);

                inboxes[j].push(msg);
            }
        }

        // === Step 2–5: Each party interpolates y(x), evaluates at its own alpha, and sends Reveal
        let mut reveals: Vec<Option<Fr>> = vec![None; n];
        for j in 0..n {
            let mut received = vec![];
            let mut seen = std::collections::HashSet::new();

            for msg in &inboxes[j] {
                if let BatchReconMsgType::Eval = msg.msg_type {
                    let i = msg.sender_id;
                    let val = Fr::deserialize_compressed(msg.payload.as_slice())
                        .expect("deserialization should not fail");

                    if seen.insert(i) {
                        received.push(RobustShamirShare::new(val, i, t));
                        if received.len() == 2 * t + 1 {
                            break;
                        }
                    }
                }
            }

            if let Ok((_, value)) = RobustShamirShare::recover_secret(&received) {
                reveals[j] = Some(value);
            }
        }

        // === Step 6: Each party collects y_j values and reconstructs x coefficients
        let mut recovered_all = vec![];
        for _ in 0..n {
            let mut y_values = vec![];
            let mut seen = std::collections::HashSet::new();

            for (j, val_opt) in reveals.iter().enumerate() {
                if let Some(y_j) = val_opt {
                    if seen.insert(j) {
                        y_values.push(RobustShamirShare::new(*y_j, j, t));
                        if y_values.len() == 2 * t + 1 {
                            break;
                        }
                    }
                }
            }
            if let Ok((mut poly, _)) = RobustShamirShare::recover_secret(&y_values) {
                //  Extract original secrets (coefficients) x_1 .. x_{t+1}
                poly.resize(t + 1, Fr::zero());
                recovered_all.push(poly);
            }
        }

        assert_eq!(recovered_all.len(), n, "Share reconstruction failed");
        // === Check all recovered results match the original secrets
        for recovered in recovered_all {
            assert_eq!(recovered[..secrets.len()], secrets[..]);
        }
    }
}
