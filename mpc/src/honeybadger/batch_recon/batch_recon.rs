use std::{
    marker::PhantomData,
    ops::{Add, Mul},
    result,
    sync::Arc,
};

use ark_serialize::CanonicalSerialize;

use super::*;
use crate::{
    common::{share::ShareError, SecretSharingScheme, ShamirShare},
    honeybadger::{
        robust_interpolate::{robust_interpolate::RobustShamirShare, *},
        triple_generation::{BatchReconFinishMessage, TripleGenMessage},
    },
};
use ark_ff::FftField;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use stoffelmpc_network::{Network, SessionId};
// use std::sync::Arc;
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
        // TODO - we might need to relax this check in preprocessing, since we will be opening deg 2t shares
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
        session_id: SessionId,
        content_type: BatchReconContentType,
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
            y_j_share.share[0]
                .serialize_compressed(&mut payload)
                .map_err(|e| BatchReconError::ArkSerialization(e))?;
            let msg = BatchReconMsg::new(
                self.id,
                session_id,
                BatchReconMsgType::Eval,
                content_type,
                payload,
            );

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
                    match RobustShamirShare::recover_secret(&self.evals_received.clone(), self.n) {
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
                            let new_msg = BatchReconMsg::new(
                                self.id,
                                msg.session_id,
                                BatchReconMsgType::Reveal,
                                msg.content_type,
                                payload,
                            );

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
                    match RobustShamirShare::recover_secret(&self.reveals_received.clone(), self.n)
                    {
                        Ok((poly, _)) => {
                            let mut result = poly;
                            // Resize the coefficient vector to `t + 1` to get all secrets.
                            result.resize(self.t + 1, F::zero());
                            self.secrets = Some(result.clone());
                            info!(self_id = self.id, "Secrets successfully reconstructed");

                            // Send the finalization message back to the triple generation or the
                            // multiplication protocol.
                            match msg.content_type {
                                BatchReconContentType::TripleGenMessage => {
                                    let triple_gen_message = BatchReconFinishMessage::new(
                                        result,
                                        self.id,
                                        msg.session_id,
                                    );
                                    let mut bytes_message = Vec::new();
                                    triple_gen_message.serialize_compressed(&mut bytes_message)?;
                                    let triple_gen_generic_msg = TripleGenMessage::new(
                                        self.id,
                                        msg.session_id,
                                        bytes_message,
                                    );
                                    let bytes_generic_msg =
                                        bincode::serialize(&triple_gen_generic_msg)?;
                                    net.send(self.id + 1, &bytes_generic_msg).await?;
                                }
                                BatchReconContentType::MultiplicationMessage => {
                                    // TODO: Complete this section.
                                    todo!()
                                }
                            }
                        }
                        Err(e) => {
                            error!(
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
        net: Arc<N>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::{Field, One, Zero};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_std::test_rng;

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
    fn test_make_vandermonde_basic() {
        let n = 4;
        let t = 2; // Matrix will have t+1 columns
        let vandermonde = make_vandermonde::<Fr>(n, t).expect("apply_vandermonde failed");

        // Verify dimensions
        assert_eq!(
            vandermonde.len(),
            n,
            "Vandermonde matrix should have 'n' rows"
        );
        for row in &vandermonde {
            assert_eq!(row.len(), t + 1, "Each row should have 't+1' columns");
        }

        let domain =
            GeneralEvaluationDomain::<Fr>::new(n).expect("Failed to create evaluation domain");

        // Verify specific elements based on the domain elements
        // Row 0: [1, 1, 1] since domain.element(0) is always 1
        assert_eq!(vandermonde[0][0], Fr::one());
        assert_eq!(vandermonde[0][1], Fr::one());
        assert_eq!(vandermonde[0][2], Fr::one());

        // Row 1: [1, alpha_1, alpha_1^2]
        let alpha_1 = domain.element(1);
        assert_eq!(vandermonde[1][0], Fr::one());
        assert_eq!(vandermonde[1][1], alpha_1);
        assert_eq!(vandermonde[1][2], alpha_1 * alpha_1);

        // Verify a general element: matrix[j][k] should be (domain.element(j))^k
        let j_test = 2;
        let k_test = 1;
        let alpha_j_test = domain.element(j_test);
        assert_eq!(
            vandermonde[j_test][k_test],
            alpha_j_test.pow([k_test as u64]),
            "Mismatch at matrix[{j_test}][{k_test}]"
        );

        let j_test_2 = 3;
        let k_test_2 = 2;
        let alpha_j_test_2 = domain.element(j_test_2);
        assert_eq!(
            vandermonde[j_test_2][k_test_2],
            alpha_j_test_2.pow([k_test_2 as u64]),
            "Mismatch at matrix[{j_test_2}][{k_test_2}]"
        );
    }

    #[test]
    fn test_apply_vandermonde_basic() {
        let n = 4;
        let t = 2;
        let vandermonde = make_vandermonde::<Fr>(n, t).expect("make_vandermonde failed");
        // Shares represent coefficients [c0, c1, c2] for a polynomial c0 + c1*x + c2*x^2
        let shares = vec![
            RobustShamirShare::new(Fr::from(1u64), 0, 2),
            RobustShamirShare::new(Fr::from(2u64), 0, 2),
            RobustShamirShare::new(Fr::from(3u64), 0, 2),
        ];
        let y_values = apply_vandermonde(&vandermonde, &shares).expect("apply_vandermonde failed");
        assert_eq!(
            y_values.len(),
            n,
            "Output y_values should have 'n' elements"
        );

        let domain =
            GeneralEvaluationDomain::<Fr>::new(n).expect("Failed to create evaluation domain");

        // Expected y_values[j] = sum(shares[k] * alpha_j^k)
        // This is equivalent to evaluating the polynomial represented by 'shares' at alpha_j
        for j in 0..n {
            let alpha_j = domain.element(j);
            let expected_y_j = shares[0].share[0] * alpha_j.pow([0]) // shares[0] * 1
                             + shares[1].share[0] * alpha_j.pow([1]) // shares[1] * alpha_j
                             + shares[2].share[0] * alpha_j.pow([2]); // shares[2] * alpha_j^2
            assert_eq!(
                y_values[j].share[0], expected_y_j,
                "Mismatch for y_values at index {}",
                j
            );
        }
    }

    #[test]
    fn test_batch_reconstruct_sequential() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_test_writer()
            .try_init();

        let t = 1;
        let n = 4;
        let session_id = 111;
        let secrets: Vec<Fr> = vec![Fr::from(3u64), Fr::from(4u64)];
        let content_type = BatchReconContentType::TripleGenMessage;
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
                let msg = BatchReconMsg::new(
                    i,
                    session_id,
                    BatchReconMsgType::Eval,
                    content_type,
                    payload,
                );

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

            if let Ok((_, value)) = RobustShamirShare::recover_secret(&received, n) {
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
            if let Ok((mut poly, _)) = RobustShamirShare::recover_secret(&y_values, n) {
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
