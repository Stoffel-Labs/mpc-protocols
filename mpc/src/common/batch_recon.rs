use super::robust_interpolate::*;
use ark_ff::FftField;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use tokio::sync::mpsc::Sender;
use tracing::{debug, info, warn};

/// Mocked for testing purposes.
/// Represents messages exchanged between network nodes during the batch reconstruction protocol.
#[derive(Debug, Clone)]
pub enum Msg<F: FftField> {
    Eval(usize, F),   // (sender_id, share of y_j) - sent in the first round
    Reveal(usize, F), // (sender_id, y_j value) - sent in the second round
}
/// Mocked for testing purposes.
/// Represents a network interface for a node, allowing it to send messages to other nodes.
#[derive(Clone)]
pub struct Network<F: FftField> {
    pub id: usize,
    pub senders: Vec<Sender<Msg<F>>>,
}
impl<F: FftField> Network<F> {
    pub async fn broadcast(&self, msg: Msg<F>) {
        for sender in &self.senders {
            let _ = sender.send(msg.clone()).await;
        }
    }
    pub async fn send(&self, target: usize, msg: Msg<F>) {
        let _ = self.senders[target].send(msg).await;
    }
}

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
    pub id: usize,                         // This node's unique identifier
    pub n: usize,                          // Total number of nodes/shares
    pub t: usize,                          // Number of malicious parties
    pub evals_received: Vec<(usize, F)>,   // Stores (sender_id, eval_share) messages
    pub reveals_received: Vec<(usize, F)>, // Stores (sender_id, y_j_value) messages
    pub y_j: Option<F>,                    // The interpolated y_j value for this node's index
    pub secrets: Option<Vec<F>>, // The finally reconstructed original secrets (polynomial coefficients)
}

impl<F: FftField> BatchReconNode<F> {
    /// Creates a new `Node` instance.
    pub fn new(id: usize, n: usize, t: usize) -> Result<Self, String> {
        if !(t < (n + 2) / 3) {
            // ceil(n / 3)
            return Err(format!(
                "Invalid t: must satisfy 0 <= t < n / 3 (t={}, n={})",
                t, n
            ));
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
        shares: &[F], // this party's shares of x_0 to x_t
        net: &Network<F>,
    ) {
        assert!(
            shares.len() >= self.t + 1,
            "Too little shares to start batch reconstruct"
        );
        let vandermonde = make_vandermonde::<F>(self.n, self.t);
        let y_shares = apply_vandermonde(&vandermonde, &shares[..(self.t + 1)]);

        info!(
            id = net.id,
            "Initialized batch reconstruction with Vandermonde transform"
        );

        for (j, y_j_share) in y_shares.into_iter().enumerate() {
            info!(from = net.id, to = j, "Sending y_j shares ");
            net.send(j, Msg::Eval(net.id, y_j_share)).await;
        }
    }

    /// Handles incoming `Msg`s for the batch reconstruction protocol.
    ///
    /// This function processes `Eval` messages (first round) and `Reveal` messages (second round)
    /// to collectively reconstruct the original secrets.
    pub async fn batch_recon_handler(&mut self, msg: Msg<F>, net: Network<F>) {
        match msg {
            Msg::Eval(sender_id, val) => {
                debug!(
                    self_id = self.id,
                    from = sender_id,
                    ?val,
                    "Received Eval message"
                );

                // Store the received evaluation share if it's from a new sender.
                if !self.evals_received.iter().any(|(id, _)| *id == sender_id) {
                    self.evals_received.push((sender_id, val));
                }
                // Check if we have enough evaluation shares and haven't already computed our `y_j`.
                if self.evals_received.len() >= 2 * self.t + 1 && self.y_j.is_none() {
                    info!(
                        self_id = self.id,
                        "Enough Evals collected, interpolating y_j"
                    );

                    // Attempt to interpolate the polynomial and get our specific `y_j` value.
                    match robust_interpolate(self.n, self.t, self.evals_received.clone()) {
                        Ok((_, value)) => {
                            self.y_j = Some(value);
                            info!(node = self.id, "Broadcasting y_j value: {:?}", value);
                            // Broadcast our computed `y_j` to all other parties.
                            net.broadcast(Msg::Reveal(self.id, value)).await;
                        }
                        Err(e) => {
                            warn!(self_id = self.id, "Interpolation of y_j failed — {e}");
                        }
                    }
                }
            }
            Msg::Reveal(sender_id, y_j) => {
                debug!(
                    self_id = self.id,
                    from = sender_id,
                    ?y_j,
                    "Received Reveal message"
                );
                // Store the received revealed `y_j` value if it's from a new sender.
                if !self.reveals_received.iter().any(|(id, _)| *id == sender_id) {
                    self.reveals_received.push((sender_id, y_j));
                }
                // Check if we have enough revealed `y_j` values and haven't already reconstructed the secrets.
                if self.reveals_received.len() >= 2 * self.t + 1 && self.secrets.is_none() {
                    info!(
                        self_id = self.id,
                        "Enough Reveals collected, interpolating secrets"
                    );

                    // Attempt to interpolate the polynomial whose coefficients are the original secrets.
                    match robust_interpolate(self.n, self.t, self.reveals_received.clone()) {
                        Ok((poly, _)) => {
                            let mut result = poly.coeffs;
                            // Resize the coefficient vector to `t + 1` to get all secrets.
                            result.resize(self.t + 1, F::zero());
                            self.secrets = Some(result);
                            info!(self_id = self.id, "Secrets successfully reconstructed");
                        }
                        Err(e) => {
                            warn!(
                                self_id = self.id,
                                "Final secrets interpolation failed — {e}"
                            );
                        }
                    }
                }
            }
        }
    }
}

/// Creates a Vandermonde matrix `V` of size `n x (t+1)`.
/// Each row `j` contains powers of `domain.element(j)`: `[1, alpha_j, alpha_j^2, ..., alpha_j^t]`.
fn make_vandermonde<F: FftField>(n: usize, t: usize) -> Vec<Vec<F>> {
    assert!(
        n > t,
        "Incorrect parameters for vandermonde matrix creation"
    );
    let domain = GeneralEvaluationDomain::<F>::new(n).unwrap();
    let mut matrix = vec![vec![F::zero(); t + 1]; n];

    for j in 0..n {
        let alpha_j = domain.element(j);
        let mut pow = F::one();
        for k in 0..=t {
            matrix[j][k] = pow;
            pow *= alpha_j;
        }
    }

    matrix
}

/// Computes the matrix-vector product: `V * shares`.
/// This effectively evaluates a polynomial (defined by `shares` as coefficients)
/// at the domain elements corresponding to the Vandermonde matrix rows.
fn apply_vandermonde<F: FftField>(vandermonde: &[Vec<F>], shares: &[F]) -> Vec<F> {
    let share_len = shares.len();
    for (_, row) in vandermonde.iter().enumerate() {
        assert!(row.len() == share_len, "Incorrect matrix length",);
    }
    vandermonde
        .iter()
        .map(|row| row.iter().zip(shares.iter()).map(|(a, b)| *a * *b).sum())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::{Field, One, Zero};
    use ark_std::test_rng;
    use tokio::time::timeout;

    /// Generate secret shares where each secret is shared independently using a random polynomial
    /// with that secret as the constant term (f(0) = secret), and evaluated using FFT-based domain.
    pub fn generate_independent_shares<F: FftField>(
        secrets: &[F],
        t: usize,
        n: usize,
    ) -> Vec<Vec<F>> {
        let mut rng = test_rng();
        let mut shares = vec![vec![F::zero(); secrets.len()]; n];
        for (j, secret) in secrets.iter().enumerate() {
            // Call gen_shares to create 'n' shares for the current 'secret'
            let secret_shares = gen_shares(*secret, n, t, &mut rng);
            if let Ok(s) = secret_shares {
                for i in 0..n {
                    shares[i][j] = s[i]; // Party i receives evaluation of f_j at α_i
                }
            }
        }

        shares
    }

    #[test]
    fn test_make_vandermonde_basic() {
        let n = 4;
        let t = 2; // Matrix will have t+1 columns
        let vandermonde = make_vandermonde::<Fr>(n, t);

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
        let vandermonde = make_vandermonde::<Fr>(n, t);
        // Shares represent coefficients [c0, c1, c2] for a polynomial c0 + c1*x + c2*x^2
        let shares = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)]; // t+1 shares/coefficients

        let y_values = apply_vandermonde(&vandermonde, &shares);
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
            let expected_y_j = shares[0] * alpha_j.pow([0]) // shares[0] * 1
                             + shares[1] * alpha_j.pow([1]) // shares[1] * alpha_j
                             + shares[2] * alpha_j.pow([2]); // shares[2] * alpha_j^2
            assert_eq!(
                y_values[j], expected_y_j,
                "Mismatch for y_values at index {}",
                j
            );
        }
    }

    #[test]
    fn test_batch_reconstruct_sequential() {
        let t = 1;
        let n = 4;
        let secrets: Vec<Fr> = vec![Fr::from(3u64), Fr::from(4u64)];
        assert_eq!(secrets.len(), t + 1);

        // Step 0: Generate shares
        let shares = generate_independent_shares(&secrets, t, n);

        // Simulate network inboxes: inboxes[j] = list of Msgs received by party j
        let mut inboxes: Vec<Vec<Msg<Fr>>> = vec![vec![]; n];

        // === Step 1: Each party computes y_j_share for all j and sends to P_j
        let vandermonde = make_vandermonde::<Fr>(n, t);
        for i in 0..n {
            let y_shares = apply_vandermonde(&vandermonde, &shares[i]);
            for j in 0..n {
                inboxes[j].push(Msg::Eval(i, y_shares[j]));
            }
        }

        // === Step 2–5: Each party interpolates y(x), evaluates at its own alpha, and sends Reveal
        let mut reveals: Vec<Option<Fr>> = vec![None; n];
        for j in 0..n {
            let mut received = vec![];
            let mut seen = std::collections::HashSet::new();

            for msg in &inboxes[j] {
                if let Msg::Eval(i, val) = msg {
                    if seen.insert(*i) {
                        received.push((*i, *val));
                        if received.len() == 2 * t + 1 {
                            break;
                        }
                    }
                }
            }

            if let Ok((_, value)) = robust_interpolate(n, t, received) {
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
                        y_values.push((j, *y_j));
                        if y_values.len() == 2 * t + 1 {
                            break;
                        }
                    }
                }
            }
            if let Ok((poly, _)) = robust_interpolate(n, t, y_values) {
                //  Extract original secrets (coefficients) x_1 .. x_{t+1}
                let mut result = poly.coeffs;
                result.resize(t + 1, Fr::zero());
                recovered_all.push(result);
            }
        }

        assert_eq!(recovered_all.len(), n, "Share reconstruction failed");
        // === Check all recovered results match the original secrets
        for recovered in recovered_all {
            assert_eq!(recovered[..secrets.len()], secrets[..]);
        }
    }

    #[tokio::test]
    async fn test_batch_reconstruction_protocol() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_test_writer()
            .try_init();
        use tokio::sync::mpsc;

        let n = 4;
        let t = 1;
        let secrets: Vec<Fr> = vec![Fr::from(3u64), Fr::from(4u64)];

        // Step 1: Generate secret shares
        let shares = generate_independent_shares(&secrets, t, n);

        // Step 2: Create channels
        let mut senders = Vec::new();
        let mut receivers = Vec::new();
        for _ in 0..n {
            let (tx, rx) = mpsc::channel(100);
            senders.push(tx);
            receivers.push(rx);
        }

        // Step 3: Initialize nodes
        let mut handles = vec![];
        for i in 0..n {
            let node_senders = senders.clone();
            let net = Network {
                id: i,
                senders: node_senders,
            };
            let mut node = BatchReconNode::<Fr>::new(i, n, t).expect("Incorrect n or t");
            let mut rx = receivers.remove(0); // each node gets its own receiver
            let my_shares = shares[i].clone();

            let handle = tokio::spawn(async move {
                // Step 4: Start the protocol
                node.init_batch_reconstruct(&my_shares, &net).await;

                // Step 5: Process incoming messages
                while node.secrets.is_none() {
                    let msg = timeout(Duration::from_secs(2), rx.recv()).await;
                    match msg {
                        Ok(Some(msg)) => {
                            node.batch_recon_handler(msg, net.clone()).await;
                        }
                        Ok(None) => break, // Channel closed
                        Err(_) => {
                            panic!("Node {} timed out waiting for a message", i);
                        }
                    }
                }

                // Return recovered secrets
                node.secrets.clone().unwrap()
            });

            handles.push(handle);
        }

        // Step 6: Collect results
        for handle in handles {
            let recovered = handle.await.unwrap();
            assert_eq!(recovered[..secrets.len()], secrets[..]);
        }
    }
}
