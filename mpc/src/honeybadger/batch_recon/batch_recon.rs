use ark_ff::FftField;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use stoffelmpc_common::reed_solomon::robust_interpolate;
use tokio::sync::mpsc::Sender;
use tracing::{debug, info, warn};

//Mocked for testing
#[derive(Debug, Clone)]
pub enum Msg<F: FftField> {
    Eval(usize, F),   // (sender_id, share of y_j)
    Reveal(usize, F), // y_j revealed in round 2
}

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
#[derive(Clone)]
pub struct Node<F: FftField> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    pub evals_received: Vec<(usize, F)>,
    pub reveals_received: Vec<(usize, F)>,
    pub y_j: Option<F>,
    pub secrets: Option<Vec<F>>,
}
/// Vandermonde matrix creation
pub fn make_vandermonde<F: FftField>(n: usize, t: usize) -> Vec<Vec<F>> {
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

///  Matrix-vector product: V * shares => y values
pub fn apply_vandermonde<F: FftField>(vandermonde: &[Vec<F>], shares: &[F]) -> Vec<F> {
    vandermonde
        .iter()
        .map(|row| row.iter().zip(shares.iter()).map(|(a, b)| *a * *b).sum())
        .collect()
}

///  Each party computes y_j_share for all j and sends to P_j
pub async fn init_batch_reconstruct<F: FftField>(
    shares: &[F], // this party's shares of x_0 to x_t
    n: usize,
    net: &Network<F>,
) {
    let vandermonde = make_vandermonde::<F>(n, shares.len() - 1);
    let y_shares = apply_vandermonde(&vandermonde, shares);

    info!(
        id = net.id,
        "Initialized batch reconstruction with Vandermonde transform"
    );

    for (j, y_j_share) in y_shares.into_iter().enumerate() {
        info!(from = net.id, to = j, "Sending y_j shares ");
        net.send(j, Msg::Eval(net.id, y_j_share)).await;
    }
}

impl<F: FftField> Node<F> {
    pub fn new(id: usize, n: usize, t: usize) -> Self {
        Self {
            id,
            n,
            t,
            evals_received: vec![],
            reveals_received: vec![],
            y_j: None,
            secrets: None,
        }
    }

    pub async fn batch_recon_handler(&mut self, msg: Msg<F>, net: Network<F>) {
        match msg {
            Msg::Eval(sender_id, val) => {
                debug!(
                    self_id = self.id,
                    from = sender_id,
                    ?val,
                    "Received Eval message"
                );
                if !self.evals_received.iter().any(|(id, _)| *id == sender_id) {
                    self.evals_received.push((sender_id, val));
                }
                if self.evals_received.len() >= 2 * self.t + 1 && self.y_j.is_none() {
                    info!(
                        self_id = self.id,
                        "Enough Evals collected, interpolating y_j"
                    );

                    match robust_interpolate(self.n, self.t, self.evals_received.clone()) {
                        Some((_, value)) => {
                            self.y_j = Some(value);
                            info!(node = self.id, "Broadcasting y_j value: {:?}", value);
                            net.broadcast(Msg::Reveal(self.id, value)).await;
                        }
                        None => {
                            warn!(
                                self_id = self.id,
                                "Interpolation of y_j failed — possibly too many errors or bad data"
                            );
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
                if !self.reveals_received.iter().any(|(id, _)| *id == sender_id) {
                    self.reveals_received.push((sender_id, y_j));
                }
                if self.reveals_received.len() >= 2 * self.t + 1 && self.secrets.is_none() {
                    info!(
                        self_id = self.id,
                        "Enough Reveals collected, interpolating secrets"
                    );

                    match robust_interpolate(self.n, self.t, self.reveals_received.clone()) {
                        Some((poly, _)) => {
                            let mut result = poly.coeffs;
                            result.resize(self.t + 1, F::zero());
                            self.secrets = Some(result);
                            info!(self_id = self.id, "Secrets successfully reconstructed");
                        }
                        None => {
                            warn!(
                                self_id = self.id,
                                "Final secrets interpolation failed — possibly too many incorrect y_j"
                            );
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::Zero;
    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
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
        let domain = GeneralEvaluationDomain::<F>::new(n).expect("No suitable evaluation domain");

        for (j, secret) in secrets.iter().enumerate() {
            // Construct polynomial f_j(x) = secret + a1*x + ... + at*x^t
            let mut coeffs = vec![*secret];
            for _ in 0..t {
                coeffs.push(F::rand(&mut rng));
            }
            let poly = DensePolynomial::from_coefficients_slice(&coeffs);

            // Evaluate on the FFT domain directly (Gao-style encoding)
            let evals = domain.fft(&poly);

            for i in 0..n {
                shares[i][j] = evals[i]; // Party i receives evaluation of f_j at α_i
            }
        }

        shares
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

            if let Some((_, value)) = robust_interpolate(n, t, received) {
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
            if let Some((poly, _)) = robust_interpolate(n, t, y_values) {
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
            let mut node = Node::<Fr>::new(i, n, t);
            let mut rx = receivers.remove(0); // each node gets its own receiver
            let my_shares = shares[i].clone();

            let handle = tokio::spawn(async move {
                // Step 4: Start the protocol
                init_batch_reconstruct(&my_shares, n, &net).await;

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
