use super::reed_solomon::robust_interpolate;
use ark_ff::FftField;
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, GeneralEvaluationDomain, Polynomial,
};
use std::sync::mpsc::{Receiver, Sender};

#[derive(Debug, Clone)]
pub enum Msg<F: FftField> {
    Eval(usize, F), // (sender_id, share of y_j)
    Reveal(F),      // y_j revealed in round 2
}

#[derive(Clone)]
pub struct Network<F: FftField> {
    pub id: usize,
    pub senders: Vec<Sender<Msg<F>>>,
}

impl<F: FftField> Network<F> {
    pub fn broadcast(&self, msg: Msg<F>) {
        for sender in &self.senders {
            sender.send(msg.clone()).unwrap();
        }
    }

    pub fn send(&self, target: usize, msg: Msg<F>) {
        self.senders[target].send(msg).unwrap();
    }
}

// Vandermonde matrix creation
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

// === Matrix-vector product: V * shares => y values ===
pub fn apply_vandermonde<F: FftField>(vandermonde: &[Vec<F>], shares: &[F]) -> Vec<F> {
    vandermonde
        .iter()
        .map(|row| row.iter().zip(shares.iter()).map(|(a, b)| *a * *b).sum())
        .collect()
}

// Step 1: Each party computes y_j_share for all j and sends to P_j
pub fn init_batch_reconstruct<F: FftField>(
    shares: &[F], // this party's shares of x_0 to x_t
    n: usize,
    net: &Network<F>,
) {
    let vandermonde = make_vandermonde::<F>(n, shares.len() - 1);
    let y_shares = apply_vandermonde(&vandermonde, shares);

    for (j, y_j_share) in y_shares.into_iter().enumerate() {
        net.send(j, Msg::Eval(net.id, y_j_share));
    }
}

// Step 2: Each party collects 2t+1 evaluations and interpolates the polynomial y(x)
pub fn batch_recon_handler<F: FftField>(
    t: usize,
    n: usize,
    receiver: &Receiver<Msg<F>>,
    net: &Network<F>,
) -> Option<F> {
    let mut shares = vec![];
    let mut seen = std::collections::HashSet::new();

    while shares.len() < 2 * t + 1 {
        if let Ok(Msg::Eval(i, val)) = receiver.recv() {
            if seen.insert(i) {
                shares.push((i, val));
            }
        }
    }

    // Interpolate y_j = y(alpha_j)
    match robust_interpolate(n, t, t, shares) {
        Some((poly, _)) => {
            let domain = GeneralEvaluationDomain::<F>::new(n).unwrap();
            let y_j = poly.evaluate(&domain.element(net.id));
            net.broadcast(Msg::Reveal(y_j)); // Broadcast y_j
            Some(y_j)
        }
        None => None,
    }
}

// Each party collects between 2t+1 and n values y_j and interpolates x_1..x_{t+1}
pub fn batch_final_decode<F: FftField>(
    t: usize,
    n: usize,
    receiver: &Receiver<Msg<F>>,
) -> Option<Vec<F>> {
    let mut values = vec![];
    let mut seen = std::collections::HashSet::new();

    while values.len() < 2 * t + 1 {
        if let Ok(Msg::Reveal(y_j)) = receiver.recv() {
            let index = values.len();
            if seen.insert(index) {
                values.push((index, y_j));
            }
        }
    }

    match robust_interpolate(n, t, t, values) {
        Some((poly, _)) => Some(batch_recon_output(poly, t)),
        None => None,
    }
}

// === Extract original secrets (coefficients) x_1 .. x_{t+1} ===
pub fn batch_recon_output<F: FftField>(poly: DensePolynomial<F>, t: usize) -> Vec<F> {
    let mut result = poly.coeffs;
    result.resize(t + 1, F::zero());
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_poly::DenseUVPolynomial;
    use ark_std::test_rng;

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
        let t = 2;
        let n = 5;
        let secrets: Vec<Fr> = vec![Fr::from(3u64), Fr::from(4u64), Fr::from(5u64)];

        // Step 0: Generate shares
        let shares = generate_independent_shares(&secrets, t, n);

        // Simulate network inboxes: inboxes[j] = list of Msgs received by party j
        let mut inboxes: Vec<Vec<Msg<Fr>>> = vec![vec![]; n];

        // === Step 1: Each party computes y_j_share for all j and sends to P_j
        let vandermonde = make_vandermonde::<Fr>(n, secrets.len() - 1);
        for i in 0..n {
            let y_shares = apply_vandermonde(&vandermonde, &shares[i]);
            for j in 0..n {
                inboxes[j].push(Msg::Eval(i, y_shares[j]));
            }
        }

        // === Step 2–5: Each party interpolates y(x), evaluates at its own alpha, and sends Reveal
        let domain = GeneralEvaluationDomain::<Fr>::new(n).unwrap();
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

            if let Some((poly, _)) = robust_interpolate(n, t, t, received) {
                let y_j = poly.evaluate(&domain.element(j));
                reveals[j] = Some(y_j);
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

            if let Some((poly, _)) = robust_interpolate(n, t, t, y_values) {
                let result = batch_recon_output(poly, t);
                recovered_all.push(result);
            }
        }

        // === Check all recovered results match the original secrets
        for recovered in recovered_all {
            assert_eq!(recovered[..secrets.len()], secrets[..]);
        }
    }
}
