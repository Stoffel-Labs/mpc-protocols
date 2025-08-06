#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;
    use ark_ff::{FftField, Field, One, Zero};
    use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_std::test_rng;
    use std::{marker::PhantomData, time::Duration};
    use stoffelmpc_mpc::{
        common::SecretSharingScheme,
        honeybadger::{
            batch_recon::{
                apply_vandermonde, batch_recon::BatchReconNode, make_vandermonde,
                BatchReconContentType, BatchReconMsg, BatchReconMsgType,
            },
            robust_interpolate::robust_interpolate::RobustShamirShare,
        },
    };
    use tokio::time::timeout;
    use tracing::warn;

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
                    n: n,
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
        let session_id = 111;
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
                    BatchReconContentType::TripleGenMessage,
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
                        received.push(RobustShamirShare::new(val, i, n, t));
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
                        y_values.push(RobustShamirShare::new(*y_j, j, n, t));
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

    #[tokio::test]
    async fn test_batch_reconstruction() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_test_writer()
            .try_init();
        use std::sync::Arc;
        use stoffelmpc_network::fake_network::{FakeNetwork, FakeNetworkConfig};

        let n = 4;
        let t = 1;
        let session_id = 111;
        let config = FakeNetworkConfig::new(100);
        let (network, mut receivers) = FakeNetwork::new(n, config);
        let net = Arc::new(network);

        let secrets: Vec<Fr> = vec![Fr::from(3u64), Fr::from(6u64)];
        let all_shares = generate_independent_shares(&secrets, t, n);

        let mut handles = vec![];
        for i in 0..n {
            let mut node = BatchReconNode::new(i, n, t).unwrap();
            let shares = all_shares[i].clone();
            let net_clone = Arc::clone(&net);
            let mut recv = receivers.remove(0);

            handles.push(tokio::spawn(async move {
                match node
                    .init_batch_reconstruct(
                        &shares,
                        session_id,
                        BatchReconContentType::TripleGenMessage,
                        Arc::clone(&net_clone),
                    )
                    .await
                {
                    Ok(()) => {}
                    Err(e) => warn!(id =i,error = ?e,"Sending failure"),
                }

                while node.secrets.is_none() {
                    let msg = timeout(Duration::from_secs(2), recv.recv()).await;
                    match msg {
                        Ok(Some(msg)) => match node.process(msg, net_clone.clone()).await {
                            Ok(()) => {}
                            Err(e) => warn!(id =i,error = ?e ,"Broadcasting failure"),
                        },
                        Ok(None) => break, // Channel closed
                        Err(_) => {
                            panic!("Node {} timed out waiting for a message", i);
                        }
                    }
                }

                // Return recovered secrets
                node.secrets.clone().unwrap()
            }));
        }
        for handle in handles {
            let recovered = handle.await.unwrap();
            assert_eq!(recovered[..secrets.len()], secrets[..]);
        }
    }
}
