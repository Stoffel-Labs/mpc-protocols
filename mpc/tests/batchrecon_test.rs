pub mod utils;
#[cfg(test)]
mod tests {
    use crate::utils::test_utils::{fan_in_inboxes, generate_independent_shares, setup_tracing};
    use ark_bls12_381::Fr;
    use ark_ff::Zero;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use std::time::Duration;
    use stoffelmpc_mpc::{
        common::{
            share::{apply_vandermonde, make_vandermonde},
            ProtocolSessionId, SecretSharingScheme,
        },
        honeybadger::{
            batch_recon::{batch_recon::BatchReconNode, BatchReconMsg, BatchReconMsgType},
            robust_interpolate::robust_interpolate::RobustShare,
            ProtocolType, SessionId, WrappedMessage,
        },
    };
    use stoffelmpc_network::fake_network::{FakeInnerNetwork, SenderId};
    use tokio::{
        sync::{mpsc::Receiver, Barrier},
        time::timeout,
    };
    use tracing::warn;

    #[test]
    fn test_batch_reconstruct_sequential() {
        setup_tracing();

        let t = 1;
        let n = 4;
        let secrets: Vec<Fr> = vec![Fr::from(3u64), Fr::from(4u64)];
        let session_id = SessionId::new(
            ProtocolType::BatchRecon,
            SessionId::pack_slot(123, 0, 0),
            111,
        );
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
                let msg = BatchReconMsg::new(i, session_id, BatchReconMsgType::Eval, payload);

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
                        received.push(RobustShare::new(val, i, t));
                        if received.len() == 2 * t + 1 {
                            break;
                        }
                    }
                }
            }

            if let Ok((_, value)) = RobustShare::recover_secret(&received, n, t) {
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
                        y_values.push(RobustShare::new(*y_j, j, t));
                        if y_values.len() == 2 * t + 1 {
                            break;
                        }
                    }
                }
            }
            if let Ok((mut poly, _)) = RobustShare::recover_secret(&y_values, n, t) {
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
        setup_tracing();
        use std::sync::Arc;
        use stoffelmpc_network::fake_network::{FakeNetwork, FakeNetworkConfig};

        let n = 4;
        let t = 1;
        let session_id = SessionId::new(
            ProtocolType::BatchRecon,
            SessionId::pack_slot(123, 0, 0),
            111,
        );
        let config = FakeNetworkConfig::new(100);
        let (inner, mut receivers, _) = FakeInnerNetwork::new(n, None, config);
        let net: Vec<_> = (0..n)
            .map(|id| Arc::new(FakeNetwork::new(id, inner.clone())))
            .collect();
        let secrets: Vec<Fr> = vec![Fr::from(3u64), Fr::from(6u64)];
        let all_shares = generate_independent_shares(&secrets, t, n);

        let barrier = Arc::new(Barrier::new(n));

        let mut handles = vec![];
        for i in 0..n {
            let (batch_sender, _batch_receiver) = tokio::sync::mpsc::channel(200);
            let mut node = BatchReconNode::new(i, n, t, t, batch_sender).unwrap();
            let shares = all_shares[i].clone();
            let net_clone = net[i].clone();
            let inboxes = receivers[i].drain(..).collect::<Vec<_>>();
            let inbox: Vec<(SenderId, Receiver<Vec<u8>>)> = inboxes
                .into_iter()
                .enumerate()
                .map(|(i, r)| (SenderId::Node(i), r))
                .collect();
            let mut merged_rx = fan_in_inboxes(inbox);
            let barrier_i = barrier.clone();

            handles.push(tokio::spawn(async move {
                match node
                    .init_batch_reconstruct(&shares, session_id, net_clone.clone())
                    .await
                {
                    Ok(()) => {}
                    Err(e) => warn!(id =i,error = ?e,"Sending failure"),
                }
                // Lock the session store to update the session state.
                let session_store = node.get_or_create_store(session_id, node.id).await.unwrap().unwrap();

                while {
                    let s = session_store.lock().await;
                    s.secrets.is_none()
                } {
                    let (_from, raw) = match timeout(Duration::from_secs(2), merged_rx.recv()).await
                    {
                        Ok(Some(v)) => v,
                        _ => continue,
                    };
                    let wrapped: WrappedMessage = match bincode::deserialize(&raw) {
                        Ok(m) => m,
                        Err(_) => {
                            warn!("Malformed or unrecognized message format.");
                            continue;
                        }
                    };

                    if let WrappedMessage::BatchRecon(m) = wrapped {
                        if let Err(e) = node.process(m, net_clone.clone()).await {
                            warn!(id = i, error = ?e, "Processing failure");
                        }
                    }
                }

                barrier_i.wait().await; // synchronize, so no receivers are dropped prematurely

                // Return recovered secrets
                let recovered = session_store.lock().await.secrets.clone().unwrap();
                recovered
            }));
        }
        for handle in handles {
            let recovered = handle.await.unwrap();
            let batch_recon_result: Vec<Fr> =
                CanonicalDeserialize::deserialize_compressed(recovered.as_slice()).unwrap();

            assert_eq!(batch_recon_result[..secrets.len()], secrets[..]);
        }
    }
}
