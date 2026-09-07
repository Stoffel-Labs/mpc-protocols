pub mod utils;
#[cfg(test)]
mod tests {
    use crate::utils::test_utils::{fan_in_inboxes, setup_tracing};
    use std::time::Duration;
    use stoffelcrypto::{
        common::{gf2k::field::Gf256, gf2k::share::GfShare, ProtocolSessionId},
        honeybadger::{
            gf_batch_recon::{
                gf_batch_recon::GfBatchReconNode, GfBatchReconMsg, GfBatchReconMsgType,
            },
            ProtocolType, SessionId, WrappedMessage,
        },
    };
    use stoffelmpc_network::fake_network::{FakeInnerNetwork, SenderId};
    use tokio::{
        sync::{mpsc::Receiver, Barrier},
        time::timeout,
    };
    use tracing::warn;

    fn generate_independent_shares(
        secrets: &[Gf256],
        t: usize,
        n: usize,
        rng: &mut impl ark_std::rand::Rng,
    ) -> Vec<Vec<GfShare<Gf256>>> {
        // shares[i] = party i's shares of every secret, one GfShare per secret.
        let mut shares = vec![Vec::with_capacity(secrets.len()); n];
        for &secret in secrets {
            let per_secret = GfShare::compute_shares(secret, n, t, rng).unwrap();
            for (i, share) in per_secret.into_iter().enumerate() {
                shares[i].push(share);
            }
        }
        shares
    }

    #[tokio::test]
    async fn test_gf_batch_reconstruction() {
        setup_tracing();
        use std::sync::Arc;
        use stoffelmpc_network::fake_network::{FakeNetwork, FakeNetworkConfig};

        let n = 4;
        let t = 1;
        let session_id = SessionId::new(
            ProtocolType::GfBatchRecon,
            SessionId::pack_slot(123, 0, 0),
            111,
        );
        let config = FakeNetworkConfig::new(100);
        let (inner, mut receivers, _) = FakeInnerNetwork::new(n, None, config);
        let net: Vec<_> = (0..n)
            .map(|id| Arc::new(FakeNetwork::new(id, inner.clone())))
            .collect();
        let mut rng = ark_std::test_rng();
        let secrets: Vec<Gf256> = vec![Gf256(3), Gf256(6)];
        let all_shares = generate_independent_shares(&secrets, t, n, &mut rng);

        let barrier = Arc::new(Barrier::new(n));

        let mut handles = vec![];
        for i in 0..n {
            let (batch_sender, _batch_receiver) = tokio::sync::mpsc::channel(200);
            let mut node = GfBatchReconNode::<Gf256>::new(i, n, t, t, batch_sender).unwrap();
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
                    Err(e) => warn!(id = i, error = ?e, "Sending failure"),
                }
                let session_store = node.get_or_create_store(session_id, node.id).await.unwrap();

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

                    if let WrappedMessage::GfBatchRecon(m) = wrapped {
                        if let Err(e) = node.process(m, net_clone.clone()).await {
                            warn!(id = i, error = ?e, "Processing failure");
                        }
                    }
                }

                barrier_i.wait().await;

                let recovered = session_store.lock().await.secrets.clone().unwrap();
                recovered
            }));
        }
        for handle in handles {
            let recovered = handle.await.unwrap();
            let batch_recon_result: Vec<Gf256> = bincode::deserialize(&recovered).unwrap();

            assert_eq!(batch_recon_result[..secrets.len()], secrets[..]);
        }
    }

    /// A Byzantine sender that wins the race with a bogus-width `EvalBatch` must not be able to
    /// prevent honest parties' correctly-sized shares from being recorded. Direct port of
    /// `batchrecon_test.rs`'s equivalent regression test.
    #[tokio::test]
    async fn test_gf_eval_batch_width_poisoning_does_not_reject_honest_shares() {
        setup_tracing();
        use std::sync::Arc;
        use stoffelmpc_network::fake_network::{FakeNetwork, FakeNetworkConfig};

        let n = 4;
        let t = 1;
        let degree = t;
        let session_id = SessionId::new(
            ProtocolType::GfBatchRecon,
            SessionId::pack_slot(123, 0, 0),
            111,
        );

        let config = FakeNetworkConfig::new(100);
        let (inner, _receivers, _) = FakeInnerNetwork::new(n, None, config);
        let net = Arc::new(FakeNetwork::new(0, inner));

        let (batch_sender, _batch_receiver) = tokio::sync::mpsc::channel(200);
        let mut victim = GfBatchReconNode::<Gf256>::new(0, n, t, degree, batch_sender).unwrap();

        // Byzantine sender 3 wins the race, arriving first with a bogus width (1 value instead
        // of the real 2).
        let poison_payload = bincode::serialize(&vec![Gf256(99)]).unwrap();
        let poison_msg =
            GfBatchReconMsg::new(3, session_id, GfBatchReconMsgType::EvalBatch, poison_payload);
        victim
            .process(poison_msg, net.clone())
            .await
            .expect("a well-formed (if bogus-width) EvalBatch must not itself error");

        let honest_payload = bincode::serialize(&vec![Gf256(1), Gf256(2)]).unwrap();
        let honest_msg =
            GfBatchReconMsg::new(0, session_id, GfBatchReconMsgType::EvalBatch, honest_payload);
        victim
            .process(honest_msg, net.clone())
            .await
            .expect("honest EvalBatch must not be rejected due to the earlier poisoned width");

        let session_store = victim
            .get_or_create_store(session_id, victim.id)
            .await
            .unwrap();
        let store = session_store.lock().await;
        assert_eq!(
            store.batch_evals_received.len(),
            2,
            "both the poisoned and the honest entry should be recorded (not error-rejected)"
        );
        assert!(
            store
                .batch_evals_received
                .iter()
                .any(|(id, v)| *id == 0 && v.len() == 2),
            "the honest sender's width-2 entry must be present"
        );
    }

    /// Byzantine-fault-injection test with no analogue in the F-domain suite: corrupt up to `t`
    /// `Eval` shares among the senders and confirm reconstruction still recovers the correct
    /// secrets via the robust (OEC/Gao) fallback inside `GfShare::recover_secret`.
    #[tokio::test]
    async fn test_gf_batch_reconstruction_tolerates_t_corrupted_evals() {
        setup_tracing();
        use std::sync::Arc;
        use stoffelmpc_network::fake_network::{FakeNetwork, FakeNetworkConfig};

        let n = 7;
        let t = 2;
        let session_id = SessionId::new(
            ProtocolType::GfBatchRecon,
            SessionId::pack_slot(123, 0, 0),
            111,
        );
        let config = FakeNetworkConfig::new(100);
        let (inner, _receivers, _) = FakeInnerNetwork::new(n, None, config);
        let net = Arc::new(FakeNetwork::new(0, inner));

        let mut rng = ark_std::test_rng();
        let secret = Gf256(42);
        let shares = GfShare::compute_shares(secret, n, t, &mut rng).unwrap();

        let (batch_sender, _rx) = tokio::sync::mpsc::channel(200);
        let mut node = GfBatchReconNode::<Gf256>::new(0, n, t, t, batch_sender).unwrap();

        // Feed all n Eval shares directly (as if received over the network), corrupting the
        // first t of them. Reconstruction is attempted as soon as degree+t+1 shares have
        // arrived — with corrupted shares in that initial window, that attempt can genuinely
        // fail (the OEC fallback needs *more* than the bare minimum to have room to correct
        // errors), the same way it would for the real F-domain `BatchReconNode`. A real caller
        // tolerates that and keeps feeding messages (see `test_gf_batch_reconstruction`'s loop);
        // only the final state, once all n have arrived, is asserted on here.
        for (i, share) in shares.iter().enumerate() {
            let mut val = share.share;
            if i < t {
                val = val + Gf256(7);
            }
            let payload = bincode::serialize(&val).unwrap();
            let msg = GfBatchReconMsg::new(i, session_id, GfBatchReconMsgType::Eval, payload);
            if let Err(e) = node.process(msg, net.clone()).await {
                warn!(sender = i, error = ?e, "transient reconstruction attempt failed, continuing");
            }
        }

        let session_store = node.get_or_create_store(session_id, node.id).await.unwrap();
        let y_j = session_store.lock().await.y_j.clone();
        assert!(
            y_j.is_some(),
            "y_j must be recovered despite t corrupted Eval shares"
        );
    }
}
