pub mod utils;
#[cfg(test)]
mod tests {
    use crate::utils::test_utils::{fan_in_inboxes, setup_tracing};
    use std::{collections::HashMap, sync::Arc, time::Duration};
    use stoffelcrypto::{
        common::{gf2k::field::BinaryField, gf2k::field::Gf256, gf2k::share::GfShare, ProtocolSessionId},
        honeybadger::{
            gf_mul::gf_multiplication::GfMultiply, gf_triple_gen::GfBeaverTriple, ProtocolType,
            SessionId, WrappedMessage,
        },
    };
    use stoffelmpc_network::fake_network::{FakeNetworkConfig, SenderId};
    use tokio::{sync::mpsc::Receiver, task::JoinSet};
    use tracing::{info, warn};

    fn construct_e2e_input_mul(
        n_parties: usize,
        n_triples: usize,
        threshold: usize,
    ) -> (
        (Vec<Gf256>, Vec<Gf256>, Vec<Gf256>),
        Vec<Vec<GfBeaverTriple<Gf256>>>,
    ) {
        let mut rng = ark_std::test_rng();
        let mut secrets_a = Vec::new();
        let mut secrets_b = Vec::new();
        let mut secrets_c = Vec::new();
        let mut per_party_triples: Vec<Vec<GfBeaverTriple<Gf256>>> = vec![Vec::new(); n_parties];

        for _ in 0..n_triples {
            let a_secret = Gf256::random(&mut rng);
            let b_secret = Gf256::random(&mut rng);
            let c_secret = a_secret * b_secret;

            let shares_a = GfShare::compute_shares(a_secret, n_parties, threshold, &mut rng)
                .expect("share a creation failed");
            let shares_b = GfShare::compute_shares(b_secret, n_parties, threshold, &mut rng)
                .expect("share b creation failed");
            let shares_c = GfShare::compute_shares(c_secret, n_parties, threshold, &mut rng)
                .expect("share c creation failed");

            secrets_a.push(a_secret);
            secrets_b.push(b_secret);
            secrets_c.push(c_secret);

            for p in 0..n_parties {
                per_party_triples[p].push(GfBeaverTriple::new(
                    shares_a[p].clone(),
                    shares_b[p].clone(),
                    shares_c[p].clone(),
                ));
            }
        }
        ((secrets_a, secrets_b, secrets_c), per_party_triples)
    }

    // Steps: setup network -> generate Beaver triples -> prepare x/y inputs -> init on every
    // node -> route both batch-recon and direct-open (remainder) traffic -> collect results ->
    // compare against x*y.
    async fn mul_e2e(n_parties: usize, t: usize, no_of_mul: usize) {
        setup_tracing();
        use stoffelmpc_network::fake_network::{FakeInnerNetwork, FakeNetwork};

        let mut rng = ark_std::test_rng();
        let session_id = SessionId::new(ProtocolType::GfMul, SessionId::pack_slot(123, 0, 0), 111);

        let config = FakeNetworkConfig::new(200);
        let (inner, mut receivers, _) = FakeInnerNetwork::new(n_parties, None, config);
        let network: Vec<_> = (0..n_parties)
            .map(|id| Arc::new(FakeNetwork::new(id, inner.clone())))
            .collect();

        let (_, beaver_triples) = construct_e2e_input_mul(n_parties, no_of_mul, t);

        let mut x_values = Vec::new();
        let mut y_values = Vec::new();
        let mut x_inputs_per_node = vec![Vec::new(); n_parties];
        let mut y_inputs_per_node = vec![Vec::new(); n_parties];

        for _ in 0..no_of_mul {
            let x_value = Gf256::random(&mut rng);
            x_values.push(x_value);
            let y_value = Gf256::random(&mut rng);
            y_values.push(y_value);

            let shares_x = GfShare::compute_shares(x_value, n_parties, t, &mut rng).unwrap();
            let shares_y = GfShare::compute_shares(y_value, n_parties, t, &mut rng).unwrap();

            for p in 0..n_parties {
                x_inputs_per_node[p].push(shares_x[p].clone());
                y_inputs_per_node[p].push(shares_y[p].clone());
            }
        }

        let mut mul_nodes: Vec<_> = (0..n_parties)
            .map(|id| GfMultiply::<Gf256>::new(id, n_parties, t).unwrap())
            .collect();

        for i in 0..n_parties {
            mul_nodes[i]
                .init(
                    session_id,
                    x_inputs_per_node[i].clone(),
                    y_inputs_per_node[i].clone(),
                    beaver_triples[i].clone(),
                    network[i].clone(),
                )
                .await
                .unwrap_or_else(|e| panic!("init failed for node {i}: {e:?}"));
        }
        info!("nodes initialized");

        let mut set = JoinSet::new();
        for node in &mul_nodes {
            let mut mul_node = node.clone();
            let receiver = std::mem::take(&mut receivers[node.id]);
            let net_clone = network[node.id].clone();
            let inbox: Vec<(SenderId, Receiver<Vec<u8>>)> = receiver
                .into_iter()
                .enumerate()
                .map(|(i, r)| (SenderId::Node(i), r))
                .collect();
            let mut merged_rx = fan_in_inboxes(inbox);

            set.spawn(async move {
                while let Some(msg_bytes) = merged_rx.recv().await {
                    let wrapped: WrappedMessage = match bincode::deserialize(&msg_bytes.1) {
                        Ok(m) => m,
                        Err(_) => {
                            warn!("failed to deserialize into wrapped message");
                            continue;
                        }
                    };
                    match &wrapped {
                        WrappedMessage::GfMult(msg) => {
                            if let Err(e) = mul_node
                                .process(msg.sender, msg.session_id, msg.payload.clone())
                                .await
                            {
                                warn!("direct open processing error: {e}");
                            }
                        }
                        WrappedMessage::GfBatchRecon(batch_msg) => {
                            match batch_msg.session_id.calling_protocol() {
                                Some(ProtocolType::GfMul) => {
                                    mul_node
                                        .batch_recon
                                        .process(batch_msg.clone(), Arc::clone(&net_clone))
                                        .await
                                        .expect("batch recon error");
                                    mul_node.drain_batch_recon_output().await.unwrap();
                                }
                                _ => panic!("Unexpected caller of batch recon"),
                            }
                        }
                        _ => panic!("Unexpected protocol type"),
                    }
                }
            });
        }
        info!("receiver task spawned");

        let mut final_results = HashMap::<usize, Vec<GfShare<Gf256>>>::new();
        for i in 0..n_parties {
            let node = &mul_nodes[i];
            let final_shares = node
                .wait_for_result(session_id, Duration::from_millis(1500))
                .await
                .unwrap();

            assert_eq!(final_shares.len(), no_of_mul);
            for mul_share in &final_shares {
                assert_eq!(mul_share.degree, t);
                assert_eq!(mul_share.id, node.id);
            }
            final_results.insert(node.id, final_shares);
        }

        let mut per_multiplication_shares: Vec<Vec<GfShare<Gf256>>> = vec![Vec::new(); no_of_mul];
        for pid in 0..n_parties {
            for i in 0..no_of_mul {
                per_multiplication_shares[i].push(final_results.get(&pid).unwrap()[i].clone());
            }
        }

        for i in 0..no_of_mul {
            let shares_for_i = per_multiplication_shares[i][0..=(2 * t)].to_vec();
            let (_, z_rec) = GfShare::recover_secret(&shares_for_i, n_parties, t)
                .expect("interpolate failed");
            let expected = x_values[i] * y_values[i];

            assert_eq!(z_rec, expected, "multiplication mismatch at index {i}");
        }
    }

    #[tokio::test]
    async fn gf_mul_e2e_batch_recon_and_remainder() {
        // 2x batch recon for chunks of size t+1=4, 1x direct-open for the residue 2
        mul_e2e(10, 3, 10).await;
    }

    #[tokio::test]
    async fn gf_mul_e2e_only_batch_recon() {
        // 2x batch recon for chunks of size t+1=4, 0x direct-open (residue 0)
        mul_e2e(10, 3, 8).await;
    }

    #[tokio::test]
    async fn gf_mul_e2e_only_remainder() {
        // 0x batch recon (no full chunk), 1x direct-open for the residue 3
        mul_e2e(10, 3, 3).await;
    }
}
