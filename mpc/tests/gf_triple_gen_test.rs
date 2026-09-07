pub mod utils;
#[cfg(test)]
mod tests {
    use crate::utils::test_utils::{fan_in_inboxes, setup_tracing};
    use itertools::izip;
    use std::{sync::Arc, time::Duration};
    use stoffelcrypto::{
        common::{gf2k::field::BinaryField, gf2k::field::Gf256, gf2k::share::GfShare, ProtocolSessionId},
        honeybadger::{
            gf_double_share::GfDoubleShamirShare, gf_triple_gen::gf_triple_generation::GfTripleGenNode,
            triple_gen::triple_generation::ProtocolState, ProtocolType, SessionId, WrappedMessage,
        },
    };
    use stoffelmpc_network::fake_network::{FakeInnerNetwork, FakeNetwork, FakeNetworkConfig, SenderId};
    use tokio::sync::{mpsc::Receiver, Mutex};

    fn create_nodes(n_parties: usize, threshold: usize) -> Vec<Arc<Mutex<GfTripleGenNode<Gf256>>>> {
        (0..n_parties)
            .map(|id| Arc::new(Mutex::new(GfTripleGenNode::new(id, n_parties, threshold).unwrap())))
            .collect()
    }

    // Return vectors that contain vectors of inputs of init_handler for each node
    #[allow(clippy::type_complexity)]
    fn get_triple_init_test_shares(
        n_shares: usize,
        n_parties: usize,
        t: usize,
    ) -> (
        Vec<Vec<GfShare<Gf256>>>,
        Vec<Vec<GfShare<Gf256>>>,
        Vec<Vec<GfDoubleShamirShare<Gf256>>>,
        Vec<Gf256>,
        Vec<Gf256>,
        Vec<Gf256>,
    ) {
        let mut random_shares_a = vec![vec![]; n_parties];
        let mut random_shares_b = vec![vec![]; n_parties];
        let mut randousha_pairs = vec![vec![]; n_parties];
        let mut a_values = vec![];
        let mut b_values = vec![];
        let mut pairs_values = vec![];

        let mut rng = ark_std::test_rng();

        for _ in 0..n_shares {
            let a = Gf256::random(&mut rng);
            a_values.push(a);
            let shares_a = GfShare::compute_shares(a, n_parties, t, &mut rng).unwrap();
            let b = Gf256::random(&mut rng);
            b_values.push(b);
            let shares_b = GfShare::compute_shares(b, n_parties, t, &mut rng).unwrap();

            let r = Gf256::random(&mut rng);
            pairs_values.push(r);

            let shares_r_t = GfShare::compute_shares(r, n_parties, t, &mut rng).unwrap();
            let shares_r_2t = GfShare::compute_shares(r, n_parties, 2 * t, &mut rng).unwrap();

            for p in 0..n_parties {
                random_shares_a[p].push(shares_a[p].clone());
                random_shares_b[p].push(shares_b[p].clone());
                randousha_pairs[p].push(GfDoubleShamirShare::new(
                    shares_r_t[p].clone(),
                    shares_r_2t[p].clone(),
                ));
            }
        }
        (
            random_shares_a,
            random_shares_b,
            randousha_pairs,
            a_values,
            b_values,
            pairs_values,
        )
    }

    /// Spawns receiver tasks for all nodes. GfTripleGen has no wire messages of its own — it is
    /// driven entirely by its embedded `GfBatchReconNode`'s completions, so this only needs to
    /// route `WrappedMessage::GfBatchRecon` traffic into it and drain completions afterward.
    fn spawn_receiver_tasks(
        nodes: &[Arc<Mutex<GfTripleGenNode<Gf256>>>],
        mut receivers: Vec<Vec<Receiver<Vec<u8>>>>,
        network: Vec<Arc<FakeNetwork>>,
    ) {
        for (i, node) in nodes.iter().enumerate() {
            let triple_gen_node = Arc::clone(node);
            let receiver = receivers.remove(0);
            let inbox: Vec<(SenderId, Receiver<Vec<u8>>)> = receiver
                .into_iter()
                .enumerate()
                .map(|(i, r)| (SenderId::Node(i), r))
                .collect();
            let mut merged_rx = fan_in_inboxes(inbox);
            let net_clone = network[i].clone();

            tokio::spawn(async move {
                loop {
                    let msg = match merged_rx.recv().await {
                        Some(msg) => msg,
                        None => break,
                    };
                    let wrapped: WrappedMessage = match bincode::deserialize(&msg.1) {
                        Ok(m) => m,
                        Err(_) => continue,
                    };
                    let mut node_bind = triple_gen_node.lock().await;

                    match wrapped {
                        WrappedMessage::GfBatchRecon(batch_msg) => {
                            node_bind
                                .batch_recon_node
                                .process(batch_msg, net_clone.clone())
                                .await
                                .unwrap();
                            node_bind.drain_batch_recon_output().await.unwrap();
                        }
                        _ => break,
                    }
                }
            });
        }
    }

    #[tokio::test]
    async fn test_gf_triple_gen_e2e() {
        setup_tracing();
        let n_parties = 13;
        let threshold = 2;
        let n_shares = 2 * threshold + 1;
        let session_id = SessionId::new(ProtocolType::GfTriple, SessionId::pack_slot(123, 0, 0), 111);
        let (random_shares_a, random_shares_b, randousha_pairs, a_values, b_values, _) =
            get_triple_init_test_shares(n_shares, n_parties, threshold);

        let config = FakeNetworkConfig::new(100);
        let (inner, receivers, _) = FakeInnerNetwork::new(n_parties, None, config);
        let network: Vec<_> = (0..n_parties)
            .map(|id| Arc::new(FakeNetwork::new(id, inner.clone())))
            .collect();
        let nodes = create_nodes(n_parties, threshold);

        for (i, node) in nodes.iter().enumerate() {
            node.lock()
                .await
                .init(
                    random_shares_a[i].clone(),
                    random_shares_b[i].clone(),
                    randousha_pairs[i].clone(),
                    session_id,
                    network[i].clone(),
                )
                .await
                .unwrap();
        }
        spawn_receiver_tasks(&nodes, receivers, network.clone());
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut a_shares = vec![vec![GfShare::new(Gf256::zero(), 0, 0); n_parties]; n_shares];
        let mut b_shares = vec![vec![GfShare::new(Gf256::zero(), 0, 0); n_parties]; n_shares];
        let mut ab_shares = vec![vec![GfShare::new(Gf256::zero(), 0, 0); n_parties]; n_shares];
        for p in 0..n_parties {
            let node = nodes[p].lock().await;
            let storage = node.storage.lock().await;
            let (_, _, triple_store) = storage.get(&session_id).unwrap();
            let triple_data = triple_store.lock().await;
            assert!(matches!(triple_data.protocol_state, ProtocolState::Finished));

            for (i, triples) in triple_data.protocol_output.iter().enumerate() {
                a_shares[i][p] = triples.a.clone();
                b_shares[i][p] = triples.b.clone();
                ab_shares[i][p] = triples.mult.clone();
            }
        }

        for i in 0..n_shares {
            let (_, a) = GfShare::recover_secret(&a_shares[i], n_parties, threshold).unwrap();
            let (_, b) = GfShare::recover_secret(&b_shares[i], n_parties, threshold).unwrap();
            let (_, ab) = GfShare::recover_secret(&ab_shares[i], n_parties, threshold).unwrap();
            assert_eq!(a * b, ab);
            assert_eq!(a, a_values[i]);
            assert_eq!(b, b_values[i]);
        }
    }

    #[tokio::test]
    async fn test_gf_triple_init_test_shares() {
        let n_parties = 15;
        let threshold = 3;
        let n_shares = 5;
        let (random_shares_a, random_shares_b, randousha_pairs, a_values, b_values, pairs_values) =
            get_triple_init_test_shares(n_shares, n_parties, threshold);
        for i in 0..n_shares {
            let mut a_i = vec![];
            let mut b_i = vec![];
            let mut randousha_pairs_t_i = vec![];
            let mut randousha_pairs_2t_i = vec![];
            for p in 0..n_parties {
                a_i.push(random_shares_a[p][i].clone());
                b_i.push(random_shares_b[p][i].clone());
                randousha_pairs_t_i.push(randousha_pairs[p][i].degree_t.clone());
                randousha_pairs_2t_i.push(randousha_pairs[p][i].degree_2t.clone());
            }
            assert_eq!(
                GfShare::recover_secret(&a_i, n_parties, threshold).unwrap().1,
                a_values[i]
            );
            assert_eq!(
                GfShare::recover_secret(&b_i, n_parties, threshold).unwrap().1,
                b_values[i]
            );
            assert_eq!(
                GfShare::recover_secret_naive(&randousha_pairs_t_i, n_parties, threshold)
                    .unwrap()
                    .1,
                pairs_values[i]
            );
            assert_eq!(
                GfShare::recover_secret_naive(&randousha_pairs_2t_i, n_parties, threshold)
                    .unwrap()
                    .1,
                pairs_values[i]
            );
        }

        // test compute open(ab-r)
        let mut sub_shares_deg_2t_all = Vec::new();

        for p in 0..n_parties {
            let random_shares_a_p = random_shares_a[p].clone();
            let random_shares_b_p = random_shares_b[p].clone();
            let randousha_pairs_p = randousha_pairs[p].clone();
            let mut sub_shares_deg_2t = Vec::new();
            for (share_a, share_b, ran_dou_sha) in
                izip!(&random_shares_a_p, &random_shares_b_p, &randousha_pairs_p)
            {
                let mult_share_deg_2t = share_a.share_mul(share_b).unwrap();
                let sub_share_deg_2t = (mult_share_deg_2t - ran_dou_sha.degree_2t.clone()).unwrap();
                sub_shares_deg_2t.push(sub_share_deg_2t);
            }
            sub_shares_deg_2t_all.push(sub_shares_deg_2t);
        }
        for i in 0..n_shares {
            // shares for share i from every party
            let mut shares_i = vec![];
            for p in 0..n_parties {
                let share_i_p = sub_shares_deg_2t_all[p][i].clone();
                shares_i.push(share_i_p);
            }
            let r = GfShare::recover_secret(&shares_i, n_parties, threshold).unwrap();
            assert_eq!(r.1, (a_values[i] * b_values[i]) - pairs_values[i]);
        }
    }
}
