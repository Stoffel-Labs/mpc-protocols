pub mod utils;
#[cfg(test)]
mod tests {
    use crate::utils::test_utils::{fan_in_inboxes, setup_tracing};
    use std::{collections::HashMap, sync::Arc, time::Duration};
    use stoffelcrypto::{
        common::{
            gf2k::field::BinaryField,
            gf2k::field::Gf256,
            gf2k::share::{GfShare, GfShareWire},
            ProtocolSessionId,
        },
        honeybadger::{
            gf_mul::{gf_multiplication::GfMultiply, GfMultReconstructionMessage, OpeningPolicy},
            gf_triple_gen::GfBeaverTriple,
            ProtocolType, SessionId, WrappedMessage,
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
        mul_e2e_with(n_parties, t, no_of_mul, OpeningPolicy::Batched, &[]).await
    }

    /// [`mul_e2e`] under an explicit [`OpeningPolicy`], with `corrupt` naming parties whose
    /// direct-open shares are tampered with in flight.
    ///
    /// Tampering is applied at every recipient, which is the strongest form: one corrupt sender
    /// broadcasting a share off the polynomial to everyone at once. `id` and `degree` are left
    /// alone deliberately — `process` rejects a mismatch on either, so altering them would test
    /// the sender-authentication check rather than the robustness of the decode.
    async fn mul_e2e_with(
        n_parties: usize,
        t: usize,
        no_of_mul: usize,
        policy: OpeningPolicy,
        corrupt: &[usize],
    ) {
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
            .map(|id| GfMultiply::<Gf256>::new_with_policy(id, n_parties, t, policy).unwrap())
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

        // Proves the tamper really fired. Without it a typo in the corruption path would make the
        // robustness test pass by never attacking anything.
        let tampered = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let mut set = JoinSet::new();
        for node in &mul_nodes {
            let mut mul_node = node.clone();
            let receiver = std::mem::take(&mut receivers[node.id]);
            let net_clone = network[node.id].clone();
            let corrupt: Vec<usize> = corrupt.to_vec();
            let tampered = Arc::clone(&tampered);
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
                            let payload = if corrupt.contains(&msg.sender) {
                                let inner: GfMultReconstructionMessage<Gf256> =
                                    bincode::deserialize(&msg.payload)
                                        .expect("direct-open payload");
                                // Off the polynomial. The index and degree are no longer on the
                                // wire to touch — the receiver derives them from the
                                // authenticated sender and its own threshold — so the tampered
                                // body is still attributed to this sender at the right degree
                                // and reaches the decoder as a genuine error symbol.
                                let bump = |w: &GfShareWire<Gf256>| {
                                    GfShareWire::from_elements(
                                        w.elements().iter().map(|&e| e + Gf256(1)).collect(),
                                    )
                                };
                                let inner = GfMultReconstructionMessage::<Gf256> {
                                    a_sub_x: bump(&inner.a_sub_x),
                                    b_sub_y: bump(&inner.b_sub_y),
                                };
                                tampered.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                bincode::serialize(&inner).expect("reserialize")
                            } else {
                                msg.payload.clone()
                            };
                            if let Err(e) =
                                mul_node.process(msg.sender, msg.session_id, payload).await
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

        // Only honest parties owe an output: guaranteed output delivery is a promise to them.
        let honest: Vec<usize> = (0..n_parties).filter(|p| !corrupt.contains(p)).collect();
        assert!(
            honest.len() >= 2 * t + 1,
            "test must leave at least 2t+1 honest parties"
        );

        let mut final_results = HashMap::<usize, Vec<GfShare<Gf256>>>::new();
        for &i in &honest {
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

        if !corrupt.is_empty() {
            assert!(
                tampered.load(std::sync::atomic::Ordering::Relaxed) > 0,
                "no direct-open message was actually tampered with - the attack never fired"
            );
        }

        let mut per_multiplication_shares: Vec<Vec<GfShare<Gf256>>> = vec![Vec::new(); no_of_mul];
        for &pid in &honest {
            for i in 0..no_of_mul {
                per_multiplication_shares[i].push(final_results.get(&pid).unwrap()[i].clone());
            }
        }

        for i in 0..no_of_mul {
            let shares_for_i = per_multiplication_shares[i][0..=(2 * t)].to_vec();
            let (_, z_rec) =
                GfShare::recover_secret(&shares_for_i, n_parties, t).expect("interpolate failed");
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

    #[tokio::test]
    async fn direct_policy_opens_a_whole_wave_all_to_all() {
        // `OpeningPolicy::Direct` routes every value through the one-round path, including the
        // full `t+1`-chunks that `Batched` would have packed into a batch reconstruction. 12 is a
        // clean multiple of `t+1 = 4`, so under `Batched` the direct path would carry *nothing* —
        // which is exactly why this is the case that pins the policy rather than the remainder.
        let batched = OpeningPolicy::Batched.plan(10, 3, 12);
        assert_eq!((batched.batched, batched.direct), (12, 0));
        let direct = OpeningPolicy::Direct.plan(10, 3, 12);
        assert_eq!((direct.batched, direct.direct), (0, 12));
        mul_e2e_with(10, 3, 12, OpeningPolicy::Direct, &[]).await;
    }

    #[tokio::test]
    async fn auto_sends_a_narrow_wave_direct_at_every_party_count() {
        // The crossover is a **width**, not a threshold. A 12-wide wave is far below it at every
        // `n` the crate is measured at, so `Auto` opens it in one round — including at `n = 10`,
        // where the rule this replaced (`Direct` only at `t <= 1`) batched it into two rounds and
        // 4n*49 = 1960 bytes/party against the direct path's 10*(52+24) = 760.
        for (n, t) in [(4usize, 1usize), (7, 2), (10, 3), (13, 4)] {
            let plan = OpeningPolicy::Auto.plan(n, t, 12);
            assert_eq!((plan.batched, plan.direct), (0, 12), "n={n}");
            assert_eq!(plan.rounds(), 1, "n={n}");
        }
        mul_e2e_with(4, 1, 8, OpeningPolicy::Auto, &[]).await;
        mul_e2e_with(10, 3, 12, OpeningPolicy::Auto, &[]).await;
    }

    #[tokio::test]
    async fn auto_batches_a_wide_wave_and_pads_its_last_group() {
        // Past the crossover `Auto` batches — and never sends the sub-`t+1` remainder directly,
        // which is the traffic that used to be 31% of A2B's online bytes at `n = 13` for 0.8% of
        // its multiplications. 250 is past the crossover at `t = 3` (238) and is not a multiple
        // of `t+1 = 4`, so this is the padding case: 252 values handed to batch reconstruction,
        // the last two duplicates, 250 real ones returned.
        let plan = OpeningPolicy::Auto.plan(10, 3, 250);
        assert_eq!((plan.batched, plan.padded, plan.direct), (250, 252, 0));
        assert_eq!(plan.rounds(), 2);
        // The e2e run is the assertion that matters: it checks all 250 products, so a padding
        // value that survived into the output, or a truncation that dropped a real one, is a
        // wrong answer here rather than a silent shift. Corruption is not layered on top because
        // this plan puts no direct-open message on the wire at all, which is the point of it —
        // `mul_e2e_with`'s adversary tampers with direct messages and would never fire.
        mul_e2e_with(10, 3, 250, OpeningPolicy::Auto, &[]).await;
    }

    #[tokio::test]
    async fn direct_openings_are_robust_against_t_corrupt_openers() {
        // The point of keeping the direct path at degree `t`: it is ROBUST, not detect-and-abort.
        // Three corrupt parties send shares off the polynomial to everyone, and the honest seven
        // must still finish with the right product and no abort - guaranteed output delivery.
        //
        // This is also the tightest possible OEC case, and the reason `process` must re-attempt
        // the decode on every arrival rather than propagate the first failure: with `e = t = 3`
        // errors, unique decoding needs `m >= (t+1) + 2e = 10` received shares, so every attempt
        // at `m = 7, 8, 9` fails and only the one at `m = n = 10` succeeds.
        //
        // The corrupt parties are the *low* indices on purpose. The fan-in delivers roughly in
        // sender order, so corrupting 0..2 puts all three error symbols inside the first `2t+1`
        // arrivals and forces those failing attempts to happen; corrupting the high indices
        // instead lets the first `2t+1` be all honest and the decode succeeds immediately,
        // which passes without ever exercising the retry.
        mul_e2e_with(10, 3, 12, OpeningPolicy::Direct, &[0, 1, 2]).await;
    }

    #[tokio::test]
    async fn direct_openings_are_robust_at_n4() {
        // The same argument at the party count where `Auto` opens directly at every width:
        // `e = t = 1`, unique decoding needs `m >= 2 + 2 = 4 = n`, so again only the final
        // arrival decodes. `Auto` here rather than `Direct` so this covers the configuration a
        // four-party deployment actually gets without asking for it.
        mul_e2e_with(4, 1, 8, OpeningPolicy::Auto, &[0]).await;
    }
}
