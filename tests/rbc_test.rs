#[cfg(test)]
mod tests {
    use mpc::common::rbc_store::{GenericMsgType, MsgType, MsgTypeAba, MsgTypeAcs, MsgTypeAvid};
    use mpc::common::utils::set_value_round;
    use mpc::common::{rbc::*, rbc_store::Msg};
    use mpc::RBC;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::mpsc;
    use tracing_subscriber;
    use rand::Rng;

    /// Helper function to set up message senders and receivers for the parties.
    async fn setup_channels(n: u32) -> (Vec<mpsc::Sender<Msg>>, Vec<mpsc::Receiver<Msg>>) {
        let mut senders = Vec::new();
        let mut receivers = Vec::new();
        for _ in 0..n {
            let (tx, rx) = mpsc::channel(500); // Create a channel with capacity 500
            senders.push(tx);
            receivers.push(rx);
        }
        (senders, receivers)
    }

    /// Helper function to set up parties with their respective RBC instances.
    async fn setup_parties<T: RBC>(
        n: u32,
        t: u32,
        k: u32,
        senders: Vec<mpsc::Sender<Msg>>,
    ) -> Result<Vec<(T, Arc<Network>)>, String> {
        let mut parties = Vec::with_capacity(n as usize);

        for i in 0..n {
            let rbc = T::new(i, n, t, k)?; // Create a new RBC instance for each party
            let net = Arc::new(Network {
                id: i,
                senders: senders.clone(), // Each party has the same senders
            });
            parties.push((rbc, net));
        }

        Ok(parties)
    }
    /// Helper function to spawn tasks that will run the parties' logic concurrently.
    async fn spawn_parties<T: RBC + Clone>(
        parties: &[(T, Arc<Network>)],
        mut receivers: Vec<mpsc::Receiver<Msg>>,
    ) {
        for (rbc, net) in parties.iter().cloned() {
            let mut rx = receivers.remove(0); // Get a receiver for the party
            tokio::spawn(async move {
                rbc.run_party(&mut rx, net).await; // Run the party logic
            });
        }
    }
    #[tokio::test]
    async fn test_bracha_rbc_basic() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_test_writer()
            .try_init();

        // Set the parameters
        let n = 4;
        let t = 1;
        let payload = b"Hello, MPC!".to_vec();
        let session_id = 12;

        let (senders, receivers) = setup_channels(n).await;
        let parties = setup_parties::<Bracha>(n, t, t + 1, senders)
            .await
            .expect("Failed to set up parties");
        spawn_parties(&parties, receivers).await;

        // Party 0 initiates broadcast
        let (bracha0, net0) = &parties[0];
        bracha0
            .init(payload.clone(), session_id, net0.clone())
            .await;

        // Give time for broadcast to propagate
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Check that all parties completed broadcast and agreed on output
        for (bracha, _) in &parties {
            let session_store = {
                let store_map = bracha.store.lock().await;
                store_map
                    .get(&session_id)
                    .cloned()
                    .expect(&format!("Party {} did not create session store", bracha.id))
            };

            // Lock the specific store for this session
            let s = session_store.lock().await;

            assert!(s.ended, "Broadcast not completed for party {}", bracha.id);
            assert_eq!(
                &s.output, &payload,
                "Incorrect payload at party {}",
                bracha.id
            );
        }
    }

    #[tokio::test]
    async fn test_multiple_sessions() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_test_writer()
            .try_init();

        let n = 4;
        let t = 1;
        let session_ids = vec![101, 202, 303];
        let payloads = vec![
            b"Payload A".to_vec(),
            b"Payload B".to_vec(),
            b"Payload C".to_vec(),
        ];

        let (senders, receivers) = setup_channels(n).await;
        let parties = setup_parties::<Bracha>(n, t, t + 1, senders)
            .await
            .expect("Failed to set up parties");
        spawn_parties(&parties, receivers).await;

        // Launch all sessions from party 0
        let (bracha0, net0) = &parties[0];
        for (i, sid) in session_ids.iter().enumerate() {
            bracha0.init(payloads[i].clone(), *sid, net0.clone()).await;
        }

        tokio::time::sleep(Duration::from_millis(200)).await;

        for (bracha, _) in &parties {
            let store = bracha.store.lock().await;
            for (i, sid) in session_ids.iter().enumerate() {
                let store_arc = store.get(sid).expect("Missing session");
                let s = store_arc.lock().await;

                assert!(
                    s.ended,
                    "Session {} not completed at party {}",
                    sid, bracha.id
                );
                assert_eq!(
                    &s.output, &payloads[i],
                    "Incorrect payload for session {}",
                    sid
                );
            }
        }
    }
    #[tokio::test]
    async fn test_multiple_sessions_different_party() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_test_writer()
            .try_init();

        let n = 4;
        let t = 1;
        let session_ids = vec![10, 20, 30, 40];
        let payloads = vec![
            b"From Party 0".to_vec(),
            b"From Party 1".to_vec(),
            b"From Party 2".to_vec(),
            b"From Party 3".to_vec(),
        ];

        let (senders, receivers) = setup_channels(n).await;
        let parties = setup_parties::<Bracha>(n, t, t + 1, senders)
            .await
            .expect("Failed to set up parties");
        spawn_parties(&parties, receivers).await;

        // Each party initiates one session
        for (i, (bracha, net)) in parties.iter().enumerate() {
            bracha
                .init(payloads[i].clone(), session_ids[i], net.clone())
                .await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Validate all sessions completed successfully and consistently
        for (bracha, _) in &parties {
            let store = bracha.store.lock().await;
            for (i, session_id) in session_ids.iter().enumerate() {
                let store_arc = store.get(session_id).expect("Missing session");
                let s = store_arc.lock().await;
                assert!(
                    s.ended,
                    "Session {} not completed at party {}",
                    session_id, bracha.id
                );
                assert_eq!(
                    &s.output, &payloads[i],
                    "Incorrect output at party {} for session {}",
                    bracha.id, session_id
                );
            }
        }
    }
    #[tokio::test]
    async fn test_out_of_order_delivery() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_test_writer()
            .try_init();

        let n = 4;
        let t = 1;
        let session_id = 11;
        let payload = b"out-of-order".to_vec();

        let (senders, receivers) = setup_channels(n).await;
        let parties = setup_parties::<Bracha>(n, t, t + 1, senders.clone())
            .await
            .expect("Failed to set up parties");
        spawn_parties(&parties, receivers).await;

        // Simulate sending READY before ECHO and INIT
        let sender_id = 1;
        let ready_msg = Msg::new(
            sender_id,
            0,
            session_id,
            payload.clone(),
            vec![],
            GenericMsgType::Bracha(MsgType::Ready),
            payload.clone().len(),
        );
        let echo_msg = Msg::new(
            sender_id,
            session_id,
            0,
            payload.clone(),
            vec![],
            GenericMsgType::Bracha(MsgType::Echo),
            payload.len(),
        );

        // Send READY first
        senders[2].send(ready_msg).await.unwrap();

        // Then ECHO
        senders[3].send(echo_msg).await.unwrap();

        // Party 0 initiates broadcast
        let (bracha0, net0) = &parties[0];
        bracha0
            .init(payload.clone(), session_id, net0.clone())
            .await;

        // Allow time for processing
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Check if parties reached consensus
        for (bracha, _) in &parties {
            let store = bracha.store.lock().await;
            if let Some(state) = store.get(&session_id) {
                let s = state.lock().await;

                if s.ended {
                    println!("Party {} ended with output: {:?}", bracha.id, s.output);
                } else {
                    println!("Party {} has not yet ended", bracha.id);
                }
            } else {
                println!("Party {} has a missing session", bracha.id);
            }
        }
    }

    async fn run_avid_rbc_test(n: u32, t: u32, k: u32, session_id: u32, payload: Vec<u8>) {
        println!("Running Avid RBC with n={}, t={}, k={}", n, t, k);

        let (senders, receivers) = setup_channels(n).await;
        let parties = setup_parties::<Avid>(n, t, k, senders)
            .await
            .expect("Failed to set up parties");

        spawn_parties(&parties, receivers).await;

        // Initiate broadcast from party 0
        let (avid0, net0) = &parties[0];
        avid0.init(payload.clone(), session_id, net0.clone()).await;

        // Allow time for propagation
        tokio::time::sleep(Duration::from_millis(100)).await;

        for (avid, _) in &parties {
            let session_store = {
                let store_map = avid.store.lock().await;
                store_map
                    .get(&session_id)
                    .cloned()
                    .expect(&format!("Party {} did not create session store", avid.id))
            };

            let s = session_store.lock().await;

            assert!(
                s.ended,
                "Broadcast not completed for party {} (n={}, t={}, k={})",
                avid.id, n, t, k
            );
            assert_eq!(
                &s.output, &payload,
                "Incorrect payload at party {} (n={}, t={}, k={})",
                avid.id, n, t, k
            );
        }
    }
    #[tokio::test]
    async fn test_avid_rbc_varied_parameters() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_test_writer()
            .try_init();

        let payload = b"Param test".to_vec();

        // Define (n, t, k) parameter sets
        let test_cases = vec![
            (4, 1, 2), // basic valid
            (5, 1, 3), // valid: n=5, t=1, k in [2,3]
            (7, 2, 3), // valid: n=7, t=2, k in [3, 3]
            (20, 5, 8),
            (20, 6, 7),
            (20, 6, 8),
        ];

        for (_, &(n, t, k)) in test_cases.iter().enumerate() {
            run_avid_rbc_test(n, t, k, 100, payload.clone()).await;
        }
    }

    #[tokio::test]
    async fn test_multiple_sessions_different_party_avid() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_test_writer()
            .try_init();

        let n = 4;
        let t = 1;
        let k = 2;

        let session_ids = vec![10, 20, 30, 40];
        let payloads = vec![
            b"From Party 0".to_vec(),
            b"From Party 1".to_vec(),
            b"From Party 2".to_vec(),
            b"From Party 3".to_vec(),
        ];

        let (senders, receivers) = setup_channels(n).await;
        let parties = setup_parties::<Avid>(n, t, k, senders)
            .await
            .expect("Failed to set up parties");

        spawn_parties(&parties, receivers).await;

        // Each party initiates one session
        for (i, (avid, net)) in parties.iter().enumerate() {
            avid.init(payloads[i].clone(), session_ids[i], net.clone())
                .await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Validate all sessions completed successfully and consistently
        for (avid, _) in &parties {
            let store = avid.store.lock().await;
            for (i, session_id) in session_ids.iter().enumerate() {
                let store_arc = store.get(session_id).expect("Missing session");
                let s = store_arc.lock().await;
                assert!(
                    s.ended,
                    "Session {} not completed at party {}",
                    session_id, avid.id
                );
                assert_eq!(
                    &s.output, &payloads[i],
                    "Incorrect output at party {} for session {}",
                    avid.id, session_id
                );
            }
        }
    }
    #[tokio::test]
    async fn test_out_of_order_delivery_avid() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_test_writer()
            .try_init();

        let n = 4;
        let t = 1;
        let k = 2;
        let session_id = 11;
        let payload = b"out-of-order".to_vec();

        let (senders, receivers) = setup_channels(n).await;
        let parties = setup_parties::<Avid>(n, t, k, senders.clone())
            .await
            .expect("Failed to set up parties");
        spawn_parties(&parties, receivers).await;

        // Simulate sending READY before ECHO and INIT
        let sender_id = 1;
        let ready_msg = Msg::new(
            sender_id,
            session_id,
            0,
            payload.clone(),
            vec![],
            GenericMsgType::Avid(MsgTypeAvid::Ready),
            payload.clone().len(),
        );
        let echo_msg = Msg::new(
            sender_id,
            session_id,
            0,
            payload.clone(),
            vec![],
            GenericMsgType::Avid(MsgTypeAvid::Echo),
            payload.len(),
        );

        // Send READY first
        senders[2].send(ready_msg).await.unwrap();

        // Then ECHO
        senders[3].send(echo_msg).await.unwrap();

        // Party 0 initiates broadcast
        let (avid0, net0) = &parties[0];
        avid0.init(payload.clone(), session_id, net0.clone()).await;

        // Allow time for processing
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Check if parties reached consensus
        for (avid, _) in &parties {
            let store = avid.store.lock().await;
            if let Some(state) = store.get(&session_id) {
                let s = state.lock().await;

                if s.ended {
                    println!("Party {} ended with output: {:?}", avid.id, s.output);
                } else {
                    println!("Party {} has not yet ended", avid.id);
                }
            } else {
                println!("Party {} has a missing session", avid.id);
            }
        }
    }
    #[tokio::test]
    async fn test_bracha_rbc_faulty_nodes() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_test_writer()
            .try_init();

        let n = 7;
        let t = 2;
        let payload = b"crash fault test".to_vec();
        let session_id = 2025;

        let (senders, receivers) = setup_channels(n).await;
        let parties = setup_parties::<Bracha>(n, t, t + 1, senders)
            .await
            .expect("Failed to set up parties");

        // Simulate t=2 faulty nodes (e.g., parties 0 and 1) by not spawning them
        let honest_parties = &parties[t as usize..]; // parties 2 to 6
        let honest_receivers = receivers.into_iter().skip(t as usize).collect::<Vec<_>>();

        // Spawn only honest nodes
        spawn_parties(honest_parties, honest_receivers).await;

        // One honest party initiates the broadcast
        let (initiator_rbc, initiator_net) = &honest_parties[0];
        initiator_rbc
            .init(payload.clone(), session_id, initiator_net.clone())
            .await;

        // Give protocol time to complete
        tokio::time::sleep(Duration::from_millis(5)).await;

        // Check agreement and completion among honest nodes
        for (rbc, _) in honest_parties {
            let session_store = {
                let store_map = rbc.store.lock().await;
                store_map
                    .get(&session_id)
                    .cloned()
                    .expect(&format!("Party {} did not create session store", rbc.id))
            };

            let s = session_store.lock().await;

            assert!(s.ended, "Broadcast not completed for party {}", rbc.id);
            assert_eq!(&s.output, &payload, "Incorrect payload at party {}", rbc.id);
        }
    }
    async fn test_avid_rbc_with_faulty_nodes(
        n: u32,
        t: u32,
        k: u32,
        session_id: u32,
        payload: Vec<u8>,
    ) {
        println!(
            "Running AVID RBC with crash faults: n={}, t={}, k={}",
            n, t, k
        );

        let (senders, receivers) = setup_channels(n).await;
        let parties = setup_parties::<Avid>(n, t, k, senders)
            .await
            .expect("Failed to set up parties");

        // Simulate t crash-faulty nodes: parties 0 to t-1 do nothing
        let honest_parties = &parties[t as usize..];
        let honest_receivers = receivers.into_iter().skip(t as usize).collect::<Vec<_>>();

        // Spawn only honest nodes
        spawn_parties(honest_parties, honest_receivers).await;

        // Initiate broadcast from one honest node
        let (initiator, initiator_net) = &honest_parties[0];
        initiator
            .init(payload.clone(), session_id, initiator_net.clone())
            .await;

        // Allow time for propagation
        tokio::time::sleep(Duration::from_millis(300)).await;

        for (avid, _) in honest_parties {
            let session_store = {
                let store_map = avid.store.lock().await;
                store_map
                    .get(&session_id)
                    .cloned()
                    .expect(&format!("Party {} did not create session store", avid.id))
            };

            let s = session_store.lock().await;

            assert!(
                s.ended,
                "Broadcast not completed for party {} (n={}, t={}, k={})",
                avid.id, n, t, k
            );
            assert_eq!(
                &s.output, &payload,
                "Incorrect payload at party {} (n={}, t={}, k={})",
                avid.id, n, t, k
            );
        }
    }
    #[tokio::test]
    async fn test_avid_rbc_crash_faults_varied_parameters() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_test_writer()
            .try_init();

        let payload = b"AVID crash fault test".to_vec();

        // (n, t, k) test configurations
        let test_cases = vec![(4, 1, 2), (5, 1, 3), (7, 2, 3), (20, 5, 8), (20, 6, 8)];

        for (i, &(n, t, k)) in test_cases.iter().enumerate() {
            println!("--- Test case {} ---", i + 1);
            test_avid_rbc_with_faulty_nodes(n, t, k, 100 + i as u32, payload.clone()).await;
        }
    }

    #[tokio::test]
    async fn test_common_coin() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_test_writer()
            .try_init();

        let n = 4;
        let t = 1;
        let k = t + 1;
        let session_id = 99;
        let round_id = 0;

        // Setup network
        let (senders, receivers) = setup_channels(n).await;
        // Setup ABA parties
        let parties = setup_parties::<ABA>(n, t, k, senders.clone())
            .await
            .expect("Failed to set up ABA parties");
        // Spawn their run loops
        spawn_parties(&parties, receivers).await;

        // Setup dealer and run key distribution
        let dealer = Dealer::new(n, t);
        let dealer_msg = Msg::new(
            0,
            session_id,
            round_id,
            vec![],
            vec![],
            GenericMsgType::ABA(MsgTypeAba::Key),
            0,
        );
        dealer
            .distribute_keys(
                dealer_msg,
                Arc::new(Network {
                    id: 0,
                    senders: senders.clone(),
                }),
            )
            .await;

        // Wait for keys to propagate and be set
        tokio::time::sleep(Duration::from_millis(25)).await;

        // Trigger coin generation on all parties
        for (aba, net) in &parties {
            let coin_msg = Msg::new(
                aba.id,
                session_id,
                round_id,
                vec![],
                vec![],
                GenericMsgType::ABA(MsgTypeAba::Coin),
                0,
            );
            aba.init_coin(coin_msg, net.clone()).await;
        }

        // Wait for coin signatures and combination
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Verify that each party has the coin
        let mut coin_value: Option<bool> = None;
        for (aba, _) in &parties {
            let coin_store_map = aba.coin.lock().await;
            let coin_store = coin_store_map
                .get(&session_id)
                .expect("Missing coin store")
                .clone();
            let store = coin_store.lock().await;

            let coin = store
                .coin(round_id)
                .unwrap_or_else(|| panic!("Party {} has not generated coin", aba.id));

            match coin_value {
                None => coin_value = Some(coin),
                Some(prev) => assert_eq!(
                    prev, coin,
                    "Mismatch in coin value at party {}: expected {}, got {}",
                    aba.id, prev, coin
                ),
            }
        }

        println!(
            "All parties successfully agreed on common coin: {:?}",
            coin_value
        );
    }

    #[tokio::test]
    async fn test_aba_agreement() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_test_writer()
            .try_init();

        // === Parameters ===
        let n = 4;
        let t = 1;
        let k = t + 1;
        let session_id = 42;
        let round_id = 0;

        // === Setup Channels ===
        let (senders, receivers) = setup_channels(n).await;

        // === Setup ABA Parties ===
        let parties = setup_parties::<ABA>(n, t, k, senders.clone())
            .await
            .expect("Failed to set up ABA parties");

        // === Spawn Each Party ===
        spawn_parties(&parties, receivers).await;

        // === Dealer Distributes Keys ===
        let dealer = Dealer::new(n, t);
        let key_dist_msg = Msg::new(
            0,
            session_id,
            round_id,
            vec![],
            vec![],
            GenericMsgType::ABA(MsgTypeAba::Key),
            0,
        );
        dealer
            .distribute_keys(
                key_dist_msg,
                Arc::new(Network {
                    id: 0,
                    senders: senders.clone(),
                }),
            )
            .await;

        // Wait for keys to be received
        tokio::time::sleep(Duration::from_millis(100)).await;

        // === Trigger ABA with diverse inputs ===
        let mut rng = rand::thread_rng();
        for (i, (aba, net)) in parties.iter().enumerate() {
            let input = rng.gen_bool(0.5); // Randomly true or false
            tracing::info!("Party {} input: {}", i, input);
            let payload = set_value_round(input, round_id);
            aba.init(payload, session_id, net.clone()).await;
        }
        // Allow the protocol to run
        tokio::time::sleep(Duration::from_millis(100)).await;

        // === Check Agreement Across All Parties ===
        let mut agreed_value: Option<bool> = None;

        for (aba, _) in &parties {
            let session_store = {
                let map = aba.store.lock().await;
                map.get(&session_id)
                    .cloned()
                    .expect(&format!("Party {} has no session store", aba.id))
            };
            let store = session_store.lock().await;

            assert!(store.ended, "ABA session not ended for party {}", aba.id);

            let output = store.output;
            match agreed_value {
                None => agreed_value = Some(output),
                Some(expected) => assert_eq!(
                    output, expected,
                    "Mismatch in ABA output at party {}",
                    aba.id
                ),
            }
        }

        println!("✅ All parties agreed on value: {}", agreed_value.unwrap());
    }

    #[tokio::test]
    async fn test_multiple_aba_sessions() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_test_writer()
            .try_init();

        // === Parameters ===
        let n = 4;
        let t = 1;
        let k = t + 1;
        let session_ids: Vec<u32> = vec![100, 101, 102, 103]; // One session per party

        // === Setup Channels ===
        let (senders, receivers) = setup_channels(n).await;

        // === Setup ABA Parties ===
        let parties = setup_parties::<ABA>(n, t, k, senders.clone())
            .await
            .expect("Failed to set up ABA parties");

        // === Spawn Each Party ===
        spawn_parties(&parties, receivers).await;

        // === Dealer Distributes Keys ===
        let dealer = Dealer::new(n, t);
        let key_dist_msg = Msg::new(
            0,
            0,
            0,
            vec![],
            vec![],
            GenericMsgType::ABA(MsgTypeAba::Key),
            0,
        );
        dealer
            .distribute_keys(
                key_dist_msg,
                Arc::new(Network {
                    id: 0,
                    senders: senders.clone(),
                }),
            )
            .await;

        tokio::time::sleep(Duration::from_millis(100)).await;

        // === Trigger multiple ABA sessions per party ===
        let mut rng = rand::thread_rng();
        for session_id in &session_ids {
            for (i, (aba, net)) in parties.iter().enumerate() {
                let input = rng.gen_bool(0.5); // Randomly true or false
                tracing::info!("Party {} input: {}", i, input);
                let payload = set_value_round(input, 0);
                aba.init(payload, *session_id as u32, net.clone()).await;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // Allow the protocol to run
        tokio::time::sleep(Duration::from_millis(1000)).await;

        // === Validate ABA Output Agreement per session ===
        for session_id in session_ids {
            let mut agreed_value: Option<bool> = None;

            for (aba, _) in &parties {
                let session_store = {
                    let map = aba.store.lock().await;
                    map.get(&session_id).cloned().expect(&format!(
                        "Party {} missing ABA session {}",
                        aba.id, session_id
                    ))
                };
                let store = session_store.lock().await;

                assert!(
                    store.ended,
                    "ABA session {} not ended at party {}",
                    session_id, aba.id
                );

                let output = store.output;
                match agreed_value {
                    None => agreed_value = Some(output),
                    Some(expected) => assert_eq!(
                        output, expected,
                        "Mismatch in ABA output at party {} for session {}",
                        aba.id, session_id
                    ),
                }
            }

            println!(
                "✅ Session {}: All parties agreed on value: {}",
                session_id,
                agreed_value.unwrap()
            );
        }
    }

    #[tokio::test]
    async fn test_acs_with_simulated_rbc_outputs() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_test_writer()
            .try_init();

        let n = 4;
        let t = 1;
        let k = 2;

        // === Setup Channels for ACS ===
        let (senders, receivers) = setup_channels(n).await;

        // === Create ACS instances for each party ===
        let mut acs_instances = Vec::new();
        let mut acs_parties = Vec::new();

        for i in 0..n {
            let acs = ACS::new(i as u32, n as u32, t as u32, k as u32)
                .expect("Failed to create ACS instance");
            let net = Arc::new(Network {
                id: i,
                senders: senders.clone(),
            });

            acs_parties.push((acs.aba.clone(), net.clone()));
            acs_instances.push(acs);
        }

        // === Spawn ACS protocol handlers ===
        spawn_parties(&acs_parties, receivers).await;

        // === Dealer distributes keys ===
        let dealer = Dealer::new(n, t);
        let key_msg = Msg::new(
            0,
            0,
            0,
            vec![],
            vec![],
            GenericMsgType::ABA(MsgTypeAba::Key),
            0,
        );
        dealer
            .distribute_keys(
                key_msg,
                Arc::new(Network {
                    id: 0,
                    senders: senders.clone(),
                }),
            )
            .await;

        // Wait briefly for keys to be received
        tokio::time::sleep(Duration::from_millis(5)).await;

        // === Simulate RBC output payloads ===
        let fake_rbc_outputs = vec![
            b"Message from Party 0".to_vec(),
            b"Message from Party 1".to_vec(),
            b"Message from Party 2".to_vec(),
            b"Message from Party 3".to_vec(),
        ];

        // === Feed RBC outputs into each party's ACS instance ===
        for (session_id, payload) in fake_rbc_outputs.iter().enumerate() {
            for (i, (_, net)) in acs_parties.iter().enumerate() {
                let msg = Msg {
                    sender_id: i as u32,
                    session_id: session_id as u32,
                    round_id: 0,
                    msg_type: GenericMsgType::Acs(MsgTypeAcs::Acs),
                    payload: payload.clone(),
                    metadata: vec![],
                    msg_len: payload.len(),
                };

                acs_instances[i as usize].init(msg, net.clone()).await;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        // Wait for ACS to complete
        tokio::time::sleep(Duration::from_millis(300)).await;

        // === Validate ACS Outputs ===
        let mut commonsubsets = Vec::new();
        for i in 0..n {
            let mut store = acs_instances[i as usize].store.lock().await;

            assert!(store.ended, "Party {}: ACS has not terminated", i);

            assert!(
                store.get_aba_output_one_count() >= n - t,
                "Party {}: insufficient ACS outputs",
                i
            );

            commonsubsets.push(store.commonsubset.clone());
        }

        // All parties must agree on the same common subset
        for i in 1..n {
            assert_eq!(
                commonsubsets[0], commonsubsets[i as usize],
                "Mismatch in ACS outputs between party 0 and party {}",
                i
            );
        }
    }
    #[tokio::test]
    async fn test_acs() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_test_writer()
            .try_init();

        let n = 4;
        let t = 1;
        let k = 2;

        let session_ids = vec![0, 1, 2, 3];
        let payloads = vec![
            b"From Party 0".to_vec(),
            b"From Party 1".to_vec(),
            b"From Party 2".to_vec(),
            b"From Party 3".to_vec(),
        ];
        //--------------------------------------------------RBC--------------------------------------------------
        let (senders, receivers) = setup_channels(n).await;
        let parties = setup_parties::<Avid>(n, t, k, senders)
            .await
            .expect("Failed to set up parties");

        spawn_parties(&parties, receivers).await;

        // Each party initiates one RBC session
        for (i, (avid, net)) in parties.iter().enumerate() {
            avid.init(payloads[i].clone(), session_ids[i], net.clone())
                .await;
        }

        // Wait for all RBC instances to terminate
        tokio::time::sleep(Duration::from_millis(500)).await;

        //--------------------------------------------------ACS--------------------------------------------------

        // === Setup Channels for ACS ===
        let (senders1, receivers1) = setup_channels(n).await;

        // Create ACS instances for each party
        let mut acs_instances = Vec::new();
        let mut acs_parties = Vec::with_capacity(n as usize);
        for i in 0..n {
            let acs = ACS::new(i as u32, n as u32, t as u32, k as u32)
                .expect("Failed to create ACS instance");
            let net = Arc::new(Network {
                id: i,
                senders: senders1.clone(), // Each party has the same senders
            });
            acs_parties.push((acs.aba.clone(), net));
            acs_instances.push(acs);
        }

        // === Spawn Each Party for ACS===
        spawn_parties(&acs_parties, receivers1).await;

        // === Dealer Distributes Keys ===
        let dealer = Dealer::new(n, t);
        let key_dist_msg = Msg::new(
            0,
            0,
            0,
            vec![],
            vec![],
            GenericMsgType::ABA(MsgTypeAba::Key),
            0,
        );
        dealer
            .distribute_keys(
                key_dist_msg,
                Arc::new(Network {
                    id: 0,
                    senders: senders1.clone(),
                }),
            )
            .await;
        // Wait for keys to be received
        tokio::time::sleep(Duration::from_millis(5)).await;

        // -------------------------------Verify RBC termination and initiate ACS-------------------------------
        for session_id in &session_ids {
            for (i, (avid, _)) in parties.iter().enumerate() {
                
                let store = avid.store.lock().await;

                // Check if RBC has terminated for this session
                let session_store = store
                    .get(session_id)
                    .expect(&format!("Party {} missing RBC session {}", i, session_id));
                let session = session_store.lock().await;

                // Check if this RBC has successfully terminated with output
                assert!(
                    session.ended,
                    "RBC has not terminated yet at {}",
                    session_id
                );

                println!(
                    "Party {} received RBC output for session {}: {:?}",
                    i, session_id, session.output
                );

                // Now initiate ACS with the RBC output
                let msg = Msg {
                    sender_id: i as u32,
                    session_id: *session_id,
                    round_id: 0,
                    msg_type: GenericMsgType::Acs(MsgTypeAcs::Acs),
                    payload: session.output.clone(),
                    metadata: vec![],
                    msg_len: session.output.len(),
                };
                drop(session);
                // Initiate ACS for this party with the RBC result
                acs_instances[i].init(msg, acs_parties[i].1.clone()).await;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;

        }

        // Allow time for ACS to complete
        tokio::time::sleep(Duration::from_millis(300)).await;

        // -------------------------------------------Validate ACS-------------------------------------------
        for i in 0..n {
            let mut store_lock = acs_instances[i as usize].store.lock().await;
            // Check if ACS has values
            assert!(
                store_lock.ended,
                "ACS has not terminated yet at {} party",
                i
            );
            // Verify ACS contains at least n-t values
            assert!(
                store_lock.get_aba_output_one_count() >= (n - t),
                "Party {} ACS should contain at least {} values, got {}",
                i,
                n - t,
                store_lock.get_aba_output_one_count()
            );
        }

        // Cross-check consistency between parties
        let mut outputs = Vec::new();

        for i in 0..n {
            let store_lock = acs_instances[i as usize].store.lock().await;
            let output = &store_lock.commonsubset;
            outputs.push(output.clone());
        }

        // Check all parties have same output for this session
        for i in 1..n {
            assert_eq!(
                outputs[0], outputs[i as usize],
                "ACS output differs between parties 0 and {}",
                i
            );
        }
    }
}
