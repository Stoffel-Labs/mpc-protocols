#[cfg(test)]
mod tests {
    use rand::Rng;
    use std::time::Duration;
    use std::{collections::HashMap, sync::Arc};
    use stoffelmpc_common::rbc::rbc_store::AbaStore;
    use stoffelmpc_common::{
        rbc::{
            rbc::{Avid, Bracha, Dealer, ABA},
            rbc_store::{GenericMsgType, Msg, MsgType, MsgTypeAba, MsgTypeAvid},
            utils::set_value_round,
            RbcError,
        },
        RBC,
    };
    use stoffelmpc_network::fake_network::{FakeNetwork, FakeNetworkConfig};
    use stoffelmpc_network::Network;
    use tokio::sync::Mutex;
    use tokio::{sync::mpsc, time::timeout};
    use tracing::warn;
    use tracing_subscriber;

    /// Helper function to set up parties,Network,Receivers
    async fn setup_network_and_parties<T: RBC, N: Network>(
        n: u32,
        t: u32,
        k: u32,
        buffer_size: usize,
    ) -> Result<(Vec<T>, Arc<FakeNetwork>, Vec<mpsc::Receiver<Vec<u8>>>), RbcError> {
        let config = FakeNetworkConfig::new(buffer_size);
        let (network, receivers) = FakeNetwork::new(n as usize, config);
        let net = Arc::new(network);

        let mut parties = Vec::with_capacity(n as usize);
        for i in 0..n {
            let rbc = T::new(i, n, t, k)?; // Create a new RBC instance for each party
            parties.push(rbc);
        }
        Ok((parties, net, receivers))
    }

    ///Spawn parties for rbc
    pub async fn spawn_parties<T, N>(
        parties: &[T],
        receivers: Vec<mpsc::Receiver<Vec<u8>>>,
        net: Arc<N>,
    ) where
        T: RBC + Clone + Send + Sync + 'static,
        N: Network + Send + Sync + 'static,
    {
        for (rbc, mut rx) in parties.iter().cloned().zip(receivers.into_iter()) {
            let net_clone = Arc::clone(&net);

            tokio::spawn(async move {
                while let Some(msg) = rx.recv().await {
                    if let Err(e) = rbc.process(msg, Arc::clone(&net_clone)).await {
                        warn!(error = %e, "Message processing failed");
                    }
                }
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

        let (parties, net, receivers) =
            setup_network_and_parties::<Bracha, FakeNetwork>(n, t, t + 1, 500)
                .await
                .expect("Failed to set up parties");
        spawn_parties(&parties, receivers, net.clone()).await;

        // Party 0 initiates broadcast
        let bracha0 = &parties[0];
        let _ = bracha0.init(payload.clone(), session_id, net).await;

        // Give time for broadcast to propagate
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Check that all parties completed broadcast and agreed on output
        for bracha in &parties {
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

        let (parties, net, receivers) =
            setup_network_and_parties::<Bracha, FakeNetwork>(n, t, t + 1, 500)
                .await
                .expect("Failed to set up parties");
        spawn_parties(&parties, receivers, net.clone()).await;

        // Launch all sessions from party 0
        let bracha0 = &parties[0];
        for (i, sid) in session_ids.iter().enumerate() {
            let _ = bracha0.init(payloads[i].clone(), *sid, net.clone()).await;
        }

        tokio::time::sleep(Duration::from_millis(200)).await;

        for bracha in &parties {
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

        let (parties, net, receivers) =
            setup_network_and_parties::<Bracha, FakeNetwork>(n, t, t + 1, 500)
                .await
                .expect("Failed to set up parties");
        spawn_parties(&parties, receivers, net.clone()).await;

        // Each party initiates one session
        for (i, bracha) in parties.iter().enumerate() {
            let _ = bracha
                .init(payloads[i].clone(), session_ids[i], net.clone())
                .await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Validate all sessions completed successfully and consistently
        for bracha in &parties {
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

        let (parties, net, receivers) =
            setup_network_and_parties::<Bracha, FakeNetwork>(n, t, t + 1, 500)
                .await
                .expect("Failed to set up parties");
        spawn_parties(&parties, receivers, net.clone()).await;

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
        let _ = parties[sender_id as usize]
            .send(ready_msg, net.clone(), 2)
            .await
            .expect("Sending ready failed");

        // Then ECHO
        let _ = parties[sender_id as usize]
            .send(echo_msg, net.clone(), 3)
            .await
            .expect("Sending Echo failed");

        // Party 0 initiates broadcast
        let bracha0 = &parties[0];
        let _ = bracha0.init(payload.clone(), session_id, net.clone()).await;

        // Allow time for processing
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Check if parties reached consensus
        for bracha in &parties {
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

        let (parties, net, receivers) =
            setup_network_and_parties::<Avid, FakeNetwork>(n, t, t + 1, 500)
                .await
                .expect("Failed to set up parties");
        spawn_parties(&parties, receivers, net.clone()).await;

        // Initiate broadcast from party 0
        let avid0 = &parties[0];
        let _ = avid0.init(payload.clone(), session_id, net.clone()).await;

        // Allow time for propagation
        tokio::time::sleep(Duration::from_millis(100)).await;

        for avid in &parties {
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

        let session_ids = vec![10, 20, 30, 40];
        let payloads = vec![
            b"From Party 0".to_vec(),
            b"From Party 1".to_vec(),
            b"From Party 2".to_vec(),
            b"From Party 3".to_vec(),
        ];

        let (parties, net, receivers) =
            setup_network_and_parties::<Avid, FakeNetwork>(n, t, t + 1, 500)
                .await
                .expect("Failed to set up parties");
        spawn_parties(&parties, receivers, net.clone()).await;

        // Each party initiates one session
        for (i, avid) in parties.iter().enumerate() {
            let _ = avid
                .init(payloads[i].clone(), session_ids[i], net.clone())
                .await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Validate all sessions completed successfully and consistently
        for avid in &parties {
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

        let (parties, net, receivers) =
            setup_network_and_parties::<Avid, FakeNetwork>(n, t, k, 500)
                .await
                .expect("Failed to set up parties");
        spawn_parties(&parties, receivers, net.clone()).await;

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
        let _ = parties[sender_id as usize]
            .send(ready_msg, net.clone(), 2)
            .await
            .expect("Sending ready failed");

        // Then ECHO
        let _ = parties[sender_id as usize]
            .send(echo_msg, net.clone(), 3)
            .await
            .expect("Sending ready failed");

        // Party 0 initiates broadcast
        let avid0 = &parties[0];
        let _ = avid0.init(payload.clone(), session_id, net.clone()).await;

        // Allow time for processing
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Check if parties reached consensus
        for avid in &parties {
            let store = avid.store.lock().await;
            if let Some(state) = store.get(&session_id) {
                let s = state.lock().await;

                assert!(s.ended, "Party {} has not yet ended", avid.id);

                println!("Party {} ended with output: {:?}", avid.id, s.output);
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

        let (parties, net, receivers) =
            setup_network_and_parties::<Bracha, FakeNetwork>(n, t, t + 1, 500)
                .await
                .expect("Failed to set up parties");

        // Simulate t=2 faulty nodes (e.g., parties 0 and 1) by not spawning them
        let honest_parties = &parties[t as usize..]; // parties 2 to 6
        let honest_receivers = receivers.into_iter().skip(t as usize).collect::<Vec<_>>();

        // Spawn only honest nodes
        spawn_parties(&honest_parties, honest_receivers, net.clone()).await;

        // One honest party initiates the broadcast
        let initiator_rbc = &honest_parties[0];
        let _ = initiator_rbc
            .init(payload.clone(), session_id, net.clone())
            .await;

        // Give protocol time to complete
        tokio::time::sleep(Duration::from_millis(5)).await;

        // Check agreement and completion among honest nodes
        for rbc in honest_parties {
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

        let (parties, net, receivers) =
            setup_network_and_parties::<Avid, FakeNetwork>(n, t, k, 500)
                .await
                .expect("Failed to set up parties");

        // Simulate t crash-faulty nodes: parties 0 to t-1 do nothing
        let honest_parties = &parties[t as usize..];
        let honest_receivers = receivers.into_iter().skip(t as usize).collect::<Vec<_>>();

        // Spawn only honest nodes
        spawn_parties(&honest_parties, honest_receivers, net.clone()).await;

        // Initiate broadcast from one honest node
        let initiator = &honest_parties[0];
        let _ = initiator
            .init(payload.clone(), session_id, net.clone())
            .await
            .unwrap_or_else(|e| warn!("Initiator {} failed : {:?}", initiator.id, e));

        // Allow time for propagation
        tokio::time::sleep(Duration::from_millis(300)).await;

        for avid in honest_parties {
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

        let (parties, net, receivers) = setup_network_and_parties::<ABA, FakeNetwork>(n, t, k, 500)
            .await
            .expect("Failed to set up parties");

        spawn_parties(&parties, receivers, net.clone()).await;

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
        let _ = dealer.distribute_keys(dealer_msg, net.clone()).await;

        // Wait for keys to propagate and be set
        tokio::time::sleep(Duration::from_millis(25)).await;

        // Trigger coin generation on all parties
        for aba in &parties {
            let coin_msg = Msg::new(
                aba.id,
                session_id,
                round_id,
                vec![],
                vec![],
                GenericMsgType::ABA(MsgTypeAba::Coin),
                0,
            );
            let _ = aba.init_coin(coin_msg, net.clone()).await;
        }

        // Wait for coin signatures and combination
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Verify that each party has the coin
        let mut coin_value: Option<bool> = None;
        for aba in &parties {
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

        let (parties, net, receivers) = setup_network_and_parties::<ABA, FakeNetwork>(n, t, k, 1000)
            .await
            .expect("Failed to set up parties");
        spawn_parties(&parties, receivers, net.clone()).await;

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
        let _ = dealer.distribute_keys(key_dist_msg, net.clone()).await;

        tokio::time::sleep(Duration::from_millis(100)).await;

        // === Trigger ABA with diverse inputs ===
        let mut rng = rand::thread_rng();
        let inputs: Vec<bool> = (0..parties.len()).map(|_| rng.gen_bool(0.5)).collect();
        for (i, &input) in inputs.iter().enumerate() {
            tracing::info!("Party {} input: {}", i, input);
        }

        let init_futures = parties.iter().zip(inputs).map(|(aba, input)| {
            let payload = set_value_round(input, round_id);
            aba.init(payload, session_id, net.clone())
        });

        futures::future::join_all(init_futures).await;

        // === Wait for all ABA sessions to end and store the results ===
        let timeout_duration = Duration::from_secs(10);
        let poll_interval = Duration::from_millis(50);
        let mut session_results: HashMap<usize, Arc<Mutex<AbaStore>>> = HashMap::new();

        let result = timeout(timeout_duration, async {
            loop {
                for aba in &parties {
                    if session_results.contains_key(&(aba.id as usize)) {
                        continue;
                    }

                    let store_opt = {
                        let map = aba.store.lock().await;
                        map.get(&session_id).cloned()
                    };

                    if let Some(store) = store_opt {
                        let session = store.lock().await;
                        if session.ended {
                            session_results.insert(aba.id.try_into().unwrap(), store.clone());
                        }
                    }
                }

                if session_results.len() == parties.len() {
                    break;
                }

                tokio::time::sleep(poll_interval).await;
            }
        })
        .await;

        assert!(result.is_ok(), "Timed out waiting for ABA session to end");

        // === Check Agreement Across All Parties ===
        let mut agreed_value: Option<bool> = None;
        for aba in &parties {
            let store = session_results
                .get(&(aba.id as usize))
                .expect("Missing completed session")
                .lock()
                .await;

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

        let (parties, net, receivers) = setup_network_and_parties::<ABA, FakeNetwork>(n, t, k, 1000)
            .await
            .expect("Failed to set up parties");
        spawn_parties(&parties, receivers, net.clone()).await;

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
        let _ = dealer.distribute_keys(key_dist_msg, net.clone()).await;

        tokio::time::sleep(Duration::from_millis(100)).await;

        // === Trigger multiple ABA sessions per party ===
        let mut rng = rand::thread_rng();
        for session_id in &session_ids {
            for (i, aba) in parties.iter().enumerate() {
                let input = rng.gen_bool(0.5); // Randomly true or false
                tracing::info!("Party {} input: {}", i, input);
                let payload = set_value_round(input, 0);
                let _ = aba.init(payload, *session_id, net.clone()).await;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // === Wait for all ABA sessions to end and collect their stores ===
        use std::collections::HashMap;
        let timeout_duration = Duration::from_secs(50);
        let poll_interval = Duration::from_millis(50);
        let mut all_results: HashMap<u32, HashMap<usize, Arc<Mutex<AbaStore>>>> = HashMap::new();

        let result = timeout(timeout_duration, async {
            loop {
                for &session_id in &session_ids {
                    let entry = all_results.entry(session_id).or_default();

                    for aba in &parties {
                        if entry.contains_key(&(aba.id as usize)) {
                            continue;
                        }

                        let store_opt = {
                            let map = aba.store.lock().await;
                            map.get(&session_id).cloned()
                        };

                        if let Some(store) = store_opt {
                            let session = store.lock().await;
                            if session.ended {
                                entry.insert(aba.id.try_into().unwrap(), store.clone());
                            }
                        }
                    }
                }

                let all_done = all_results.len() == session_ids.len()
                    && all_results.values().all(|s| s.len() == n as usize);

                if all_done {
                    break;
                }

                tokio::time::sleep(poll_interval).await;
            }
        })
        .await;

        assert!(
            result.is_ok(),
            "Timed out waiting for all ABA sessions to end"
        );

        // === Validate ABA Output Agreement per session ===
        for session_id in session_ids {
            let results = all_results
                .get(&session_id)
                .expect("Missing session results");
            let mut agreed_value: Option<bool> = None;

            for aba in &parties {
                let store = results
                    .get(&(aba.id as usize))
                    .expect("Missing session store")
                    .lock()
                    .await;

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

    // #[tokio::test]
    // async fn test_acs_with_simulated_rbc_outputs() {
    //     let _ = tracing_subscriber::fmt()
    //         .with_max_level(tracing::Level::DEBUG)
    //         .with_test_writer()
    //         .try_init();

    //     let n = 4;
    //     let t = 1;
    //     let k = 2;

    //     // === Setup Channels for ACS ===
    //     let (_, net, receivers) = setup_network_and_parties::<ABA, FakeNetwork>(n, t, k,1000)
    //         .await
    //         .expect("Failed to set up parties");

    //     // === Create ACS instances for each party ===
    //     let mut acs_instances = Vec::new();
    //     let mut acs_parties = Vec::new();

    //     for i in 0..n {
    //         let acs = ACS::new(i as u32, n as u32, t as u32, k as u32)
    //             .expect("Failed to create ACS instance");
    //         acs_parties.push(acs.aba.clone());
    //         acs_instances.push(acs);
    //     }

    //     // === Spawn ACS protocol handlers ===
    //     spawn_parties(&acs_parties, receivers, net.clone()).await;

    //     // === Dealer distributes keys ===
    //     let dealer = Dealer::new(n, t);
    //     let key_msg = Msg::new(
    //         0,
    //         0,
    //         0,
    //         vec![],
    //         vec![],
    //         GenericMsgType::ABA(MsgTypeAba::Key),
    //         0,
    //     );
    //     let _ = dealer.distribute_keys(key_msg, net.clone()).await;

    //     // Wait briefly for keys to be received
    //     tokio::time::sleep(Duration::from_millis(5)).await;

    //     // === Simulate RBC output payloads ===
    //     let fake_rbc_outputs = vec![
    //         b"Message from Party 0".to_vec(),
    //         b"Message from Party 1".to_vec(),
    //         b"Message from Party 2".to_vec(),
    //         b"Message from Party 3".to_vec(),
    //     ];

    //     // === Feed RBC outputs into each party's ACS instance ===
    //     for (session_id, payload) in fake_rbc_outputs.iter().enumerate() {
    //         for (i, _) in acs_parties.iter().enumerate() {
    //             let msg = Msg {
    //                 sender_id: i as u32,
    //                 session_id: session_id as u32,
    //                 round_id: 0,
    //                 msg_type: GenericMsgType::Acs(MsgTypeAcs::Acs),
    //                 payload: payload.clone(),
    //                 metadata: vec![],
    //                 msg_len: payload.len(),
    //             };

    //             let _ = acs_instances[i as usize].init(msg, net.clone()).await;
    //         }
    //         tokio::time::sleep(Duration::from_millis(5)).await;
    //     }

    //     // Wait for ACS to complete
    //     tokio::time::sleep(Duration::from_millis(300)).await;

    //     // === Validate ACS Outputs ===
    //     let mut commonsubsets = Vec::new();
    //     for i in 0..n {
    //         let mut store = acs_instances[i as usize].store.lock().await;

    //         assert!(store.ended, "Party {}: ACS has not terminated", i);

    //         assert!(
    //             store.get_aba_output_one_count() >= n - t,
    //             "Party {}: insufficient ACS outputs",
    //             i
    //         );

    //         commonsubsets.push(store.commonsubset.clone());
    //     }

    //     // All parties must agree on the same common subset
    //     for i in 1..n {
    //         assert_eq!(
    //             commonsubsets[0], commonsubsets[i as usize],
    //             "Mismatch in ACS outputs between party 0 and party {}",
    //             i
    //         );
    //     }
    // }
    // #[tokio::test]
    // async fn test_acs() {
    //     let _ = tracing_subscriber::fmt()
    //         .with_max_level(tracing::Level::DEBUG)
    //         .with_test_writer()
    //         .try_init();

    //     let n = 4;
    //     let t = 1;
    //     let k = 2;

    //     let session_ids = vec![0, 1, 2, 3];
    //     let payloads = vec![
    //         b"From Party 0".to_vec(),
    //         b"From Party 1".to_vec(),
    //         b"From Party 2".to_vec(),
    //         b"From Party 3".to_vec(),
    //     ];
    //     //--------------------------------------------------RBC--------------------------------------------------
    //     let (parties, net, receivers) = setup_network_and_parties::<Avid, FakeNetwork>(n, t, k,1000)
    //         .await
    //         .expect("Failed to set up parties");
    //     spawn_parties(&parties, receivers, net.clone()).await;

    //     // Each party initiates one RBC session
    //     for (i, avid) in parties.iter().enumerate() {
    //         let _ = avid.init(payloads[i].clone(), session_ids[i], net.clone())
    //             .await;
    //     }

    //     // Wait for all RBC instances to terminate
    //     tokio::time::sleep(Duration::from_millis(500)).await;

    //     //--------------------------------------------------ACS--------------------------------------------------

    //     // === Setup Channels for ACS ===
    //     let (_, net1, receivers1) = setup_network_and_parties::<Avid, FakeNetwork>(n, t, k,500)
    //         .await
    //         .expect("Failed to set up parties");

    //     // Create ACS instances for each party
    //     let mut acs_instances = Vec::new();
    //     let mut acs_parties = Vec::with_capacity(n as usize);
    //     for i in 0..n {
    //         let acs = ACS::new(i as u32, n as u32, t as u32, k as u32)
    //             .expect("Failed to create ACS instance");
    //         acs_parties.push(acs.aba.clone());
    //         acs_instances.push(acs);
    //     }

    //     // === Spawn Each Party for ACS===
    //     spawn_parties(&acs_parties, receivers1, net1.clone()).await;

    //     // === Dealer Distributes Keys ===
    //     let dealer = Dealer::new(n, t);
    //     let key_dist_msg = Msg::new(
    //         0,
    //         0,
    //         0,
    //         vec![],
    //         vec![],
    //         GenericMsgType::ABA(MsgTypeAba::Key),
    //         0,
    //     );
    //     let _ = dealer.distribute_keys(key_dist_msg, net1.clone()).await;
    //     // Wait for keys to be received
    //     tokio::time::sleep(Duration::from_millis(5)).await;

    //     // -------------------------------Verify RBC termination and initiate ACS-------------------------------
    //     for session_id in &session_ids {
    //         for (i, avid) in parties.iter().enumerate() {
    //             let store = avid.store.lock().await;

    //             // Check if RBC has terminated for this session
    //             let session_store = store
    //                 .get(session_id)
    //                 .expect(&format!("Party {} missing RBC session {}", i, session_id));
    //             let session = session_store.lock().await;

    //             // Check if this RBC has successfully terminated with output
    //             assert!(
    //                 session.ended,
    //                 "RBC has not terminated yet at {}",
    //                 session_id
    //             );

    //             println!(
    //                 "Party {} received RBC output for session {}: {:?}",
    //                 i, session_id, session.output
    //             );

    //             // Now initiate ACS with the RBC output
    //             let msg = Msg {
    //                 sender_id: i as u32,
    //                 session_id: *session_id,
    //                 round_id: 0,
    //                 msg_type: GenericMsgType::Acs(MsgTypeAcs::Acs),
    //                 payload: session.output.clone(),
    //                 metadata: vec![],
    //                 msg_len: session.output.len(),
    //             };
    //             drop(session);
    //             // Initiate ACS for this party with the RBC result
    //             let _ = acs_instances[i].init(msg, net1.clone()).await;
    //         }
    //         tokio::time::sleep(Duration::from_millis(5)).await;
    //     }

    //     // Allow time for ACS to complete
    //     tokio::time::sleep(Duration::from_millis(500)).await;

    //     // -------------------------------------------Validate ACS-------------------------------------------
    //     for i in 0..n {
    //         let mut store_lock = acs_instances[i as usize].store.lock().await;
    //         // Check if ACS has values
    //         assert!(
    //             store_lock.ended,
    //             "ACS has not terminated yet at {} party",
    //             i
    //         );
    //         // Verify ACS contains at least n-t values
    //         assert!(
    //             store_lock.get_aba_output_one_count() >= (n - t),
    //             "Party {} ACS should contain at least {} values, got {}",
    //             i,
    //             n - t,
    //             store_lock.get_aba_output_one_count()
    //         );
    //     }

    //     // Cross-check consistency between parties
    //     let mut outputs = Vec::new();

    //     for i in 0..n {
    //         let store_lock = acs_instances[i as usize].store.lock().await;
    //         let output = &store_lock.commonsubset;
    //         outputs.push(output.clone());
    //     }

    //     // Check all parties have same output for this session
    //     for i in 1..n {
    //         assert_eq!(
    //             outputs[0], outputs[i as usize],
    //             "ACS output differs between parties 0 and {}",
    //             i
    //         );
    //     }
    // }
}
