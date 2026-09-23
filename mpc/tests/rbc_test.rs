pub mod utils;
#[cfg(test)]
mod tests {
    use rand::Rng;
    use std::{collections::HashMap, sync::Arc, time::Duration};
    use stoffelcrypto::{
        common::{
            rbc::{
                rbc::{Avid, Bracha, Dealer, ABA},
                rbc_store::{AbaStore, GenericMsgType, Msg, MsgType, MsgTypeAba, MsgTypeAvid},
                utils::set_value_round,
            },
            ProtocolSessionId, RBC,
        },
        honeybadger::{ProtocolType, SessionId, WrappedMessage},
    };
    use stoffelmpc_network::fake_network::{FakeInnerNetwork, FakeNetwork, FakeNetworkConfig};
    use tokio::sync::{mpsc, Mutex};
    use tokio::time::timeout;
    use tracing::warn;

    use crate::utils::test_utils::{setup_network_and_parties, setup_tracing, spawn_parties};

    #[tokio::test]
    async fn test_bracha_rbc_basic() {
        setup_tracing();

        // Set the parameters
        let n = 4;
        let t = 1;
        let payload = b"Hello, MPC!".to_vec();
        let session_id = SessionId::new(ProtocolType::Rbc, SessionId::pack_slot(123, 0, 0), 12);

        let (parties, net, receivers) =
            setup_network_and_parties::<Bracha<SessionId>, FakeNetwork>(n, t, t + 1, 500)
                .await
                .expect("Failed to set up parties");
        spawn_parties(&parties, receivers, net.clone()).await;

        // Party 0 initiates broadcast
        let bracha0 = &parties[0];
        let _ = bracha0
            .init(payload.clone(), session_id, net[0].clone())
            .await;

        // Give time for broadcast to propagate
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Check that all parties completed broadcast and agreed on output
        for bracha in &parties {
            let session_store = {
                let store_map = bracha.store.lock().await;
                store_map
                    .get(&session_id)
                    .map(|(_, _, arc)| arc.clone())
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

    /// Regression test for the dispatcher-freeze DoS this module's `try_send` fix closes:
    /// `ready_handler` used to hand off a completed session via a blocking
    /// `output_sender.send(...).await`. Since `AvssMPCNode::process` takes `&mut self` and
    /// processes one inbound message at a time, a single node's completion channel filling
    /// up (e.g. from an authenticated-but-unsolicited flood of unrelated sessions nobody is
    /// consuming) would block that one blocking send forever, wedging *every* subsequent
    /// inbound message on that node shut — not just the session that filled the queue.
    ///
    /// This drives more Bracha sessions to completion than the output channel has capacity
    /// for, with the receiving end deliberately never drained (mirroring "nobody is
    /// consuming completions right now"), and checks that processing still returns
    /// promptly instead of hanging.
    #[tokio::test]
    async fn test_full_output_channel_does_not_block_bracha_dispatch() {
        setup_tracing();

        let n = 4;
        let t = 1;
        let k = t + 1;
        let cap = 2usize; // tiny on purpose, to reach "full" without needing thousands of sessions

        let (rbc_sender, mut rbc_receiver) = mpsc::channel(cap);
        let bracha =
            Bracha::<SessionId>::new(0, n, t, k, rbc_sender, Arc::new(WrappedMessage::rbc_wrap))
                .expect("failed to construct Bracha instance");

        // A network is required for `process`'s broadcast side effects, but nothing needs
        // to drain it for this test — only `bracha`'s own completion channel matters here.
        let config = FakeNetworkConfig::new(500);
        let (inner, _receivers, _) = FakeInnerNetwork::new(n, None, config);
        let net = Arc::new(FakeNetwork::new(0, inner));

        // Drives one session to completion via synthetic READY votes from three distinct
        // senders. Bracha's own completion logic only counts votes by `sender_id` and
        // admits sessions lazily — per the `Msg` doc comment, sender authentication is the
        // caller's job, not the RBC layer's — so this reaches the 2t+1=3 threshold without
        // any real INIT/ECHO round-trip or other live party instances.
        async fn complete_session(bracha: &Bracha<SessionId>, net: Arc<FakeNetwork>, exec: u64) {
            let session_id =
                SessionId::new(ProtocolType::Rbc, SessionId::pack_slot(exec, 0, 0), 77);
            let payload = format!("payload-{exec}").into_bytes();
            for sender in 0..3 {
                let msg = Msg::new(
                    sender,
                    session_id,
                    0,
                    payload.clone(),
                    vec![],
                    GenericMsgType::Bracha(MsgType::Ready),
                );
                bracha.process(msg, net.clone()).await.unwrap();
            }
        }

        // Fill the completion channel to capacity with unsolicited sessions nobody drains.
        for exec in 0..cap as u64 {
            complete_session(&bracha, net.clone(), exec).await;
        }

        // The next completion pushes past capacity. Before the fix, the blocking
        // `output_sender.send().await` inside `ready_handler` would hang here forever;
        // `try_send` must let this return promptly instead, dropping the notification.
        let result = timeout(
            Duration::from_secs(3),
            complete_session(&bracha, net.clone(), cap as u64),
        )
        .await;
        assert!(
            result.is_ok(),
            "processing a completion past a full output channel must not block — this is \
             exactly the node-wide dispatcher freeze the try_send fix closes"
        );

        // A completely unrelated, later session must still get processed normally — proving
        // the dispatcher isn't left wedged after the channel filled.
        let followup = timeout(
            Duration::from_secs(3),
            complete_session(&bracha, net.clone(), (cap + 1) as u64),
        )
        .await;
        assert!(
            followup.is_ok(),
            "a later, unrelated session must still be processed after the channel filled"
        );

        // The channel isn't wedged shut either: the first `cap` completions that fit are
        // still there to be drained.
        let mut drained = 0;
        while rbc_receiver.try_recv().is_ok() {
            drained += 1;
        }
        assert_eq!(
            drained, cap,
            "expected exactly the first {cap} completions to have been queued"
        );
    }

    #[tokio::test]
    async fn test_multiple_sessions() {
        setup_tracing();

        let n = 4;
        let t = 1;
        let session_ids = vec![
            SessionId::new(ProtocolType::Rbc, SessionId::pack_slot(123, 0, 0), 101),
            SessionId::new(ProtocolType::Rbc, SessionId::pack_slot(123, 0, 0), 102),
            SessionId::new(ProtocolType::Rbc, SessionId::pack_slot(123, 0, 0), 103),
        ];
        let payloads = vec![
            b"Payload A".to_vec(),
            b"Payload B".to_vec(),
            b"Payload C".to_vec(),
        ];

        let (parties, net, receivers) =
            setup_network_and_parties::<Bracha<SessionId>, FakeNetwork>(n, t, t + 1, 500)
                .await
                .expect("Failed to set up parties");
        spawn_parties(&parties, receivers, net.clone()).await;

        // Launch all sessions from party 0
        let bracha0 = &parties[0];
        for (i, sid) in session_ids.iter().enumerate() {
            let _ = bracha0
                .init(payloads[i].clone(), *sid, net[i].clone())
                .await;
        }

        tokio::time::sleep(Duration::from_millis(200)).await;

        for bracha in &parties {
            let store = bracha.store.lock().await;
            for (i, sid) in session_ids.iter().enumerate() {
                let (_, _, store_arc) = store.get(sid).expect("Missing session");
                let s = store_arc.lock().await;

                assert!(
                    s.ended,
                    "Session {} not completed at party {}",
                    sid.as_u128(),
                    bracha.id
                );
                assert_eq!(
                    &s.output,
                    &payloads[i],
                    "Incorrect payload for session {}",
                    sid.as_u128()
                );
            }
        }
    }
    #[tokio::test]
    async fn test_multiple_sessions_different_party() {
        setup_tracing();

        let n = 4;
        let t = 1;
        let session_ids = vec![
            SessionId::new(ProtocolType::Rbc, SessionId::pack_slot(123, 0, 0), 10),
            SessionId::new(ProtocolType::Rbc, SessionId::pack_slot(123, 0, 0), 20),
            SessionId::new(ProtocolType::Rbc, SessionId::pack_slot(123, 0, 0), 30),
            SessionId::new(ProtocolType::Rbc, SessionId::pack_slot(123, 0, 0), 40),
        ];
        let payloads = vec![
            b"From Party 0".to_vec(),
            b"From Party 1".to_vec(),
            b"From Party 2".to_vec(),
            b"From Party 3".to_vec(),
        ];

        let (parties, net, receivers) =
            setup_network_and_parties::<Bracha<SessionId>, FakeNetwork>(n, t, t + 1, 500)
                .await
                .expect("Failed to set up parties");
        spawn_parties(&parties, receivers, net.clone()).await;

        // Each party initiates one session
        for (i, bracha) in parties.iter().enumerate() {
            let _ = bracha
                .init(payloads[i].clone(), session_ids[i], net[i].clone())
                .await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Validate all sessions completed successfully and consistently
        for bracha in &parties {
            let store = bracha.store.lock().await;
            for (i, session_id) in session_ids.iter().enumerate() {
                let (_, _, store_arc) = store.get(session_id).expect("Missing session");
                let s = store_arc.lock().await;
                assert!(
                    s.ended,
                    "Session {} not completed at party {}",
                    session_id.as_u128(),
                    bracha.id
                );
                assert_eq!(
                    &s.output,
                    &payloads[i],
                    "Incorrect output at party {} for session {}",
                    bracha.id,
                    session_id.as_u128()
                );
            }
        }
    }
    #[tokio::test]
    async fn test_out_of_order_delivery() {
        setup_tracing();

        let n = 4;
        let t = 1;
        let session_id = SessionId::new(ProtocolType::Rbc, SessionId::pack_slot(123, 0, 0), 11);
        let payload = b"out-of-order".to_vec();

        let (parties, net, receivers) =
            setup_network_and_parties::<Bracha<SessionId>, FakeNetwork>(n, t, t + 1, 500)
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
            GenericMsgType::Bracha(MsgType::Ready),
        );
        let echo_msg = Msg::new(
            sender_id,
            session_id,
            0,
            payload.clone(),
            vec![],
            GenericMsgType::Bracha(MsgType::Echo),
        );

        // Send READY first
        let _ = parties[sender_id as usize]
            .send(ready_msg, net[sender_id].clone(), 2)
            .await
            .expect("Sending ready failed");

        // Then ECHO
        let _ = parties[sender_id as usize]
            .send(echo_msg, net[sender_id].clone(), 3)
            .await
            .expect("Sending Echo failed");

        // Party 0 initiates broadcast
        let bracha0 = &parties[0];
        let _ = bracha0
            .init(payload.clone(), session_id, net[0].clone())
            .await;

        // Allow time for processing
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Check if parties reached consensus
        for bracha in &parties {
            let store = bracha.store.lock().await;
            if let Some((_, _, state)) = store.get(&session_id) {
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

    async fn run_avid_rbc_test(
        n: usize,
        t: usize,
        k: usize,
        session_id: SessionId,
        payload: Vec<u8>,
    ) {
        println!("Running Avid RBC with n={}, t={}, k={}", n, t, k);

        let (parties, net, receivers) =
            setup_network_and_parties::<Avid<SessionId>, FakeNetwork>(n, t, t + 1, 500)
                .await
                .expect("Failed to set up parties");
        spawn_parties(&parties, receivers, net.clone()).await;

        // Initiate broadcast from party 0
        let avid0 = &parties[0];
        let _ = avid0
            .init(payload.clone(), session_id, net[avid0.id].clone())
            .await;

        // Allow time for propagation
        tokio::time::sleep(Duration::from_millis(500)).await;

        for avid in &parties {
            let session_store = {
                let store_map = avid.store.lock().await;
                store_map
                    .get(&session_id)
                    .map(|(_, _, arc)| arc.clone())
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
        setup_tracing();

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
            run_avid_rbc_test(
                n,
                t,
                k,
                SessionId::new(ProtocolType::Rbc, SessionId::pack_slot(123, 0, 0), 100),
                payload.clone(),
            )
            .await;
        }
    }

    #[tokio::test]
    async fn test_multiple_sessions_different_party_avid() {
        setup_tracing();

        let n = 4;
        let t = 1;

        let session_ids = vec![
            SessionId::new(ProtocolType::Rbc, SessionId::pack_slot(123, 0, 0), 10),
            SessionId::new(ProtocolType::Rbc, SessionId::pack_slot(123, 0, 0), 20),
            SessionId::new(ProtocolType::Rbc, SessionId::pack_slot(123, 0, 0), 30),
            SessionId::new(ProtocolType::Rbc, SessionId::pack_slot(123, 0, 0), 40),
        ];
        let payloads = vec![
            b"From Party 0".to_vec(),
            b"From Party 1".to_vec(),
            b"From Party 2".to_vec(),
            b"From Party 3".to_vec(),
        ];

        let (parties, net, receivers) =
            setup_network_and_parties::<Avid<SessionId>, FakeNetwork>(n, t, t + 1, 500)
                .await
                .expect("Failed to set up parties");
        spawn_parties(&parties, receivers, net.clone()).await;

        // Each party initiates one session
        for (i, avid) in parties.iter().enumerate() {
            let _ = avid
                .init(payloads[i].clone(), session_ids[i], net[0].clone())
                .await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Validate all sessions completed successfully and consistently
        for avid in &parties {
            let store = avid.store.lock().await;
            for (i, session_id) in session_ids.iter().enumerate() {
                let (_, _, store_arc) = store.get(session_id).expect("Missing session");
                let s = store_arc.lock().await;
                assert!(
                    s.ended,
                    "Session {} not completed at party {}",
                    session_id.as_u128(),
                    avid.id
                );
                assert_eq!(
                    &s.output,
                    &payloads[i],
                    "Incorrect output at party {} for session {}",
                    avid.id,
                    session_id.as_u128()
                );
            }
        }
    }
    #[tokio::test]
    async fn test_out_of_order_delivery_avid() {
        setup_tracing();

        let n = 4;
        let t = 1;
        let k = 2;
        let session_id = SessionId::new(ProtocolType::Rbc, SessionId::pack_slot(123, 0, 0), 11);
        let payload = b"out-of-order".to_vec();

        let (parties, net, receivers) =
            setup_network_and_parties::<Avid<SessionId>, FakeNetwork>(n, t, k, 500)
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
        );
        let echo_msg = Msg::new(
            sender_id,
            session_id,
            0,
            payload.clone(),
            vec![],
            GenericMsgType::Avid(MsgTypeAvid::Echo),
        );

        // Send READY first
        let _ = parties[sender_id as usize]
            .send(ready_msg, net[sender_id].clone(), 2)
            .await
            .expect("Sending ready failed");

        // Then ECHO
        let _ = parties[sender_id as usize]
            .send(echo_msg, net[sender_id].clone(), 3)
            .await
            .expect("Sending ready failed");

        // Party 0 initiates broadcast
        let avid0 = &parties[0];
        let _ = avid0
            .init(payload.clone(), session_id, net[sender_id].clone())
            .await;

        // Allow time for processing
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Check if parties reached consensus
        for avid in &parties {
            let store = avid.store.lock().await;
            if let Some((_, _, state)) = store.get(&session_id) {
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
        setup_tracing();

        let n = 7;
        let t = 2;
        let payload = b"crash fault test".to_vec();
        let session_id = SessionId::new(ProtocolType::Rbc, SessionId::pack_slot(123, 0, 0), 2025);

        let (parties, net, receivers) =
            setup_network_and_parties::<Bracha<SessionId>, FakeNetwork>(n, t, t + 1, 500)
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
            .init(payload.clone(), session_id, net[initiator_rbc.id].clone())
            .await;

        // Give protocol time to complete
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Check agreement and completion among honest nodes
        for rbc in honest_parties {
            let session_store = {
                let store_map = rbc.store.lock().await;
                store_map
                    .get(&session_id)
                    .map(|(_, _, arc)| arc.clone())
                    .expect(&format!("Party {} did not create session store", rbc.id))
            };

            let s = session_store.lock().await;

            assert!(s.ended, "Broadcast not completed for party {}", rbc.id);
            assert_eq!(&s.output, &payload, "Incorrect payload at party {}", rbc.id);
        }
    }
    async fn test_avid_rbc_with_faulty_nodes(
        n: usize,
        t: usize,
        k: usize,
        session_id: SessionId,
        payload: Vec<u8>,
    ) {
        println!(
            "Running AVID RBC with crash faults: n={}, t={}, k={}",
            n, t, k
        );

        let (parties, net, receivers) =
            setup_network_and_parties::<Avid<SessionId>, FakeNetwork>(n, t, k, 500)
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
            .init(payload.clone(), session_id, net[0].clone())
            .await
            .unwrap_or_else(|e| warn!("Initiator {} failed : {:?}", initiator.id, e));

        // Allow time for propagation
        tokio::time::sleep(Duration::from_millis(300)).await;

        for avid in honest_parties {
            let session_store = {
                let store_map = avid.store.lock().await;
                store_map
                    .get(&session_id)
                    .map(|(_, _, arc)| arc.clone())
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
        setup_tracing();

        let payload = b"AVID crash fault test".to_vec();

        // (n, t, k) test configurations
        let test_cases = vec![(4, 1, 2), (5, 1, 3), (7, 2, 3), (20, 5, 8), (20, 6, 8)];

        for (i, &(n, t, k)) in test_cases.iter().enumerate() {
            println!("--- Test case {} ---", i + 1);
            test_avid_rbc_with_faulty_nodes(
                n,
                t,
                k,
                SessionId::new(
                    ProtocolType::Rbc,
                    SessionId::pack_slot(123, 0, 0),
                    100 + i as u32,
                ),
                payload.clone(),
            )
            .await;
        }
    }

    #[tokio::test]
    async fn test_common_coin() {
        setup_tracing();

        let n = 4;
        let t = 1;
        let k = t + 1;
        let session_id = SessionId::new(ProtocolType::Rbc, SessionId::pack_slot(123, 0, 0), 99);

        let round_id = 0;

        let (parties, net, receivers) =
            setup_network_and_parties::<ABA<SessionId>, FakeNetwork>(n, t, k, 500)
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
        );
        let _ = dealer
            .distribute_keys(
                dealer_msg,
                net[0].clone(),
                Arc::new(WrappedMessage::rbc_wrap),
            )
            .await;

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
            );
            let _ = aba.init_coin(coin_msg, net[aba.id].clone()).await;
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
        setup_tracing();

        // === Parameters ===
        let n = 4;
        let t = 1;
        let k = t + 1;
        let session_id = SessionId::new(ProtocolType::Rbc, SessionId::pack_slot(123, 0, 0), 42);
        let round_id = 0;

        let (parties, net, receivers) =
            setup_network_and_parties::<ABA<SessionId>, FakeNetwork>(n, t, k, 1000)
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
        );
        let _ = dealer
            .distribute_keys(
                key_dist_msg,
                net[0].clone(),
                Arc::new(WrappedMessage::rbc_wrap),
            )
            .await;

        tokio::time::sleep(Duration::from_millis(5)).await;

        // === Trigger ABA with diverse inputs ===
        let mut rng = rand::thread_rng();
        let inputs: Vec<bool> = (0..parties.len()).map(|_| rng.gen_bool(0.5)).collect();
        for (i, &input) in inputs.iter().enumerate() {
            tracing::info!("Party {} input: {}", i, input);
        }

        let init_futures = parties.iter().zip(inputs).map(|(aba, input)| {
            let payload = set_value_round(input, round_id as u32);
            aba.init(payload, session_id, net[aba.id].clone())
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
}
