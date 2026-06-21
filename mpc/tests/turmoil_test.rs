mod utils;

use crate::utils::{
    test_utils::{
        construct_e2e_input, construct_e2e_input_mul, create_clients, create_global_nodes,
        generate_independent_shares, setup_quiet_tracing, setup_tracing,
    },
    turmoil::{add_driver, collect_results, turmoil_setup, turmoil_setup_with_duration},
};
use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    rand::{rngs::StdRng, SeedableRng},
    test_rng,
};
use chacha20poly1305::aead::OsRng;
use std::{sync::Arc, time::Instant};
use stoffelmpc_mpc::{
    common::{
        rbc::rbc::Avid,
        types::fixed::{ClearFixedPoint, FixedPointPrecision, SecretFixedPoint},
        MPCProtocol, MPCTypeOps, PreprocessingMPCProtocol, ProtocolSessionId, SecretSharingScheme,
        ShamirShare,
    },
    honeybadger::{
        batch_recon::{
            batch_recon::BatchReconNode, BatchReconError, BatchReconMsg, BatchReconMsgType,
        },
        fpmul::f256::Gf256,
        input::input::{InputClient, InputType},
        ran_dou_sha::RanDouShaState,
        robust_interpolate::robust_interpolate::{Robust, RobustShare},
        share_gen::{RanShaError, RanShaMessage, RanShaMessageType, RanShaPayload, RanShaState},
        ProtocolType, SessionId, WrappedMessage,
    },
};
use stoffelmpc_network::{
    // bad_fake_network::setup_tracing,
    fake_network::SenderId,
    turmoil_network::TurmoilNetwork,
};
use stoffelnet::network_utils::{ClientId, NetworkError};
use tokio::sync::Barrier;
use tokio::time::{sleep, timeout, Duration};
use tracing::{error, info};

#[derive(Clone)]
struct DelayedStart {
    delayed_nodes: Vec<usize>,
    time: Duration,
}

#[test]
fn ransha_e2e_turmoil() {
    setup_tracing();

    let n_parties = 4;
    let t = 1;

    let session_id = SessionId::new(ProtocolType::Ransha, SessionId::pack_slot(123, 0, 0), 111);

    let (mut sim, inner) = turmoil_setup(n_parties, vec![], Some((10, 2000)));
    let nodes = create_global_nodes::<Fr, Avid<SessionId>, RobustShare<Fr>, TurmoilNetwork>(
        n_parties,
        t,
        0,
        0,
        111,
        0,
        0,
        0,
        0,
        Duration::from_secs(30),
        vec![],
    );

    let (tx, rx_done) = std::sync::mpsc::channel::<Result<(), String>>();

    for id in 0..n_parties {
        let inner = inner.clone();
        let node = nodes[id].clone();
        let tx = tx.clone();

        sim.host(format!("node{}", id), move || {
            let inner = inner.clone();
            let mut node = node.clone();
            let tx = tx.clone();

            async move {
                let (network, mut rx) = TurmoilNetwork::new(SenderId::Node(id), inner).await;
                sleep(Duration::from_millis(50)).await;

                let network_arc = Arc::new(network);
                let mut rng = StdRng::from_rng(OsRng).unwrap();
                let node_id = node.preprocess.share_gen.id;

                match node
                    .preprocess
                    .share_gen
                    .init(session_id, &mut rng, network_arc.clone())
                    .await
                {
                    Ok(()) => {}
                    Err(RanShaError::NetworkError(NetworkError::SendError)) => {}
                    Err(e) => {
                        let _ = tx.send(Err(format!("node {} init error: {:?}", node_id, e)));
                        return Ok(());
                    }
                }

                let mut msg_count = 0usize;
                let result = timeout(Duration::from_secs(30), async {
                    loop {
                        match rx.recv().await {
                            Some((sender, msg)) => {
                                msg_count += 1;
                                let sender_id = match sender {
                                    SenderId::Node(i) => i,
                                    SenderId::Client(i) => i,
                                };
                                node.process(sender_id, msg, network_arc.clone())
                                    .await
                                    .unwrap();
                            }
                            None => break,
                        }

                        let store = node
                            .preprocess
                            .share_gen
                            .get_or_create_store(session_id)
                            .await
                            .unwrap();
                        if store.lock().await.state == RanShaState::Finished {
                            break;
                        }
                    }
                })
                .await;

                if result.is_err() {
                    let _ = tx.send(Err(format!(
                        "node {} timed out after {} msgs",
                        node_id, msg_count
                    )));
                    return Ok(());
                }

                let store = node
                    .preprocess
                    .share_gen
                    .get_or_create_store(session_id)
                    .await
                    .unwrap();
                let store = store.lock().await;

                for s_t in store.computed_r_shares.iter() {
                    if s_t.degree != t {
                        let _ = tx.send(Err(format!(
                            "node {} share degree {} != {}",
                            node_id, s_t.degree, t
                        )));
                        return Ok(());
                    }
                    if s_t.id != node.id {
                        let _ = tx.send(Err(format!("node {} share id mismatch", node_id)));
                        return Ok(());
                    }
                }

                if store.computed_r_shares.len() != n_parties {
                    let _ = tx.send(Err(format!(
                        "node {} expected {} shares, got {}",
                        node_id,
                        n_parties,
                        store.computed_r_shares.len()
                    )));
                    return Ok(());
                }

                let _ = tx.send(Ok(()));
                Ok(())
            }
        });
    }

    drop(tx);

    add_driver(&mut sim, 60);
    collect_results(sim, rx_done, n_parties);
}

#[test]
fn ransha_late_message_recreates_cleared_store_turmoil() {
    setup_tracing();

    let n_parties = 5;
    let t = 1;
    let session_id = SessionId::new(ProtocolType::Ransha, SessionId::pack_slot(7, 0, 0), 111);

    let (mut sim, inner) = turmoil_setup(1, vec![], Some((10, 2000)));
    let nodes = create_global_nodes::<Fr, Avid<SessionId>, RobustShare<Fr>, TurmoilNetwork>(
        n_parties,
        t,
        0,
        0,
        111,
        0,
        0,
        0,
        0,
        Duration::from_secs(30),
        vec![],
    );
    let (tx, rx_done) = std::sync::mpsc::channel::<Result<(), String>>();

    let node = nodes[0].clone();
    let host_tx = tx.clone();
    sim.host("node0", move || {
        let inner = inner.clone();
        let mut node = node.clone();
        let tx = host_tx.clone();

        async move {
            let (network, _rx) = TurmoilNetwork::new(SenderId::Node(0), inner).await;
            let network_arc = Arc::new(network);

            node.preprocess
                .share_gen
                .get_or_create_store(session_id)
                .await
                .unwrap();
            if !node.preprocess.share_gen.clear_store(session_id).await {
                let _ = tx.send(Err(
                    "expected initial RanSha store to be cleared".to_string()
                ));
                return Ok(());
            }

            let late_share = RobustShare::new(Fr::from(9u8), 0, t);
            let mut payload = Vec::new();
            late_share.serialize_compressed(&mut payload).unwrap();
            let late_msg = RanShaMessage::new(
                1,
                RanShaMessageType::ShareMessage,
                session_id,
                RanShaPayload::Share(payload),
            );

            node.preprocess
                .share_gen
                .process(late_msg, network_arc)
                .await
                .unwrap();

            let resurrected = node
                .preprocess
                .share_gen
                .get_or_create_store(session_id)
                .await
                .unwrap();
            let resurrected = resurrected.lock().await;
            if !resurrected.initial_shares.contains_key(&1) {
                let _ = tx.send(Err(
                    "late RanSha message did not recreate cleared session state".to_string(),
                ));
                return Ok(());
            }

            let _ = tx.send(Ok(()));
            Ok(())
        }
    });

    drop(tx);
    add_driver(&mut sim, 10);
    collect_results(sim, rx_done, 1);
}

#[test]
fn batch_recon_late_message_recreates_cleared_store_turmoil() {
    setup_tracing();

    let n_parties = 5;
    let t = 1;
    let session_id = SessionId::new(ProtocolType::BatchRecon, SessionId::pack_slot(7, 0, 0), 111);

    let (mut sim, inner) = turmoil_setup(1, vec![], Some((10, 2000)));
    let (output_tx, _output_rx) = tokio::sync::mpsc::channel(8);
    let node = BatchReconNode::<Fr>::new(0, n_parties, t, t, output_tx).unwrap();
    let (tx, rx_done) = std::sync::mpsc::channel::<Result<(), String>>();

    let host_tx = tx.clone();
    sim.host("node0", move || {
        let inner = inner.clone();
        let mut node = node.clone();
        let tx = host_tx.clone();

        async move {
            let (network, _rx) = TurmoilNetwork::new(SenderId::Node(0), inner).await;
            let network_arc = Arc::new(network);

            node.get_or_create_store(session_id).await.unwrap();
            if !node.clear_store(session_id).await {
                let _ = tx.send(Err(
                    "expected initial BatchRecon store to be cleared".to_string()
                ));
                return Ok(());
            }

            let mut payload = Vec::new();
            Fr::from(11u8).serialize_compressed(&mut payload).unwrap();
            let late_msg = BatchReconMsg::new(1, session_id, BatchReconMsgType::Eval, payload);

            node.process(late_msg, network_arc).await.unwrap();

            let resurrected = node.get_or_create_store(session_id).await.unwrap().unwrap();
            let resurrected = resurrected.lock().await;
            if resurrected.evals_received.len() != 1 {
                let _ = tx.send(Err(
                    "late BatchRecon message did not recreate cleared session state".to_string(),
                ));
                return Ok(());
            }

            let _ = tx.send(Ok(()));
            Ok(())
        }
    });

    drop(tx);
    add_driver(&mut sim, 10);
    collect_results(sim, rx_done, 1);
}

#[test]
fn test_input_protocol_e2e_turmoil() {
    setup_tracing();

    let n = 4;
    let t = 1;
    let client_id: ClientId = 100;
    let input_values: Vec<Fr> = vec![Fr::from(10), Fr::from(20)];
    let mask_values: Vec<Fr> = vec![Fr::from(11), Fr::from(21)];

    let (mut sim, inner) = turmoil_setup(n, vec![client_id], Some((10, 2000)));
    let (tx, rx_done) = std::sync::mpsc::channel::<Result<Option<Vec<RobustShare<Fr>>>, String>>();

    // shared done signal — hosts notify driver when finished
    let (done_tx, done_rx) = tokio::sync::broadcast::channel::<()>(n + 1);

    let local_shares = generate_independent_shares(&mask_values, t, n);
    let nodes = create_global_nodes::<Fr, Avid<SessionId>, RobustShare<Fr>, TurmoilNetwork>(
        n,
        t,
        0,
        0,
        111,
        0,
        0,
        0,
        0,
        Duration::from_secs(30),
        vec![client_id],
    );
    let barrier = Arc::new(tokio::sync::Barrier::new(n + 1)); // n nodes + client

    // --- client host ---
    let inner_c = inner.clone();
    let tx_c = tx.clone();
    let done_tx_c = done_tx.clone();
    let input_values_c = input_values.clone();
    let barrier_c = barrier.clone();

    sim.host(format!("client{}", client_id), move || {
        let inner = inner_c.clone();
        let tx = tx_c.clone();
        let done_tx = done_tx_c.clone();
        let input_values = input_values_c.clone();
        let barrier = barrier_c.clone();

        async move {
            let mut client =
                InputClient::<Fr, Avid<SessionId>>::new(client_id, n, t, 111, input_values)
                    .unwrap();

            let (network, mut rx) = TurmoilNetwork::new(SenderId::Client(client_id), inner).await;
            let network_arc = Arc::new(network);
            barrier.wait().await;
            loop {
                match rx.recv().await {
                    Some((_sender, msg)) => {
                        let wrapped: WrappedMessage = match bincode::deserialize(&msg) {
                            Ok(w) => w,
                            Err(_) => continue,
                        };
                        match wrapped {
                            WrappedMessage::Input(msg) => {
                                match client.process(msg, network_arc.clone()).await {
                                    Ok(_) => {}
                                    Err(e) => {
                                        let _ =
                                            tx.send(Err(format!("client processing error: {}", e)));
                                        let _ = done_tx.send(());
                                        return Ok(());
                                    }
                                }
                            }
                            _ => continue,
                        }
                    }
                    None => break,
                }

                tokio::task::yield_now().await;

                if client.client_data.lock().await.rbc_done {
                    break;
                }
            }

            let _ = tx.send(Ok(None));
            let _ = done_tx.send(());
            Ok(())
        }
    });

    // --- node hosts ---
    for id in 0..n {
        let inner = inner.clone();
        let node = nodes[id].clone();
        let tx = tx.clone();
        let done_tx = done_tx.clone();
        let local_share = local_shares[id].clone();
        let barrier = barrier.clone();

        sim.host(format!("node{}", id), move || {
            let inner = inner.clone();
            let mut node = node.clone();
            let tx = tx.clone();
            let done_tx = done_tx.clone();
            let local_share = local_share.clone();
            let barrier = barrier.clone();

            async move {
                let (network, mut rx) = TurmoilNetwork::new(SenderId::Node(id), inner).await;
                let network_arc = Arc::new(network);
                barrier.wait().await;
                match node
                    .preprocess
                    .input
                    .init(client_id, local_share, 2, network_arc.clone())
                    .await
                {
                    Ok(_) => {}
                    Err(e) => {
                        let _ = tx.send(Err(format!("node {} init error: {}", id, e)));
                        let _ = done_tx.send(());
                        return Ok(());
                    }
                }

                loop {
                    match rx.recv().await {
                        Some((sender, msg)) => {
                            let sender_id = match sender {
                                SenderId::Node(i) => i,
                                SenderId::Client(i) => i,
                            };
                            node.process(sender_id, msg, network_arc.clone())
                                .await
                                .unwrap();
                        }
                        None => break,
                    }

                    tokio::task::yield_now().await;

                    let is_done = {
                        let statuses = node.preprocess.input.status_receiver.borrow();
                        statuses
                            .iter()
                            .map(|(_, (status, _))| status)
                            .all(|status| *status == InputType::InputShares)
                    };
                    if is_done {
                        break;
                    }
                }

                let shares = node
                    .preprocess
                    .input
                    .wait_for_all_inputs(Duration::from_millis(0))
                    .await
                    .expect("input error");

                let server_shares = match shares.get(&client_id) {
                    Some(s) => s.clone(),
                    None => {
                        let _ = tx.send(Err(format!("node {} missing client shares", id)));
                        let _ = done_tx.send(());
                        return Ok(());
                    }
                };

                let _ = tx.send(Ok(Some(server_shares)));
                let _ = done_tx.send(());
                Ok(())
            }
        });
    }

    drop(tx);
    drop(done_tx);

    // driver waits for all n+1 hosts to signal done
    let mut done_rx = done_rx;
    sim.client("driver", async move {
        let mut count = 0;
        while count < n + 1 {
            match done_rx.recv().await {
                Ok(()) => count += 1,
                Err(_) => break,
            }
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    });

    sim.run().unwrap();

    let results: Vec<_> = std::iter::from_fn(|| rx_done.try_recv().ok()).collect();
    assert_eq!(
        results.len(),
        n + 1,
        "not all hosts reported: got {}/{}",
        results.len(),
        n + 1
    );

    let mut recovered_shares: Vec<Vec<ShamirShare<Fr, 1, Robust>>> =
        vec![vec![]; input_values.len()];

    for r in results {
        match r {
            Err(e) => panic!("host failed: {}", e),
            Ok(None) => {}
            Ok(Some(server_shares)) => {
                for (i, s) in server_shares.iter().enumerate() {
                    recovered_shares[i].push(s.clone());
                }
            }
        }
    }

    for (i, secret) in input_values.iter().enumerate() {
        let shares: Vec<ShamirShare<Fr, 1, Robust>> = recovered_shares[i].iter().cloned().collect();
        let (_, r) = RobustShare::recover_secret(&shares, n, t).unwrap();
        assert_eq!(r, *secret);
    }
}

fn preprocessing_e2e_turmoil(
    node_delay: Option<Vec<(usize, Duration)>>,
    node_freeze_start: Option<DelayedStart>,
) {
    setup_tracing();

    let n_parties = 4;
    let t = 1;
    let l = 8;
    let k = 4;
    let no_of_triples = 7;
    let no_of_randomshares = 4;
    let instance_id = 111;
    let n_prandbit = 4;
    let n_prandint = 4;

    let (mut sim, inner) = turmoil_setup_with_duration(
        n_parties,
        vec![],
        Some((10, 2000)),
        Duration::from_secs(300_000),
    );

    let (tx, rx_done) = std::sync::mpsc::channel::<Result<(usize, usize, usize, usize), String>>();
    let (done_tx, done_rx) = tokio::sync::broadcast::channel::<()>(n_parties);
    let barrier = Arc::new(tokio::sync::Barrier::new(n_parties));

    let nodes = create_global_nodes::<Fr, Avid<SessionId>, RobustShare<Fr>, TurmoilNetwork>(
        n_parties,
        t,
        no_of_triples,
        no_of_randomshares,
        instance_id,
        n_prandbit,
        n_prandint,
        l,
        k,
        Duration::from_secs(30),
        vec![],
    );

    for id in 0..n_parties {
        let inner = inner.clone();
        let node = nodes[id].clone();
        let tx = tx.clone();
        let done_tx = done_tx.clone();
        let barrier = barrier.clone();

        sim.host(format!("node{}", id), move || {
            let inner = inner.clone();
            let mut node = node.clone();
            let tx = tx.clone();
            let done_tx = done_tx.clone();
            let barrier = barrier.clone();

            async move {
                let (network, mut rx) = TurmoilNetwork::new(SenderId::Node(id), inner).await;
                let network_arc = Arc::new(network);
                barrier.wait().await;

                let mut rng = StdRng::from_rng(OsRng).unwrap();

                // run preprocessing concurrently with the message loop
                // since run_preprocessing sends messages that trigger responses
                let net = network_arc.clone();
                let mut node_for_init = node.clone();
                let preprocessing_handle = tokio::spawn(async move {
                    if let Err(e) = node_for_init.run_preprocessing(net, &mut rng).await {
                        eprintln!("node {} preprocessing error: {:?}", id, e);
                    }
                });

                loop {
                    match rx.recv().await {
                        Some((sender, msg)) => {
                            let sender_id = match sender {
                                SenderId::Node(i) => i,
                                SenderId::Client(i) => i,
                            };
                            if let Err(e) = node.process(sender_id, msg, network_arc.clone()).await
                            {
                                eprintln!("node {} process error: {:?}", id, e);
                            }
                        }
                        None => break,
                    }

                    tokio::task::yield_now().await;

                    // only check counts once preprocessing has fully finished
                    if preprocessing_handle.is_finished() {
                        let len = node.preprocessing_material.lock().await.length();
                        let n_triples = len.beaver_triples;
                        let n_pbit = len.prandbit;
                        let n_pint = len.prandint;
                        // no_of_triples=7 rounds up to a multiple of group_size (2t+1=3) -> 9.
                        if n_triples == 9 && n_pbit == n_prandbit && n_pint == n_prandint {
                            break;
                        }
                    }
                }

                // collect final counts
                let len = node.preprocessing_material.lock().await.length();
                let n_triples = len.beaver_triples;
                let n_shares = len.random_shr;
                let n_pbit = len.prandbit;
                let n_pint = len.prandint;

                let _ = tx.send(Ok((n_triples, n_shares, n_pbit, n_pint)));
                let _ = done_tx.send(());
                Ok(())
            }
        });
    }

    drop(tx);
    drop(done_tx);

    if let Some(delayed_start) = &node_freeze_start {
        for delayed_node in &delayed_start.delayed_nodes {
            for other_id in 0..n_parties {
                if *delayed_node != other_id {
                    sim.hold(format!("node{}", delayed_node), format!("node{}", other_id));
                }
            }
        }
    }

    let mut done_rx = done_rx;
    sim.client("driver", async move {
        if let Some(delayed_start) = node_freeze_start {
            tokio::time::sleep(delayed_start.time).await;

            // Now, the nodes connect again
            for freezed_node in delayed_start.delayed_nodes {
                for other_id in 0..n_parties {
                    if freezed_node != other_id {
                        turmoil::release(
                            format!("node{}", freezed_node),
                            format!("node{}", other_id),
                        );
                    }
                }
            }
        }

        let mut count = 0;
        while count < n_parties {
            match done_rx.recv().await {
                Ok(()) => count += 1,
                Err(_) => break,
            }
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    });

    if let Some(delayed_nodes) = node_delay {
        for (slow_node, delay) in delayed_nodes {
            for other_id in 0..n_parties {
                if slow_node != other_id {
                    sim.set_link_latency(
                        format!("node{}", slow_node),
                        format!("node{}", other_id),
                        delay,
                    );
                }
            }
        }
    }

    sim.run().unwrap();

    let results: Vec<_> = std::iter::from_fn(|| rx_done.try_recv().ok()).collect();
    assert_eq!(
        results.len(),
        n_parties,
        "not all nodes reported: got {}/{}",
        results.len(),
        n_parties
    );

    for r in results {
        match r {
            Err(e) => panic!("node failed: {}", e),
            Ok((n_triples, n_shares, n_pbit, n_pint)) => {
                assert_eq!(n_triples, 9); // no_of_triples=7 rounds up to group_size (2t+1=3) -> 9
                assert_eq!(n_shares, 4); // no_of_randomshares=4 remain after triple gen
                assert_eq!(n_pbit, 4);
                assert_eq!(n_pint, 4);
            }
        }
    }
}

#[test]
fn preprocessing_e2e_with_delay() {
    let slow_nodes = Some(vec![(0, Duration::from_secs(3))]);
    preprocessing_e2e_turmoil(slow_nodes, None);
}

#[test]
fn preprocessing_e2e_without_delay() {
    preprocessing_e2e_turmoil(None, None);
}

#[test]
fn preprocessing_e2e_with_freeze_start() {
    preprocessing_e2e_turmoil(
        None,
        Some(DelayedStart {
            delayed_nodes: vec![0],
            time: Duration::from_secs(3),
        }),
    );
}

#[test]
#[ignore = "expensive repro: attempts to produce 402,000,000 HoneyBadger random shares"]
fn honeybadger_402m_random_shares_5_nodes_t1_turmoil() {
    setup_quiet_tracing();

    let n_parties = 5;
    let t = 1;
    let n_random_shares = 402_000_000usize;
    let instance_id = 111;

    let (mut sim, inner) = turmoil_setup_with_duration(
        n_parties,
        vec![],
        Some((10, 2000)),
        Duration::from_secs(300_000),
    );
    let (tx, rx_done) = std::sync::mpsc::channel::<Result<usize, String>>();
    let (done_tx, done_rx) = tokio::sync::broadcast::channel::<()>(n_parties);
    let barrier = Arc::new(Barrier::new(n_parties));

    let nodes = create_global_nodes::<Fr, Avid<SessionId>, RobustShare<Fr>, TurmoilNetwork>(
        n_parties,
        t,
        0,
        n_random_shares,
        instance_id,
        0,
        0,
        0,
        0,
        Duration::from_secs(120),
        vec![],
    );

    for id in 0..n_parties {
        let inner = inner.clone();
        let node = nodes[id].clone();
        let tx = tx.clone();
        let done_tx = done_tx.clone();
        let barrier = barrier.clone();

        sim.host(format!("node{}", id), move || {
            let inner = inner.clone();
            let mut node = node.clone();
            let tx = tx.clone();
            let done_tx = done_tx.clone();
            let barrier = barrier.clone();

            async move {
                let (network, mut rx) = TurmoilNetwork::new(SenderId::Node(id), inner).await;
                let network_arc = Arc::new(network);
                barrier.wait().await;

                let net = network_arc.clone();
                let mut node_for_preprocessing = node.clone();
                let preprocessing_handle = tokio::spawn(async move {
                    let mut rng = StdRng::from_rng(OsRng).unwrap();
                    node_for_preprocessing
                        .run_preprocessing(net, &mut rng)
                        .await
                });

                let mut msg_count = 0usize;
                let mut last_store_log = Instant::now();
                loop {
                    if preprocessing_handle.is_finished() {
                        break;
                    }

                    match timeout(Duration::from_millis(100), rx.recv()).await {
                        Ok(Some((sender, msg))) => {
                            msg_count += 1;
                            if last_store_log.elapsed() >= Duration::from_secs(5) {
                                eprintln!(
                                    "[402m-store] node={} msgs={} {}",
                                    id,
                                    msg_count,
                                    node.debug_store_sizes().await
                                );
                                last_store_log = Instant::now();
                            }
                            let sender_id = match sender {
                                SenderId::Node(i) => i,
                                SenderId::Client(i) => i,
                            };
                            if let Err(e) = node.process(sender_id, msg, network_arc.clone()).await
                            {
                                let _ = tx.send(Err(format!(
                                    "node {} process error after {} msgs: {:?}; {}",
                                    id,
                                    msg_count,
                                    e,
                                    node.debug_store_sizes().await
                                )));
                                let _ = done_tx.send(());
                                return Ok(());
                            }
                        }
                        Ok(None) => break,
                        Err(_) => {
                            if last_store_log.elapsed() >= Duration::from_secs(5) {
                                eprintln!(
                                    "[402m-store] node={} msgs={} {}",
                                    id,
                                    msg_count,
                                    node.debug_store_sizes().await
                                );
                                last_store_log = Instant::now();
                            }
                        }
                    }
                }

                match preprocessing_handle.await {
                    Ok(Ok(())) => {
                        let len = node.preprocessing_material.lock().await.length();
                        let produced_random_shares = len.random_shr;
                        if produced_random_shares == n_random_shares {
                            eprintln!(
                                "[402m-store] node={} completed msgs={} {}",
                                id,
                                msg_count,
                                node.debug_store_sizes().await
                            );
                            let _ = tx.send(Ok(produced_random_shares));
                        } else {
                            let _ = tx.send(Err(format!(
                                "node {} produced {} random shares, expected {}; {}",
                                id,
                                produced_random_shares,
                                n_random_shares,
                                node.debug_store_sizes().await
                            )));
                        }
                    }
                    Ok(Err(e)) => {
                        let _ = tx.send(Err(format!(
                            "node {} preprocessing failed after {} msgs: {:?}; {}",
                            id,
                            msg_count,
                            e,
                            node.debug_store_sizes().await
                        )));
                    }
                    Err(e) => {
                        let _ = tx.send(Err(format!(
                            "node {} preprocessing join error: {:?}",
                            id, e
                        )));
                    }
                }

                let _ = done_tx.send(());
                Ok(())
            }
        });
    }

    drop(tx);
    drop(done_tx);

    let mut done_rx = done_rx;
    sim.client("driver", async move {
        let mut count = 0;
        while count < n_parties {
            match done_rx.recv().await {
                Ok(()) => count += 1,
                Err(_) => break,
            }
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    });

    if let Err(error) = sim.run() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            for (id, node) in nodes.iter().enumerate() {
                eprintln!(
                    "[402m-store-final] node={} sim_error={} {}",
                    id,
                    error,
                    node.debug_store_sizes().await
                );
            }
        });
        panic!("turmoil simulation failed: {error}");
    }

    let results: Vec<_> = std::iter::from_fn(|| rx_done.try_recv().ok()).collect();
    assert_eq!(
        results.len(),
        n_parties,
        "not all nodes reported: got {}/{}",
        results.len(),
        n_parties
    );

    for result in results {
        match result {
            Ok(produced) => assert_eq!(produced, n_random_shares),
            Err(error) => panic!("{}", error),
        }
    }
}

fn run_preprocessing_stress_turmoil(
    n_parties: usize,
    t: usize,
    n_triples: usize,
    n_random_shares: usize,
    n_prandbit: usize,
    n_prandint: usize,
    env_overrides: &[(&str, &str)],
) {
    setup_quiet_tracing();

    let old_env = env_overrides
        .iter()
        .map(|(key, _)| (*key, std::env::var(key).ok()))
        .collect::<Vec<_>>();
    for (key, value) in env_overrides {
        std::env::set_var(key, value);
    }

    let instance_id = 111;
    let (mut sim, inner) = turmoil_setup(n_parties, vec![], Some((1, 20)));
    let (tx, rx_done) = std::sync::mpsc::channel::<Result<(usize, usize, usize, usize), String>>();
    let (done_tx, done_rx) = tokio::sync::broadcast::channel::<()>(n_parties);
    let barrier = Arc::new(Barrier::new(n_parties));

    let nodes = create_global_nodes::<Fr, Avid<SessionId>, RobustShare<Fr>, TurmoilNetwork>(
        n_parties,
        t,
        n_triples,
        n_random_shares,
        instance_id,
        n_prandbit,
        n_prandint,
        8,
        4,
        Duration::from_secs(120),
        vec![],
    );

    for id in 0..n_parties {
        let inner = inner.clone();
        let node = nodes[id].clone();
        let tx = tx.clone();
        let done_tx = done_tx.clone();
        let barrier = barrier.clone();

        sim.host(format!("node{}", id), move || {
            let inner = inner.clone();
            let mut node = node.clone();
            let tx = tx.clone();
            let done_tx = done_tx.clone();
            let barrier = barrier.clone();

            async move {
                let (network, mut rx) = TurmoilNetwork::new(SenderId::Node(id), inner).await;
                let network_arc = Arc::new(network);
                barrier.wait().await;

                let net = network_arc.clone();
                let mut node_for_preprocessing = node.clone();
                let preprocessing_handle = tokio::spawn(async move {
                    let mut rng = StdRng::from_rng(OsRng).unwrap();
                    node_for_preprocessing
                        .run_preprocessing(net, &mut rng)
                        .await
                });

                let mut msg_count = 0usize;
                loop {
                    if preprocessing_handle.is_finished() {
                        break;
                    }

                    match timeout(Duration::from_millis(100), rx.recv()).await {
                        Ok(Some((sender, msg))) => {
                            msg_count += 1;
                            let sender_id = match sender {
                                SenderId::Node(i) => i,
                                SenderId::Client(i) => i,
                            };
                            if let Err(e) = node.process(sender_id, msg, network_arc.clone()).await
                            {
                                let _ = tx.send(Err(format!(
                                    "node {} process error after {} msgs: {:?}",
                                    id, msg_count, e
                                )));
                                let _ = done_tx.send(());
                                return Ok(());
                            }
                        }
                        Ok(None) => break,
                        Err(_) => {}
                    }
                }

                match preprocessing_handle.await {
                    Ok(Ok(())) => {
                        let len = node.preprocessing_material.lock().await.length();
                        let counts = (
                            len.beaver_triples,
                            len.random_shr,
                            len.prandbit,
                            len.prandint,
                        );
                        let _ = tx.send(Ok(counts));
                    }
                    Ok(Err(e)) => {
                        let _ = tx.send(Err(format!(
                            "node {} preprocessing failed after {} msgs: {:?}",
                            id, msg_count, e
                        )));
                    }
                    Err(e) => {
                        let _ = tx.send(Err(format!(
                            "node {} preprocessing join error: {:?}",
                            id, e
                        )));
                    }
                }

                let _ = done_tx.send(());
                Ok(())
            }
        });
    }

    drop(tx);
    drop(done_tx);

    let mut done_rx = done_rx;
    sim.client("driver", async move {
        let mut count = 0;
        while count < n_parties {
            match done_rx.recv().await {
                Ok(()) => count += 1,
                Err(_) => break,
            }
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    });

    if let Err(error) = sim.run() {
        let snapshot = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async { preprocessing_stress_snapshot(&nodes).await });
        panic!("turmoil run failed: {error}\n{snapshot}");
    }

    for (key, value) in old_env {
        match value {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }
    }

    let results: Vec<_> = std::iter::from_fn(|| rx_done.try_recv().ok()).collect();
    assert_eq!(
        results.len(),
        n_parties,
        "not all nodes reported: got {}/{}",
        results.len(),
        n_parties
    );

    for result in results {
        let (produced_triples, produced_random_shares, produced_pbits, produced_pints) =
            result.unwrap_or_else(|error| panic!("{}", error));

        assert!(
            produced_triples >= n_triples.saturating_sub(n_prandbit),
            "produced {} triples, expected at least {}",
            produced_triples,
            n_triples.saturating_sub(n_prandbit)
        );
        assert!(
            produced_random_shares >= n_random_shares.saturating_sub(n_prandbit),
            "produced {} random shares, expected at least {}",
            produced_random_shares,
            n_random_shares.saturating_sub(n_prandbit)
        );
        assert!(
            produced_pbits >= n_prandbit,
            "produced {} probabilistic bits, expected at least {}",
            produced_pbits,
            n_prandbit
        );
        assert!(
            produced_pints >= n_prandint,
            "produced {} probabilistic ints, expected at least {}",
            produced_pints,
            n_prandint
        );
    }
}

async fn preprocessing_stress_snapshot(
    nodes: &[stoffelmpc_mpc::honeybadger::HoneyBadgerMPCNode<Fr, Avid<SessionId>>],
) -> String {
    let mut out = String::new();
    out.push_str("preprocessing stress snapshot:\n");

    for node in nodes {
        let len = node.preprocessing_material.lock().await.length();
        let n_triples = len.beaver_triples;
        let n_random = len.random_shr;
        let n_pbits = len.prandbit;
        let n_pints = len.prandint;
        out.push_str(&format!(
            "node {} material triples={} random={} pbits={} pints={}\n",
            node.id, n_triples, n_random, n_pbits, n_pints
        ));

        let rand_bit_sessions = node
            .preprocess
            .small_field_preproc
            .rand_bit
            .storage
            .lock()
            .await;
        out.push_str(&format!(
            "node {} rand_bit.sessions={}\n",
            node.id,
            rand_bit_sessions.len()
        ));
        for (session_id, store) in rand_bit_sessions.iter().take(8) {
            let store = store.lock().await;
            out.push_str(&format!(
                "  rand_bit {:?} state={:?} a_len={} output_len={} openings={}\n",
                session_id,
                store.protocol_state,
                store
                    .a_share
                    .as_ref()
                    .map(|shares| shares.len())
                    .unwrap_or(0),
                store
                    .protocol_output
                    .as_ref()
                    .map(|shares| shares.len())
                    .unwrap_or(0),
                store.output_open.len()
            ));
        }
        drop(rand_bit_sessions);

        let rand_bit_batch_output_len = node
            .preprocess
            .small_field_preproc
            .rand_bit
            .batch_output
            .lock()
            .await
            .len();
        out.push_str(&format!(
            "node {} rand_bit.batch_output.pending={}\n",
            node.id, rand_bit_batch_output_len
        ));

        let rand_bit_mul_sessions = node
            .preprocess
            .small_field_preproc
            .rand_bit
            .mult_node
            .mult_storage
            .lock()
            .await;
        out.push_str(&format!(
            "node {} rand_bit.mul.sessions={}\n",
            node.id,
            rand_bit_mul_sessions.len()
        ));
        for (session_id, store) in rand_bit_mul_sessions.iter().take(8) {
            let store = store.lock().await;
            out.push_str(&format!(
                "  rand_bit.mul {:?} state={:?} no_of_mul={:?} inputs=({}, {}) received_shares={} openings={} open_mult1={} open_mult2={}\n",
                session_id,
                store.protocol_state,
                store.no_of_mul,
                store.inputs.0.len(),
                store.inputs.1.len(),
                store.received_shares.len(),
                store.openings.is_some(),
                store.output_open_mult1.len(),
                store.output_open_mult2.len()
            ));
        }
        drop(rand_bit_mul_sessions);

        let rand_bit_mul_batch_output_len = node
            .preprocess
            .small_field_preproc
            .rand_bit
            .mult_node
            .batch_output
            .lock()
            .await
            .len();
        let rand_bit_mul_rbc_output_len = node
            .preprocess
            .small_field_preproc
            .rand_bit
            .mult_node
            .rbc_output
            .lock()
            .await
            .len();
        out.push_str(&format!(
            "node {} rand_bit.mul.batch_output.pending={} rbc_output.pending={}\n",
            node.id, rand_bit_mul_batch_output_len, rand_bit_mul_rbc_output_len
        ));

        let rand_bit_mul_batch_sessions = node
            .preprocess
            .small_field_preproc
            .rand_bit
            .mult_node
            .batch_recon
            .store
            .lock()
            .await;
        let mut min_sub_id = u8::MAX;
        let mut max_sub_id = 0u8;
        let mut y_j_count = 0usize;
        let mut any_reveals = 0usize;
        let mut secrets_count = 0usize;
        let mut total_evals = 0usize;
        let mut total_reveals = 0usize;
        for (session_id, store) in rand_bit_mul_batch_sessions.iter() {
            let store = store.lock().await;
            min_sub_id = min_sub_id.min(session_id.sub_id());
            max_sub_id = max_sub_id.max(session_id.sub_id());
            if store.y_j.is_some() {
                y_j_count += 1;
            }
            if !store.reveals_received.is_empty() {
                any_reveals += 1;
            }
            if store.secrets.is_some() {
                secrets_count += 1;
            }
            total_evals += store.evals_received.len();
            total_reveals += store.reveals_received.len();
        }
        out.push_str(&format!(
            "node {} rand_bit.mul.batch_recon.sessions={} sub_id_range={}..={} y_j_sessions={} sessions_with_reveals={} secrets_sessions={} total_evals={} total_reveals={}\n",
            node.id,
            rand_bit_mul_batch_sessions.len(),
            if rand_bit_mul_batch_sessions.is_empty() {
                0
            } else {
                min_sub_id
            },
            max_sub_id,
            y_j_count,
            any_reveals,
            secrets_count,
            total_evals,
            total_reveals
        ));
        for (session_id, store) in rand_bit_mul_batch_sessions.iter().take(8) {
            let store = store.lock().await;
            out.push_str(&format!(
                "  rand_bit.mul.batch {:?} evals={} reveals={} batch_evals={} batch_reveals={} y_j={} y_j_batch_len={} secrets_len={}\n",
                session_id,
                store.evals_received.len(),
                store.reveals_received.len(),
                store.batch_evals_received.len(),
                store.batch_reveals_received.len(),
                store.y_j.is_some(),
                store.y_j_batch.as_ref().map(|values| values.len()).unwrap_or(0),
                store.secrets.as_ref().map(|values| values.len()).unwrap_or(0)
            ));
        }
        drop(rand_bit_mul_batch_sessions);

        let rand_bit_batch_sessions = node
            .preprocess
            .small_field_preproc
            .rand_bit
            .batch_recon
            .store
            .lock()
            .await;
        let mut y_j_count = 0usize;
        let mut any_reveals = 0usize;
        let mut secrets_count = 0usize;
        let mut total_evals = 0usize;
        let mut total_reveals = 0usize;
        for (_, store) in rand_bit_batch_sessions.iter() {
            let store = store.lock().await;
            if store.y_j.is_some() {
                y_j_count += 1;
            }
            if !store.reveals_received.is_empty() {
                any_reveals += 1;
            }
            if store.secrets.is_some() {
                secrets_count += 1;
            }
            total_evals += store.evals_received.len();
            total_reveals += store.reveals_received.len();
        }
        out.push_str(&format!(
            "node {} rand_bit.batch_recon.sessions={} y_j_sessions={} sessions_with_reveals={} secrets_sessions={} total_evals={} total_reveals={}\n",
            node.id,
            rand_bit_batch_sessions.len(),
            y_j_count,
            any_reveals,
            secrets_count,
            total_evals,
            total_reveals
        ));
        for (session_id, store) in rand_bit_batch_sessions.iter().take(8) {
            let store = store.lock().await;
            out.push_str(&format!(
                "  rand_bit.batch {:?} evals={} reveals={} batch_evals={} batch_reveals={} y_j={} y_j_batch_len={} secrets_len={}\n",
                session_id,
                store.evals_received.len(),
                store.reveals_received.len(),
                store.batch_evals_received.len(),
                store.batch_reveals_received.len(),
                store.y_j.is_some(),
                store.y_j_batch.as_ref().map(|values| values.len()).unwrap_or(0),
                store.secrets.as_ref().map(|values| values.len()).unwrap_or(0)
            ));
        }
    }

    out
}

#[test]
#[ignore = "stress repro: 1000 back-to-back top-level Mul executions (regression for the u8 exec_id / 256 LimitError, now u64)"]
fn honeybadger_sequential_mul_1000_turmoil() {
    setup_quiet_tracing();

    let n_parties = 4;
    let t = 1;
    let no_of_multiplication = 1000;

    let mut rng = test_rng();
    let mut x_values = Vec::with_capacity(no_of_multiplication);
    let mut y_values = Vec::with_capacity(no_of_multiplication);
    let mut x_inputs_per_node = vec![Vec::with_capacity(no_of_multiplication); n_parties];
    let mut y_inputs_per_node = vec![Vec::with_capacity(no_of_multiplication); n_parties];

    for _ in 0..no_of_multiplication {
        let x_value = Fr::rand(&mut rng);
        let y_value = Fr::rand(&mut rng);
        x_values.push(x_value);
        y_values.push(y_value);

        let shares_x = RobustShare::compute_shares(x_value, n_parties, t, None, &mut rng).unwrap();
        let shares_y = RobustShare::compute_shares(y_value, n_parties, t, None, &mut rng).unwrap();

        for p in 0..n_parties {
            x_inputs_per_node[p].push(shares_x[p].clone());
            y_inputs_per_node[p].push(shares_y[p].clone());
        }
    }

    let (_, triple) = construct_e2e_input_mul(n_parties, no_of_multiplication, t);
    let nodes = create_global_nodes::<Fr, Avid<SessionId>, RobustShare<Fr>, TurmoilNetwork>(
        n_parties,
        t,
        0,
        0,
        111,
        0,
        0,
        0,
        0,
        Duration::from_secs(120),
        vec![],
    );

    tokio::runtime::Runtime::new().unwrap().block_on(async {
        for pid in 0..n_parties {
            nodes[pid].preprocessing_material.lock().await.add(
                Some(triple[pid].clone()),
                None,
                None,
                None,
                None,
                None,
            );
        }
    });

    let (mut sim, inner) = turmoil_setup(n_parties, vec![], Some((1, 20)));
    let (tx, rx_done) = std::sync::mpsc::channel::<Result<(usize, Vec<RobustShare<Fr>>), String>>();
    let (done_tx, done_rx) = tokio::sync::broadcast::channel::<()>(n_parties);
    let barrier = Arc::new(Barrier::new(n_parties));

    for id in 0..n_parties {
        let inner = inner.clone();
        let node = nodes[id].clone();
        let tx = tx.clone();
        let done_tx = done_tx.clone();
        let barrier = barrier.clone();
        let x_shares = x_inputs_per_node[id].clone();
        let y_shares = y_inputs_per_node[id].clone();

        sim.host(format!("node{}", id), move || {
            let inner = inner.clone();
            let mut node = node.clone();
            let tx = tx.clone();
            let done_tx = done_tx.clone();
            let barrier = barrier.clone();
            let x_shares = x_shares.clone();
            let y_shares = y_shares.clone();

            async move {
                let (network, mut rx) = TurmoilNetwork::new(SenderId::Node(id), inner).await;
                let network_arc = Arc::new(network);
                barrier.wait().await;

                let net = network_arc.clone();
                let mut node_for_mul = node.clone();
                let mul_handle = tokio::spawn(async move {
                    let mut outputs = Vec::with_capacity(no_of_multiplication);
                    for i in 0..no_of_multiplication {
                        info!("Sequential Mul run {}", i);
                        let mut result = node_for_mul
                            .mul(
                                vec![x_shares[i].clone()],
                                vec![y_shares[i].clone()],
                                net.clone(),
                            )
                            .await?;
                        outputs.push(result.remove(0));
                    }
                    Ok::<Vec<RobustShare<Fr>>, stoffelmpc_mpc::honeybadger::HoneyBadgerError>(
                        outputs,
                    )
                });

                let mut msg_count = 0usize;
                loop {
                    if mul_handle.is_finished() {
                        break;
                    }

                    match timeout(Duration::from_millis(100), rx.recv()).await {
                        Ok(Some((sender, msg))) => {
                            msg_count += 1;
                            let sender_id = match sender {
                                SenderId::Node(i) => i,
                                SenderId::Client(i) => i,
                            };
                            if let Err(e) = node.process(sender_id, msg, network_arc.clone()).await
                            {
                                let _ = tx.send(Err(format!(
                                    "node {} process error after {} msgs: {:?}",
                                    id, msg_count, e
                                )));
                                let _ = done_tx.send(());
                                return Ok(());
                            }
                        }
                        Ok(None) => break,
                        Err(_) => {}
                    }
                }

                match mul_handle.await {
                    Ok(Ok(shares)) => {
                        let _ = tx.send(Ok((id, shares)));
                    }
                    Ok(Err(e)) => {
                        let _ = tx.send(Err(format!(
                            "node {} sequential mul failed after {} msgs: {:?}",
                            id, msg_count, e
                        )));
                    }
                    Err(e) => {
                        let _ = tx.send(Err(format!("node {} mul join error: {:?}", id, e)));
                    }
                }

                let _ = done_tx.send(());
                Ok(())
            }
        });
    }

    drop(tx);
    drop(done_tx);

    let mut done_rx = done_rx;
    sim.client("driver", async move {
        let mut count = 0;
        while count < n_parties {
            match done_rx.recv().await {
                Ok(()) => count += 1,
                Err(_) => break,
            }
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    });

    sim.run().unwrap();

    let results: Vec<_> = std::iter::from_fn(|| rx_done.try_recv().ok()).collect();
    assert_eq!(
        results.len(),
        n_parties,
        "not all nodes reported: got {}/{}",
        results.len(),
        n_parties
    );

    let mut final_results = std::collections::HashMap::<usize, Vec<RobustShare<Fr>>>::new();
    for result in results {
        match result {
            Ok((id, shares)) => {
                assert_eq!(shares.len(), no_of_multiplication);
                final_results.insert(id, shares);
            }
            Err(error) => panic!("{}", error),
        }
    }

    for i in 0..no_of_multiplication {
        let shares_for_i = (0..n_parties)
            .map(|pid| final_results.get(&pid).unwrap()[i].clone())
            .collect::<Vec<_>>();
        let (_, z_rec) =
            RobustShare::recover_secret(&shares_for_i[0..=(2 * t)], n_parties, t).unwrap();
        assert_eq!(z_rec, x_values[i] * y_values[i]);
    }
}

#[test]
#[ignore = "stress repro: forces more than 256 triple-generation protocol sessions"]
fn honeybadger_triple_heavy_preprocessing_turmoil() {
    run_preprocessing_stress_turmoil(4, 1, 771, 0, 0, 0, &[("HMPC_TRIPLE_BATCH_GROUPS", "1")]);
}

#[test]
#[ignore = "stress repro: forces more than 256 RanDouSha protocol sessions"]
fn honeybadger_randousha_heavy_preprocessing_turmoil() {
    run_preprocessing_stress_turmoil(4, 1, 771, 0, 0, 0, &[("HMPC_RANDOUSHA_BATCH_COLUMNS", "1")]);
}

#[test]
#[ignore = "stress repro: generates triple, RanDouSha, RandBit, PRandBit, and PRandInt material"]
fn honeybadger_multiply_heavy_preprocessing_turmoil() {
    run_preprocessing_stress_turmoil(
        4,
        1,
        1536,
        512,
        512,
        512,
        &[
            ("HMPC_TRIPLE_BATCH_GROUPS", "8"),
            ("HMPC_RANDOUSHA_BATCH_COLUMNS", "8"),
        ],
    );
}

#[test]
fn mul_e2e_with_preprocessing_turmoil_variable_latency() {
    setup_tracing();

    let n_parties = 4;
    let t = 1;
    let no_of_triples = 2 * t + 1;
    let input_client_id: ClientId = 100;
    let output_client_id: ClientId = 200;
    let client_ids = vec![input_client_id, output_client_id];
    let input_values: Vec<Fr> = vec![Fr::from(10), Fr::from(20)];
    let no_of_multiplications = 2;
    let output_values = vec![Fr::from(100), Fr::from(400)];

    let (mut sim, inner) = turmoil_setup(n_parties, client_ids.clone(), Some((10, 2000)));

    let (tx, rx_done) = std::sync::mpsc::channel::<Result<(), String>>();
    let (done_tx, done_rx) = tokio::sync::broadcast::channel::<()>(n_parties + 2);

    // barriers for each phase
    let barrier_connected = Arc::new(tokio::sync::Barrier::new(n_parties + 2)); // nodes + 2 clients
    let barrier_preprocessing_done = Arc::new(tokio::sync::Barrier::new(n_parties));
    let barrier_input_done = Arc::new(tokio::sync::Barrier::new(n_parties + 1)); // nodes + input client
    let barrier_mul_done = Arc::new(tokio::sync::Barrier::new(n_parties));

    let nodes = create_global_nodes::<Fr, Avid<SessionId>, RobustShare<Fr>, TurmoilNetwork>(
        n_parties,
        t,
        no_of_triples,
        2,
        111,
        0,
        0,
        0,
        0,
        Duration::from_secs(30),
        vec![input_client_id],
    );

    let clients = create_clients::<Fr, Avid<SessionId>>(
        client_ids.clone(),
        n_parties,
        t,
        111,
        input_values.clone(),
        2,
    );

    // --- input client host ---
    let inner_ic = inner.clone();
    let tx_ic = tx.clone();
    let done_tx_ic = done_tx.clone();
    let barrier_connected_ic = barrier_connected.clone();
    let barrier_input_done_ic = barrier_input_done.clone();
    let client_ic = clients[&input_client_id].clone();
    sim.host(format!("client{}", input_client_id), move || {
        let inner = inner_ic.clone();
        let tx = tx_ic.clone();
        let done_tx = done_tx_ic.clone();
        let barrier_connected = barrier_connected_ic.clone();
        let barrier_input_done = barrier_input_done_ic.clone();
        let mut client = client_ic.clone();

        async move {
            let (network, mut rx) =
                TurmoilNetwork::new(SenderId::Client(input_client_id), inner).await;
            let network_arc = Arc::new(network);
            barrier_connected.wait().await;

            // message loop for input client
            loop {
                match rx.recv().await {
                    Some((sender, msg)) => {
                        if let SenderId::Node(s) = sender {
                            if let Err(e) = client.process(s, msg, network_arc.clone()).await {
                                let _ = tx.send(Err(format!("input client process error: {}", e)));
                                let _ = done_tx.send(());
                                return Ok(());
                            }
                        }
                    }
                    None => break,
                }

                tokio::task::yield_now().await;

                if client.input.client_data.lock().await.rbc_done {
                    break;
                }
            }

            barrier_input_done.wait().await;

            let _ = tx.send(Ok(()));
            let _ = done_tx.send(());
            Ok(())
        }
    });

    // --- output client host ---
    let inner_oc = inner.clone();
    let tx_oc = tx.clone();
    let done_tx_oc = done_tx.clone();
    let barrier_connected_oc = barrier_connected.clone();
    let client_oc = clients[&output_client_id].clone();
    let output_values_oc = output_values.clone();
    sim.host(format!("client{}", output_client_id), move || {
        let inner = inner_oc.clone();
        let tx = tx_oc.clone();
        let done_tx = done_tx_oc.clone();
        let barrier_connected = barrier_connected_oc.clone();
        let mut client = client_oc.clone();
        let output_values = output_values_oc.clone();

        async move {
            let (network, mut rx) =
                TurmoilNetwork::new(SenderId::Client(output_client_id), inner).await;
            let network_arc = Arc::new(network);
            barrier_connected.wait().await;

            // message loop for output client
            loop {
                match rx.recv().await {
                    Some((sender, msg)) => {
                        if let SenderId::Node(s) = sender {
                            if let Err(e) = client.process(s, msg, network_arc.clone()).await {
                                let _ = tx.send(Err(format!("output client process error: {}", e)));
                                let _ = done_tx.send(());
                                return Ok(());
                            }
                        }
                    }
                    None => break,
                }

                tokio::task::yield_now().await;

                // check if output is ready
                let is_done = {
                    let data = client.output.output_receiver.borrow();
                    data.output.is_some()
                };
                if is_done {
                    info!("Here1");
                    break;
                }
            }

            // verify output
            let output = {
                let data = client.output.output_receiver.borrow();
                data.output.as_ref().unwrap().clone()
            };

            if output != output_values {
                let _ = tx.send(Err(format!(
                    "output mismatch: got {:?}, expected {:?}",
                    output, output_values
                )));
            } else {
                let _ = tx.send(Ok(()));
            }

            let _ = done_tx.send(());
            Ok(())
        }
    });

    // --- node hosts ---
    for id in 0..n_parties {
        let inner = inner.clone();
        let node = nodes[id].clone();
        let tx = tx.clone();
        let done_tx = done_tx.clone();
        let barrier_connected = barrier_connected.clone();
        let barrier_preprocessing_done = barrier_preprocessing_done.clone();
        let barrier_input_done = barrier_input_done.clone();
        let barrier_mul_done = barrier_mul_done.clone();

        sim.host(format!("node{}", id), move || {
            let inner = inner.clone();
            let mut node = node.clone();
            let tx = tx.clone();
            let done_tx = done_tx.clone();
            let barrier_connected = barrier_connected.clone();
            let barrier_preprocessing_done = barrier_preprocessing_done.clone();
            let barrier_input_done = barrier_input_done.clone();
            let barrier_mul_done = barrier_mul_done.clone();

            async move {
                let (network, mut rx) = TurmoilNetwork::new(SenderId::Node(id), inner).await;
                let network_arc = Arc::new(network);
                barrier_connected.wait().await;

                let mut rng = StdRng::from_rng(OsRng).unwrap();

                // --- phase 1: preprocessing ---
                let net = network_arc.clone();
                let mut node_for_preprocessing = node.clone();
                tokio::spawn(async move {
                    if let Err(e) = node_for_preprocessing
                        .run_preprocessing(net, &mut rng)
                        .await
                    {
                        eprintln!("node {} preprocessing error: {:?}", id, e);
                    }
                });

                // message loop until preprocessing done
                loop {
                    match rx.recv().await {
                        Some((sender, msg)) => {
                            let sender_id = match sender {
                                SenderId::Node(i) => i,
                                SenderId::Client(i) => i,
                            };
                            if let Err(e) = node.process(sender_id, msg, network_arc.clone()).await
                            {
                                eprintln!("node {} process error: {:?}", id, e);
                            }
                        }
                        None => break,
                    }

                    tokio::task::yield_now().await;

                    let n_triples = node
                        .preprocessing_material
                        .lock()
                        .await
                        .length()
                        .beaver_triples;
                    if n_triples >= 3 {
                        break;
                    }
                }

                barrier_preprocessing_done.wait().await;

                // --- phase 2: input ---
                let local_shares = node
                    .preprocessing_material
                    .lock()
                    .await
                    .take_random_shares(2)
                    .unwrap();

                if let Err(e) = node
                    .preprocess
                    .input
                    .init(input_client_id, local_shares, 2, network_arc.clone())
                    .await
                {
                    let _ = tx.send(Err(format!("node {} input init error: {}", id, e)));
                    let _ = done_tx.send(());
                    return Ok(());
                }

                // message loop until input done
                loop {
                    match rx.recv().await {
                        Some((sender, msg)) => {
                            let sender_id = match sender {
                                SenderId::Node(i) => i,
                                SenderId::Client(i) => i,
                            };
                            if let Err(e) = node.process(sender_id, msg, network_arc.clone()).await
                            {
                                eprintln!("node {} process error: {:?}", id, e);
                            }
                        }
                        None => break,
                    }

                    tokio::task::yield_now().await;

                    let is_done = {
                        let statuses = node.preprocess.input.status_receiver.borrow();
                        statuses
                            .iter()
                            .map(|(_, (status, _))| status)
                            .all(|status| *status == InputType::InputShares)
                    };
                    if is_done {
                        break;
                    }
                }

                barrier_input_done.wait().await;

                // --- phase 3: multiplication ---
                let (x_shares, y_shares) = {
                    let input_store = node
                        .preprocess
                        .input
                        .wait_for_all_inputs(Duration::from_millis(0))
                        .await
                        .expect("input error");
                    let inputs = input_store.get(&input_client_id).unwrap();
                    (
                        vec![inputs[0].clone(), inputs[1].clone()],
                        vec![inputs[0].clone(), inputs[1].clone()],
                    )
                };

                let mut node_for_mul = node.clone();
                let net = network_arc.clone();
                let mul_done_tx = done_tx.clone();
                let mul_tx = tx.clone();
                let mul_shares_handle = tokio::spawn(async move {
                    match node_for_mul.mul(x_shares, y_shares, net).await {
                        Ok(shares) => Some(shares),
                        Err(e) => {
                            let _ = mul_tx.send(Err(format!("node {} mul error: {:?}", id, e)));
                            let _ = mul_done_tx.send(());
                            None
                        }
                    }
                });

                // message loop until mul done
                loop {
                    match rx.recv().await {
                        Some((sender, msg)) => {
                            let sender_id = match sender {
                                SenderId::Node(i) => i,
                                SenderId::Client(i) => i,
                            };
                            if let Err(e) = node.process(sender_id, msg, network_arc.clone()).await
                            {
                                eprintln!("node {} process error: {:?}", id, e);
                            }
                        }
                        None => break,
                    }

                    tokio::task::yield_now().await;

                    if mul_shares_handle.is_finished() {
                        break;
                    }
                }

                let mul_shares = match mul_shares_handle.await {
                    Ok(Some(shares)) => shares,
                    _ => return Ok(()),
                };

                barrier_mul_done.wait().await;

                // --- phase 4: output ---
                if let Err(e) = node
                    .output
                    .init(
                        output_client_id,
                        mul_shares,
                        no_of_multiplications,
                        network_arc.clone(),
                    )
                    .await
                {
                    let _ = tx.send(Err(format!("node {} output init error: {}", id, e)));
                    let _ = done_tx.send(());
                    return Ok(());
                }

                // message loop until output client receives
                // nodes just need to send, no further processing needed
                let _ = tx.send(Ok(()));
                let _ = done_tx.send(());
                Ok(())
            }
        });
    }

    drop(tx);
    drop(done_tx);

    let mut done_rx = done_rx;
    sim.client("driver", async move {
        let mut count = 0;
        while count < n_parties + 2 {
            match done_rx.recv().await {
                Ok(()) => count += 1,
                Err(_) => break,
            }
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    });

    sim.run().unwrap();

    let results: Vec<_> = std::iter::from_fn(|| rx_done.try_recv().ok()).collect();
    assert_eq!(
        results.len(),
        n_parties + 2,
        "not all hosts reported: got {}/{}",
        results.len(),
        n_parties + 2
    );
    for r in results {
        assert!(r.is_ok(), "host failed: {}", r.unwrap_err());
    }
}

#[test]
fn randousha_e2e_turmoil() {
    setup_tracing();

    let n_parties = 4;
    let t = 1;
    let degree_t = 1;
    let session_id = SessionId::new(
        ProtocolType::Randousha,
        SessionId::pack_slot(123, 0, 0),
        111,
    );

    let (mut sim, inner) = turmoil_setup(n_parties, vec![], Some((10, 2000)));
    let (tx, rx_done) = std::sync::mpsc::channel::<Result<(), String>>();
    let (done_tx, done_rx) = tokio::sync::broadcast::channel::<()>(n_parties);
    let barrier = Arc::new(tokio::sync::Barrier::new(n_parties));

    let (_, n_shares_t, n_shares_2t) = construct_e2e_input(n_parties, degree_t);
    let nodes = create_global_nodes::<Fr, Avid<SessionId>, RobustShare<Fr>, TurmoilNetwork>(
        n_parties,
        t,
        0,
        0,
        111,
        0,
        0,
        0,
        0,
        Duration::from_secs(30),
        vec![],
    );

    for id in 0..n_parties {
        let inner = inner.clone();
        let node = nodes[id].clone();
        let tx = tx.clone();
        let done_tx = done_tx.clone();
        let barrier = barrier.clone();
        let n_shares_t = n_shares_t.clone();
        let n_shares_2t = n_shares_2t.clone();

        sim.host(format!("node{}", id), move || {
            let inner = inner.clone();
            let mut node = node.clone();
            let tx = tx.clone();
            let done_tx = done_tx.clone();
            let barrier = barrier.clone();
            let n_shares_t = n_shares_t.clone();
            let n_shares_2t = n_shares_2t.clone();

            async move {
                let (network, mut rx) = TurmoilNetwork::new(SenderId::Node(id), inner).await;
                let network_arc = Arc::new(network);
                barrier.wait().await;

                // init
                if let Err(e) = node
                    .preprocess
                    .ran_dou_sha
                    .init(
                        n_shares_t[id].clone(),
                        n_shares_2t[id].clone(),
                        session_id,
                        network_arc.clone(),
                    )
                    .await
                {
                    let _ = tx.send(Err(format!("node {} init error: {:?}", id, e)));
                    let _ = done_tx.send(());
                    return Ok(());
                }

                // message loop
                loop {
                    match rx.recv().await {
                        Some((sender, msg)) => {
                            let sender_id = match sender {
                                SenderId::Node(i) => i,
                                SenderId::Client(i) => i,
                            };
                            if let Err(e) = node.process(sender_id, msg, network_arc.clone()).await
                            {
                                eprintln!("node {} process error: {:?}", id, e);
                            }
                        }
                        None => break,
                    }

                    tokio::task::yield_now().await;

                    let store = node
                        .preprocess
                        .ran_dou_sha
                        .get_or_create_store(session_id)
                        .await
                        .unwrap();
                    let store = store.lock().await;
                    if store.state == RanDouShaState::Finished {
                        break;
                    }
                }

                // verify
                let store = node
                    .preprocess
                    .ran_dou_sha
                    .get_or_create_store(session_id)
                    .await
                    .unwrap();
                let store = store.lock().await;

                if store.state != RanDouShaState::Finished {
                    let _ = tx.send(Err(format!("node {} did not finish", id)));
                    let _ = done_tx.send(());
                    return Ok(());
                }

                for (s_t, s_2t) in store
                    .computed_r_shares_degree_t
                    .iter()
                    .zip(&store.computed_r_shares_degree_2t)
                {
                    if s_t.degree != t {
                        let _ = tx.send(Err(format!(
                            "node {} s_t degree {} != {}",
                            id, s_t.degree, t
                        )));
                        let _ = done_tx.send(());
                        return Ok(());
                    }
                    if s_2t.degree != 2 * t {
                        let _ = tx.send(Err(format!(
                            "node {} s_2t degree {} != {}",
                            id,
                            s_2t.degree,
                            2 * t
                        )));
                        let _ = done_tx.send(());
                        return Ok(());
                    }
                    if s_t.id != node.id {
                        let _ = tx.send(Err(format!("node {} s_t id mismatch", id)));
                        let _ = done_tx.send(());
                        return Ok(());
                    }
                    if s_2t.id != node.id {
                        let _ = tx.send(Err(format!("node {} s_2t id mismatch", id)));
                        let _ = done_tx.send(());
                        return Ok(());
                    }
                }

                let _ = tx.send(Ok(()));
                let _ = done_tx.send(());
                Ok(())
            }
        });
    }

    drop(tx);
    drop(done_tx);

    let mut done_rx = done_rx;
    sim.client("driver", async move {
        let mut count = 0;
        while count < n_parties {
            match done_rx.recv().await {
                Ok(()) => count += 1,
                Err(_) => break,
            }
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    });

    sim.run().unwrap();

    let results: Vec<_> = std::iter::from_fn(|| rx_done.try_recv().ok()).collect();
    assert_eq!(
        results.len(),
        n_parties,
        "not all nodes reported: got {}/{}",
        results.len(),
        n_parties
    );
    for r in results {
        assert!(r.is_ok(), "node failed: {}", r.unwrap_err());
    }
}

#[test]
fn mul_e2e_without_preprocessing_turmoil() {
    setup_tracing();

    let n_parties = 4;
    let t = 1;
    let no_of_multiplication = 5;

    let mut rng = test_rng();
    let mut x_values = Vec::new();
    let mut y_values = Vec::new();
    let mut x_inputs_per_node = vec![Vec::new(); n_parties];
    let mut y_inputs_per_node = vec![Vec::new(); n_parties];

    for _ in 0..no_of_multiplication {
        let x_value = Fr::rand(&mut rng);
        let y_value = Fr::rand(&mut rng);
        x_values.push(x_value);
        y_values.push(y_value);

        let shares_x = RobustShare::compute_shares(x_value, n_parties, t, None, &mut rng).unwrap();
        let shares_y = RobustShare::compute_shares(y_value, n_parties, t, None, &mut rng).unwrap();

        for p in 0..n_parties {
            x_inputs_per_node[p].push(shares_x[p].clone());
            y_inputs_per_node[p].push(shares_y[p].clone());
        }
    }

    let (_, triple) = construct_e2e_input_mul(n_parties, no_of_multiplication, t);

    let nodes = create_global_nodes::<Fr, Avid<SessionId>, RobustShare<Fr>, TurmoilNetwork>(
        n_parties,
        t,
        0,
        0,
        111,
        0,
        0,
        0,
        0,
        Duration::from_secs(30),
        vec![],
    );

    // load triples before sim starts
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        for pid in 0..n_parties {
            nodes[pid].preprocessing_material.lock().await.add(
                Some(triple[pid].clone()),
                None,
                None,
                None,
                None,
                None,
            );
        }
    });

    let (mut sim, inner) = turmoil_setup(n_parties, vec![], Some((10, 2000)));
    let (tx, rx_done) = std::sync::mpsc::channel::<Result<(usize, Vec<RobustShare<Fr>>), String>>();
    let (done_tx, done_rx) = tokio::sync::broadcast::channel::<()>(n_parties);
    let barrier = Arc::new(tokio::sync::Barrier::new(n_parties));

    for id in 0..n_parties {
        let inner = inner.clone();
        let node = nodes[id].clone();
        let tx = tx.clone();
        let done_tx = done_tx.clone();
        let barrier = barrier.clone();
        let x_shares = x_inputs_per_node[id].clone();
        let y_shares = y_inputs_per_node[id].clone();

        sim.host(format!("node{}", id), move || {
            let inner = inner.clone();
            let mut node = node.clone();
            let tx = tx.clone();
            let done_tx = done_tx.clone();
            let barrier = barrier.clone();
            let x_shares = x_shares.clone();
            let y_shares = y_shares.clone();

            async move {
                let (network, mut rx) = TurmoilNetwork::new(SenderId::Node(id), inner).await;
                let network_arc = Arc::new(network);
                barrier.wait().await;

                let net = network_arc.clone();
                let mut node_for_mul = node.clone();
                let mul_handle =
                    tokio::spawn(async move { node_for_mul.mul(x_shares, y_shares, net).await });

                loop {
                    match rx.recv().await {
                        Some((sender, msg)) => {
                            let sender_id = match sender {
                                SenderId::Node(i) => i,
                                SenderId::Client(i) => i,
                            };
                            if let Err(e) = node.process(sender_id, msg, network_arc.clone()).await
                            {
                                eprintln!("node {} process error: {:?}", id, e);
                            }
                        }
                        None => break,
                    }

                    tokio::task::yield_now().await;

                    if mul_handle.is_finished() {
                        break;
                    }
                }

                let final_shares = match mul_handle.await {
                    Ok(Ok(shares)) => shares,
                    Ok(Err(e)) => {
                        let _ = tx.send(Err(format!("node {} mul error: {:?}", id, e)));
                        let _ = done_tx.send(());
                        return Ok(());
                    }
                    Err(e) => {
                        let _ = tx.send(Err(format!("node {} join error: {:?}", id, e)));
                        let _ = done_tx.send(());
                        return Ok(());
                    }
                };

                if final_shares.len() != no_of_multiplication {
                    let _ = tx.send(Err(format!(
                        "node {} expected {} shares got {}",
                        id,
                        no_of_multiplication,
                        final_shares.len()
                    )));
                    let _ = done_tx.send(());
                    return Ok(());
                }

                for mul_share in &final_shares {
                    if mul_share.degree != t {
                        let _ = tx.send(Err(format!(
                            "node {} share degree {} != {}",
                            id, mul_share.degree, t
                        )));
                        let _ = done_tx.send(());
                        return Ok(());
                    }
                    if mul_share.id != id {
                        let _ = tx.send(Err(format!("node {} share id mismatch", id)));
                        let _ = done_tx.send(());
                        return Ok(());
                    }
                }

                let _ = tx.send(Ok((id, final_shares)));
                let _ = done_tx.send(());
                Ok(())
            }
        });
    }

    drop(tx);
    drop(done_tx);

    let mut done_rx = done_rx;
    sim.client("driver", async move {
        let mut count = 0;
        while count < n_parties {
            match done_rx.recv().await {
                Ok(()) => count += 1,
                Err(_) => break,
            }
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    });

    sim.run().unwrap();

    let results: Vec<_> = std::iter::from_fn(|| rx_done.try_recv().ok()).collect();
    assert_eq!(
        results.len(),
        n_parties,
        "not all nodes reported: got {}/{}",
        results.len(),
        n_parties
    );

    let mut final_results = std::collections::HashMap::<usize, Vec<RobustShare<Fr>>>::new();
    for r in results {
        match r {
            Err(e) => panic!("node failed: {}", e),
            Ok((id, shares)) => {
                final_results.insert(id, shares);
            }
        }
    }

    let mut per_multiplication_shares: Vec<Vec<RobustShare<Fr>>> =
        vec![Vec::new(); no_of_multiplication];

    for pid in 0..n_parties {
        for i in 0..no_of_multiplication {
            per_multiplication_shares[i].push(final_results.get(&pid).unwrap()[i].clone());
        }
    }

    for i in 0..no_of_multiplication {
        let shares_for_i = per_multiplication_shares[i][0..=(2 * t)].to_vec();
        let (_, z_rec) =
            RobustShare::recover_secret(&shares_for_i, n_parties, t).expect("interpolate failed");
        let expected = x_values[i] * y_values[i];
        assert_eq!(z_rec, expected, "multiplication mismatch at index {}", i);
    }
}

fn fpmul_e2e_with_preprocessing(
    node_delay: Option<Vec<(usize, Duration)>>,
    node_freeze_start: Option<DelayedStart>,
) {
    setup_tracing();

    let n_parties = 4;
    let t = 1;
    let k = 16; // total bitlength
    let m = 4; // fractional bits to truncate
    let mut rng = test_rng();
    let n_triples = 1 + m; // 1 (fpmul) + m(no of random bits)
    let n_random_shares = m; // no of random bits
    let n_prandbit = m;
    let n_prandint = 1;
    let bound_l = 8;
    let security_k = 4;
    let precision = FixedPointPrecision::new(k, m);

    // Setup of the network.
    let (mut sim, inner) = turmoil_setup(n_parties, vec![], Some((10, 2000)));
    let (tx_out, rx_out) = std::sync::mpsc::channel();
    let (tx_client, mut rx_client) = tokio::sync::broadcast::channel(n_parties);

    // Prepare inputs for multiplication
    let mut a_fix = Vec::new();
    let mut b_fix = Vec::new();

    // x = 5.5 * 2^4=88, y = 3.25 * 2^4=52
    // x * y = 17.875 * 2^8 = 4576
    // 17.875 * 2^8 / 2^4 = 4576 / 2^4
    // 17.875 * 2^4 = 286
    let x = RobustShare::compute_shares(Fr::from(88), n_parties, t, None, &mut rng).unwrap();
    let y = RobustShare::compute_shares(Fr::from(52), n_parties, t, None, &mut rng).unwrap();
    for i in 0..n_parties {
        a_fix.push(SecretFixedPoint::new_with_precision(
            x[i].clone(),
            precision,
        ));
        b_fix.push(SecretFixedPoint::new_with_precision(
            y[i].clone(),
            precision,
        ));
    }

    let nodes = create_global_nodes::<Fr, Avid<SessionId>, RobustShare<Fr>, TurmoilNetwork>(
        n_parties,
        t,
        n_triples,
        n_random_shares,
        111,
        n_prandbit,
        n_prandint,
        bound_l,
        security_k,
        Duration::from_secs(300),
        vec![],
    );

    let barrier_net = Arc::new(Barrier::new(n_parties));

    for pid in 0..n_parties {
        let node = nodes[pid].clone();
        let inner = inner.clone();
        let a = a_fix[pid].clone();
        let b = b_fix[pid].clone();
        let barrier = barrier_net.clone();
        let tx_out = tx_out.clone();
        let tx_client = tx_client.clone();
        sim.host(format!("node{}", pid), move || {
            let mut node = node.clone();
            let inner = inner.clone();
            let a = a.clone();
            let b = b.clone();
            let barrier = barrier.clone();
            let tx_out = tx_out.clone();
            let tx_client = tx_client.clone();

            async move {
                let (network, mut rx) = TurmoilNetwork::new(SenderId::Node(pid), inner).await;
                let net_arc = Arc::new(network);
                barrier.wait().await;

                let mul_handle = tokio::spawn({
                    let a = a.clone();
                    let b = b.clone();
                    let mut node = node.clone();
                    let net_arc = net_arc.clone();
                    async move { node.mul_fixed(a, b, net_arc.clone()).await }
                });

                // Simulation of the process function.
                loop {
                    match rx.recv().await {
                        Some((sender, msg)) => {
                            let sender_id = match sender {
                                SenderId::Node(i) => i,
                                SenderId::Client(i) => i,
                            };
                            if let Err(e) = node.process(sender_id, msg, net_arc.clone()).await {
                                error!("node {} process error: {:?}", pid, e);
                            }
                        }
                        None => break,
                    }

                    tokio::task::yield_now().await;

                    if mul_handle.is_finished() {
                        break;
                    }
                }

                let mul_share = match mul_handle.await {
                    Ok(Ok(shares)) => shares,
                    Ok(Err(e)) => {
                        let _ = tx_out.send(Err(format!("node {} mul error: {:?}", pid, e)));
                        let _ = tx_client.send(());
                        return Ok(());
                    }
                    Err(e) => {
                        let _ = tx_out.send(Err(format!("node {} join error: {:?}", pid, e)));
                        let _ = tx_client.send(());
                        return Ok(());
                    }
                };

                if mul_share.value().degree != t {
                    let _ = tx_out.send(Err(format!(
                        "node {} share degree {} != {}",
                        pid,
                        mul_share.value().degree,
                        t
                    )));
                    let _ = tx_client.send(());
                    return Ok(());
                }
                if mul_share.value().id != pid {
                    let _ = tx_out.send(Err(format!("node {} share id mismatch", pid)));
                    let _ = tx_client.send(());
                    return Ok(());
                }

                let _ = tx_out.send(Ok((pid, mul_share)));
                let _ = tx_client.send(());

                Ok(())
            }
        });
    }

    drop(tx_out);
    drop(tx_client);

    if let Some(delayed_start) = &node_freeze_start {
        for freezed_node in &delayed_start.delayed_nodes {
            for other_id in 0..n_parties {
                if *freezed_node != other_id {
                    sim.hold(format!("node{}", freezed_node), format!("node{}", other_id));
                }
            }
        }
    }

    sim.client("driver", async move {
        if let Some(delayed_start) = node_freeze_start {
            tokio::time::sleep(delayed_start.time).await;

            // Now, the nodes connect again
            for freezed_node in delayed_start.delayed_nodes {
                for other_id in 0..n_parties {
                    if freezed_node != other_id {
                        turmoil::release(
                            format!("node{}", freezed_node),
                            format!("node{}", other_id),
                        );
                    }
                }
            }
        }

        let mut count = 0;
        while count < n_parties {
            match rx_client.recv().await {
                Ok(()) => count += 1,
                Err(_) => break,
            }
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    });

    if let Some(slow_nodes) = node_delay {
        for (slow_node_id, delay) in slow_nodes {
            for other_id in 0..n_parties {
                if slow_node_id != other_id {
                    sim.set_link_latency(
                        format!("node{}", slow_node_id),
                        format!("node{}", other_id),
                        delay,
                    );
                }
            }
        }
    }

    sim.run().unwrap();

    let shares_result: Result<Vec<_>, _> = std::iter::from_fn(|| rx_out.try_recv().ok()).collect();
    let shares: Vec<_> = shares_result
        .unwrap()
        .into_iter()
        .map(|(_, share)| share.value().clone())
        .collect();
    let (_, rec) = RobustShare::recover_secret(&shares, n_parties, t).expect("interpolate failed");
    assert_eq!(rec, Fr::from(286));
}

#[test]
fn fpmul_e2e_with_preprocessing_node_delayed() {
    let slow_node = 0;
    let delay = Duration::from_secs(5);
    fpmul_e2e_with_preprocessing(Some(vec![(slow_node, delay)]), None);
}

#[test]
fn fpmul_e2e_with_preprocessing_freezing_start() {
    fpmul_e2e_with_preprocessing(
        None,
        Some(DelayedStart {
            delayed_nodes: vec![0],
            time: Duration::from_secs(3),
        }),
    );
}

#[test]
fn fpmul_e2e_with_preprocessing_without_delay() {
    fpmul_e2e_with_preprocessing(None, None);
}

fn fpdiv_const_e2e(
    node_delay: Option<Vec<(usize, Duration)>>,
    node_freeze_start: Option<DelayedStart>,
) {
    setup_tracing();
    let n_parties = 4;
    let t = 1;
    let mut rng = test_rng();

    // Prepare inputs for division
    let k = 16; // total bitlength
    let m = 4; // fractional bits
    let precision = FixedPointPrecision::new(k, m);

    let mut a_fix = Vec::new();
    let mut denom_fix = Vec::new();

    // x = 5.5 -> 5.5 * 2^4 = 88
    // d = 2.0 -> 2.0 * 2^4 = 32
    // x/d = 2.75 -> scaled = 2.75 * 2^4 = 44

    let x_shares = RobustShare::compute_shares(Fr::from(88), n_parties, t, None, &mut rng).unwrap();

    // denom is *public*, but each party needs ClearFixedPoint
    let denom_clear = ClearFixedPoint::new_with_precision(Fr::from(32u64), precision);

    for i in 0..n_parties {
        a_fix.push(SecretFixedPoint::new_with_precision(
            x_shares[i].clone(),
            precision,
        ));
        denom_fix.push(denom_clear.clone());
    }

    for i in 0..n_parties {
        a_fix.push(SecretFixedPoint::new_with_precision(
            x_shares[i].clone(),
            precision,
        ));
        denom_fix.push(denom_clear.clone());
    }

    // ----------------------------------------PREPROCESSING INPUTS----------------------------------------
    // PRandInt
    let r_int = RobustShare::compute_shares(Fr::from(3u64), n_parties, t, None, &mut rng).unwrap();

    // PRandBits: m bits
    let mut r_bits = vec![Vec::new(); n_parties];
    for j in 0..m {
        let bit_shares =
            RobustShare::compute_shares(Fr::from((j % 2) as u64), n_parties, t, None, &mut rng)
                .unwrap();
        for (i, share) in bit_shares.iter().enumerate() {
            r_bits[i].push((share.clone(), Gf256::one()));
        }
    }

    // --------------------------------------- NETWORK SETUP ---------------------------------------------
    let (mut sim, inner) = turmoil_setup(n_parties, vec![], Some((10, 2000)));
    let (tx_out, rx_out) = std::sync::mpsc::channel();
    let (tx_client, mut rx_client) = tokio::sync::broadcast::channel(n_parties);

    //----------------------------------------SETUP NODES----------------------------------------
    let nodes = create_global_nodes::<Fr, Avid<SessionId>, RobustShare<Fr>, TurmoilNetwork>(
        n_parties,
        t,
        0,
        0,
        222,
        0,
        0,
        0,
        0,
        Duration::from_secs(30),
        vec![],
    );

    //----------------------------------------LOAD PREPROCESSING----------------------------------------

    let barrier_net = Arc::new(Barrier::new(n_parties));

    for pid in 0..n_parties {
        let node = nodes[pid].clone();
        let inner = inner.clone();
        let a = a_fix[pid].clone();
        let denom_fix = denom_fix[pid].clone();
        let barrier = barrier_net.clone();
        let tx_out = tx_out.clone();
        let tx_client = tx_client.clone();
        let r_bits = r_bits[pid].clone();
        let r_int = r_int[pid].clone();
        sim.host(format!("node{}", pid), move || {
            let mut node = node.clone();
            let inner = inner.clone();
            let a = a.clone();
            let denom_fix = denom_fix.clone();
            let barrier = barrier.clone();
            let tx_out = tx_out.clone();
            let tx_client = tx_client.clone();
            let r_bits = r_bits.clone();
            let r_int = r_int.clone();

            async move {
                node.preprocessing_material.lock().await.add(
                    None, // No Beaver triple needed
                    None,
                    None,
                    None,
                    Some(r_bits),      // PRandBit[]
                    Some(vec![r_int]), // PRandInt[]
                );
                let (network, mut rx) = TurmoilNetwork::new(SenderId::Node(pid), inner).await;
                let net_arc = Arc::new(network);
                barrier.wait().await;

                let mul_handle = tokio::spawn({
                    let a = a.clone();
                    let denom_fix = denom_fix.clone();
                    let mut node = node.clone();
                    let net_arc = net_arc.clone();
                    async move {
                        node.div_with_const_fixed(a, denom_fix, net_arc.clone())
                            .await
                    }
                });

                // Simulation of the process function.
                loop {
                    match rx.recv().await {
                        Some((sender, msg)) => {
                            let sender_id = match sender {
                                SenderId::Node(i) => i,
                                SenderId::Client(i) => i,
                            };
                            if let Err(e) = node.process(sender_id, msg, net_arc.clone()).await {
                                error!("node {} process error: {:?}", pid, e);
                            }
                        }
                        None => break,
                    }

                    tokio::task::yield_now().await;

                    if mul_handle.is_finished() {
                        break;
                    }
                }

                let mul_share = match mul_handle.await {
                    Ok(Ok(shares)) => shares,
                    Ok(Err(e)) => {
                        let _ = tx_out.send(Err(format!("node {} mul error: {:?}", pid, e)));
                        let _ = tx_client.send(());
                        return Ok(());
                    }
                    Err(e) => {
                        let _ = tx_out.send(Err(format!("node {} join error: {:?}", pid, e)));
                        let _ = tx_client.send(());
                        return Ok(());
                    }
                };

                if mul_share.value().degree != t {
                    let _ = tx_out.send(Err(format!(
                        "node {} share degree {} != {}",
                        pid,
                        mul_share.value().degree,
                        t
                    )));
                    let _ = tx_client.send(());
                    return Ok(());
                }
                if mul_share.value().id != pid {
                    let _ = tx_out.send(Err(format!("node {} share id mismatch", pid)));
                    let _ = tx_client.send(());
                    return Ok(());
                }

                let _ = tx_out.send(Ok((pid, mul_share)));
                let _ = tx_client.send(());

                Ok(())
            }
        });
    }

    drop(tx_out);
    drop(tx_client);

    if let Some(delayed_start) = &node_freeze_start {
        for freezed_node in &delayed_start.delayed_nodes {
            for other_id in 0..n_parties {
                if *freezed_node != other_id {
                    sim.hold(format!("node{}", freezed_node), format!("node{}", other_id));
                }
            }
        }
    }

    sim.client("driver", async move {
        if let Some(delayed_start) = node_freeze_start {
            tokio::time::sleep(delayed_start.time).await;

            // Now, the nodes connect again
            for freezed_node in delayed_start.delayed_nodes {
                for other_id in 0..n_parties {
                    if freezed_node != other_id {
                        turmoil::release(
                            format!("node{}", freezed_node),
                            format!("node{}", other_id),
                        );
                    }
                }
            }
        }

        let mut count = 0;
        while count < n_parties {
            match rx_client.recv().await {
                Ok(()) => count += 1,
                Err(_) => break,
            }
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    });

    if let Some(slow_nodes) = node_delay {
        for (slow_node_id, delay) in slow_nodes {
            for other_id in 0..n_parties {
                if slow_node_id != other_id {
                    sim.set_link_latency(
                        format!("node{}", slow_node_id),
                        format!("node{}", other_id),
                        delay,
                    );
                }
            }
        }
    }

    sim.run().unwrap();

    let shares_result: Result<Vec<_>, _> = std::iter::from_fn(|| rx_out.try_recv().ok()).collect();
    let shares: Vec<_> = shares_result
        .unwrap()
        .into_iter()
        .map(|(_, share)| share.value().clone())
        .collect();

    let (_, rec) = RobustShare::recover_secret(&shares, n_parties, t).expect("interpolate failed");

    // 2.75 * 2^4 = 44
    assert_eq!(rec, Fr::from(44u64));
}

#[test]
fn fpdiv_const_e2e_delayed() {
    let slow_node = 0;
    let delay = Duration::from_secs(5);
    fpdiv_const_e2e(Some(vec![(slow_node, delay)]), None);

    let slow_node = 0;
    let delay = Duration::from_secs(7);
    fpdiv_const_e2e(Some(vec![(slow_node, delay)]), None);

    let slow_node = 0;
    let delay = Duration::from_secs(1);
    fpdiv_const_e2e(Some(vec![(slow_node, delay)]), None);
}

#[test]
fn fpdiv_const_e2e_without_delay() {
    fpdiv_const_e2e(None, None);
}

#[test]
fn fpdiv_const_e2e_freeze_start() {
    fpdiv_const_e2e(
        None,
        Some(DelayedStart {
            delayed_nodes: vec![0],
            time: Duration::from_secs(3),
        }),
    );
    fpdiv_const_e2e(
        None,
        Some(DelayedStart {
            delayed_nodes: vec![0],
            time: Duration::from_secs(5),
        }),
    );
    fpdiv_const_e2e(
        None,
        Some(DelayedStart {
            delayed_nodes: vec![0],
            time: Duration::from_secs(7),
        }),
    );
}

fn ransha_e2e_turmoil_with_hold(
    n_parties: usize,
    t: usize,
    hold_nodes: Vec<usize>,
    hold_time: Duration,
) {
    setup_tracing();

    let session_id = SessionId::new(ProtocolType::Ransha, SessionId::pack_slot(123, 0, 0), 111);

    let (mut sim, inner) = turmoil_setup(n_parties, vec![], Some((10, 2000)));
    let nodes = create_global_nodes::<Fr, Avid<SessionId>, RobustShare<Fr>, TurmoilNetwork>(
        n_parties,
        t,
        0,
        0,
        111,
        0,
        0,
        0,
        0,
        Duration::from_secs(30),
        vec![],
    );

    let (tx, rx_done) = std::sync::mpsc::channel::<Result<(), String>>();
    let (tx_partition, mut rx_partition) = tokio::sync::mpsc::unbounded_channel();
    let (tx_finished, mut rx_finished) = tokio::sync::mpsc::unbounded_channel();

    for id in 0..n_parties {
        let inner = inner.clone();
        let node = nodes[id].clone();
        let tx = tx.clone();
        let tx_partition = tx_partition.clone();
        let tx_finished = tx_finished.clone();

        sim.host(format!("node{}", id), move || {
            let inner = inner.clone();
            let mut node = node.clone();
            let tx = tx.clone();
            let tx_partition = tx_partition.clone();
            let tx_finished = tx_finished.clone();

            async move {
                let (network, mut rx) = TurmoilNetwork::new(SenderId::Node(id), inner).await;
                sleep(Duration::from_millis(50)).await;

                let network_arc = Arc::new(network);
                let mut rng = StdRng::from_rng(OsRng).unwrap();
                let node_id = node.preprocess.share_gen.id;

                match node
                    .preprocess
                    .share_gen
                    .init(session_id, &mut rng, network_arc.clone())
                    .await
                {
                    Ok(()) => {}
                    Err(RanShaError::NetworkError(NetworkError::SendError)) => {}
                    Err(e) => {
                        let _ = tx.send(Err(format!("node {} init error: {:?}", node_id, e)));
                        return Ok(());
                    }
                }

                // Send the signal that the node 0 can be partitioned. I can stop the party here
                // given that we finished the initialization process.
                tx_partition
                    .send(())
                    .expect("the signal to partition node 0 should be sent correctly");

                let mut msg_count = 0usize;
                let result = timeout(Duration::from_secs(30), async {
                    loop {
                        match rx.recv().await {
                            Some((sender, msg)) => {
                                msg_count += 1;
                                let sender_id = match sender {
                                    SenderId::Node(i) => i,
                                    SenderId::Client(i) => i,
                                };
                                node.process(sender_id, msg, network_arc.clone())
                                    .await
                                    .unwrap();
                            }
                            None => break,
                        }

                        let store = node
                            .preprocess
                            .share_gen
                            .get_or_create_store(session_id)
                            .await
                            .unwrap();
                        if store.lock().await.state == RanShaState::Finished {
                            break;
                        }
                    }
                })
                .await;

                if result.is_err() {
                    let _ = tx.send(Err(format!(
                        "node {} timed out after {} msgs",
                        node_id, msg_count
                    )));
                    return Ok(());
                }

                let store = node
                    .preprocess
                    .share_gen
                    .get_or_create_store(session_id)
                    .await
                    .unwrap();
                let store = store.lock().await;

                for s_t in store.computed_r_shares.iter() {
                    if s_t.degree != t {
                        let _ = tx.send(Err(format!(
                            "node {} share degree {} != {}",
                            node_id, s_t.degree, t
                        )));
                        return Ok(());
                    }
                    if s_t.id != node.id {
                        let _ = tx.send(Err(format!("node {} share id mismatch", node_id)));
                        return Ok(());
                    }
                }

                if store.computed_r_shares.len() != n_parties {
                    let _ = tx.send(Err(format!(
                        "node {} expected {} shares, got {}",
                        node_id,
                        n_parties,
                        store.computed_r_shares.len()
                    )));
                    return Ok(());
                }

                let _ = tx.send(Ok(()));
                tx_finished
                    .send(())
                    .expect("signal that the protocol finished should be sent");
                Ok(())
            }
        });
    }

    drop(tx);

    let other_nodes: Vec<_> = (0..n_parties)
        .filter(|node| !hold_nodes.contains(node))
        .collect();

    sim.client("driver", async move {
        let mut counter = 0;
        while let Some(()) = rx_partition.recv().await {
            counter += 1;
            if counter == n_parties {
                for id in &hold_nodes {
                    for other_id in &other_nodes {
                        turmoil::hold(format!("node{}", id), format!("node{}", other_id));
                    }
                }
                break;
            }
        }

        // This instruct the driver to wait for some time.
        tokio::time::sleep(hold_time).await;

        for id in &hold_nodes {
            for other_id in &other_nodes {
                turmoil::release(format!("node{}", id), format!("node{}", other_id));
            }
        }

        // This allows that all the parties finishes. Hence the sim.run() will not suddenly finish.
        for _ in 0..n_parties {
            rx_finished.recv().await.unwrap();
        }

        Ok(())
    });

    drop(tx_partition);
    drop(tx_finished);
    collect_results(sim, rx_done, n_parties);
}

#[test]
fn ransha_e2e_turmoil_with_hold_one_partition() {
    let n_parties = 4;
    let t = 1;
    let hold_time = Duration::from_secs(1);

    let hold_nodes = vec![0];

    ransha_e2e_turmoil_with_hold(n_parties, t, hold_nodes, hold_time);
}

#[test]
fn ransha_e2e_turmoil_with_hold_minority_partition() {
    let n_parties = 10;
    let t = 3;
    let hold_time = Duration::from_secs(1);

    let hold_nodes = vec![0, 1];

    ransha_e2e_turmoil_with_hold(n_parties, t, hold_nodes, hold_time);
}

#[test]
fn ransha_e2e_turmoil_with_hold_minority_partition_2_secs() {
    let n_parties = 10;
    let t = 3;
    let hold_time = Duration::from_secs(2);

    let hold_nodes = vec![0, 1];

    ransha_e2e_turmoil_with_hold(n_parties, t, hold_nodes, hold_time);
}

#[test]
fn ransha_e2e_turmoil_with_hold_minority_partition_3_secs() {
    let n_parties = 10;
    let t = 3;
    let hold_time = Duration::from_secs(3);

    let hold_nodes = vec![0, 1];

    ransha_e2e_turmoil_with_hold(n_parties, t, hold_nodes, hold_time);
}

fn batch_reconstruction_with_partition(hold_nodes: Vec<usize>, n_parties: usize, t: usize) {
    setup_tracing();
    assert!(hold_nodes.len() <= t);

    let session_id = SessionId::new(
        ProtocolType::BatchRecon,
        SessionId::pack_slot(123, 0, 0),
        111,
    );
    let (mut sim, inner) = turmoil_setup(n_parties, vec![], Some((10, 2000)));

    let mut _batch_recon_receivers = Vec::new();

    let nodes = (0..n_parties)
        .map(|id| {
            let (tx, rx) = tokio::sync::mpsc::channel(1024);
            _batch_recon_receivers.push(rx);
            BatchReconNode::new(id, n_parties, t, t, tx).unwrap()
        })
        .collect::<Vec<_>>();

    let (tx_done, rx_done) = std::sync::mpsc::channel::<Result<(), String>>();
    let (tx_partition, mut rx_partition) = tokio::sync::mpsc::unbounded_channel();
    let (tx_finished, mut rx_finished) = tokio::sync::mpsc::unbounded_channel();

    // Prepare the input.
    let mut rng = test_rng();
    let secrets = (0..t + 1).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
    let all_shares = generate_independent_shares(&secrets, t, n_parties);

    for id in 0..n_parties {
        let inner = inner.clone();
        let node = nodes[id].clone();
        let tx_done = tx_done.clone();
        let tx_partition = tx_partition.clone();
        let tx_finished = tx_finished.clone();
        let shares = all_shares[id].clone();
        let secrets = secrets.clone();

        sim.host(format!("node{}", id), move || {
            let inner = inner.clone();
            let mut node = node.clone();
            let tx_done = tx_done.clone();
            let tx_partition = tx_partition.clone();
            let tx_finished = tx_finished.clone();
            let shares = shares.clone();
            let secrets = secrets.clone();

            async move {
                let (network, mut rx) = TurmoilNetwork::new(SenderId::Node(id), inner).await;
                sleep(Duration::from_millis(50)).await;

                let network_arc = Arc::new(network);
                let node_id = node.id;

                match node
                    .init_batch_reconstruct(&shares, session_id, network_arc.clone())
                    .await
                {
                    Ok(()) => {}
                    Err(BatchReconError::NetworkError(NetworkError::SendError)) => {}
                    Err(e) => {
                        let _ = tx_done.send(Err(format!("node {} init error: {:?}", node_id, e)));
                        return Ok(());
                    }
                }

                let mut msg_count = 0usize;
                let result = timeout(Duration::from_secs(30), async {
                    let mut signaled = false;
                    loop {
                        match rx.recv().await {
                            Some((sender, raw_msg)) => {
                                msg_count += 1;
                                let wrapped: WrappedMessage =
                                    bincode::deserialize(&raw_msg).unwrap();
                                match wrapped {
                                    WrappedMessage::BatchRecon(msg) => {
                                        node.process(msg, network_arc.clone()).await.unwrap();
                                    }
                                    _ => error!(from = ?sender, id = id, "unknown message type"),
                                }

                                // If the y_j were received and in place, send a signal to interrupt
                                // the node.
                                {
                                    if node.get_store(session_id).await.is_ok() {
                                        if !signaled {
                                            tx_partition.send(()).unwrap();
                                        }
                                        break;
                                    }

                                    let Some(store) =
                                        node.get_or_create_store(session_id).await.unwrap()
                                    else {
                                        continue;
                                    };
                                    if store.lock().await.y_j.is_some() && !signaled {
                                        tx_partition.send(()).unwrap();
                                        signaled = true;
                                    }
                                }
                            }
                            None => break,
                        }
                    }
                })
                .await;

                if result.is_err() {
                    let _ = tx_done.send(Err(format!(
                        "node {} timed out after {} msgs",
                        node_id, msg_count
                    )));
                    return Ok(());
                }

                // Check that the recovered secrets match with the originals.
                let revealed_secrets = node.get_store(session_id).await.unwrap();
                let revealed_secrets_field: Vec<Fr> =
                    CanonicalDeserialize::deserialize_compressed(revealed_secrets.as_slice())
                        .unwrap();
                assert_eq!(revealed_secrets_field, secrets);

                tx_done
                    .send(Ok(()))
                    .expect("signal that the protocol finished correctly should be sent");
                tx_finished
                    .send(())
                    .expect("signal that the protocol finished should be sent");
                Ok(())
            }
        });
    }

    drop(tx_done);

    let other_nodes: Vec<_> = (0..n_parties)
        .filter(|node| !hold_nodes.contains(node))
        .collect();

    let hold_nodes_client = hold_nodes.clone();
    sim.client("driver", async move {
        // Wait for all the nodes to get y_i.
        let mut counter = 0;
        while let Some(()) = rx_partition.recv().await {
            counter += 1;
            if counter == n_parties {
                for id in &hold_nodes_client {
                    for other_id in &other_nodes {
                        turmoil::hold(format!("node{}", id), format!("node{}", other_id));
                    }
                }
                break;
            }
        }

        // This allows that all the parties finishes. Hence the sim.run() will not suddenly finish.
        for _ in 0..n_parties - hold_nodes_client.len() {
            rx_finished.recv().await.unwrap();
        }

        Ok(())
    });

    drop(tx_partition);
    drop(tx_finished);
    collect_results(sim, rx_done, n_parties - hold_nodes.len());
}

#[test]
fn batch_reconstruction_with_partition_n_7_t_2() {
    let n_parties = 7;
    let t = 2;
    let hold_nodes = vec![0, 1];
    batch_reconstruction_with_partition(hold_nodes, n_parties, t);
}

#[test]
fn batch_reconstruction_with_partition_n_7_t_1() {
    let n_parties = 7;
    let t = 1;
    let hold_nodes = vec![0];
    batch_reconstruction_with_partition(hold_nodes, n_parties, t);
}

#[test]
fn batch_reconstruction_with_partition_n_7_t_2_one_hold() {
    let n_parties = 7;
    let t = 2;
    let hold_nodes = vec![0];
    batch_reconstruction_with_partition(hold_nodes, n_parties, t);
}
