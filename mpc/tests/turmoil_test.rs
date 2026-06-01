mod utils;

use crate::utils::test_utils::{
    construct_e2e_input, construct_e2e_input_mul, create_clients, create_global_nodes,
    generate_independent_shares, setup_tracing,
};
use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_std::{
    rand::{rngs::StdRng, SeedableRng},
    test_rng,
};
use chacha20poly1305::aead::OsRng;
use std::sync::Arc;
use stoffelmpc_mpc::{
    common::{
        rbc::rbc::Avid, MPCProtocol, PreprocessingMPCProtocol, ProtocolSessionId,
        SecretSharingScheme, ShamirShare,
    },
    honeybadger::{
        input::input::{InputClient, InputType},
        ran_dou_sha::RanDouShaState,
        robust_interpolate::robust_interpolate::{Robust, RobustShare},
        share_gen::{RanShaError, RanShaState},
        ProtocolType, SessionId, WrappedMessage,
    },
};
use stoffelmpc_network::{
    // bad_fake_network::setup_tracing,
    fake_network::{FakeNetworkConfig, SenderId},
    turmoil_network::{TurmoilInnerNetwork, TurmoilNetwork},
};
use stoffelnet::network_utils::{ClientId, NetworkError};
use tokio::time::{sleep, timeout, Duration};
use tracing::info;
use turmoil::{Builder, Sim};

pub fn turmoil_setup(
    n_nodes: usize,
    client_ids: Vec<ClientId>,
    latency: Option<(u64, u64)>,
) -> (turmoil::Sim<'static>, TurmoilInnerNetwork) {
    let sim = if let Some((min, max)) = latency {
        Builder::new()
            .min_message_latency(Duration::from_millis(min))
            .max_message_latency(Duration::from_millis(max))
            .simulation_duration(Duration::from_secs(120))
            .build()
    } else {
        Builder::new()
            .simulation_duration(Duration::from_secs(120))
            .build()
    };

    let inner = TurmoilInnerNetwork::new(
        n_nodes,
        if client_ids.is_empty() {
            None
        } else {
            Some(client_ids)
        },
        FakeNetworkConfig::new(100),
        7000,
        8000,
    );

    (sim, inner)
}

// --- sim setup ---

fn add_driver(sim: &mut Sim, secs: u64) {
    sim.client("driver", async move {
        sleep(Duration::from_secs(secs)).await;
        Ok::<(), Box<dyn std::error::Error>>(())
    });
}

// --- result collection ---

fn collect_results(
    mut sim: Sim,
    rx_done: std::sync::mpsc::Receiver<Result<(), String>>,
    expected: usize,
) {
    sim.run().unwrap();
    let results: Vec<_> = std::iter::from_fn(|| rx_done.try_recv().ok()).collect();
    assert_eq!(
        results.len(),
        expected,
        "not all nodes reported: got {}/{}",
        results.len(),
        expected
    );
    for r in results {
        assert!(r.is_ok(), "node failed: {}", r.unwrap_err());
    }
}

#[test]
fn ransha_e2e_turmoil() {
    setup_tracing();

    let n_parties = 4;
    let t = 1;

    let session_id = SessionId::new(
        ProtocolType::Randousha,
        SessionId::pack_slot24(123, 0, 0),
        111,
    );

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
        0,
        0,
        0,
        0,
        0,
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
        0,
        0,
        0,
        0,
        0,
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

#[test]
fn preprocessing_e2e_turmoil() {
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

    let (mut sim, inner) = turmoil_setup(n_parties, vec![], Some((10, 2000)));

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
        0,
        0,
        0,
        0,
        n_prandbit,
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
                        let (n_triples, _, n_pbit, n_pint) =
                            node.preprocessing_material.lock().await.len();
                        if n_triples == 9 && n_pbit == n_prandbit && n_pint == n_prandint {
                            break;
                        }
                    }
                }

                // collect final counts
                let (n_triples, n_shares, n_pbit, n_pint) =
                    node.preprocessing_material.lock().await.len();

                let _ = tx.send(Ok((n_triples, n_shares, n_pbit, n_pint)));
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
        match r {
            Err(e) => panic!("node failed: {}", e),
            Ok((n_triples, n_shares, n_pbit, n_pint)) => {
                assert_eq!(n_triples, 9);
                assert_eq!(n_shares, 0);
                assert_eq!(n_pbit, 4);
                assert_eq!(n_pint, 4);
            }
        }
    }
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
        0,
        0,
        0,
        0,
        0,
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

                    let (n_triples, _, _, _) = node.preprocessing_material.lock().await.len();
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
        SessionId::pack_slot24(123, 0, 0),
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
        0,
        0,
        0,
        0,
        0,
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
        0,
        0,
        0,
        0,
        0,
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
