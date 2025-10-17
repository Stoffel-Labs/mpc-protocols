use crate::utils::test_utils::{
    construct_e2e_input, construct_e2e_input_mul, create_clients, create_global_nodes,
    generate_independent_shares, initialize_global_nodes_randousha, initialize_global_nodes_ransha,
    receive, receive_client, setup_tracing, test_setup, test_setup_bad,
};
use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Field, UniformRand};
use ark_std::{
    rand::{
        distributions::Uniform,
        rngs::{OsRng, StdRng},
        SeedableRng,
    },
    test_rng,
};
use futures::future::join_all;
use std::{collections::HashMap, sync::Arc};
use stoffelmpc_mpc::{
    common::{
        rbc::rbc::Avid,
        types::{
            fixed::{ClearFixedPoint, FixedPointPrecision, SecretFixedPoint},
            integer::SecretInt,
        },
        MPCProtocol, MPCTypeOps, PreprocessingMPCProtocol, SecretSharingScheme, ShamirShare,
    },
    honeybadger::{
        fpmul::f256::F2_8,
        mul::MulError,
        input::input::InputClient,
        output::output::{OutputClient, OutputServer},
        ran_dou_sha::RanDouShaState,
        robust_interpolate::robust_interpolate::{Robust, RobustShare},
        share_gen::RanShaState,
        ProtocolType, SessionId, WrappedMessage,
    },
};
use stoffelmpc_network::{bad_fake_network::BadFakeNetwork, fake_network::FakeNetwork};
use stoffelnet::network_utils::ClientId;
use tokio::{
    sync::{mpsc, Mutex},
    time::{Duration, sleep, timeout},
};
use tracing::info;

pub mod utils;

#[tokio::test]
async fn randousha_e2e() {
    setup_tracing();
    let n_parties = 5;
    let t = 1;
    let session_id = SessionId::new(ProtocolType::Randousha, 123, 0, 0, 111);
    let degree_t = 1;

    //Setup
    let (network, receivers, _) = test_setup(n_parties, vec![]);
    let (_, n_shares_t, n_shares_2t) = construct_e2e_input(n_parties, degree_t);
    // create global nodes
    let mut nodes = create_global_nodes::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(
        n_parties, t, 0, 0, 111, 0, 0, 0, 0, vec![]
    );
    // spawn tasks to process received messages
    receive::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(receivers, nodes.clone(), network.clone());

    // init all randousha nodes
    initialize_global_nodes_randousha(
        nodes.clone(),
        &n_shares_t,
        &n_shares_2t,
        session_id,
        Arc::clone(&network),
    )
    .await;

    let result = timeout(
        Duration::from_secs(5),
        join_all(nodes.iter_mut().map(|node| async move {
            let store = node
                .preprocess
                .ran_dou_sha
                .get_or_create_store(session_id)
                .await;

            loop {
                let store = store.lock().await;
                if store.state == RanDouShaState::Finished {
                    break;
                }
                store
                    .computed_r_shares_degree_t
                    .iter()
                    .zip(&store.computed_r_shares_degree_2t)
                    .for_each(|(s_t, s_2t)| {
                        assert_eq!(s_t.degree, t);
                        assert_eq!(s_2t.degree, 2 * t);
                        assert_eq!(s_t.id, node.id);
                        assert_eq!(s_2t.id, node.id);
                    });
                sleep(Duration::from_millis(10)).await;
            }
        })),
    )
    .await;

    assert!(
        result.is_ok(),
        "RanDouSha did not complete within the timeout"
    );
}

#[tokio::test]
async fn ransha_e2e() {
    setup_tracing();
    let n_parties = 5;
    let t = 1;
    let session_id = SessionId::new(ProtocolType::Randousha, 123, 0, 0, 111);

    //Setup
    let (network, receivers, _) = test_setup(n_parties, vec![]);
    // create global nodes
    let mut nodes = create_global_nodes::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(
        n_parties, t, 0, 0, 111, 0, 0, 0, 0, vec![]
    );
    // spawn tasks to process received messages
    receive::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(receivers, nodes.clone(), network.clone());

    // init all ransha nodes
    initialize_global_nodes_ransha(nodes.clone(), session_id, Arc::clone(&network)).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let result = timeout(
        Duration::from_secs(5),
        join_all(nodes.iter_mut().map(|node| async move {
            let store = node
                .preprocess
                .share_gen
                .get_or_create_store(session_id)
                .await;

            loop {
                let store = store.lock().await;
                if store.state == RanShaState::Finished {
                    break;
                }
                store.computed_r_shares.iter().for_each(|s_t| {
                    assert_eq!(s_t.degree, t);
                    assert_eq!(s_t.id, node.id);
                });
                assert_eq!(store.computed_r_shares.len(), n_parties);
                sleep(Duration::from_millis(10)).await;
            }
        })),
    )
    .await;

    assert!(result.is_ok(), "RanSha did not complete within the timeout");
}

#[tokio::test]
async fn test_input_protocol_e2e() {
    setup_tracing();
    let n = 4;
    let t = 1;
    let clientid: Vec<ClientId> = vec![100];
    let input_values: Vec<Fr> = vec![Fr::from(10), Fr::from(20)];
    let mask_values: Vec<Fr> = vec![Fr::from(11), Fr::from(21)];

    //Setup network
    let (net, server_recv, mut client_recv) = test_setup(n, clientid.clone());
    //Generate local shares
    let local_shares = generate_independent_shares(&mask_values, t, n);

    // Set up InputServers/InputClient
    let mut client =
        InputClient::<Fr, Avid>::new(clientid[0], n, t, 111, input_values.clone()).unwrap();
    let mut nodes =
        create_global_nodes::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(n, t, 0, 0, 111, 0, 0, 0, 0, clientid.clone());

    //Receive at server
    receive::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(server_recv, nodes.clone(), net.clone());
    //Receive at client
    let net_clone2 = net.clone();
    let mut recv = client_recv.remove(&clientid[0]).unwrap();
    tokio::spawn(async move {
        while let Some(received) = recv.recv().await {
            let wrapped: WrappedMessage = match bincode::deserialize(&received) {
                Ok(w) => w,
                Err(_) => continue,
            };
            match wrapped {
                WrappedMessage::Input(msg) => match client.process(msg, net_clone2.clone()).await {
                    Ok(_) => {}
                    Err(e) => eprintln!("Processing error : {}", e),
                },
                _ => continue,
            }
        }
    });

    //Initialize input servers
    for (i, node) in nodes.iter_mut().enumerate() {
        match node
            .preprocess
            .input
            .init(clientid[0], local_shares[i].clone(), 2, net.clone())
            .await
        {
            Ok(_) => {}
            Err(e) => {
                eprint!("{e}");
            }
        }
    }

    // Check final result: each server should have m_i = input_i
    let mut recovered_shares = vec![vec![]; input_values.len()];
    for server in &mut nodes {
        let shares = server.preprocess.input.wait_for_all_inputs(Duration::MAX).await.expect("input error");
        let server_shares = shares.get(&clientid[0]).unwrap();
        for (i, s) in server_shares.iter().enumerate() {
            recovered_shares[i].push(s.clone());
        }
    }
    for (i, secret) in input_values.iter().enumerate() {
        let shares: Vec<ShamirShare<Fr, 1, Robust>> = recovered_shares[i].iter().cloned().collect();
        let (_, r) = RobustShare::recover_secret(&shares, n).unwrap();
        assert_eq!(r, *secret);
    }
}

#[tokio::test]
async fn gen_masks_for_input_e2e() {
    setup_tracing();
    //----------------------------------------SETUP PARAMETERS----------------------------------------
    let n_parties = 4;
    let t = 1;
    let session_id = SessionId::new(ProtocolType::Ransha, 123, 0, 0, 111);
    let clientid: Vec<ClientId> = vec![100];
    let input_values: Vec<Fr> = vec![Fr::from(10), Fr::from(20)];
    //Setup the network for servers and client
    let (network, receivers, mut client_recv) = test_setup(n_parties, clientid.clone());

    //----------------------------------------SETUP NODES----------------------------------------
    //Create global nodes for InputServers
    let mut nodes = create_global_nodes::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(
        n_parties, t, 0, 0, 111, 0, 0, 0, 0, clientid.clone()
    );
    //Create nodes for InputClient
    let mut client =
        InputClient::<Fr, Avid>::new(clientid[0], n_parties, t, 111, input_values.clone()).unwrap();

    //----------------------------------------RECIEVE----------------------------------------
    //At servers
    receive::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(receivers, nodes.clone(), network.clone());
    //At client
    let net_clone2 = network.clone();
    let mut recv = client_recv.remove(&clientid[0]).unwrap();
    tokio::spawn(async move {
        while let Some(received) = recv.recv().await {
            let wrapped: WrappedMessage = match bincode::deserialize(&received) {
                Ok(w) => w,
                Err(_) => continue,
            };
            match wrapped {
                WrappedMessage::Input(msg) => match client.process(msg, net_clone2.clone()).await {
                    Ok(_) => {}
                    Err(e) => eprintln!("Processing error : {}", e),
                },
                _ => continue,
            }
        }
    });

    //----------------------------------------RUN PROTOCOL----------------------------------------
    //Run nodes for Share generation
    initialize_global_nodes_ransha(nodes.clone(), session_id, Arc::clone(&network)).await;
    let result = timeout(
        Duration::from_secs(5),
        join_all(nodes.iter_mut().map(|node| async move {
            let store = node
                .preprocess
                .share_gen
                .get_or_create_store(session_id)
                .await;

            loop {
                let store = store.lock().await;
                if store.state == RanShaState::Finished {
                    info!("Ransha ended");
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })),
    )
    .await;
    assert!(result.is_ok(), "RanSha did not complete within the timeout");

    //Run nodes for inputting
    for (_, node) in nodes.iter_mut().enumerate() {
        let local_store = node
            .preprocess
            .share_gen
            .get_or_create_store(session_id)
            .await;
        let local_shares = local_store.lock().await.protocol_output.clone();
        match node
            .preprocess
            .input
            .init(clientid[0], local_shares, 2, network.clone())
            .await
        {
            Ok(_) => {}
            Err(e) => {
                eprint!("{e}");
            }
        }
    }

    //----------------------------------------VALIDATE VALUES----------------------------------------
    //Check final result: each server should have m_i = input_i
    let mut recovered_shares = vec![vec![]; input_values.len()];
    for server in &mut nodes {
        let shares = server.preprocess.input.wait_for_all_inputs(Duration::from_millis(100)).await.expect("input error");
        let server_shares = shares.get(&clientid[0]).unwrap();
        for (i, s) in server_shares.iter().enumerate() {
            recovered_shares[i].push(s.clone());
        }
    }
    for (i, secret) in input_values.iter().enumerate() {
        let shares: Vec<ShamirShare<Fr, 1, Robust>> = recovered_shares[i].iter().cloned().collect();
        let (_, r) = RobustShare::recover_secret(&shares, n_parties).unwrap();
        assert_eq!(r, *secret);
    }
}

//----------------------------------------MUL----------------------------------------

#[tokio::test]
async fn mul_e2e_bad_net() {
    setup_tracing();
    //----------------------------------------SETUP PARAMETERS----------------------------------------
    let n_parties = 5;
    let t = 1;
    let mut rng = test_rng();
    let session_id = SessionId::new(ProtocolType::Mul, 0, 0, 0, 111);   // foresees the session ID
    let no_of_multiplication = 5;

    //Setup
    let (network, net_rx, node_channels, receivers, _) = test_setup_bad(n_parties, vec![]);

    BadFakeNetwork::start(
        net_rx,
        node_channels.clone(),
        StdRng::seed_from_u64(1u64),
        Uniform::new(1, 100),
    );

    //Generate triples
    let (_, triple) = construct_e2e_input_mul(n_parties, no_of_multiplication, t).await;

    // Prepare inputs for multiplication
    let mut x_values = Vec::new();
    let mut y_values = Vec::new();

    let mut x_inputs_per_node = vec![Vec::new(); n_parties];
    let mut y_inputs_per_node = vec![Vec::new(); n_parties];

    for _i in 0..no_of_multiplication {
        let x_value = Fr::rand(&mut rng);
        x_values.push(x_value);
        let y_value = Fr::rand(&mut rng);
        y_values.push(y_value);

        let shares_x = RobustShare::compute_shares(x_value, n_parties, t, None, &mut rng).unwrap();
        let shares_y = RobustShare::compute_shares(y_value, n_parties, t, None, &mut rng).unwrap();

        for p in 0..n_parties {
            x_inputs_per_node[p].push(shares_x[p].clone());
            y_inputs_per_node[p].push(shares_y[p].clone());
        }
    }

    //----------------------------------------SETUP NODES----------------------------------------
    // create global nodes
    let nodes = create_global_nodes::<Fr, Avid, RobustShare<Fr>, BadFakeNetwork>(
        n_parties, t, 0, 0, 111, 0, 0, 0, 0, vec![]
    );

    //----------------------------------------RECIEVE----------------------------------------
    // spawn tasks to process received messages
    receive::<Fr, Avid, RobustShare<Fr>, BadFakeNetwork>(receivers, nodes.clone(), network.clone());

    //----------------------------------------RUN PROTOCOL----------------------------------------
    //Load the triples
    for pid in 0..n_parties {
        let node = nodes[pid].clone();
        node.preprocessing_material
            .lock()
            .await
            .add(Some(triple[pid].clone()), None, None, None);
    }

    // init all nodes
    let (fin_send, mut fin_recv) = mpsc::channel::<(usize, Vec<RobustShare<Fr>>)>(100);
    let mut handles = Vec::new();
    for pid in 0..n_parties {
        let mut node = nodes[pid].clone();
        let net = network.clone();
        let fin_send = fin_send.clone();
        let x_shares = x_inputs_per_node[pid].clone();
        let y_shares = y_inputs_per_node[pid].clone();

        let handle = tokio::spawn(async move {
            {
                let final_shares = node.mul(x_shares.clone(), y_shares.clone(), net.clone())
                    .await
                    .expect("mul failed");
                fin_send.send((pid, final_shares)).await.unwrap();
            }
        });
        handles.push(handle);
    }

    // Wait for all mul tasks to finish
    futures::future::join_all(handles).await;

    let mut final_results = HashMap::<usize, Vec<RobustShare<Fr>>>::new();
    while let Some((id, final_shares)) = fin_recv.recv().await {
        final_results.insert(id, final_shares);
        if final_results.len() == n_parties {
            // check final_shares consist of correct shares
            for (id, mul_shares) in &final_results {
                assert_eq!(mul_shares.len(), no_of_multiplication);
                let _ = mul_shares.iter().map(|mul_share| {
                    assert_eq!(mul_share.degree, t);
                    assert_eq!(mul_share.id, *id);
                });
            }
            break;
        }
    }

    //----------------------------------------VALIDATE VALUES----------------------------------------

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
            RobustShare::recover_secret(&shares_for_i, n_parties).expect("interpolate failed");
        let expected = x_values[i] * y_values[i];

        assert_eq!(z_rec, expected, "multiplication mismatch at index {}", i);
    }
}

#[tokio::test]
async fn mul_e2e() {
    setup_tracing();
    //----------------------------------------SETUP PARAMETERS----------------------------------------
    let n_parties = 5;
    let t = 1;
    let mut rng = test_rng();
    let session_id = SessionId::new(ProtocolType::Mul, 0, 0, 0, 111);   // foresees the session ID
    let no_of_multiplication = 5;

    //Setup
    let (network, receivers, _) = test_setup(n_parties, vec![]);
    //Generate triples
    let (_, triple) = construct_e2e_input_mul(n_parties, no_of_multiplication, t).await;

    // Prepare inputs for multiplication
    let mut x_values = Vec::new();
    let mut y_values = Vec::new();

    let mut x_inputs_per_node = vec![Vec::new(); n_parties];
    let mut y_inputs_per_node = vec![Vec::new(); n_parties];

    for _i in 0..no_of_multiplication {
        let x_value = Fr::rand(&mut rng);
        x_values.push(x_value);
        let y_value = Fr::rand(&mut rng);
        y_values.push(y_value);

        let shares_x = RobustShare::compute_shares(x_value, n_parties, t, None, &mut rng).unwrap();
        let shares_y = RobustShare::compute_shares(y_value, n_parties, t, None, &mut rng).unwrap();

        for p in 0..n_parties {
            x_inputs_per_node[p].push(shares_x[p].clone());
            y_inputs_per_node[p].push(shares_y[p].clone());
        }
    }

    //----------------------------------------SETUP NODES----------------------------------------
    // create global nodes
    let nodes = create_global_nodes::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(
        n_parties, t, 0, 0, 111, 0, 0, 0, 0, vec![]
    );

    //----------------------------------------RECIEVE----------------------------------------
    // spawn tasks to process received messages
    receive::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(receivers, nodes.clone(), network.clone());

    //----------------------------------------RUN PROTOCOL----------------------------------------
    //Load the triples
    for pid in 0..n_parties {
        let node = nodes[pid].clone();
        node.preprocessing_material
            .lock()
            .await
            .add(Some(triple[pid].clone()), None, None, None);
    }

    // init all nodes
    let (fin_send, mut fin_recv) = mpsc::channel::<(usize, Vec<RobustShare<Fr>>)>(100);
    let mut handles = Vec::new();
    for pid in 0..n_parties {
        let mut node = nodes[pid].clone();
        let net = network.clone();
        let fin_send = fin_send.clone();
        let x_shares = x_inputs_per_node[pid].clone();
        let y_shares = y_inputs_per_node[pid].clone();

        let handle = tokio::spawn(async move {
            {
                let final_shares = node.mul(x_shares.clone(), y_shares.clone(), net.clone())
                    .await
                    .expect("mul failed");
                fin_send.send((pid, final_shares)).await.unwrap();
            }
        });
        handles.push(handle);
    }

    // Wait for all mul tasks to finish
    futures::future::join_all(handles).await;

    let mut final_results = HashMap::<usize, Vec<RobustShare<Fr>>>::new();
    while let Some((id, final_shares)) = fin_recv.recv().await {
        final_results.insert(id, final_shares);
        if final_results.len() == n_parties {
            // check final_shares consist of correct shares
            for (id, mul_shares) in &final_results {
                assert_eq!(mul_shares.len(), no_of_multiplication);
                let _ = mul_shares.iter().map(|mul_share| {
                    assert_eq!(mul_share.degree, t);
                    assert_eq!(mul_share.id, *id);
                });
            }
            break;
        }
    }

    //----------------------------------------VALIDATE VALUES----------------------------------------

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
            RobustShare::recover_secret(&shares_for_i, n_parties).expect("interpolate failed");
        let expected = x_values[i] * y_values[i];

        assert_eq!(z_rec, expected, "multiplication mismatch at index {}", i);
    }
}

#[tokio::test]
async fn mul_e2e_with_preprocessing_bad_net() {
    setup_tracing();
    //----------------------------------------SETUP PARAMETERS----------------------------------------
    let n_parties = 5;
    let t = 1;
    let no_of_triples = 2 * t + 1;
    let session_id = SessionId::new(ProtocolType::Mul, 0, 0, 0, 111);
    let clientid: Vec<ClientId> = vec![100, 200];
    let input_values: Vec<Fr> = vec![Fr::from(10), Fr::from(20)];
    let no_of_multiplications = 2; // 10*10, 20*20

    //Setup
    let (network, net_rx, node_channels, receivers, client_recv) =
        test_setup_bad(n_parties, clientid.clone());
    BadFakeNetwork::start(
        net_rx,
        node_channels.clone(),
        StdRng::seed_from_u64(1u64),
        Uniform::new(1, 10),
    );

    //----------------------------------------SETUP NODES----------------------------------------
    // create global nodes
    let mut nodes = create_global_nodes::<Fr, Avid, RobustShare<Fr>, BadFakeNetwork>(
        n_parties,
        t,
        no_of_triples,
        2,
        111,
        0,
        0,
        0,
        0,
        vec![clientid[0]]
    );

    //Create Clients
    let clients = create_clients::<Fr, Avid>(clientid.clone(), n_parties, t, 111, input_values, 2);

    //----------------------------------------RECIEVE----------------------------------------
    //At servers
    receive::<Fr, Avid, RobustShare<Fr>, BadFakeNetwork>(receivers, nodes.clone(), network.clone());

    //At client
    receive_client(client_recv, clients.clone(), network.clone());

    //----------------------------------------RUN PREPROCESSING----------------------------------------
    let mut handles = Vec::new();
    for pid in 0..n_parties {
        let mut node = nodes[pid].clone();
        let net = network.clone();
        let mut rng = StdRng::from_rng(OsRng).unwrap();

        let handle = tokio::spawn(async move {
            {
                node.run_preprocessing(net, &mut rng)
                    .await
                    .expect("Preprocessing failed");
            }
        });
        handles.push(handle);
    }

    // Wait for all mul tasks to finish
    futures::future::join_all(handles).await;
    std::thread::sleep(std::time::Duration::from_millis(300));

    //----------------------------------------RUN INPUT----------------------------------------
    for (_, node) in nodes.iter_mut().enumerate() {
        let local_shares = node
            .preprocessing_material
            .lock()
            .await
            .take_random_shares(2)
            .unwrap();
        match node
            .preprocess
            .input
            .init(clientid[0], local_shares, 2, network.clone())
            .await
        {
            Ok(_) => {}
            Err(e) => {
                eprint!("{e}");
            }
        }
    }

    //----------------------------------------RUN MULTIPLICATION----------------------------------------

    let mut handles = Vec::new();
    let (fin_send, mut fin_recv) = mpsc::channel::<(usize, Vec<RobustShare<Fr>>)>(100);
    for pid in 0..n_parties {
        let mut node = nodes[pid].clone();
        let net = network.clone();
        let fin_send = fin_send.clone();

        let (x_shares, y_shares) = {
            let input_store = node.preprocess.input.wait_for_all_inputs(Duration::from_millis(300)).await.expect("input error");
            let inputs = input_store.get(&clientid[0]).unwrap();
            (
                vec![inputs[0].clone(), inputs[1].clone()],
                vec![inputs[0].clone(), inputs[1].clone()],
            )
        };

        let handle = tokio::spawn(async move {
            {
                let final_shares = node.mul(x_shares.clone(), y_shares.clone(), net.clone())
                    .await
                    .expect("mul failed");
                fin_send.send((pid, final_shares)).await.unwrap();
            }
        });
        handles.push(handle);
    }

    // Wait for all mul tasks to finish
    futures::future::join_all(handles).await;

    let mut final_results = HashMap::<usize, Vec<RobustShare<Fr>>>::new();
    while let Some((id, final_shares)) = fin_recv.recv().await {
        final_results.insert(id, final_shares);
        if final_results.len() == n_parties {
            // check final_shares consist of correct shares
            for (id, mul_shares) in &final_results {
                assert_eq!(mul_shares.len(), no_of_multiplications);
                let _ = mul_shares.iter().map(|mul_share| {
                    assert_eq!(mul_share.degree, t);
                    assert_eq!(mul_share.id, *id);
                });
            }
            break;
        }
    }

    //----------------------------------------VALIDATE VALUES----------------------------------------

    let output_clientid: ClientId = 200;
    // Each server sends its output shares
    for (i, server) in nodes.iter().enumerate() {
        let net = network.clone();
        let shares_mult_for_node = final_results.get(&i).unwrap();

        match server
            .output
            .init(
                output_clientid,
                shares_mult_for_node.clone(),
                no_of_multiplications,
                net.clone(),
            )
            .await
        {
            Ok(_) => {}
            Err(e) => eprintln!("Server init error: {e}"),
        }
    }

    // Give async tasks time to run
    tokio::time::sleep(Duration::from_millis(100)).await;
    // Collect reconstructed result
    let final_output = clients[&output_clientid].lock().await.output.output.clone();
    assert!(
        final_output.is_some(),
        "Client failed to reconstruct output"
    );
    let recovered = final_output.unwrap();
    let output_values = vec![Fr::from(100), Fr::from(400)];
    assert!(
        output_values.contains(&recovered),
        "Recovered output {} not in expected values {:?}",
        recovered,
        output_values
    );
}

#[tokio::test]
async fn mul_e2e_with_preprocessing() {
    setup_tracing();
    //----------------------------------------SETUP PARAMETERS----------------------------------------
    let n_parties = 5;
    let t = 1;
    let no_of_triples = 2 * t + 1;
    let session_id = SessionId::new(ProtocolType::Mul, 0, 0, 0, 111);
    let clientid: Vec<ClientId> = vec![100, 200];
    let input_values: Vec<Fr> = vec![Fr::from(10), Fr::from(20)];
    let no_of_multiplications = 2; // 10*10, 20*20

    //Setup
    let (network, receivers, client_recv) = test_setup(n_parties, clientid.clone());

    //----------------------------------------SETUP NODES----------------------------------------
    // create global nodes
    let mut nodes = create_global_nodes::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(
        n_parties,
        t,
        no_of_triples,
        2,
        111,
        0,
        0,
        0,
        0,
        vec![clientid[0]]
    );

    //Create Clients
    let clients = create_clients::<Fr, Avid>(clientid.clone(), n_parties, t, 111, input_values, 2);

    //----------------------------------------RECIEVE----------------------------------------
    //At servers
    receive::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(receivers, nodes.clone(), network.clone());

    //At client
    receive_client(client_recv, clients.clone(), network.clone());

    //----------------------------------------RUN PREPROCESSING----------------------------------------
    let mut handles = Vec::new();
    for pid in 0..n_parties {
        let mut node = nodes[pid].clone();
        let net = network.clone();
        let mut rng = StdRng::from_rng(OsRng).unwrap();

        let handle = tokio::spawn(async move {
            {
                node.run_preprocessing(net, &mut rng)
                    .await
                    .expect("Preprocessing failed");
            }
        });
        handles.push(handle);
    }

    futures::future::join_all(handles).await;

    //----------------------------------------RUN INPUT----------------------------------------
    for (_, node) in nodes.iter_mut().enumerate() {
        let local_shares = node
            .preprocessing_material
            .lock()
            .await
            .take_random_shares(2)
            .unwrap();
        match node
            .preprocess
            .input
            .init(clientid[0], local_shares, 2, network.clone())
            .await
        {
            Ok(_) => {}
            Err(e) => {
                eprint!("{e}");
            }
        }
    }

    //----------------------------------------RUN MULTIPLICATION----------------------------------------

    let mut handles = Vec::new();
    let (fin_send, mut fin_recv) = mpsc::channel::<(usize, Vec<RobustShare<Fr>>)>(100);
    for pid in 0..n_parties {
        let mut node = nodes[pid].clone();
        let net = network.clone();
        let fin_send = fin_send.clone();

        let (x_shares, y_shares) = {
            let input_store = node.preprocess.input.wait_for_all_inputs(Duration::from_millis(500)).await.expect("input error");
            let inputs = input_store.get(&clientid[0]).unwrap();
            (
                vec![inputs[0].clone(), inputs[1].clone()],
                vec![inputs[0].clone(), inputs[1].clone()],
            )
        };

        let handle = tokio::spawn(async move {
            {
                let final_shares = node.mul(x_shares.clone(), y_shares.clone(), net.clone())
                    .await
                    .expect("mul failed");
                fin_send.send((pid, final_shares)).await.unwrap();
            }
        });
        handles.push(handle);
    }

    // Wait for all mul tasks to finish
    futures::future::join_all(handles).await;

    let mut final_results = HashMap::<usize, Vec<RobustShare<Fr>>>::new();
    while let Some((id, final_shares)) = fin_recv.recv().await {
        final_results.insert(id, final_shares);
        if final_results.len() == n_parties {
            // check final_shares consist of correct shares
            for (id, mul_shares) in &final_results {
                assert_eq!(mul_shares.len(), no_of_multiplications);
                let _ = mul_shares.iter().map(|mul_share| {
                    assert_eq!(mul_share.degree, t);
                    assert_eq!(mul_share.id, *id);
                });
            }
            break;
        }
    }

    //----------------------------------------VALIDATE VALUES----------------------------------------

    let output_clientid: ClientId = 200;
    // Each server sends its output shares
    for (i, server) in nodes.iter().enumerate() {
        let net = network.clone();
        let shares_mult_for_node = final_results.get(&i).unwrap();

        match server
            .output
            .init(
                output_clientid,
                shares_mult_for_node.clone(),
                no_of_multiplications,
                net.clone(),
            )
            .await
        {
            Ok(_) => {}
            Err(e) => eprintln!("Server init error: {e}"),
        }
    }

    // Give async tasks time to run
    tokio::time::sleep(Duration::from_millis(100)).await;
    // Collect reconstructed result
    let final_output = clients[&output_clientid].lock().await.output.output.clone();
    assert!(
        final_output.is_some(),
        "Client failed to reconstruct output"
    );
    let recovered = final_output.unwrap();
    let output_values = vec![Fr::from(100), Fr::from(400)];
    assert!(
        output_values.contains(&recovered),
        "Recovered output {} not in expected values {:?}",
        recovered,
        output_values
    );
}

//----------------------------------------PREPROCESSING----------------------------------------


#[tokio::test]
async fn preprocessing_e2e() {
    setup_tracing();
    //----------------------------------------SETUP PARAMETERS----------------------------------------
    let n_parties = 5;
    let t = 1;
    let l = 8;
    let k = 4;
    let no_of_triples = 7;
    let no_of_randomshares = 4;
    let instance_id = 111;
    let n_prandbit = 4;
    let n_prandint = 4;

    //Setup
    let (network, receivers, _) = test_setup(n_parties, vec![]);

    //----------------------------------------SETUP NODES----------------------------------------
    // create global nodes
    let nodes = create_global_nodes::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(
        n_parties,
        t,
        no_of_triples,
        no_of_randomshares,
        instance_id,
        n_prandbit,
        n_prandint,
        l,
        k,
        vec![]
    );

    //----------------------------------------RECIEVE----------------------------------------
    // spawn tasks to process received messages
    receive::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(receivers, nodes.clone(), network.clone());

    //----------------------------------------RUN PROTOCOL----------------------------------------

    // init all nodes
    let mut handles = Vec::new();
    for pid in 0..n_parties {
        let mut node = nodes[pid].clone();
        let net = network.clone();
        let mut rng = StdRng::from_rng(OsRng).unwrap();

        let handle = tokio::spawn(async move {
            {
                node.run_preprocessing(net, &mut rng)
                    .await
                    .expect("Preprocessing failed");
            }
        });
        handles.push(handle);
    }

    // Wait for all mul tasks to finish
    futures::future::join_all(handles).await;
    std::thread::sleep(std::time::Duration::from_millis(300));

    //----------------------------------------VALIDATE VALUES----------------------------------------

    for pid in 0..n_parties {
        let node = nodes[pid].clone();
        let (n_triples, n_shares, n_prandbit, n_prandint) =
            node.preprocessing_material.lock().await.len();
        assert_eq!(n_triples, 5); //>no_of_triples
        assert_eq!(n_shares, 2); //>no_of_randomshares
        assert_eq!(n_prandbit, 4);
        assert_eq!(n_prandint, 4);
    }
}

#[tokio::test]
async fn preprocessing_e2e_bad_net() {
    setup_tracing();
    //----------------------------------------SETUP PARAMETERS----------------------------------------
    let n_parties = 5;
    let t = 1;
    let no_of_triples = 4;
    let no_of_randomshares = 0;

    //Setup
    let (network, net_rx, node_channels, receivers, _) = test_setup_bad(n_parties, vec![]);

    BadFakeNetwork::start(net_rx, node_channels.clone(), StdRng::seed_from_u64(1u64), Uniform::new_inclusive(1, 3));

    //----------------------------------------SETUP NODES----------------------------------------
    // create global nodes
    let nodes = create_global_nodes::<Fr, Avid, RobustShare<Fr>, BadFakeNetwork>(
        n_parties,
        t,
        no_of_triples,
        no_of_randomshares,
        111,
        0,
        0,
        0,
        0,
        vec![]
    );

    //----------------------------------------RECIEVE----------------------------------------
    // spawn tasks to process received messages
    receive::<Fr, Avid, RobustShare<Fr>, BadFakeNetwork>(receivers, nodes.clone(), network.clone());

    //----------------------------------------RUN PROTOCOL----------------------------------------

    // init all nodes
    let mut handles = Vec::new();
    for pid in 0..n_parties {
        let mut node = nodes[pid].clone();
        let net = network.clone();
        let mut rng = StdRng::from_rng(OsRng).unwrap();

        let handle = tokio::spawn(async move {
            {
                node.run_preprocessing(net, &mut rng)
                    .await
                    .expect("Preprocessing failed");
            }
        });
        handles.push(handle);
    }

    // Wait for all mul tasks to finish
    futures::future::join_all(handles).await;
    std::thread::sleep(std::time::Duration::from_millis(300));

    //----------------------------------------VALIDATE VALUES----------------------------------------

    for pid in 0..n_parties {
        let node = nodes[pid].clone();
        let (n_triples, n_random_shares, n_prandbit_shares, n_prandint_shares) = node.preprocessing_material.lock().await.len();
        assert_eq!(n_triples, 6); //>no_of_triples
        assert_eq!(n_random_shares, 0); //>no_of_randomshares
        assert_eq!(n_prandbit_shares, 0);
        assert_eq!(n_prandint_shares, 0);
    }
}


#[tokio::test]
async fn test_output_protocol_e2e() {
    setup_tracing();
    let n = 4;
    let t = 1;
    let clientid: usize = 200;
    let output_values: Vec<Fr> = vec![Fr::from(123), Fr::from(456)];

    // Setup network
    let (net, _server_recv, mut client_recv) = test_setup(n, vec![clientid]);

    // Generate shares of output values
    let output_shares = generate_independent_shares(&output_values, t, n);

    // Set up OutputServers and OutputClient
    let client = Arc::new(Mutex::new(
        OutputClient::<Fr>::new(clientid, n, t, output_values.len()).unwrap(),
    ));
    let servers: Vec<OutputServer> = (0..n).map(|i| OutputServer::new(i, n).unwrap()).collect();

    // Spawn receiver task for client
    let client_clone = client.clone();
    let mut recv = client_recv.remove(&clientid).unwrap();
    tokio::spawn(async move {
        while let Some(received) = recv.recv().await {
            let wrapped: WrappedMessage = match bincode::deserialize(&received) {
                Ok(w) => w,
                Err(_) => continue,
            };
            match wrapped {
                WrappedMessage::Output(msg) => match client_clone.lock().await.process(msg).await {
                    Ok(_) => {}
                    Err(e) => eprintln!("Processing error : {}", e),
                },
                _ => continue,
            }
        }
    });

    // Each server sends its output shares
    for (i, server) in servers.iter().enumerate() {
        match server
            .init(
                clientid,
                output_shares[i].clone(),
                output_values.len(),
                net.clone(),
            )
            .await
        {
            Ok(_) => {}
            Err(e) => eprintln!("Server init error: {e}"),
        }
    }

    // Give async tasks time to run
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Collect reconstructed result
    let client_locked = client.lock().await;
    let final_output = client_locked.output.clone();
    assert!(
        final_output.is_some(),
        "Client failed to reconstruct output"
    );

    let recovered = final_output.unwrap();
    assert!(
        output_values.contains(&recovered),
        "Recovered output {} not in expected values {:?}",
        recovered,
        output_values
    );
}

#[tokio::test]
async fn test_rand_bit() {
    setup_tracing();

    let n_parties = 5;
    let t = 1;
    let mut rng = test_rng();
    let session_id = SessionId::new(ProtocolType::RandBit, 123, 0, 0, 111);
    let no_of_rand_bits = 2;

    //Setup
    let (network, receivers, _) = test_setup(n_parties, vec![]);

    // The construction of triples is same as that of mul
    let (_, per_party_triples) = construct_e2e_input_mul(n_parties, no_of_rand_bits, t).await;

    // assumes each party holds shares of some secrets
    let mut a = Vec::new();
    let mut shares_a = Vec::new();
    for _ in 0..no_of_rand_bits {
        let a_value = Fr::rand(&mut rng);
        a.push(a_value);
        let shares = RobustShare::compute_shares(a_value, n_parties, t, None, &mut rng).unwrap();
        shares_a.push(shares);
    }

    //----------------------------------------SETUP NODES----------------------------------------
    // create global nodes
    let nodes = create_global_nodes::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(
        n_parties,
        t,
        no_of_rand_bits,
        no_of_rand_bits,
        111,
        0,
        0,
        0,
        0,
        vec![]
    );

    //----------------------------------------RECIEVE----------------------------------------
    // spawn tasks to process received messages
    receive::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(receivers, nodes.clone(), network.clone());

    // init all nodes
    let mut handles = Vec::new();
    for pid in 0..n_parties {
        let node = nodes[pid].clone();
        let mut prand_bit_node = node.preprocess.rand_bit;
        let net = network.clone();

        // Prepare the input shares for this party
        let mut a_value = Vec::new();
        for i in 0..no_of_rand_bits {
            a_value.push(shares_a[i][pid].clone());
        }
        assert!(a_value.len() == no_of_rand_bits);

        let mult_triple = per_party_triples[pid].clone().clone();

        let handle = tokio::spawn(async move {
            {
                prand_bit_node
                    .init(a_value, mult_triple, session_id, net.clone())
                    .await
                    .expect("rand bit init failed");
            }
        });
        handles.push(handle);
    }

    // Wait for all tasks to finish
    futures::future::join_all(handles).await;
    std::thread::sleep(std::time::Duration::from_millis(500));

    //----------------------------------------VALIDATE VALUES----------------------------------------

    let mut bit_shares = Vec::new();
    for pid in 0..n_parties {
        let node = nodes[pid].clone();
        let store = node
            .preprocess
            .rand_bit
            .storage
            .lock()
            .await
            .get(&session_id)
            .cloned();
        if let Some(store) = store {
            let store_lock = store.lock().await;
            let store2 = store_lock.clone();
            let protocol_output = store2.protocol_output.clone();
            assert!(protocol_output.is_some());
            bit_shares.push(protocol_output.unwrap().clone());
        }
    }
    let mut bit_share0 = Vec::new();
    let mut bit_share1 = Vec::new();
    for i in 0..n_parties {
        bit_share0.push(bit_shares[i][0].clone());
        bit_share1.push(bit_shares[i][1].clone());
    }
    let bit0 = RobustShare::recover_secret(&bit_share0, n_parties)
        .unwrap()
        .1;
    println!("recovered bit: {}", bit0);
    // check if bit is 0 or 1
    assert!(bit0 == Fr::ZERO || bit0 == Fr::ONE);

    let bit1 = RobustShare::recover_secret(&bit_share1, n_parties)
        .unwrap()
        .1;
    println!("recovered bit: {}", bit1);
    // check if bit is 0 or 1
    assert!(bit1 == Fr::ZERO || bit1 == Fr::ONE);
}
//----------------------------------------MUL----------------------------------------

#[tokio::test]
async fn fpmul_e2e() {
    setup_tracing();
    //----------------------------------------SETUP PARAMETERS----------------------------------------
    let n_parties = 5;
    let t = 1;
    let mut rng = test_rng();
    let no_of_multiplication = 1;

    //Setup
    let (network, receivers, _) = test_setup(n_parties, vec![]);

    // Prepare inputs for multiplication
    let k = 16; // total bitlength
    let m = 4; // fractional bits to truncate
    let precision = FixedPointPrecision::new(k, m);
    let mut a_fix = Vec::new();
    let mut b_fix = Vec::new();

    //x = 5.5 * 2^4=88, y = 3.25 * 2^4=52
    //x*y = 17.875 * 2^8 = 4576
    //17.875 * 2^8/2^4 = 4576/2^4
    //17.875 * 2^4 = 286
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

    let (_, triple) = construct_e2e_input_mul(n_parties, no_of_multiplication, t).await;
    let r_int = RobustShare::compute_shares(Fr::from(3), n_parties, t, None, &mut rng).unwrap();
    let mut r_bits = vec![Vec::new(); n_parties];
    for j in 0..m {
        let x = RobustShare::compute_shares(Fr::from((j % 2) as u64), n_parties, t, None, &mut rng)
            .unwrap();
        for (i, share) in x.iter().enumerate() {
            r_bits[i].push((share.clone(), F2_8::one()));
        }
    }
    //----------------------------------------SETUP NODES----------------------------------------
    // create global nodes
    let nodes = create_global_nodes::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(
        n_parties, t, 0, 0, 111, 0, 0, 0, 0, vec![]
    );

    //----------------------------------------RECIEVE----------------------------------------
    // spawn tasks to process received messages
    receive::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(receivers, nodes.clone(), network.clone());

    //----------------------------------------RUN PROTOCOL----------------------------------------
    //Load
    for pid in 0..n_parties {
        let node = nodes[pid].clone();
        node.preprocessing_material.lock().await.add(
            Some(triple[pid].clone()),
            None,
            Some(r_bits[pid].clone()),
            Some(vec![r_int[pid].clone()]),
        );
    }

    // init all nodes
    let mut handles = Vec::new();
    for pid in 0..n_parties {
        let mut node = nodes[pid].clone();
        let net = network.clone();
        let a = a_fix[pid].clone();
        let b = b_fix[pid].clone();

        let handle =
            tokio::spawn(async move { node.mul_fixed(a, b, net).await.expect("mul failed") });
        handles.push(handle);
    }

    // wait for all tasks and collect their results
    let output_fixed: Vec<_> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|r| r.expect("task panicked"))
        .collect();

    std::thread::sleep(std::time::Duration::from_millis(200));

    //----------------------------------------VALIDATE VALUES----------------------------------------

    let shares: Vec<_> = output_fixed
        .iter()
        .map(|s| {
            assert_eq!(*s.precision(), precision);
            s.value().clone()
        })
        .collect();
    let (_, rec) = RobustShare::recover_secret(&shares, n_parties).expect("interpolate failed");
    assert_eq!(rec, Fr::from(286));
}

#[tokio::test]
async fn fpmul_e2e_with_preprocessing() {
    setup_tracing();
    //----------------------------------------SETUP PARAMETERS----------------------------------------
    let n_parties = 5;
    let t = 1;
    let instance_id = 111;
    let mut rng = test_rng();
    let k = 16; // total bitlength
    let m = 4; // fractional bits to truncate
    let precision = FixedPointPrecision::new(k, m);
    let n_triples = 1 + m; // 1 (fpmul) + m(no of random bits)
    let n_random_shares = m; // no of random bits
    let n_prandbit = m;
    let n_prandint = 1;
    let bound_l = 8;
    let security_k = 4;

    //Setup
    let (network, receivers, _) = test_setup(n_parties, vec![]);

    // Prepare inputs for multiplication

    let mut a_fix = Vec::new();
    let mut b_fix = Vec::new();

    //x = 5.5 * 2^4=88, y = 3.25 * 2^4=52
    //x*y = 17.875 * 2^8 = 4576
    //17.875 * 2^8/2^4 = 4576/2^4
    //17.875 * 2^4 = 286
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

    //----------------------------------------SETUP NODES----------------------------------------
    // create global nodes
    let nodes = create_global_nodes::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(
        n_parties,
        t,
        n_triples,
        n_random_shares,
        instance_id,
        n_prandbit,
        n_prandint,
        bound_l,
        security_k,
        vec![]
    );

    //----------------------------------------RECIEVE----------------------------------------
    // spawn tasks to process received messages
    receive::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(receivers, nodes.clone(), network.clone());

    //----------------------------------------RUN PROTOCOL----------------------------------------

    // init all nodes
    let mut handles = Vec::new();
    for pid in 0..n_parties {
        let mut node = nodes[pid].clone();
        let net = network.clone();
        let a = a_fix[pid].clone();
        let b = b_fix[pid].clone();

        let handle =
            tokio::spawn(async move { node.mul_fixed(a, b, net).await.expect("mul failed") });
        handles.push(handle);
    }

    // wait for all tasks and collect their results
    let output_fixed: Vec<_> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|r| r.expect("task panicked"))
        .collect();

    std::thread::sleep(std::time::Duration::from_millis(100));

    //----------------------------------------VALIDATE VALUES----------------------------------------

    let shares: Vec<_> = output_fixed
        .iter()
        .map(|s| {
            assert_eq!(*s.precision(), precision);
            s.value().clone()
        })
        .collect();
    let (_, rec) = RobustShare::recover_secret(&shares, n_parties).expect("interpolate failed");
    assert_eq!(rec, Fr::from(286));
}

#[tokio::test]
async fn add_fixed_e2e() {
    setup_tracing();
    //----------------------------------------SETUP PARAMETERS----------------------------------------
    let n_parties = 5;
    let t = 1;
    let instance_id = 200;
    let mut rng = test_rng();
    let k = 16;
    let m = 4;
    let precision = FixedPointPrecision::new(k, m);

    // Setup fake network
    let (network, receivers, _) = test_setup(n_parties, vec![]);

    //----------------------------------------PREPARE INPUTS----------------------------------------
    // Example: x = 5.5 * 2^4 = 88, y = 3.25 * 2^4 = 52 → expected (x + y) / 2^4 = 8.75
    let x = RobustShare::compute_shares(Fr::from(88u64), n_parties, t, None, &mut rng).unwrap();
    let y = RobustShare::compute_shares(Fr::from(52u64), n_parties, t, None, &mut rng).unwrap();

    let mut a_fix = Vec::new();
    let mut b_fix = Vec::new();

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

    //----------------------------------------SETUP NODES----------------------------------------
    let nodes = create_global_nodes::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(
        n_parties,
        t,
        0,
        0,
        instance_id,
        0,
        0,
        8,
        4,
        vec![]
    );

    // Receiver loop
    receive::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(receivers, nodes.clone(), network.clone());

    //----------------------------------------RUN ADDITION----------------------------------------
    let mut handles = Vec::new();
    for pid in 0..n_parties {
        let node = nodes[pid].clone();
        let x = a_fix[pid].clone();
        let y = b_fix[pid].clone();

        handles.push(tokio::spawn(async move {
            MPCTypeOps::<Fr, RobustShare<Fr>, FakeNetwork>::add_fixed(&node, vec![x], vec![y])
                .await
                .expect("add_fixed failed")
        }));
    }

    let results = futures::future::join_all(handles).await;
    let output_fixed: Vec<_> = results.into_iter().map(|r| r.unwrap()[0].clone()).collect();

    //----------------------------------------VALIDATE----------------------------------------
    let shares: Vec<_> = output_fixed.iter().map(|s| s.value().clone()).collect();
    let (_, rec) = RobustShare::recover_secret(&shares, n_parties).unwrap();

    // Expected: (88 + 52) = 140
    assert_eq!(rec, Fr::from(140u64));
}

#[tokio::test]
async fn sub_fixed_e2e() {
    setup_tracing();
    let n_parties = 5;
    let t = 1;
    let instance_id = 201;
    let mut rng = test_rng();
    let precision = FixedPointPrecision::new(16, 4);

    let (network, receivers, _) = test_setup(n_parties, vec![]);

    // Example: x = 9.5 * 2^4 = 152, y = 2.25 * 2^4 = 36 → expected = (116) / 2^4 = 7.25
    let x = RobustShare::compute_shares(Fr::from(152u64), n_parties, t, None, &mut rng).unwrap();
    let y = RobustShare::compute_shares(Fr::from(36u64), n_parties, t, None, &mut rng).unwrap();

    let mut a_fix = Vec::new();
    let mut b_fix = Vec::new();
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

    let nodes = create_global_nodes::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(
        n_parties,
        t,
        0,
        0,
        instance_id,
        0,
        0,
        8,
        4,
        vec![]
    );

    receive::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(receivers, nodes.clone(), network.clone());

    let mut handles = Vec::new();
    for pid in 0..n_parties {
        let node = nodes[pid].clone();
        let x = a_fix[pid].clone();
        let y = b_fix[pid].clone();

        handles.push(tokio::spawn(async move {
            MPCTypeOps::<Fr, RobustShare<Fr>, FakeNetwork>::sub_fixed(&node, vec![x], vec![y])
                .await
                .expect("sub failed")
        }));
    }

    let results = futures::future::join_all(handles).await;
    let output_fixed: Vec<_> = results.into_iter().map(|r| r.unwrap()[0].clone()).collect();

    let shares: Vec<_> = output_fixed.iter().map(|s| s.value().clone()).collect();
    let (_, rec) = RobustShare::recover_secret(&shares, n_parties).unwrap();

    assert_eq!(rec, Fr::from(116u64)); // 152 - 36
}

#[tokio::test]
async fn add_int_e2e() {
    setup_tracing();
    let n_parties = 5;
    let t = 1;
    let instance_id = 202;
    let mut rng = test_rng();

    let (network, receivers, _) = test_setup(n_parties, vec![]);

    let bitlen = 8;
    let x = RobustShare::compute_shares(Fr::from(7u64), n_parties, t, None, &mut rng).unwrap();
    let y = RobustShare::compute_shares(Fr::from(11u64), n_parties, t, None, &mut rng).unwrap();

    let mut a_int = Vec::new();
    let mut b_int = Vec::new();
    for i in 0..n_parties {
        a_int.push(SecretInt::new(x[i].clone(), bitlen));
        b_int.push(SecretInt::new(y[i].clone(), bitlen));
    }

    let nodes = create_global_nodes::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(
        n_parties,
        t,
        0,
        0,
        instance_id,
        0,
        0,
        8,
        4,
        vec![]
    );

    receive::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(receivers, nodes.clone(), network.clone());

    let mut handles = Vec::new();
    for pid in 0..n_parties {
        let node = nodes[pid].clone();
        let x = a_int[pid].clone();
        let y = b_int[pid].clone();

        handles.push(tokio::spawn(async move {
            MPCTypeOps::<Fr, RobustShare<Fr>, FakeNetwork>::add_int(&node, vec![x], vec![y])
                .await
                .expect("add_int failed")
        }));
    }

    let results = futures::future::join_all(handles).await;
    let output_int: Vec<_> = results.into_iter().map(|r| r.unwrap()[0].clone()).collect();

    let shares: Vec<_> = output_int.iter().map(|s| s.share().clone()).collect();
    let (_, rec) = RobustShare::recover_secret(&shares, n_parties).unwrap();

    assert_eq!(rec, Fr::from(18u64)); // 7 + 11
}

#[tokio::test]
async fn sub_int_e2e() {
    setup_tracing();
    let n_parties = 5;
    let t = 1;
    let instance_id = 203;
    let mut rng = test_rng();

    let (network, receivers, _) = test_setup(n_parties, vec![]);

    let bitlen = 16;
    let x = RobustShare::compute_shares(Fr::from(50u64), n_parties, t, None, &mut rng).unwrap();
    let y = RobustShare::compute_shares(Fr::from(20u64), n_parties, t, None, &mut rng).unwrap();

    let mut a_int = Vec::new();
    let mut b_int = Vec::new();
    for i in 0..n_parties {
        a_int.push(SecretInt::new(x[i].clone(), bitlen));
        b_int.push(SecretInt::new(y[i].clone(), bitlen));
    }

    let nodes = create_global_nodes::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(
        n_parties,
        t,
        0,
        0,
        instance_id,
        0,
        0,
        8,
        4,
        vec![]
    );

    receive::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(receivers, nodes.clone(), network.clone());

    let mut handles = Vec::new();
    for pid in 0..n_parties {
        let node = nodes[pid].clone();
        let x = a_int[pid].clone();
        let y = b_int[pid].clone();

        handles.push(tokio::spawn(async move {
            MPCTypeOps::<Fr, RobustShare<Fr>, FakeNetwork>::sub_int(&node, vec![x], vec![y])
                .await
                .expect("sub_int failed")
        }));
    }

    let results = futures::future::join_all(handles).await;
    let output_int: Vec<_> = results.into_iter().map(|r| r.unwrap()[0].clone()).collect();

    let shares: Vec<_> = output_int.iter().map(|s| s.share().clone()).collect();
    let (_, rec) = RobustShare::recover_secret(&shares, n_parties).unwrap();

    assert_eq!(rec, Fr::from(30u64)); // 50 - 20
}

#[tokio::test]
async fn mul_int_e2e_with_preprocessing() {
    setup_tracing();

    //----------------------------------------SETUP PARAMETERS----------------------------------------
    let n_parties = 5;
    let t = 1;
    let instance_id = 777;
    let bitlen = 8; // int8 example
    let mut rng = test_rng();

    // we will compute:  7 * 6 = 42
    let x_val = Fr::from(7u64);
    let y_val = Fr::from(6u64);

    //Setup network
    let (network, receivers, _) = test_setup(n_parties, vec![]);

    //----------------------------------------SETUP NODES----------------------------------------
    let nodes = create_global_nodes::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(
        n_parties,
        t,
        /*beaver triples*/ 2, // safe for one mul
        /*random shares */ 2,
        instance_id,
        /*prandbit*/ 0,
        /*prandint*/ 0,
        0,
        0,
        vec![]
    );

    //----------------------------------------SECRET-SHARE INPUTS----------------------------------------
    let x_shares = RobustShare::compute_shares(x_val, n_parties, t, None, &mut rng).unwrap();
    let y_shares = RobustShare::compute_shares(y_val, n_parties, t, None, &mut rng).unwrap();

    let mut secret_x = Vec::new();
    let mut secret_y = Vec::new();

    for i in 0..n_parties {
        secret_x.push(SecretInt::new(x_shares[i].clone(), bitlen));
        secret_y.push(SecretInt::new(y_shares[i].clone(), bitlen));
    }

    //----------------------------------------RECEIVE LOOP----------------------------------------
    receive::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(receivers, nodes.clone(), network.clone());

    //----------------------------------------RUN PREPROCESSING----------------------------------------
    let mut pre_handles = Vec::new();
    for pid in 0..n_parties {
        let mut node = nodes[pid].clone();
        let net = network.clone();
        let mut r = StdRng::from_rng(OsRng).unwrap();
        pre_handles.push(tokio::spawn(async move {
            node.run_preprocessing(net, &mut r).await.unwrap();
        }));
    }
    futures::future::join_all(pre_handles).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    //----------------------------------------RUN mul_int----------------------------------------
    let mut handles = Vec::new();
    for pid in 0..n_parties {
        let mut node = nodes[pid].clone();
        let net = network.clone();
        let x = secret_x[pid].clone();
        let y = secret_y[pid].clone();

        handles.push(tokio::spawn(async move {
            let out = node.mul_int(vec![x], vec![y], net).await.unwrap();
            out[0].clone()
        }));
    }

    let out = futures::future::join_all(handles).await;
    let outputs: Vec<SecretInt<Fr, RobustShare<Fr>>> =
        out.into_iter().map(|v| v.unwrap()).collect();

    //----------------------------------------RECONSTRUCT & ASSERT----------------------------------------
    let shares: Vec<RobustShare<Fr>> = outputs.iter().map(|v| v.share().clone()).collect();
    let (_, rec) = RobustShare::recover_secret(&shares, n_parties).unwrap();

    assert_eq!(rec, Fr::from(42u64)); // 7 * 6
}

//----------------------------------------DIV----------------------------------------

#[tokio::test]
async fn fpdiv_const_e2e() {
    setup_tracing();
    //----------------------------------------SETUP PARAMETERS----------------------------------------
    let n_parties = 5;
    let t = 1;
    let mut rng = test_rng();

    //Setup
    let (network, receivers, _) = test_setup(n_parties, vec![]);

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
            r_bits[i].push((share.clone(), F2_8::one()));
        }
    }

    //----------------------------------------SETUP NODES----------------------------------------
    let nodes = create_global_nodes::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(
        n_parties, t, 0, 0, 222, 0, 0, 0, 0, vec![]
    );

    //----------------------------------------RECEIVE LOOP----------------------------------------
    receive::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(receivers, nodes.clone(), network.clone());

    //----------------------------------------LOAD PREPROCESSING----------------------------------------
    for pid in 0..n_parties {
        let node = nodes[pid].clone();
        node.preprocessing_material.lock().await.add(
            None, // No Beaver triple needed
            None,
            Some(r_bits[pid].clone()),      // PRandBit[]
            Some(vec![r_int[pid].clone()]), // PRandInt[]
        );
    }

    //----------------------------------------RUN PROTOCOL----------------------------------------
    let mut handles = Vec::new();
    for pid in 0..n_parties {
        let mut node = nodes[pid].clone();
        let net = network.clone();
        let a = a_fix[pid].clone();
        let d = denom_fix[pid].clone();

        let handle = tokio::spawn(async move {
            node.div_with_const_fixed(a, d, net)
                .await
                .expect("division failed")
        });
        handles.push(handle);
    }

    // wait for all nodes
    let output_fixed: Vec<_> = futures::future::join_all(handles)
        .await
        .into_iter()
        .map(|r| r.expect("task panicked"))
        .collect();

    std::thread::sleep(std::time::Duration::from_millis(200));

    //----------------------------------------VALIDATE RESULT----------------------------------------
    let shares: Vec<_> = output_fixed
        .iter()
        .map(|s| {
            assert_eq!(*s.precision(), precision);
            s.value().clone()
        })
        .collect();

    let (_, rec) = RobustShare::recover_secret(&shares, n_parties).expect("interpolate failed");

    // 2.75 * 2^4 = 44
    assert_eq!(rec, Fr::from(44u64));
}
