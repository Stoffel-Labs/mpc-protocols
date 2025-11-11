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
use std::{sync::Arc, time::Duration};
use stoffelmpc_mpc::{
    common::{
        rbc::rbc::Avid,
        types::fixed::{FixedPointPrecision, SecretFixedPoint},
        MPCProtocol, MPCTypeOps, PreprocessingMPCProtocol, SecretSharingScheme, ShamirShare,
    },
    honeybadger::{
        fpmul::f256::F2_8,
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
    sync::Mutex,
    time::{sleep, timeout},
};
use tracing::info;

pub mod utils;

#[tokio::test]
async fn randousha_e2e() {
    setup_tracing();
    let n_parties = 5;
    let t = 1;
    let session_id = SessionId::new(ProtocolType::Randousha, 0, 0, 111);
    let degree_t = 1;

    //Setup
    let (network, receivers, _) = test_setup(n_parties, vec![]);
    let (_, n_shares_t, n_shares_2t) = construct_e2e_input(n_parties, degree_t);
    // create global nodes
    let mut nodes = create_global_nodes::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(
        n_parties, t, 0, 0, 111, 0, 0, 0, 0,
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
    let session_id = SessionId::new(ProtocolType::Randousha, 0, 0, 111);

    //Setup
    let (network, receivers, _) = test_setup(n_parties, vec![]);
    // create global nodes
    let mut nodes = create_global_nodes::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(
        n_parties, t, 0, 0, 111, 0, 0, 0, 0,
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
    let nodes =
        create_global_nodes::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(n, t, 0, 0, 111, 0, 0, 0, 0);

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
    for (i, node) in nodes.iter().enumerate() {
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
    tokio::time::sleep(Duration::from_millis(100)).await;
    // Check final result: each server should have m_i = input_i
    let mut recovered_shares = vec![vec![]; input_values.len()];
    for server in &nodes {
        let shares = server.preprocess.input.input_shares.lock().await;
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
    let session_id = SessionId::new(ProtocolType::Ransha, 0, 0, 111);
    let clientid: Vec<ClientId> = vec![100];
    let input_values: Vec<Fr> = vec![Fr::from(10), Fr::from(20)];
    //Setup the network for servers and client
    let (network, receivers, mut client_recv) = test_setup(n_parties, clientid.clone());

    //----------------------------------------SETUP NODES----------------------------------------
    //Create global nodes for InputServers
    let mut nodes = create_global_nodes::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(
        n_parties, t, 0, 0, 111, 0, 0, 0, 0,
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

    tokio::time::sleep(Duration::from_millis(100)).await;
    //----------------------------------------VALIDATE VALUES----------------------------------------
    //Check final result: each server should have m_i = input_i
    let mut recovered_shares = vec![vec![]; input_values.len()];
    for server in &nodes {
        let shares = server.preprocess.input.input_shares.lock().await;
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
    let session_id = SessionId::new(ProtocolType::Mul, 0, 0, 111);
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
    let triple = construct_e2e_input_mul(n_parties, no_of_multiplication, t).await;

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
        n_parties, t, 0, 0, 111, 0, 0, 0, 0,
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
    let mut handles = Vec::new();
    for pid in 0..n_parties {
        let mut node = nodes[pid].clone();
        let net = network.clone();
        let x_shares = x_inputs_per_node[pid].clone();
        let y_shares = y_inputs_per_node[pid].clone();

        let handle = tokio::spawn(async move {
            {
                node.mul(x_shares.clone(), y_shares.clone(), net.clone())
                    .await
                    .expect("mul failed");
            }
        });
        handles.push(handle);
    }

    // Wait for all mul tasks to finish
    futures::future::join_all(handles).await;
    std::thread::sleep(std::time::Duration::from_millis(500));

    //----------------------------------------VALIDATE VALUES----------------------------------------

    let mut per_multiplication_shares: Vec<Vec<RobustShare<Fr>>> =
        vec![Vec::new(); no_of_multiplication];

    for pid in 0..n_parties {
        let node = nodes[pid].clone();
        let storage_map = node.operations.mul.mult_storage.lock().await;
        if let Some(storage_mutex) = storage_map.get(&session_id) {
            let storage = storage_mutex.lock().await;

            if storage.protocol_output.is_empty() {
                panic!("protocol_output empty for node {}", pid);
            }
            let shares_mult_for_node: Vec<RobustShare<Fr>> = storage.protocol_output.clone();
            assert_eq!(shares_mult_for_node.len(), no_of_multiplication);

            for i in 0..no_of_multiplication {
                per_multiplication_shares[i].push(shares_mult_for_node[i].clone());
            }
        } else {
            panic!(
                "no mult_storage entry for session {:?} on node {}",
                session_id, pid
            );
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
    let session_id = SessionId::new(ProtocolType::Mul, 0, 0, 111);
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
    tokio::time::sleep(Duration::from_millis(100)).await;

    //----------------------------------------RUN MULTIPLICATION----------------------------------------

    let mut handles = Vec::new();
    for pid in 0..n_parties {
        let mut node = nodes[pid].clone();
        let net = network.clone();

        let (x_shares, y_shares) = {
            let input_store = node.preprocess.input.input_shares.lock().await;
            let inputs = input_store.get(&clientid[0]).unwrap();
            (
                vec![inputs[0].clone(), inputs[1].clone()],
                vec![inputs[0].clone(), inputs[1].clone()],
            )
        };

        let handle = tokio::spawn(async move {
            {
                node.mul(x_shares.clone(), y_shares.clone(), net.clone())
                    .await
                    .expect("mul failed");
            }
        });
        handles.push(handle);
    }

    // Wait for all mul tasks to finish
    futures::future::join_all(handles).await;
    std::thread::sleep(std::time::Duration::from_millis(300));

    //----------------------------------------VALIDATE VALUES----------------------------------------

    let output_clientid: ClientId = 200;
    // Each server sends its output shares
    for (i, server) in nodes.iter().enumerate() {
        let net = network.clone();
        let storage_map = server.operations.mul.mult_storage.lock().await;
        if let Some(storage_mutex) = storage_map.get(&session_id) {
            let storage = storage_mutex.lock().await;

            if storage.protocol_output.is_empty() {
                panic!("protocol_output empty for node {}", i);
            }
            let shares_mult_for_node: Vec<RobustShare<Fr>> = storage.protocol_output.clone();
            assert_eq!(shares_mult_for_node.len(), no_of_multiplications);
            match server
                .output
                .init(
                    output_clientid,
                    shares_mult_for_node,
                    no_of_multiplications,
                    net.clone(),
                )
                .await
            {
                Ok(_) => {}
                Err(e) => eprintln!("Server init error: {e}"),
            }
        } else {
            panic!(
                "no mult_storage entry for session {:?} on node {}",
                session_id, i
            );
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
    let session_id = SessionId::new(ProtocolType::RandBit, 0, 0, 111);
    let no_of_rand_bits = 2;

    //Setup
    let (network, receivers, _) = test_setup(n_parties, vec![]);

    // The construction of triples is same as that of mul
    let per_party_tripes = construct_e2e_input_mul(n_parties, no_of_rand_bits, t).await;

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

        let mult_triple = per_party_tripes[pid].clone().clone();

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
        a_fix.push(SecretFixedPoint::new(x[i].clone(), precision));
        b_fix.push(SecretFixedPoint::new(y[i].clone(), precision));
    }

    let triple = construct_e2e_input_mul(n_parties, no_of_multiplication, t).await;
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
        n_parties, t, 0, 0, 111, 0, 0, 0, 0,
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
        a_fix.push(SecretFixedPoint::new(x[i].clone(), precision));
        b_fix.push(SecretFixedPoint::new(y[i].clone(), precision));
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
