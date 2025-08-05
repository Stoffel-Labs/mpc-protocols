use ark_bls12_381::Fr;
use futures::future::join_all;
use std::{sync::Arc, time::Duration};
use stoffelmpc_mpc::{
    common::{rbc::rbc::Avid, SecretSharingScheme, ShamirShare},
    honeybadger::{
        input::
            input::InputClient
        ,
        ran_dou_sha::RanDouShaState,
        robust_interpolate::robust_interpolate::{Robust, RobustShamirShare},
        share_gen::RanShaState,
        ProtocolType, SessionId, WrappedMessage,
    },
};
use stoffelmpc_network::ClientId;
use tokio::time::{sleep, timeout};

use crate::utils::test_utils::{
    construct_e2e_input, create_global_nodes, generate_independent_shares,
    initialize_global_nodes_randousha, initialize_global_nodes_ransha, receive, setup_tracing,
    test_setup,
};

pub mod utils;

#[tokio::test]
async fn randousha_e2e() {
    setup_tracing();
    let n_parties = 10;
    let t = 3;
    let session_id = SessionId::new(ProtocolType::Randousha, 1111);
    let degree_t = 3;

    //Setup
    let (network, receivers, _) = test_setup(n_parties, vec![]);
    let (_, n_shares_t, n_shares_2t) = construct_e2e_input(n_parties, degree_t);
    // create global nodes
    let mut nodes = create_global_nodes::<Fr, Avid>(n_parties, t, t + 1);
    // spawn tasks to process received messages
    receive(receivers, nodes.clone(), network.clone());

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
                .preprocessing
                .randousha
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
                        assert_eq!(s_t.id, node.id + 1);
                        assert_eq!(s_2t.id, node.id + 1);
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
    let n_parties = 10;
    let t = 3;
    let session_id = SessionId::new(ProtocolType::Ransha, 1111);

    //Setup
    let (network, receivers, _) = test_setup(n_parties, vec![]);
    let (_, n_shares_t, _) = construct_e2e_input(n_parties, t);
    // create global nodes
    let mut nodes = create_global_nodes::<Fr, Avid>(n_parties, t, t + 1);
    // spawn tasks to process received messages
    receive(receivers, nodes.clone(), network.clone());

    // init all randousha nodes
    initialize_global_nodes_ransha(nodes.clone(), &n_shares_t, session_id, Arc::clone(&network))
        .await;

    let result = timeout(
        Duration::from_secs(5),
        join_all(nodes.iter_mut().map(|node| async move {
            let store = node
                .preprocessing
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
                    assert_eq!(s_t.id, node.id + 1);
                });
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
    let mut client = InputClient::<Fr, Avid>::new(clientid[0], n, t, input_values.clone()).unwrap();
    let nodes = create_global_nodes::<Fr, Avid>(n, t, t + 1);

    //Receive at server
    receive(server_recv, nodes.clone(), net.clone());
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
                WrappedMessage::Input(msg) => {
                        match client.process(msg, net_clone2.clone()).await {
                            Ok(_) => {}
                            Err(e) => eprintln!("{}", e),
                        }
                    
                }
                _ => continue,
            }
        }
    });

    //Initialize input servers
    for (i, node) in nodes.iter().enumerate() {
        match node
            .preprocessing
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
        let shares = server.preprocessing.input.input_shares.lock().await;
        let server_shares = shares.get(&clientid[0]).unwrap();
        for (i, s) in server_shares.iter().enumerate() {
            recovered_shares[i].push(s.clone());
        }
    }
    for (i, secret) in input_values.iter().enumerate() {
        let shares: Vec<ShamirShare<Fr, 1, Robust>> = recovered_shares[i].iter().cloned().collect();
        let (_, r) = RobustShamirShare::recover_secret(&shares).unwrap();
        assert_eq!(r, *secret);
    }
}
