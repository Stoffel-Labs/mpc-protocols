use crate::utils::test_utils::{
    create_global_nodes, generate_independent_shares, receive, setup_tracing, test_setup,
};
use ark_bls12_381::Fr;
use stoffelmpc_mpc::honeybadger::input::InputError;
use stoffelmpc_mpc::{
    common::{rbc::rbc::Avid, SecretSharingScheme, ShamirShare},
    honeybadger::{
        input::{input::InputClient, InputMessageType},
        robust_interpolate::robust_interpolate::{Robust, RobustShare},
        HoneyBadgerMPCNode, WrappedMessage,
    },
};
use tokio::time::{sleep, Duration};
use stoffelmpc_network::fake_network::FakeNetwork;

pub mod utils;
#[tokio::test]
async fn test_multiple_clients_parallel_input() {
    setup_tracing();
    let n = 4;
    let t = 1;
    let client_ids = vec![100, 101];
    let inputs = vec![
        vec![Fr::from(10), Fr::from(20)],
        vec![Fr::from(30), Fr::from(40)],
    ];
    let masks = vec![
        vec![Fr::from(11), Fr::from(21)],
        vec![Fr::from(31), Fr::from(41)],
    ];

    let (net, server_recv, mut client_recv) = test_setup(n, client_ids.clone());
    let local_shares: Vec<_> = masks
        .iter()
        .map(|mask| generate_independent_shares(mask, t, n))
        .collect();

    let mut nodes: Vec<HoneyBadgerMPCNode<Fr, Avid>> =
        create_global_nodes::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(n, t, 0, 0, 111, client_ids.clone());
    receive::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(server_recv, nodes.clone(), net.clone());

    for (i, &cid) in client_ids.iter().enumerate() {
        let input = inputs[i].clone();
        let mut client = InputClient::<Fr, Avid>::new(cid, n, t, 111, input.clone()).unwrap();
        let mut recv = client_recv.remove(&cid).unwrap();
        let net_clone = net.clone();
        tokio::spawn(async move {
            while let Some(received) = recv.recv().await {
                let wrapped: WrappedMessage = bincode::deserialize(&received).ok().unwrap();
                if let WrappedMessage::Input(msg) = wrapped {
                    if msg.msg_type == InputMessageType::MaskShare {
                        client.process(msg, net_clone.clone()).await.ok();
                    }
                }
            }
        });
        for (j, node) in nodes.iter_mut().enumerate() {
            node.preprocess
                .input
                .init(cid, local_shares[i][j].clone(), 2, net.clone())
                .await
                .unwrap();
        }
    }

    for (i, &cid) in client_ids.iter().enumerate() {
        let mut recovered_shares = vec![vec![]; inputs[i].len()];
        for server in &mut nodes {
            let shares = server.preprocess.input.wait_for_all_inputs(Duration::from_millis(200)).await.expect("input error");
            let server_shares = shares.get(&cid).unwrap();
            for (j, s) in server_shares.iter().enumerate() {
                recovered_shares[j].push(s.clone());
            }
        }
        for (j, secret) in inputs[i].iter().enumerate() {
            let shares: Vec<ShamirShare<Fr, 1, Robust>> =
                recovered_shares[j].iter().cloned().collect();
            let (_, r) = RobustShare::recover_secret(&shares, n).unwrap();
            assert_eq!(r, *secret);
        }
    }
}

#[tokio::test]
async fn test_input_recovery_with_missing_server() {
    setup_tracing();
    let n = 4;
    let t = 1;
    let clientid = 100;
    let input_values = vec![Fr::from(10)];
    let mask_values = vec![Fr::from(11)];

    let (net, server_recv, mut client_recv) = test_setup(n, vec![clientid]);
    let local_shares = generate_independent_shares(&mask_values, t, n);
    let mut client =
        InputClient::<Fr, Avid>::new(clientid, n, t, 111, input_values.clone()).unwrap();
    let mut nodes = create_global_nodes::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(n, t, 0, 0, 111, vec![clientid]);

    receive::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(server_recv, nodes.clone(), net.clone());
    let mut recv = client_recv.remove(&clientid).unwrap();
    let net_clone = net.clone();
    tokio::spawn(async move {
        while let Some(received) = recv.recv().await {
            if let Ok(WrappedMessage::Input(msg)) = bincode::deserialize(&received) {
                if msg.msg_type == InputMessageType::MaskShare {
                    client.process(msg, net_clone.clone()).await.ok();
                }
            }
        }
    });

    // Simulate only 3 out of 4 servers responding
    for (i, node) in nodes.iter_mut().take(3).enumerate() {
        node.preprocess
            .input
            .init(clientid, local_shares[i].clone(), 1, net.clone())
            .await
            .unwrap();
    }

    let mut recovered_shares = vec![];
    for server in &mut nodes[..3] {
        let shares = server.preprocess.input.wait_for_all_inputs(Duration::from_millis(200)).await.expect("input error");
        let server_shares = shares.get(&clientid).unwrap();
        recovered_shares.push(server_shares[0].clone());
    }

    let shares: Vec<ShamirShare<Fr, 1, Robust>> = recovered_shares;
    let (_, r) = RobustShare::recover_secret(&shares, n).unwrap();
    assert_eq!(r, input_values[0]);
}

#[tokio::test]
async fn test_input_with_too_many_faulty_shares() {
    setup_tracing();
    let n = 10;
    let t = 3;
    let client_id = 103;
    let input_value = Fr::from(33);
    let mask_value = Fr::from(88);

    let (net, server_recv, mut client_recv) = test_setup(n, vec![client_id]);

    let mut local_shares = generate_independent_shares(&[mask_value], t, n);
    let mut client = InputClient::<Fr, Avid>::new(client_id, n, t, 111, vec![input_value]).unwrap();
    let mut nodes = create_global_nodes::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(n, t, 0, 0, 111, vec![client_id]);

    // Start server receiver loop
    receive::<Fr, Avid, RobustShare<Fr>, FakeNetwork>(server_recv, nodes.clone(), net.clone());

    // Start client receiver loop
    let mut recv = client_recv.remove(&client_id).unwrap();
    let net_clone = net.clone();
    tokio::spawn(async move {
        while let Some(received) = recv.recv().await {
            if let Ok(WrappedMessage::Input(msg)) = bincode::deserialize(&received) {
                // Client will fail internally when trying to decode faulty shares
                let _ = client.process(msg, net_clone.clone()).await;
            }
        }
    });

    // Corrupt more than t=1 shares
    local_shares[0][0].share[0] += Fr::from(321);
    local_shares[1][0].share[0] += Fr::from(123);
    local_shares[2][0].share[0] += Fr::from(123);
    local_shares[3][0].share[0] += Fr::from(123);

    for (i, node) in nodes.iter_mut().enumerate() {
        node.preprocess
            .input
            .init(client_id, local_shares[i].clone(), 1, net.clone())
            .await
            .unwrap();
    }

    // Ensure no server accepted the faulty masked input
    for (i, server) in nodes.iter_mut().enumerate() {
        let shares = server.preprocess.input.wait_for_all_inputs(Duration::from_millis(300)).await;
        assert!(
            matches!(shares, Err(InputError::Timeout(_))),
            "Server {i} should not have received input from client due to decoding failure"
        );
    }
}
