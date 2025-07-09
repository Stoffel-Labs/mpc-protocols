pub mod utils;

use crate::utils::test_utils::{
    construct_e2e_input, create_nodes, get_reconstruct_input, initialize_all_nodes,
    initialize_node, setup_tracing, spawn_receiver_tasks, test_setup,
};
use ark_bls12_381::Fr;
use ark_ff::{Field, UniformRand};
use ark_std::test_rng;
use std::{
    collections::HashMap, iter::zip, sync::atomic::AtomicUsize, sync::atomic::Ordering, sync::Arc,
    time::Duration, vec,
};
use stoffelmpc_mpc::common::share::shamir::ShamirShare;
use stoffelmpc_mpc::common::SecretSharingScheme;
use stoffelmpc_mpc::honeybadger::ran_dou_sha::messages::{
    InitMessage, OutputMessage, RanDouShaMessage, RanDouShaMessageType, ReconstructionMessage,
};
use stoffelmpc_mpc::honeybadger::ran_dou_sha::{RanDouShaError, RanDouShaNode, RanDouShaState};
use stoffelmpc_network::{Network, Node};
use tokio::sync::{
    mpsc::{self},
    Mutex,
};

#[tokio::test]
async fn test_init_reconstruct_flow() {
    setup_tracing();

    let n_parties = 10;
    let threshold = 3;
    let session_id = 1111;
    let degree_t = 3;

    let (params, network, mut receivers) = test_setup(n_parties, threshold, session_id);
    let (_, shares_si_t, shares_si_2t) = construct_e2e_input(n_parties, degree_t);

    let sender_id = 1;

    let init_msg = InitMessage {
        sender_id: sender_id,
        s_shares_deg_t: shares_si_t[sender_id].clone(),
        s_shares_deg_2t: shares_si_2t[sender_id].clone(),
    };

    // create randousha nodes
    let mut randousha_nodes = vec![];
    for i in 0..n_parties {
        randousha_nodes.push(initialize_node(i + 1));
    }

    let mut sender = randousha_nodes.get(sender_id - 1).unwrap().clone();

    sender
        .init_handler(&init_msg, &params, Arc::clone(&network))
        .await
        .unwrap();

    for party in network.lock().await.parties_mut() {
        // check only designated parties are receiving messages
        if party.id() > params.threshold + 1 && party.id() <= params.n_parties {
            let received_message = receivers[party.id() - 1].try_recv().unwrap();
            let deseralized_msg: RanDouShaMessage =
                bincode::deserialize(received_message.as_slice()).unwrap();
            let msg_type = deseralized_msg.msg_type;
            let payload = deseralized_msg.payload;

            // check all the assertions
            let reconstruct_msg: ReconstructionMessage<Fr> =
                ark_serialize::CanonicalDeserialize::deserialize_compressed(payload.as_slice())
                    .expect("Should be able to deseralize the message");

            assert!(msg_type == RanDouShaMessageType::ReconstructMessage);
            assert!(reconstruct_msg.sender_id == sender_id);
        }
        // check that rest does not receive messages
        else {
            assert!(receivers[party.id() - 1].try_recv().is_err());
        }

        // check all stores should be empty except for the sender's store
        let store = randousha_nodes
            .get(party.id() - 1)
            .unwrap()
            .clone()
            .get_or_create_store(&params)
            .await
            .lock()
            .await
            .clone();
        if party.id() != sender_id {
            assert!(store.computed_r_shares_degree_t.len() == 0);
            assert!(store.computed_r_shares_degree_2t.len() == 0);
            assert!(store.received_r_shares_degree_t.len() == 0);
            assert!(store.received_r_shares_degree_2t.len() == 0);
            assert!(store.received_ok_msg.len() == 0);
            assert!(store.state == RanDouShaState::Initialized);
        }

        if party.id() == sender_id {
            assert!(store.computed_r_shares_degree_t.len() == n_parties);
            assert!(store.computed_r_shares_degree_2t.len() == n_parties);
            assert!(store.received_r_shares_degree_t.len() == 0);
            assert!(store.received_r_shares_degree_2t.len() == 0);
            assert!(store.received_ok_msg.len() == 0);
            assert!(store.state == RanDouShaState::Initialized);
        }
    }
}

#[tokio::test]
async fn test_reconstruct_handler() {
    setup_tracing();
    let n_parties = 10;
    let threshold = 3;
    let session_id = 1111;
    let degree_t = 3;

    let (params, network, mut receivers) = test_setup(n_parties, threshold, session_id);
    let (_, shares_ri_t, shares_ri_2t) = get_reconstruct_input(n_parties, degree_t);

    // initialize RanDouShaNode
    let mut randousha_nodes = vec![];
    for i in 0..n_parties {
        randousha_nodes.push(initialize_node(i + 1));
    }

    // receiver id receives reconstruct messages from other party
    let receiver_id = threshold + 2;

    // receiver randousha node
    let mut randousha_node = randousha_nodes.get(receiver_id - 1).unwrap().clone();

    // receiver nodes received 2t+1 ReconstructionMessage
    for i in 0..2 * threshold + 1 {
        let rec_msg =
            ReconstructionMessage::new(i + 1, shares_ri_t[i].clone(), shares_ri_2t[i].clone());
        randousha_node
            .reconstruction_handler(&rec_msg, &params, Arc::clone(&network))
            .await
            .unwrap();
    }

    // check all parties received OutputMessage Ok sent by the receiver of the ReconstructionMessage
    for party in network.lock().await.parties_mut() {
        let received_message = receivers[party.id() - 1].try_recv().unwrap();
        let deseralized_msg: RanDouShaMessage =
            bincode::deserialize(received_message.as_slice()).unwrap();
        let msg_type = deseralized_msg.msg_type;
        let payload = deseralized_msg.payload;

        let reconstruct_msg: OutputMessage =
            ark_serialize::CanonicalDeserialize::deserialize_compressed(payload.as_slice())
                .expect("Should be able to deseralize the message");

        assert!(msg_type == RanDouShaMessageType::OutputMessage);
        assert!(reconstruct_msg.sender_id == receiver_id);
        assert!(reconstruct_msg.msg);
    }

    // check the store
    let store = randousha_node
        .get_or_create_store(&params)
        .await
        .lock()
        .await
        .clone();
    assert!(store.received_r_shares_degree_t.len() == 2 * threshold + 1);
    assert!(store.received_r_shares_degree_2t.len() == 2 * threshold + 1);
    assert!(store.received_ok_msg.len() == 0);
    assert!(store.state == RanDouShaState::Reconstruction);
}

#[tokio::test]
async fn test_reconstruct_handler_mismatch_r_t_2t() {
    setup_tracing();
    let n_parties = 10;
    let threshold = 3;
    let session_id = 1111;

    let (params, network, mut receivers) = test_setup(n_parties, threshold, session_id);
    let secret = Fr::from(1234);
    let secret_2t = Fr::from(4321);
    let degree_t = 3;
    let degree_2t = 6;

    let ids: Vec<usize> = network
        .lock()
        .await
        .parties()
        .iter()
        .map(|p| p.id())
        .collect();
    // receiver id receives recconstruct messages from other party
    let receiver_id = threshold + 2;

    let mut rng = test_rng();
    // ri_t created by each party i
    let shares_ri_t =
        ShamirShare::compute_shares(secret, n_parties, degree_t, Some(&ids), &mut rng).unwrap();
    // ri_2t created by each party i
    let shares_ri_2t =
        ShamirShare::compute_shares(secret_2t, n_parties, degree_2t, Some(&ids), &mut rng).unwrap();

    // create receiver randousha node
    let mut randousha_node: RanDouShaNode<Fr> = RanDouShaNode {
        id: receiver_id,
        store: Arc::new(Mutex::new(HashMap::new())),
    };
    // receiver nodes received t+1 ReconstructionMessage
    for i in 0..2 * threshold + 1 {
        let rec_msg =
            ReconstructionMessage::new(i + 1, shares_ri_t[i].clone(), shares_ri_2t[i].clone());
        randousha_node
            .reconstruction_handler(&rec_msg, &params, Arc::clone(&network))
            .await
            .unwrap();
    }

    // check all parties received OutputMessage Ok sent by the receiver of the ReconstructionMessage
    for party in network.lock().await.parties_mut() {
        let received_message = receivers[party.id() - 1].try_recv().unwrap();
        let deseralized_msg: RanDouShaMessage =
            bincode::deserialize(received_message.as_slice()).unwrap();
        let msg_type = deseralized_msg.msg_type;
        let payload = deseralized_msg.payload;

        let reconstruct_msg: OutputMessage =
            ark_serialize::CanonicalDeserialize::deserialize_compressed(payload.as_slice())
                .expect("Should be able to deseralize the message");

        assert!(msg_type == RanDouShaMessageType::OutputMessage);
        assert!(reconstruct_msg.sender_id == receiver_id);
        // msg should be false causing by mismatch randoms
        assert!(reconstruct_msg.msg == false);
    }

    // check the store
    let store = randousha_node
        .get_or_create_store(&params)
        .await
        .lock()
        .await
        .clone();
    assert!(store.received_r_shares_degree_t.len() == 2 * threshold + 1);
    assert!(store.received_r_shares_degree_2t.len() == 2 * threshold + 1);
    assert!(store.received_ok_msg.len() == 0);
    assert!(store.state == RanDouShaState::Reconstruction);
}

#[tokio::test]
async fn test_output_handler() {
    setup_tracing();
    let n_parties = 10;
    let threshold = 3;
    let session_id = 1111;
    let degree_t = 3;

    let (params, network, _receivers) = test_setup(n_parties, threshold, session_id);
    let (_, shares_si_t, shares_si_2t) = construct_e2e_input(n_parties, degree_t);
    let receiver_id = 1;

    let init_msg = InitMessage {
        sender_id: receiver_id,
        s_shares_deg_t: shares_si_t[receiver_id].clone(),
        s_shares_deg_2t: shares_si_2t[receiver_id].clone(),
    };

    // create receiver randousha node
    let mut randousha_node: RanDouShaNode<Fr> = RanDouShaNode {
        id: receiver_id,
        store: Arc::new(Mutex::new(HashMap::new())),
    };

    // call init_handler to create random share
    randousha_node
        .init_handler(&init_msg, &params, Arc::clone(&network))
        .await
        .unwrap();

    let node_store = randousha_node.get_or_create_store(&params).await;

    // first n-(t+1)-1 message should return error
    for i in 0..params.n_parties - (params.threshold + 2) {
        let output_message = OutputMessage::new(i + 1, true);
        let result = randousha_node
            .output_handler(&output_message, &params)
            .await;
        let e = result.expect_err("should return waitForOk");
        assert_eq!(e.to_string(), RanDouShaError::WaitForOk.to_string());
    }
    // check the store (n-(t+1)-1 shares)
    assert!(
        node_store.lock().await.received_ok_msg.len() == params.n_parties - (params.threshold + 2)
    );

    // existed id should not be counted
    let output_message = OutputMessage::new(1, true);
    let e = randousha_node
        .output_handler(&output_message, &params)
        .await
        .expect_err("should return waitForOk");
    assert_eq!(e.to_string(), RanDouShaError::WaitForOk.to_string());
    // check the store (n-(t+1)-1 shares)
    assert!(
        node_store.lock().await.received_ok_msg.len() == params.n_parties - (params.threshold + 2)
    );

    // should return abort once received false outputMessage
    let output_message = OutputMessage::new(1, false);
    let e = randousha_node
        .output_handler(&output_message, &params)
        .await
        .expect_err("should return abort");
    assert_eq!(e.to_string(), RanDouShaError::Abort.to_string());
    // check the store (n-(t+1)-1 shares)
    assert!(
        node_store.lock().await.received_ok_msg.len() == params.n_parties - (params.threshold + 2)
    );

    // should return two t+1 shares once received n-(t+1) Ok message
    let output_message = OutputMessage::new(params.n_parties, true);
    let (v_t1, v_t2) = randousha_node
        .output_handler(&output_message, &params)
        .await
        .expect("should return vecs");

    assert!(v_t1.len() == params.threshold + 1 && v_t2.len() == params.threshold + 1);
    for (share_t1, share_t2) in zip(v_t1, v_t2) {
        assert!(share_t1.degree == params.threshold);
        assert!(share_t2.degree == 2 * params.threshold)
    }
    // check the store (n-(t+1) shares)
    assert!(
        node_store.lock().await.received_ok_msg.len() == params.n_parties - (params.threshold + 1)
    );
    assert!(node_store.lock().await.state == RanDouShaState::Finished);
}

#[tokio::test]
async fn randousha_e2e() {
    setup_tracing();
    let n_parties = 10;
    let threshold = 3;
    let session_id = 1111;
    let degree_t = 3;

    let (params, network, receivers) = test_setup(n_parties, threshold, session_id);
    let (_, n_shares_t, n_shares_2t) = construct_e2e_input(params.n_parties, degree_t);

    // create randousha nodes
    let randousha_nodes = create_nodes(n_parties);
    let (fin_send, mut fin_recv) =
        mpsc::channel::<(usize, (Vec<ShamirShare<Fr>>, Vec<ShamirShare<Fr>>))>(100);
    // spawn tasks to process received messages
    let _set = spawn_receiver_tasks(
        randousha_nodes.clone(),
        receivers,
        params.clone(),
        Arc::clone(&network),
        fin_send,
        None,
    );

    // init all randousha nodes
    initialize_all_nodes(
        &randousha_nodes,
        &n_shares_t,
        &n_shares_2t,
        &params,
        Arc::clone(&network),
    )
    .await;

    let mut final_results = HashMap::<usize, (Vec<ShamirShare<Fr>>, Vec<ShamirShare<Fr>>)>::new();
    while let Some((id, final_shares)) = fin_recv.recv().await {
        final_results.insert(id, final_shares);
        if final_results.len() == 10 {
            // check final_shares consist of correct shares
            for (id, (shares_t, shares_2t)) in final_results {
                let _ = shares_t.iter().zip(shares_2t).map(|(s_t, s_2t)| {
                    assert_eq!(s_t.degree, params.threshold);
                    assert_eq!(s_2t.degree, 2 * params.threshold);
                    assert_eq!(s_t.id, id);
                    assert_eq!(s_2t.id, id);
                });
            }
            break;
        }
    }

    // wait for all randousha nodes to finish
    tokio::time::sleep(Duration::from_millis(300)).await;

    for nodes in &randousha_nodes {
        let mut node_locked = nodes.lock().await;
        let store = node_locked.get_or_create_store(&params).await;
        let store_locked = store.lock().await;
        assert!(store_locked.state == RanDouShaState::Finished);
    }
}

#[tokio::test]
async fn test_e2e_reconstruct_mismatch() {
    setup_tracing();
    let n_parties = 10;
    let threshold = 3;
    let session_id = 1111;
    let degree_t = 3;

    let (params, network, receivers) = test_setup(n_parties, threshold, session_id);
    let (_, mut n_shares_t, n_shares_2t) = construct_e2e_input(params.n_parties, degree_t);

    // lets corrupt the shares of party 1 so that the shares reconstruct different values
    let rng = &mut test_rng();
    n_shares_t[0][0] =
        ShamirShare::new(Fr::rand(rng), n_shares_t[0][0].id, n_shares_t[0][0].degree);

    // create randousha nodes
    let randousha_nodes = create_nodes(n_parties);

    let (fin_send, mut fin_recv) =
        mpsc::channel::<(usize, (Vec<ShamirShare<Fr>>, Vec<ShamirShare<Fr>>))>(100);

    // Keep track of aborts
    let abort_count = Arc::new(AtomicUsize::new(0));

    let _set = spawn_receiver_tasks(
        randousha_nodes.clone(),
        receivers,
        params.clone(),
        Arc::clone(&network),
        fin_send,
        Some(abort_count.clone()),
    );

    // init all randousha nodes
    initialize_all_nodes(
        &randousha_nodes,
        &n_shares_t,
        &n_shares_2t,
        &params,
        Arc::clone(&network),
    )
    .await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    let num_aborted_tasks = abort_count.load(Ordering::SeqCst);

    // since there are 10 nodes, each one should have receive abort by some party
    assert!(num_aborted_tasks == 10);

    let mut final_shares_received = Vec::new();
    while let Ok(msg) = fin_recv.try_recv() {
        final_shares_received.push(msg);
    }
    assert!(
        final_shares_received.is_empty(),
        "No final shares should be received when an abort occurs."
    );
}

#[tokio::test]
async fn test_e2e_wrong_degree() {
    // Setup the test.
    setup_tracing();
    let n_parties = 10;
    let threshold = 3;
    let session_id = 1111;
    let degree_t = 3;

    // Generate the network and parameters.
    let (params, network, receivers) = test_setup(n_parties, threshold, session_id);
    let (secrets, mut n_shares_t, n_shares_2t) = construct_e2e_input(params.n_parties, degree_t);

    // Modify the shares to obtain a sharing of different degree.
    let idx_mod = 5; // Index of the input share that will be modified.

    // Increasing the degree of s_{idx_mod} by two.
    // This computes the new shares as new_share = secret + id^2 * prev_share.
    // More specifically:
    // p(x) = s + a_1 * x + ... + a_t * x^t.
    // q(x) = s + x^2 * p(x) = s + x^2 * s + a_1 x^3 + ... + a_t * x^{t + 2}
    for j in 0..n_parties {
        let id_fr = Fr::from(n_shares_t[j][idx_mod].id as u64);
        n_shares_t[j][idx_mod].share[0] =
            secrets[idx_mod] + id_fr.pow([0, 0, 0, 2]) * n_shares_t[j][idx_mod].share[0];
    }

    let randousha_nodes = create_nodes(n_parties);

    let (fin_send, mut fin_recv) =
        mpsc::channel::<(usize, (Vec<ShamirShare<Fr>>, Vec<ShamirShare<Fr>>))>(100);

    // Keep track of aborts
    let abort_count = Arc::new(AtomicUsize::new(0));

    let _set = spawn_receiver_tasks(
        randousha_nodes.clone(),
        receivers,
        params.clone(),
        Arc::clone(&network),
        fin_send,
        Some(abort_count.clone()),
    );

    // Init all randousha nodes
    initialize_all_nodes(
        &randousha_nodes,
        &n_shares_t,
        &n_shares_2t,
        &params,
        Arc::clone(&network),
    )
    .await;

    tokio::time::sleep(Duration::from_millis(500)).await;

    let num_aborted_tasks = abort_count.load(Ordering::SeqCst);

    // since there are 10 nodes, each one should have receive abort by some party
    assert!(num_aborted_tasks == 10);

    let mut final_shares_received = Vec::new();
    while let Ok(msg) = fin_recv.try_recv() {
        final_shares_received.push(msg);
    }
    assert!(
        final_shares_received.is_empty(),
        "No final shares should be received when an abort occurs."
    );
}
