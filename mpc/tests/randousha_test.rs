pub mod utils;

use crate::utils::test_utils::{
    construct_e2e_input, create_nodes, get_reconstruct_input, initialize_all_nodes,
    initialize_node, setup_tracing, spawn_receiver_tasks, test_setup,
};
use ark_bls12_381::Fr;
use ark_ff::{Field, UniformRand};
use ark_serialize::CanonicalSerialize;
use ark_std::test_rng;
use std::{
    collections::HashMap, sync::atomic::AtomicUsize, sync::atomic::Ordering, sync::Arc,
    time::Duration, vec,
};
use stoffelmpc_mpc::common::rbc::rbc::Avid;
use stoffelmpc_mpc::common::share::shamir::NonRobustShare;
use stoffelmpc_mpc::common::{SecretSharingScheme, RBC};
use stoffelmpc_mpc::honeybadger::double_share::DoubleShamirShare;
use stoffelmpc_mpc::honeybadger::ran_dou_sha::messages::{
    RanDouShaMessage, RanDouShaMessageType, RanDouShaPayload, ReconstructionMessage,
};
use stoffelmpc_mpc::honeybadger::ran_dou_sha::{RanDouShaError, RanDouShaNode, RanDouShaState};
use stoffelmpc_mpc::honeybadger::{ProtocolType, SessionId, WrappedMessage};
use tokio::sync::mpsc::{self};
use tokio::task::JoinSet;
use tracing::{info, warn};

#[tokio::test]
async fn test_init_reconstruct_flow() {
    setup_tracing();

    let n_parties = 10;
    let threshold = 3;
    let session_id = SessionId::new(ProtocolType::Randousha, 0, 0, 111);
    let degree_t = 3;

    let (network, mut receivers, _) = test_setup(n_parties, vec![]);
    let (_, shares_si_t, shares_si_2t) = construct_e2e_input(n_parties, degree_t);

    let sender_id = 0;
    let mut sender_channels = Vec::new();
    let mut receiver_channels = Vec::new();
    for _ in 0..n_parties {
        let (sender, receiver) = mpsc::channel(128);
        sender_channels.push(sender);
        receiver_channels.push(receiver);
    }

    // create randousha nodes
    let mut randousha_nodes = vec![];
    for (i, sender_ch) in (0..n_parties).zip(sender_channels) {
        randousha_nodes.push(initialize_node(
            i,
            n_parties,
            degree_t,
            threshold + 1,
            sender_ch,
        ));
    }

    let mut sender = randousha_nodes.get(sender_id).unwrap().clone();

    sender
        .init(
            shares_si_t[sender_id].clone(),
            shares_si_2t[sender_id].clone(),
            session_id,
            Arc::clone(&network),
        )
        .await
        .unwrap();

    for i in 0..n_parties {
        // check only designated parties are receiving messages
        if i >= threshold + 1 && i < n_parties {
            let received_message = receivers[i].try_recv().unwrap();
            let wrapped: WrappedMessage = bincode::deserialize(&received_message).unwrap();
            let rdsmsg = match wrapped {
                WrappedMessage::RanDouSha(ran_dou_sha_message) => ran_dou_sha_message,
                _ => todo!(),
            };

            let msg_type = rdsmsg.msg_type;
            assert!(matches!(rdsmsg.payload, RanDouShaPayload::Reconstruct(_)));
            assert!(msg_type == RanDouShaMessageType::ReconstructMessage);
        }
        // check that rest does not receive messages
        else {
            assert!(receivers[i].try_recv().is_err());
        }

        // check all stores should be empty except for the sender's store
        let store = randousha_nodes
            .get(i)
            .unwrap()
            .clone()
            .get_or_create_store(session_id)
            .await
            .lock()
            .await
            .clone();
        if i != sender_id {
            assert!(store.computed_r_shares_degree_t.len() == 0);
            assert!(store.computed_r_shares_degree_2t.len() == 0);
            assert!(store.received_r_shares_degree_t.len() == 0);
            assert!(store.received_r_shares_degree_2t.len() == 0);
            assert!(store.received_ok_msg.len() == 0);
            assert!(store.state == RanDouShaState::Initialized);
        }

        if i == sender_id {
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
    let session_id = SessionId::new(ProtocolType::Randousha, 0, 0, 111);
    let degree_t = 3;

    let (network, mut receivers, _) = test_setup(n_parties, vec![]);
    let (_, shares_ri_t, shares_ri_2t) = get_reconstruct_input(n_parties, degree_t);

    let mut sender_channels = Vec::new();
    let mut receiver_channels = Vec::new();
    for _ in 0..n_parties {
        let (sender, receiver) = mpsc::channel(128);
        sender_channels.push(sender);
        receiver_channels.push(receiver);
    }

    // initialize RanDouShaNode
    let mut randousha_nodes = vec![];
    for (i, sender_ch) in (0..n_parties).zip(sender_channels) {
        randousha_nodes.push(initialize_node(
            i,
            n_parties,
            threshold,
            threshold + 1,
            sender_ch,
        ));
    }

    // receiver id receives reconstruct messages from other party
    let receiver_id = threshold + 2;

    // receiver randousha node
    let mut randousha_node = randousha_nodes.get(receiver_id).unwrap().clone();

    // receiver nodes received 2t+1 ReconstructionMessage
    for i in 0..2 * threshold + 1 {
        let rec_msg = ReconstructionMessage::new(shares_ri_t[i].clone(), shares_ri_2t[i].clone());
        let mut bytes_rec_message = Vec::new();
        rec_msg
            .serialize_compressed(&mut bytes_rec_message)
            .map_err(RanDouShaError::ArkSerialization)
            .unwrap();
        let rds_message = RanDouShaMessage::new(
            i,
            RanDouShaMessageType::ReconstructMessage,
            session_id,
            RanDouShaPayload::Reconstruct(bytes_rec_message),
        );
        randousha_node
            .reconstruction_handler(rds_message, Arc::clone(&network))
            .await
            .unwrap();
    }

    // check all parties received OutputMessage Ok sent by the receiver of the ReconstructionMessage
    let mut set = JoinSet::new();
    for i in 0..n_parties {
        let mut receiver = receivers.remove(0);
        let randousha_node = randousha_nodes[i].clone();
        let net = Arc::clone(&network);
        let receiver_id = receiver_id; // capture from outer scope

        set.spawn(async move {
            while let Some(received) = receiver.recv().await {
                let wrapped: WrappedMessage = match bincode::deserialize(&received) {
                    Ok(w) => w,
                    Err(_) => continue,
                };

                match wrapped {
                    WrappedMessage::RanDouSha(msg) => {
                        if msg.msg_type == RanDouShaMessageType::OutputMessage {
                            assert_eq!(msg.sender_id, receiver_id);
                            assert!(matches!(msg.payload, RanDouShaPayload::Output(true)));
                            return; // we're done for this party
                        }
                    }
                    WrappedMessage::Rbc(msg) => {
                        if let Err(e) = randousha_node.rbc.process(msg, Arc::clone(&net)).await {
                            warn!("Rbc processing error: {e}");
                        }
                    }
                    _ => continue,
                }
            }
        });
    }

    // check the store
    let store = randousha_node
        .get_or_create_store(session_id)
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
    let session_id = SessionId::new(ProtocolType::Randousha, 0, 0, 111);

    let (network, mut receivers, _) = test_setup(n_parties, vec![]);
    let secret = Fr::from(1234);
    let secret_2t = Fr::from(4321);
    let degree_t = 3;
    let degree_2t = 6;

    let (sender_ch, _receiver_ch) = mpsc::channel(128);

    // receiver id receives recconstruct messages from other party
    let receiver_id = threshold + 2;

    let mut rng = test_rng();
    // ri_t created by each party i
    let shares_ri_t =
        NonRobustShare::compute_shares(secret, n_parties, degree_t, None, &mut rng).unwrap();
    // ri_2t created by each party i
    let shares_ri_2t =
        NonRobustShare::compute_shares(secret_2t, n_parties, degree_2t, None, &mut rng).unwrap();
    // initialize RanDouShaNode
    let mut randousha_nodes = vec![];
    for i in 0..n_parties {
        randousha_nodes.push(initialize_node(
            i,
            n_parties,
            threshold,
            threshold + 1,
            sender_ch.clone(),
        ));
    }

    // receiver randousha node
    let mut randousha_node = randousha_nodes.get(receiver_id).unwrap().clone();

    // Send 2t+1 reconstruction messages to the receiver node
    for i in 0..n_parties {
        let rec_msg = ReconstructionMessage::new(shares_ri_t[i].clone(), shares_ri_2t[i].clone());
        let mut bytes_rec_message = Vec::new();
        rec_msg
            .serialize_compressed(&mut bytes_rec_message)
            .map_err(RanDouShaError::ArkSerialization)
            .unwrap();
        let rds_message = RanDouShaMessage::new(
            i,
            RanDouShaMessageType::ReconstructMessage,
            session_id,
            RanDouShaPayload::Reconstruct(bytes_rec_message),
        );
        randousha_node
            .reconstruction_handler(rds_message, Arc::clone(&network))
            .await
            .unwrap();
    }

    // check all parties received OutputMessage Ok sent by the receiver of the ReconstructionMessage
    let mut set = JoinSet::new();
    for i in 0..n_parties {
        let mut receiver = receivers.remove(0);
        let randousha_node = randousha_nodes[i].clone();
        let net = Arc::clone(&network);
        let receiver_id = receiver_id;

        set.spawn(async move {
            while let Some(received) = receiver.recv().await {
                let wrapped: WrappedMessage = match bincode::deserialize(&received) {
                    Ok(w) => w,
                    Err(_) => continue,
                };

                match wrapped {
                    WrappedMessage::RanDouSha(msg) => {
                        if msg.msg_type == RanDouShaMessageType::OutputMessage {
                            assert_eq!(msg.sender_id, receiver_id);
                            assert!(matches!(msg.payload, RanDouShaPayload::Output(false)));
                            return;
                        }
                    }
                    WrappedMessage::Rbc(msg) => {
                        if let Err(e) = randousha_node.rbc.process(msg, Arc::clone(&net)).await {
                            warn!("Rbc processing error: {e}");
                        }
                    }
                    _ => continue,
                }
            }
        });
    }

    while let Some(res) = set.join_next().await {
        res.expect("Task panicked");
    }

    // check the store
    let store = randousha_node
        .get_or_create_store(session_id)
        .await
        .lock()
        .await
        .clone();
    assert_eq!(store.received_r_shares_degree_t.len(), n_parties);
    assert_eq!(store.received_r_shares_degree_2t.len(), n_parties);
    assert_eq!(store.received_ok_msg.len(), 0);
    assert_eq!(store.state, RanDouShaState::Reconstruction);
}

#[tokio::test]
async fn test_output_handler() {
    setup_tracing();
    let n_parties = 10;
    let threshold = 3;
    let session_id = SessionId::new(ProtocolType::Randousha, 0, 0, 111);
    let degree_t = 3;

    let (network, _receivers, _) = test_setup(n_parties, vec![]);
    let (_, shares_si_t, shares_si_2t) = construct_e2e_input(n_parties, degree_t);
    let receiver_id = 1;

    let (sender_ch, _receiver_ch) = mpsc::channel(128);

    // create receiver randousha node
    let mut randousha_node: RanDouShaNode<Fr, Avid> =
        RanDouShaNode::new(receiver_id, sender_ch, n_parties, threshold, threshold + 1).unwrap();
    // call init_handler to create random share
    randousha_node
        .init(
            shares_si_t[receiver_id].clone(),
            shares_si_2t[receiver_id].clone(),
            session_id,
            Arc::clone(&network),
        )
        .await
        .unwrap();

    let node_store = randousha_node.get_or_create_store(session_id).await;

    // first n-(t+1)-1 message should return error
    for i in 0..n_parties - (threshold + 2) {
        let output_message = RanDouShaMessage::new(
            i,
            RanDouShaMessageType::OutputMessage,
            session_id,
            RanDouShaPayload::Output(true),
        );
        let result = randousha_node.output_handler(output_message).await;
        let e = result.expect_err("should return waitForOk");
        assert_eq!(e.to_string(), RanDouShaError::WaitForOk.to_string());
    }
    // check the store (n-(t+1)-1 shares)
    assert!(node_store.lock().await.received_ok_msg.len() == n_parties - (threshold + 2));

    // existed id should not be counted
    let output_message = RanDouShaMessage::new(
        1,
        RanDouShaMessageType::OutputMessage,
        session_id,
        RanDouShaPayload::Output(true),
    );
    let e = randousha_node
        .output_handler(output_message)
        .await
        .expect_err("should return waitForOk");
    assert_eq!(e.to_string(), RanDouShaError::WaitForOk.to_string());
    // check the store (n-(t+1)-1 shares)
    assert!(node_store.lock().await.received_ok_msg.len() == n_parties - (threshold + 2));

    // should return abort once received false outputMessage
    let output_message = RanDouShaMessage::new(
        1,
        RanDouShaMessageType::OutputMessage,
        session_id,
        RanDouShaPayload::Output(false),
    );
    let e = randousha_node
        .output_handler(output_message)
        .await
        .expect_err("should return abort");
    assert_eq!(e.to_string(), RanDouShaError::Abort.to_string());
    // check the store (n-(t+1)-1 shares)
    assert!(node_store.lock().await.received_ok_msg.len() == n_parties - (threshold + 2));

    // should return two t+1 shares once received n-(t+1) Ok message
    let output_message = RanDouShaMessage::new(
        n_parties,
        RanDouShaMessageType::OutputMessage,
        session_id,
        RanDouShaPayload::Output(true),
    );
    randousha_node
        .output_handler(output_message)
        .await
        .expect("output handler should not fail");
    {
        let storage_mutex = randousha_node.get_or_create_store(session_id).await;
        let storage = storage_mutex.lock().await;
        let output = storage.protocol_output.clone();

        assert!(output.len() == threshold + 1);
        for double_share in output {
            assert!(double_share.degree_t.degree == threshold);
            assert!(double_share.degree_2t.degree == 2 * threshold);
        }
    }
    // check the store (n-(t+1) shares)
    assert!(node_store.lock().await.received_ok_msg.len() == n_parties - (threshold + 1));
    assert!(node_store.lock().await.state == RanDouShaState::Finished);
}

#[tokio::test]
async fn randousha_e2e() {
    setup_tracing();
    let n_parties = 10;
    let threshold = 3;
    let session_id = SessionId::new(ProtocolType::Randousha, 0, 0, 111);
    let degree_t = 3;

    let (network, receivers, _) = test_setup(n_parties, vec![]);
    let (_, n_shares_t, n_shares_2t) = construct_e2e_input(n_parties, degree_t);

    let mut sender_channels = Vec::new();
    let mut receiver_channels = Vec::new();
    for _ in 0..n_parties {
        let (sender, receiver) = mpsc::channel(128);
        sender_channels.push(sender);
        receiver_channels.push(receiver);
    }

    info!("channels created");

    // create randousha nodes
    let randousha_nodes = create_nodes(n_parties, sender_channels, threshold, threshold + 1);
    let (fin_send, mut fin_recv) = mpsc::channel::<(usize, Vec<DoubleShamirShare<Fr>>)>(100);
    // spawn tasks to process received messages
    let _set = spawn_receiver_tasks(
        randousha_nodes.clone(),
        receivers,
        Arc::clone(&network),
        fin_send,
        None,
    );

    info!("receiver task spawned");

    // init all randousha nodes
    initialize_all_nodes(
        &randousha_nodes,
        &n_shares_t,
        &n_shares_2t,
        session_id,
        Arc::clone(&network),
    )
    .await;

    info!("nodes initialized");

    let mut final_results = HashMap::<usize, Vec<DoubleShamirShare<Fr>>>::new();
    while let Some((id, final_shares)) = fin_recv.recv().await {
        final_results.insert(id, final_shares);
        if final_results.len() == 10 {
            // check final_shares consist of correct shares
            for (id, double_shares) in final_results {
                assert_eq!(double_shares.len(), threshold + 1);
                let _ = double_shares.iter().map(|double_share| {
                    assert_eq!(double_share.degree_t.degree, threshold);
                    assert_eq!(double_share.degree_2t.degree, 2 * threshold);
                    assert_eq!(double_share.degree_t.id, id);
                    assert_eq!(double_share.degree_2t.id, id);
                });
            }
            break;
        }
    }

    // wait for all randousha nodes to finish
    tokio::time::sleep(Duration::from_millis(300)).await;

    for nodes in &randousha_nodes {
        let mut node_locked = nodes.lock().await;
        let store = node_locked.get_or_create_store(session_id).await;
        let store_locked = store.lock().await;
        assert!(store_locked.state == RanDouShaState::Finished);
    }
}

#[tokio::test]
async fn test_e2e_reconstruct_mismatch() {
    setup_tracing();
    let n_parties = 10;
    let threshold = 3;
    let session_id = SessionId::new(ProtocolType::Randousha, 0, 0, 111);
    let degree_t = 3;

    let (network, receivers, _) = test_setup(n_parties, vec![]);
    let (_, mut n_shares_t, n_shares_2t) = construct_e2e_input(n_parties, degree_t);

    // lets corrupt the shares of party 1 so that the shares reconstruct different values
    let rng = &mut test_rng();
    n_shares_t[0][0] =
        NonRobustShare::new(Fr::rand(rng), n_shares_t[0][0].id, n_shares_t[0][0].degree);

    let mut sender_channels = Vec::new();
    let mut receiver_channels = Vec::new();
    for _ in 0..n_parties {
        let (sender, receiver) = mpsc::channel(128);
        sender_channels.push(sender);
        receiver_channels.push(receiver);
    }

    // create randousha nodes
    let randousha_nodes = create_nodes(n_parties, sender_channels, threshold, threshold + 1);

    let (fin_send, mut fin_recv) = mpsc::channel::<(usize, Vec<DoubleShamirShare<Fr>>)>(100);

    // Keep track of aborts
    let abort_count = Arc::new(AtomicUsize::new(0));

    let _set = spawn_receiver_tasks(
        randousha_nodes.clone(),
        receivers,
        Arc::clone(&network),
        fin_send,
        Some(abort_count.clone()),
    );

    // init all randousha nodes
    initialize_all_nodes(
        &randousha_nodes,
        &n_shares_t,
        &n_shares_2t,
        session_id,
        Arc::clone(&network),
    )
    .await;

    tokio::time::sleep(Duration::from_millis(1000)).await;

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
    let session_id = SessionId::new(ProtocolType::Randousha, 0, 0, 111);
    let degree_t = 3;

    // Generate the network and parameters.
    let (network, receivers, _) = test_setup(n_parties, vec![]);
    let (secrets, mut n_shares_t, n_shares_2t) = construct_e2e_input(n_parties, degree_t);

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

    let mut sender_channels = Vec::new();
    let mut receiver_channels = Vec::new();
    for _ in 0..n_parties {
        let (sender, receiver) = mpsc::channel(128);
        sender_channels.push(sender);
        receiver_channels.push(receiver);
    }
    let randousha_nodes = create_nodes(n_parties, sender_channels, threshold, threshold + 1);
    let (fin_send, mut fin_recv) = mpsc::channel::<(usize, Vec<DoubleShamirShare<Fr>>)>(100);

    // Keep track of aborts
    let abort_count = Arc::new(AtomicUsize::new(0));

    let _set = spawn_receiver_tasks(
        randousha_nodes.clone(),
        receivers,
        Arc::clone(&network),
        fin_send,
        Some(abort_count.clone()),
    );

    // Init all randousha nodes
    initialize_all_nodes(
        &randousha_nodes,
        &n_shares_t,
        &n_shares_2t,
        session_id,
        Arc::clone(&network),
    )
    .await;

    tokio::time::sleep(Duration::from_millis(1000)).await;

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
