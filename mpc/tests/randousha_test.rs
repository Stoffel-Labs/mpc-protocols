#[cfg(test)]
mod tests {

    use ark_bls12_381::Fr;
    use ark_ff::UniformRand;
    use ark_std::test_rng;
    use std::collections::HashMap;
    use std::iter::zip;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::Duration;
    use std::vec;
    use stoffelmpc_common::share::shamir::{self, ShamirSecretSharing};
    use stoffelmpc_mpc::honeybadger::ran_dou_sha::messages::{
        InitMessage, OutputMessage, RanDouShaMessage, RanDouShaMessageType, ReconstructionMessage,
    };
    use stoffelmpc_mpc::honeybadger::ran_dou_sha::{
        RanDouShaError, RanDouShaNode, RanDouShaParams, RanDouShaState,
    };
    use stoffelmpc_network::fake_network::{FakeNetwork, FakeNetworkConfig,};
    use stoffelmpc_network::{Network, Node, NetworkError};
    use tokio::sync::mpsc::{self, Receiver};
    use tokio::sync::Mutex;
    use tokio::task::JoinSet;

    fn test_setup(
        n: usize,
        t: usize,
        session_id: usize,
    ) -> (
        RanDouShaParams,
        Arc<Mutex<FakeNetwork>>,
        Vec<Receiver<Vec<u8>>>,
    ) {
        let config = FakeNetworkConfig::new(500);
        let (network, receivers) = FakeNetwork::new(n, config);
        let network = Arc::new(Mutex::new(network));
        let params = RanDouShaParams {
            session_id,
            n_parties: n,
            threshold: t,
        };
        (params, network, receivers)
    }

    fn construct_input(
        n: usize,
        degree_t: usize,
    ) -> (
        Fr,
        Vec<ShamirSecretSharing<Fr>>,
        Vec<ShamirSecretSharing<Fr>>,
    ) {
        let mut rng = test_rng();
        let secret = Fr::rand(&mut rng);
        let ids: Vec<Fr> = (1..=n).map(|i| Fr::from(i as u64)).collect();
        let (shares_si_t, _) =
            shamir::ShamirSecretSharing::compute_shares(secret, degree_t, &ids, &mut rng);
        let (shares_si_2t, _) =
            shamir::ShamirSecretSharing::compute_shares(secret, degree_t * 2, &ids, &mut rng);
        (secret, shares_si_t, shares_si_2t)
    }

    // return vec conxtains vecs of inputs for each node
    fn construct_e2e_input(
        n: usize,
        degree_t: usize,
    ) -> (
        Vec<Vec<ShamirSecretSharing<Fr>>>,
        Vec<Vec<ShamirSecretSharing<Fr>>>,
    ) {
        let mut n_shares_t = vec![vec![]; n];
        let mut n_shares_2t = vec![vec![]; n];
        let mut rng = test_rng();
        let ids: Vec<Fr> = (1..=n).map(|i| Fr::from(i as u64)).collect();

        for _ in 0..n {
            let secret = Fr::rand(&mut rng);
            let (shares_si_t, _) =
                shamir::ShamirSecretSharing::compute_shares(secret, degree_t, &ids, &mut rng);
            let (shares_si_2t, _) =
                shamir::ShamirSecretSharing::compute_shares(secret, degree_t * 2, &ids, &mut rng);
            for j in 0..n {
                n_shares_t[j].push(shares_si_t[j]);
                n_shares_2t[j].push(shares_si_2t[j]);
            }
        }

        return (n_shares_t, n_shares_2t);
    }

    fn initialize_node(node_id: usize) -> RanDouShaNode<Fr> {
        RanDouShaNode {
            id: node_id,
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[tokio::test]
    async fn test_init_reconstruct_flow() {
        let n_parties = 10;
        let threshold = 3;
        let session_id = 1111;
        let degree_t = 3;

        let (params, network, mut receivers) = test_setup(n_parties, threshold, session_id);
        let (_, shares_si_t, shares_si_2t) = construct_input(n_parties, degree_t);

        let sender_id = 1;

        let init_msg = InitMessage {
            sender_id: sender_id,
            s_shares_deg_t: shares_si_t.clone(),
            s_shares_deg_2t: shares_si_2t.clone(),
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
                .get(party.id - 1)
                .unwrap()
                .clone()
                .get_or_create_store(&params)
                .await
                .lock()
                .await
                .clone();
            if party.id != sender_id {
                assert!(store.computed_r_shares_degree_t.len() == 0);
                assert!(store.computed_r_shares_degree_2t.len() == 0);
                assert!(store.received_r_shares_degree_t.len() == 0);
                assert!(store.received_r_shares_degree_2t.len() == 0);
                assert!(store.received_ok_msg.len() == 0);
                assert!(store.state == RanDouShaState::Initialized);
            }

            if party.id == sender_id {
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
        let n_parties = 10;
        let threshold = 3;
        let session_id = 1111;
        let degree_t = 3;

        let (params, network, mut receivers) = test_setup(n_parties, threshold, session_id);
        let (_, shares_ri_t, shares_ri_2t) = construct_input(n_parties, degree_t);

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
            let rec_msg = ReconstructionMessage::new(i + 1, shares_ri_t[i], shares_ri_2t[i]);
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
        let n_parties = 10;
        let threshold = 3;
        let session_id = 1111;

        let (params, network, mut receivers) = test_setup(n_parties, threshold, session_id);
        let secret = Fr::from(1234);
        let secret_2t = Fr::from(4321);
        let degree_t = 3;
        let degree_2t = 6;

        let ids: Vec<Fr> = network
            .lock()
            .await
            .parties()
            .iter()
            .map(|p| p.scalar_id())
            .collect();
        // receiver id receives recconstruct messages from other party
        let receiver_id = threshold + 2;

        let mut rng = test_rng();
        // ri_t created by each party i
        let (shares_ri_t, _) =
            shamir::ShamirSecretSharing::compute_shares(secret, degree_t, &ids, &mut rng);
        // ri_2t created by each party i
        let (shares_ri_2t, _) =
            shamir::ShamirSecretSharing::compute_shares(secret_2t, degree_2t, &ids, &mut rng);

        // create receiver randousha node
        let mut randousha_node: RanDouShaNode<Fr> = RanDouShaNode {
            id: receiver_id,
            store: Arc::new(Mutex::new(HashMap::new())),
        };
        // receiver nodes received t+1 ReconstructionMessage
        for i in 0..2 * threshold + 1 {
            let rec_msg = ReconstructionMessage::new(i + 1, shares_ri_t[i], shares_ri_2t[i]);
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
        let n_parties = 10;
        let threshold = 3;
        let session_id = 1111;
        let degree_t = 3;

        let (params, network, receivers) = test_setup(n_parties, threshold, session_id);
        let (_, shares_si_t, shares_si_2t) = construct_input(n_parties, degree_t);
        let receiver_id = 1;

        let init_msg = InitMessage {
            sender_id: receiver_id,
            s_shares_deg_t: shares_si_t.clone(),
            s_shares_deg_2t: shares_si_2t.clone(),
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
            node_store.lock().await.received_ok_msg.len()
                == params.n_parties - (params.threshold + 2)
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
            node_store.lock().await.received_ok_msg.len()
                == params.n_parties - (params.threshold + 2)
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
            node_store.lock().await.received_ok_msg.len()
                == params.n_parties - (params.threshold + 2)
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
            node_store.lock().await.received_ok_msg.len()
                == params.n_parties - (params.threshold + 1)
        );
        assert!(node_store.lock().await.state == RanDouShaState::Finished);
    }

    #[tokio::test]
    async fn randousha_e2e() {
        let n_parties = 10;
        let threshold = 3;
        let session_id = 1111;
        let degree_t = 3;

        let (params, network, mut receivers) = test_setup(n_parties, threshold, session_id);
        let (n_shares_t, n_shares_2t) = construct_e2e_input(params.n_parties, degree_t);

        // create randousha nodes
        let mut randousha_nodes = vec![];
        for i in 1..=n_parties {
            randousha_nodes.push(Arc::new(Mutex::new(initialize_node(i))));
        }
        let mut set: JoinSet<_> = JoinSet::new();
        let (fin_send, mut fin_recv) = mpsc::channel::<(
            usize,
            (Vec<ShamirSecretSharing<Fr>>, Vec<ShamirSecretSharing<Fr>>),
        )>(100);
        // spawn tasks to process received messages
        for i in 1..=n_parties {
            let randosha_node = Arc::clone(&randousha_nodes[i - 1]);
            let network = Arc::clone(&network);
            let mut receiver = receivers.remove(0);
            let fin_send = fin_send.clone();
            set.spawn(async move {
                loop {
                    // println!("get_msg: {}", randosha_node.lock().await.id);
                    let msg = receiver.recv().await.unwrap();
                    let deseralized_msg: RanDouShaMessage =
                        bincode::deserialize(msg.as_slice()).unwrap();
                    let process_result = randosha_node
                        .lock()
                        .await
                        .process(&deseralized_msg, &params, Arc::clone(&network))
                        .await;
                    match process_result {
                        Ok(r) => match r {
                            Some(final_shares) => {
                                fin_send
                                    .send((randosha_node.lock().await.id, final_shares))
                                    .await
                                    .unwrap();
                            }
                            None => continue,
                        },
                        Err(e) => match e {
                            RanDouShaError::NetworkError(network_error) => {
                                panic!("NetWork Error: {}", network_error)
                            }
                            RanDouShaError::ArkSerialization(serialization_error) => {
                                panic!("ArkSerialization Error: {}", serialization_error)
                            }
                            RanDouShaError::ArkDeserialization(serialization_error) => {
                                panic!("ArkDeserialization Error: {}", serialization_error)
                            }
                            RanDouShaError::SerializationError(error_kind) => {
                                panic!("SerializationError Error: {}", error_kind)
                            }
                            RanDouShaError::Abort => {
                                panic!("Abort")
                            }
                            RanDouShaError::WaitForOk => {}
                        },
                    }
                }
            });
        }

        // init all randousha nodes
        for node in &randousha_nodes {
            let mut node_locked = node.lock().await;
            let init_msg = InitMessage {
                sender_id: node_locked.id,
                s_shares_deg_t: n_shares_t[node_locked.id - 1].clone(),
                s_shares_deg_2t: n_shares_2t[node_locked.id - 1].clone(),
            };
            node_locked
                .init_handler(&init_msg, &params, Arc::clone(&network))
                .await
                .unwrap();
        }
        let mut final_results =
            HashMap::<usize, (Vec<ShamirSecretSharing<Fr>>, Vec<ShamirSecretSharing<Fr>>)>::new();
        while let Some((id, final_shares)) = fin_recv.recv().await {
            final_results.insert(id, final_shares);
            if final_results.len() == 10 {
                // check final_shares consist of correct shares
                for (id, (shares_t, shares_2t)) in final_results {
                    let _ = shares_t.iter().zip(shares_2t).map(|(s_t, s_2t)| {
                        assert_eq!(s_t.degree, params.threshold);
                        assert_eq!(s_2t.degree, 2 * params.threshold);
                        assert_eq!(s_t.id, Fr::from(id as u64));
                        assert_eq!(s_2t.id, Fr::from(id as u64));
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
        let n_parties = 10;
        let threshold = 3;
        let session_id = 1111;
        let degree_t = 3;

        let (params, network, mut receivers) = test_setup(n_parties, threshold, session_id);
        let (mut n_shares_t, n_shares_2t) = construct_e2e_input(params.n_parties, degree_t);

        // lets corrupt the shares of party 1 so that the shares reconstruct different values
        let rng = &mut test_rng();
        n_shares_t[0][0] =
            ShamirSecretSharing::new(Fr::rand(rng), n_shares_t[0][0].id, n_shares_t[0][0].degree);

        // create randousha nodes
        let mut randousha_nodes = vec![];
        for i in 1..=n_parties {
            randousha_nodes.push(Arc::new(Mutex::new(initialize_node(i))));
        }

        let mut set: JoinSet<_> = JoinSet::new();
        let (fin_send, mut fin_recv) = mpsc::channel::<(
            usize,
            (Vec<ShamirSecretSharing<Fr>>, Vec<ShamirSecretSharing<Fr>>),
        )>(100);

        // Keep track of aborts
        let abort_count = Arc::new(AtomicUsize::new(0));

        // spawn tasks to process received messages
        for i in 1..=n_parties {
            let randosha_node = Arc::clone(&randousha_nodes[i - 1]);
            let network = Arc::clone(&network);
            let mut receiver = receivers.remove(0);
            let fin_send = fin_send.clone();
            let abort_count_clone = Arc::clone(&abort_count); // Clone for each task

            set.spawn(async move {
                loop {
                    // println!("get_msg: {}", randosha_node.lock().await.id);
                    let msg = receiver.recv().await.unwrap();
                    let deseralized_msg: RanDouShaMessage =
                        bincode::deserialize(msg.as_slice()).unwrap();
                    let process_result = randosha_node
                        .lock()
                        .await
                        .process(&deseralized_msg, &params, Arc::clone(&network))
                        .await;
                    match process_result {
                        Ok(r) => match r {
                            Some(final_shares) => {
                                fin_send
                                    .send((randosha_node.lock().await.id, final_shares))
                                    .await
                                    .unwrap();
                            }
                            None => continue,
                        },
                        Err(e) => match e {
                            RanDouShaError::NetworkError(network_error) => {
                                // we are allowing because Some parties will be dropped because of Abort
                                eprintln!(
                                    "Party {} encountered SendError: {:?}",
                                    randosha_node.lock().await.id,
                                    network_error
                                );
                                continue;
                            }
                            RanDouShaError::ArkSerialization(serialization_error) => {
                                panic!("ArkSerialization Error: {}", serialization_error)
                            }
                            RanDouShaError::ArkDeserialization(serialization_error) => {
                                panic!("ArkDeserialization Error: {}", serialization_error)
                            }
                            RanDouShaError::SerializationError(error_kind) => {
                                panic!("SerializationError Error: {}", error_kind)
                            }
                            RanDouShaError::Abort => {
                                println!(
                                    "RanDouSha Aborted by node {}",
                                    randosha_node.lock().await.id
                                );

                                // Increment the abort counter
                                abort_count_clone.fetch_add(1, Ordering::SeqCst);

                                // break is done so that the party no more processes messages
                                break;
                            }
                            RanDouShaError::WaitForOk => {}
                        },
                    }
                }
            });
        }

        // init all randousha nodes
        for node in &randousha_nodes {
            let mut node_locked = node.lock().await;
            let init_msg = InitMessage {
                sender_id: node_locked.id,
                s_shares_deg_t: n_shares_t[node_locked.id - 1].clone(),
                s_shares_deg_2t: n_shares_2t[node_locked.id - 1].clone(),
            };
            match node_locked
                .init_handler(&init_msg, &params, Arc::clone(&network))
                .await
            {
                Ok(()) => {}
                // Allowing NetworkError because some nodes will be dropped because of Abort
                Err(e) => {
                    if let RanDouShaError::NetworkError(NetworkError::SendError) = e {
                        eprintln!(
                            "Test: Init handler for node {} got expected SendError: {:?}",
                            node_locked.id, e
                        );
                        
                    } else {
                        panic!(
                            "Test: Unexpected error during init_handler for node {}: {:?}",
                            node_locked.id, e
                        );
                    }
                }
            }
        }

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
}
