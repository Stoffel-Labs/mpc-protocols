#[cfg(test)]
mod tests {

    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::vec;

    use ark_bls12_381::Fr;
    use ark_ff::UniformRand;
    use ark_std::test_rng;
    use stoffelmpc_common::share::shamir::{self, ShamirSecretSharing};
    use stoffelmpc_mpc::honeybadger::ran_dou_sha::messages::{
        InitMessage, OutputMessage, RanDouShaMessage, RanDouShaMessageType, ReconstructionMessage,
    };
    use stoffelmpc_mpc::honeybadger::ran_dou_sha::{RanDouShaNode, RanDouShaParams};
    use stoffelmpc_network::fake_network::{FakeNetwork, FakeNetworkConfig};
    use stoffelmpc_network::{Network, Node};

    fn test_setup(
        n: usize,
        t: usize,
        session_id: usize,
    ) -> (RanDouShaParams, Arc<Mutex<FakeNetwork>>) {
        let config = FakeNetworkConfig::new(100);
        let network = Arc::new(Mutex::new(FakeNetwork::new(n, config)));
        let params = RanDouShaParams {
            session_id,
            n_parties: n,
            threshold: t,
        };
        (params, network)
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

        let (params, network) = test_setup(n_parties, threshold, session_id);
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

        for party in network.lock().unwrap().parties_mut() {
            // check only designated parties are receiving messages
            if party.id() > params.threshold + 1 && party.id() <= params.n_parties {
                let received_message = party.receiver_channel.try_recv().unwrap();
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
                assert!(party.receiver_channel.try_recv().is_err());
            }

            // check all stores should be empty except for the sender's store
            let store = randousha_nodes
                .get(party.id - 1)
                .unwrap()
                .clone()
                .get_or_create_store(&params)
                .lock()
                .unwrap()
                .clone();
            if party.id != sender_id {
                assert!(store.computed_r_shares_degree_t.len() == 0);
                assert!(store.computed_r_shares_degree_2t.len() == 0);
                assert!(store.received_r_shares_degree_t.len() == 0);
                assert!(store.received_r_shares_degree_2t.len() == 0);
                assert!(store.received_ok_msg.len() == 0);
            }

            if party.id == sender_id {
                assert!(store.computed_r_shares_degree_t.len() == n_parties);
                assert!(store.computed_r_shares_degree_2t.len() == n_parties);
                assert!(store.received_r_shares_degree_t.len() == 0);
                assert!(store.received_r_shares_degree_2t.len() == 0);
                assert!(store.received_ok_msg.len() == 0);
            }
        }
    }

    #[tokio::test]
    async fn test_reconstruct_handler() {
        let n_parties = 10;
        let threshold = 3;
        let session_id = 1111;
        let degree_t = 3;

        let (params, network) = test_setup(n_parties, threshold, session_id);
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

        // receiver nodes received t+1 ReconstructionMessage
        for i in 0..2 * threshold + 1 {
            let rec_msg = ReconstructionMessage::new(i + 1, shares_ri_t[i], shares_ri_2t[i]);
            randousha_node
                .reconstruction_handler(&rec_msg, &params, Arc::clone(&network))
                .await
                .unwrap();
        }

        // check all parties received OutputMessage Ok sent by the receiver of the ReconstructionMessage
        for party in network.lock().unwrap().parties_mut() {
            let received_message = party.receiver_channel.try_recv().unwrap();
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
            .lock()
            .unwrap()
            .clone();
        assert!(store.received_r_shares_degree_t.len() == 2 * threshold + 1);
        assert!(store.received_r_shares_degree_2t.len() == 2 * threshold + 1);
        assert!(store.received_ok_msg.len() == 0);
    }

    #[tokio::test]
    async fn test_reconstruct_handler_mismatch_r_t_2t() {
        let n_parties = 10;
        let threshold = 3;
        let session_id = 1111;

        let (params, network) = test_setup(n_parties, threshold, session_id);
        let secret = Fr::from(1234);
        let secret_2t = Fr::from(4321);
        let degree_t = 3;
        let degree_2t = 6;

        let ids: Vec<Fr> = network
            .lock()
            .unwrap()
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
        for party in network.lock().unwrap().parties_mut() {
            let received_message = party.receiver_channel.try_recv().unwrap();
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
            .lock()
            .unwrap()
            .clone();
        assert!(store.received_r_shares_degree_t.len() == 2 * threshold + 1);
        assert!(store.received_r_shares_degree_2t.len() == 2 * threshold + 1);
        assert!(store.received_ok_msg.len() == 0);
    }
}
