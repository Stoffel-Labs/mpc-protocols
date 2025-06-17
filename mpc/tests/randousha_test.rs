#[cfg(test)]
mod tests {

    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use ark_bls12_381::Fr;
    use ark_std::test_rng;
    use stoffelmpc_common::share::shamir;
    use stoffelmpc_mpc::honeybadger::ran_dou_sha::messages::{
        InitMessage, OutputMessage, RanDouShaMessage, RanDouShaMessageType, ReconstructionMessage,
    };
    use stoffelmpc_mpc::honeybadger::ran_dou_sha::{RanDouShaNode, RanDouShaParams};
    use stoffelmpc_network::fake_network::FakeNetwork;
    use stoffelmpc_network::{Network, Node};

    #[test]
    fn test_init_reconstruct_flow() {
        let n_parties = 10;
        let threshold = 3;
        let session_id = 1111;

        let secret = Fr::from(1234);
        let degree_t = 3;
        let degree_2t = 6;

        let network: FakeNetwork = FakeNetwork::new(n_parties);
        let ids: Vec<Fr> = network.parties().iter().map(|p| p.scalar_id()).collect();
        let sender_id = 1;
        let params = RanDouShaParams {
            session_id,
            n_parties,
            threshold,
        };

        let mut rng = test_rng();
        let (shares_si_t, _) =
            shamir::ShamirSecretSharing::compute_shares(secret, degree_t, &ids, &mut rng);
        let (shares_si_2t, _) =
            shamir::ShamirSecretSharing::compute_shares(secret, degree_2t, &ids, &mut rng);

        let init_msg = InitMessage {
            sender_id: sender_id,
            s_shares_deg_t: shares_si_t.clone(),
            s_shares_deg_2t: shares_si_2t.clone(),
        };

        // This is done because of the following error:
        // error[E0502]: cannot borrow *network_mut as immutable because it is also borrowed as mutable
        // let node_ptr: *mut RanDouShaNode<Fr> = {
        //     let parties = network.parties_mut();
        //     parties.into_iter().find(|n| n.id == sender_id).unwrap() as *mut _
        // };

        // SAFETY:ensure no aliasing occurs by not using `network.parties_mut()` again.
        // let sender_node = unsafe { &mut *node_ptr };
        // sender_node
        //     .init_handler(&init_msg, &params, &network)
        //     .unwrap();

        // create randousha node
        let mut randousha_node: RanDouShaNode<Fr> = RanDouShaNode {
            id: sender_id,
            store: Arc::new(Mutex::new(HashMap::new())),
        };
        randousha_node
            .init_handler(&init_msg, &params, &network)
            .unwrap();

        for party in network.parties() {
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
        }
    }

    #[test]
    fn test_reconstruct_handler() {
        let n_parties = 10;
        let threshold = 3;
        let session_id = 1111;

        let secret = Fr::from(1234);
        let degree_t = 3;
        let degree_2t = 6;

        let network = FakeNetwork::new(n_parties);
        let ids: Vec<Fr> = network.parties().iter().map(|p| p.scalar_id()).collect();
        // receiver id receives recconstruct messages from other party
        let receiver_id = threshold + 2;
        let params = RanDouShaParams {
            session_id,
            n_parties,
            threshold,
        };

        let mut rng = test_rng();
        // ri_t created by each party i
        let (shares_ri_t, _) =
            shamir::ShamirSecretSharing::compute_shares(secret, degree_t, &ids, &mut rng);
        // ri_2t created by each party i
        let (shares_ri_2t, _) =
            shamir::ShamirSecretSharing::compute_shares(secret, degree_2t, &ids, &mut rng);

        // create receiver randousha node
        let mut randousha_node: RanDouShaNode<Fr> = RanDouShaNode {
            id: receiver_id,
            store: Arc::new(Mutex::new(HashMap::new())),
        };
        // receiver nodes received t+1 ReconstructionMessage
        for i in 0..2 * threshold + 1 {
            let rec_msg = ReconstructionMessage::new(i + 1, shares_ri_t[i], shares_ri_2t[i]);
            randousha_node
                .reconstruction_handler(&rec_msg, &params, &network)
                .unwrap();
        }

        // check all parties received OutputMessage Ok sent by the receiver of the ReconstructionMessage
        for party in network.parties() {
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
    }

    #[test]
    fn test_reconstruct_handler_mismatch_r_t_2t() {
        let n_parties = 10;
        let threshold = 3;
        let session_id = 1111;

        let secret = Fr::from(1234);
        let secret_2t = Fr::from(4321);
        let degree_t = 3;
        let degree_2t = 6;

        let network = FakeNetwork::new(n_parties);
        let ids: Vec<Fr> = network.parties().iter().map(|p| p.scalar_id()).collect();
        // receiver id receives recconstruct messages from other party
        let receiver_id = threshold + 2;
        let params = RanDouShaParams {
            session_id,
            n_parties,
            threshold,
        };

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
                .reconstruction_handler(&rec_msg, &params, &network)
                .unwrap();
        }

        // check all parties received OutputMessage Ok sent by the receiver of the ReconstructionMessage
        for party in network.parties() {
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
    }
}
