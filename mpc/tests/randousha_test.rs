#[cfg(test)]
mod tests {

    use ark_bls12_381::Fr;
    use ark_std::test_rng;
    use stoffelmpc_common::share::shamir;
    use stoffelmpc_mpc::honeybadger::ran_dou_sha::messages::{
        InitMessage, RanDouShaMessage, RanDouShaMessageType, ReconstructionMessage,
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

        let mut network: FakeNetwork<RanDouShaNode<Fr>> = FakeNetwork::new(n_parties);
        let ids: Vec<Fr> = network.parties().iter().map(|p| p.scalar_id()).collect();
        let sender_id = 0;
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
        let node_ptr: *mut RanDouShaNode<Fr> = {
            let parties = network.parties_mut();
            parties.into_iter().find(|n| n.id == sender_id).unwrap() as *mut _
        };

        // SAFETY:ensure no aliasing occurs by not using `network.parties_mut()` again.
        let sender_node = unsafe { &mut *node_ptr };
        sender_node
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
}
