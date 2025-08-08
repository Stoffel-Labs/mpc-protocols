use crate::utils::test_utils::{
    construct_e2e_input_ransha, create_global_nodes, setup_tracing, test_setup,
};
use ark_bls12_381::Fr;
use ark_serialize::CanonicalSerialize;
use ark_std::test_rng;
use std::sync::Arc;
use stoffelmpc_mpc::{
    common::{rbc::rbc::Avid, SecretSharingScheme, RBC},
    honeybadger::{
        robust_interpolate::robust_interpolate::RobustShamirShare,
        share_gen::{
            share_gen::RanShaNode, RanShaError, RanShaMessage, RanShaMessageType, RanShaPayload,
            RanShaState,
        },
        ProtocolType, SessionId, WrappedMessage,
    },
};
use tokio::task::JoinSet;
use tracing::warn;

pub mod utils;

#[tokio::test]
async fn test_reconstruct_handler_incorrect_share() {
    setup_tracing();
    let n_parties = 10;
    let t = 3;
    let session_id = SessionId::new(ProtocolType::Ransha, 1111);

    let (network, mut receivers, _) = test_setup(n_parties, vec![]);
    let secret = Fr::from(1234);
    let degree_t = 3;

    // receiver id receives recconstruct messages from other party
    let receiver_id = t + 2;

    let mut rng = test_rng();
    // ri_t created by each party i
    let mut shares_ri_t =
        RobustShamirShare::compute_shares(secret, n_parties, degree_t, None, &mut rng).unwrap();

    // Set the corruption indices
    let corruption_indices = [0, 1, 3, 4]; // Corrupt 4 shares, which is > t=3

    // Corrupt more than t shares
    for &i in &corruption_indices {
        shares_ri_t[i].share[0] += Fr::from(7u64);
    }
    // create global nodes
    let nodes = create_global_nodes::<Fr, Avid>(n_parties, t, t + 1);

    // receiver randousha node
    let mut ransha_node = nodes.get(receiver_id).unwrap().clone();

    for i in 0..n_parties {
        let mut bytes_rec_message = Vec::new();
        shares_ri_t[i]
            .clone()
            .serialize_compressed(&mut bytes_rec_message)
            .map_err(RanShaError::ArkSerialization)
            .unwrap();
        let message = RanShaMessage::new(
            i,
            RanShaMessageType::ReconstructMessage,
            session_id,
            RanShaPayload::Reconstruct(bytes_rec_message),
        );

        ransha_node
            .preprocessing
            .share_gen
            .reconstruction_handler(message, Arc::clone(&network))
            .await
            .unwrap();
    }

    // check all parties received OutputMessage Ok sent by the receiver of the ReconstructionMessage
    let mut set = JoinSet::new();
    for i in 0..n_parties {
        let mut receiver = receivers.remove(0);
        let ransha_node = nodes[i].clone();
        let net = Arc::clone(&network);

        set.spawn(async move {
            while let Some(received) = receiver.recv().await {
                let wrapped: WrappedMessage = match bincode::deserialize(&received) {
                    Ok(w) => w,
                    Err(_) => continue,
                };
                match wrapped {
                    WrappedMessage::RanSha(msg) => {
                        if msg.msg_type == RanShaMessageType::OutputMessage {
                            assert_eq!(msg.sender_id, receiver_id);
                            assert!(matches!(msg.payload, RanShaPayload::Output(false)));
                            return;
                        }
                    }
                    WrappedMessage::Rbc(msg) => {
                        if let Err(e) = ransha_node
                            .preprocessing
                            .share_gen
                            .rbc
                            .process(msg, Arc::clone(&net))
                            .await
                        {
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
    let store = ransha_node
        .preprocessing
        .share_gen
        .get_or_create_store(session_id)
        .await
        .lock()
        .await
        .clone();
    assert_eq!(store.received_r_shares.len(), n_parties);
    assert_eq!(store.received_ok_msg.len(), 0);
    assert_eq!(store.state, RanShaState::Reconstruction);
}

#[tokio::test]
async fn test_output_handler() {
    setup_tracing();
    let n_parties = 10;
    let threshold = 3;
    let session_id = SessionId::new(ProtocolType::Ransha, 1111);
    let degree_t = 3;

    let (network, _receivers, _) = test_setup(n_parties, vec![]);
    let (_, shares_si_t) = construct_e2e_input_ransha(n_parties, degree_t);
    let receiver_id = 1;

    // create receiver randousha node
    let mut ransha_node: RanShaNode<Fr, Avid> =
        RanShaNode::new(receiver_id, n_parties, threshold, threshold + 1).unwrap();
    // call init_handler to create random share
    ransha_node
        .init(
            shares_si_t[receiver_id].clone(),
            session_id,
            Arc::clone(&network),
        )
        .await
        .unwrap();

    let node_store = ransha_node.get_or_create_store(session_id).await;

    // first n-(t+1)-1 message should return error
    for i in 0..(n_parties - 2 * threshold - 1) {
        let output_message = RanShaMessage::new(
            i,
            RanShaMessageType::OutputMessage,
            session_id,
            RanShaPayload::Output(true),
        );
        let result = ransha_node.output_handler(output_message).await;
        let e = result.expect_err("should return waitForOk");
        assert_eq!(e.to_string(), RanShaError::WaitForOk.to_string());
    }
    // check the store (n-(t+1)-1 shares)
    assert!(node_store.lock().await.received_ok_msg.len() == (n_parties - 2 * threshold - 1));

    // existed id should not be counted
    let output_message = RanShaMessage::new(
        1,
        RanShaMessageType::OutputMessage,
        session_id,
        RanShaPayload::Output(true),
    );
    let e = ransha_node
        .output_handler(output_message)
        .await
        .expect_err("should return waitForOk");
    assert_eq!(e.to_string(), RanShaError::WaitForOk.to_string());
    assert!(node_store.lock().await.received_ok_msg.len() == (n_parties - 2 * threshold - 1));

    // should return abort once received false outputMessage
    let output_message = RanShaMessage::new(
        1,
        RanShaMessageType::OutputMessage,
        session_id,
        RanShaPayload::Output(false),
    );
    let e = ransha_node
        .output_handler(output_message)
        .await
        .expect_err("should return abort");
    assert_eq!(e.to_string(), RanShaError::Abort.to_string());
    assert!(node_store.lock().await.received_ok_msg.len() == (n_parties - 2 * threshold - 1));

    let output_message = RanShaMessage::new(
        n_parties,
        RanShaMessageType::OutputMessage,
        session_id,
        RanShaPayload::Output(true),
    );
    let v = ransha_node
        .output_handler(output_message)
        .await
        .expect("should return vec");

    assert!(v.len() == threshold + 1);
    for share_t1 in v {
        assert!(share_t1.degree == threshold);
    }
    assert!(node_store.lock().await.received_ok_msg.len() == (n_parties - 2 * threshold));
    assert!(node_store.lock().await.state == RanShaState::Finished);
}
