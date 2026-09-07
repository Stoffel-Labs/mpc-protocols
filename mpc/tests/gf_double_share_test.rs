pub mod utils;

use crate::utils::test_utils::{fan_in_inboxes, setup_tracing, test_setup};
use std::{collections::HashMap, time::Duration};
use stoffelcrypto::{
    common::{
        gf2k::{field::Gf256, share::GfShare},
        ProtocolSessionId,
    },
    honeybadger::{
        gf_double_share::gf_double_share_generation::GfDoubleShareNode, ProtocolType, SessionId,
        WrappedMessage,
    },
};
use stoffelmpc_network::fake_network::SenderId;
use tokio::sync::mpsc;
use tokio::time::timeout;

#[tokio::test]
async fn test_gf_double_share_e2e() {
    setup_tracing();
    let n_parties = 5;
    let threshold = 2;
    let session_id = SessionId::new(ProtocolType::GfDousha, SessionId::pack_slot(123, 0, 0), 111);

    let (network, receivers, _, _) = test_setup(n_parties, vec![]);
    let mut rng = ark_std::test_rng();

    let nodes: Vec<GfDoubleShareNode<Gf256>> = (0..n_parties)
        .map(|i| GfDoubleShareNode::new(i, n_parties, threshold))
        .collect();

    let (final_result_sender, mut final_result_receiver) = mpsc::channel(1024);

    for (i, receiver) in receivers.into_iter().enumerate() {
        let mut node = nodes[i].clone();
        let inbox: Vec<(SenderId, tokio::sync::mpsc::Receiver<Vec<u8>>)> = receiver
            .into_iter()
            .enumerate()
            .map(|(j, r)| (SenderId::Node(j), r))
            .collect();
        let mut merged_rx = fan_in_inboxes(inbox);
        let sender = final_result_sender.clone();

        tokio::spawn(async move {
            let node_store = node
                .get_or_create_store(session_id, node.id)
                .await
                .unwrap();
            loop {
                {
                    let store = node_store.lock().await;
                    if !store.protocol_output.is_empty() {
                        break;
                    }
                }
                let (_from, raw) = match timeout(Duration::from_secs(2), merged_rx.recv()).await {
                    Ok(Some(v)) => v,
                    _ => continue,
                };
                let wrapped: WrappedMessage = match bincode::deserialize(&raw) {
                    Ok(w) => w,
                    Err(_) => continue,
                };
                if let WrappedMessage::GfDousha(msg) = wrapped {
                    let _ = node.process(msg).await;
                }
            }
            let store = node_store.lock().await;
            let _ = sender.send((node.id, store.protocol_output.clone())).await;
        });
    }

    for (i, node) in nodes.iter().enumerate() {
        let mut node = node.clone();
        node.init(session_id, &mut rng, network[i].clone())
            .await
            .unwrap();
    }

    let mut resulting_shares = HashMap::new();
    while let Some((id, shares)) = final_result_receiver.recv().await {
        resulting_shares.insert(id, shares);
        if resulting_shares.len() == n_parties {
            for (id, final_double_shares) in &resulting_shares {
                assert_eq!(final_double_shares.len(), n_parties);
                for double_share in final_double_shares {
                    assert_eq!(*id, double_share.degree_t.id);
                    assert_eq!(*id, double_share.degree_2t.id);
                    assert_eq!(double_share.degree_t.degree, threshold);
                    assert_eq!(double_share.degree_2t.degree, 2 * threshold);
                }
            }
            break;
        }
    }

    // For each dealer i, the degree-t and degree-2t sharings must be of the SAME secret (this
    // is exactly the property RanDouSha's checksum later verifies — here we confirm the raw
    // dealing already produces consistent pairs in the honest case).
    for i in 0..n_parties {
        let shares_t: Vec<_> = resulting_shares
            .values()
            .map(|shares| shares[i].degree_t.clone())
            .collect();
        let shares_2t: Vec<_> = resulting_shares
            .values()
            .map(|shares| shares[i].degree_2t.clone())
            .collect();

        let secret_t = GfShare::recover_secret_naive(&shares_t, n_parties, threshold);
        let secret_2t = GfShare::recover_secret_naive(&shares_2t, n_parties, threshold);

        assert_eq!(secret_t.unwrap().1, secret_2t.unwrap().1, "Mismatch for secret {i}");
    }
}
