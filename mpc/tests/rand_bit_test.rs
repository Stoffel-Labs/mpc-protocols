use crate::utils::rand_bit_utils::{create_rand_bit_input, spawn_receiver_tasks};
use crate::utils::test_utils::{setup_tracing, test_setup};
use ark_ff::{AdditiveGroup, Field};
use std::time::Duration;
use stoffelmpc_mpc::common::math::goldilocks::GoldilocksField;
use stoffelmpc_mpc::common::rbc::rbc::Avid;
use stoffelmpc_mpc::common::{ProtocolSessionId, SecretSharingScheme};
use stoffelmpc_mpc::honeybadger::fpmul::rand_bit::RandBit;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::{ProtocolType, SessionId};
use tokio::task::JoinSet;

mod utils;

#[tokio::test]
async fn rand_bit_with_small_field_e2e() {
    setup_tracing();

    let num_parties = 5;
    let threshold = 1;
    let batch_size = threshold + 1;
    let duration = Duration::from_secs(10);

    let session_id = SessionId::new(
        ProtocolType::RandBit,
        SessionId::pack_slot24(123, 0, 0),
        111,
    );

    // === Build fake network ===
    let (network, receivers, _, _) = test_setup(num_parties, vec![]);

    // === Create RandBit nodes ===
    let nodes: Vec<RandBit<GoldilocksField, Avid<SessionId>>> = (0..num_parties)
        .map(|i| RandBit::new(i, num_parties, threshold).unwrap())
        .collect();

    // === Create protocol inputs ===
    let (a_shares, mult_triples) =
        create_rand_bit_input::<GoldilocksField>(num_parties, threshold, batch_size);

    // === Spawn receiver tasks ===
    let _receiver_tasks_set =
        spawn_receiver_tasks(num_parties, receivers, nodes.clone(), network.clone()).await;

    let mut set = JoinSet::new();
    for node in &nodes {
        let id = node.id;
        set.spawn({
            let a_share = a_shares[id].clone();
            let mult_triple = mult_triples[id].clone();
            let session_id = session_id.clone();
            let network = network[id].clone();
            let mut node = node.clone();
            async move {
                node.init(a_share, mult_triple, session_id, duration, network)
                    .await
                    .unwrap()
            }
        });
    }

    while let Some(result) = set.join_next().await {
        result.unwrap();
    }

    // Allow protocol to finish
    tokio::time::sleep(Duration::from_millis(200)).await;

    // === Collect outputs ===
    let mut all_outputs = Vec::new();

    for node in &nodes {
        let store = node.get_or_create_storage(session_id).await.unwrap();
        let id = node.id;
        let s = store.lock().await;

        assert!(
            s.protocol_output.is_some(),
            "Node {} missing RandBit output",
            id
        );

        let out = s.protocol_output.clone().unwrap();
        assert_eq!(out.len(), batch_size);

        all_outputs.push(out);
    }

    for j in 0..batch_size {
        let mut shares = Vec::new();
        for i in 0..num_parties {
            shares.push(all_outputs[i][j].clone());
        }
        let (_, bit) = RobustShare::recover_secret(&shares, num_parties, threshold).unwrap();
        assert!(
            bit == GoldilocksField::ZERO || bit == GoldilocksField::ONE,
            "Invalid RandBit output: {:?}",
            bit
        );
    }
}
