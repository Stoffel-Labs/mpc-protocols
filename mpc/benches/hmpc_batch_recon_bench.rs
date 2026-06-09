#[path = "bench_utils.rs"]
mod bench_utils;

use ark_bls12_381::Fr;
use bench_utils::{fan_in_inboxes, test_setup};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::time::Duration;
use stoffelmpc_mpc::{
    common::ProtocolSessionId,
    honeybadger::{
        batch_recon::batch_recon::BatchReconNode,
        robust_interpolate::robust_interpolate::RobustShare, ProtocolType, SessionId,
        WrappedMessage,
    },
};
use stoffelmpc_network::fake_network::SenderId;
use tokio::sync::mpsc::Receiver;
use tokio::time::timeout;

async fn run_batch_recon(n_parties: usize, t: usize, n_secrets: usize) {
    // n_secrets must equal t+1 (the batch size)
    let (network, mut receivers) = test_setup(n_parties);
    let session_id = SessionId::new(ProtocolType::BatchRecon, SessionId::pack_slot(0, 0, 0), 1);

    // Generate independent shares for each secret
    let mut rng = ark_std::test_rng();
    let secrets: Vec<Fr> = (0..n_secrets).map(|i| Fr::from(i as u64 + 1)).collect();
    let all_shares = {
        use stoffelmpc_mpc::common::SecretSharingScheme;
        let mut per_node = vec![Vec::new(); n_parties];
        for &secret in &secrets {
            let shares = RobustShare::compute_shares(secret, n_parties, t, None, &mut rng).unwrap();
            for pid in 0..n_parties {
                per_node[pid].push(shares[pid].clone());
            }
        }
        per_node
    };

    let mut handles = Vec::new();
    for i in 0..n_parties {
        let (tx, _rx) = tokio::sync::mpsc::channel(200);
        let mut node = BatchReconNode::<Fr>::new(i, n_parties, t, t, tx).unwrap();
        let shares = all_shares[i].clone();
        let net = network[i].clone();
        let inbox_row = receivers[i].drain(..).collect::<Vec<_>>();
        let labeled: Vec<(SenderId, Receiver<Vec<u8>>)> = inbox_row
            .into_iter()
            .enumerate()
            .map(|(j, r)| (SenderId::Node(j), r))
            .collect();
        let mut merged = fan_in_inboxes(labeled);

        handles.push(tokio::spawn(async move {
            node.init_batch_reconstruct(&shares, session_id, net.clone())
                .await
                .expect("init failed");

            let session_store = node.get_or_create_store(session_id, node.id).await.unwrap().unwrap();

            while {
                let s = session_store.lock().await;
                s.secrets.is_none()
            } {
                let (_from, raw) = match timeout(Duration::from_secs(30), merged.0.recv()).await {
                    Ok(Some(v)) => v,
                    _ => continue,
                };
                if let Ok(WrappedMessage::BatchRecon(m)) = bincode::deserialize(&raw) {
                    node.process(m, net.clone()).await.ok();
                }
            }
        }));
    }

    futures::future::join_all(handles).await;
}

fn bench_batch_recon(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    // (n_parties, t) — n_secrets is always t+1
    let params: &[(usize, usize)] = &[(4, 1), (7, 2), (10, 3), (13, 4)];

    let mut group = c.benchmark_group("batch_recon");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(60));

    for &(n, t) in params {
        group.bench_with_input(
            BenchmarkId::new("protocol", format!("n{n}_t{t}_secrets{}", t + 1)),
            &(n, t),
            |b, &(n, t)| b.to_async(&rt).iter(|| run_batch_recon(n, t, t + 1)),
        );
    }

    group.finish();
}

criterion_group!(benches, bench_batch_recon);
criterion_main!(benches);
