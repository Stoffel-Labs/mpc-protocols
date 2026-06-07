#![allow(dead_code)]

use ark_bls12_381::Fr;
use std::env;
use std::sync::Arc;
use std::time::Duration;
use stoffelmpc_mpc::common::{rbc::rbc::Avid, MPCProtocol};
use stoffelmpc_mpc::honeybadger::{
    robust_interpolate::robust_interpolate::RobustShare, HoneyBadgerMPCNode,
    HoneyBadgerMPCNodeOpts, SessionId,
};
use stoffelmpc_network::fake_network::{
    FakeInnerNetwork, FakeNetwork, FakeNetworkConfig, SenderId,
};
use tokio::sync::mpsc::{self, Receiver};
use tokio::task::JoinHandle;

const BENCH_CHANNEL_BUFFER: usize = 262_144;

pub fn test_setup(n: usize) -> (Vec<Arc<FakeNetwork>>, Vec<Vec<Receiver<Vec<u8>>>>) {
    let config = FakeNetworkConfig::new(BENCH_CHANNEL_BUFFER);
    let (inner, receivers, _) = FakeInnerNetwork::new(n, None, config);
    let network = (0..n)
        .map(|id| Arc::new(FakeNetwork::new(id, inner.clone())))
        .collect();
    (network, receivers)
}

pub fn fan_in_inboxes(
    inboxes: Vec<(SenderId, Receiver<Vec<u8>>)>,
) -> (Receiver<(SenderId, Vec<u8>)>, Vec<JoinHandle<()>>) {
    let (tx, rx) = mpsc::channel(BENCH_CHANNEL_BUFFER);
    let mut handles = Vec::with_capacity(inboxes.len());
    for (sender, mut rx_i) in inboxes {
        let tx_i = tx.clone();
        handles.push(tokio::spawn(async move {
            while let Some(msg) = rx_i.recv().await {
                let _ = tx_i.send((sender, msg)).await;
            }
        }));
    }
    (rx, handles)
}

pub fn create_nodes(
    n_parties: usize,
    t: usize,
    n_triples: usize,
    n_shares: usize,
    n_prandbit: usize,
    n_prandint: usize,
    instance_id: u32,
) -> Vec<HoneyBadgerMPCNode<Fr, Avid<SessionId>>> {
    let timeout = env::var("HMPC_BENCH_TIMEOUT_SECS")
        .ok()
        .and_then(|secs| secs.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(60));

    let opts = HoneyBadgerMPCNodeOpts::new(
        n_parties,
        t,
        n_triples,
        n_shares,
        instance_id,
        n_prandbit,
        n_prandint,
        8,
        4,
        timeout,
    )
    .unwrap();

    (0..n_parties)
        .map(|id| {
            <HoneyBadgerMPCNode<Fr, Avid<SessionId>> as MPCProtocol<
                Fr,
                RobustShare<Fr>,
                FakeNetwork,
            >>::setup(id, opts.clone(), vec![])
            .unwrap()
        })
        .collect()
}

pub fn spawn_receivers(
    mut receivers: Vec<Vec<Receiver<Vec<u8>>>>,
    nodes: Vec<HoneyBadgerMPCNode<Fr, Avid<SessionId>>>,
    network: Vec<Arc<FakeNetwork>>,
) -> Vec<JoinHandle<()>> {
    let mut handles = Vec::new();
    for i in 0..nodes.len() {
        let inbox_row = receivers.remove(0);
        let mut node = nodes[i].clone();
        let net = network[i].clone();
        let labeled: Vec<(SenderId, Receiver<Vec<u8>>)> = inbox_row
            .into_iter()
            .enumerate()
            .map(|(j, r)| (SenderId::Node(j), r))
            .collect();
        let (mut merged, mut fan_in_handles) = fan_in_inboxes(labeled);
        handles.append(&mut fan_in_handles);
        handles.push(tokio::spawn(async move {
            while let Some((sender, raw)) = merged.recv().await {
                let id = match sender {
                    SenderId::Node(i) | SenderId::Client(i) => i,
                };
                let _ = node.process(id, raw, net.clone()).await;
            }
        }));
    }
    handles
}
