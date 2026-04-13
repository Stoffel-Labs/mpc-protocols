#![allow(dead_code)]

use ark_bls12_381::Fr;
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

pub fn test_setup(n: usize) -> (Vec<Arc<FakeNetwork>>, Vec<Vec<Receiver<Vec<u8>>>>) {
    let config = FakeNetworkConfig::new(500);
    let (inner, receivers, _) = FakeInnerNetwork::new(n, None, config);
    let network = (0..n)
        .map(|id| Arc::new(FakeNetwork::new(id, inner.clone())))
        .collect();
    (network, receivers)
}

pub fn fan_in_inboxes(
    inboxes: Vec<(SenderId, Receiver<Vec<u8>>)>,
) -> Receiver<(SenderId, Vec<u8>)> {
    let (tx, rx) = mpsc::channel(300);
    for (sender, mut rx_i) in inboxes {
        let tx_i = tx.clone();
        tokio::spawn(async move {
            while let Some(msg) = rx_i.recv().await {
                let _ = tx_i.send((sender, msg)).await;
            }
        });
    }
    rx
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
        Duration::from_secs(60),
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
) {
    for i in 0..nodes.len() {
        let inbox_row = receivers.remove(0);
        let mut node = nodes[i].clone();
        let net = network[i].clone();
        let labeled: Vec<(SenderId, Receiver<Vec<u8>>)> = inbox_row
            .into_iter()
            .enumerate()
            .map(|(j, r)| (SenderId::Node(j), r))
            .collect();
        let mut merged = fan_in_inboxes(labeled);
        tokio::spawn(async move {
            while let Some((sender, raw)) = merged.recv().await {
                let id = match sender {
                    SenderId::Node(i) | SenderId::Client(i) => i,
                };
                let _ = node.process(id, raw, net.clone()).await;
            }
        });
    }
}
