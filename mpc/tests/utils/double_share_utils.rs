use std::{
    collections::HashMap,
    sync::{atomic::AtomicUsize, mpsc, Arc},
};

use ark_bls12_381::Fr;
use ark_std::test_rng;
use stoffelmpc_mpc::honeybadger::{
    double_share_generation::{DouShaMessage, DouShaParams, DoubleShareNode, ProtocolState},
    DoubleShamirShare,
};
use stoffelmpc_network::fake_network::{FakeNetwork, FakeNetworkConfig};
use tokio::sync::{mpsc::Sender, Mutex};
use tokio::{sync::mpsc::Receiver, task::JoinSet};
use tracing::error;

pub fn test_setup(
    n_parties: usize,
    threshold: usize,
    session_id: usize,
) -> (DouShaParams, Arc<FakeNetwork>, Vec<Receiver<Vec<u8>>>) {
    let config = FakeNetworkConfig::new(500);
    let (network, receivers) = FakeNetwork::new(n_parties, config);
    let network = Arc::new(network);
    let params = DouShaParams {
        session_id,
        n_parties,
        threshold,
    };
    (params, network, receivers)
}

/// Initializes all RanDouSha nodes and returns them wrapped in `Arc<Mutex<_>>`.
pub fn create_nodes(n_parties: usize) -> Vec<Arc<Mutex<DoubleShareNode<Fr>>>> {
    (1..=n_parties)
        .map(|id| Arc::new(Mutex::new(DoubleShareNode::new(id))))
        .collect()
}

/// Spawns receiver tasks for all nodes.
///
/// In the case of a SendError, we log the error and continue because of the expected Abort behaviour
/// In the case of Abort, the node is dropped from the network and the task is cancelled
/// For the rest of the errors, we panic
pub fn spawn_receiver_tasks(
    nodes: &[Arc<Mutex<DoubleShareNode<Fr>>>],
    mut receivers: Vec<Receiver<Vec<u8>>>,
    params: &DouShaParams,
    network: Arc<FakeNetwork>,
    final_result_data_chan: Sender<(usize, Vec<DoubleShamirShare<Fr>>)>,
) {
    for node in nodes {
        let dousha_node = Arc::clone(&node);
        let mut receiver = receivers.remove(0);

        let params = params.clone();
        let network = Arc::clone(&network);
        let final_result_data_chan = final_result_data_chan.clone();

        // Keep track of aborts
        let mut rng = test_rng();

        // spawn tasks to process received messages
        tokio::spawn(async move {
            loop {
                let msg = match receiver.recv().await {
                    Some(msg) => msg,
                    None => break,
                };
                let deserialized_msg: DouShaMessage = bincode::deserialize(&msg).unwrap();
                let result = dousha_node
                    .lock()
                    .await
                    .proccess(&params, &deserialized_msg, &mut rng, Arc::clone(&network))
                    .await;

                match result {
                    Ok(_) => {
                        let dousha_node_lock = dousha_node.lock().await;
                        let storage_lock = dousha_node_lock.storage.lock().await;
                        let node_storage =
                            storage_lock.get(&params.session_id).unwrap().lock().await;
                        if node_storage.state == ProtocolState::Finished {
                            let resulting_double_shares = node_storage.shares.clone();
                            final_result_data_chan
                                .send((dousha_node_lock.id, resulting_double_shares))
                                .await
                                .unwrap();
                        }
                    }
                    Err(e) => {
                        error!("Encountered an error: {:?}", e);
                    }
                }
            }
        });
    }
}
