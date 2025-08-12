use ark_bls12_381::Fr;
use std::sync::Arc;
use stoffelmpc_mpc::honeybadger::double_share::{
    double_share_generation::{DoubleShareNode, ProtocolState},
    DouShaMessage, DoubleShamirShare,
};
use stoffelmpc_mpc::honeybadger::SessionId;
use tokio::sync::mpsc::Receiver;
use tokio::sync::{mpsc::Sender, Mutex};
use tracing::error;

/// Initializes all RanDouSha nodes and returns them wrapped in `Arc<Mutex<_>>`.
pub fn create_nodes(
    n_parties: usize,
    threshold: usize,
    senders: Vec<Sender<SessionId>>,
) -> Vec<Arc<Mutex<DoubleShareNode<Fr>>>> {
    (0..n_parties)
        .zip(senders.into_iter())
        .map(|(id, sender)| {
            Arc::new(Mutex::new(DoubleShareNode::new(
                id, n_parties, threshold, sender,
            )))
        })
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
    final_result_data_chan: Sender<(usize, Vec<DoubleShamirShare<Fr>>)>,
) {
    for node in nodes {
        let dousha_node = Arc::clone(&node);
        let mut receiver = receivers.remove(0);

        let final_result_data_chan = final_result_data_chan.clone();

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
                    .proccess(deserialized_msg.clone())
                    .await;

                match result {
                    Ok(_) => {
                        let dousha_node_lock = dousha_node.lock().await;
                        let storage_lock = dousha_node_lock.storage.lock().await;
                        let node_storage = storage_lock
                            .get(&deserialized_msg.session_id)
                            .unwrap()
                            .lock()
                            .await;
                        if node_storage.state == ProtocolState::Finished {
                            let resulting_double_shares = node_storage.protocol_output.clone();
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
