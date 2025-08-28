use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_std::test_rng;
use std::sync::Arc;
use stoffelmpc_mpc::{
    common::{share::shamir::NonRobustShare, SecretSharingScheme},
    honeybadger::{
        double_share::DoubleShamirShare,
        robust_interpolate::robust_interpolate::RobustShare,
        triple_gen::{triple_generation::TripleGenNode},
        SessionId, WrappedMessage,
    },
};
use stoffelmpc_network::fake_network::FakeNetwork;
use tokio::sync::mpsc::{self, Receiver};
use tokio::sync::Mutex;
use tracing::{debug, warn};

pub fn create_nodes(
    n_parties: usize,
    threshold: usize,
) -> (Vec<Arc<Mutex<TripleGenNode<Fr>>>>, Vec<Receiver<SessionId>>) {
    let mut receivers = vec![];
    let triple_gen_nodes = (0..n_parties)
        .map(|id| {
            let (triple_sender, triple_receiver) = mpsc::channel(128);
            let triple_gen_node =
                TripleGenNode::new(id, n_parties, threshold, triple_sender).unwrap();
            receivers.push(triple_receiver);
            Arc::new(Mutex::new(triple_gen_node))
        })
        .collect();
    (triple_gen_nodes, receivers)
}

// Return vectors that contain vectors of inputs of init_handler for each node
pub fn get_triple_init_test_shares(
    n_shares: usize,
    n_parties: usize,
    t: usize,
) -> (
    Vec<Vec<RobustShare<Fr>>>,
    Vec<Vec<RobustShare<Fr>>>,
    Vec<Vec<DoubleShamirShare<Fr>>>,
    Vec<Fr>,
    Vec<Fr>,
    Vec<Fr>,
) {
    let mut random_shares_a = vec![vec![]; n_parties];
    let mut random_shares_b = vec![vec![]; n_parties];
    let mut randousha_pairs = vec![vec![]; n_parties];
    let mut a_values = vec![];
    let mut b_values = vec![];
    let mut pairs_values = vec![];

    let mut rng = test_rng();

    for _ in 0..n_shares {
        // gen share of a_i, b_i for n parties
        let a = Fr::rand(&mut rng);
        a_values.push(a);
        let shares_a = RobustShare::compute_shares(a, n_parties, t, None, &mut rng).unwrap();
        let b = Fr::rand(&mut rng);
        b_values.push(b);
        let shares_b = RobustShare::compute_shares(b, n_parties, t, None, &mut rng).unwrap();

        let r = Fr::rand(&mut rng);
        pairs_values.push(r);

        let ids: Vec<usize> = (1..=n_parties).collect();
        let shares_r_t =
            NonRobustShare::compute_shares(r, n_parties, t, Some(&ids), &mut rng).unwrap();
        let shares_r_2t =
            NonRobustShare::compute_shares(r, n_parties, 2 * t, Some(&ids), &mut rng).unwrap();

        for p in 0..n_parties {
            random_shares_a[p].push(shares_a[p].clone());
            random_shares_b[p].push(shares_b[p].clone());
            randousha_pairs[p].push(DoubleShamirShare::new(
                shares_r_t[p].clone(),
                shares_r_2t[p].clone(),
            ));
        }
    }
    (
        random_shares_a,
        random_shares_b,
        randousha_pairs,
        a_values,
        b_values,
        pairs_values,
    )
}

/// Spawns receiver tasks for all nodes.
///
/// In the case of a SendError, we log the error and continue because of the expected Abort behaviour
/// In the case of Abort, the node is dropped from the network and the task is cancelled
/// For the rest of the errors, we panic
pub fn spawn_receiver_tasks(
    nodes: &[Arc<Mutex<TripleGenNode<Fr>>>],
    mut receivers: Vec<Receiver<Vec<u8>>>,
    network: Arc<FakeNetwork>,
) {
    for node in nodes {
        let triple_gen_node = Arc::clone(&node);
        let mut receiver = receivers.remove(0);

        let net_clone = Arc::clone(&network);
        // spawn tasks to process received messages
        tokio::spawn(async move {
            loop {
                let msg = match receiver.recv().await {
                    Some(msg) => msg,
                    None => break,
                };
                let wrapped: WrappedMessage = match bincode::deserialize(&msg) {
                    Ok(m) => m,
                    Err(_) => {
                        warn!("Malformed or unrecognized message format.");
                        continue;
                    }
                };
                let mut node_bind = triple_gen_node.lock().await;

                match wrapped {
                    WrappedMessage::BatchRecon(batch_msg) => {
                        node_bind
                            .batch_recon_node
                            .process(batch_msg, net_clone.clone())
                            .await
                            .unwrap();
                    }
                    WrappedMessage::Triple(triple_gen_msg) => {
                        debug!("Received triple_gen_msg");
                        node_bind.process(triple_gen_msg).await.unwrap();
                    }
                    _ => {
                        warn!("received invalid msg type");
                        break;
                    }
                }
            }
        });
    }
}
