use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_std::test_rng;
use once_cell::sync::Lazy;
use std::{sync::atomic::AtomicUsize, sync::atomic::Ordering, sync::Arc, vec};
use stoffelmpc_mpc::common::rbc::rbc::Avid;
use stoffelmpc_mpc::common::share::shamir::NonRobustShare;
use stoffelmpc_mpc::common::{SecretSharingScheme, RBC};
use stoffelmpc_mpc::honeybadger::WrappedMessage;
use tracing::warn;

use stoffelmpc_mpc::honeybadger::ran_dou_sha::{RanDouShaError, RanDouShaNode};
use stoffelmpc_network::fake_network::{FakeNetwork, FakeNetworkConfig};
use stoffelmpc_network::{NetworkError, SessionId};
use tokio::sync::mpsc::{self, Receiver};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::FmtSubscriber;

pub fn test_setup(n: usize) -> (Arc<FakeNetwork>, Vec<Receiver<Vec<u8>>>) {
    let config = FakeNetworkConfig::new(500);
    let (network, receivers) = FakeNetwork::new(n, config);
    let network = Arc::new(network);
    (network, receivers)
}

pub fn get_reconstruct_input(
    n: usize,
    degree_t: usize,
) -> (Fr, Vec<NonRobustShare<Fr>>, Vec<NonRobustShare<Fr>>) {
    let mut rng = test_rng();
    let secret = Fr::rand(&mut rng);
    let ids: Vec<usize> = (1..=n).collect();
    let shares_si_t =
        NonRobustShare::compute_shares(secret, n, degree_t, Some(&ids), &mut rng).unwrap();
    let shares_si_2t =
        NonRobustShare::compute_shares(secret, n, degree_t * 2, Some(&ids), &mut rng).unwrap();
    (secret, shares_si_t, shares_si_2t)
}

// Return a vector that contains a vector of inputs for each node
pub fn construct_e2e_input(
    n: usize,
    degree_t: usize,
) -> (
    Vec<Fr>,
    Vec<Vec<NonRobustShare<Fr>>>,
    Vec<Vec<NonRobustShare<Fr>>>,
) {
    let mut n_shares_t = vec![vec![]; n];
    let mut n_shares_2t = vec![vec![]; n];
    let mut secrets = Vec::new();
    let mut rng = test_rng();
    let ids: Vec<usize> = (1..=n).collect();

    for _ in 0..n {
        let secret = Fr::rand(&mut rng);
        secrets.push(secret);
        let shares_si_t =
            NonRobustShare::compute_shares(secret, n, degree_t, Some(&ids), &mut rng).unwrap();
        let shares_si_2t =
            NonRobustShare::compute_shares(secret, n, degree_t * 2, Some(&ids), &mut rng).unwrap();
        for j in 0..n {
            n_shares_t[j].push(shares_si_t[j].clone());
            n_shares_2t[j].push(shares_si_2t[j].clone());
        }
    }

    return (secrets, n_shares_t, n_shares_2t);
}

pub fn initialize_node(node_id: usize, n: usize, t: usize, k: usize) -> RanDouShaNode<Fr, Avid> {
    RanDouShaNode::new(node_id, n, t, k).unwrap()
}

/// Initializes all RanDouSha nodes and returns them wrapped in `Arc<Mutex<_>>`.
pub fn create_nodes(
    n_parties: usize,
    t: usize,
    k: usize,
) -> Vec<Arc<Mutex<RanDouShaNode<Fr, Avid>>>> {
    (1..=n_parties)
        .map(|id| Arc::new(Mutex::new(initialize_node(id, n_parties, t, k))))
        .collect()
}

/// Initializes all nodes with their respective shares.
pub async fn initialize_all_nodes(
    nodes: &[Arc<Mutex<RanDouShaNode<Fr, Avid>>>],
    n_shares_t: &[Vec<NonRobustShare<Fr>>],
    n_shares_2t: &[Vec<NonRobustShare<Fr>>],
    session_id: SessionId,
    network: Arc<FakeNetwork>,
) {
    assert!(nodes.len() == n_shares_t.len());
    assert!(nodes.len() == n_shares_2t.len());

    for node in nodes {
        let node_locked = &mut node.lock().await;
        let node_id = node_locked.id;
        match node_locked
            .init(
                n_shares_t[node_id - 1].clone(),
                n_shares_2t[node_id - 1].clone(),
                session_id,
                Arc::clone(&network),
            )
            .await
        {
            Ok(()) => (),
            Err(e) => {
                if let RanDouShaError::NetworkError(NetworkError::SendError) = e {
                    // allow for SendError because of Abort
                    eprintln!(
                        "Test: Init handler for node {} got expected SendError: {:?}",
                        node_locked.id, e
                    );
                } else {
                    panic!(
                        "Test: Unexpected error during init_handler for node {}: {:?}",
                        node_locked.id, e
                    );
                }
            }
        }
    }
}

/// Spawns receiver tasks for all nodes.
/// NOTE: In the case of a SendError, we log the error and continue because of the expected Abort behaviour
/// In the case of Abort, the node is dropped from the network and the task is cancelled
/// For the rest of the errors, we panic
pub fn spawn_receiver_tasks(
    nodes: Vec<Arc<Mutex<RanDouShaNode<Fr, Avid>>>>,
    mut receivers: Vec<Receiver<Vec<u8>>>,
    network: Arc<FakeNetwork>,
    fin_send: mpsc::Sender<(usize, (Vec<NonRobustShare<Fr>>, Vec<NonRobustShare<Fr>>))>,
    abort_counter: Option<Arc<AtomicUsize>>,
) -> JoinSet<()> {
    let mut set = JoinSet::new();
    for node in nodes {
        let randousha_node = Arc::clone(&node);
        let mut receiver = receivers.remove(0);
        let net_clone = Arc::clone(&network);
        let fin_send = fin_send.clone();
        let abort_count = abort_counter.clone();

        set.spawn(async move {
            while let Some(msg_bytes) = receiver.recv().await {
                // Attempt to deserialize into WrappedMessage
                let wrapped: WrappedMessage = match bincode::deserialize(&msg_bytes) {
                    Ok(m) => m,
                    Err(_) => {
                        warn!("Malformed or unrecognized message format.");
                        continue;
                    }
                };
                // Match the message type and route it appropriately
                match &wrapped {
                    WrappedMessage::RanDouSha(rds) => {
                        let result = randousha_node
                            .lock()
                            .await
                            .process(rds.clone(), Arc::clone(&net_clone))
                            .await;

                        match result {
                            Ok(Some(final_shares)) => {
                                let id = randousha_node.lock().await.id;
                                fin_send.send((id, final_shares)).await.unwrap();
                            }
                            Ok(None) => {}
                            Err(RanDouShaError::Abort) => {
                                let id = randousha_node.lock().await.id;
                                println!("RanDouSha aborted by node {id}");
                                if let Some(c) = abort_count {
                                    c.fetch_add(1, Ordering::SeqCst);
                                }
                                break;
                            }
                            Err(RanDouShaError::WaitForOk) => {}
                            Err(RanDouShaError::NetworkError(NetworkError::SendError)) => {
                                eprintln!(
                                    "Party {} encountered SendError (ignored)",
                                    randousha_node.lock().await.id
                                );
                            }
                            Err(e) => {
                                panic!(
                                    "Node {} encountered unexpected error: {e}",
                                    randousha_node.lock().await.id
                                );
                            }
                        }
                    }
                    WrappedMessage::Rbc(msg) => {
                        if let Err(e) = randousha_node
                            .lock()
                            .await
                            .rbc
                            .process(msg.clone(), Arc::clone(&net_clone))
                            .await
                        {
                            warn!("Rbc processing error: {e}");
                        }
                    }
                    WrappedMessage::BatchRecon(_) => todo!(),
                }
            }
        });
    }

    set
}

static TRACING_INIT: Lazy<()> = Lazy::new(|| {
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(EnvFilter::from_default_env().add_directive("trace".parse().unwrap()))
        .pretty()
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");
});

pub fn setup_tracing() {
    Lazy::force(&TRACING_INIT);
}
