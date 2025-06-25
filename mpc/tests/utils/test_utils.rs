use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_std::test_rng;
use once_cell::sync::Lazy;
use std::{
    collections::HashMap, sync::atomic::AtomicUsize, sync::atomic::Ordering, sync::Arc, vec,
};

use stoffelmpc_common::share::shamir::{self, ShamirSecretSharing};
use stoffelmpc_mpc::honeybadger::ran_dou_sha::messages::{InitMessage, RanDouShaMessage};
use stoffelmpc_mpc::honeybadger::ran_dou_sha::{RanDouShaError, RanDouShaNode, RanDouShaParams};
use stoffelmpc_network::fake_network::{FakeNetwork, FakeNetworkConfig};
use stoffelmpc_network::NetworkError;
use tokio::sync::mpsc::{self, Receiver};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::FmtSubscriber;

pub fn test_setup(
    n: usize,
    t: usize,
    session_id: usize,
) -> (
    RanDouShaParams,
    Arc<Mutex<FakeNetwork>>,
    Vec<Receiver<Vec<u8>>>,
) {
    let config = FakeNetworkConfig::new(500);
    let (network, receivers) = FakeNetwork::new(n, config);
    let network = Arc::new(Mutex::new(network));
    let params = RanDouShaParams {
        session_id,
        n_parties: n,
        threshold: t,
    };
    (params, network, receivers)
}

pub fn construct_input(
    n: usize,
    degree_t: usize,
) -> (
    Fr,
    Vec<ShamirSecretSharing<Fr>>,
    Vec<ShamirSecretSharing<Fr>>,
) {
    let mut rng = test_rng();
    let secret = Fr::rand(&mut rng);
    let ids: Vec<Fr> = (1..=n).map(|i| Fr::from(i as u64)).collect();
    let (shares_si_t, _) =
        shamir::ShamirSecretSharing::compute_shares(secret, degree_t, &ids, &mut rng);
    let (shares_si_2t, _) =
        shamir::ShamirSecretSharing::compute_shares(secret, degree_t * 2, &ids, &mut rng);
    (secret, shares_si_t, shares_si_2t)
}

// Return a vector that contains a vector of inputs for each node
pub fn construct_e2e_input(
    n: usize,
    degree_t: usize,
) -> (
    Vec<Fr>,
    Vec<Vec<ShamirSecretSharing<Fr>>>,
    Vec<Vec<ShamirSecretSharing<Fr>>>,
) {
    let mut n_shares_t = vec![vec![]; n];
    let mut n_shares_2t = vec![vec![]; n];
    let mut secrets = Vec::new();
    let mut rng = test_rng();
    let ids: Vec<Fr> = (1..=n).map(|i| Fr::from(i as u64)).collect();

    for _ in 0..n {
        let secret = Fr::rand(&mut rng);
        secrets.push(secret);
        let (shares_si_t, _) =
            shamir::ShamirSecretSharing::compute_shares(secret, degree_t, &ids, &mut rng);
        let (shares_si_2t, _) =
            shamir::ShamirSecretSharing::compute_shares(secret, degree_t * 2, &ids, &mut rng);
        for j in 0..n {
            n_shares_t[j].push(shares_si_t[j]);
            n_shares_2t[j].push(shares_si_2t[j]);
        }
    }

    return (secrets, n_shares_t, n_shares_2t);
}

pub fn initialize_node(node_id: usize) -> RanDouShaNode<Fr> {
    RanDouShaNode {
        id: node_id,
        store: Arc::new(Mutex::new(HashMap::new())),
    }
}

/// Initializes all RanDouSha nodes and returns them wrapped in `Arc<Mutex<_>>`.
pub fn create_nodes(n_parties: usize) -> Vec<Arc<Mutex<RanDouShaNode<Fr>>>> {
    (1..=n_parties)
        .map(|id| Arc::new(Mutex::new(initialize_node(id))))
        .collect()
}

/// Initializes all nodes with their respective shares.
pub async fn initialize_all_nodes(
    nodes: &[Arc<Mutex<RanDouShaNode<Fr>>>],
    n_shares_t: &[Vec<ShamirSecretSharing<Fr>>],
    n_shares_2t: &[Vec<ShamirSecretSharing<Fr>>],
    params: &RanDouShaParams,
    network: Arc<Mutex<FakeNetwork>>,
) {
    assert!(nodes.len() == n_shares_t.len());
    assert!(nodes.len() == n_shares_2t.len());

    for node in nodes {
        let node_locked = &mut node.lock().await;
        let init_msg = InitMessage {
            sender_id: node_locked.id,
            s_shares_deg_t: n_shares_t[node_locked.id - 1].clone(),
            s_shares_deg_2t: n_shares_2t[node_locked.id - 1].clone(),
        };
        match node_locked
            .init_handler(&init_msg, params, Arc::clone(&network))
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
    nodes: Vec<Arc<Mutex<RanDouShaNode<Fr>>>>,
    mut receivers: Vec<Receiver<Vec<u8>>>,
    params: RanDouShaParams,
    network: Arc<Mutex<FakeNetwork>>,
    fin_send: mpsc::Sender<(
        usize,
        (Vec<ShamirSecretSharing<Fr>>, Vec<ShamirSecretSharing<Fr>>),
    )>,
    abort_counter: Option<Arc<AtomicUsize>>,
) -> JoinSet<()> {
    let mut set = JoinSet::new();
    for node in nodes {
        let randousha_node = Arc::clone(&node);
        let mut receiver = receivers.remove(0);
        let network = Arc::clone(&network);
        let fin_send = fin_send.clone();

        // Keep track of aborts
        let abort_count = abort_counter.clone();

        // spawn tasks to process received messages
        set.spawn(async move {
            loop {
                let msg = match receiver.recv().await {
                    Some(msg) => msg,
                    None => break,
                };
                let deserialized_msg: RanDouShaMessage = bincode::deserialize(&msg).unwrap();
                let result = randousha_node
                    .lock()
                    .await
                    .process(&deserialized_msg, &params, Arc::clone(&network))
                    .await;

                match result {
                    Ok(Some(final_shares)) => {
                        fin_send
                            .send((randousha_node.lock().await.id, final_shares))
                            .await
                            .unwrap();
                    }
                    Ok(None) => continue,
                    Err(RanDouShaError::Abort) => {
                        println!("RanDouSha Aborted by node {}", node.lock().await.id);
                        if let Some(counter) = abort_count {
                            counter.fetch_add(1, Ordering::SeqCst);
                        }
                        break;
                    }
                    Err(RanDouShaError::WaitForOk) => {}
                    Err(RanDouShaError::NetworkError(e)) => match e {
                        NetworkError::SendError => {
                            // we are allowing because Some parties will be dropped because of Abort
                            eprintln!(
                                "Party {} encountered SendError: {:?}",
                                node.lock().await.id,
                                e
                            );
                            continue;
                        }

                        _ => {
                            panic!("{} Node encountered Error: {}", node.lock().await.id, e)
                        }
                    },
                    Err(e) => {
                        panic!("{} Node encountered Error: {}", node.lock().await.id, e)
                    }
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
