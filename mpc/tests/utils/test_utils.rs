use ark_bls12_381::Fr;
use ark_ff::{FftField, PrimeField, UniformRand};
use ark_std::test_rng;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::{sync::atomic::AtomicUsize, sync::atomic::Ordering, sync::Arc, vec};
use stoffelmpc_mpc::common::rbc::rbc::Avid;
use stoffelmpc_mpc::common::rbc::RbcError;
use stoffelmpc_mpc::common::share::shamir::NonRobustShare;
use stoffelmpc_mpc::common::{MPCProtocol, SecretSharingScheme, RBC};
use stoffelmpc_mpc::honeybadger::double_share::DoubleShamirShare;
use stoffelmpc_mpc::honeybadger::ran_dou_sha::{RanDouShaError, RanDouShaNode, RanDouShaState};
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::share_gen::RanShaError;
use stoffelmpc_mpc::honeybadger::triple_gen::ShamirBeaverTriple;
use stoffelmpc_mpc::honeybadger::{
    HoneyBadgerMPCClient, HoneyBadgerMPCNode, HoneyBadgerMPCNodeOpts, SessionId, WrappedMessage,
};
use stoffelmpc_network::bad_fake_network::{BadFakeNetwork, BadFakeNetworkConfig};
use stoffelmpc_network::fake_network::{FakeNetwork, FakeNetworkConfig};
use stoffelnet::network_utils::{ClientId, Network, NetworkError, PartyId};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tracing::warn;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::FmtSubscriber;

//--------------------------RBC--------------------------

/// Helper function to set up parties,Network,Receivers
pub async fn setup_network_and_parties<T: RBC, N: Network>(
    n: usize,
    t: usize,
    k: usize,
    buffer_size: usize,
) -> Result<(Vec<T>, Arc<FakeNetwork>, Vec<mpsc::Receiver<Vec<u8>>>), RbcError> {
    let config = FakeNetworkConfig::new(buffer_size);
    let (network, receivers, _) = FakeNetwork::new(n as usize, None, config);
    let net = Arc::new(network);

    let mut parties = Vec::with_capacity(n as usize);
    for i in 0..n {
        let rbc = T::new(i, n, t, k)?; // Create a new RBC instance for each party
        parties.push(rbc);
    }
    Ok((parties, net, receivers))
}

///Spawn parties for rbc
pub async fn spawn_parties<T, N>(
    parties: &[T],
    receivers: Vec<mpsc::Receiver<Vec<u8>>>,
    net: Arc<N>,
) where
    T: RBC + Clone + Send + Sync + 'static,
    N: Network + Send + Sync + 'static,
{
    for (rbc, mut rx) in parties.iter().cloned().zip(receivers.into_iter()) {
        let net_clone = Arc::clone(&net);

        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                let wrapped: WrappedMessage = match bincode::deserialize(&msg) {
                    Ok(m) => m,
                    Err(_) => {
                        warn!("Malformed or unrecognized message format.");
                        continue;
                    }
                };
                match wrapped {
                    WrappedMessage::RanDouSha(_) => todo!(),
                    WrappedMessage::Rbc(msg) => {
                        if let Err(e) = rbc.process(msg, Arc::clone(&net_clone)).await {
                            warn!(error = %e, "Message processing failed");
                        }
                    }
                    _ => todo!(),
                }
            }
        });
    }
}

//--------------------------RANDOUSHA--------------------------

pub fn test_setup(
    n: usize,
    clientid: Vec<ClientId>,
) -> (
    Arc<FakeNetwork>,
    Vec<Receiver<Vec<u8>>>,
    HashMap<usize, Receiver<Vec<u8>>>,
) {
    let config = FakeNetworkConfig::new(500);
    let (network, receivers, client_recv) = FakeNetwork::new(n, Some(clientid), config);
    let network = Arc::new(network);
    (network, receivers, client_recv)
}

pub fn test_setup_bad(
    n: usize,
    clientid: Vec<ClientId>,
) -> (
    Arc<BadFakeNetwork>,
    Receiver<(PartyId, Vec<u8>)>,
    Vec<Sender<Vec<u8>>>,
    Vec<Receiver<Vec<u8>>>,
    HashMap<ClientId, Receiver<Vec<u8>>>,
) {
    let config = BadFakeNetworkConfig::new(500);
    let (network, net_rx, node_channels, receivers, client_recv) =
        BadFakeNetwork::new(n, Some(clientid), config);
    let network = Arc::new(network);
    (network, net_rx, node_channels, receivers, client_recv)
}

pub fn get_reconstruct_input(
    n: usize,
    degree_t: usize,
) -> (Fr, Vec<NonRobustShare<Fr>>, Vec<NonRobustShare<Fr>>) {
    let mut rng = test_rng();
    let secret = Fr::rand(&mut rng);
    let shares_si_t = NonRobustShare::compute_shares(secret, n, degree_t, None, &mut rng).unwrap();
    let shares_si_2t =
        NonRobustShare::compute_shares(secret, n, degree_t * 2, None, &mut rng).unwrap();
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

    for _ in 0..n {
        let secret = Fr::rand(&mut rng);
        secrets.push(secret);
        let shares_si_t =
            NonRobustShare::compute_shares(secret, n, degree_t, None, &mut rng).unwrap();
        let shares_si_2t =
            NonRobustShare::compute_shares(secret, n, degree_t * 2, None, &mut rng).unwrap();
        for j in 0..n {
            n_shares_t[j].push(shares_si_t[j].clone());
            n_shares_2t[j].push(shares_si_2t[j].clone());
        }
    }

    return (secrets, n_shares_t, n_shares_2t);
}

pub fn initialize_node(
    node_id: usize,
    n: usize,
    t: usize,
    k: usize,
    output_sender: Sender<SessionId>,
) -> RanDouShaNode<Fr, Avid> {
    RanDouShaNode::new(node_id, output_sender, n, t, k).unwrap()
}

/// Initializes all RanDouSha nodes and returns them wrapped in `Arc<Mutex<_>>`.
pub fn create_nodes(
    n_parties: usize,
    senders: Vec<Sender<SessionId>>,
    t: usize,
    k: usize,
) -> Vec<Arc<Mutex<RanDouShaNode<Fr, Avid>>>> {
    (0..n_parties)
        .zip(senders)
        .map(|(id, sender)| Arc::new(Mutex::new(initialize_node(id, n_parties, t, k, sender))))
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
                n_shares_t[node_id].clone(),
                n_shares_2t[node_id].clone(),
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
    fin_send: mpsc::Sender<(usize, Vec<DoubleShamirShare<Fr>>)>,
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
                            Ok(()) => {
                                let node = randousha_node.lock().await;
                                let storage_db = node.store.lock().await;
                                let storage = storage_db.get(&rds.session_id).unwrap().lock().await;
                                if storage.state == RanDouShaState::Finished {
                                    let final_shares = storage.protocol_output.clone();
                                    fin_send.send((node.id, final_shares)).await.unwrap();
                                }
                            }
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
                                continue;
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
                    _ => todo!(),
                }
            }
        });
    }

    set
}

//--------------------------TRACING--------------------------

static TRACING_INIT: Lazy<()> = Lazy::new(|| {
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
        .pretty()
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    let old_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        old_hook(info);
        tracing::error!("{}", info);
        std::process::exit(1);
    }));
});

pub fn setup_tracing() {
    Lazy::force(&TRACING_INIT);
}
//--------------------------BATCH RECON--------------------------

/// Generate secret shares where each secret is shared independently using a random polynomial
/// with that secret as the constant term (f(0) = secret), and evaluated using FFT-based domain.
pub fn generate_independent_shares<F: FftField>(
    secrets: &[F],
    t: usize,
    n: usize,
) -> Vec<Vec<RobustShare<F>>> {
    let mut rng = test_rng();
    let mut shares = vec![
        vec![
            RobustShare {
                share: [F::zero()],
                id: 0,
                degree: t,
                commitments: None,
                _sharetype: PhantomData
            };
            secrets.len()
        ];
        n
    ];
    for (j, secret) in secrets.iter().enumerate() {
        // Call gen_shares to create 'n' shares for the current 'secret'
        let secret_shares = RobustShare::compute_shares(*secret, n, t, None, &mut rng).unwrap();
        for i in 0..n {
            shares[i][j] = secret_shares[i].clone(); // Party i receives evaluation of f_j at α_i
        }
    }

    shares
}

//--------------------------NODE--------------------------

pub fn receive<F, R, S, N>(
    mut receivers: Vec<Receiver<Vec<u8>>>,
    mut nodes: Vec<HoneyBadgerMPCNode<F, R>>,
    net: Arc<N>,
) where
    F: PrimeField,
    R: RBC + 'static,
    N: Network + Send + Sync + 'static,
    S: SecretSharingScheme<F>,
    HoneyBadgerMPCNode<F, R>: MPCProtocol<F, S, N>,
{
    assert_eq!(
        receivers.len(),
        nodes.len(),
        "Each node must have a receiver"
    );

    for i in 0..receivers.len() {
        let mut rx = receivers.remove(0);
        let mut node = nodes.remove(0);
        let net_clone = net.clone();

        tokio::spawn(async move {
            while let Some(raw_msg) = rx.recv().await {
                if let Err(e) = node.process(raw_msg, net_clone.clone()).await {
                    tracing::error!("Node {i} failed to process message: {e:?}");
                }
            }
            tracing::info!("Receiver task for node {i} ended");
        });
    }
}

pub fn create_global_nodes<F: PrimeField, R: RBC + 'static, S, N>(
    n_parties: usize,
    t: usize,
    n_triples: usize,
    n_random_shares: usize,
    instance_id: u32,
    n_prandbit: usize,
    n_prandint: usize,
    l: usize,
    k: usize,
    input_ids: Vec<ClientId>,
) -> Vec<HoneyBadgerMPCNode<F, R>>
where
    N: Network + Send + Sync + 'static,
    S: SecretSharingScheme<F>,
    HoneyBadgerMPCNode<F, R>: MPCProtocol<F, S, N, MPCOpts = HoneyBadgerMPCNodeOpts>,
{
    let parameters = HoneyBadgerMPCNodeOpts::new(
        n_parties,
        t,
        n_triples,
        n_random_shares,
        instance_id,
        n_prandbit,
        n_prandint,
        l,
        k,
    );
    (0..n_parties)
        .map(|id| HoneyBadgerMPCNode::setup(id, parameters.clone(), input_ids.clone()).unwrap())
        .collect()
}

/// Initializes all global nodes with their respective shares for randousha.
pub async fn initialize_global_nodes_randousha<F, R, N>(
    nodes: Vec<HoneyBadgerMPCNode<F, R>>,
    n_shares_t: &[Vec<NonRobustShare<F>>],
    n_shares_2t: &[Vec<NonRobustShare<F>>],
    session_id: SessionId,
    network: Arc<N>,
) where
    F: PrimeField,
    R: RBC + 'static,
    N: Network + Send + Sync + 'static,
{
    assert!(nodes.len() == n_shares_t.len());
    assert!(nodes.len() == n_shares_2t.len());

    for node in nodes {
        let mut node_rds = node.preprocess.ran_dou_sha;
        let node_id = node_rds.id;
        match node_rds
            .init(
                n_shares_t[node_id].clone(),
                n_shares_2t[node_id].clone(),
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
                        node_id, e
                    );
                } else {
                    panic!(
                        "Test: Unexpected error during init_handler for node {}: {:?}",
                        node_id, e
                    );
                }
            }
        }
    }
}

// Return a vector that contains a vector of inputs for each node
pub fn construct_e2e_input_ransha(
    n: usize,
    degree_t: usize,
) -> (Vec<Fr>, Vec<Vec<RobustShare<Fr>>>) {
    let mut n_shares_t = vec![vec![]; n];
    let mut secrets = Vec::new();
    let mut rng = test_rng();

    for _ in 0..n {
        let secret = Fr::rand(&mut rng);
        secrets.push(secret);
        let shares_si_t = RobustShare::compute_shares(secret, n, degree_t, None, &mut rng).unwrap();
        for j in 0..n {
            n_shares_t[j].push(shares_si_t[j].clone());
        }
    }

    return (secrets, n_shares_t);
}
/// Initializes all global nodes with their respective shares for ransha.
pub async fn initialize_global_nodes_ransha<F, R, N>(
    nodes: Vec<HoneyBadgerMPCNode<F, R>>,
    session_id: SessionId,
    network: Arc<N>,
) where
    F: PrimeField,
    R: RBC + 'static,
    N: Network + Send + Sync + 'static,
{
    let mut rng = test_rng();

    for node in nodes {
        let mut node_rds = node.preprocess.share_gen;
        let node_id = node_rds.id;
        match node_rds
            .init(session_id, &mut rng, Arc::clone(&network))
            .await
        {
            Ok(()) => (),
            Err(e) => {
                if let RanShaError::NetworkError(NetworkError::SendError) = e {
                    // allow for SendError because of Abort
                    eprintln!(
                        "Test: Init handler for node {} got expected SendError: {:?}",
                        node_id, e
                    );
                } else {
                    panic!(
                        "Test: Unexpected error during init_handler for node {}: {:?}",
                        node_id, e
                    );
                }
            }
        }
    }
}

//--------------------------MUL--------------------------

pub async fn construct_e2e_input_mul(
    n_parties: usize,
    n_triples: usize,
    threshold: usize,
) -> (
    (Vec<Fr>, Vec<Fr>, Vec<Fr>),
    Vec<Vec<ShamirBeaverTriple<Fr>>>,
) {
    let mut rng = test_rng();
    let mut secrets_a = Vec::new();
    let mut secrets_b = Vec::new();
    let mut secrets_c = Vec::new();
    let mut per_party_triples: Vec<Vec<ShamirBeaverTriple<Fr>>> = vec![Vec::new(); n_parties];

    for _i in 0..n_triples {
        // sample secrets a,b
        let a_secret = Fr::rand(&mut rng);
        let b_secret = Fr::rand(&mut rng);
        let c_secret = a_secret * b_secret;

        // make robust shares for each secret (length == n_parties)
        let shares_a = RobustShare::compute_shares(a_secret, n_parties, threshold, None, &mut rng)
            .expect("share a creation failed");
        let shares_b = RobustShare::compute_shares(b_secret, n_parties, threshold, None, &mut rng)
            .expect("share b creation failed");
        let shares_c = RobustShare::compute_shares(c_secret, n_parties, threshold, None, &mut rng)
            .expect("share c creation failed");

        // push the secrets to the vectors
        secrets_a.push(a_secret);
        secrets_b.push(b_secret);
        secrets_c.push(c_secret);

        // For each party, create their per-party ShamirBeaverTriple and push it
        for pid in 0..n_parties {
            let triple = ShamirBeaverTriple {
                a: shares_a[pid].clone(),
                b: shares_b[pid].clone(),
                mult: shares_c[pid].clone(),
            };
            per_party_triples[pid].push(triple);
        }
    }
    ((secrets_a, secrets_b, secrets_c), per_party_triples)
}

//--------------------------CLIENT--------------------------
pub fn create_clients<F: FftField, R: RBC + 'static>(
    client_ids: Vec<ClientId>,
    n_parties: usize,
    t: usize,
    instance_id: u32,
    inputs: Vec<F>,
    input_len: usize,
) -> HashMap<ClientId, HoneyBadgerMPCClient<F, R>> {
    client_ids
        .into_iter()
        .map(|id| {
            let client =
                HoneyBadgerMPCClient::new(id, n_parties, t, instance_id, inputs.clone(), input_len)
                    .unwrap();
            (id, client)
        })
        .collect()
}

pub fn receive_client<F, R, N>(
    mut receivers: HashMap<ClientId, Receiver<Vec<u8>>>,
    clients: HashMap<ClientId, HoneyBadgerMPCClient<F, R>>,
    net: Arc<N>,
) where
    F: FftField + 'static,
    R: RBC + 'static,
    N: Network + Send + Sync + 'static,
{
    assert_eq!(
        receivers.len(),
        clients.len(),
        "Each node must have a receiver"
    );

    for (clientid, mut recv) in receivers.drain() {
        let mut client = clients[&clientid].clone();
        let net_clone = net.clone();

        tokio::spawn(async move {
            while let Some(received) = recv.recv().await {
                if let Err(e) = client.process(received, net_clone.clone()).await {
                    tracing::error!("Client {clientid} failed to process message: {e:?}");
                }
            }
            tracing::info!("Receiver task for client {clientid} ended");
        });
    }
}
