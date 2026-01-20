use crate::utils::test_utils::{setup_tracing, test_setup};
use ark_bls12_381::{Fr, G1Projective as G};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::PrimeField;
use ark_std::{
    rand::{
        rngs::{OsRng, StdRng},
        SeedableRng,
    },
    test_rng,
};
use std::sync::Arc;
use stoffelmpc_mpc::{
    adkg::{AdkgNode, AdkgNodeOpts},
    common::{
        rbc::rbc::Avid, share::feldman::FeldmanShamirShare, MPCProtocol, PreprocessingMPCProtocol,
        SecretSharingScheme, RBC,
    },
};
use stoffelmpc_network::fake_network::FakeNetwork;
use stoffelnet::network_utils::Network;
use tokio::sync::mpsc::{self, Receiver};

pub mod utils;

pub fn adkg_receive<F, R, S, N, G>(
    mut receivers: Vec<Receiver<Vec<u8>>>,
    mut nodes: Vec<AdkgNode<F, R, G>>,
    net: Arc<N>,
) where
    F: PrimeField,
    R: RBC + 'static,
    N: Network + Send + Sync + 'static,
    S: SecretSharingScheme<F>,
    AdkgNode<F, R, G>: MPCProtocol<F, S, N>,
    G: CurveGroup<ScalarField = F>,
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

pub fn create_adkg_nodes<F: PrimeField, R: RBC + 'static, S, N, G>(
    n_parties: usize,
    t: usize,
    n_v_random_shares: usize,
    instance_id: u32,
) -> Vec<AdkgNode<F, R, G>>
where
    N: Network + Send + Sync + 'static,
    S: SecretSharingScheme<F>,
    AdkgNode<F, R, G>: MPCProtocol<F, S, N, MPCOpts = AdkgNodeOpts<F, G>>,
    G: CurveGroup<ScalarField = F>,
{
    let mut rng = test_rng();

    let mut sks = Vec::new();
    let mut pks = Vec::new();
    for _ in 0..n_parties {
        let sk = F::rand(&mut rng);
        let pk = G::generator() * sk;
        sks.push(sk);
        pks.push(pk);
    }
    let pk_map = Arc::new(pks);

    let parameters: Vec<_> = (0..n_parties)
        .map(|i| {
            AdkgNodeOpts::new(
                n_parties,
                t,
                n_v_random_shares,
                sks[i],
                pk_map.clone(),
                instance_id,
            )
        })
        .collect();

    (0..n_parties)
        .map(|id| AdkgNode::setup(id, parameters[id].clone(), vec![]).unwrap())
        .collect()
}

#[tokio::test]
async fn adkg_e2e() {
    setup_tracing();
    //----------------------------------------SETUP PARAMETERS----------------------------------------
    let n_parties = 5;
    let t = 1;
    //Setup
    let (network, receivers, _) = test_setup(n_parties, vec![]);

    //----------------------------------------SETUP NODES----------------------------------------
    // create global nodes
    let nodes = create_adkg_nodes::<Fr, Avid, FeldmanShamirShare<Fr, G>, FakeNetwork, G>(
        n_parties, t, 1, 111,
    );

    //----------------------------------------RECIEVE----------------------------------------
    // spawn tasks to process received messages
    adkg_receive::<Fr, Avid, FeldmanShamirShare<Fr, G>, FakeNetwork, G>(
        receivers,
        nodes.clone(),
        network.clone(),
    );

    //----------------------------------------RUN PROTOCOL----------------------------------------
    // init all nodes
    let (fin_send, mut fin_recv) = mpsc::channel::<(usize, FeldmanShamirShare<Fr, G>)>(100);
    let mut handles = Vec::new();
    for pid in 0..n_parties {
        let mut node = nodes[pid].clone();
        let net = network.clone();
        let fin_send = fin_send.clone();
        let handle = tokio::spawn(async move {
            {
                let key_share = node.rand(net).await.expect("mul failed");
                fin_send.send((pid, key_share)).await.unwrap();
            }
        });
        handles.push(handle);
    }

    // Wait for all mul tasks to finish
    futures::future::join_all(handles).await;
    let mut per_party: Vec<Option<FeldmanShamirShare<Fr, G>>> = vec![None; n_parties];
    while let Some((pid, shares)) = fin_recv.recv().await {
        per_party[pid] = Some(shares);
        if per_party.iter().all(|x| x.is_some()) {
            break;
        }
    }

    let mut feldman_shares: Vec<FeldmanShamirShare<Fr, G>> = Vec::with_capacity(n_parties);

    for pid in 0..n_parties {
        let shares = per_party[pid].as_ref().unwrap();
        feldman_shares.push(shares.clone());
    }

    //----------------------------------------VALIDATE EACH KEY----------------------------------------

    // Reconstruct secret from t+1 shares
    let subset = feldman_shares[0..(t + 1)].to_vec();
    let (_, secret_rec) =
        FeldmanShamirShare::recover_secret(&subset, n_parties).expect("recover_secret failed");

    //-------------------------------- PK checks --------------------------------
    let pk_expected = G::generator() * secret_rec;

    // Feldman invariant: pk == C_0
    let c0 = feldman_shares[0].commitments[0];
    assert_eq!(pk_expected, c0, "pk != Feldman C0 ");

    // ADKG public_key API
    let pk_from_method = nodes[0].public_key(feldman_shares[0].clone());

    assert_eq!(pk_from_method, pk_expected, "public_key() != g^secret",);

    //-------------------------------- Commitments consistency --------------------------------
    let reference_commitments = &feldman_shares[0].commitments;

    assert_eq!(
        reference_commitments.len(),
        t + 1,
        "commitment length mismatch",
    );

    for (pid, fs) in feldman_shares.iter().enumerate() {
        assert_eq!(
            fs.commitments, *reference_commitments,
            "Feldman commitments mismatch at party {}",
            pid
        );
    }
}

#[tokio::test]
async fn preprocessing_e2e() {
    setup_tracing();
    //----------------------------------------SETUP PARAMETERS----------------------------------------
    let n_parties = 5;
    let t = 1;
    let no_of_randomshares = 4;
    let instance_id = 111;

    //Setup
    let (network, receivers, _) = test_setup(n_parties, vec![]);

    //----------------------------------------SETUP NODES----------------------------------------
    // create global nodes
    let nodes = create_adkg_nodes::<Fr, Avid, FeldmanShamirShare<Fr, G>, FakeNetwork, G>(
        n_parties,
        t,
        no_of_randomshares,
        instance_id,
    );

    //----------------------------------------RECIEVE----------------------------------------
    // spawn tasks to process received messages
    adkg_receive::<Fr, Avid, FeldmanShamirShare<Fr, G>, FakeNetwork, G>(
        receivers,
        nodes.clone(),
        network.clone(),
    );

    //----------------------------------------RUN PROTOCOL----------------------------------------

    // init all nodes
    let mut handles = Vec::new();
    for pid in 0..n_parties {
        let mut node = nodes[pid].clone();
        let net = network.clone();
        let mut rng = StdRng::from_rng(OsRng).unwrap();

        let handle = tokio::spawn(async move {
            {
                node.run_preprocessing(net, &mut rng)
                    .await
                    .expect("Preprocessing failed");
            }
        });
        handles.push(handle);
    }

    // Wait for all mul tasks to finish
    futures::future::join_all(handles).await;
    std::thread::sleep(std::time::Duration::from_millis(300));

    //----------------------------------------VALIDATE VALUES----------------------------------------

    for pid in 0..n_parties {
        let node = nodes[pid].clone();
        let n_v_shares = node.preprocessing_material.lock().await.len();

        assert_eq!(n_v_shares, 6);
    }
}
