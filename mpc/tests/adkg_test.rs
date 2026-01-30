use crate::utils::test_utils::{fan_in_inboxes, setup_tracing, test_setup};
use ark_bls12_381::{Fr, G1Projective as G};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{PrimeField, UniformRand};
use ark_std::{
    rand::{
        rngs::{OsRng, StdRng},
        SeedableRng,
    },
    test_rng,
};
use std::{collections::HashMap, sync::Arc};
use stoffelmpc_mpc::{
    avss_mpc::{triple_gen::BeaverTriple, AdkgNode, AdkgNodeOpts, AvssSessionId},
    common::{
        rbc::rbc::Avid, share::feldman::FeldmanShamirShare, MPCProtocol, PreprocessingMPCProtocol,
        SecretSharingScheme, RBC,
    },
};
use stoffelmpc_network::fake_network::{FakeNetwork, SenderId};
use stoffelnet::network_utils::Network;
use tokio::sync::mpsc::{self, Receiver};

pub mod utils;

pub fn adkg_receive<F, R, S, N, G>(
    mut receivers: Vec<Vec<Receiver<Vec<u8>>>>, // inboxes[to][*]
    mut nodes: Vec<AdkgNode<F, R, G>>,
    net: Vec<Arc<N>>,
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
    let n_len = nodes.len();
    for i in 0..n_len {
        let inbox_row = receivers.remove(0);
        let mut node = nodes.remove(0);
        let net_clone = net[i].clone();

        // ---- label inboxes ----
        let mut labeled_inboxes = Vec::with_capacity(inbox_row.len());

        for (idx, rx) in inbox_row.into_iter().enumerate() {
            assert!(idx < n_len);
            {
                // node → node
                labeled_inboxes.push((SenderId::Node(idx), rx));
            }
        }

        let mut merged_rx = fan_in_inboxes(labeled_inboxes);

        tokio::spawn(async move {
            while let Some((sender, raw_msg)) = merged_rx.recv().await {
                let id = match sender {
                    SenderId::Node(i) => i,
                    SenderId::Client(i) => i,
                };
                if let Err(e) = node.process(id, raw_msg, net_clone.clone()).await {
                    tracing::error!(
                        "Node {:?} failed to process message from {:?}: {:?}",
                        i,
                        sender,
                        e
                    );
                }
            }
            tracing::info!("Receiver task for node {:?} ended", i);
        });
    }
}

pub fn create_adkg_nodes<F: PrimeField, R: RBC + 'static, S, N, G>(
    n_parties: usize,
    t: usize,
    n_v_random_shares: usize,
    n_triples: usize,
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
                n_triples,
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

pub async fn construct_e2e_input_mul(
    n_parties: usize,
    n_triples: usize,
    threshold: usize,
) -> ((Vec<Fr>, Vec<Fr>, Vec<Fr>), Vec<Vec<BeaverTriple<Fr, G>>>) {
    let mut rng = test_rng();
    let mut secrets_a = Vec::new();
    let mut secrets_b = Vec::new();
    let mut secrets_c = Vec::new();
    let mut per_party_triples: Vec<Vec<BeaverTriple<Fr, G>>> = vec![Vec::new(); n_parties];
    let ids: Vec<_> = (1..=n_parties).collect();

    for _i in 0..n_triples {
        // sample secrets a,b
        let a_secret = Fr::rand(&mut rng);
        let b_secret = Fr::rand(&mut rng);
        let c_secret = a_secret * b_secret;

        // make robust shares for each secret (length == n_parties)
        let shares_a = FeldmanShamirShare::compute_shares(
            a_secret,
            n_parties,
            threshold,
            Some(&ids),
            &mut rng,
        )
        .expect("share a creation failed");
        let shares_b = FeldmanShamirShare::compute_shares(
            b_secret,
            n_parties,
            threshold,
            Some(&ids),
            &mut rng,
        )
        .expect("share b creation failed");
        let shares_c = FeldmanShamirShare::compute_shares(
            c_secret,
            n_parties,
            threshold,
            Some(&ids),
            &mut rng,
        )
        .expect("share c creation failed");

        // push the secrets to the vectors
        secrets_a.push(a_secret);
        secrets_b.push(b_secret);
        secrets_c.push(c_secret);

        // For each party, create their per-party ShamirBeaverTriple and push it
        for pid in 0..n_parties {
            let triple = BeaverTriple {
                a: shares_a[pid].clone(),
                b: shares_b[pid].clone(),
                c: shares_c[pid].clone(),
            };
            per_party_triples[pid].push(triple);
        }
    }
    ((secrets_a, secrets_b, secrets_c), per_party_triples)
}

#[tokio::test]
async fn adkg_e2e() {
    setup_tracing();
    //----------------------------------------SETUP PARAMETERS----------------------------------------
    let n_parties = 5;
    let t = 1;
    //Setup
    let (network, receivers, _, _) = test_setup(n_parties, vec![]);

    //----------------------------------------SETUP NODES----------------------------------------
    // create global nodes
    let nodes =
        create_adkg_nodes::<Fr, Avid<AvssSessionId>, FeldmanShamirShare<Fr, G>, FakeNetwork, G>(
            n_parties, t, 1, 0, 111,
        );

    //----------------------------------------RECIEVE----------------------------------------
    // spawn tasks to process received messages
    adkg_receive::<Fr, Avid<AvssSessionId>, FeldmanShamirShare<Fr, G>, FakeNetwork, G>(
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
        let net = network[pid].clone();
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
        FeldmanShamirShare::recover_secret(&subset, n_parties, t).expect("recover_secret failed");

    //-------------------------------- PK checks --------------------------------
    let pk_expected = G::generator() * secret_rec;

    // Feldman invariant: pk == C_0
    let c0 = feldman_shares[0].commitments[0];
    assert_eq!(pk_expected, c0, "pk != Feldman C0 ");

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
    let n_parties = 4;
    let t = 1;
    let no_of_randomshares = 4;
    let no_of_triples = 4;
    let instance_id = 111;

    //Setup
    let (network, receivers, _, _) = test_setup(n_parties, vec![]);

    //----------------------------------------SETUP NODES----------------------------------------
    // create global nodes
    let nodes = create_adkg_nodes::<
        Fr,
        Avid<AvssSessionId>,
        FeldmanShamirShare<Fr, G>,
        FakeNetwork,
        G,
    >(n_parties, t, no_of_randomshares, no_of_triples, instance_id);

    //----------------------------------------RECIEVE----------------------------------------
    // spawn tasks to process received messages
    adkg_receive::<Fr, Avid<AvssSessionId>, FeldmanShamirShare<Fr, G>, FakeNetwork, G>(
        receivers,
        nodes.clone(),
        network.clone(),
    );

    //----------------------------------------RUN PROTOCOL----------------------------------------

    // init all nodes
    let mut handles = Vec::new();
    for pid in 0..n_parties {
        let mut node = nodes[pid].clone();
        let net = network[pid].clone();
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
        let (n_triples, n_v_shares) = node.preprocessing_material.lock().await.len();

        assert_eq!(n_v_shares, 4);
        assert_eq!(n_triples, 4);
    }
}

#[tokio::test]
async fn mul_e2e() {
    setup_tracing();
    //----------------------------------------SETUP PARAMETERS----------------------------------------
    let n_parties = 5;
    let t = 1;
    let mut rng = test_rng();
    let no_of_multiplication = 2;
    let ids: Vec<_> = (1..=n_parties).collect();

    //Setup
    let (network, receivers, _, _) = test_setup(n_parties, vec![]);
    //Generate triples
    let (_, triple) = construct_e2e_input_mul(n_parties, no_of_multiplication, t).await;

    // Prepare inputs for multiplication
    let mut x_values = Vec::new();
    let mut y_values = Vec::new();

    let mut x_inputs_per_node = vec![Vec::new(); n_parties];
    let mut y_inputs_per_node = vec![Vec::new(); n_parties];

    for _i in 0..no_of_multiplication {
        let x_value = Fr::rand(&mut rng);
        x_values.push(x_value);
        let y_value = Fr::rand(&mut rng);
        y_values.push(y_value);

        let shares_x =
            FeldmanShamirShare::compute_shares(x_value, n_parties, t, Some(&ids), &mut rng)
                .unwrap();
        let shares_y =
            FeldmanShamirShare::compute_shares(y_value, n_parties, t, Some(&ids), &mut rng)
                .unwrap();

        for p in 0..n_parties {
            x_inputs_per_node[p].push(shares_x[p].clone());
            y_inputs_per_node[p].push(shares_y[p].clone());
        }
    }

    //----------------------------------------SETUP NODES----------------------------------------
    // create global nodes
    let nodes = create_adkg_nodes::<
        Fr,
        Avid<AvssSessionId>,
        FeldmanShamirShare<Fr, G>,
        FakeNetwork,
        G,
    >(n_parties, t, 0, no_of_multiplication, 111);

    //----------------------------------------RECIEVE----------------------------------------
    // spawn tasks to process received messages
    adkg_receive::<Fr, Avid<AvssSessionId>, FeldmanShamirShare<Fr, G>, FakeNetwork, G>(
        receivers,
        nodes.clone(),
        network.clone(),
    );

    //----------------------------------------RUN PROTOCOL----------------------------------------
    //Load the triples
    for pid in 0..n_parties {
        let node = nodes[pid].clone();
        node.preprocessing_material
            .lock()
            .await
            .add(Some(triple[pid].clone()), None);
    }

    // init all nodes
    let (fin_send, mut fin_recv) = mpsc::channel::<(usize, Vec<FeldmanShamirShare<Fr, G>>)>(100);
    let mut handles = Vec::new();
    for pid in 0..n_parties {
        let mut node = nodes[pid].clone();
        let net = network[pid].clone();
        let fin_send = fin_send.clone();
        let x_shares = x_inputs_per_node[pid].clone();
        let y_shares = y_inputs_per_node[pid].clone();

        let handle = tokio::spawn(async move {
            {
                let final_shares = node
                    .mul(x_shares.clone(), y_shares.clone(), net.clone())
                    .await
                    .expect("mul failed");
                fin_send.send((pid, final_shares)).await.unwrap();
            }
        });
        handles.push(handle);
    }

    // Wait for all mul tasks to finish
    futures::future::join_all(handles).await;

    let mut final_results = HashMap::<usize, Vec<FeldmanShamirShare<Fr, G>>>::new();
    while let Some((id, final_shares)) = fin_recv.recv().await {
        final_results.insert(id, final_shares);
        if final_results.len() == n_parties {
            // check final_shares consist of correct shares
            for (id, mul_shares) in &final_results {
                assert_eq!(mul_shares.len(), no_of_multiplication);
                let _ = mul_shares.iter().map(|mul_share| {
                    assert_eq!(mul_share.feldmanshare.degree, t);
                    assert_eq!(mul_share.feldmanshare.id, *id);
                });
            }
            break;
        }
    }

    //----------------------------------------VALIDATE VALUES----------------------------------------

    let mut per_multiplication_shares: Vec<Vec<FeldmanShamirShare<Fr, G>>> =
        vec![Vec::new(); no_of_multiplication];

    for pid in 0..n_parties {
        for i in 0..no_of_multiplication {
            per_multiplication_shares[i].push(final_results.get(&pid).unwrap()[i].clone());
        }
    }

    for i in 0..no_of_multiplication {
        let shares_for_i = per_multiplication_shares[i][0..=t].to_vec();
        let (_, z_rec) = FeldmanShamirShare::recover_secret(&shares_for_i, n_parties, t)
            .expect("interpolate failed");
        let expected = x_values[i] * y_values[i];

        assert_eq!(z_rec, expected, "multiplication mismatch at index {}", i);
    }
}
