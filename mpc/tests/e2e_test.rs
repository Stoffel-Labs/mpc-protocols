use crate::utils::test_utils::{
    construct_e2e_input, construct_e2e_input_mul, create_clients, create_global_nodes,
    generate_independent_shares, initialize_global_nodes_randousha, initialize_global_nodes_ransha,
    receive_client, setup_tracing, test_setup, test_setup_bad
};
use ark_bls12_381::Fr;
use ark_ff::{UniformRand, FftField};
use ark_std::{
    Zero, One,
    rand::{
        rngs::{OsRng, StdRng},
        distributions::Uniform,
        SeedableRng,
    },
    test_rng,
};
use ark_poly::polynomial::{DenseMVPolynomial, Polynomial, multivariate::{Term, SparsePolynomial, SparseTerm}};
use futures::future::join_all;
use std::{collections::HashMap, ops::{Mul, Add}, sync::Arc, fmt, net::SocketAddr};
use stoffelmpc_mpc::{
    common::{
        share::shamir::Shamirshare, RBC, rbc::rbc::Avid, MPCProtocol, PreprocessingMPCProtocol, SecretSharingScheme, ShamirShare,
    },
    honeybadger::{
        HoneyBadgerError,
        HoneyBadgerMPCClient,
        HoneyBadgerMPCNode,
        HoneyBadgerMPCNodeOpts,
        input::input::InputClient,
        output::output::{OutputClient, OutputServer},
        ran_dou_sha::RanDouShaState,
        robust_interpolate::robust_interpolate::{Robust, RobustShare},
        share_gen::RanShaState,
        ProtocolType, SessionId, WrappedMessage,
    },
};
use stoffelmpc_network::{fake_network::FakeNetwork, bad_fake_network::BadFakeNetwork};
use stoffelnet::{transports::{net_envelope::NetEnvelope, quic::{PeerConnection, NetworkManager, QuicNetworkManager}}, network_utils::{Network, ClientId, PartyId}};
use tokio::{
    task::JoinSet,
    sync::Mutex,
    time::{Duration, sleep, timeout},
};
use tracing::{info, error};
use rustls::crypto::aws_lc_rs;

pub mod utils;

trait Process<F: FftField, R: RBC, N: Network + Send + Sync + 'static> {
    async fn process(
        &mut self,
        raw_msg: Vec<u8>,
        net: Arc<N>,
    ) -> Result<(), HoneyBadgerError>;
}

async fn receive<F: FftField, R: RBC, N: Network + Send + Sync + 'static>(mut p: impl Process<F, R, N>, net: Arc<N>, conns: Vec<Arc<dyn PeerConnection>>)
{
    let mut receivers = JoinSet::new();
    let mut id_to_index: HashMap<_, _> = (0..conns.len()).map(|i| {
        let conn = conns[i].clone();
        let id = receivers.spawn(async move {
            conn.receive().await
        }).id();
        (id, i)
    }).collect();

    while let Some(join_res) = receivers.join_next_with_id().await {
        let msg = match join_res {
            Ok((old_id, recv_res)) => match recv_res {
                Ok(msg) => {
                    // `old_id` must exist
                    let i = *id_to_index.get(&old_id).unwrap();
                    let conn = conns[i].clone();
                    let new_id = receivers.spawn(async move {
                        conn.receive().await
                    }).id();

                    assert!(id_to_index.remove(&old_id).is_some());
                    id_to_index.insert(new_id, i);
                    msg
                }
                Err(err_msg) => panic!("error while receiving: {}", err_msg)
            }
            Err(_) => {
                panic!("error while waiting for join result");
            }
        };

        match p.process(msg, net.clone()).await {
            Ok(()) => { }
            Err(e) => error!("error processing message on node level: {e}")
        }
    }

    panic!("all receivers terminated");
}

impl<R: RBC, N: Network + Send + Sync + 'static> Process<Fr, R, N> for HoneyBadgerMPCClient<Fr, R> {
    async fn process(&mut self, raw_msg: Vec<u8>, net: Arc<N>) -> Result<(), HoneyBadgerError> {
        HoneyBadgerMPCClient::process(self, raw_msg, net).await
    }
}

impl<R: RBC, N: Network + Send + Sync + 'static> Process<Fr, R, N> for HoneyBadgerMPCNode<Fr, R> {
    async fn process(&mut self, raw_msg: Vec<u8>, net: Arc<N>) -> Result<(), HoneyBadgerError> {
        MPCProtocol::process(self, raw_msg, net).await
    }
}

/*
 * To evaluate a multivariate polynomial f, each party i proceeds as follows:
 * 
 * input x_i
 * result = 0
 * for each monomial:
 *   result_monomial = 1
 *   for each variable:
 *     result_var = evaluate power by multiplying a variable with itself
 *     result_monomial *= result_var
 *   result += result_monomial
 *
 * Denoting the number of monomials by m and each monomial by m_i and the exponent for a variable
 * in a monomial m_i by e_ij, the number of multiplications is
 *   sum_ij e_ij
 *
 * The test runs as follows:
 *   1. Connect nodes to each other and each client to each node
 */

#[tokio::test]
async fn test_poly() {
    //console_subscriber::init();
    setup_tracing();
    assert!(aws_lc_rs::default_provider().install_default().is_ok());

    let n_parties = 5;
    let t = 1;
    let node_addrs = [
        "127.0.0.1:12340",
        "127.0.0.1:12341",
        "127.0.0.1:12342",
        "127.0.0.1:12343",
        "127.0.0.1:12344"
    ];
    let client_addrs =  [
        "127.0.0.1:12350",
        "127.0.0.1:12351",
        "127.0.0.1:12352",
        "127.0.0.1:12353",
        "127.0.0.1:12354"
    ];

    let inputs = vec![Fr::from(1), Fr::from(2), Fr::from(3), Fr::from(4), Fr::from(5)];
    let instance_id = 111;

    let poly = SparsePolynomial::from_coefficients_vec(
        n_parties,
        vec![
            (Fr::from(1), SparseTerm::new(vec![(0, 1), (1, 2), (2, 3), (3, 4), (4, 5)]))
        ],
    );

    let result = poly.evaluate(&inputs);

    let n_mults = poly
        .terms()
        .into_iter()
        .map(|(_, term)| term.powers())
        .flatten()
        .sum();

    let mut node_handles = Vec::new();
    for i in 0..n_parties {
        let node_addrs = node_addrs.clone();
        let client_addrs = client_addrs.clone();
        let poly = poly.clone();
        let id = i as PartyId;

        let program = async move {
        let mut node_conns = Vec::new();
        let quic_node = {
            let mut quic_node = QuicNetworkManager::with_node_id(id);

            // to connect to all other nodes, we let node 0 connect to everyone, then node 1, and so
            // forth. currently, connecting does not check if a connection is already established, so
            // we need to make sure that we connect only once. the real setting might use a central
            // node for discovery anyway.
            // to connect clients with nodes, we let the clients connect to the nodes. this makes sense
            // because the nodes are well-known, whereas the clients change for each instance.
            quic_node.listen(node_addrs[i].parse().unwrap()).await.unwrap();

            if i > 0 {
                info!("node {}: wait for nodes 0 to {} to connect", i, i - 1);
            }

            // wait for nodes to connect
            for j in 0..i {
                node_conns.push(quic_node.accept().await.unwrap());
            }

            if i < n_parties - 1 {
                info!("node {}: connect to nodes {} to {}", i, i + 1, n_parties);
            }

            // connect to next nodes
            for j in i + 1..n_parties {
                node_conns.push(quic_node.connect(node_addrs[j].parse().unwrap()).await.unwrap());
            }
            quic_node.ensure_loopback_installed();
            node_conns.push(quic_node.get_connection(id).await.unwrap());

            info!("node {}: wait for clients to connect", i);

            // wait for clients to connect
            for j in 0..client_addrs.len() {
                node_conns.push(quic_node.accept().await.unwrap());
            }

            Arc::new(quic_node)
        };

        info!("node {}: all connections ready", i);

        // hard-code client IDs, since I see no way of getting the client ID after establishing a
        // connection to a client
        let client_ids: Vec<_> = (0..client_addrs.len()).collect();

        let opts = HoneyBadgerMPCNodeOpts::new(n_parties, t, n_mults, client_addrs.len(), instance_id, 0, 0, 0, 0);
        let mut node = <HoneyBadgerMPCNode<Fr, Avid> as MPCProtocol<Fr, RobustShare<Fr>, QuicNetworkManager>>::setup(id, opts, client_ids.clone()).unwrap();

        let _ = tokio::spawn({
            let quic_node = quic_node.clone();
            let node = node.clone();
            async move {
                receive(node, quic_node, node_conns).await;
            }
        });

        let mut rng = StdRng::seed_from_u64(1u64);

        node.run_preprocessing(quic_node.clone(), &mut rng)
            .await
            .expect("Preprocessing failed");

        for cid in client_ids.clone() {
            let local_shares = node
                .preprocessing_material
                .lock()
                .await
                .take_random_shares(1)
                .unwrap();
            node.preprocess
                      .input
                      .init(cid, local_shares, 1, quic_node.clone())
                      .await
                      .unwrap();
        }

        let inputs = node.preprocess.input.wait_for_all_inputs(Duration::MAX).await.expect("input error").clone();

        // calculation + output
        let mut result: Option<RobustShare<Fr>> = None;

        for (coeff, term) in &poly.terms {
            let mut term_result: Option<RobustShare<Fr>> = None;
        
            for (var, pow) in term.vars().into_iter().zip(term.powers()) {
                let var_share = inputs.get(&var).unwrap().clone();

                for _ in 0..pow {
                    term_result = match term_result {
                        None => Some(var_share.clone()[0].clone()),
                        Some(term_result_value) => Some(node
                            .mul(vec![term_result_value.clone()], var_share.clone(), quic_node.clone())
                            .await
                            .expect("mul failed")[0].clone())
                    };
                }
            }

            term_result = Some((term_result.unwrap() * *coeff).expect("mul failed"));
            result = match result {
                Some(result_value) => Some((result_value + term_result.unwrap()).expect("add failed")),
                None => term_result
            };
        }

        for cid in client_ids.clone() {
            node.output.init(
                cid,
                vec![result.clone().unwrap()],
                1,
                quic_node.clone(),
            ).await.expect("server init error: {e}");
        }
        };

        node_handles.push(tokio::spawn(program));
    }


    // start clients
    let mut client_handles = Vec::new();
    for i in 0..inputs.len() {
        let node_addrs = node_addrs.clone();
        let client_addr = client_addrs[i].clone();
        let id = i as ClientId;
        let input = vec![inputs[i]];

        let program = async move {
        let mut node_conns = Vec::new();
        let quic_node = {
            let mut quic_node = QuicNetworkManager::new();

            info!("client {}: connect to nodes", i);

            // connect to nodes
            for j in 0..n_parties {
                node_conns.push(quic_node.connect_as_client(node_addrs[j].parse().unwrap(), id).await.unwrap());
            }

            Arc::new(quic_node)
        };

        let mut client = HoneyBadgerMPCClient::<Fr, Avid>::new(id, n_parties, t, instance_id, input, 1).unwrap();

        let _ = tokio::spawn({
            let quic_node = quic_node.clone();
            let client = client.clone();
            async move {
                receive(client, quic_node, node_conns).await;
            }
        });

        let output = match client.output.wait_for_output(Duration::from_millis(5000)).await {
            Err(e) => panic!("error while waiting for output: {e}"),
            Ok(output) => output
        };

        assert_eq!(output, vec![result]);
        };

        client_handles.push(tokio::spawn(program));
    }

    futures::future::join_all(client_handles).await;
    futures::future::join_all(node_handles).await;
}
