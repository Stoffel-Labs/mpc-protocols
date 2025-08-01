use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_std::test_rng;
use std::{collections::HashMap, sync::Arc};
use stoffelmpc_mpc::{
    common::{share::shamir::NonRobustShamirShare, SecretSharingScheme},
    honeybadger::{
        robust_interpolate::robust_interpolate::RobustShamirShare,
        triple_generation::{TripleGenNode, TripleGenParams, TripleGenStorage},
        DoubleShamirShare,
    },
};
use stoffelmpc_network::fake_network::{FakeNetwork, FakeNetworkConfig};
use tokio::sync::mpsc::{self, Receiver};
use tokio::sync::Mutex;

pub fn test_setup(
    n_parties: usize,
    threshold: usize,
    n_triples: usize,
) -> (TripleGenParams, Arc<FakeNetwork>, Vec<Receiver<Vec<u8>>>) {
    let config = FakeNetworkConfig::new(500);
    let (network, receivers) = FakeNetwork::new(n_parties, config);
    let network = Arc::new(network);
    let params = TripleGenParams {
        n_parties,
        threshold,
        n_triples,
    };
    (params, network, receivers)
}

pub fn create_nodes(
    n_parties: usize,
    params: TripleGenParams,
) -> (Vec<Arc<Mutex<TripleGenNode<Fr>>>>, Vec<Receiver<usize>>) {
    let mut receivers = vec![];
    let triple_gen_nodes = (1..=n_parties)
        .map(|id| {
            let (triple_sender, triple_receiver) = mpsc::channel(128);
            let triple_gen_node = TripleGenNode::new(id, params, triple_sender);
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
    Vec<Vec<RobustShamirShare<Fr>>>,
    Vec<Vec<RobustShamirShare<Fr>>>,
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
        let shares_a = RobustShamirShare::compute_shares(a, n_parties, t, None, &mut rng).unwrap();
        let b = Fr::rand(&mut rng);
        b_values.push(b);
        let shares_b = RobustShamirShare::compute_shares(b, n_parties, t, None, &mut rng).unwrap();

        let r = Fr::rand(&mut rng);
        pairs_values.push(r);
        // TODO: match the brhavior of robust shamir and non-robust shamir
        let ids: Vec<usize> = (1..=n_parties).collect();
        let shares_r_t =
            NonRobustShamirShare::compute_shares(r, n_parties, t, Some(&ids), &mut rng).unwrap();
        let shares_r_2t =
            NonRobustShamirShare::compute_shares(r, n_parties, 2 * t, Some(&ids), &mut rng)
                .unwrap();

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
