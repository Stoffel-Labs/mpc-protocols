//! End-to-end test of GF(2^k) operations wired directly onto `HoneyBadgerMPCNode` (not the
//! standalone `GfMultiply`/`GfTripleGenNode` used by `gf_mul_test.rs`/`gf_triple_gen_test.rs`).
//! Exercises the full path in one call: `node.gf_mul` -> `run_gf_preprocessing` (RanSha for a/b,
//! DoubleShare+RanDouSha for the mask, TripleGen) -> `GfMultiply`, all driven purely through
//! `node.process`'s dispatch (including the RBC multiplexing added for `GfRansha`/`GfRandousha`
//! and the batch-recon multiplexing added for `GfMul`/`GfTriple`).
pub mod utils;

use crate::utils::test_utils::{receive, setup_tracing, test_setup, unused_precision};
use ark_bls12_381::Fr;
use std::time::Duration;
use stoffelcrypto::{
    common::{
        gf2k::field::{BinaryField, Gf256},
        gf2k::share::GfShare,
        rbc::rbc::Avid,
        GfMPCProtocol, MPCProtocol,
    },
    honeybadger::{
        robust_interpolate::robust_interpolate::RobustShare, GfPreprocessingOpts,
        HoneyBadgerMPCNode, HoneyBadgerMPCNodeOpts, SessionId, MIN_STATISTICAL_SECURITY,
    },
};
use stoffelmpc_network::fake_network::FakeNetwork;

#[tokio::test]
async fn gf_mul_e2e_through_node_dispatch() {
    setup_tracing();

    let n_parties = 4;
    let t = 1;
    let no_of_multiplications = 2;
    // Matches the F-domain `mul_e2e_with_preprocessing` test's own sizing convention: one triple
    // group (2t+1) covers the batch, and random shares cover 2 per triple.
    let n_gf_triples = 2 * t + 1;
    let n_gf_random_shares = 2 * n_gf_triples;

    let (network, receivers, _, _) = test_setup(n_parties, vec![]);

    // Built directly (not via `create_global_nodes`, which always passes `gf: None`) so this
    // node's setup actually includes a binary field.
    let opts = HoneyBadgerMPCNodeOpts::new(
        n_parties,
        t,
        1, // F-domain preprocessing is irrelevant here; keep it minimal but valid.
        2,
        111,
        0,
        0,
        unused_precision(),
        MIN_STATISTICAL_SECURITY,
        Duration::from_secs(30),
        Some(GfPreprocessingOpts {
            n_gf_triples,
            n_gf_random_shares,
        }),
    )
    .unwrap();
    let nodes: Vec<HoneyBadgerMPCNode<Fr, Avid<SessionId>>> = (0..n_parties)
        .map(|id| {
            <HoneyBadgerMPCNode<Fr, Avid<SessionId>> as MPCProtocol<
                Fr,
                RobustShare<Fr>,
                FakeNetwork,
            >>::setup(id, opts.clone(), vec![])
            .unwrap()
        })
        .collect();

    receive::<Fr, Avid<SessionId>, RobustShare<Fr>, FakeNetwork>(
        receivers,
        nodes.clone(),
        network.clone(),
        None,
    );

    let mut rng = ark_std::test_rng();
    let mut x_values = Vec::new();
    let mut y_values = Vec::new();
    let mut x_inputs_per_node = vec![Vec::new(); n_parties];
    let mut y_inputs_per_node = vec![Vec::new(); n_parties];
    for _ in 0..no_of_multiplications {
        let x = Gf256::random(&mut rng);
        x_values.push(x);
        let y = Gf256::random(&mut rng);
        y_values.push(y);

        let shares_x = GfShare::compute_shares(x, n_parties, t, &mut rng).unwrap();
        let shares_y = GfShare::compute_shares(y, n_parties, t, &mut rng).unwrap();
        for p in 0..n_parties {
            x_inputs_per_node[p].push(shares_x[p].clone());
            y_inputs_per_node[p].push(shares_y[p].clone());
        }
    }

    let mut handles = Vec::new();
    for pid in 0..n_parties {
        let mut node = nodes[pid].clone();
        let net = network[pid].clone();
        let x = x_inputs_per_node[pid].clone();
        let y = y_inputs_per_node[pid].clone();
        handles.push(tokio::spawn(async move { node.gf_mul(x, y, net).await }));
    }

    let mut per_party_results = Vec::with_capacity(n_parties);
    for handle in handles {
        let result = handle.await.unwrap().expect("gf_mul failed");
        assert_eq!(result.len(), no_of_multiplications);
        per_party_results.push(result);
    }

    for i in 0..no_of_multiplications {
        let shares_for_i: Vec<GfShare<Gf256>> = per_party_results
            .iter()
            .map(|shares| shares[i].clone())
            .collect();
        let (_, z) = GfShare::recover_secret(&shares_for_i, n_parties, t).unwrap();
        assert_eq!(z, x_values[i] * y_values[i], "mismatch at index {i}");
    }
}

/// The other half of the opt-in design: a node whose setup never supplied `gf` must fail
/// cleanly on every GF(2^k) entry point instead of panicking on an absent `Option`.
#[tokio::test]
async fn gf_ops_fail_cleanly_when_not_configured() {
    use stoffelcrypto::honeybadger::HoneyBadgerError;

    let n_parties = 4;
    let t = 1;
    let opts = HoneyBadgerMPCNodeOpts::new(
        n_parties,
        t,
        1,
        2,
        111,
        0,
        0,
        unused_precision(),
        MIN_STATISTICAL_SECURITY,
        Duration::from_secs(30),
        None, // no binary field for this node's setup
    )
    .unwrap();
    let mut node = <HoneyBadgerMPCNode<Fr, Avid<SessionId>> as MPCProtocol<
        Fr,
        RobustShare<Fr>,
        FakeNetwork,
    >>::setup(0, opts, vec![])
    .unwrap();
    assert!(node.gf.is_none());

    let a = GfShare::new(Gf256(1), 0, t);
    let b = GfShare::new(Gf256(2), 0, t);
    // `gf_add`/`gf_sub` don't otherwise pin down `N` (the trait's third param), so it has to be
    // named explicitly here even though these two ops never touch the network.
    assert!(matches!(
        <HoneyBadgerMPCNode<Fr, Avid<SessionId>> as GfMPCProtocol<
            Gf256,
            GfShare<Gf256>,
            FakeNetwork,
        >>::gf_add(&node, vec![a.clone()], vec![b.clone()]),
        Err(HoneyBadgerError::GfNotConfigured)
    ));
    assert!(matches!(
        <HoneyBadgerMPCNode<Fr, Avid<SessionId>> as GfMPCProtocol<
            Gf256,
            GfShare<Gf256>,
            FakeNetwork,
        >>::gf_sub(&node, vec![a.clone()], vec![b.clone()]),
        Err(HoneyBadgerError::GfNotConfigured)
    ));

    let (network, _receivers, _, _) = test_setup(n_parties, vec![]);
    assert!(matches!(
        node.gf_mul(vec![a], vec![b], network[0].clone()).await,
        Err(HoneyBadgerError::GfNotConfigured)
    ));
}
