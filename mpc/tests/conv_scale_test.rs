//! A2B and B2A at scale, on **real** preprocessing.
//!
//! Every other node-level conversion test deals its daBits, edaBits and triples in the clear.
//! Here nothing is dealt: each run generates its own material with the production generators
//! (`run_conversion_preprocessing`, `run_gf_preprocessing`), converts a batch of full-range
//! values to bits, checks every bit, converts the low 63 bits back, checks every value, and
//! checks that the pools were drained exactly.
//!
//! The runs are `#[ignore]`d because the larger ones take minutes. Each prints one `SCALE` line:
//!
//! ```text
//! cargo test -p stoffelcrypto --release --test conv_scale_test -- --ignored --nocapture --test-threads 1
//! ```

pub mod utils;

use crate::utils::test_utils::{
    create_global_nodes, receive, setup_quiet_tracing, test_setup, unused_precision,
};
use ark_ff::PrimeField;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use std::time::{Duration, Instant};
use stoffelcrypto::common::convert::{canonical_bits, field_bit_width};
use stoffelcrypto::common::gf2k::field::{BinaryField, Gf256};
use stoffelcrypto::common::gf2k::share::GfShare;
use stoffelcrypto::common::{
    rbc::rbc::Avid, ConversionPreprocessingProtocol, GfPreprocessingMPCProtocol,
    SecretSharingScheme, ShareConversionProtocol,
};
use stoffelcrypto::honeybadger::{
    a2b::a2b::A2BNode, b2a::b2a::max_width, robust_interpolate::robust_interpolate::RobustShare,
    HoneyBadgerMPCNode, SessionId, MIN_STATISTICAL_SECURITY,
};
use stoffelmpc_network::fake_network::FakeNetwork;

type K = Gf256;
/// The scalar field of BLS12-381: 255 bits, and not of the Solinas shape, so the edaBit filter
/// takes its general comparison.
type Bls = ark_bls12_381::Fr;
/// The scalar field of BN254: 254 bits.
type Bn = ark_bn254::Fr;

/// The values a full-range conversion has to get right — both ends of the range and the carry
/// boundaries of the reduction — followed by uniform ones.
fn values<F: PrimeField>(count: usize, rng: &mut StdRng) -> Vec<F> {
    let width = field_bit_width::<F>() as u64;
    let one = F::one();
    let two = F::from(2u64);
    let mut out = vec![
        F::zero(),
        one,
        -one,                       // p - 1
        -two,                       // p - 2
        two.pow([width - 1]),       // 2^(w-1): the top bit alone
        two.pow([width - 1]) - one, // 2^(w-1) - 1: every bit below it
        -two.pow([width - 1]),      // p - 2^(w-1)
        two.pow([width]),           // 2^w mod p = 2^w - p: the offset the adder folds in
        two.pow([width]) - one,
        two.pow([width / 2]),
    ];
    out.truncate(count);
    while out.len() < count {
        out.push(F::rand(rng));
    }
    out
}

/// One full run on real preprocessing: generate, `a2b` a batch, `b2a` the low bits back.
async fn scale<F: PrimeField>(n: usize, t: usize, conversions: usize, instance_id: u32) {
    setup_quiet_tracing();
    let width = field_bit_width::<F>();
    let back = max_width::<F>();
    let per_conversion = A2BNode::<F, K>::gf_triples_per_conversion().unwrap();

    let (network, receivers, _, _) = test_setup(n, vec![]);
    let mut nodes: Vec<HoneyBadgerMPCNode<F, Avid<SessionId>>> =
        create_global_nodes::<F, Avid<SessionId>, RobustShare<F>, FakeNetwork>(
            n,
            t,
            1,
            2,
            instance_id,
            0,
            0,
            unused_precision(),
            MIN_STATISTICAL_SECURITY,
            Duration::from_secs(3600),
            vec![],
        );
    for node in &mut nodes {
        node.params.n_edabits = conversions;
        node.params.n_dabits = conversions * back;
        node.params.n_gf_triples = conversions * per_conversion;
        node.params.n_gf_random_shares = 0;
    }
    receive::<F, Avid<SessionId>, RobustShare<F>, FakeNetwork>(
        receivers,
        nodes.clone(),
        network.clone(),
        None,
    );

    // ---- preprocessing: nothing dealt -----------------------------------------------------
    let started = Instant::now();
    let mut handles = Vec::with_capacity(n);
    for party in 0..n {
        let mut node = nodes[party].clone();
        let net = network[party].clone();
        handles.push(tokio::spawn(async move {
            let mut rng = StdRng::seed_from_u64(0x5CA1_E000 + party as u64);
            node.run_conversion_preprocessing(net.clone(), &mut rng)
                .await
                .unwrap_or_else(|e| panic!("conversion preprocessing, party {party}: {e:?}"));
            node.run_gf_preprocessing(net, &mut rng)
                .await
                .unwrap_or_else(|e| panic!("GF preprocessing, party {party}: {e:?}"));
        }));
    }
    for handle in handles {
        handle.await.expect("preprocessing task panicked");
    }
    let preprocessing = started.elapsed();
    let mut dabits_made = 0;
    for (party, node) in nodes.iter().enumerate() {
        let store = node.conv_preprocessing_material.lock().await;
        assert!(
            store.length().edabits >= conversions,
            "party {party}: edaBits"
        );
        assert!(
            store.length().dabits >= conversions * back,
            "party {party}: daBits"
        );
        dabits_made = store.dabits_produced();
    }

    let mut rng = StdRng::seed_from_u64(0xBA7C_4000 + instance_id as u64);
    let values: Vec<F> = values(conversions, &mut rng);
    let mut inputs: Vec<Vec<RobustShare<F>>> = vec![Vec::with_capacity(conversions); n];
    for value in &values {
        let shares = RobustShare::compute_shares(*value, n, t, None, &mut rng).unwrap();
        for (party, share) in shares.into_iter().enumerate() {
            inputs[party].push(share);
        }
    }

    // ---- A2B --------------------------------------------------------------------------------
    let started = Instant::now();
    let mut handles = Vec::with_capacity(n);
    for party in 0..n {
        let mut node = nodes[party].clone();
        let net = network[party].clone();
        let x = inputs[party].clone();
        handles.push(tokio::spawn(async move { node.a2b(x, net).await }));
    }
    let mut bits: Vec<Vec<Vec<GfShare<K>>>> = Vec::with_capacity(n);
    for (party, handle) in handles.into_iter().enumerate() {
        bits.push(
            handle
                .await
                .expect("a2b task panicked")
                .unwrap_or_else(|e| panic!("a2b, party {party}: {e:?}")),
        );
    }
    let a2b = started.elapsed();

    let recover_bit = |column: &[GfShare<K>]| {
        let (_, value) = GfShare::recover_secret(&column[0..=2 * t], n, t).unwrap();
        assert!(value == K::one() || value == K::zero(), "not a bit");
        value == K::one()
    };
    for (index, value) in values.iter().enumerate() {
        let want = canonical_bits::<F>(*value, width).unwrap();
        for bit in 0..width {
            let column: Vec<GfShare<K>> = bits.iter().map(|b| b[index][bit].clone()).collect();
            assert_eq!(
                recover_bit(&column),
                want[bit],
                "n = {n}: bit {bit} of value {index} ({value})"
            );
        }
    }

    // ---- B2A on the low `width - 1` bits ----------------------------------------------------
    let started = Instant::now();
    let mut handles = Vec::with_capacity(n);
    for party in 0..n {
        let mut node = nodes[party].clone();
        let net = network[party].clone();
        let low: Vec<Vec<GfShare<K>>> = bits[party].iter().map(|b| b[..back].to_vec()).collect();
        handles.push(tokio::spawn(async move { node.b2a(low, net).await }));
    }
    let mut shares: Vec<Vec<RobustShare<F>>> = Vec::with_capacity(n);
    for (party, handle) in handles.into_iter().enumerate() {
        shares.push(
            handle
                .await
                .expect("b2a task panicked")
                .unwrap_or_else(|e| panic!("b2a, party {party}: {e:?}")),
        );
    }
    let b2a = started.elapsed();

    for (index, value) in values.iter().enumerate() {
        let column: Vec<RobustShare<F>> = shares.iter().map(|s| s[index].clone()).collect();
        let (_, got) = RobustShare::recover_secret(&column[0..=2 * t], n, t).unwrap();
        // The value with its top bit cleared: what the low `width - 1` bits encode.
        let want = canonical_bits::<F>(*value, width).unwrap()[..back]
            .iter()
            .rev()
            .fold(F::zero(), |acc, bit| acc.double() + F::from(*bit as u64));
        assert_eq!(
            got, want,
            "n = {n}: value {index} ({value}) did not come back"
        );
    }

    // ---- nothing left over, nothing left running -------------------------------------------
    for (party, node) in nodes.iter().enumerate() {
        let conv = node.conv_preprocessing_material.lock().await.length();
        assert_eq!(conv.edabits, 0, "party {party}: edaBits left over");
        assert_eq!(conv.dabits, 0, "party {party}: daBits left over");
        assert_eq!(
            node.conv.a2b.store_len().await,
            0,
            "party {party}: a2b store"
        );
        assert_eq!(
            node.conv.b2a.store_len().await,
            0,
            "party {party}: b2a store"
        );
    }

    println!(
        "SCALE field_bits={width} n={n} t={t} conversions={conversions} \
         triples_per_a2b={per_conversion} dabits_made={dabits_made} \
         preprocessing={:.2}s a2b={:.3}s b2a={:.3}s",
        preprocessing.as_secs_f64(),
        a2b.as_secs_f64(),
        b2a.as_secs_f64(),
    );
}

macro_rules! scale_test {
    ($name:ident, $field:ty, $n:expr, $t:expr, $conversions:expr, $instance:expr) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
        #[ignore = "scale run; see the module header"]
        async fn $name() {
            scale::<$field>($n, $t, $conversions, $instance).await;
        }
    };
}

scale_test!(bls_n4_t1_x1, Bls, 4, 1, 1, 9101);
scale_test!(bls_n4_t1_x16, Bls, 4, 1, 16, 9102);
scale_test!(bls_n4_t1_x64, Bls, 4, 1, 64, 9103);
scale_test!(bls_n4_t1_x256, Bls, 4, 1, 256, 9104);
scale_test!(bls_n5_t1_x16, Bls, 5, 1, 16, 9141);
scale_test!(bls_n7_t2_x1, Bls, 7, 2, 1, 9111);
scale_test!(bls_n7_t2_x16, Bls, 7, 2, 16, 9112);
scale_test!(bls_n7_t2_x64, Bls, 7, 2, 64, 9113);
scale_test!(bls_n8_t2_x4, Bls, 8, 2, 4, 9142);
scale_test!(bls_n10_t3_x1, Bls, 10, 3, 1, 9121);
scale_test!(bls_n10_t3_x8, Bls, 10, 3, 8, 9122);
scale_test!(bls_n13_t4_x1, Bls, 13, 4, 1, 9131);
scale_test!(bls_n16_t5_x1, Bls, 16, 5, 1, 9151);
scale_test!(bn_n4_t1_x16, Bn, 4, 1, 16, 9201);
scale_test!(bn_n7_t2_x4, Bn, 7, 2, 4, 9202);
