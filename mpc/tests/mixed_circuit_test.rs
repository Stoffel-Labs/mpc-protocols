//! **Mixed arithmetic/binary circuit, end to end, through the whole engine.**
//!
//! Every other conversion test in this crate either round-trips A2B/B2A in isolation or
//! reconstructs the conversion's output directly in the harness. None of them composes a
//! conversion with the rest of the MPC engine: measured across `conv_node_test.rs`,
//! `a2b_node_test.rs` and `b2a_test.rs` there are zero `.mul(` calls and zero `.output(` calls.
//! This file closes that gap. The circuit it runs is
//!
//! ```text
//!   client inputs x, y      -- InputClient, over RBC
//!   z   = mul(x, y)         -- ARITHMETIC, consumes a Beaver triple
//!   b   = a2b(z)            -- consumes an edaBit (and so daBits) + ~695 GF triples
//!   a_i = b_i AND b_{i+1}   -- BINARY multiplicative: node.gf_mul, W triples
//!   u_i = a_i XOR b_i       -- BINARY linear: local GfShare addition, no round
//!   n_i = NOT u_i           -- BINARY linear: local GfShare + public K::one()
//!   v   = b2a(n)            -- consumes W daBits
//!   out = mul(v, x)         -- ARITHMETIC again, on a B2A output
//!   reveal(out)             -- OutputServer -> OutputClient, over RBC
//! ```
//!
//! and the assertion is on the *cleartext the client receives*, against the same circuit
//! evaluated in the clear on `u64`s.
//!
//! # What this is built to catch, rather than merely to pass
//!
//! **Degree and provenance.** `a2b`'s input here is the output of a Beaver multiplication, not a
//! freshly input or freshly dealt sharing. A `mul` result is a degree-`t` sharing that was
//! *reconstituted* from a degree-`2t` product minus a mask, and nothing in the tree currently
//! feeds one to a conversion. `assert_bits` below checks the whole 64-bit decomposition against
//! `canonical_bits(z)` so a provenance failure is localised to the bit, not just to the answer.
//!
//! **Preprocessing pool interaction.** Nothing is dealt by a trusted dealer. Every piece of
//! material -- the two Beaver triples, the edaBit, its daBits, the loose daBits B2A spends, and
//! the ~700 GF triples -- is produced by this node's own preprocessing, off one PRSS key family
//! and therefore one `PrssAllocator`, established by a single `setup_prss_keys` RISS run. A
//! position-reuse or pool-exhaustion bug between the arithmetic and conversion tracks has nowhere
//! else in the suite to show itself: every other conversion test deals its material and never
//! touches the allocator, and every other allocator test drives the allocator without running a
//! conversion.
//!
//! **Session-id collisions.** Arithmetic (`Mul` -> `BatchRecon`), conversion (`A2B` -> `BatchRecon`,
//! `A2BGfMul`/`B2A` -> `GfBatchRecon`), the caller's own binary layer (`GfMul` -> `GfBatchRecon`)
//! and preprocessing (`Dn07`, `GfDn07`, `DaBitOpen`, `DaBitGfMul`, `DaBitGfOpen`) all run under
//! one node against one `SubProtocolCounters`. `mixed_circuit_with_concurrent_arithmetic` runs an
//! independent arithmetic multiplication *concurrently with* the conversion so the two tracks'
//! sessions and pool draws interleave rather than merely alternate.
//!
//! **The output path**, which no conversion test touches and which is the only step a real
//! consumer ends on.
//!
//! # Threat model
//!
//! Steps 2 onward are ONLINE: asynchronous, robust, guaranteed output delivery, degree-`t`
//! openings only. `mixed_circuit_survives_t_corrupt_online_openers` asserts that -- `t` parties
//! send shares off the polynomial in every online opening, and the honest majority must still
//! deliver the *correct* cleartext with no abort. Preprocessing is synchronous and may abort, so
//! the tamper is scoped to online session tags only; see `TamperScope`.

pub mod utils;

use crate::utils::test_utils::{
    create_global_nodes, fan_in_inboxes, receive, receive_client, setup_tracing, test_setup,
};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use stoffelcrypto::{
    common::{
        convert::{bit_to_binary, canonical_bits, field_bit_width},
        gf2k::field::{BinaryField, Gf256},
        gf2k::share::GfShare,
        math::goldilocks::GoldilocksField,
        rbc::rbc::Avid,
        types::fixed::FixedPointPrecision,
        GfMPCProtocol, MPCProtocol, PreprocessingMPCProtocol, ProtocolSessionId,
        SecretSharingScheme, ShareConversionProtocol,
    },
    honeybadger::{
        a2b::a2b::A2BNode, robust_interpolate::robust_interpolate::RobustShare,
        HoneyBadgerMPCClient, ProtocolType, SessionId, WrappedMessage, MIN_STATISTICAL_SECURITY,
    },
};
use stoffelmpc_network::fake_network::{FakeNetwork, SenderId};
use stoffelnet::network_utils::ClientId;

type F = GoldilocksField;
type K = Gf256;
type Node = stoffelcrypto::honeybadger::HoneyBadgerMPCNode<F, Avid<SessionId>>;

/// Working width of the binary section, in bits.
///
/// Deliberately below both `field_bit_width::<F>()` (64) and B2A's hard `max_width` bound (63):
/// the values are chosen so `z < 2^W`, which makes the top `64 - W` bits of `a2b(z)` provably
/// zero and gives `assert_high_bits_zero` something exact to check. A conversion that mis-sized
/// its decomposition, or a `mul` that returned a share of the wrong value, shows up there before
/// it shows up in the answer.
const W: usize = 32;

/// The two client inputs. Small on purpose: `x * y < 2^W`, and the final product
/// `v * x < 2^42`, so every intermediate is exactly an integer and the clear-text model below is
/// plain `u64` arithmetic with no modular reduction to reason about.
const X_CLEAR: u64 = 1234;
const Y_CLEAR: u64 = 5678;

// ---------------------------------------------------------------------------------------------
// The circuit, in the clear.
// ---------------------------------------------------------------------------------------------

/// Evaluates the same circuit on `u64`s. Returns `(z, bits_of_z, final_bits, v, out)`.
///
/// Written as an explicit bit loop rather than a closed form (`z & rotr(z, 1)` and friends)
/// because the point of the comparison is that it was derived independently of the protocol's
/// own bit ordering, not that it is short.
fn clear_circuit(x: u64, y: u64) -> (u64, Vec<bool>, Vec<bool>, u64, u64) {
    let z = x * y;
    let z_bits: Vec<bool> = (0..W).map(|i| (z >> i) & 1 == 1).collect();

    let mut final_bits = Vec::with_capacity(W);
    for i in 0..W {
        let and = z_bits[i] & z_bits[(i + 1) % W];
        let xor = and ^ z_bits[i];
        final_bits.push(!xor);
    }

    let v: u64 = final_bits
        .iter()
        .enumerate()
        .map(|(i, b)| if *b { 1u64 << i } else { 0 })
        .sum();

    (z, z_bits, final_bits, v, v * x)
}

// ---------------------------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------------------------

/// Nodes sized for exactly one run of the circuit.
///
/// Every pool size is derived from the circuit rather than guessed, so that a change to `W` or to
/// the AND layer cannot silently leave a pool one short and turn a real failure into a
/// `NotEnoughPreprocessing`.
fn nodes_for(n_parties: usize, t: usize, instance_id: u32, input_ids: Vec<ClientId>) -> Vec<Node> {
    // Two arithmetic multiplications: `z = x * y` and `out = v * x`. Triples are taken in groups,
    // so ask for a whole group.
    let n_triples = 2 * t + 1;
    // A2B's circuit, plus this test's own AND layer, plus one group of slack.
    let per_conversion = A2BNode::<F, K>::gf_triples_per_conversion().unwrap();
    let n_gf_triples = per_conversion + W + (2 * t + 1);

    let mut nodes = create_global_nodes::<F, Avid<SessionId>, RobustShare<F>, FakeNetwork>(
        n_parties,
        t,
        n_triples,
        2 * n_triples + 2,
        instance_id,
        0,
        0,
        conv_precision(),
        MIN_STATISTICAL_SECURITY,
        Duration::from_secs(120),
        input_ids,
    );
    for node in &mut nodes {
        node.params.n_gf_triples = n_gf_triples;
        node.params.n_gf_random_shares = 0;
        // One edaBit per A2B-converted value; `W` loose daBits for the single B2A.
        node.params.n_edabits = 1;
        node.params.n_dabits = W;
    }
    nodes
}

/// One RISS run per party, in parallel: this is the only place the PRSS key family comes from,
/// and every subsequent piece of preprocessing -- arithmetic, GF and conversion -- is derived off
/// it through the single allocator it installs.
async fn install_prss_keys(nodes: &mut [Node], network: &[Arc<FakeNetwork>]) {
    let mut handles = Vec::new();
    for (pid, node) in nodes.iter().enumerate() {
        let mut node = node.clone();
        let net = network[pid].clone();
        handles.push(tokio::spawn(async move {
            node.setup_prss_keys(net).await.expect("prss setup");
            node
        }));
    }
    for (pid, handle) in handles.into_iter().enumerate() {
        nodes[pid] = handle.await.unwrap();
        assert!(
            nodes[pid].prss_keys_installed(),
            "node {pid} has no PRSS keys, so every pool below would fall back to a dealt path \
             and this test would not be testing allocator contention at all"
        );
    }
}

/// **Anti-vacuity guard.** Every sub-protocol this file claims to compose must actually have
/// minted at least one session on every party.
///
/// Without this the test degrades quietly rather than loudly: if a future change made `a2b` hand
/// back a cached decomposition, or made `gf_mul` fold a one-wave AND layer into a local
/// operation, or made the two `mul` calls collapse into one, every assertion below would still
/// pass and the file would go on claiming to test a composition it no longer exercises. `peek`
/// is the counter's read-only "did that protocol run at all?" accessor and exists for exactly
/// this question.
async fn assert_every_track_ran(nodes: &[Node]) {
    for (pid, node) in nodes.iter().enumerate() {
        let c = &node.counters;
        assert_eq!(
            c.mul_counter.peek().await,
            Some(2),
            "node {pid}: expected exactly two arithmetic multiplications (steps 2 and 6)"
        );
        assert_eq!(
            c.a2b_counter.peek().await,
            Some(1),
            "node {pid}: A2B never ran, so nothing here converted a multiplication output"
        );
        assert_eq!(
            c.b2a_counter.peek().await,
            Some(1),
            "node {pid}: B2A never ran, so nothing returned to the arithmetic domain"
        );
        assert!(
            c.gf_mul_counter.peek().await.unwrap_or(0) >= 1,
            "node {pid}: the caller's own binary AND layer never ran"
        );
        // Conversion preprocessing is the pool the arithmetic track competes with. If it never
        // ran, the edaBit and daBits came from somewhere this test does not control.
        assert!(
            c.gf_triple_counter.peek().await.unwrap_or(0) >= 1,
            "node {pid}: no GF triple batch was generated, so A2B's AND gates were not paid for"
        );
    }
}

/// Reconstructs one column of GF bit shares. Takes only `2t + 1` of them: these are degree-`t`
/// openings and no single party may be depended upon.
fn recover_bit(shares: &[GfShare<K>], n_parties: usize, t: usize) -> K {
    let (_, got) = GfShare::recover_secret(&shares[0..=2 * t], n_parties, t)
        .expect("bit column is not a degree-t sharing");
    got
}

/// The A2B output, checked bit by bit against `canonical_bits(z)`.
///
/// This is the degree/provenance assertion. `z` reached `a2b` as the output of a Beaver
/// multiplication, and if a `mul` result is in any way not an ordinary degree-`t` sharing of `z`
/// -- wrong degree, wrong evaluation point, a stale mask never subtracted -- the decomposition
/// goes wrong here, at an identifiable bit, rather than silently at the end.
fn assert_bits(per_party: &[Vec<Vec<GfShare<K>>>], z: F, n_parties: usize, t: usize) {
    let width = field_bit_width::<F>();
    let want = canonical_bits::<F>(z, width).unwrap();
    for bit in 0..width {
        let column: Vec<GfShare<K>> = per_party.iter().map(|r| r[0][bit].clone()).collect();
        assert_eq!(
            recover_bit(&column, n_parties, t),
            bit_to_binary::<K>(want[bit]),
            "a2b of a multiplication output is wrong at bit {bit}"
        );
    }
}

/// `z < 2^W` by construction, so `a2b` must have produced exactly `64 - W` zero high bits.
fn assert_high_bits_zero(per_party: &[Vec<Vec<GfShare<K>>>], n_parties: usize, t: usize) {
    for bit in W..field_bit_width::<F>() {
        let column: Vec<GfShare<K>> = per_party.iter().map(|r| r[0][bit].clone()).collect();
        assert_eq!(
            recover_bit(&column, n_parties, t),
            bit_to_binary::<K>(false),
            "high bit {bit} of a value below 2^{W} is not zero"
        );
    }
}

/// The precision PRSS key setup can carry on Goldilocks.
///
/// `setup_prss_keys` sizes its RISS batch from `params.mask_bits() = (2k - f) + kappa`, and
/// `PRandIntNode` refuses a mask wider than
/// `MODULUS_BIT_SIZE - 2 - ceil(log2 n) - ceil(log2 C(n,t))`. The suite-wide
/// `unused_precision()` (32/16, so `2k - f = 48`) is fine on the 255-bit BLS scalar field the
/// other node tests use and fails here with `SurpassedFieldCapacity`. Nothing in this circuit
/// masks a fixed-point value, so the figure only has to be *legal*; `5/4` gives `mask_bits = 46`
/// and clears the bound at both committee sizes. Same choice, same reason, as
/// `conv_cost_measurement::conv_precision`.
fn conv_precision() -> FixedPointPrecision {
    FixedPointPrecision::new(5, 4)
}

fn f_to_u64(v: F) -> u64 {
    let bytes = v.into_bigint().to_bytes_le();
    let mut repr = [0u8; 8];
    repr.copy_from_slice(&bytes[0..8]);
    u64::from_le_bytes(repr)
}

/// Runs `run_preprocessing` on every party, then drives the client input protocol, and returns
/// each party's `(x_share, y_share)`.
///
/// Preprocessing is explicit here only because the *input masks* have no lazy top-up path of
/// their own -- `input.init` needs random shares in hand. Everything downstream (triples, GF
/// triples, edaBits, daBits) is deliberately left to top itself up from inside the online calls,
/// which is what puts the two tracks in contention over one allocator.
async fn run_input_phase(
    nodes: &mut [Node],
    network: &[Arc<FakeNetwork>],
    input_client: ClientId,
) -> Vec<(RobustShare<F>, RobustShare<F>)> {
    let n_parties = nodes.len();

    let mut handles = Vec::new();
    for (pid, node) in nodes.iter().enumerate() {
        let mut node = node.clone();
        let net = network[pid].clone();
        handles.push(tokio::spawn(async move {
            let mut rng = StdRng::seed_from_u64(0xA2B0_0000 + pid as u64);
            PreprocessingMPCProtocol::<F, RobustShare<F>, FakeNetwork>::run_preprocessing(
                &mut node, net, &mut rng,
            )
            .await
            .expect("preprocessing failed");
        }));
    }
    for handle in handles {
        handle.await.unwrap();
    }

    for (pid, node) in nodes.iter_mut().enumerate() {
        let masks = node
            .preprocessing_material
            .lock()
            .await
            .take_random_shares(2)
            .expect("no input masks");
        node.preprocess
            .input
            .init(input_client, masks, 2, network[pid].clone())
            .await
            .expect("input init failed");
    }

    let mut out = Vec::with_capacity(n_parties);
    for node in nodes.iter_mut() {
        let store = node
            .preprocess
            .input
            .wait_for_all_inputs(Duration::from_secs(30))
            .await
            .expect("input never completed");
        let inputs = store.get(&input_client).expect("no inputs for client");
        out.push((inputs[0].clone(), inputs[1].clone()));
    }
    out
}

/// Steps 2..6 on one party: `mul -> a2b -> gf_mul/XOR/NOT -> b2a -> mul`.
///
/// Returned as `(a2b_bits, final_share)` so the caller can make the bit-level provenance
/// assertion as well as the end-to-end one.
async fn run_online_circuit(
    mut node: Node,
    net: Arc<FakeNetwork>,
    x: RobustShare<F>,
    y: RobustShare<F>,
) -> (Vec<Vec<GfShare<K>>>, RobustShare<F>) {
    // 2. ARITHMETIC multiply -- consumes a Beaver triple.
    let z = node
        .mul(vec![x.clone()], vec![y], net.clone())
        .await
        .expect("first arithmetic mul failed");

    // 3. A2B on a share that came *out of a multiplication*.
    let bits = node
        .a2b(z, net.clone())
        .await
        .expect("a2b of a mul output failed");
    let b = &bits[0];

    // 4a. BINARY multiplicative layer: one AND per bit position, all W ANDs in one wave.
    let lhs: Vec<GfShare<K>> = (0..W).map(|i| b[i].clone()).collect();
    let rhs: Vec<GfShare<K>> = (0..W).map(|i| b[(i + 1) % W].clone()).collect();
    let and = node
        .gf_mul(lhs, rhs, net.clone())
        .await
        .expect("binary AND layer failed");

    // 4b. BINARY linear ops, both local and neither costing a round: XOR is share addition,
    //     NOT is addition of the public constant `1`.
    //     `GfShare`'s `Add` rejects a degree or index mismatch, so these two lines are also the
    //     assertion that `gf_mul` handed back a degree-`t` sharing at this party's own index --
    //     a binary multiplicative output that did not agree with the A2B bits it is being
    //     combined with cannot reach `b2a` silently.
    let final_bits: Vec<GfShare<K>> = (0..W)
        .map(|i| {
            let xor = (and[i].clone() + b[i].clone())
                .expect("AND output does not match the A2B bit it is XORed with");
            (xor + K::one()).expect("NOT by public constant")
        })
        .collect();

    // 5. B2A back to the arithmetic domain.
    let v = node
        .b2a(vec![final_bits], net.clone())
        .await
        .expect("b2a failed");

    // 6. A second ARITHMETIC multiply, on the B2A output, against the original client input.
    let out = node
        .mul(v, vec![x], net.clone())
        .await
        .expect("second arithmetic mul failed");

    (bits, out[0].clone())
}

/// Step 7: every server opens its share to `output_client`, which reconstructs.
async fn reveal(
    nodes: &[Node],
    network: &[Arc<FakeNetwork>],
    clients: &mut HashMap<ClientId, HoneyBadgerMPCClient<F, Avid<SessionId>>>,
    output_client: ClientId,
    shares: &[RobustShare<F>],
) -> Vec<F> {
    for (pid, node) in nodes.iter().enumerate() {
        node.output
            .init(
                output_client,
                vec![shares[pid].clone()],
                1,
                network[pid].clone(),
            )
            .await
            .expect("output init failed");
    }
    clients
        .get_mut(&output_client)
        .unwrap()
        .output
        .wait_for_output(Duration::from_secs(30))
        .await
        .expect("client failed to reconstruct output")
}

// ---------------------------------------------------------------------------------------------
// The honest tests
// ---------------------------------------------------------------------------------------------

async fn mixed_circuit_e2e(n_parties: usize, t: usize, instance_id: u32) {
    setup_tracing();

    let input_client: ClientId = 100;
    let output_client: ClientId = 200;
    let client_ids = vec![input_client, output_client];

    let (network, receivers, client_net, client_recv) = test_setup(n_parties, client_ids.clone());
    let mut nodes = nodes_for(n_parties, t, instance_id, vec![input_client]);
    // Built one at a time rather than through `create_clients`: that helper gives every client
    // the same `input_len`, and here the two clients have genuinely different shapes -- the input
    // client supplies two values, the output client receives one. Sizing the output client at 2
    // makes it reject every share it is sent with `Mismatch in input and share length` and then
    // time out, which is a confusing way to discover a one-value circuit.
    let mut clients: HashMap<ClientId, HoneyBadgerMPCClient<F, Avid<SessionId>>> = HashMap::new();
    clients.insert(
        input_client,
        HoneyBadgerMPCClient::new(
            input_client,
            n_parties,
            t,
            instance_id,
            vec![F::from(X_CLEAR), F::from(Y_CLEAR)],
            2,
        )
        .unwrap(),
    );
    clients.insert(
        output_client,
        HoneyBadgerMPCClient::new(output_client, n_parties, t, instance_id, Vec::new(), 1).unwrap(),
    );

    receive::<F, Avid<SessionId>, RobustShare<F>, FakeNetwork>(
        receivers,
        nodes.clone(),
        network.clone(),
        Some(client_ids.clone()),
    );
    receive_client(client_recv, clients.clone(), client_net);

    install_prss_keys(&mut nodes, &network).await;
    let inputs = run_input_phase(&mut nodes, &network, input_client).await;

    let mut handles = Vec::new();
    for pid in 0..n_parties {
        let node = nodes[pid].clone();
        let net = network[pid].clone();
        let (x, y) = inputs[pid].clone();
        handles.push(tokio::spawn(async move {
            run_online_circuit(node, net, x, y).await
        }));
    }

    let mut per_party_bits = Vec::with_capacity(n_parties);
    let mut final_shares = Vec::with_capacity(n_parties);
    for handle in handles {
        let (bits, share) = handle.await.expect("a party's online circuit panicked");
        per_party_bits.push(bits);
        final_shares.push(share);
    }

    let (z, _, _, v, expected) = clear_circuit(X_CLEAR, Y_CLEAR);

    // Provenance, at the bit: the A2B input was a multiplication output.
    assert_bits(&per_party_bits, F::from(z), n_parties, t);
    assert_high_bits_zero(&per_party_bits, n_parties, t);

    // Step 7: the output path, which is where a real consumer ends.
    let revealed = reveal(&nodes, &network, &mut clients, output_client, &final_shares).await;
    assert_eq!(revealed.len(), 1, "expected exactly one revealed value");
    assert_eq!(
        revealed[0],
        F::from(expected),
        "mixed circuit revealed {} ({:?}), expected {expected} (z = {z}, v = {v})",
        f_to_u64(revealed[0]),
        revealed[0]
    );

    assert_every_track_ran(&nodes).await;

    // Every conversion store the circuit touched is retired, and both drain-only pools are empty
    // of exactly what the circuit spent -- a conversion that leaked a session or forgot to drain
    // would show up here and nowhere in the answer.
    for (pid, node) in nodes.iter().enumerate() {
        assert_eq!(node.conv.a2b.store_len().await, 0, "node {pid}: a2b store");
        assert_eq!(
            node.conv.a2b.open.store_len().await,
            0,
            "node {pid}: a2b open store"
        );
        assert_eq!(
            node.conv.a2b.gf_mul.store_len().await,
            0,
            "node {pid}: a2b gf_mul store"
        );
        assert_eq!(node.conv.b2a.store_len().await, 0, "node {pid}: b2a store");
        assert_eq!(
            node.conv.b2a.gf_open.store_len().await,
            0,
            "node {pid}: b2a gf_open store"
        );
    }
}

/// `n = 4`, `t = 1`: the smallest committee the threshold rule admits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mixed_circuit_e2e_n4_t1() {
    mixed_circuit_e2e(4, 1, 701).await;
}

/// `n = 10`, `t = 3`: the size at which batch reconstruction is the cheaper opening and at which
/// `2t + 1 = 7` shares is a genuine quorum rather than the whole committee.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mixed_circuit_e2e_n10_t3() {
    mixed_circuit_e2e(10, 3, 702).await;
}

// ---------------------------------------------------------------------------------------------
// Concurrency: the two tracks interleaved rather than merely alternating
// ---------------------------------------------------------------------------------------------

/// The conversion and an independent arithmetic multiplication, **in flight at the same time on
/// the same node**.
///
/// `mixed_circuit_e2e` runs the tracks strictly in sequence, which exercises composition but not
/// contention: every pool draw and every session-id mint is separated in time from the next, so a
/// collision between the arithmetic and binary tracks has no opportunity to occur. Here `a2b` and
/// a second `mul` are driven from two clones of the same node concurrently, so their
/// `SubProtocolCounters` mints, their `BatchRecon`/`GfBatchRecon` child sessions and -- when
/// either finds its pool short -- their preprocessing top-ups off the one `PrssAllocator`
/// interleave arbitrarily.
///
/// The assertion is that *both* results are right: the conversion still decomposes `z`, and the
/// concurrent multiplication still returns `x * x`.
async fn mixed_circuit_concurrent(n_parties: usize, t: usize, instance_id: u32) {
    setup_tracing();

    let input_client: ClientId = 100;
    let output_client: ClientId = 200;
    let client_ids = vec![input_client, output_client];

    let (network, receivers, client_net, client_recv) = test_setup(n_parties, client_ids.clone());
    let mut nodes = nodes_for(n_parties, t, instance_id, vec![input_client]);
    // One extra triple group: the concurrent multiplication is a third `mul` on top of the
    // circuit's two, and this test is about contention, not about `NotEnoughPreprocessing`.
    for node in &mut nodes {
        node.params.n_triples = 2 * (2 * t + 1);
        node.params.n_random_shares = 2 * node.params.n_triples + 2;
    }

    let mut clients: HashMap<ClientId, HoneyBadgerMPCClient<F, Avid<SessionId>>> = HashMap::new();
    clients.insert(
        input_client,
        HoneyBadgerMPCClient::new(
            input_client,
            n_parties,
            t,
            instance_id,
            vec![F::from(X_CLEAR), F::from(Y_CLEAR)],
            2,
        )
        .unwrap(),
    );
    clients.insert(
        output_client,
        HoneyBadgerMPCClient::new(output_client, n_parties, t, instance_id, Vec::new(), 1).unwrap(),
    );

    receive::<F, Avid<SessionId>, RobustShare<F>, FakeNetwork>(
        receivers,
        nodes.clone(),
        network.clone(),
        Some(client_ids.clone()),
    );
    receive_client(client_recv, clients.clone(), client_net);

    install_prss_keys(&mut nodes, &network).await;
    let inputs = run_input_phase(&mut nodes, &network, input_client).await;

    let mut handles = Vec::new();
    for pid in 0..n_parties {
        let node = nodes[pid].clone();
        let net = network[pid].clone();
        let (x, y) = inputs[pid].clone();
        handles.push(tokio::spawn(async move {
            // Step 2 first: the conversion needs its output.
            let mut lead = node.clone();
            let z = lead
                .mul(vec![x.clone()], vec![y], net.clone())
                .await
                .expect("first arithmetic mul failed");

            // Now the two tracks, together. Two clones of one node: the stores, pools, counters
            // and allocator behind them are the same `Arc`s.
            let conv_fut = {
                let mut node = node.clone();
                let net = net.clone();
                let z = z.clone();
                let x = x.clone();
                async move {
                    let bits = node.a2b(z, net.clone()).await.expect("a2b failed");
                    let b = &bits[0];
                    let lhs: Vec<GfShare<K>> = (0..W).map(|i| b[i].clone()).collect();
                    let rhs: Vec<GfShare<K>> = (0..W).map(|i| b[(i + 1) % W].clone()).collect();
                    let and = node
                        .gf_mul(lhs, rhs, net.clone())
                        .await
                        .expect("AND layer failed");
                    let final_bits: Vec<GfShare<K>> = (0..W)
                        .map(|i| {
                            let xor = (and[i].clone() + b[i].clone()).expect("XOR");
                            (xor + K::one()).expect("NOT")
                        })
                        .collect();
                    let v = node
                        .b2a(vec![final_bits], net.clone())
                        .await
                        .expect("b2a failed");
                    let out = node.mul(v, vec![x], net).await.expect("final mul failed");
                    (bits, out[0].clone())
                }
            };
            let arith_fut = {
                let mut node = node.clone();
                let net = net.clone();
                let x = x.clone();
                async move {
                    node.mul(vec![x.clone()], vec![x], net)
                        .await
                        .expect("concurrent arithmetic mul failed")
                }
            };

            let ((bits, out), squared) = tokio::join!(conv_fut, arith_fut);
            (bits, out, squared[0].clone())
        }));
    }

    let mut per_party_bits = Vec::with_capacity(n_parties);
    let mut final_shares = Vec::with_capacity(n_parties);
    let mut squared_shares = Vec::with_capacity(n_parties);
    for handle in handles {
        let (bits, out, squared) = handle.await.expect("a party's circuit panicked");
        per_party_bits.push(bits);
        final_shares.push(out);
        squared_shares.push(squared);
    }

    let (z, _, _, _, expected) = clear_circuit(X_CLEAR, Y_CLEAR);
    assert_bits(&per_party_bits, F::from(z), n_parties, t);

    // The concurrent arithmetic multiplication is correct too -- it must not have had a triple,
    // a session id or a PRSS position taken out from under it by the conversion.
    let (_, squared) =
        RobustShare::recover_secret(&squared_shares[0..=2 * t], n_parties, t).unwrap();
    assert_eq!(
        squared,
        F::from(X_CLEAR * X_CLEAR),
        "the multiplication run concurrently with the conversion returned the wrong value"
    );

    let revealed = reveal(&nodes, &network, &mut clients, output_client, &final_shares).await;
    assert_eq!(
        revealed[0],
        F::from(expected),
        "mixed circuit under concurrency revealed {}, expected {expected}",
        f_to_u64(revealed[0])
    );

    for (pid, node) in nodes.iter().enumerate() {
        assert_eq!(
            node.counters.mul_counter.peek().await,
            Some(3),
            "node {pid}: expected three multiplications (two in the circuit, one concurrent)"
        );
        assert_eq!(node.counters.a2b_counter.peek().await, Some(1));
        assert_eq!(node.counters.b2a_counter.peek().await, Some(1));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mixed_circuit_with_concurrent_arithmetic_n4_t1() {
    mixed_circuit_concurrent(4, 1, 703).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mixed_circuit_with_concurrent_arithmetic_n10_t3() {
    mixed_circuit_concurrent(10, 3, 704).await;
}

// ---------------------------------------------------------------------------------------------
// Byzantine: t parties send shares off the polynomial in every ONLINE opening
// ---------------------------------------------------------------------------------------------

/// Which session tags a corrupt party is allowed to attack.
///
/// The phase boundary is load-bearing and this is where the test respects it. Steps 2..6 are
/// ONLINE -- asynchronous, robust, guaranteed output delivery, degree-`t` openings only -- so a
/// corrupt share there must be *decoded through*, never aborted on. Preprocessing is
/// SYNCHRONOUS and may abort, and its openings are legally degree-`2t`, where `t` error symbols
/// are not correctable; attacking `Dn07`/`GfDn07`/`GfTriple`/`DaBit*` would therefore be testing
/// a robustness property the protocol does not claim, and would fail for the right reason in a
/// way that told us nothing. The `Input` and `Output` protocols are likewise out of scope: they
/// ride RBC, are steps 1 and 7 rather than "step 2 onward", and have their own tests.
///
/// `None` from `calling_protocol()` is *not* tampered: an untagged session is not identifiably
/// online.
fn is_online_tag(tag: Option<ProtocolType>) -> bool {
    matches!(
        tag,
        Some(ProtocolType::Mul)          // step 2 and step 6, and the concurrent multiplication
            | Some(ProtocolType::A2B)     // step 3's degree-t mask opening
            | Some(ProtocolType::A2BGfMul) // step 3's AND layers
            | Some(ProtocolType::GfMul)   // step 4's AND layer, the caller's own
            | Some(ProtocolType::B2A) // step 5's degree-t K-side opening
    )
}

/// Per-track tamper tally, so the test can prove the attack reached *both* the arithmetic and the
/// binary halves rather than only whichever one happened to open first.
#[derive(Default)]
struct TamperTally {
    arithmetic: AtomicUsize,
    binary: AtomicUsize,
}

impl TamperTally {
    fn record(&self, tag: Option<ProtocolType>) {
        match tag {
            Some(ProtocolType::Mul) | Some(ProtocolType::A2B) => {
                self.arithmetic.fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.binary.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    fn arithmetic(&self) -> usize {
        self.arithmetic.load(Ordering::Relaxed)
    }
    fn binary(&self) -> usize {
        self.binary.load(Ordering::Relaxed)
    }
}

/// Moves every field element in an online opening off the polynomial by `+1`.
///
/// `sender` and `session_id` are left exactly as they were, deliberately. `HoneyBadgerMPCNode`
/// rejects a message whose envelope sender does not match the transport party, and both wire
/// bodies have already had `id`/`degree` *removed* in favour of receiver-derived values -- so a
/// tampered body still arrives correctly attributed, at the right degree, and reaches the robust
/// decoder as a genuine error symbol rather than being thrown out by an authentication check.
/// That is the point: this must test the decode, not the sender check.
///
/// Returns `None` when the message is not an in-scope online opening, in which case the original
/// bytes are delivered untouched.
fn tamper(raw: &[u8], corrupt: &[usize], tally: &TamperTally) -> Option<Vec<u8>> {
    use stoffelcrypto::common::ShamirShareWire;
    use stoffelcrypto::honeybadger::batch_recon::BatchReconMsgType;
    use stoffelcrypto::honeybadger::gf_batch_recon::GfBatchReconMsgType;
    use stoffelcrypto::honeybadger::gf_mul::GfMultReconstructionMessage;
    use stoffelcrypto::honeybadger::mul::ReconstructionMessage;

    let wrapped: WrappedMessage = bincode::deserialize(raw).ok()?;

    let bump_f = |w: &ShamirShareWire<F, 1>| {
        ShamirShareWire::<F, 1>::from_elements(
            w.elements().iter().map(|&e| e + F::from(1u64)).collect(),
        )
    };
    let bump_k = |w: &stoffelcrypto::common::gf2k::share::GfShareWire<K>| {
        stoffelcrypto::common::gf2k::share::GfShareWire::<K>::from_elements(
            w.elements().iter().map(|&e| e + K::one()).collect(),
        )
    };

    match wrapped {
        WrappedMessage::BatchRecon(mut m) => {
            if !corrupt.contains(&m.sender_id) || !is_online_tag(m.session_id.calling_protocol()) {
                return None;
            }
            let mut payload = Vec::new();
            match m.msg_type {
                BatchReconMsgType::Eval | BatchReconMsgType::Reveal => {
                    let v = F::deserialize_compressed(&m.payload[..]).ok()?;
                    (v + F::from(1u64))
                        .serialize_compressed(&mut payload)
                        .ok()?;
                }
                BatchReconMsgType::EvalBatch | BatchReconMsgType::RevealBatch => {
                    let v = Vec::<F>::deserialize_compressed(&m.payload[..]).ok()?;
                    let v: Vec<F> = v.into_iter().map(|e| e + F::from(1u64)).collect();
                    v.serialize_compressed(&mut payload).ok()?;
                }
            }
            tally.record(m.session_id.calling_protocol());
            m.payload = payload;
            bincode::serialize(&WrappedMessage::BatchRecon(m)).ok()
        }
        WrappedMessage::GfBatchRecon(mut m) => {
            if !corrupt.contains(&m.sender_id) || !is_online_tag(m.session_id.calling_protocol()) {
                return None;
            }
            let payload = match m.msg_type {
                GfBatchReconMsgType::Eval | GfBatchReconMsgType::Reveal => {
                    let v: K = bincode::deserialize(&m.payload).ok()?;
                    bincode::serialize(&(v + K::one())).ok()?
                }
                GfBatchReconMsgType::EvalBatch | GfBatchReconMsgType::RevealBatch => {
                    let v: Vec<K> = bincode::deserialize(&m.payload).ok()?;
                    let v: Vec<K> = v.into_iter().map(|e| e + K::one()).collect();
                    bincode::serialize(&v).ok()?
                }
            };
            tally.record(m.session_id.calling_protocol());
            m.payload = payload;
            bincode::serialize(&WrappedMessage::GfBatchRecon(m)).ok()
        }
        WrappedMessage::Mult(mut m) => {
            if !corrupt.contains(&m.sender) || !is_online_tag(m.session_id.calling_protocol()) {
                return None;
            }
            let inner = ReconstructionMessage::<F>::deserialize_compressed(&m.payload[..]).ok()?;
            let inner = ReconstructionMessage::<F> {
                a_sub_x: bump_f(&inner.a_sub_x),
                b_sub_y: bump_f(&inner.b_sub_y),
            };
            let mut payload = Vec::new();
            inner.serialize_compressed(&mut payload).ok()?;
            tally.record(m.session_id.calling_protocol());
            m.payload = payload;
            bincode::serialize(&WrappedMessage::Mult(m)).ok()
        }
        WrappedMessage::GfMult(mut m) => {
            if !corrupt.contains(&m.sender) || !is_online_tag(m.session_id.calling_protocol()) {
                return None;
            }
            let inner: GfMultReconstructionMessage<K> = bincode::deserialize(&m.payload).ok()?;
            let inner = GfMultReconstructionMessage::<K> {
                a_sub_x: bump_k(&inner.a_sub_x),
                b_sub_y: bump_k(&inner.b_sub_y),
            };
            tally.record(m.session_id.calling_protocol());
            m.payload = bincode::serialize(&inner).ok()?;
            bincode::serialize(&WrappedMessage::GfMult(m)).ok()
        }
        _ => None,
    }
}

/// `test_utils::receive`, with a man-in-the-middle on every inbound message.
///
/// Written here rather than added to `test_utils` because it is this file's threat model, not a
/// shared fixture: the scoping in `is_online_tag` is the whole argument, and a shared helper
/// would invite a caller to reuse it across the phase boundary.
fn receive_tampering(
    mut receivers: Vec<Vec<tokio::sync::mpsc::Receiver<Vec<u8>>>>,
    mut nodes: Vec<Node>,
    net: Vec<Arc<FakeNetwork>>,
    client_ids: Vec<ClientId>,
    corrupt: Vec<usize>,
    tally: Arc<TamperTally>,
) {
    let n_len = nodes.len();
    for i in 0..n_len {
        let inbox_row = receivers.remove(0);
        let mut node = nodes.remove(0);
        let net_clone = net[i].clone();
        let corrupt = corrupt.clone();
        let tally = Arc::clone(&tally);

        let mut labeled = Vec::with_capacity(inbox_row.len());
        for (idx, rx) in inbox_row.into_iter().enumerate() {
            if idx < n_len {
                labeled.push((SenderId::Node(idx), rx));
            } else {
                labeled.push((SenderId::Client(client_ids[idx - n_len]), rx));
            }
        }
        let mut merged_rx = fan_in_inboxes(labeled);

        tokio::spawn(async move {
            while let Some((sender, raw)) = merged_rx.recv().await {
                let id = match sender {
                    SenderId::Node(i) => i,
                    SenderId::Client(i) => i,
                };
                let raw = tamper(&raw, &corrupt, &tally).unwrap_or(raw);
                if let Err(e) = node.process(id, raw, net_clone.clone()).await {
                    // Not a panic: a corrupt share reaching a store that has already decoded is
                    // an expected, tolerated outcome, and the assertion this test makes is about
                    // the *result*, not about every message being individually accepted.
                    tracing::debug!("node {i} could not process a message from {sender:?}: {e:?}");
                }
            }
        });
    }
}

/// **The robustness claim, on the composed circuit.**
///
/// `t` parties send every ONLINE opening off the polynomial -- both `a - x`/`b - y` remainders in
/// the arithmetic multiplications, both rounds of every degree-`t` batch reconstruction, and both
/// the `F`-side and `K`-side openings the two conversions perform. Guaranteed output delivery
/// says this must not stop anything: the honest parties still produce the *correct* cleartext,
/// and nothing aborts or times out.
///
/// Note what is *not* asserted: that no error is logged. Robust interpolation reaching a decode
/// after discarding error symbols is the mechanism, and individual rejected messages on the way
/// there are normal. The claim is about the result.
async fn mixed_circuit_byzantine(n_parties: usize, t: usize, instance_id: u32) {
    setup_tracing();

    let input_client: ClientId = 100;
    let output_client: ClientId = 200;
    let client_ids = vec![input_client, output_client];
    // The *low* indices, on purpose. The fan-in delivers roughly in sender order, so corrupting
    // 0..t-1 puts every error symbol inside the first `2t + 1` arrivals and forces the decoder to
    // actually correct them; corrupting the high indices often lets a clean quorum land first and
    // the attack never bites.
    let corrupt: Vec<usize> = (0..t).collect();
    let honest: Vec<usize> = (t..n_parties).collect();
    assert!(
        honest.len() >= 2 * t + 1,
        "the test must leave a full degree-t quorum of honest parties: {} honest, need {}",
        honest.len(),
        2 * t + 1
    );

    let (network, receivers, client_net, client_recv) = test_setup(n_parties, client_ids.clone());
    let mut nodes = nodes_for(n_parties, t, instance_id, vec![input_client]);

    let mut clients: HashMap<ClientId, HoneyBadgerMPCClient<F, Avid<SessionId>>> = HashMap::new();
    clients.insert(
        input_client,
        HoneyBadgerMPCClient::new(
            input_client,
            n_parties,
            t,
            instance_id,
            vec![F::from(X_CLEAR), F::from(Y_CLEAR)],
            2,
        )
        .unwrap(),
    );
    clients.insert(
        output_client,
        HoneyBadgerMPCClient::new(output_client, n_parties, t, instance_id, Vec::new(), 1).unwrap(),
    );

    let tally = Arc::new(TamperTally::default());
    receive_tampering(
        receivers,
        nodes.clone(),
        network.clone(),
        client_ids.clone(),
        corrupt.clone(),
        Arc::clone(&tally),
    );
    receive_client(client_recv, clients.clone(), client_net);

    // Preprocessing and input run unattacked -- see `is_online_tag` for why that is the threat
    // model and not a convenience.
    install_prss_keys(&mut nodes, &network).await;
    let inputs = run_input_phase(&mut nodes, &network, input_client).await;

    let mut handles = Vec::new();
    for pid in 0..n_parties {
        let node = nodes[pid].clone();
        let net = network[pid].clone();
        let (x, y) = inputs[pid].clone();
        handles.push(tokio::spawn(async move {
            run_online_circuit(node, net, x, y).await
        }));
    }

    let mut per_party_bits = Vec::with_capacity(n_parties);
    let mut final_shares = Vec::with_capacity(n_parties);
    for handle in handles {
        // No party is allowed to fail. Guaranteed output delivery is a promise to the honest
        // parties, and the corrupt ones here are honest-but-tampered-in-flight, so they complete
        // too; a panic on any of them means the attack caused an abort, which is the failure this
        // test exists to detect.
        let (bits, share) = handle.await.expect("a party aborted under attack");
        per_party_bits.push(bits);
        final_shares.push(share);
    }

    // The attack really fired, in both halves of the circuit. Without this a typo in `tamper`
    // would make the whole test pass by never attacking anything.
    assert!(
        tally.arithmetic() > 0,
        "no arithmetic-track opening was tampered: the attack never fired on mul/A2B"
    );
    assert!(
        tally.binary() > 0,
        "no binary-track opening was tampered: the attack never fired on gf_mul/B2A"
    );

    let (z, _, _, _, expected) = clear_circuit(X_CLEAR, Y_CLEAR);

    // A2B still decomposed the multiplication output correctly, bit for bit, reading only the
    // honest parties' shares.
    let honest_bits: Vec<Vec<Vec<GfShare<K>>>> =
        honest.iter().map(|&p| per_party_bits[p].clone()).collect();
    assert_bits(&honest_bits, F::from(z), n_parties, t);

    // And the honest parties' final shares lie on one degree-`t` polynomial through the right
    // value -- checked before the reveal, so a failure is attributed to the circuit rather than
    // to the output protocol.
    let honest_finals: Vec<RobustShare<F>> =
        honest.iter().map(|&p| final_shares[p].clone()).collect();
    let (coeffs, got) =
        RobustShare::recover_secret(&honest_finals[0..=2 * t], n_parties, t).unwrap();
    assert!(
        coeffs.len() <= t + 1,
        "the honest parties' result is not a degree-t sharing"
    );
    assert_eq!(
        got,
        F::from(expected),
        "under t corrupt online openers the honest parties computed {} instead of {expected}",
        f_to_u64(got)
    );

    // Step 7 as a real consumer sees it.
    let revealed = reveal(&nodes, &network, &mut clients, output_client, &final_shares).await;
    assert_eq!(
        revealed[0],
        F::from(expected),
        "under attack the client reconstructed {} instead of {expected}",
        f_to_u64(revealed[0])
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mixed_circuit_survives_t_corrupt_online_openers_n4_t1() {
    mixed_circuit_byzantine(4, 1, 705).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mixed_circuit_survives_t_corrupt_online_openers_n10_t3() {
    mixed_circuit_byzantine(10, 3, 706).await;
}

// ---------------------------------------------------------------------------------------------
// Regression witness for the defect this file found
// ---------------------------------------------------------------------------------------------
//
// `mixed_circuit_survives_t_corrupt_online_openers_*` failed on first run with
//
//     b2a failed: B2AError(MaterialLengthMismatch {
//         what: "opened GF(2^k) values", expected: 32, got: 24 })
//
// at both `n = 4, t = 1` and `n = 10, t = 3`. The cause was in `batch_recover_secret`, in both
// the `F` and `GF(2^k)` copies:
//
//   * its **fast path** (every chunk verifies against the optimistic Lagrange subset) builds a
//     `vec![zero; degree + 1]` and always returns exactly `degree + 1` coefficients;
//   * its **error-correction fallback** — the branch a corrupt share *forces* — returned
//     `recover_secret`'s own coefficient vector, which is the interpolated polynomial's
//     normalized `Poly::coeffs`. A chunk whose top secrets are zero has a lower-degree
//     polynomial and so came back **shorter** than `degree + 1`.
//
// Both batch-reconstruction handlers flatten those chunks at a fixed stride of `degree + 1`
// (`for coeffs in decoded { result.extend(coeffs) }`), so a short chunk truncated the batch *and
// shifted every later value down a slot*. The `F`-side handler even carries the comment
// "`batch_recover_secret` already resizes each chunk to `degree + 1`" — an invariant the code had
// stopped enforcing.
//
// Severity: this is on the ONLINE, robust, guaranteed-output-delivery path, and the trigger is
// adversarial — any corrupt share forces the fallback. B2A caught it only because it hard-checks
// the opened length, which converts the misalignment into a denial of output (itself a GOD
// violation: `t` parties could stop honest parties getting a result). A consumer that did not
// length-check, or a batch whose lengths happened to line up, would have taken silently
// misaligned plaintext. On B2A's own openings the values are bits, so roughly half of all chunks
// have a zero top secret and the truncation is near-certain rather than a corner case.
//
// Fix: `coeffs.resize(degree + 1, zero())` in the fallback branch of each copy, restoring the
// invariant the fast path already satisfied and both callers already assumed.
//
// These two tests pin it where it lives, so a regression is caught in microseconds by a unit
// assertion rather than in ten seconds by a Byzantine end-to-end run.

/// GF(2^k): the fallback branch must return `degree + 1` coefficients per chunk, as the fast
/// path does.
#[test]
fn gf_batch_recover_pads_short_fallback_chunks() {
    use stoffelcrypto::common::gf2k::get_or_create_gf2k_domain;
    use stoffelcrypto::common::gf2k::robust_interpolate::batch_recover_secret;

    let (n, t, degree) = (4usize, 1usize, 1usize);
    let domain = get_or_create_gf2k_domain::<K>(n).unwrap();

    // Chunk 0's secrets are `(1, 0)`: a degree-0 polynomial, which is what `Poly` normalizes
    // away. Chunk 1's are `(1, 1)` and stay full degree, so the assertion distinguishes
    // "everything is padded" from "nothing was truncated in the first place".
    let chunks = [(K::one(), K::zero()), (K::one(), K::one())];
    let mut evals: Vec<(usize, Vec<K>)> = (0..n)
        .map(|id| {
            let x = domain.element(id);
            (id, chunks.iter().map(|(c0, c1)| *c0 + *c1 * x).collect())
        })
        .collect();

    let clean = batch_recover_secret(&evals, n, degree, t).unwrap();
    for (c, coeffs) in clean.iter().enumerate() {
        assert_eq!(coeffs.len(), degree + 1, "fast path, chunk {c}");
    }

    // One corrupt sender (the bound allows `t = 1`) forces the error-correction fallback.
    evals[0].1 = evals[0].1.iter().map(|&e| e + K::one()).collect();
    let corrected = batch_recover_secret(&evals, n, degree, t).unwrap();
    for (c, coeffs) in corrected.iter().enumerate() {
        assert_eq!(
            coeffs.len(),
            degree + 1,
            "fallback path, chunk {c}: a short chunk truncates and misaligns the whole batch"
        );
    }
    assert_eq!(clean, corrected, "correction changed the recovered secrets");

    // The assembly `GfBatchReconNode`'s `RevealBatch` arm performs.
    let flat: Vec<K> = corrected.into_iter().flatten().collect();
    assert_eq!(flat.len(), chunks.len() * (degree + 1));
}

/// `F`: the same property, in the copy whose caller documents it as already holding.
#[test]
fn f_batch_recover_pads_short_fallback_chunks() {
    use ark_poly::EvaluationDomain;
    use stoffelcrypto::common::get_or_create_evaluation_domain;
    use stoffelcrypto::honeybadger::robust_interpolate::robust_interpolate::batch_recover_secret;

    let (n, t, degree) = (4usize, 1usize, 1usize);
    let domain = get_or_create_evaluation_domain::<F>(n).unwrap();

    let chunks = [
        (F::from(1u64), F::from(0u64)),
        (F::from(1u64), F::from(1u64)),
    ];
    let mut evals: Vec<(usize, Vec<F>)> = (0..n)
        .map(|id| {
            let x = domain.element(id);
            (id, chunks.iter().map(|(c0, c1)| *c0 + *c1 * x).collect())
        })
        .collect();

    let clean = batch_recover_secret(&evals, n, degree, t).unwrap();
    for (c, coeffs) in clean.iter().enumerate() {
        assert_eq!(coeffs.len(), degree + 1, "fast path, chunk {c}");
    }

    evals[0].1 = evals[0].1.iter().map(|&e| e + F::from(1u64)).collect();
    let corrected = batch_recover_secret(&evals, n, degree, t).unwrap();
    for (c, coeffs) in corrected.iter().enumerate() {
        assert_eq!(
            coeffs.len(),
            degree + 1,
            "fallback path, chunk {c}: a short chunk truncates and misaligns the whole batch"
        );
    }
    assert_eq!(clean, corrected, "correction changed the recovered secrets");
}
