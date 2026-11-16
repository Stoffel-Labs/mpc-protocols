//! Fixtures for the daBit tests in `dabit_test.rs`.
//!
//! Drives [`ReplicatedDaBitNode`] — the information-theoretic generator — over a real
//! `FakeNetwork`: the dealing, the echo, and the `F`-side XOR fold's degree-`2t` openings all
//! travel as messages. Only the double sharings the fold consumes are dealt by the test, because
//! `RanDouSha` is its own protocol with its own tests.
//!
//! Two checks here are deliberately strong:
//!
//! * **Degree is checked as *form*, never as metadata.** `RobustShare::degree` and
//!   `GfShare::degree` are caller-written `usize` fields. [`assert_degree_t_form`] interpolates
//!   each half at `0` from several different `t+1`-subsets of the `n` shares and requires every
//!   subset to agree with the robust reconstruction from all `n`.
//! * **Uniformity is a two-sided band**, not "the batch was not constant".
//!
//! # Phase: PREPROCESSING
//!
//! Synchronous, abort permitted. The adversarial tests rely on exactly that: a tampered dealing
//! must end in an error at every party it reaches, never in a daBit.

use std::sync::Arc;
use std::time::Duration;

use ark_ff::{Field, UniformRand};
use ark_poly::EvaluationDomain;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use stoffelcrypto::{
    common::{
        get_or_create_evaluation_domain,
        gf2k::{
            field::{BinaryField, Gf256, Gf2kDomain},
            share::GfShare,
        },
        share::shamir::NonRobustShare,
        ProtocolSessionId, SecretSharingScheme,
    },
    honeybadger::{
        batch_recon::BatchReconMsg,
        dabit::{replicated::ReplicatedDaBitNode, DaBit, DaBitError, DaBitMessage},
        double_share::DoubleShamirShare,
        robust_interpolate::robust_interpolate::RobustShare,
        ProtocolType, SessionId, WrappedMessage,
    },
};
use stoffelmpc_network::fake_network::{FakeNetwork, SenderId};
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinSet;
use tracing::warn;

use crate::utils::test_utils::{fan_in_inboxes, test_setup};

pub type F = ark_bls12_381::Fr;
pub type K = Gf256;
pub type Node = ReplicatedDaBitNode<F, K>;

/// Generous: an honest run finishes in milliseconds, and the adversarial tests pass their own.
pub const PROTOCOL_TIMEOUT: Duration = Duration::from_secs(120);

pub const INSTANCE: u32 = 0x0D_AB_C7;

/// Rewrites a dealing message on its way into `recipient`. Models a corrupt sender: the message
/// is authenticated as coming from `msg.sender_id`, and says whatever the hook makes it say.
pub type Tamper = Arc<dyn Fn(usize, &mut DaBitMessage) + Send + Sync>;

/// Rewrites an XOR-fold opening message on its way into `recipient`: a corrupt party lying about
/// its share of a degree-`2t` opening.
pub type OpenTamper = Arc<dyn Fn(usize, &mut BatchReconMsg) + Send + Sync>;

/// Deals `count` double sharings `([r]_t, [r]_2t)` of independent uniform `r`, one list per
/// party.
pub fn deal_doubles(
    count: usize,
    n: usize,
    t: usize,
    rng: &mut StdRng,
) -> Vec<Vec<DoubleShamirShare<F>>> {
    let mut per_party: Vec<Vec<DoubleShamirShare<F>>> = vec![Vec::with_capacity(count); n];
    for _ in 0..count {
        let r = F::rand(rng);
        let low = NonRobustShare::compute_shares(r, n, t, None, rng).expect("degree-t sharing");
        let high =
            NonRobustShare::compute_shares(r, n, 2 * t, None, rng).expect("degree-2t sharing");
        for (party, (l, h)) in low.into_iter().zip(high).enumerate() {
            per_party[party].push(DoubleShamirShare::new(l, h));
        }
    }
    per_party
}

/// `n` daBit nodes on one `FakeNetwork`, with a pump task per party.
pub struct DaBitHarness {
    pub n: usize,
    pub t: usize,
    nodes: Vec<Node>,
    network: Vec<Arc<FakeNetwork>>,
    rng: StdRng,
    next_exec: u64,
    _pump: JoinSet<()>,
}

impl DaBitHarness {
    pub fn new(n: usize, t: usize, seed: u64) -> Self {
        Self::with_tamper(n, t, seed, None)
    }

    pub fn with_tamper(n: usize, t: usize, seed: u64, tamper: Option<Tamper>) -> Self {
        Self::with_tampers(n, t, seed, tamper, None)
    }

    pub fn with_tampers(
        n: usize,
        t: usize,
        seed: u64,
        tamper: Option<Tamper>,
        open_tamper: Option<OpenTamper>,
    ) -> Self {
        let nodes: Vec<Node> = (0..n)
            .map(|id| Node::new(id, n, t).expect("daBit node construction"))
            .collect();
        let (network, receivers, _, _) = test_setup(n, vec![]);
        let pump = spawn_receivers(receivers, &nodes, &network, tamper, open_tamper);
        Self {
            n,
            t,
            nodes,
            network,
            rng: StdRng::seed_from_u64(seed),
            next_exec: 0,
            _pump: pump,
        }
    }

    pub fn node(&self, id: usize) -> &Node {
        &self.nodes[id]
    }

    /// One batch of `count` daBits at every party, on a fresh session.
    pub async fn generate(&mut self, count: usize) -> Vec<Result<Vec<DaBit<F, K>>, DaBitError>> {
        self.generate_within(count, PROTOCOL_TIMEOUT).await
    }

    pub async fn generate_within(
        &mut self,
        count: usize,
        duration: Duration,
    ) -> Vec<Result<Vec<DaBit<F, K>>, DaBitError>> {
        let per_dabit = self.nodes[0].doubles_per_dabit();
        let doubles = deal_doubles(count * per_dabit, self.n, self.t, &mut self.rng);
        let session_id = SessionId::new(
            ProtocolType::DaBit,
            SessionId::pack_slot(self.next_exec, 0, 0),
            INSTANCE,
        );
        self.next_exec += 1;

        let mut set: JoinSet<(usize, Result<Vec<DaBit<F, K>>, DaBitError>)> = JoinSet::new();
        for (party, node) in self.nodes.iter().enumerate() {
            let mut node = node.clone();
            let net = Arc::clone(&self.network[party]);
            let doubles = doubles[party].clone();
            set.spawn(async move {
                let out = node
                    .generate(session_id, count, doubles, duration, net)
                    .await;
                (party, out)
            });
        }

        let mut results: Vec<Option<Result<Vec<DaBit<F, K>>, DaBitError>>> =
            (0..self.n).map(|_| None).collect();
        while let Some(joined) = set.join_next().await {
            let (party, out) = joined.expect("a daBit generation task panicked");
            results[party] = Some(out);
        }
        results
            .into_iter()
            .enumerate()
            .map(|(party, r)| r.unwrap_or_else(|| panic!("party {party} never reported")))
            .collect()
    }
}

fn spawn_receivers(
    receivers: Vec<Vec<Receiver<Vec<u8>>>>,
    nodes: &[Node],
    network: &[Arc<FakeNetwork>],
    tamper: Option<Tamper>,
    open_tamper: Option<OpenTamper>,
) -> JoinSet<()> {
    let mut set = JoinSet::new();

    for (party, inboxes) in receivers.into_iter().enumerate() {
        let mut node = nodes[party].clone();
        let net = Arc::clone(&network[party]);
        let tamper = tamper.clone();
        let open_tamper = open_tamper.clone();
        let inbox: Vec<(SenderId, Receiver<Vec<u8>>)> = inboxes
            .into_iter()
            .enumerate()
            .map(|(sender, rx)| (SenderId::Node(sender), rx))
            .collect();
        let mut merged = fan_in_inboxes(inbox);

        set.spawn(async move {
            while let Some((envelope, bytes)) = merged.recv().await {
                let SenderId::Node(sender) = envelope else {
                    warn!("party {party} received a client message in a node-only test");
                    continue;
                };
                let wrapped: WrappedMessage = match bincode::deserialize(&bytes) {
                    Ok(w) => w,
                    Err(e) => {
                        warn!("party {party} could not deserialize a message: {e:?}");
                        continue;
                    }
                };
                match wrapped {
                    WrappedMessage::DaBit(mut msg) => {
                        if msg.sender_id != sender {
                            warn!("party {party} dropped a daBit message with a forged sender");
                            continue;
                        }
                        if let Some(hook) = tamper.as_ref() {
                            hook(party, &mut msg);
                        }
                        if let Err(e) = node.process(msg, Arc::clone(&net)).await {
                            warn!("party {party} daBit dealing error: {e:?}");
                        }
                    }
                    WrappedMessage::BatchRecon(mut msg) => {
                        match msg.session_id.calling_protocol() {
                            Some(ProtocolType::DaBitMul) => {
                                if msg.sender_id != sender {
                                    warn!("party {party} dropped an opening with a forged sender");
                                    continue;
                                }
                                if let Some(hook) = open_tamper.as_ref() {
                                    hook(party, &mut msg);
                                }
                                if let Err(e) =
                                    node.dn07.batch_recon.process(msg, Arc::clone(&net)).await
                                {
                                    warn!("party {party} XOR-fold opening error: {e:?}");
                                }
                                if let Err(e) = node.drain_mul_output().await {
                                    warn!("party {party} XOR-fold drain error: {e:?}");
                                }
                            }
                            other => {
                                warn!("party {party} saw a BatchRecon message tagged {other:?}")
                            }
                        }
                    }
                    other => warn!("party {party} saw an unexpected message: {other:?}"),
                }
            }
        });
    }

    set
}

/// Unwraps every party's batch, reporting *which* party failed and how.
pub fn expect_all_ok(results: Vec<Result<Vec<DaBit<F, K>>, DaBitError>>) -> Vec<Vec<DaBit<F, K>>> {
    results
        .into_iter()
        .enumerate()
        .map(|(party, r)| {
            r.unwrap_or_else(|e| panic!("party {party} daBit generation failed: {e:?}"))
        })
        .collect()
}

/// Requires every party to have failed, and hands back the errors for a variant check.
pub fn expect_all_err(results: Vec<Result<Vec<DaBit<F, K>>, DaBitError>>) -> Vec<DaBitError> {
    results
        .into_iter()
        .enumerate()
        .map(|(party, r)| match r {
            Ok(batch) => panic!(
                "party {party} produced {} daBits where the call had to be refused",
                batch.len()
            ),
            Err(e) => e,
        })
        .collect()
}

// -------------------------------------------------------------------------------------------
// The contract
// -------------------------------------------------------------------------------------------

/// Reconstructs every daBit in both domains and checks the primitive's defining property,
/// returning the batch's clear bits.
///
/// `per_party[party][nu]` is party `party`'s `nu`-th daBit.
///
/// * **T1 (domain).** Both halves carry the holder's own party index, and the two ids index
///   *unrelated* point sets — the `F` share sits on the FFT domain, the `K` share on the powers of
///   the `GF(2^k)` generator — so only the party index crosses, never an x-coordinate.
/// * **T3 (value).** The `F` secret is `0` or `1` as a field element; the `K` secret satisfies
///   `b^2 = b`, which in characteristic 2 holds exactly on the canonical `GF(2)` subfield.
/// * **The tie.** The two reconstruct to the same bit.
pub fn assert_same_bit_in_both_domains(
    per_party: &[Vec<DaBit<F, K>>],
    n: usize,
    t: usize,
) -> Vec<u64> {
    assert_eq!(per_party.len(), n, "one batch per party");
    let count = per_party[0].len();
    // Everything below is a loop over the batch, so an empty one would make the whole contract
    // pass vacuously.
    assert!(count > 0, "the batch was empty");
    for (party, dabits) in per_party.iter().enumerate() {
        assert_eq!(dabits.len(), count, "party {party} produced a short batch");
        for (nu, dabit) in dabits.iter().enumerate() {
            // T1. `DaBit::new` is the only constructor that enforces this, so a failure here
            // means something reached a consumer without going through it.
            assert_eq!(dabit.arith.id, party, "party {party} daBit {nu} arith id");
            assert_eq!(dabit.bin.id, party, "party {party} daBit {nu} bin id");
            assert_eq!(dabit.arith.id, dabit.bin.id, "daBit {nu} half indices");
        }
    }

    let mut bits = Vec::with_capacity(count);
    for nu in 0..count {
        let arith: Vec<RobustShare<F>> = (0..n).map(|p| per_party[p][nu].arith.clone()).collect();
        let bin: Vec<GfShare<K>> = (0..n).map(|p| per_party[p][nu].bin.clone()).collect();

        let (_, a) = RobustShare::recover_secret(&arith, n, t)
            .unwrap_or_else(|e| panic!("daBit {nu} arithmetic reconstruction failed: {e:?}"));
        let (_, b) = GfShare::recover_secret(&bin, n, t)
            .unwrap_or_else(|e| panic!("daBit {nu} binary reconstruction failed: {e:?}"));

        // T3 in `F`.
        let a_bit = if a == F::from(0u64) {
            0u64
        } else if a == F::from(1u64) {
            1u64
        } else {
            panic!("daBit {nu} arithmetic half reconstructed to {a:?}, which is not a bit");
        };
        // T3 in `K`: structural, a sum of `GF(2)` elements in characteristic 2.
        assert!(
            b.is_bit(),
            "daBit {nu} binary half reconstructed to {b:?}, which is not a bit"
        );
        let b_bit = u64::from(b != K::zero());

        assert_eq!(
            a_bit, b_bit,
            "daBit {nu} is {a_bit} in F but {b_bit} in K: the two halves are not the same bit"
        );
        bits.push(a_bit);
    }
    bits
}

/// **T2 (form), checked as form.** Every half really is a polynomial of degree at most `t`.
///
/// `RobustShare::degree` and `GfShare::degree` are dealer-written metadata; this instead
/// interpolates at `0` from `n - t` different `t+1`-subsets of the `n` shares (the rotations
/// `{j, j+1, .., j+t}`) and requires all of them to agree with each other and with the robust
/// reconstruction from all `n` shares. For a sharing of degree `d > t` two rotations agree only
/// if the interpolation error happens to vanish, so a single lifted coefficient is caught.
///
/// Applied to the whole batch it is `O(count * n * t^2)` field operations, which is why the callers
/// that use it stay at batch sizes in the tens.
pub fn assert_degree_t_form(per_party: &[Vec<DaBit<F, K>>], n: usize, t: usize) {
    let count = per_party[0].len();
    assert!(count > 0, "the batch was empty");
    // With one rotation the check degenerates into "the interpolation agrees with itself".
    assert!(
        n - t >= 2,
        "n={n} t={t} leaves too few t+1-subsets to compare"
    );
    let f_domain = get_or_create_evaluation_domain::<F>(n).expect("FFT domain");
    let k_domain = Gf2kDomain::<K>::new(n).expect("GF(2^k) domain");

    for nu in 0..count {
        let arith: Vec<RobustShare<F>> = (0..n).map(|p| per_party[p][nu].arith.clone()).collect();
        let bin: Vec<GfShare<K>> = (0..n).map(|p| per_party[p][nu].bin.clone()).collect();
        let (_, a) = RobustShare::recover_secret(&arith, n, t).expect("arith reconstruction");
        let (_, b) = GfShare::recover_secret(&bin, n, t).expect("binary reconstruction");

        for start in 0..(n - t) {
            let f_points: Vec<(F, F)> = (start..=start + t)
                .map(|j| (f_domain.element(j), arith[j].share[0]))
                .collect();
            assert_eq!(
                lagrange_at_zero_f(&f_points),
                a,
                "daBit {nu}: F shares {start}..={} interpolate to a different secret, so the \
                 arithmetic half is not a degree-{t} polynomial",
                start + t
            );

            let k_points: Vec<(K, K)> = (start..=start + t)
                .map(|j| (k_domain.element(j), bin[j].share))
                .collect();
            assert_eq!(
                lagrange_at_zero_k(&k_points),
                b,
                "daBit {nu}: K shares {start}..={} interpolate to a different secret, so the \
                 binary half is not a degree-{t} polynomial",
                start + t
            );
        }
    }
}

/// Lagrange interpolation of `(x, y)` pairs evaluated at `0`, over the prime field.
pub fn lagrange_at_zero_f(points: &[(F, F)]) -> F {
    let mut acc = F::from(0u64);
    for (j, (xj, yj)) in points.iter().enumerate() {
        let mut term = *yj;
        for (m, (xm, _)) in points.iter().enumerate() {
            if m == j {
                continue;
            }
            term *= *xm * (*xm - *xj).inverse().expect("distinct evaluation points");
        }
        acc += term;
    }
    acc
}

/// The same, over `GF(2^k)`, where subtraction is addition.
pub fn lagrange_at_zero_k(points: &[(K, K)]) -> K {
    let mut acc = K::zero();
    for (j, (xj, yj)) in points.iter().enumerate() {
        let mut term = *yj;
        for (m, (xm, _)) in points.iter().enumerate() {
            if m == j {
                continue;
            }
            term = term * *xm * (*xm - *xj).inverse().expect("distinct evaluation points");
        }
        acc = acc + term;
    }
    acc
}

/// A two-sided uniformity band on a batch's bits.
///
/// "Not constant" would pass for a batch that is 63 ones and one zero, which is not a usable
/// one-time pad. The band is four standard deviations of `Binomial(count, 1/2)` either side of
/// `count/2`, so a genuinely uniform batch fails it with probability about `2^-15` — and these
/// batches are seeded, so the only way to reach it is a change in the derivation.
pub fn assert_bits_look_uniform(bits: &[u64], label: &str) {
    let count = bits.len();
    assert!(count >= 32, "{label}: {count} bits is too small a sample");
    let ones = bits.iter().filter(|b| **b == 1).count();
    assert!(
        ones > 0 && ones < count,
        "{label}: the batch's {count} bits were constant ({ones} ones)"
    );
    // 4 sigma, sigma = sqrt(count)/2, kept in integers: |2*ones - count| <= 4*sqrt(count).
    let deviation = (2 * ones).abs_diff(count);
    let bound = 4.0 * (count as f64).sqrt();
    assert!(
        (deviation as f64) <= bound,
        "{label}: {ones} ones out of {count} is outside a four-sigma band around {}",
        count / 2
    );
}

/// Positions at which two equal-length bit vectors differ.
pub fn hamming(a: &[u64], b: &[u64]) -> usize {
    assert_eq!(a.len(), b.len(), "hamming distance of unequal lengths");
    a.iter().zip(b).filter(|(x, y)| x != y).count()
}

// -------------------------------------------------------------------------------------------
// Hand-dealt daBits, for the negative controls only
// -------------------------------------------------------------------------------------------

/// Deals `pairs.len()` daBits by hand, transposed so that `out[party][nu]` is party `party`'s
/// `nu`-th.
///
/// `pairs[nu] = (arith_value, bin_bit)`, and the two are deliberately *not* required to agree —
/// producing a pair that disagrees, or an arithmetic half that is not a bit at all, is the whole
/// point. The real generator cannot produce either (the tie is by construction), which is exactly
/// why the assertions that would catch them have to be shown to fire on something.
///
/// `degree` is the sharing degree, and is also what [`DaBit::new`] is given as the threshold, so
/// that a sharing above the protocol degree can be built at all.
pub fn deal_dabits(
    pairs: &[(u64, u8)],
    n: usize,
    degree: usize,
    rng: &mut StdRng,
) -> Vec<Vec<DaBit<F, K>>> {
    let mut per_party: Vec<Vec<DaBit<F, K>>> = vec![Vec::with_capacity(pairs.len()); n];
    for (arith_value, bin_bit) in pairs {
        let arith = RobustShare::compute_shares(F::from(*arith_value), n, degree, None, rng)
            .expect("dealing the arithmetic half");
        let secret = if *bin_bit == 0 { K::zero() } else { K::one() };
        let bin = GfShare::compute_shares(secret, n, degree, rng).expect("dealing the binary half");
        for (party, (a, b)) in arith.into_iter().zip(bin).enumerate() {
            per_party[party].push(DaBit::new(a, b, degree).expect("pairing the halves"));
        }
    }
    per_party
}
