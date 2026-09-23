//! Fixtures for the daBit **contract** tests in `dabit_test.rs`.
//!
//! # Division of labour with `prss_dabit_test.rs`
//!
//! `prss_dabit_test.rs` is the *generator's* end-to-end file: that the protocol runs over a real
//! network at `n = 4 / 7 / 10`, that a corrupt opener can neither change nor stall it, and that
//! the `beta` and `psi` keystreams are separated. This file is about the *object* the generator
//! emits — the contract every consumer (A2B, B2A, the edaBit composition) relies on — at the two
//! party counts a production deployment is sized for, plus the lifetime leak budget that caps how
//! many daBits one key family may ever produce.
//!
//! Three checks here are deliberately stronger than the generator file's equivalents:
//!
//! * **T2 is checked as *form*, never as metadata.** `RobustShare::degree` and `GfShare::degree`
//!   are dealer-written `usize` fields, so comparing them proves only that nobody overwrote a
//!   struct field. [`assert_degree_t_form`] interpolates each half at `0` from several different
//!   `t+1`-subsets of the `n` shares and requires every subset to agree with the robust
//!   reconstruction from all `n` — which is false for a sharing of any degree above `t`.
//! * **Uniformity is a two-sided band**, not "the batch was not constant".
//! * **Independence across batches is checked.** Two batches drawn at different `exec_id`s must
//!   not repeat their bits: that is the observable consequence of PRSS cursor monotonicity, and
//!   a rewound cursor is one of the three errors the plan flags as otherwise silent.
//!
//! # Phase: PREPROCESSING
//!
//! Everything here drives [`PrssDaBitNode`], which is a preprocessing-phase protocol. Its one
//! opening is nevertheless degree-`t` and robust, so nothing in this file exercises — or could
//! reach — a degree-`2t` opening, a timeout-driven abort, or a broadcast.
//!
//! # What is dealt, and what is not
//!
//! The PRSS key family and the `RandBit`s are dealt, exactly as in `prss_dabit_test.rs` and for
//! the same reason: `setup_prss_keys` is `PRandIntNode`'s protocol and `RandBit` rides `MulPub`,
//! and both have their own tests. Everything the daBit protocol itself does — both PRSS
//! conversions, the mask assembly, the `Mod2` opening over a real `FakeNetwork`, and the
//! public-affine step — is real.

use std::sync::Arc;
use std::time::Duration;

use ark_ff::Field;
use ark_poly::EvaluationDomain;
use ark_std::rand::{rngs::StdRng, Rng, SeedableRng};
use stoffelcrypto::{
    common::{
        get_or_create_evaluation_domain,
        gf2k::{
            field::{BinaryField, Gf256, Gf2kDomain},
            share::GfShare,
        },
        math::goldilocks::GoldilocksField,
        ProtocolSessionId, SecretSharingScheme,
    },
    honeybadger::{
        dabit::{
            prss_dabit::{PrssDaBitKeys, PrssDaBitNode},
            DaBit, DaBitError,
        },
        gf_prss::gf_prss::GfPrssKeys,
        prss::{prss::PrssKeys, PrssAllocator},
        robust_interpolate::robust_interpolate::RobustShare,
        ProtocolType, WrappedMessage,
    },
};
use stoffelmpc_network::fake_network::{FakeNetwork, SenderId};
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinSet;
use tracing::warn;

use crate::utils::prss_utils::deal_keys;
use crate::utils::test_utils::{fan_in_inboxes, test_setup};

pub type F = GoldilocksField;
pub type K = Gf256;
pub type Node = PrssDaBitNode<F, K>;

/// Generous: an in-process network in a debug build. Nothing in these tests is supposed to reach
/// it, so a run that takes this long has already failed.
pub const PROTOCOL_TIMEOUT: Duration = Duration::from_secs(120);

/// Instance id for this file's sessions. Distinct from `prss_dabit_test.rs`'s so that a stray
/// cross-file session id is visible in a log rather than plausible.
pub const INSTANCE: u32 = 0x0D_AB_C7;

// -------------------------------------------------------------------------------------------
// Dealt material
// -------------------------------------------------------------------------------------------

/// `count` degree-`t` sharings of genuine random bits, transposed so that `out[party][i]` is
/// party `party`'s share of bit `i`.
///
/// These stand in for `RandBit`'s output. Their *bit-ness* is what the daBit's `F` half inherits
/// (T3 by provenance), so they are dealt as real `0`/`1` sharings and never as arbitrary values.
pub fn deal_rand_bits(
    count: usize,
    n: usize,
    t: usize,
    rng: &mut StdRng,
) -> Vec<Vec<RobustShare<F>>> {
    let mut per_party: Vec<Vec<RobustShare<F>>> = vec![Vec::with_capacity(count); n];
    for _ in 0..count {
        let b: u64 = rng.gen::<bool>() as u64;
        let shares = RobustShare::compute_shares(F::from(b), n, t, None, rng)
            .expect("dealing a RandBit sharing failed");
        for (party, share) in shares.into_iter().enumerate() {
            per_party[party].push(share);
        }
    }
    per_party
}

// -------------------------------------------------------------------------------------------
// The harness
// -------------------------------------------------------------------------------------------

/// `n` daBit nodes over one `FakeNetwork`, with the `Mod2` message pump already running.
///
/// The pump is spawned once and kept for the lifetime of the harness so that several batches can
/// be run back to back against the *same* nodes — which is what makes the cross-batch
/// independence and lifetime-budget tests meaningful: `PrssDaBitNode::produced` is `Arc`-shared
/// across clones, so a cloned handle spends the same budget as the original.
pub struct DaBitHarness {
    pub n: usize,
    pub t: usize,
    nodes: Vec<Node>,
    /// One allocator per party, stamped with that party's own key-family fingerprint.
    ///
    /// This is the fixture's stand-in for the single allocator `setup_prss_keys` builds. Every
    /// party's starts at zero and every party claims in the same order, so the `exec_id` a batch
    /// lands on agrees across parties without anything being sent — which is exactly the property
    /// production relies on, and why the harness no longer lets a caller name the exec.
    allocs: Vec<PrssAllocator>,
    network: Vec<Arc<FakeNetwork>>,
    rng: StdRng,
    /// Aborted on drop, which is what `JoinSet` does anyway; named to make that deliberate.
    _pump: JoinSet<()>,
}

impl DaBitHarness {
    /// Builds `n` nodes at threshold `t`, deals them a PRSS key family, and starts the pump.
    ///
    /// `topup` is the `k` knob (`None` = the production default `ceil(log2 C(n,t)) - 3`);
    /// `statistical_security` is `kappa`. Both feed `DaBitLeakBudget`, and raising `kappa` is the
    /// only way to reach the lifetime cap inside a test: at the minimum `kappa = 40` the smallest
    /// budget any supported party count admits is `2^13` daBits.
    pub fn new(
        n: usize,
        t: usize,
        topup: Option<usize>,
        statistical_security: usize,
        seed: u64,
    ) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        let dealt = deal_keys(n, t, &mut rng);
        let mut allocs = Vec::with_capacity(n);
        let nodes: Vec<Node> = (0..n)
            .map(|id| {
                let mut node = Node::new(id, n, t, statistical_security, topup)
                    .expect("daBit node construction");
                let prss = PrssKeys::<F>::new(id, n, t, &dealt[id]).expect("F PRSS store");
                let gf_prss = GfPrssKeys::<K>::new(id, n, t, &dealt[id]).expect("K PRSS store");
                // Stamped with the key family it will be counted against, exactly as
                // `setup_prss_keys` does — a window from an allocator over other keys is refused.
                allocs.push(PrssAllocator::new(INSTANCE, prss.key_family_id()));
                node.install_keys(
                    PrssDaBitKeys::new(id, t, prss, gf_prss).expect("paired key stores"),
                );
                node
            })
            .collect();

        let (network, receivers, _, _) = test_setup(n, vec![]);
        let pump = spawn_receivers(receivers, &nodes, &network);

        Self {
            n,
            t,
            nodes,
            allocs,
            network,
            rng,
            _pump: pump,
        }
    }

    /// Read-only access to a node, for budget accounting.
    pub fn node(&self, id: usize) -> &Node {
        &self.nodes[id]
    }

    /// daBits party `0` has produced over its lifetime. The counter is per key family and shared
    /// across clones, so every party's is the same in an honest run.
    pub async fn produced(&self) -> u64 {
        self.nodes[0].produced().await
    }

    /// Runs one batch of `count` daBits, dealing the `count * (1 + k)` `RandBit`s it bills for.
    ///
    /// There is no `exec_id` parameter: the exec is minted by each party's `PrssAllocator` on the
    /// `DaBitSeed` cursor, one per call, in call order. A caller that could name the exec could
    /// name it twice, which is the reuse this whole discipline exists to make unrepresentable.
    ///
    /// Returns one result per party rather than panicking, so that a test can assert on the
    /// *error* — the lifetime budget's whole point is that exhaustion is a clean typed error.
    pub async fn generate(&mut self, count: usize) -> Vec<Result<Vec<DaBit<F, K>>, DaBitError>> {
        let per_dabit = self.nodes[0].rand_bits_per_dabit();
        let bits = deal_rand_bits(count * per_dabit, self.n, self.t, &mut self.rng);
        self.generate_with(count, bits).await
    }

    /// As [`Self::generate`], but with a caller-supplied `RandBit` bill — for the tests that check
    /// what happens when it does not match `count * (1 + k)`.
    ///
    /// Note that a rejected batch still **burns** its claimed range on every party: the claim
    /// precedes the length check, exactly as it does in production.
    pub async fn generate_with(
        &mut self,
        count: usize,
        rand_bits: Vec<Vec<RobustShare<F>>>,
    ) -> Vec<Result<Vec<DaBit<F, K>>, DaBitError>> {
        let mut set: JoinSet<(usize, Result<Vec<DaBit<F, K>>, DaBitError>)> = JoinSet::new();
        for (party, node) in self.nodes.iter().enumerate() {
            let mut node = node.clone();
            let net = Arc::clone(&self.network[party]);
            let bits = rand_bits[party].clone();
            let windows = self.allocs[party]
                .claim_dabit_batch(count, node.mask_bits())
                .await
                .expect("claiming a daBit batch");
            set.spawn(async move {
                let out = node.generate(windows, bits, PROTOCOL_TIMEOUT, net).await;
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

/// One receiver task per party, demultiplexing exactly the arm the node dispatcher routes to the
/// daBit generator: `BatchRecon` under [`ProtocolType::DaBitOpen`], each `process` immediately
/// followed by its drain.
///
/// Errors are logged rather than unwrapped. A late arrival for a session the peer has already
/// finished and retired is normal asynchronously, and an honest party must not be abortable by
/// one.
fn spawn_receivers(
    receivers: Vec<Vec<Receiver<Vec<u8>>>>,
    nodes: &[Node],
    network: &[Arc<FakeNetwork>],
) -> JoinSet<()> {
    let mut set = JoinSet::new();

    for (party, inboxes) in receivers.into_iter().enumerate() {
        let mut node = nodes[party].clone();
        let net = Arc::clone(&network[party]);
        let inbox: Vec<(SenderId, Receiver<Vec<u8>>)> = inboxes
            .into_iter()
            .enumerate()
            .map(|(sender, rx)| (SenderId::Node(sender), rx))
            .collect();
        let mut merged = fan_in_inboxes(inbox);

        set.spawn(async move {
            while let Some((envelope, bytes)) = merged.recv().await {
                let SenderId::Node(_) = envelope else {
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
                    WrappedMessage::BatchRecon(msg) => match msg.session_id.calling_protocol() {
                        Some(ProtocolType::DaBitOpen) => {
                            if let Err(e) = node.mod2.open.process(msg, Arc::clone(&net)).await {
                                warn!("party {party} Mod2 open error: {e:?}");
                            }
                            if let Err(e) = node.drain_open_output().await {
                                warn!("party {party} Mod2 drain error: {e:?}");
                            }
                        }
                        other => warn!("party {party} saw a BatchRecon message tagged {other:?}"),
                    },
                    other => warn!("party {party} saw an unexpected message: {other:?}"),
                }
            }
        });
    }

    set
}

// -------------------------------------------------------------------------------------------
// Result plumbing
// -------------------------------------------------------------------------------------------

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
