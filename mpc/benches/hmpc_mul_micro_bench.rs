//! Component micro-benchmarks for the HoneyBadger multiply hot path.
//!
//! Prices each primitive that `Multiply::init` + `BatchReconNode` + `finalize_mul` exercise, at
//! fixed `(n, t)`, so the end-to-end report can attribute wall-clock time to per-operation cost
//! multiplied by the measured call counts:
//!
//!   - `RobustShare::recover_secret` (honest / optimistic path)
//!   - `RobustShare::recover_secret` with `t` corrupted shares (forces the OEC/Gao fallback)
//!   - `make_vandermonde` + `apply_vandermonde` (the per-batch-recon encoding)
//!   - `GeneralEvaluationDomain::new(n)` (rebuilt on every recover_secret today)
//!   - share arithmetic `.mul(F)` / `- share` (the `finalize_mul` inner loop)
//!   - bincode of a `WrappedMessage::BatchRecon(Eval)` and ark-serialize of a `Vec<F>` reveal batch
//!
//! Run:  cargo bench -p stoffelcrypto --bench hmpc_mul_micro_bench

use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain,
    Polynomial,
};
use ark_serialize::CanonicalSerialize;
use ark_std::test_rng;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::ops::Mul;
use stoffelcrypto::common::{
    share::{apply_vandermonde, make_vandermonde},
    ProtocolSessionId, SecretSharingScheme, ShamirShare,
};
use stoffelcrypto::honeybadger::{
    batch_recon::{BatchReconMsg, BatchReconMsgType},
    robust_interpolate::robust_interpolate::{batch_recover_secret, Robust, RobustShare},
    ProtocolType, SessionId, WrappedMessage,
};

/// `(n, t)` configurations. `n >= 3t + 1` is required for Byzantine recovery.
const PARAMS: &[(usize, usize)] = &[(5, 1), (10, 3), (20, 6)];

/// Build `n` honest shares of a random degree-`t` polynomial, plus a corrupted copy with `t`
/// errors (forces the OEC/Gao path in `recover_secret`).
fn build_shares(n: usize, t: usize) -> (Vec<RobustShare<Fr>>, Vec<RobustShare<Fr>>) {
    let mut rng = test_rng();
    let secret = Fr::rand(&mut rng);
    let honest = RobustShare::compute_shares(secret, n, t, None, &mut rng).unwrap();
    let mut corrupted = honest.clone();
    for i in 0..t {
        corrupted[i].share[0] += Fr::from((i as u64) + 7);
    }
    (honest, corrupted)
}

fn bench_recover_secret(c: &mut Criterion) {
    let mut group = c.benchmark_group("recover_secret");
    for &(n, t) in PARAMS {
        let (honest, corrupted) = build_shares(n, t);
        group.bench_with_input(
            BenchmarkId::new("optimistic", format!("n{n}_t{t}")),
            &(n, t),
            |b, _| {
                b.iter(|| {
                    let _ = RobustShare::recover_secret(black_box(&honest), n, t).unwrap();
                })
            },
        );
        group.bench_with_input(
            BenchmarkId::new("oec_gao_corrupted", format!("n{n}_t{t}")),
            &(n, t),
            |b, _| {
                b.iter(|| {
                    let _ = RobustShare::recover_secret(black_box(&corrupted), n, t).unwrap();
                })
            },
        );
    }
    group.finish();
}

/// `batch_recover_secret` is the dominant per-round compute in the batched mul: it runs once on the
/// EvalBatch→RevealBatch transition and once on RevealBatch→done, per session, per node. This prices
/// the honest (optimistic) path at a fixed `batch_len` (number of (t+1)-chunks) matching a real mul
/// session size, so the matrix-flattening optimization can be measured in isolation.
fn bench_batch_recover(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_recover_secret");
    for &(n, t) in PARAMS {
        let degree = t;
        let batch_len = 16; // chunks — a 16·(t+1)-pair session (64 pairs at t=3, 32 at t=6)
        let mut rng = test_rng();
        let domain = GeneralEvaluationDomain::<Fr>::new(n).unwrap();
        let polys: Vec<DensePolynomial<Fr>> = (0..batch_len)
            .map(|_| DensePolynomial::<Fr>::rand(degree, &mut rng))
            .collect();
        // Per-sender evaluation vectors in the `(sender_id, values)` representation used by batch
        // reconstruction: `evals_by_sender[id].1[c]` = P_c(α_id).
        let evals_by_sender: Vec<(usize, Vec<Fr>)> = (0..n)
            .map(|id| {
                let x = domain.element(id);
                (id, polys.iter().map(|p| p.evaluate(&x)).collect())
            })
            .collect();

        group.bench_with_input(
            BenchmarkId::new("honest", format!("n{n}_t{t}_b{batch_len}")),
            &(n, t),
            |b, _| {
                b.iter(|| {
                    let _ = batch_recover_secret(
                        black_box(&evals_by_sender),
                        black_box(n),
                        black_box(degree),
                        black_box(t),
                    )
                    .unwrap();
                })
            },
        );
    }
    group.finish();
}

fn bench_vandermonde(c: &mut Criterion) {
    let mut group = c.benchmark_group("vandermonde");
    for &(n, t) in PARAMS {
        let mut rng = test_rng();
        // `t+1` coefficient-shares, as BatchReconNode::init_batch_reconstruct feeds in.
        let coeff_shares: Vec<RobustShare<Fr>> = (0..(t + 1))
            .map(|_| {
                let s = Fr::rand(&mut rng);
                RobustShare::new(s, 0, t)
            })
            .collect();
        group.bench_with_input(
            BenchmarkId::new("make_plus_apply", format!("n{n}_t{t}")),
            &(n, t),
            |b, _| {
                b.iter(|| {
                    let vm = make_vandermonde::<Fr>(n, t).unwrap();
                    let _ = apply_vandermonde(black_box(&vm), black_box(&coeff_shares)).unwrap();
                })
            },
        );
    }
    group.finish();
}

fn bench_domain(c: &mut Criterion) {
    let mut group = c.benchmark_group("evaluation_domain");
    for &(n, _t) in PARAMS {
        group.bench_with_input(BenchmarkId::new("new", format!("n{n}")), &n, |b, &n| {
            b.iter(|| {
                let _ = GeneralEvaluationDomain::<Fr>::new(black_box(n));
            })
        });
    }
    group.finish();
}

fn bench_share_arith(c: &mut Criterion) {
    let mut group = c.benchmark_group("share_arith");
    for &(n, t) in PARAMS {
        let mut rng = test_rng();
        let share: RobustShare<Fr> = RobustShare::new(Fr::rand(&mut rng), 0, t);
        let scalar = Fr::rand(&mut rng);
        let other: RobustShare<Fr> = RobustShare::new(Fr::rand(&mut rng), 0, t);
        // Mimics one finalize_mul iteration: mul by scalar, then two subtractions of shares.
        group.bench_with_input(
            BenchmarkId::new("finalize_iter", format!("n{n}_t{t}")),
            &(n, t),
            |b, _| {
                b.iter(|| {
                    let a = share.clone().mul(black_box(scalar)).unwrap();
                    let b: ShamirShare<Fr, 1, Robust> = (a - black_box(other.clone())).unwrap();
                    let _ = (b - black_box(other.clone())).unwrap();
                })
            },
        );
    }
    group.finish();
}

fn bench_serialize(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialize");
    let session_id = SessionId::new(ProtocolType::Mul, SessionId::pack_slot(1, 0, 1), 111);

    // A small per-round-1 Eval message (single field element) wrapped for the wire.
    let mut payload = Vec::new();
    Fr::from(42u64).serialize_compressed(&mut payload).unwrap();
    let eval_msg = WrappedMessage::BatchRecon(BatchReconMsg::new(
        0,
        session_id,
        BatchReconMsgType::Eval,
        payload,
    ));
    group.bench_function("wrapped_eval_bincode", |b| {
        b.iter(|| bincode::serialize(black_box(&eval_msg)).unwrap())
    });
    group.bench_function("wrapped_eval_bincode_deser", |b| {
        let bytes = bincode::serialize(&eval_msg).unwrap();
        b.iter(|| {
            let _: WrappedMessage =
                bincode::deserialize(black_box(&bytes)).expect("deserialize failed");
        })
    });

    // A RevealBatch payload: a `Vec<F>` of width = number of (t+1)-chunks opened in one batched
    // session. Price at a few widths to expose linear per-element cost.
    for &width in &[1usize, 16, 64] {
        let mut rng = test_rng();
        let values: Vec<Fr> = (0..width).map(|_| Fr::rand(&mut rng)).collect();
        group.bench_with_input(
            BenchmarkId::new("revealbatch_ark_ser", format!("w{width}")),
            &width,
            |b, _| {
                b.iter(|| {
                    let mut out = Vec::new();
                    black_box(&values).serialize_compressed(&mut out).unwrap();
                    out
                })
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_recover_secret,
    bench_batch_recover,
    bench_vandermonde,
    bench_domain,
    bench_share_arith,
    bench_serialize,
);
criterion_main!(benches);
