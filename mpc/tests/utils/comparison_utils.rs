use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Field, UniformRand};
use ark_std::rand::Rng;
use ark_std::test_rng;
use stoffelmpc_mpc::common::SecretSharingScheme;
use stoffelmpc_mpc::honeybadger::comparison::kor_cs::KOrCSPrep;
use stoffelmpc_mpc::honeybadger::comparison::{PRandMPrep, PreMulCPrep};
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::triple_gen::ShamirBeaverTriple;
use tokio::task::JoinSet;

pub fn make_triples(n: usize, t: usize, k: usize) -> Vec<Vec<ShamirBeaverTriple<Fr>>> {
    let mut rng = test_rng();
    let mut per_party: Vec<Vec<ShamirBeaverTriple<Fr>>> = vec![vec![]; n];
    for _ in 0..k {
        let a = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);
        let c = a * b;
        let sa = RobustShare::compute_shares(a, n, t, None, &mut rng).unwrap();
        let sb = RobustShare::compute_shares(b, n, t, None, &mut rng).unwrap();
        let sc = RobustShare::compute_shares(c, n, t, None, &mut rng).unwrap();
        for p in 0..n {
            per_party[p].push(ShamirBeaverTriple {
                a: sa[p].clone(),
                b: sb[p].clone(),
                mult: sc[p].clone(),
            });
        }
    }
    per_party
}

pub fn share_value(v: Fr, n: usize, t: usize) -> Vec<RobustShare<Fr>> {
    let mut rng = test_rng();
    RobustShare::compute_shares(v, n, t, None, &mut rng).unwrap()
}

pub fn share_bits_of(v: u64, k: usize, n: usize, t: usize) -> Vec<Vec<RobustShare<Fr>>> {
    let mut per_party: Vec<Vec<RobustShare<Fr>>> = vec![vec![]; n];
    for i in 0..k {
        let bit = Fr::from((v >> i) & 1);
        let shares = share_value(bit, n, t);
        for p in 0..n {
            per_party[p].push(shares[p].clone());
        }
    }
    per_party
}

/// PRandM(dp_bits, m): r'' is dp_bits-wide, r' is m-bit with full bit decomposition.
pub fn make_prandm_prep(dp_bits: usize, m: usize, n: usize, t: usize) -> Vec<PRandMPrep<Fr>> {
    let mut rng = test_rng();
    let r_dp = Fr::from(rng.gen::<u64>() % (1u64 << dp_bits as u64));
    let r_prime_int = rng.gen::<u64>() % (1u64 << m as u64);
    let r_dp_shares = share_value(r_dp, n, t);
    let r_prime_shares = share_value(Fr::from(r_prime_int), n, t);
    let r_prime_bits_pp = share_bits_of(r_prime_int, m, n, t);
    (0..n)
        .map(|i| PRandMPrep {
            r_double_prime: r_dp_shares[i].clone(),
            r_prime: r_prime_shares[i].clone(),
            r_prime_bits: r_prime_bits_pp[i].clone(),
        })
        .collect()
}

/// Mod2 preprocessing: r'' is (k-1)-bit, r' is a random bit, no bit decomposition.
pub fn make_mod2_prep(k: usize, n: usize, t: usize) -> Vec<PRandMPrep<Fr>> {
    let mut rng = test_rng();
    let r_dp = Fr::from(rng.gen::<u64>() % (1u64 << (k as u64 - 1)));
    let r_zp = Fr::from(rng.gen::<u64>() & 1);
    let r_dp_shares = share_value(r_dp, n, t);
    let r_zp_shares = share_value(r_zp, n, t);
    (0..n)
        .map(|i| PRandMPrep {
            r_double_prime: r_dp_shares[i].clone(),
            r_prime: r_zp_shares[i].clone(),
            r_prime_bits: vec![],
        })
        .collect()
}

/// Synthetic PreMulC preprocessing. Satisfies prefix_product(w)[j] * z[j] = 1 for all j.
pub fn make_premulc_prep(pk: usize, n: usize, t: usize) -> Vec<PreMulCPrep<Fr>> {
    let mut rng = test_rng();
    let r_vals: Vec<Fr> = (0..pk)
        .map(|_| loop {
            let v = Fr::rand(&mut rng);
            if v != Fr::from(0u64) {
                break v;
            }
        })
        .collect();
    let w_vals: Vec<Fr> = (0..pk)
        .map(|i| {
            if i == 0 {
                r_vals[0]
            } else {
                r_vals[i] * r_vals[i - 1].inverse().unwrap()
            }
        })
        .collect();
    let z_vals: Vec<Fr> = r_vals.iter().map(|r| r.inverse().unwrap()).collect();
    let triples = make_triples(n, t, pk);
    let mut w_pp = vec![vec![]; n];
    let mut z_pp = vec![vec![]; n];
    for i in 0..pk {
        let sw = share_value(w_vals[i], n, t);
        let sz = share_value(z_vals[i], n, t);
        for p in 0..n {
            w_pp[p].push(sw[p].clone());
            z_pp[p].push(sz[p].clone());
        }
    }
    (0..n)
        .map(|i| PreMulCPrep {
            w: w_pp[i].clone(),
            z: z_pp[i].clone(),
            triples: triples[i].clone(),
        })
        .collect()
}

/// KOrCSPrep for m input bits: m random invertible pairs, (m-1) round-1 triples, m round-2 triples.
pub fn make_kor_cs_prep(m: usize, n: usize, t: usize) -> Vec<KOrCSPrep<Fr>> {
    let mut rng = test_rng();
    let mut pairs_per_party: Vec<Vec<(RobustShare<Fr>, RobustShare<Fr>)>> = vec![vec![]; n];
    for _ in 0..m {
        let r = loop {
            let v = Fr::rand(&mut rng);
            if v != Fr::ZERO {
                break v;
            }
        };
        let r_inv = r.inverse().unwrap();
        let sr = share_value(r, n, t);
        let sr_inv = share_value(r_inv, n, t);
        for p in 0..n {
            pairs_per_party[p].push((sr[p].clone(), sr_inv[p].clone()));
        }
    }
    let triples1 = make_triples(n, t, m.saturating_sub(1));
    let triples2 = make_triples(n, t, m);
    (0..n)
        .map(|i| KOrCSPrep {
            rand_inv_pairs: pairs_per_party[i].clone(),
            triples_round1: if m > 1 { triples1[i].clone() } else { vec![] },
            triples_round2: triples2[i].clone(),
        })
        .collect()
}

pub async fn collect_result_shares(mut set: JoinSet<RobustShare<Fr>>) -> Vec<RobustShare<Fr>> {
    let mut shares = vec![];
    while let Some(r) = set.join_next().await {
        shares.push(r.unwrap());
    }
    shares
}
pub fn make_zero_shares(n: usize, t: usize, k: usize) -> Vec<Vec<RobustShare<Fr>>> {
    let mut rng = test_rng();
    let mut per_party: Vec<Vec<RobustShare<Fr>>> = vec![vec![]; n];
    for _ in 0..k {
        let shares = RobustShare::compute_shares(Fr::ZERO, n, 2 * t, None, &mut rng).unwrap();
        for p in 0..n {
            per_party[p].push(shares[p].clone());
        }
    }
    per_party
}
