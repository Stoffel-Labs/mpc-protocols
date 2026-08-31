use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField, UniformRand};
use ark_std::rand::Rng;
use ark_std::test_rng;
use itertools::izip;
use stoffelcrypto::common::SecretSharingScheme;
use stoffelcrypto::honeybadger::bitwise::{
    kor_cs::KOrCSPrep, AppRecPrep, PRandMPrep, PreBitLTPrep, PreMod2mPrep, PreMulCPrep,
};
use stoffelcrypto::honeybadger::fpdiv::fpdiv::{FpDivIterPrep, FpDivPrep};
use stoffelcrypto::honeybadger::fpdiv::fpdiv_theta;
use stoffelcrypto::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelcrypto::honeybadger::triple_gen::ShamirBeaverTriple;
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
    let mut r_pp = vec![vec![]; n];
    for i in 0..pk {
        let sw = share_value(w_vals[i], n, t);
        let sz = share_value(z_vals[i], n, t);
        let sr = share_value(r_vals[i], n, t);
        for p in 0..n {
            w_pp[p].push(sw[p].clone());
            z_pp[p].push(sz[p].clone());
            r_pp[p].push(sr[p].clone());
        }
    }
    (0..n)
        .map(|i| PreMulCPrep {
            w: w_pp[i].clone(),
            z: z_pp[i].clone(),
            r: r_pp[i].clone(),
            triples: triples[i].clone(),
        })
        .collect()
}

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

/// PreBitLT preprocessing for k bits: SufMulInv prep for k inputs, k-1 Beaver
/// triples (phase 4's Multiply), and k independent PRandMPrep sets (one per
/// parallel Mod2 call in phase 5).
pub fn make_prebitlt_prep(k: usize, n: usize, t: usize) -> Vec<PreBitLTPrep<Fr>> {
    let suf_mul_inv_prep = make_premulc_prep(k, n, t);
    let mul_triples = make_triples(n, t, k - 1);
    let mod2_preps_per_bit: Vec<Vec<PRandMPrep<Fr>>> =
        (0..k).map(|_| make_mod2_prep(k, n, t)).collect();
    (0..n)
        .map(|p| PreBitLTPrep {
            suf_mul_inv_prep: suf_mul_inv_prep[p].clone(),
            mul_triples: mul_triples[p].clone(),
            mod2_preps: (0..k).map(|b| mod2_preps_per_bit[b][p].clone()).collect(),
        })
        .collect()
}

/// PreMod2m preprocessing: PRandM(dp_bits, m) for the reveal mask, plus
/// PreBitLT prep sized for PreMod2m's internal Phase 3 call (which operates
/// on m bits, not m's caller-side bit length k).
pub fn make_premod2m_prep(dp_bits: usize, m: usize, n: usize, t: usize) -> Vec<PreMod2mPrep<Fr>> {
    let prandm = make_prandm_prep(dp_bits, m, n, t);
    let pre_bitlt = make_prebitlt_prep(m, n, t);
    prandm
        .into_iter()
        .zip(pre_bitlt)
        .map(|(prandm, pre_bitlt)| PreMod2mPrep { prandm, pre_bitlt })
        .collect()
}

/// AppRec preprocessing for a k-bit input: BitDec prep (internally m=k-1),
/// SufOr prep sized for k-1 inputs, triples for the XOR/batch/final Multiply
/// rounds, and PRandM material for the final TruncPr call (k_trunc=2k,
/// m_trunc=2(k-f-1)).
pub fn make_apprec_prep(
    dp_bits: usize,
    k: usize,
    f: usize,
    n: usize,
    t: usize,
) -> Vec<AppRecPrep<Fr>> {
    let mut bitdec_prep = make_premod2m_prep(dp_bits, k - 1, n, t).into_iter();
    let mut sufor_prep = make_premulc_prep(k - 1, n, t).into_iter();
    let mut xor_triples = make_triples(n, t, k - 1).into_iter();
    let mut batch_triples = make_triples(n, t, 2).into_iter();
    let mut final_triple = make_triples(n, t, 1).into_iter();
    let m_trunc = 2 * (k - f - 1);
    let mut trunc_prandm = make_prandm_prep(dp_bits, m_trunc, n, t).into_iter();

    (0..n)
        .map(|_| {
            let prandm = trunc_prandm.next().unwrap();
            AppRecPrep {
                bitdec_prep: bitdec_prep.next().unwrap(),
                sufor_prep: sufor_prep.next().unwrap(),
                xor_triples: xor_triples.next().unwrap(),
                batch_triples: batch_triples.next().unwrap(),
                final_triple: final_triple.next().unwrap(),
                trunc_r_bits: prandm.r_prime_bits,
                trunc_r_int: prandm.r_double_prime,
            }
        })
        .collect()
}

/// FXDiv preprocessing for a k-bit, f-fractional-bit division: AppRec's own
/// prep (step 2), 2 triples for the step-3/4 batch, PRandM material for
/// step 3's TruncPr (m = f), one `FpDivIterPrep` per refinement-loop
/// iteration (`fpdiv_theta(k).saturating_sub(1)` of them, each carrying 2
/// Round-A triples and 2 independent PRandM sets (m = 2f) for steps 6/7's
/// truncations), and finally the one-shot step 8 (Round B) material — 1
/// triple and one PRandM(m = 2f) set — which runs once after the loop, not
/// once per iteration.
pub fn make_fpdiv_prep(
    dp_bits: usize,
    k: usize,
    f: usize,
    n: usize,
    t: usize,
) -> Vec<FpDivPrep<Fr>> {
    let app_rec_prep = make_apprec_prep(dp_bits, k, f, n, t);
    let step3_4_triples = make_triples(n, t, 2);
    let step3_trunc_prandm = make_prandm_prep(dp_bits, f, n, t);

    let num_iters = fpdiv_theta(k).saturating_sub(1);
    let mut iters_per_party: Vec<Vec<FpDivIterPrep<Fr>>> =
        (0..n).map(|_| Vec::with_capacity(num_iters)).collect();
    for _ in 0..num_iters {
        let round_a_triples = make_triples(n, t, 2);
        let step6_prandm = make_prandm_prep(dp_bits, 2 * f, n, t);
        let step7_prandm = make_prandm_prep(dp_bits, 2 * f, n, t);
        for p in 0..n {
            iters_per_party[p].push(FpDivIterPrep {
                round_a_triples: round_a_triples[p].clone(),
                step6_trunc_r_bits: step6_prandm[p].r_prime_bits.clone(),
                step6_trunc_r_int: step6_prandm[p].r_double_prime.clone(),
                step7_trunc_r_bits: step7_prandm[p].r_prime_bits.clone(),
                step7_trunc_r_int: step7_prandm[p].r_double_prime.clone(),
            });
        }
    }

    let round_b_triple = make_triples(n, t, 1);
    let step8_prandm = make_prandm_prep(dp_bits, 2 * f, n, t);

    izip!(
        app_rec_prep,
        step3_4_triples,
        step3_trunc_prandm,
        iters_per_party,
        round_b_triple,
        step8_prandm,
    )
    .map(
        |(app_rec_prep, step3_4_triples, step3_trunc, iters, round_b_triple, step8_trunc)| {
            FpDivPrep {
                app_rec_prep,
                step3_4_triples,
                step3_trunc_r_bits: step3_trunc.r_prime_bits,
                step3_trunc_r_int: step3_trunc.r_double_prime,
                iters,
                round_b_triple,
                step8_trunc_r_bits: step8_trunc.r_prime_bits,
                step8_trunc_r_int: step8_trunc.r_double_prime,
            }
        },
    )
    .collect()
}

/// Shares a k-bit signed integer `u_bar` (two's-complement-style field
/// encoding: negative values as `q + u_bar`) at the given fixed-point scale.
pub fn share_signed_fixed(u_bar: i128, n: usize, t: usize) -> Vec<RobustShare<Fr>> {
    let val = if u_bar >= 0 {
        Fr::from(u_bar as u128)
    } else {
        -Fr::from((-u_bar) as u128)
    };
    share_value(val, n, t)
}

/// Decodes a field element back to a signed integer, assuming its true
/// magnitude is small relative to the field modulus (always true for the
/// small k-bit test values used here). Whichever of `val`/`-val` has the
/// smaller canonical representative determines the sign.
pub fn field_to_signed_i128(val: Fr) -> i128 {
    fn to_u128(v: Fr) -> u128 {
        let bytes = v.into_bigint().to_bytes_le();
        let mut buf = [0u8; 16];
        let len = core::cmp::min(16, bytes.len());
        buf[..len].copy_from_slice(&bytes[..len]);
        u128::from_le_bytes(buf)
    }
    let pos = to_u128(val);
    let neg = to_u128(-val);
    if pos <= neg {
        pos as i128
    } else {
        -(neg as i128)
    }
}

/// Decodes a field element as a signed fixed-point real number with f
/// fractional bits.
pub fn field_to_signed_real(val: Fr, f: usize) -> f64 {
    field_to_signed_i128(val) as f64 / (1u128 << f) as f64
}
