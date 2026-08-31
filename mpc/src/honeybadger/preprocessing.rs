use crate::{
    common::math::goldilocks::GoldilocksField,
    honeybadger::{
        bitwise::{AppRecPrep, PRandMPrep, PreBitLTPrep, PreMod2mPrep, PreMulCPrep},
        fpdiv::{
            fpdiv::{FpDivIterPrep, FpDivPrep},
            fpdiv_theta,
        },
        fpmul::f256::Gf256,
        robust_interpolate::robust_interpolate::RobustShare,
        triple_gen::ShamirBeaverTriple,
        HoneyBadgerError,
    },
};
use ark_ff::FftField;
use std::collections::BTreeMap;
use tracing::error;

/// Raw preprocessing material that a batch of planned online operations will
/// consume.
///
/// HoneyBadger is preprocessing-based: material is generated in bulk offline
/// and only *drawn* online. Sizing it by hand is awkward because operations
/// consume two layers at once — the flat pools directly, and *derived* material
/// (PreMulC bundles, ([r],[r^-1]) pairs) whose own generation draws from those
/// same pools. Every `demand_for_*` constructor reports the **total** across
/// both layers, so `run_preprocessing` sizes the offline phase in one pass and
/// callers never redo the arithmetic.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PreprocDemand {
    pub triples: usize,
    pub random_shares: usize,
    pub prandbit: usize,
    pub prandint: usize,
    pub zero_shares: usize,
    pub rand_inv_pairs: usize,
    /// PreMulC bundles keyed by the `pk` they must be generated at. A bundle is
    /// only usable at the width it was built for, and one node can serve several
    /// widths at once (LTZ at k=8 wants pk=7 while FpDiv at k=15 wants pk=14),
    /// so this is a map rather than a single (count, size) pair.
    pub premulc: BTreeMap<usize, usize>,
}

impl PreprocDemand {
    /// Folds in `count` PreMulC bundles at `pk`, including their generation
    /// cost: `ensure_premulc_shares` draws `(pk-1) + pk` triples, `2*pk` random
    /// shares and `pk` zero-sharings per bundle.
    pub fn add_premulc(&mut self, pk: usize, count: usize) {
        if pk == 0 || count == 0 {
            return;
        }
        *self.premulc.entry(pk).or_default() += count;
        self.triples += count * (2 * pk - 1);
        self.random_shares += count * 2 * pk;
        self.zero_shares += count * pk;
    }

    /// Folds in `count` ([r], [r^-1]) pairs, including their generation cost:
    /// each pair reveals one product via MulPub, drawing 2 random shares and 1
    /// degree-2t zero-sharing.
    pub fn add_rand_inv_pairs(&mut self, count: usize) {
        self.rand_inv_pairs += count;
        self.random_shares += 2 * count;
        self.zero_shares += count;
    }

    /// Accumulates another demand (pools add, PreMulC bundles merge per `pk`).
    pub fn add(&mut self, other: &PreprocDemand) {
        self.triples += other.triples;
        self.random_shares += other.random_shares;
        self.prandbit += other.prandbit;
        self.prandint += other.prandint;
        self.zero_shares += other.zero_shares;
        self.rand_inv_pairs += other.rand_inv_pairs;
        for (&pk, &count) in &other.premulc {
            *self.premulc.entry(pk).or_default() += count;
        }
    }

    /// How many triples and random shares must actually be generated, given
    /// what is already pooled.
    ///
    /// The other pools are simple shortfalls that each `ensure_*` computes for
    /// itself, but these two are coupled and need care:
    ///
    /// * triples come out of TripleGen in whole groups of `2t+1`, so a shortfall
    ///   is rounded up to a group boundary;
    /// * generating a triple *itself* consumes 2 random shares, so that cost is
    ///   added on top of the random-share shortfall
    ///
    /// Returns `(0, 0)` when both pools are already satisfied.
    pub fn to_generate(&self, have: &PreprocMaterialLength, threshold: usize) -> GenerationPlan {
        let group_size = 2 * threshold + 1;

        let triples = if have.beaver_triples >= self.triples {
            0
        } else {
            (self.triples - have.beaver_triples).div_ceil(group_size) * group_size
        };

        let random_shortfall = self.random_shares.saturating_sub(have.random_shr);
        let random_shares = random_shortfall + 2 * triples;

        GenerationPlan {
            triples,
            random_shares,
        }
    }

    /// This demand repeated `n` times (`n` executions of the same operation).
    pub fn scaled(&self, n: usize) -> PreprocDemand {
        PreprocDemand {
            triples: self.triples * n,
            random_shares: self.random_shares * n,
            prandbit: self.prandbit * n,
            prandint: self.prandint * n,
            zero_shares: self.zero_shares * n,
            rand_inv_pairs: self.rand_inv_pairs * n,
            premulc: self.premulc.iter().map(|(&pk, &c)| (pk, c * n)).collect(),
        }
    }
}

/// The amounts `run_preprocessing` must actually generate for the two coupled
/// pools, after accounting for what is already held. See
/// [`PreprocDemand::to_generate`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GenerationPlan {
    /// Rounded up to a whole number of `2t+1` TripleGen groups.
    pub triples: usize,
    /// Shortfall plus the 2 shares each generated triple consumes.
    pub random_shares: usize,
}

impl GenerationPlan {
    /// Nothing to do — both pools already cover the demand.
    pub fn is_empty(&self) -> bool {
        self.triples == 0 && self.random_shares == 0
    }
}

/// Total demand of `count` secure multiplications (`mul`, and each element of a
/// `mul_int` batch): one Beaver triple apiece.
///
/// The random shares triple *generation* consumes are not counted here —
/// `run_preprocessing` already adds `2` per generated triple on top of whatever
/// the pools are asked for.
pub fn demand_for_mul(count: usize) -> PreprocDemand {
    PreprocDemand {
        triples: count,
        ..Default::default()
    }
}

/// Total demand of one `mul_fixed` at fractional precision `f`: one triple for
/// the product plus a TruncPr mask (`f` PRandBit draws and one PRandInt).
pub fn demand_for_fpmul(f: usize) -> PreprocDemand {
    PreprocDemand {
        triples: 1,
        prandbit: f,
        prandint: 1,
        ..Default::default()
    }
}

/// Total demand of one `div_with_const_fixed` at fractional precision `f`: a
/// TruncPr mask only, since the divisor is public.
pub fn demand_for_fpdiv_const(f: usize) -> PreprocDemand {
    PreprocDemand {
        prandbit: f,
        prandint: 1,
        ..Default::default()
    }
}

/// Total demand of `count` random-share draws (`rand`, and input masks): one
/// pooled random share apiece.
pub fn demand_for_rand(count: usize) -> PreprocDemand {
    PreprocDemand {
        random_shares: count,
        ..Default::default()
    }
}

/// Total demand of one `ltz_int` at bit width `k`.
///
/// LTZ runs PreMod2m(a, k, m = k-1); its inner PreBitLT needs one PreMulC
/// bundle at `pk = m`.
pub fn demand_for_ltz(k: usize) -> PreprocDemand {
    let (triples, prandbit, prandint) = crate::honeybadger::comparison::ltz_prep_counts(k);
    let mut d = PreprocDemand {
        triples,
        prandbit,
        prandint,
        ..Default::default()
    };
    d.add_premulc(k - 1, 1);
    d
}

/// Total demand of one `eqz_int` at bit width `k`.
///
/// EQZ needs no PreMulC bundle; its derived material is the `m` ([r],[r^-1])
/// pairs KOrCS consumes, where `m = floor(log2(k)) + 1`.
pub fn demand_for_eqz(k: usize) -> PreprocDemand {
    let (triples, prandbit, prandint, pairs) = crate::honeybadger::comparison::eqz_prep_counts(k);
    let mut d = PreprocDemand {
        triples,
        prandbit,
        prandint,
        ..Default::default()
    };
    d.add_rand_inv_pairs(pairs);
    d
}

/// Total demand of one `div_fixed` at precision `(k, f)`.
///
/// Note `fpdiv_prep_counts` differs in contract from the LTZ/EQZ counterparts:
/// its `triples`/`random_shares` **already include** what generating FpDiv's two
/// PreMulC bundles costs. So the bundles are recorded here without re-adding
/// that cost — only the zero-sharings, which it does not cover.
pub fn demand_for_fpdiv(k: usize, f: usize) -> PreprocDemand {
    let (triples, random_shares, prandbit, prandint) =
        crate::honeybadger::fpdiv::fpdiv_prep_counts(k, f);
    let pk = k - 1;
    let mut premulc = BTreeMap::new();
    premulc.insert(pk, 2);
    PreprocDemand {
        triples,
        random_shares,
        prandbit,
        prandint,
        zero_shares: 2 * pk,
        rand_inv_pairs: 0,
        premulc,
    }
}

/// Preprocessing material for the HoneyBadgerMPCNode protocol.
#[derive(Clone, Debug)]
pub struct HoneyBadgerMPCNodePreprocMaterial<F: FftField> {
    /// A pool of random double shares used for secure multiplication.
    beaver_triples: Vec<ShamirBeaverTriple<F>>,
    /// A pool of random shares used for inputing private data for the protocol.
    random_shares: Vec<RobustShare<F>>,
    /// A pool of PRandBit outputs for truncation
    prandbit_shares: Vec<(RobustShare<F>, Gf256)>,
    /// A pool of PRandInt outputs for truncation
    prandint_shares: Vec<RobustShare<F>>,
    /// A pool of random shares in the Goldilocks field for rand bit generation.
    random_shares_small_field: Vec<RobustShare<GoldilocksField>>,
    /// A pool of PreMulC offline-phase bundles (all sized at the same
    /// configured `premulc_pk`), topped up by `run_preprocessing`.
    premulc_preps: BTreeMap<usize, Vec<PreMulCPrep<F>>>,
    /// A pool of degree-2t zero-sharings (ZeroShaNode output).
    zero_shares: Vec<RobustShare<F>>,
    /// A pool of degree-2t zero-sharings in the Goldilocks field, feeding
    /// RandBit's MulPub-based reveal of `a^2`.
    zero_shares_small_field: Vec<RobustShare<GoldilocksField>>,
    /// A pool of ([r], [r^-1]) pairs (RandInvPairNode output)
    rand_inv_pairs: Vec<(RobustShare<F>, RobustShare<F>)>,
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub struct PreprocMaterialLength {
    pub beaver_triples: usize,
    pub random_shr: usize,
    pub random_shr_small_field: usize,
    pub prandbit: usize,
    pub prandint: usize,
    pub premulc: usize,
    pub zero_shares: usize,
    pub zero_shares_small_field: usize,
    pub rand_inv_pairs: usize,
}

impl PreprocMaterialLength {
    pub fn zero() -> Self {
        Self {
            beaver_triples: 0,
            random_shr: 0,
            random_shr_small_field: 0,
            prandbit: 0,
            prandint: 0,
            premulc: 0,
            zero_shares: 0,
            zero_shares_small_field: 0,
            rand_inv_pairs: 0,
        }
    }
}

impl<F> HoneyBadgerMPCNodePreprocMaterial<F>
where
    F: FftField,
{
    /// Generates empty preprocessing material storage.
    pub fn empty() -> Self {
        Self {
            random_shares: Vec::new(),
            beaver_triples: Vec::new(),
            prandbit_shares: Vec::new(),
            prandint_shares: Vec::new(),
            random_shares_small_field: Vec::new(),
            premulc_preps: BTreeMap::new(),
            zero_shares: Vec::new(),
            zero_shares_small_field: Vec::new(),
            rand_inv_pairs: Vec::new(),
        }
    }

    /// Files a freshly generated bundle under its own width.
    pub fn add_premulc_prep(&mut self, prep: PreMulCPrep<F>) {
        self.premulc_preps.entry(prep.pk()).or_default().push(prep);
    }

    /// How many bundles are ready at exactly `pk`.
    pub fn premulc_len(&self, pk: usize) -> usize {
        self.premulc_preps.get(&pk).map_or(0, Vec::len)
    }

    /// Bundles ready across every width. Reporting only — a consumer can never
    /// draw from a bucket other than its own.
    pub fn premulc_len_total(&self) -> usize {
        self.premulc_preps.values().map(Vec::len).sum()
    }

    /// Widths currently held, with their counts.
    pub fn premulc_widths(&self) -> Vec<(usize, usize)> {
        self.premulc_preps
            .iter()
            .map(|(&pk, v)| (pk, v.len()))
            .collect()
    }

    /// Takes one bundle of width exactly `pk`.
    ///
    /// Bundles of other widths are left untouched. The pool is bucketed by
    /// width precisely so that a node alternating between (say) FpDiv at pk=15
    /// and LTZ on an int8 at pk=7 keeps both stocks intact, rather than
    /// discarding whichever width it is not currently asking for.
    pub fn take_premulc_prep(&mut self, pk: usize) -> Result<PreMulCPrep<F>, HoneyBadgerError> {
        match self.premulc_preps.get_mut(&pk) {
            Some(bucket) if !bucket.is_empty() => {
                let prep = bucket.remove(0);
                if bucket.is_empty() {
                    self.premulc_preps.remove(&pk);
                }
                Ok(prep)
            }
            _ => {
                error!(
                    "Error trying to take a PreMulC bundle of width {pk}: none ready (widths held: {:?})",
                    self.premulc_widths()
                );
                Err(HoneyBadgerError::NotEnoughPreprocessing)
            }
        }
    }

    /// Adds newly-generated zero-sharings to the pool.
    pub fn add_zero_shares(&mut self, mut shares: Vec<RobustShare<F>>) {
        self.zero_shares.append(&mut shares);
    }

    /// Take up to n zero-sharings from the preprocessing material.
    pub fn take_zero_shares(
        &mut self,
        n_shares: usize,
    ) -> Result<Vec<RobustShare<F>>, HoneyBadgerError> {
        if n_shares > self.zero_shares.len() {
            error!("Error trying to take zero shares: There is no enough preprocessing");
            return Err(HoneyBadgerError::NotEnoughPreprocessing);
        }
        Ok(self.zero_shares.drain(0..n_shares).collect())
    }

    /// Adds newly-generated small-field zero-sharings to the pool.
    pub fn add_zero_shares_small_field(&mut self, mut shares: Vec<RobustShare<GoldilocksField>>) {
        self.zero_shares_small_field.append(&mut shares);
    }

    /// Take up to n small-field zero-sharings from the preprocessing material.
    pub fn take_zero_shares_small_field(
        &mut self,
        n_shares: usize,
    ) -> Result<Vec<RobustShare<GoldilocksField>>, HoneyBadgerError> {
        if n_shares > self.zero_shares_small_field.len() {
            error!(
                "Error trying to take small-field zero shares: There is no enough preprocessing"
            );
            return Err(HoneyBadgerError::NotEnoughPreprocessing);
        }
        Ok(self.zero_shares_small_field.drain(0..n_shares).collect())
    }

    /// Adds newly-generated ([r], [r^-1]) pairs to the pool.
    pub fn add_rand_inv_pairs(&mut self, mut pairs: Vec<(RobustShare<F>, RobustShare<F>)>) {
        self.rand_inv_pairs.append(&mut pairs);
    }

    /// Take up to n ([r], [r^-1]) pairs from the preprocessing material.
    pub fn take_rand_inv_pairs(
        &mut self,
        n_pairs: usize,
    ) -> Result<Vec<(RobustShare<F>, RobustShare<F>)>, HoneyBadgerError> {
        if n_pairs > self.rand_inv_pairs.len() {
            error!("Error trying to take random inverse pairs: There is no enough preprocessing");
            return Err(HoneyBadgerError::NotEnoughPreprocessing);
        }
        Ok(self.rand_inv_pairs.drain(0..n_pairs).collect())
    }

    /// Adds the provided new preprocessing material to the current pool.
    pub fn add(
        &mut self,
        mut triples: Option<Vec<ShamirBeaverTriple<F>>>,
        mut random_shares: Option<Vec<RobustShare<F>>>,
        mut random_shares_small_field: Option<Vec<RobustShare<GoldilocksField>>>,
        mut prandbit_shares: Option<Vec<(RobustShare<F>, Gf256)>>,
        mut prandbit_int: Option<Vec<RobustShare<F>>>,
    ) {
        if let Some(pairs) = &mut triples {
            self.beaver_triples.append(pairs);
        }

        if let Some(shares) = &mut random_shares_small_field {
            self.random_shares_small_field.append(shares);
        }

        if let Some(shares) = &mut random_shares {
            self.random_shares.append(shares);
        }

        if let Some(shares) = &mut prandbit_shares {
            self.prandbit_shares.append(shares);
        }
        if let Some(shares) = &mut prandbit_int {
            self.prandint_shares.append(shares);
        }
    }

    /// Returns the number of random double share pairs, and the number of random shares
    /// respectively.
    pub fn length(&self) -> PreprocMaterialLength {
        PreprocMaterialLength {
            beaver_triples: self.beaver_triples.len(),
            random_shr: self.random_shares.len(),
            random_shr_small_field: self.random_shares_small_field.len(),
            prandbit: self.prandbit_shares.len(),
            prandint: self.prandint_shares.len(),
            premulc: self.premulc_len_total(),
            zero_shares: self.zero_shares.len(),
            zero_shares_small_field: self.zero_shares_small_field.len(),
            rand_inv_pairs: self.rand_inv_pairs.len(),
        }
    }

    /// Take up to n pairs of random double sharings from the preprocessing material.
    pub fn take_beaver_triples(
        &mut self,
        n_triples: usize,
    ) -> Result<Vec<ShamirBeaverTriple<F>>, HoneyBadgerError> {
        if n_triples > self.beaver_triples.len() {
            error!("Error trying to take triples: There is no enough preprocessing");
            return Err(HoneyBadgerError::NotEnoughPreprocessing);
        }
        Ok(self.beaver_triples.drain(0..n_triples).collect())
    }

    /// Take up to n random shares from the preprocessing material.
    pub fn take_random_shares(
        &mut self,
        n_shares: usize,
    ) -> Result<Vec<RobustShare<F>>, HoneyBadgerError> {
        if n_shares > self.random_shares.len() {
            error!("Error trying to take random shares: There is no enough preprocessing");
            return Err(HoneyBadgerError::NotEnoughPreprocessing);
        }
        Ok(self.random_shares.drain(0..n_shares).collect())
    }

    pub fn take_random_shares_small_field(
        &mut self,
        n_shares: usize,
    ) -> Result<Vec<RobustShare<GoldilocksField>>, HoneyBadgerError> {
        if n_shares > self.random_shares_small_field.len() {
            error!("Error trying to take random shares in the small field: There is no enough preprocessing");
            return Err(HoneyBadgerError::NotEnoughPreprocessing);
        }
        Ok(self.random_shares_small_field.drain(0..n_shares).collect())
    }

    pub fn take_prandbit_shares(
        &mut self,
        n_prandbit: usize,
    ) -> Result<Vec<(RobustShare<F>, Gf256)>, HoneyBadgerError> {
        if n_prandbit > self.prandbit_shares.len() {
            error!("Error trying to take PRandBit shares: There is no enough preprocessing");
            return Err(HoneyBadgerError::NotEnoughPreprocessing);
        }
        Ok(self.prandbit_shares.drain(0..n_prandbit).collect())
    }

    pub fn take_prandint_shares(
        &mut self,
        n_prandint: usize,
    ) -> Result<Vec<RobustShare<F>>, HoneyBadgerError> {
        if n_prandint > self.prandint_shares.len() {
            error!("Error trying to take PRandInt shares: There is no enough preprocessing");
            return Err(HoneyBadgerError::NotEnoughPreprocessing);
        }
        Ok(self.prandint_shares.drain(0..n_prandint).collect())
    }

    // ── FpDiv preprocessing assembly ──────────────────────────────────────

    /// A `m`-bit PRandM bundle (a PRandInt draw plus `m` PRandBit draws,
    /// combined via `PRandMPrep::from_prand_outputs`).
    pub fn take_prandm_prep(&mut self, m: usize) -> Result<PRandMPrep<F>, HoneyBadgerError> {
        let r_double_prime = self.take_prandint_shares(1)?.remove(0);
        let r_prime_bits: Vec<RobustShare<F>> = self
            .take_prandbit_shares(m)?
            .into_iter()
            .map(|(share, _)| share)
            .collect();
        Ok(PRandMPrep::from_prand_outputs(
            r_double_prime,
            r_prime_bits,
        )?)
    }

    /// Mod2's own degenerate PRandM (m=1, no bit decomposition needed —
    /// `r_prime` is used directly as the random bit, `r_prime_bits` stays
    /// empty).
    pub fn take_mod2_prandm_prep(&mut self) -> Result<PRandMPrep<F>, HoneyBadgerError> {
        let r_double_prime = self.take_prandint_shares(1)?.remove(0);
        let r_prime = self.take_prandbit_shares(1)?.remove(0).0;
        Ok(PRandMPrep {
            r_double_prime,
            r_prime,
            r_prime_bits: vec![],
        })
    }

    /// A `PreMod2mPrep` for `PreMod2m(k, m)`: the PRandM(k, m) reveal mask plus
    /// the inner PreBitLT material (which operates on `m`-bit inputs, so it
    /// needs `m-1` triples and `m` degenerate Mod2 PRandM bundles).
    /// `suf_mul_inv_prep` must already be sized at pk = m.
    pub fn build_premod2m_prep(
        &mut self,
        m: usize,
        suf_mul_inv_prep: PreMulCPrep<F>,
    ) -> Result<PreMod2mPrep<F>, HoneyBadgerError> {
        let prandm = self.take_prandm_prep(m)?;
        let mul_triples = self.take_beaver_triples(m - 1)?;
        let mut mod2_preps = Vec::with_capacity(m);
        for _ in 0..m {
            mod2_preps.push(self.take_mod2_prandm_prep()?);
        }
        Ok(PreMod2mPrep {
            prandm,
            pre_bitlt: PreBitLTPrep {
                suf_mul_inv_prep,
                mul_triples,
                mod2_preps,
            },
        })
    }

    /// Packages a full `FpDivPrep(k, f)` from the pool plus the two
    /// already-generated PreMulC bundles (`bitdec_suf_mul_inv_prep`,
    /// `sufor_prep` — both pk=k-1).
    pub fn build_fpdiv_prep(
        &mut self,
        k: usize,
        f: usize,
        bitdec_suf_mul_inv_prep: PreMulCPrep<F>,
        sufor_prep: PreMulCPrep<F>,
    ) -> Result<FpDivPrep<F>, HoneyBadgerError> {
        let bitdec_prep = self.build_premod2m_prep(k - 1, bitdec_suf_mul_inv_prep)?;

        let apprec_trunc_prandm = self.take_prandm_prep(2 * (k - f - 1))?;
        let app_rec_prep = AppRecPrep {
            bitdec_prep,
            sufor_prep,
            xor_triples: self.take_beaver_triples(k - 1)?,
            batch_triples: self.take_beaver_triples(2)?,
            final_triple: self.take_beaver_triples(1)?,
            trunc_r_bits: apprec_trunc_prandm.r_prime_bits,
            trunc_r_int: apprec_trunc_prandm.r_double_prime,
        };

        let step3_trunc_prandm = self.take_prandm_prep(f)?;
        let num_iters = fpdiv_theta(k).saturating_sub(1);
        let mut iters = Vec::with_capacity(num_iters);
        for _ in 0..num_iters {
            let round_a_triples = self.take_beaver_triples(2)?;
            let step6 = self.take_prandm_prep(2 * f)?;
            let step7 = self.take_prandm_prep(2 * f)?;
            iters.push(FpDivIterPrep {
                round_a_triples,
                step6_trunc_r_bits: step6.r_prime_bits,
                step6_trunc_r_int: step6.r_double_prime,
                step7_trunc_r_bits: step7.r_prime_bits,
                step7_trunc_r_int: step7.r_double_prime,
            });
        }

        // Step 8 (Round B) runs once, after the loop — not per iteration.
        let round_b_triple = self.take_beaver_triples(1)?;
        let step8 = self.take_prandm_prep(2 * f)?;

        Ok(FpDivPrep {
            app_rec_prep,
            step3_4_triples: self.take_beaver_triples(2)?,
            step3_trunc_r_bits: step3_trunc_prandm.r_prime_bits,
            step3_trunc_r_int: step3_trunc_prandm.r_double_prime,
            iters,
            round_b_triple,
            step8_trunc_r_bits: step8.r_prime_bits,
            step8_trunc_r_int: step8.r_double_prime,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::honeybadger::HoneyBadgerError;
    use crate::honeybadger::{
        robust_interpolate::robust_interpolate::RobustShare, triple_gen::ShamirBeaverTriple,
    };
    use ark_bn254::Fr;

    #[test]
    fn to_generate_rounds_triples_and_adds_two_shares_each() {
        let t = 1;
        let group = 2 * t + 1; // 3
        let mut have = PreprocMaterialLength::zero();

        // 7 triples wanted, none held -> round 7 up to 9 (3 groups of 3),
        // and 9 generated triples pull 2 random shares each.
        let d = PreprocDemand {
            triples: 7,
            ..Default::default()
        };
        let plan = d.to_generate(&have, t);
        assert_eq!(plan.triples, 9);
        assert_eq!(plan.triples % group, 0);
        assert_eq!(plan.random_shares, 18);

        // Direct random-share demand is added on top of the per-triple cost.
        let d = PreprocDemand {
            triples: 7,
            random_shares: 4,
            ..Default::default()
        };
        assert_eq!(d.to_generate(&have, t).random_shares, 4 + 18);

        // Already-held material offsets the shortfall.
        have.beaver_triples = 9;
        have.random_shr = 4;
        let plan = d.to_generate(&have, t);
        assert!(plan.is_empty(), "satisfied demand should generate nothing");

        // Held triples but a random-share gap: no triples, no per-triple cost.
        have.random_shr = 1;
        let plan = d.to_generate(&have, t);
        assert_eq!(plan.triples, 0);
        assert_eq!(plan.random_shares, 3);
    }

    #[tokio::test]
    async fn test_preproc_material_add_and_take() {
        let mut cache = HoneyBadgerMPCNodePreprocMaterial::<Fr>::empty();

        // Create dummy data
        let triple = ShamirBeaverTriple::<Fr>::new(
            RobustShare::new(Fr::from(0), 1, 1),
            RobustShare::new(Fr::from(0), 1, 1),
            RobustShare::new(Fr::from(0), 1, 1),
        );
        let share = RobustShare::new(Fr::from(0), 1, 1);

        cache.add(
            Some(vec![triple.clone(), triple.clone()]),
            Some(vec![share.clone()]),
            None,
            None,
            None,
        );

        assert_eq!(
            cache.length(),
            PreprocMaterialLength {
                beaver_triples: 2,
                random_shr: 1,
                random_shr_small_field: 0,
                prandbit: 0,
                prandint: 0,
                premulc: 0,
                zero_shares: 0,
                zero_shares_small_field: 0,
                rand_inv_pairs: 0
            }
        );

        // Take Beaver triples
        let triples = cache.take_beaver_triples(1).unwrap();
        assert_eq!(triples.len(), 1);
        assert_eq!(
            cache.length(),
            PreprocMaterialLength {
                beaver_triples: 1,
                random_shr: 1,
                random_shr_small_field: 0,
                prandbit: 0,
                prandint: 0,
                premulc: 0,
                zero_shares: 0,
                zero_shares_small_field: 0,
                rand_inv_pairs: 0
            }
        );

        // Take too many → error
        let err = cache.take_beaver_triples(10).unwrap_err();
        assert!(matches!(err, HoneyBadgerError::NotEnoughPreprocessing));
    }
}
