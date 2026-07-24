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
use tracing::error;

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
    /// A pool of random Breaver triples in the Goldilocks field.
    beaver_triples_small_field: Vec<ShamirBeaverTriple<GoldilocksField>>,
    /// A pool of PreMulC offline-phase bundles (all sized at the same
    /// configured `premulc_pk`), topped up by `run_preprocessing`.
    premulc_preps: Vec<PreMulCPrep<F>>,
    /// A pool of degree-2t zero-sharings (ZeroShaNode output).
    zero_shares: Vec<RobustShare<F>>,
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub struct PreprocMaterialLength {
    pub beaver_triples: usize,
    pub beaver_triples_small_field: usize,
    pub random_shr: usize,
    pub random_shr_small_field: usize,
    pub prandbit: usize,
    pub prandint: usize,
    pub premulc: usize,
    pub zero_shares: usize,
}

impl PreprocMaterialLength {
    pub fn zero() -> Self {
        Self {
            beaver_triples: 0,
            beaver_triples_small_field: 0,
            random_shr: 0,
            random_shr_small_field: 0,
            prandbit: 0,
            prandint: 0,
            premulc: 0,
            zero_shares: 0,
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
            beaver_triples_small_field: Vec::new(),
            prandbit_shares: Vec::new(),
            prandint_shares: Vec::new(),
            random_shares_small_field: Vec::new(),
            premulc_preps: Vec::new(),
            zero_shares: Vec::new(),
        }
    }

    /// Adds one PreMulC offline-phase bundle to the pool.
    pub fn add_premulc_prep(&mut self, prep: PreMulCPrep<F>) {
        self.premulc_preps.push(prep);
    }

    /// Takes the next queued PreMulC preprocessing bundle.
    pub fn take_premulc_prep(&mut self) -> Result<PreMulCPrep<F>, HoneyBadgerError> {
        if self.premulc_preps.is_empty() {
            error!("Error trying to take PreMulC prep: there is no enough preprocessing");
            return Err(HoneyBadgerError::NotEnoughPreprocessing);
        }
        Ok(self.premulc_preps.remove(0))
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

    /// Adds the provided new preprocessing material to the current pool.
    pub fn add(
        &mut self,
        mut triples: Option<Vec<ShamirBeaverTriple<F>>>,
        mut triples_small_field: Option<Vec<ShamirBeaverTriple<GoldilocksField>>>,
        mut random_shares: Option<Vec<RobustShare<F>>>,
        mut random_shares_small_field: Option<Vec<RobustShare<GoldilocksField>>>,
        mut prandbit_shares: Option<Vec<(RobustShare<F>, Gf256)>>,
        mut prandbit_int: Option<Vec<RobustShare<F>>>,
    ) {
        if let Some(pairs) = &mut triples {
            self.beaver_triples.append(pairs);
        }

        if let Some(triples) = &mut triples_small_field {
            self.beaver_triples_small_field.append(triples);
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
            beaver_triples_small_field: self.beaver_triples_small_field.len(),
            random_shr: self.random_shares.len(),
            random_shr_small_field: self.random_shares_small_field.len(),
            prandbit: self.prandbit_shares.len(),
            prandint: self.prandint_shares.len(),
            premulc: self.premulc_preps.len(),
            zero_shares: self.zero_shares.len(),
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

    pub fn take_beaver_triples_small_field(
        &mut self,
        n_triples: usize,
    ) -> Result<Vec<ShamirBeaverTriple<GoldilocksField>>, HoneyBadgerError> {
        let current_beaver_triples = self.beaver_triples_small_field.len();
        if n_triples > current_beaver_triples {
            error!(
                "Error trying to take triples in the small field: There is no enough preprocessing. Current Beaver triples: {current_beaver_triples}, Needed Beaver triples: {n_triples}"
            );
            return Err(HoneyBadgerError::NotEnoughPreprocessing);
        }
        Ok(self
            .beaver_triples_small_field
            .drain(0..n_triples)
            .collect())
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
        let bitdec_prandm = self.take_prandm_prep(k - 1)?;
        let bitdec_mul_triples = self.take_beaver_triples(k - 2)?;
        let mut bitdec_mod2_preps = Vec::with_capacity(k - 1);
        for _ in 0..k - 1 {
            bitdec_mod2_preps.push(self.take_mod2_prandm_prep()?);
        }
        let bitdec_prep = PreMod2mPrep {
            prandm: bitdec_prandm,
            pre_bitlt: PreBitLTPrep {
                suf_mul_inv_prep: bitdec_suf_mul_inv_prep,
                mul_triples: bitdec_mul_triples,
                mod2_preps: bitdec_mod2_preps,
            },
        };

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
            let round_b_triple = self.take_beaver_triples(1)?;
            let step6 = self.take_prandm_prep(2 * f)?;
            let step7 = self.take_prandm_prep(2 * f)?;
            let step8 = self.take_prandm_prep(2 * f)?;
            iters.push(FpDivIterPrep {
                round_a_triples,
                round_b_triple,
                step6_trunc_r_bits: step6.r_prime_bits,
                step6_trunc_r_int: step6.r_double_prime,
                step7_trunc_r_bits: step7.r_prime_bits,
                step7_trunc_r_int: step7.r_double_prime,
                step8_trunc_r_bits: step8.r_prime_bits,
                step8_trunc_r_int: step8.r_double_prime,
            });
        }

        Ok(FpDivPrep {
            app_rec_prep,
            step3_4_triples: self.take_beaver_triples(2)?,
            step3_trunc_r_bits: step3_trunc_prandm.r_prime_bits,
            step3_trunc_r_int: step3_trunc_prandm.r_double_prime,
            iters,
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
            None,
            Some(vec![share.clone()]),
            None,
            None,
            None,
        );

        assert_eq!(
            cache.length(),
            PreprocMaterialLength {
                beaver_triples: 2,
                beaver_triples_small_field: 0,
                random_shr: 1,
                random_shr_small_field: 0,
                prandbit: 0,
                prandint: 0,
                premulc: 0,
                zero_shares: 0
            }
        );

        // Take Beaver triples
        let triples = cache.take_beaver_triples(1).unwrap();
        assert_eq!(triples.len(), 1);
        assert_eq!(
            cache.length(),
            PreprocMaterialLength {
                beaver_triples: 1,
                beaver_triples_small_field: 0,
                random_shr: 1,
                random_shr_small_field: 0,
                prandbit: 0,
                prandint: 0,
                premulc: 0,
                zero_shares: 0
            }
        );

        // Take too many → error
        let err = cache.take_beaver_triples(10).unwrap_err();
        assert!(matches!(err, HoneyBadgerError::NotEnoughPreprocessing));
    }
}
