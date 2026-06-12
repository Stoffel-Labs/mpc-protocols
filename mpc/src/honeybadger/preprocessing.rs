use std::{collections::HashMap, sync::Arc};

use crate::{
    common::math::goldilocks::GoldilocksField,
    honeybadger::{
        fpmul::f256::Gf256, robust_interpolate::robust_interpolate::RobustShare,
        triple_gen::ShamirBeaverTriple, HoneyBadgerError,
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
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub struct PreprocMaterialLength {
    pub beaver_triples: usize,
    pub beaver_triples_small_field: usize,
    pub random_shr: usize,
    pub random_shr_small_field: usize,
    pub prandbit: usize,
    pub prandint: usize,
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
        }
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
                prandint: 0
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
                prandint: 0
            }
        );

        // Take too many → error
        let err = cache.take_beaver_triples(10).unwrap_err();
        assert!(matches!(err, HoneyBadgerError::NotEnoughPreprocessing));
    }
}
