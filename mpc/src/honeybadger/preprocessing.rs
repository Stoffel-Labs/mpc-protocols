use crate::honeybadger::{
    robust_interpolate::robust_interpolate::RobustShare, triple_gen::ShamirBeaverTriple,
    HoneyBadgerError,
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
    /// A pool of RandBit outputs for truncation
    randbit_shares: Vec<RobustShare<F>>,
    /// A pool of PRandInt outputs for truncation
    prandint_shares: Vec<RobustShare<F>>,
    /// Count of PRandInt masks ever generated, independent of how many have since been consumed.
    prandint_cursor: usize,
    /// A pool of degree-`2t` sharings of zero, consumed by RandBit's MulPub opening.
    zero_shares: Vec<RobustShare<F>>,
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub struct PreprocMaterialLength {
    pub beaver_triples: usize,
    pub random_shr: usize,
    pub randbit: usize,
    pub prandint: usize,
    pub zero_shares: usize,
}

impl PreprocMaterialLength {
    pub fn zero() -> Self {
        Self {
            beaver_triples: 0,
            random_shr: 0,
            randbit: 0,
            prandint: 0,
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
            randbit_shares: Vec::new(),
            prandint_shares: Vec::new(),
            prandint_cursor: 0,
            zero_shares: Vec::new(),
        }
    }

    /// Adds the provided new preprocessing material to the current pool.
    pub fn add(
        &mut self,
        mut triples: Option<Vec<ShamirBeaverTriple<F>>>,
        mut random_shares: Option<Vec<RobustShare<F>>>,
        mut randbit_shares: Option<Vec<RobustShare<F>>>,
        mut prandint_shares: Option<Vec<RobustShare<F>>>,
    ) {
        if let Some(pairs) = &mut triples {
            self.beaver_triples.append(pairs);
        }

        if let Some(shares) = &mut random_shares {
            self.random_shares.append(shares);
        }

        if let Some(shares) = &mut randbit_shares {
            self.randbit_shares.append(shares);
        }
        if let Some(shares) = &mut prandint_shares {
            self.prandint_cursor += shares.len();
            self.prandint_shares.append(shares);
        }
    }

    /// Absolute PRSS position to derive the next batch of PRandInt masks at. Tracks total
    /// generation, not remaining pool depth, so it only ever advances.
    pub fn prandint_cursor(&self) -> usize {
        self.prandint_cursor
    }

    /// Returns the number of random double share pairs, and the number of random shares
    /// respectively.
    pub fn length(&self) -> PreprocMaterialLength {
        PreprocMaterialLength {
            beaver_triples: self.beaver_triples.len(),
            random_shr: self.random_shares.len(),
            randbit: self.randbit_shares.len(),
            prandint: self.prandint_shares.len(),
            zero_shares: self.zero_shares.len(),
        }
    }

    /// Adds degree-`2t` zero-sharings to the pool.
    pub fn add_zero_shares(&mut self, mut shares: Vec<RobustShare<F>>) {
        self.zero_shares.append(&mut shares);
    }

    /// Take `n_shares` degree-`2t` zero-sharings from the preprocessing material.
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

    pub fn take_randbit_shares(
        &mut self,
        n_randbit: usize,
    ) -> Result<Vec<RobustShare<F>>, HoneyBadgerError> {
        if n_randbit > self.randbit_shares.len() {
            error!("Error trying to take RandBit shares: There is no enough preprocessing");
            return Err(HoneyBadgerError::NotEnoughPreprocessing);
        }
        Ok(self.randbit_shares.drain(0..n_randbit).collect())
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
            Some(vec![share.clone()]),
            None,
            None,
        );

        assert_eq!(
            cache.length(),
            PreprocMaterialLength {
                beaver_triples: 2,
                random_shr: 1,
                randbit: 0,
                prandint: 0,
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
                random_shr: 1,
                randbit: 0,
                prandint: 0,
                zero_shares: 0
            }
        );

        // Take too many → error
        let err = cache.take_beaver_triples(10).unwrap_err();
        assert!(matches!(err, HoneyBadgerError::NotEnoughPreprocessing));
    }
}
