use crate::honeybadger::{
    fpmul::f256::Gf2568, robust_interpolate::robust_interpolate::RobustShare,
    triple_gen::ShamirBeaverTriple, HoneyBadgerError,
};
use ark_ff::FftField;

/// Preprocessing material for the HoneyBadgerMPCNode protocol.
#[derive(Clone, Debug)]
pub struct HoneyBadgerMPCNodePreprocMaterial<F: FftField> {
    /// A pool of random double shares used for secure multiplication.
    beaver_triples: Vec<ShamirBeaverTriple<F>>,
    /// A pool of random shares used for inputing private data for the protocol.
    random_shares: Vec<RobustShare<F>>,
    ///A pool of PRandBit outputs for truncation
    prandbit_shares: Vec<(RobustShare<F>, Gf2568)>,
    ///A pool of PRandInt outputs for truncation
    prandint_shares: Vec<RobustShare<F>>,
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
        }
    }

    /// Adds the provided new preprocessing material to the current pool.
    pub fn add(
        &mut self,
        mut triples: Option<Vec<ShamirBeaverTriple<F>>>,
        mut random_shares: Option<Vec<RobustShare<F>>>,
        mut prandbit_shares: Option<Vec<(RobustShare<F>, Gf2568)>>,
        mut prandbit_int: Option<Vec<RobustShare<F>>>,
    ) {
        if let Some(pairs) = &mut triples {
            self.beaver_triples.append(pairs);
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
    pub fn len(&self) -> (usize, usize, usize, usize) {
        (
            self.beaver_triples.len(),
            self.random_shares.len(),
            self.prandbit_shares.len(),
            self.prandint_shares.len(),
        )
    }

    /// Take up to n pairs of random double sharings from the preprocessing material.
    pub fn take_beaver_triples(
        &mut self,
        n_triples: usize,
    ) -> Result<Vec<ShamirBeaverTriple<F>>, HoneyBadgerError> {
        if n_triples > self.beaver_triples.len() {
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
            return Err(HoneyBadgerError::NotEnoughPreprocessing);
        }
        Ok(self.random_shares.drain(0..n_shares).collect())
    }
    pub fn take_prandbit_shares(
        &mut self,
        n_prandbit: usize,
    ) -> Result<Vec<(RobustShare<F>, Gf2568)>, HoneyBadgerError> {
        if n_prandbit > self.prandbit_shares.len() {
            return Err(HoneyBadgerError::NotEnoughPreprocessing);
        }
        Ok(self.prandbit_shares.drain(0..n_prandbit).collect())
    }
    pub fn take_prandint_shares(
        &mut self,
        n_prandint: usize,
    ) -> Result<Vec<RobustShare<F>>, HoneyBadgerError> {
        if n_prandint > self.prandint_shares.len() {
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

        assert_eq!(cache.len(), (2, 1, 0, 0));

        // Take Beaver triples
        let triples = cache.take_beaver_triples(1).unwrap();
        assert_eq!(triples.len(), 1);
        assert_eq!(cache.len(), (1, 1, 0, 0));

        // Take too many → error
        let err = cache.take_beaver_triples(10).unwrap_err();
        assert!(matches!(err, HoneyBadgerError::NotEnoughPreprocessing));
    }
}
