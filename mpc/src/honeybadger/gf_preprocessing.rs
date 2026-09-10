//! GF(2^k) equivalent of `preprocessing` (`honeybadger::preprocessing`), a direct structural
//! port. Holds only `beaver_triples`/`random_shares`

use thiserror::Error;
use tracing::error;

use crate::common::gf2k::field::BinaryField;
use crate::common::gf2k::share::GfShare;
use crate::honeybadger::gf_triple_gen::GfBeaverTriple;

#[derive(Debug, Error)]
pub enum GfPreprocessingError {
    #[error("there is not enough preprocessing to complete the protocol")]
    NotEnoughPreprocessing,
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub struct GfPreprocMaterialLength {
    pub beaver_triples: usize,
    pub random_shr: usize,
}

impl GfPreprocMaterialLength {
    pub fn zero() -> Self {
        Self {
            beaver_triples: 0,
            random_shr: 0,
        }
    }
}

/// Preprocessing material for a GF(2^k) HoneyBadgerMPC node.
#[derive(Clone, Debug)]
pub struct GfHoneyBadgerMPCNodePreprocMaterial<K: BinaryField> {
    /// A pool of Beaver triples used for secure multiplication.
    beaver_triples: Vec<GfBeaverTriple<K>>,
    /// A pool of random shares used for inputting private data for the protocol.
    random_shares: Vec<GfShare<K>>,
}

impl<K: BinaryField> GfHoneyBadgerMPCNodePreprocMaterial<K> {
    /// Generates empty preprocessing material storage.
    pub fn empty() -> Self {
        Self {
            beaver_triples: Vec::new(),
            random_shares: Vec::new(),
        }
    }

    /// Adds the provided new preprocessing material to the current pool.
    pub fn add(
        &mut self,
        mut triples: Option<Vec<GfBeaverTriple<K>>>,
        mut random_shares: Option<Vec<GfShare<K>>>,
    ) {
        if let Some(pairs) = &mut triples {
            self.beaver_triples.append(pairs);
        }

        if let Some(shares) = &mut random_shares {
            self.random_shares.append(shares);
        }
    }

    /// Returns the number of Beaver triples and the number of random shares, respectively.
    pub fn length(&self) -> GfPreprocMaterialLength {
        GfPreprocMaterialLength {
            beaver_triples: self.beaver_triples.len(),
            random_shr: self.random_shares.len(),
        }
    }

    /// Take `n_triples` Beaver triples from the preprocessing material.
    pub fn take_beaver_triples(
        &mut self,
        n_triples: usize,
    ) -> Result<Vec<GfBeaverTriple<K>>, GfPreprocessingError> {
        if n_triples > self.beaver_triples.len() {
            error!("Error trying to take triples: There is no enough preprocessing");
            return Err(GfPreprocessingError::NotEnoughPreprocessing);
        }
        Ok(self.beaver_triples.drain(0..n_triples).collect())
    }

    /// Take `n_shares` random shares from the preprocessing material.
    pub fn take_random_shares(
        &mut self,
        n_shares: usize,
    ) -> Result<Vec<GfShare<K>>, GfPreprocessingError> {
        if n_shares > self.random_shares.len() {
            error!("Error trying to take random shares: There is no enough preprocessing");
            return Err(GfPreprocessingError::NotEnoughPreprocessing);
        }
        Ok(self.random_shares.drain(0..n_shares).collect())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::common::gf2k::field::Gf256;

    #[tokio::test]
    async fn test_gf_preproc_material_add_and_take() {
        let mut cache = GfHoneyBadgerMPCNodePreprocMaterial::<Gf256>::empty();

        let triple = GfBeaverTriple::<Gf256>::new(
            GfShare::new(Gf256(0), 1, 1),
            GfShare::new(Gf256(0), 1, 1),
            GfShare::new(Gf256(0), 1, 1),
        );
        let share = GfShare::new(Gf256(0), 1, 1);

        cache.add(Some(vec![triple.clone(), triple.clone()]), Some(vec![share.clone()]));

        assert_eq!(
            cache.length(),
            GfPreprocMaterialLength {
                beaver_triples: 2,
                random_shr: 1,
            }
        );

        let triples = cache.take_beaver_triples(1).unwrap();
        assert_eq!(triples.len(), 1);
        assert_eq!(
            cache.length(),
            GfPreprocMaterialLength {
                beaver_triples: 1,
                random_shr: 1,
            }
        );

        let err = cache.take_beaver_triples(10).unwrap_err();
        assert!(matches!(err, GfPreprocessingError::NotEnoughPreprocessing));
    }
}
