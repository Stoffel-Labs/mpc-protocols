//! Conversion preprocessing pools — the daBit and edaBit equivalents of `preprocessing` and
//! `gf_preprocessing`, and a direct structural port of them.
//!
//! A third store rather than an extension of either existing one:
//! `HoneyBadgerMPCNodePreprocMaterial<F>` is not generic in `K` and
//! `GfHoneyBadgerMPCNodePreprocMaterial<K>` is not generic in `F`, and making either generic in
//! the other churns every call site for no gain.
//!
//! # INVARIANT (C15): drain, never index
//!
//! Both pools are **FIFO `drain(0..n)` only**. There is no PRF stream and no cursor, so the
//! rewind hazard that the deleted `prandint_cursor` had cannot arise here. That matters more than it looks: a
//! daBit handed out twice is one-time-pad reuse, and two B2A openings under the same daBit reveal
//! `c XOR c' = x XOR x'`. [`ConvPreprocMaterial::dabits_produced`] counts total-ever-generated for
//! sizing and observability and is **never** an index into anything.

use thiserror::Error;
use tracing::error;

use ark_ff::PrimeField;

use crate::common::gf2k::field::BinaryField;
use crate::honeybadger::dabit::{DaBit, EdaBit};

#[derive(Debug, Error)]
pub enum ConvPreprocessingError {
    #[error("there is not enough conversion preprocessing to complete the protocol")]
    NotEnoughPreprocessing,
}

/// Current depth of each pool.
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub struct ConvPreprocMaterialLength {
    pub dabits: usize,
    pub edabits: usize,
}

impl ConvPreprocMaterialLength {
    pub fn zero() -> Self {
        Self {
            dabits: 0,
            edabits: 0,
        }
    }
}

/// Conversion preprocessing material for a HoneyBadgerMPC node.
#[derive(Clone, Debug)]
pub struct ConvPreprocMaterial<F: PrimeField, K: BinaryField> {
    /// A pool of doubly-shared bits, consumed by B2A (one per input bit) and by edaBit
    /// composition.
    dabits: Vec<DaBit<F, K>>,
    /// A pool of full-range edaBits, consumed by A2B (one per converted value). "Full-range"
    /// means `width == field_bit_width::<F>()` and `r < p`, i.e. the modulus-overflow filter has
    /// already rejected the wrapping masks.
    edabits: Vec<EdaBit<F, K>>,
    /// Total ever produced. Observability and sizing only — never an index (see the module docs).
    dabits_produced: usize,
    edabits_produced: usize,
}

impl<F: PrimeField, K: BinaryField> ConvPreprocMaterial<F, K> {
    /// Generates empty conversion preprocessing storage.
    pub fn empty() -> Self {
        Self {
            dabits: Vec::new(),
            edabits: Vec::new(),
            dabits_produced: 0,
            edabits_produced: 0,
        }
    }

    /// Adds the provided new preprocessing material to the current pools.
    pub fn add(&mut self, dabits: Option<Vec<DaBit<F, K>>>, edabits: Option<Vec<EdaBit<F, K>>>) {
        if let Some(mut new) = dabits {
            self.dabits_produced = self.dabits_produced.saturating_add(new.len());
            self.dabits.append(&mut new);
        }
        if let Some(mut new) = edabits {
            self.edabits_produced = self.edabits_produced.saturating_add(new.len());
            self.edabits.append(&mut new);
        }
    }

    /// Returns the current depth of both pools.
    pub fn length(&self) -> ConvPreprocMaterialLength {
        ConvPreprocMaterialLength {
            dabits: self.dabits.len(),
            edabits: self.edabits.len(),
        }
    }

    /// Total daBits ever added to this store. Monotone; never a pool depth and never an index.
    pub fn dabits_produced(&self) -> usize {
        self.dabits_produced
    }

    /// Total edaBits ever added to this store. Monotone; never a pool depth and never an index.
    pub fn edabits_produced(&self) -> usize {
        self.edabits_produced
    }

    /// Takes `n` daBits out of the pool.
    ///
    /// `drain`, not index: the returned daBits are gone from the pool, so a second call can never
    /// return one of them again. That is the whole of the single-use guarantee.
    pub fn take_dabits(&mut self, n: usize) -> Result<Vec<DaBit<F, K>>, ConvPreprocessingError> {
        if n > self.dabits.len() {
            error!("Error trying to take daBits: there is not enough conversion preprocessing");
            return Err(ConvPreprocessingError::NotEnoughPreprocessing);
        }
        Ok(self.dabits.drain(0..n).collect())
    }

    /// Takes `n` edaBits out of the pool. Same drain-only discipline as [`Self::take_dabits`].
    pub fn take_edabits(&mut self, n: usize) -> Result<Vec<EdaBit<F, K>>, ConvPreprocessingError> {
        if n > self.edabits.len() {
            error!("Error trying to take edaBits: there is not enough conversion preprocessing");
            return Err(ConvPreprocessingError::NotEnoughPreprocessing);
        }
        Ok(self.edabits.drain(0..n).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::gf2k::field::Gf256;
    use crate::common::gf2k::share::GfShare;
    use crate::common::math::goldilocks::GoldilocksField;
    use crate::honeybadger::robust_interpolate::robust_interpolate::RobustShare;

    type F = GoldilocksField;
    type K = Gf256;

    fn dabit(value: u64) -> DaBit<F, K> {
        DaBit::new(
            RobustShare::new(F::from(value), 0, 1),
            GfShare::new(Gf256(value as u8), 0, 1),
            1,
        )
        .unwrap()
    }

    fn edabit(value: u64) -> EdaBit<F, K> {
        EdaBit::compose(&[dabit(value), dabit(0), dabit(0), dabit(0)], 4).unwrap()
    }

    #[test]
    fn add_length_and_take() {
        let mut pool = ConvPreprocMaterial::<F, K>::empty();
        assert_eq!(pool.length(), ConvPreprocMaterialLength::zero());

        pool.add(Some(vec![dabit(0), dabit(1)]), Some(vec![edabit(1)]));
        assert_eq!(
            pool.length(),
            ConvPreprocMaterialLength {
                dabits: 2,
                edabits: 1
            }
        );

        assert_eq!(pool.take_dabits(1).unwrap().len(), 1);
        assert_eq!(
            pool.length(),
            ConvPreprocMaterialLength {
                dabits: 1,
                edabits: 1
            }
        );
        assert_eq!(pool.take_edabits(1).unwrap().len(), 1);
    }

    #[test]
    fn take_more_than_available_is_an_error_and_leaves_the_pool_intact() {
        let mut pool = ConvPreprocMaterial::<F, K>::empty();
        pool.add(Some(vec![dabit(0)]), None);
        assert!(matches!(
            pool.take_dabits(2),
            Err(ConvPreprocessingError::NotEnoughPreprocessing)
        ));
        assert_eq!(pool.length().dabits, 1);
        assert!(matches!(
            pool.take_edabits(1),
            Err(ConvPreprocessingError::NotEnoughPreprocessing)
        ));
    }

    #[test]
    fn successive_takes_never_overlap() {
        // C15: the single-use property. Two drains of the same pool must return disjoint ranges,
        // because a daBit returned twice turns two B2A openings into `c XOR c' = x XOR x'`.
        let mut pool = ConvPreprocMaterial::<F, K>::empty();
        pool.add(Some((0..6u64).map(dabit).collect()), None);
        let first = pool.take_dabits(3).unwrap();
        let second = pool.take_dabits(3).unwrap();
        for a in &first {
            assert!(
                !second.iter().any(|b| b == a),
                "a daBit was handed out twice"
            );
        }
        assert_eq!(pool.length().dabits, 0);
    }

    #[test]
    fn produced_counters_only_ever_increase() {
        let mut pool = ConvPreprocMaterial::<F, K>::empty();
        pool.add(Some(vec![dabit(0), dabit(1)]), Some(vec![edabit(1)]));
        assert_eq!(pool.dabits_produced(), 2);
        assert_eq!(pool.edabits_produced(), 1);
        // Draining the pool must not move the produced counters.
        let _ = pool.take_dabits(2).unwrap();
        let _ = pool.take_edabits(1).unwrap();
        assert_eq!(pool.dabits_produced(), 2);
        assert_eq!(pool.edabits_produced(), 1);
        pool.add(Some(vec![dabit(0)]), None);
        assert_eq!(pool.dabits_produced(), 3);
    }
}
