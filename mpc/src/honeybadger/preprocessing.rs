use crate::honeybadger::{
    fpmul::f256::F2_8, robust_interpolate::robust_interpolate::RobustShare,
    triple_gen::ShamirBeaverTriple, HoneyBadgerError,
};
use ark_ff::FftField;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;
use uuid::Uuid;

/// Preprocessing material for the HoneyBadgerMPCNode protocol.
#[derive(Clone, Debug)]
pub struct HoneyBadgerMPCNodePreprocMaterial<F: FftField> {
    /// A pool of random double shares used for secure multiplication.
    beaver_triples: Vec<ShamirBeaverTriple<F>>,
    /// A pool of random shares used for inputing private data for the protocol.
    random_shares: Vec<RobustShare<F>>,
    ///A pool of PRandBit outputs for truncation
    prandbit_shares: Vec<(RobustShare<F>, F2_8)>,
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
        mut prandbit_shares: Option<Vec<(RobustShare<F>, F2_8)>>,
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
    ) -> Result<Vec<(RobustShare<F>, F2_8)>, HoneyBadgerError> {
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

#[derive(Clone, Debug)]
pub struct PreprocBatchMetadata {
    pub id: Uuid, // Make this deterministic?
    pub kind: PreprocKind,
    pub field_name: String,
    pub n: usize,
    pub t: usize,
    pub instance_id: Vec<u8>,
    pub reserved: Option<Uuid>, //Client id
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Indexed<T> {
    pub index: usize,
    pub value: T,
}

#[derive(Clone, Debug)]
pub struct PreprocBatch<F: FftField> {
    pub meta: PreprocBatchMetadata,
    pub contents: PreprocContents<F>,
}

#[derive(Clone, Copy, Debug)]
pub enum PreprocKind {
    /// Random double shares used for secure multiplication (Beaver triples)
    BeaverTriple,
    /// Random shared values used for secret inputs
    RandomShare,
    /// PRandBit outputs used for truncation
    PRandBit,
    /// PRandInt outputs used for truncation
    PRandInt,
}
#[derive(Clone, Debug)]
pub enum PreprocContents<F: FftField> {
    BeaverTriples(Vec<Indexed<ShamirBeaverTriple<F>>>),
    RandomShares(Vec<Indexed<RobustShare<F>>>),
    PRandBits(Vec<Indexed<(RobustShare<F>, F2_8)>>),
    PRandInts(Vec<Indexed<RobustShare<F>>>),
}

#[async_trait]
pub trait PreprocBatchOps<F: FftField>: Send + Sync {
    /// Create a new batch from the current preprocessing cache.
    /// This drains relevant materials from the cache and returns a `PreprocBatch`.
    async fn from_cache(
        cache: &mut HoneyBadgerMPCNodePreprocMaterial<F>,
        field_name: &str,
        n: usize,
        t: usize,
        seed: Vec<u8>,
    ) -> Result<Vec<PreprocBatch<F>>, HoneyBadgerError>;

    /// Load this batch's materials back into the given cache.
    async fn load_into_cache(
        &self,
        cache: &mut HoneyBadgerMPCNodePreprocMaterial<F>,
    ) -> Result<(), HoneyBadgerError>;

    /// Reserve this batch for a specific client UUID.
    /// Returns the batch's own UUID.
    async fn reserve_with_registry(
        &mut self,
        client_id: Uuid,
        registry: &PreprocReservationRegistry,
    ) -> Result<Uuid, HoneyBadgerError>;
    /// Get this batch’s unique ID.
    fn id(&self) -> Uuid;
}

#[async_trait]
impl<F: FftField> PreprocBatchOps<F> for PreprocBatch<F> {
    async fn from_cache(
        cache: &mut HoneyBadgerMPCNodePreprocMaterial<F>,
        field_name: &str,
        n: usize,
        t: usize,
        instance_id: Vec<u8>, // Instance/session ID
    ) -> Result<Vec<PreprocBatch<F>>, HoneyBadgerError> {
        let mut batches = Vec::new();

        // Helper closure for deterministic UUID generation
        let mk_id = |kind: PreprocKind| {
            Uuid::new_v5(
                &Uuid::NAMESPACE_OID,
                format!("{}:{}:{}:{:?}:{:x?}", field_name, n, t, kind, instance_id).as_bytes(),
            )
        };

        // -- Beaver Triples -----------------------------------------------------
        if !cache.beaver_triples.is_empty() {
            let triples = cache
                .beaver_triples
                .drain(..)
                .enumerate()
                .map(|(i, v)| Indexed { index: i, value: v })
                .collect();

            batches.push(PreprocBatch {
                meta: PreprocBatchMetadata {
                    id: mk_id(PreprocKind::BeaverTriple),
                    kind: PreprocKind::BeaverTriple,
                    field_name: field_name.to_string(),
                    n,
                    t,
                    instance_id: instance_id.clone(),
                    reserved: None,
                },
                contents: PreprocContents::BeaverTriples(triples),
            });
        }

        // -- Random Shares -----------------------------------------------------
        if !cache.random_shares.is_empty() {
            let shares = cache
                .random_shares
                .drain(..)
                .enumerate()
                .map(|(i, v)| Indexed { index: i, value: v })
                .collect();

            batches.push(PreprocBatch {
                meta: PreprocBatchMetadata {
                    id: mk_id(PreprocKind::RandomShare),
                    kind: PreprocKind::RandomShare,
                    field_name: field_name.to_string(),
                    n,
                    t,
                    instance_id: instance_id.clone(),
                    reserved: None,
                },
                contents: PreprocContents::RandomShares(shares),
            });
        }

        // -- PRandBit Shares ---------------------------------------------------
        if !cache.prandbit_shares.is_empty() {
            let bits = cache
                .prandbit_shares
                .drain(..)
                .enumerate()
                .map(|(i, v)| Indexed { index: i, value: v })
                .collect();

            batches.push(PreprocBatch {
                meta: PreprocBatchMetadata {
                    id: mk_id(PreprocKind::PRandBit),
                    kind: PreprocKind::PRandBit,
                    field_name: field_name.to_string(),
                    n,
                    t,
                    instance_id: instance_id.clone(),
                    reserved: None,
                },
                contents: PreprocContents::PRandBits(bits),
            });
        }

        // -- PRandInt Shares ---------------------------------------------------
        if !cache.prandint_shares.is_empty() {
            let ints = cache
                .prandint_shares
                .drain(..)
                .enumerate()
                .map(|(i, v)| Indexed { index: i, value: v })
                .collect();

            batches.push(PreprocBatch {
                meta: PreprocBatchMetadata {
                    id: mk_id(PreprocKind::PRandInt),
                    kind: PreprocKind::PRandInt,
                    field_name: field_name.to_string(),
                    n,
                    t,
                    instance_id,
                    reserved: None,
                },
                contents: PreprocContents::PRandInts(ints),
            });
        }

        Ok(batches)
    }

    async fn load_into_cache(
        &self,
        cache: &mut HoneyBadgerMPCNodePreprocMaterial<F>,
    ) -> Result<(), HoneyBadgerError> {
        match &self.contents {
            PreprocContents::BeaverTriples(v) => {
                cache
                    .beaver_triples
                    .extend(v.iter().map(|x| x.value.clone()));
            }
            PreprocContents::RandomShares(v) => {
                cache
                    .random_shares
                    .extend(v.iter().map(|x| x.value.clone()));
            }
            PreprocContents::PRandBits(v) => {
                cache
                    .prandbit_shares
                    .extend(v.iter().map(|x| x.value.clone()));
            }
            PreprocContents::PRandInts(v) => {
                cache
                    .prandint_shares
                    .extend(v.iter().map(|x| x.value.clone()));
            }
        }
        Ok(())
    }

    async fn reserve_with_registry(
        &mut self,
        client_id: Uuid,
        registry: &PreprocReservationRegistry,
    ) -> Result<Uuid, HoneyBadgerError> {
        if self.meta.reserved.is_some() {
            return Err(HoneyBadgerError::AlreadyReserved);
        }

        self.meta.reserved = Some(client_id);
        registry.reserve(client_id, self.meta.id).await;

        tracing::info!("Batch {} reserved for client {}", self.meta.id, client_id);

        Ok(self.meta.id)
    }

    fn id(&self) -> Uuid {
        self.meta.id
    }
}

/// Tracks which client reserved which preprocessing batches.
#[derive(Clone, Default)]
pub struct PreprocReservationRegistry {
    inner: Arc<Mutex<HashMap<Uuid, Vec<Uuid>>>>, // client_id -> list of batch_ids
}

impl PreprocReservationRegistry {
    /// Create a new, empty registry.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Reserve a batch for a specific client.
    pub async fn reserve(&self, client_id: Uuid, batch_id: Uuid) {
        let mut guard = self.inner.lock().await;
        guard
            .entry(client_id)
            .or_insert_with(Vec::new)
            .push(batch_id);
    }

    /// Get all batch IDs reserved by a specific client.
    pub async fn get_reserved_batches(&self, client_id: &Uuid) -> Vec<Uuid> {
        let guard = self.inner.lock().await;
        guard.get(client_id).cloned().unwrap_or_default()
    }

    /// Release a specific batch reservation.
    pub async fn release_batch(&self, client_id: &Uuid, batch_id: &Uuid) {
        let mut guard = self.inner.lock().await;
        if let Some(v) = guard.get_mut(client_id) {
            v.retain(|b| b != batch_id);
            if v.is_empty() {
                guard.remove(client_id);
            }
        }
    }

    /// Release all batches reserved by a client.
    pub async fn release_all(&self, client_id: &Uuid) {
        let mut guard = self.inner.lock().await;
        guard.remove(client_id);
    }

    /// Get a full mapping snapshot (client -> batch list).
    pub async fn all(&self) -> HashMap<Uuid, Vec<Uuid>> {
        let guard = self.inner.lock().await;
        guard.clone()
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

    #[tokio::test]
    async fn test_from_cache_and_load_into_cache_symmetry() {
        let mut cache = HoneyBadgerMPCNodePreprocMaterial::<Fr>::empty();
        let triple = ShamirBeaverTriple::<Fr>::new(
            RobustShare::new(Fr::from(0), 1, 1),
            RobustShare::new(Fr::from(0), 1, 1),
            RobustShare::new(Fr::from(0), 1, 1),
        );
        let share = RobustShare::new(Fr::from(0), 1, 1);

        // Fill cache
        cache.add(
            Some(vec![triple.clone()]),
            Some(vec![share.clone()]),
            None,
            None,
        );

        // Create batches
        let instance_id = b"session_001".to_vec();
        let batches =
            PreprocBatch::<Fr>::from_cache(&mut cache, "ark_bls12_381::Fr", 4, 1, instance_id)
                .await
                .unwrap();

        // Verify cache drained
        assert_eq!(cache.len(), (0, 0, 0, 0));
        assert_eq!(batches.len(), 2);

        // Load one batch back into cache
        batches[0].load_into_cache(&mut cache).await.unwrap();

        // Ensure materials restored
        let (bt, rs, pb, pi) = cache.len();
        assert!(bt + rs + pb + pi > 0);
    }

    #[tokio::test]
    async fn test_reservation_registry_basic() {
        use uuid::Uuid;

        let registry = PreprocReservationRegistry::new();
        let client_a = Uuid::new_v4();
        let batch_1 = Uuid::new_v4();
        let batch_2 = Uuid::new_v4();

        // Reserve two batches
        registry.reserve(client_a, batch_1).await;
        registry.reserve(client_a, batch_2).await;

        // Query back
        let reserved = registry.get_reserved_batches(&client_a).await;
        assert_eq!(reserved.len(), 2);

        // Release one
        registry.release_batch(&client_a, &batch_1).await;
        let reserved = registry.get_reserved_batches(&client_a).await;
        assert_eq!(reserved, vec![batch_2]);

        // Release all
        registry.release_all(&client_a).await;
        let reserved = registry.get_reserved_batches(&client_a).await;
        assert!(reserved.is_empty());
    }

    #[tokio::test]
    async fn test_reserve_with_registry_on_batch() {
        let registry = PreprocReservationRegistry::new();
        let client_id = Uuid::new_v4();

        // Minimal batch
        let instance_id: Vec<u8> = b"session_001".to_vec();
        let mut batch = PreprocBatch {
            meta: PreprocBatchMetadata {
                id: Uuid::new_v4(),
                kind: PreprocKind::RandomShare,
                field_name: "ark_bls12_381::Fr".to_string(),
                n: 4,
                t: 1,
                instance_id,
                reserved: None,
            },
            contents: PreprocContents::<Fr>::RandomShares(vec![]),
        };

        // Reserve it
        let bid = batch
            .reserve_with_registry(client_id, &registry)
            .await
            .unwrap();
        assert_eq!(bid, batch.meta.id);
        assert_eq!(batch.meta.reserved, Some(client_id));

        // Verify registry updated
        let reserved = registry.get_reserved_batches(&client_id).await;
        assert_eq!(reserved, vec![bid]);

        // Double-reserve should error
        let err = batch
            .reserve_with_registry(client_id, &registry)
            .await
            .unwrap_err();
        assert!(matches!(err, HoneyBadgerError::AlreadyReserved));
    }

    #[tokio::test]
    async fn test_full_preprocessing_flow() {
        let mut cache = HoneyBadgerMPCNodePreprocMaterial::<Fr>::empty();
        let registry = PreprocReservationRegistry::new();

        let triple = ShamirBeaverTriple::<Fr>::new(
            RobustShare::new(Fr::from(0), 1, 1),
            RobustShare::new(Fr::from(0), 1, 1),
            RobustShare::new(Fr::from(0), 1, 1),
        );
        let share = RobustShare::new(Fr::from(0), 1, 1);
        cache.add(Some(vec![triple]), Some(vec![share]), None, None);

        // 1. Drain cache into batches
        let instance_id: Vec<u8> = b"session_001".to_vec();
        let mut batches =
            PreprocBatch::<Fr>::from_cache(&mut cache, "ark_bls12_381::Fr", 4, 1, instance_id)
                .await
                .unwrap();

        // 2. Reserve all for a client
        let client = Uuid::new_v4();
        for b in &mut batches {
            b.reserve_with_registry(client, &registry).await.unwrap();
        }

        // 3. Verify all reserved
        let reserved_batches = registry.get_reserved_batches(&client).await;
        assert_eq!(reserved_batches.len(), batches.len());

        // 4. Reload one batch back to cache
        batches[0].load_into_cache(&mut cache).await.unwrap();
        let (bt, rs, _, _) = cache.len();
        assert!(bt + rs > 0);

        // 5. Release one
        registry.release_batch(&client, &batches[0].id()).await;
        let remaining = registry.get_reserved_batches(&client).await;
        assert_eq!(remaining.len(), batches.len() - 1);
    }
    #[tokio::test]
    async fn test_deterministic_batch_ids() {
        let mut c1 = HoneyBadgerMPCNodePreprocMaterial::<Fr>::empty();
        let mut c2 = HoneyBadgerMPCNodePreprocMaterial::<Fr>::empty();

        let triple = ShamirBeaverTriple::<Fr>::new(
            RobustShare::new(Fr::from(0), 1, 1),
            RobustShare::new(Fr::from(0), 1, 1),
            RobustShare::new(Fr::from(0), 1, 1),
        );
        c1.add(Some(vec![triple.clone()]), None, None, None);
        c2.add(Some(vec![triple.clone()]), None, None, None);
        let instance_id: Vec<u8> = b"session_001".to_vec();

        let b1 = PreprocBatch::<Fr>::from_cache(&mut c1, "Fr", 4, 1, instance_id.clone())
            .await
            .unwrap();
        let b2 = PreprocBatch::<Fr>::from_cache(&mut c2, "Fr", 4, 1, instance_id)
            .await
            .unwrap();

        assert_eq!(b1[0].meta.id, b2[0].meta.id);
    }
}
