use crate::common::ProtocolSessionId;
use crate::honeybadger::fpmul::{ProtocolState, RandBitError, RandBitStorage};
use crate::honeybadger::mul_pub::mul_pub::MulPubNode;
use crate::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use crate::honeybadger::SessionId;
use ark_ff::FftField;
use std::collections::HashMap;
use std::ops::{Add, Mul};
use std::sync::Arc;
use stoffelnet::network_utils::{Network, PartyId};
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};

#[derive(Clone, Debug)]
pub struct RandBit<F>
where
    F: FftField,
{
    /// The ID of the node.
    pub id: PartyId,
    /// The number of parties participating in the protocol.
    pub n_parties: usize,
    /// The threshold of corrupted parties.
    pub threshold: usize,
    /// Storage for the protocol.
    pub storage: Arc<Mutex<HashMap<SessionId, Arc<Mutex<RandBitStorage<F>>>>>>,
    pub mul_pub: MulPubNode<F>,
}

impl<F> RandBit<F>
where
    F: FftField,
{
    pub fn new(id: PartyId, n_parties: usize, threshold: usize) -> Result<Self, RandBitError> {
        let mul_pub =
            MulPubNode::new(id, n_parties, threshold).map_err(RandBitError::MulPubError)?;
        Ok(Self {
            id,
            n_parties,
            threshold,
            storage: Arc::new(Mutex::new(HashMap::new())),
            mul_pub,
        })
    }

    pub async fn clear_store(&self, session_id: SessionId) -> Result<(), RandBitError> {
        self.mul_pub.clear_store(session_id).await;
        let mut store = self.storage.lock().await;
        store
            .remove(&session_id)
            .map(|_| ())
            .ok_or(RandBitError::ClearStoreError(session_id))
    }

    pub async fn get_or_create_storage(
        &self,
        session_id: SessionId,
    ) -> Result<Arc<Mutex<RandBitStorage<F>>>, RandBitError> {
        let mut storage = self.storage.lock().await;

        // only exec ID changes between different runs
        if storage.len() >= 256 && !storage.contains_key(&session_id) {
            return Err(RandBitError::LimitError(
                "Maximum number of concurrent sessions (256) exceeded".to_string(),
            ));
        }
        Ok(storage
            .entry(session_id)
            .or_insert(Arc::new(Mutex::new(RandBitStorage::empty())))
            .clone())
    }

    pub async fn wait_for_result(
        &self,
        session_id: SessionId,
        duration: Duration,
    ) -> Result<Vec<RobustShare<F>>, RandBitError> {
        let output_receiver = {
            let storage = self.storage.lock().await;
            let storage_bind = match storage.get(&session_id) {
                Some(value) => value,
                None => return Err(RandBitError::NoSuchSessionId(session_id)),
            };
            let mut storage = storage_bind.lock().await;

            storage
                .output_receiver
                .take()
                .ok_or(RandBitError::ResultAlreadyReceived(session_id))?
        };

        match timeout(duration, output_receiver).await {
            Err(_) => Err(RandBitError::Timeout(session_id)),
            Ok(Err(_)) => Err(RandBitError::ReceiveError(session_id)),
            Ok(Ok(shares)) => Ok(shares),
        }
    }

    /// Computes [a^2] via MulPub (public opening), then derives the random bit
    /// [d] = ([a]/sqrt(a^2) + 1) / 2.
    ///
    /// `zero_shares`: k degree-2t sharings of 0, one per element of `a`.
    pub async fn init<N>(
        &mut self,
        a: Vec<RobustShare<F>>,
        zero_shares: Vec<RobustShare<F>>,
        session_id: SessionId,
        duration: Duration,
        network: Arc<N>,
    ) -> Result<(), RandBitError>
    where
        N: Network + Send + Sync + 'static,
    {
        if a.len() % (self.threshold + 1) != 0 {
            return Err(RandBitError::Incompatible);
        }

        if a.len() / (self.threshold + 1) > 256 {
            return Err(RandBitError::ShareLimitError(a.len()));
        }

        assert!(session_id.calling_protocol().is_some());
        assert_eq!(session_id.sub_id(), 0);
        assert_eq!(session_id.round_id(), 0);

        // Mark the protocol as initialized.
        {
            let storage_bind = self.get_or_create_storage(session_id).await?;
            let mut storage = storage_bind.lock().await;
            storage.protocol_state = ProtocolState::Initialized;
        }

        self.mul_pub
            .init(session_id, a.clone(), a.clone(), zero_shares, network)
            .await
            .map_err(RandBitError::MulPubError)?;

        let a_square_vals = self
            .mul_pub
            .wait_for_result(session_id, duration)
            .await
            .map_err(RandBitError::MulPubError)?;

        for a_square in &a_square_vals {
            if *a_square == F::zero() {
                return Err(RandBitError::ZeroSquare);
            }
        }

        let mut b_inv_array = Vec::with_capacity(a_square_vals.len());
        for a_square in &a_square_vals {
            let b = a_square.sqrt().ok_or(RandBitError::SquareRoot)?;
            let b_inv = b.inverse().ok_or(RandBitError::Inverse)?;
            b_inv_array.push(b_inv);
        }

        let mut c_share_array = Vec::with_capacity(a.len());
        for (a_share, b_inv) in a.iter().zip(&b_inv_array) {
            c_share_array.push(a_share.clone().mul(*b_inv)?);
        }

        let two_inv = (F::one() + F::one()).inverse().unwrap();
        let mut d_share_array = Vec::with_capacity(c_share_array.len());
        for c_share in &c_share_array {
            d_share_array.push(c_share.clone().add(F::one())?.mul(two_inv)?);
        }

        let storage_bind = self.get_or_create_storage(session_id).await?;
        let mut storage = storage_bind.lock().await;
        storage.protocol_state = ProtocolState::Finished;
        storage.protocol_output = Some(d_share_array.clone());
        let sender = storage
            .output_sender
            .take()
            .ok_or(RandBitError::SendError(session_id))?;
        sender
            .send(d_share_array)
            .map_err(|_| RandBitError::SendError(session_id))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;

    #[tokio::test]
    async fn test_randbit_storage_limit() {
        let node = RandBit::<Fr>::new(0, 5, 1).unwrap();

        // Fill up storage to the limit (256 sessions)
        for i in 0u8..=255 {
            let session_id = SessionId::new(
                crate::honeybadger::ProtocolType::RandBit,
                SessionId::pack_slot24(i, 0, 0),
                111,
            );
            let _ = node.get_or_create_storage(session_id).await;
        }

        // The 257th session should fail
        let session_id = SessionId::new(
            crate::honeybadger::ProtocolType::RandBit,
            SessionId::pack_slot24(0, 1, 0),
            111,
        );
        let result = node.get_or_create_storage(session_id).await;
        assert!(
            matches!(result, Err(RandBitError::LimitError(_))),
            "Should error on exceeding storage limit"
        );
    }
}
