use crate::{
    common::lagrange_interpolate,
    honeybadger::{
        fpmul::{mod_pow2_from_field, pow2_f, TruncPrError, TruncPrMessage, TruncPrStore},
        SessionId,
    },
};
use ark_ff::PrimeField;
use ark_poly::Polynomial;
use ark_serialize::CanonicalDeserialize;
use std::{collections::HashMap, sync::Arc};
use stoffelnet::network_utils::Network;
use tokio::sync::{mpsc::Sender, Mutex};
use tracing::info;

#[derive(Debug, Clone)]
pub struct TruncPrNode<F: PrimeField> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    pub store: Arc<Mutex<HashMap<SessionId, Arc<Mutex<TruncPrStore<F>>>>>>,
    pub output_channel: Sender<SessionId>,
}

impl<F: PrimeField> TruncPrNode<F> {
    pub fn new(id: usize, n: usize, t: usize, output_channel: Sender<SessionId>) -> Self {
        Self {
            id,
            n,
            t,
            store: Arc::new(Mutex::new(HashMap::new())),
            output_channel,
        }
    }

    pub async fn get_or_create_store(&mut self, session: SessionId) -> Arc<Mutex<TruncPrStore<F>>> {
        let mut map = self.store.lock().await;
        map.entry(session)
            .or_insert((|| Arc::new(Mutex::new(TruncPrStore::empty())))())
            .clone()
    }

    /// Start TruncPr:
    /// - builds [r'] and [r] from preseeded randomness,
    /// - forms share of (b + r) where b = 2^{k-1} + [a],
    /// - broadcasts the share for opening.
    pub async fn init<N: Network>(
        &mut self,
        a: F,
        k: usize,
        m: usize,
        session: SessionId,
        network: Arc<N>,
    ) -> Result<(), TruncPrError> {
        info!(node_id = self.id, "TruncPr start");

        let store = self.get_or_create_store(session).await; // k,m already set in store
        let mut s = store.lock().await;
        s.k = k;
        s.m = m;
        s.share_a = Some(a);

        // b = 2^{k-1} + [a]   (2^{k-1} is public constant in the field)
        let b = pow2_f::<F>(k - 1) + a;

        let r_bits = match &s.r_bits {
            Some(r) if r.len() >= m => r,
            _ => {
                // Run PRandBitL to generate a fresh batch of m bits
                todo!()
            }
        };
        let r_int = match s.r_int {
            Some(r) => r,
            None => {
                // Run PRandInt to generate int
                todo!()
            }
        };

        // [r'] = sum_{i=0}^{m-1} 2^i [r_i]
        let mut r_dash = F::zero();
        for (i, bit_share) in r_bits.iter().take(m).enumerate() {
            r_dash += pow2_f::<F>(i) * (*bit_share);
        }
        s.r_dash = Some(r_dash);

        // [r] = 2^m [r''] + [r']
        let r = pow2_f::<F>(m) * r_int + r_dash;

        // share of (b + r)
        let open_share = b + r;

        // serialize and broadcast
        let mut payload = Vec::new();
        open_share.serialize_compressed(&mut payload)?;
        let msg = TruncPrMessage::new(self.id, session, payload);
        network.broadcast(&bincode::serialize(&msg)?).await?;
        Ok(())
    }

    async fn handle_open(&mut self, msg: TruncPrMessage) -> Result<(), TruncPrError> {
        info!(
            node_id = self.id,
            sender = msg.sender_id,
            "TruncPr open handler"
        );
        let store = self.get_or_create_store(msg.session_id).await;
        let mut s = store.lock().await;

        // de-serialize incoming share of (b + r)
        let share_i: F = CanonicalDeserialize::deserialize_compressed(msg.payload.as_slice())?;

        // dedup
        if s.open_buf.contains_key(&msg.sender_id) {
            return Err(TruncPrError::Duplicate(msg.sender_id));
        }
        s.open_buf.insert(msg.sender_id, share_i);

        // reconstruct when we have t+1
        if s.open_buf.len() >= (self.t + 1) {
            // collect first t+1 shares
            let mut xs = Vec::with_capacity(self.t + 1);
            let mut ys = Vec::with_capacity(self.t + 1);
            for (&sid, val) in s.open_buf.iter().take(self.t + 1) {
                xs.push(F::from(sid as u64));
                ys.push(*val);
            }
            let poly = lagrange_interpolate(&xs, &ys)?;
            let c = poly.evaluate(&F::zero()); // opened (b + r) as field element

            // c' = c mod 2^m  (public integer)
            let m = s.m;
            let c_mod = mod_pow2_from_field::<F>(c, m);

            // [a'] = c' - [r']  (work in the field; lift c' into F)
            let r_dash = s.r_dash.ok_or(TruncPrError::NotSet("r_dash".to_string()))?;
            let a_prime = c_mod - r_dash;

            // [d] = ([a] - [a']) * (2^{-m} mod q)
            let a = s
                .share_a
                .ok_or(TruncPrError::NotSet("share_a".to_string()))?;
            let inv_2m = pow2_f::<F>(m).inverse().expect("2^m invertible mod q");
            let d = (a - a_prime) * inv_2m;

            s.share_d = Some(d);
            s.open_buf.clear();

            self.output_channel.send(msg.session_id).await?;
        }

        Ok(())
    }

    /// Handle received messages
    pub async fn process<N: Network>(
        &mut self,
        msg: TruncPrMessage,
        _network: Arc<N>,
    ) -> Result<(), TruncPrError> {
        self.handle_open(msg).await?;
        Ok(())
    }
}
