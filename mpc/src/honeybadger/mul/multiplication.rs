use crate::{
    common::{share::ShareError, SecretSharingScheme, ShamirShare, RBC},
    honeybadger::{
        batch_recon::batch_recon::BatchReconNode,
        mul::{
            concat_sorted, MulError, InterpolateError, MultMessage, MultProtocolState, MultStorage,
            ReconstructionMessage,
        },
        robust_interpolate::robust_interpolate::{Robust, RobustShare},
        triple_gen::ShamirBeaverTriple,
        SessionId, WrappedMessage,
    },
};
use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use itertools::izip;
use std::{
    collections::HashMap,
    ops::{Mul, Sub},
    sync::Arc,
};
use stoffelnet::network_utils::{Network, PartyId};
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};
use tracing::{info, warn, error};

/// Secret multiplication is explained in Section 2.2 of the paper.
/// Assume that we want to multiply two t-shares x and y. We take a Beaver triple
/// (a, b, a*b) and 
/// 
/// 1. calculate a - x and b - y and open these values
/// 2. calculate x*y = a*b - (a - x)(b - y) - (a - x)y - (b - y)x; a - x and b - y have been
///    opened, a*b is part of the Beaver triple and x and y are known shares
///
/// Opening in step (1) happens using batch reconstruction and also RBC.
/// The former is used for chunks of t + 1 shares and the remainder of these, if any, is
/// reconstructed using the latter.
/// For example, if `n = 10` and `t = 3`, then 10 multiplications would be performed by running
/// batch reconstruction four times: on two chunks each of size 4 for `a - x` and `b - y`,
/// respectively. In addition, each node would run RBC once for the remaining values, which are two
/// values of `a - x` and `b - y`, respectively. While batch reconstruction takes care of the
/// distribution of the shares and their reconstruction at the same time, the nodes need to
/// manually reconstruct the shares received via RBC.
///
/// The storage per multiplication is accessed by `Multiply::init` and `open_mult_handler` and is protected by
/// a mutex.

// requires that Multiply::init has been called before and all chunks and shares via RBC have been
// received
fn finalize_mul<F: FftField>(storage: &MultStorage<F>) -> Result<Vec<RobustShare<F>>, MulError> {
    assert!(storage.openings.is_some());    // always ensured by the caller

    let openings = storage.openings.as_ref().unwrap();

    let mut concatenated_mult1: Vec<F> = concat_sorted(&storage.output_open_mult1);
    concatenated_mult1.extend(openings.0.clone());

    let mut concatenated_mult2: Vec<F> = concat_sorted(&storage.output_open_mult2);
    concatenated_mult2.extend(openings.1.clone());

    let mut shares_mult = Vec::with_capacity(storage.share_mult_from_triple.len());
    for (triple_mult, input_a, input_b, subtraction_a, subtraction_b) in izip!(
        &storage.share_mult_from_triple,
        &storage.inputs.0,
        &storage.inputs.1,
        concatenated_mult1,
        concatenated_mult2,
    ) {
        //(a−x)(b−y)
        let mult_subs = subtraction_a * subtraction_b;
        //(a−x)[y]_t
        let mult_sub_a_y = input_b.clone().mul(subtraction_a)?;
        //(b−y)[x]_t
        let mult_sub_b_x = input_a.clone().mul(subtraction_b)?;
        //[xy]_t
        let share = triple_mult.clone().sub(mult_subs)?;
        let share2: ShamirShare<F, 1, Robust> = (share - mult_sub_a_y)?;
        let share3 = (share2 - mult_sub_b_x)?;
        shares_mult.push(share3);
    }

    Ok(shares_mult)
}

fn reconstruct_rbc<F: FftField>(received_shares: &HashMap<PartyId, (Vec<RobustShare<F>>, Vec<RobustShare<F>>)>, share_len: usize, n: usize) -> Result<(Vec<F>, Vec<F>), InterpolateError> {
    let mut a_sub_x: Vec<F> = Vec::new();
    let mut b_sub_y: Vec<F> = Vec::new();
    let mut a_shares = vec![vec![]; share_len];
    let mut b_shares = vec![vec![]; share_len];

    for (id, (a, b)) in received_shares.iter() {
        if a.len() != share_len || b.len() != share_len {
            warn!("Node {} did not send right number of shares to reconstruct using RBC (sent {} for a-x and {} for b-y)", id, a.len(), b.len());
        }
    
        for i in 0..share_len {
            a_shares[i].push(a[i].clone());
            b_shares[i].push(b[i].clone());
        }
    }
    for i in 0..share_len {
        let a = RobustShare::recover_secret(&a_shares[i], n)?;
        let b = RobustShare::recover_secret(&b_shares[i], n)?;
    
        a_sub_x.push(a.1);
        b_sub_y.push(b.1);
    }

    Ok((a_sub_x, b_sub_y))
}

#[derive(Clone, Debug)]
pub struct Multiply<F: FftField, R: RBC> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    pub mult_storage: Arc<Mutex<HashMap<SessionId, Arc<Mutex<MultStorage<F>>>>>>,
    pub batch_recon: BatchReconNode<F>,
    pub rbc: R,
}

impl<F: FftField, R: RBC> Multiply<F, R> {
    pub fn new(
        id: PartyId,
        n: usize,
        threshold: usize,
    ) -> Result<Self, MulError> {
        let batch_recon = BatchReconNode::<F>::new(id, n, threshold)?;
        let rbc = R::new(id, n, threshold, threshold + 1)?;
        Ok(Self {
            id,
            n,
            t: threshold,
            mult_storage: Arc::new(Mutex::new(HashMap::new())),
            batch_recon,
            rbc,
        })
    }
    pub async fn clear_store(&self) {
        let mut store = self.mult_storage.lock().await;
        store.clear();
        self.batch_recon.clear_entire_store().await;
        self.rbc.clear_store().await;
    }

    // 1. Take storage lock
    // 2. Find chunks for batch reconstruction that have not been opened yet
    // 3. Set inputs x and y, Beaver triples, number of multiplications, and disable RBC if not
    //    needed
    // 4. Reconstruct from RBC-sent shares if enough have been received and needed
    // 5. Perform the multiplication and return if all openings are available
    // 6. Otherwise, compute all local (a - x)- and (b - y)-shares
    // 7. Release the storage lock
    // 8. Initiate batch reconstruction for all chunks that have not been opened yet
    // 9. Initiate RBC if needed
    //
    // `init` mainly serves to set the inputs and Beaver triples for multiplication and to
    // initiate the opening of the a-x,b-y values. However, due to the asynchronous nature of the
    // protocols and the malicious security, some or even all openings could already have been
    // received without any contribution by one node. Therefore, `init` does not initiate the
    // opening for all values, but only for the missing ones. Since `init` could even be called
    // after all openings have been received, it needs to be able to perform the final multiplication
    // itself.
    //
    // The lock is released before initiating batch reconstruction or RBC to avoid unforeseen delays
    // or other synchronicity issues. While this enables a possible race condition where batches or
    // the RBC broadcast are received right after releasing the lock and therefore batch
    // reconstruction or RBC are initiated unnecessarily, this does no harm.
    pub async fn init<N: Network + Send + Sync>(
        &mut self,
        session_id: SessionId,
        x: Vec<RobustShare<F>>,
        y: Vec<RobustShare<F>>,
        beaver_triples: Vec<ShamirBeaverTriple<F>>,
        network: Arc<N>
    ) -> Result<(), MulError> {
        info!(party = self.id, "Initializing multiplication");
        if x.len() != y.len() || x.len() != beaver_triples.len() {
            return Err(MulError::InvalidInput("Length of x and y vectors and Beaver triples must match".to_string()));
        }

        assert!(session_id.calling_protocol().is_some());

        let no_of_mul = x.len();
        let no_of_batch = no_of_mul / (self.t + 1);
        let share_len = x.len() % (self.t + 1);

        // 1.
        let storage_bind = self.get_or_create_mult_storage(session_id).await;
        let mut storage = storage_bind.lock().await;

        // 2.
        let have_batch_recon1: Vec<_> = (0..no_of_batch)
            .map(|i| storage.output_open_mult1.contains_key(&((2 * i) as u8)))
            .collect();
        let have_batch_recon2: Vec<_> = (0..no_of_batch)
            .map(|i| storage.output_open_mult2.contains_key(&((2 * i + 1) as u8)))
            .collect();

        // 3.
        storage.no_of_mul = Some(no_of_mul);
        storage.inputs = (x.clone(), y.clone());
        storage.share_mult_from_triple = beaver_triples
            .iter()
            .map(|triple| triple.mult.clone())
            .collect();
        if share_len == 0 {
            storage.openings = Some((vec![], vec![]));
        }

        // 4.
        if storage.received_shares.len() >= 2 * self.t + 1 && storage.openings.is_none() {
            // `share_len != 0`, since some honest nodes have sent us their shares
            info!("Received enough messages with shares to try reconstruction using RBC");

            match reconstruct_rbc(&storage.received_shares, share_len, self.n) {
                Ok(openings) => {
                    info!("Reconstruction succeeded");
                    storage.openings = Some(openings);
                }
                Err(e) => error!("Reconstruction in init failed: {e}")  // could fail if shares corrupt
            };
        }

        // 5.
        if have_batch_recon1.iter().all(|b| *b) && have_batch_recon2.iter().all(|b| *b) && storage.openings.is_some() {
            let shares_mult = finalize_mul(&storage)?;
    
            // never None because checked at the beginning
            let taken_output_sender = storage.output_sender.take().unwrap();
    
            taken_output_sender.send(shares_mult).map_err(|_| MulError::SendError(session_id))?;
            storage.protocol_state = MultProtocolState::Finished;

            info!("Multiplication completed at node {}", self.id);

            return Ok(());
        }

        // 6.
        let a_sub_x = x
            .iter()
            .zip(beaver_triples.iter())
            .map(|(x, triple)| triple.a.clone() - x.clone())
            .collect::<Result<Vec<RobustShare<F>>, ShareError>>()?;
        let b_sub_y = y
            .iter()
            .zip(beaver_triples.iter())
            .map(|(y, triple)| triple.b.clone() - y.clone())
            .collect::<Result<Vec<RobustShare<F>>, ShareError>>()?;

        let split_at = a_sub_x.len() - share_len;
        let (a_full, remaining_a) = a_sub_x.split_at(split_at);
        let (b_full, remaining_b) = b_sub_y.split_at(split_at);

        let need_rbc = storage.openings.is_none();

        // 7.
        drop(storage);

        // 8.
        // initiate batch reconstruction for those chunks that need it
        for (i, (chunk_a, chunk_b)) in a_full.chunks(self.t + 1).zip(b_full.chunks(self.t + 1)).enumerate() {
            if !have_batch_recon1[i] {
                let session_id1 = SessionId::new(
                    session_id.calling_protocol().unwrap(),
                    session_id.exec_id(),
                    1,
                    (2 * i) as u8,
                    session_id.instance_id(),
                );
                // Execute batch reconstruction for a-x values
                self.batch_recon
                    .init_batch_reconstruct(chunk_a, session_id1, Arc::clone(&network))
                    .await?;
            }

            if !have_batch_recon2[i] {
                let session_id2 = SessionId::new(
                    session_id.calling_protocol().unwrap(),
                    session_id.exec_id(),
                    1,
                    (2 * i + 1) as u8,
                    session_id.instance_id(),
                );
                // Execute batch reconstruction for b-y values
                self.batch_recon
                    .init_batch_reconstruct(chunk_b, session_id2, Arc::clone(&network))
                    .await?;
            }
        }

        // 9.
        if need_rbc {
            // Reconstruct < t+1 values
            let reconst_message =
                ReconstructionMessage::new(remaining_a.to_vec(), remaining_b.to_vec());
            let mut bytes_rec_message = Vec::new();
            reconst_message.serialize_compressed(&mut bytes_rec_message)?;

            let sessionid = SessionId::new(
                session_id.calling_protocol().unwrap(),
                session_id.exec_id(),
                2,
                self.id as u8,
                session_id.instance_id(),
            );

            let wrapped =
                WrappedMessage::Mul(MultMessage::new(self.id, sessionid, bytes_rec_message));
            let bytes_wrapped = bincode::serialize(&wrapped)?;

            self.rbc
                .init(bytes_wrapped, sessionid, Arc::clone(&network))
                .await?;
        }

        Ok(())
    }

    // 1. Take storage lock
    // 2. Store the a-x, b-y values opened through batch reconstruction in the appropriate slot
    // 3. Get the number of multiplications or return if `init` has not been called yet
    // 4. Reconstruct from RBC-sent shares if enough have been received and needed
    // 5. Return if not all openings are available
    // 5. Perform the multiplication and return if all openings are available
    // 6. Otherwise, compute all local (a - x)- and (b - y)-shares
    //
    // `open_mult_handler` mainly serves to receive opened values from batch reconstruction
    // or shares from RBC, from which openings will be manually reconstructed.
    // If `init` has been called, then it can also try to perform the multiplication.
    pub async fn open_mult_handler(
        &self,
        msg: MultMessage,
    ) -> Result<(), MulError> {
        let calling_proto = match msg.session_id.calling_protocol() {
            Some(proto) => proto,
            None => {
                return Err(MulError::InvalidInput(
                    format!("Unknown calling protocol in session ID {:?}", msg.session_id)
                ));
            }
        };

        let session_id = SessionId::new(
            calling_proto,
            msg.session_id.exec_id(),
            0,
            0,
            msg.session_id.instance_id(),
        );

        // 1.
        let storage_bind = self.get_or_create_mult_storage(session_id).await;
        let mut storage = storage_bind.lock().await;

        if storage.protocol_state == MultProtocolState::Finished {
            return Ok(());
        }

        // 2.
        if msg.session_id.sub_id() == 1 {
            let open: Vec<F> =
                CanonicalDeserialize::deserialize_compressed(msg.payload.as_slice())?;
            let round_id = msg.session_id.round_id();
            let (target_map, label) = if round_id % 2 == 0 {
                (&mut storage.output_open_mult1, "a-x")
            } else {
                (&mut storage.output_open_mult2, "b-y")
            };

            if target_map.contains_key(&round_id) {
                return Err(MulError::Duplicate(format!(
                    "Received duplicate of round {}",
                    round_id
                )));
            }

            info!(
                self_id = self.id,
                "Received opened {} values for session_id: {:?} and round {:?}",
                label,
                session_id,
                round_id
            );

            target_map.insert(round_id, open);
        } else if msg.session_id.sub_id() == 2 {
            info!(
                self_id = self.id,
                "Received shares for reconstruction using RBC for session_id: {:?}", session_id
            );
            if storage.received_shares.contains_key(&msg.sender) {
                return Err(MulError::Duplicate(format!(
                    "Already received shares for reconstruction using RBC from {}",
                    msg.sender
                )));
            }

            let open_message: ReconstructionMessage<F> =
                CanonicalDeserialize::deserialize_compressed(msg.payload.as_slice())?;

            storage
                .received_shares
                .insert(msg.sender, (open_message.a_sub_x, open_message.b_sub_y));
        }

        // 3.
        let no_of_mul = storage.no_of_mul.ok_or(MulError::InvalidInput(format!(
            "No. of multiplications not set for node (init not called yet) {}",
            self.id
        )))?;
        let no_of_batch = no_of_mul / (self.t + 1);
        let share_len = no_of_mul % (self.t + 1);

        // 4.
        if storage.received_shares.len() >= 2 * self.t + 1 && storage.openings.is_none() {
            // `share_len != 0`, since some honest nodes have sent us their shares
            info!("Received enough messages with shares to try reconstruction using RBC");
            let openings = reconstruct_rbc(&storage.received_shares, share_len, self.n)?;

            info!("Reconstruction succeeded");
            storage.openings = Some(openings);
        }

        // 5.
        if storage.output_open_mult1.len() != no_of_batch
            || storage.output_open_mult2.len() != no_of_batch
            || storage.openings.is_none()
        {
            return Err(MulError::WaitForOk);
        }

        // 6.
        let shares_mult = finalize_mul(&storage)?;

        // never None because checked at the beginning
        let taken_output_sender = storage.output_sender.take().unwrap();

        taken_output_sender.send(shares_mult).map_err(|_| MulError::SendError(session_id))?;
        storage.protocol_state = MultProtocolState::Finished;

        info!("Multiplication completed at node {}", self.id);

        Ok(())
    }

    pub async fn process(&mut self, message: MultMessage) -> Result<(), MulError> {
        self.open_mult_handler(message).await?;
        Ok(())
    }

    pub async fn get_or_create_mult_storage(
        &self,
        session_id: SessionId,
    ) -> Arc<Mutex<MultStorage<F>>> {
        let mut storage = self.mult_storage.lock().await;
        storage
            .entry(session_id)
            .or_insert(Arc::new(Mutex::new(MultStorage::empty())))
            .clone()
    }

    pub async fn wait_for_result(&self, session_id: SessionId, duration: Duration) -> Result<Vec<RobustShare<F>>, MulError> {
        // scoped because self.mult_storage and storage locks must not be held anymore
        // when receiving afterwards
        let output_receiver = {
            let mult_storage = self.mult_storage.lock().await;
            let storage_bind = match mult_storage.get(&session_id) {
                Some(value) => value,
                None => return Err(MulError::NoSuchSessionId(session_id))
            };
            let mut storage = storage_bind.lock().await;

            storage.output_receiver
                   .take()
                   .ok_or(MulError::ResultAlreadyReceived(session_id))?
        };

        match timeout(duration, output_receiver).await {
            Err(_) => {
                Err(MulError::Timeout(session_id))
            }
            Ok(Err(_)) => {
                Err(MulError::ReceiveError(session_id))
            }
            Ok(Ok(mul_shares)) => {
                Ok(mul_shares)
            }
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_std::test_rng;
    use ark_bls12_381::Fr;
    use ark_ff::UniformRand;
    use crate::{
        common::{rbc::rbc::Avid, SecretSharingScheme},
        honeybadger::{
            ProtocolType,
            RbcError,
            robust_interpolate::robust_interpolate::RobustShare,
            WrappedMessage,
        }
    };
    use tokio::time::{sleep, Duration};
    use stoffelmpc_network::fake_network::{FakeNetwork, FakeNetworkConfig};
    use rand::{thread_rng, prelude::SliceRandom};

    async fn construct_input_mul(
        n_parties: usize,
        n_triples: usize,
        threshold: usize,
    ) -> ((Vec<Fr>, Vec<Fr>, Vec<Fr>), Vec<Vec<ShamirBeaverTriple<Fr>>>) {
        let mut rng = test_rng();
        let mut secrets_a = Vec::new();
        let mut secrets_b = Vec::new();
        let mut secrets_c = Vec::new();
        let mut per_party_triples: Vec<Vec<ShamirBeaverTriple<Fr>>> = vec![Vec::new(); n_parties];
    
        for _i in 0..n_triples {
            // sample secrets a,b
            let a_secret = Fr::rand(&mut rng);
            let b_secret = Fr::rand(&mut rng);
            let c_secret = a_secret * b_secret;
    
            // make robust shares for each secret (length == n_parties)
            let shares_a = RobustShare::compute_shares(a_secret, n_parties, threshold, None, &mut rng)
                .expect("share a creation failed");
            let shares_b = RobustShare::compute_shares(b_secret, n_parties, threshold, None, &mut rng)
                .expect("share b creation failed");
            let shares_c = RobustShare::compute_shares(c_secret, n_parties, threshold, None, &mut rng)
                .expect("share c creation failed");
    
            // push the secrets to the vectors
            secrets_a.push(a_secret);
            secrets_b.push(b_secret);
            secrets_c.push(c_secret);
    
            // For each party, create their per-party ShamirBeaverTriple and push it
            for pid in 0..n_parties {
                let triple = ShamirBeaverTriple {
                    a: shares_a[pid].clone(),
                    b: shares_b[pid].clone(),
                    mult: shares_c[pid].clone(),
                };
                per_party_triples[pid].push(triple);
            }
        }
        ((secrets_a, secrets_b, secrets_c), per_party_triples)
    }

    /// `2t+1` nodes send random shares to the client, which reconstructs the random value and
    /// broadcasts the masked input. Some node, which is not one of the `2t+1` has not sent its
    /// random share and receives the masked input before even having called `InputServer::init`.
    #[tokio::test]
    async fn test_init_last() {
        let n = 10;
        let t = 3;
        let node_id = 0;
        let no_of_mul = 10;
        let session_id = SessionId::new(ProtocolType::Mul, 123, 0, 0, 111);
        let mut rng = test_rng();
    
        // 1. Generate Beaver triples
        let ((secrets_a, secrets_b, _), beaver_triples) = construct_input_mul(n, no_of_mul, t).await;
        let mult_from_triple: Vec<_> = beaver_triples[node_id]
            .iter()
            .map(|triple| triple.mult.clone())
            .collect();
    
        // 2. Prepare inputs for multiplication
        let mut x_values = Vec::new();
        let mut y_values = Vec::new();
        let mut x_inputs_per_node = vec![Vec::new(); n];
        let mut y_inputs_per_node = vec![Vec::new(); n];
    
        for _i in 0..no_of_mul {
            let x_value = Fr::rand(&mut rng);
            x_values.push(x_value);
            let y_value = Fr::rand(&mut rng);
            y_values.push(y_value);
    
            let shares_x = RobustShare::compute_shares(x_value, n, t, None, &mut rng).unwrap();
            let shares_y = RobustShare::compute_shares(y_value, n, t, None, &mut rng).unwrap();
    
            for p in 0..n {
                x_inputs_per_node[p].push(shares_x[p].clone());
                y_inputs_per_node[p].push(shares_y[p].clone());
            }
        }
    
        // 3. Generate correct openings and shares
        let correct_a_sub_x = secrets_a.clone().iter().zip(x_values.clone()).map(|(a, x)| *a - x).collect::<Vec<_>>();
        let correct_b_sub_y = secrets_b.clone().iter().zip(y_values.clone()).map(|(b, y)| *b - y).collect::<Vec<_>>();
    
        let mut correct_shares = Vec::with_capacity(mult_from_triple.len());
        for (triple_mult, input_a, input_b, subtraction_a, subtraction_b) in izip!(
            &mult_from_triple,
            &x_inputs_per_node[node_id],
            &y_inputs_per_node[node_id],
            &correct_a_sub_x,
            &correct_b_sub_y
        ) {
            //(a−x)(b−y)
            let mult_subs = subtraction_a * subtraction_b;
            //(a−x)[y]_t
            let mult_sub_a_y = input_b.clone().mul(*subtraction_a).expect("multiplication failed");
            //(b−y)[x]_t
            let mult_sub_b_x = input_a.clone().mul(*subtraction_b).expect("multiplication failed");
            //[xy]_t
            let share = triple_mult.clone().sub(mult_subs).expect("subtraction failed");
            let share2: ShamirShare<Fr, 1, Robust> = (share - mult_sub_a_y).expect("subtraction failed");
            let share3 = (share2 - mult_sub_b_x).expect("subtraction failed");
            correct_shares.push(share3);
        }

        let config = FakeNetworkConfig::new(500);
        let (network, mut receivers, _) = FakeNetwork::new(n, None, config);
        let network = Arc::new(network);

        let mut nodes: Vec<_> = (0..n).map(|i| { Multiply::<Fr, Avid>::new(i, n, t).unwrap() }).collect();

        // all but one node call init
        for i in 0..nodes.len() {
            if i == node_id {
                continue;
            }

            let mut node = nodes[i].clone();
            let network = network.clone();
            let x_inputs_per_node = x_inputs_per_node[i].clone();
            let y_inputs_per_node = y_inputs_per_node[i].clone();
            let beaver_triples = beaver_triples[i].clone();

            tokio::spawn(async move {
                assert!(node
                    .init(session_id, x_inputs_per_node, y_inputs_per_node, beaver_triples, network)
                    .await
                    .is_ok());
            });
        }

        // run RBC for masked input and eventually process it
        for node in nodes.iter_mut() {
            let network = network.clone();
            let mut node = node.clone();
            let mut receiver = receivers.remove(0);

            tokio::spawn(async move {
                while let Some(raw_msg) = receiver.recv().await {
                    let wrapped: WrappedMessage = bincode::deserialize(&raw_msg).expect("deserialization error");

                    match wrapped {
                        WrappedMessage::BatchRecon(batchrecon_msg) => {
                            node.batch_recon.process(batchrecon_msg, network.clone()).await.unwrap();
                        }
                        WrappedMessage::Rbc(rbc_msg) => {
                            match node.rbc.process(rbc_msg, network.clone()).await {
                                Ok(()) => { },
                                Err(RbcError::SessionEnded(_)) => { },
                                Err(e) => { panic!("unexpected error during RBC: {e}"); }
                            }
                        }
                        WrappedMessage::Mul(input_msg) => {
                            let _ = node.process(input_msg).await;
                        }
                        _ => { panic!(); }
                    };
                }
            });
        }

        // wait for left out node to receive messages and calculate result
        sleep(Duration::from_millis(500)).await;
        
        let storage_bind = nodes[node_id].get_or_create_mult_storage(session_id).await;
        let storage = storage_bind.lock().await;

        let no_of_batch = no_of_mul / (t + 1);

        // all openings except for the RBC ones should be there, but enough shares
        // for reconstruction should be there
        assert!((0..no_of_batch).all(|i| storage.output_open_mult1.contains_key(&((2 * i) as u8))));
        assert!((0..no_of_batch).all(|i| storage.output_open_mult2.contains_key(&((2 * i + 1) as u8))));
        assert!(storage.openings.is_none());
        assert!(storage.received_shares.len() >= 2 * t + 1);

        drop(storage);

        // so now we call init...
        assert!(nodes[node_id]
            .init(session_id, x_inputs_per_node[node_id].clone(), y_inputs_per_node[node_id].clone(), beaver_triples[node_id].clone(), network)
            .await
            .is_ok()
        );

        let storage_bind = nodes[node_id].get_or_create_mult_storage(session_id).await;
        let storage = storage_bind.lock().await;

        // openings via RBC should be there now
        assert!(storage.openings.is_some());

        drop(storage);

        // ...and obtain the result
        let mut real_shares = None;
        match nodes[node_id].wait_for_result(session_id, Duration::from_millis(5)).await {
            Err(MulError::ResultAlreadyReceived(_)) => { info!("already received result"); }
            Err(e) => { panic!("unexpected error during waiting: {e}"); }
            Ok(shares) => { real_shares = Some(shares); }
        }

        // 8. Check that shares are correct
        assert!(real_shares.is_some());
        for (real_share, correct_share) in real_shares.unwrap().into_iter().zip(correct_shares) {
            assert_eq!(real_share.degree, t);
            assert_eq!(real_share.id, node_id);
            assert_eq!(real_share.share[0], correct_share.share[0]);
        }
    }

    // 1. Generate Beaver triples
    // 2. Prepare inputs for multiplication
    // 3. Generate correct openings and shares
    // 4. Create node
    // 5. Generate messages
    // 6. Shuffle messages
    // 7. Make node handle messages
    // 8. Check that shares are correct
    #[tokio::test]
    async fn test_open_mult_handler() {
        let n_parties = 10;
        let t = 3;
        let node_id = 0;
        let no_of_mul = 10;
        let split_at = no_of_mul - no_of_mul % (t + 1);
        let session_id = SessionId::new(ProtocolType::Mul, 123, 0, 0, 111);
        let mut rng = test_rng();

        // 1. Generate Beaver triples
        let ((secrets_a, secrets_b, _), beaver_triples) = construct_input_mul(n_parties, no_of_mul, t).await;
        let mult_from_triple: Vec<_> = beaver_triples[node_id]
            .iter()
            .map(|triple| triple.mult.clone())
            .collect();

        // 2. Prepare inputs for multiplication
        let mut x_values = Vec::new();
        let mut y_values = Vec::new();
        let mut x_inputs_per_node = vec![Vec::new(); n_parties];
        let mut y_inputs_per_node = vec![Vec::new(); n_parties];

        for _i in 0..no_of_mul {
            let x_value = Fr::rand(&mut rng);
            x_values.push(x_value);
            let y_value = Fr::rand(&mut rng);
            y_values.push(y_value);

            let shares_x = RobustShare::compute_shares(x_value, n_parties, t, None, &mut rng).unwrap();
            let shares_y = RobustShare::compute_shares(y_value, n_parties, t, None, &mut rng).unwrap();

            for p in 0..n_parties {
                x_inputs_per_node[p].push(shares_x[p].clone());
                y_inputs_per_node[p].push(shares_y[p].clone());
            }
        }

        // 3. Generate correct openings and shares
        let correct_a_sub_x = secrets_a.clone().iter().zip(x_values.clone()).map(|(a, x)| *a - x).collect::<Vec<_>>();
        let correct_b_sub_y = secrets_b.clone().iter().zip(y_values.clone()).map(|(b, y)| *b - y).collect::<Vec<_>>();

        let mut correct_shares = Vec::with_capacity(mult_from_triple.len());
        for (triple_mult, input_a, input_b, subtraction_a, subtraction_b) in izip!(
            &mult_from_triple,
            &x_inputs_per_node[node_id],
            &y_inputs_per_node[node_id],
            &correct_a_sub_x,
            &correct_b_sub_y
        ) {
            //(a−x)(b−y)
            let mult_subs = subtraction_a * subtraction_b;
            //(a−x)[y]_t
            let mult_sub_a_y = input_b.clone().mul(*subtraction_a).expect("multiplication failed");
            //(b−y)[x]_t
            let mult_sub_b_x = input_a.clone().mul(*subtraction_b).expect("multiplication failed");
            //[xy]_t
            let share = triple_mult.clone().sub(mult_subs).expect("subtraction failed");
            let share2: ShamirShare<Fr, 1, Robust> = (share - mult_sub_a_y).expect("subtraction failed");
            let share3 = (share2 - mult_sub_b_x).expect("subtraction failed");
            correct_shares.push(share3);
        }

        // 4. Create node
        let mut mul_node = Multiply::<Fr, Avid>::new(node_id, n_parties, t).unwrap();

        let storage_bind = mul_node.get_or_create_mult_storage(session_id).await;
        let mut storage = storage_bind.lock().await;
        storage.inputs = (x_inputs_per_node[node_id].clone(), y_inputs_per_node[node_id].clone());
        storage.share_mult_from_triple = beaver_triples[node_id]
            .iter()
            .map(|triple| triple.mult.clone())
            .collect();
        storage.no_of_mul = Some(correct_a_sub_x.len());
        drop(storage);

        // 5. Generate messages
        let mut mul_msgs = Vec::new();

        let open_a_sub_x = correct_a_sub_x.clone()[0..split_at].to_vec();
        let open_b_sub_y = correct_b_sub_y.clone()[0..split_at].to_vec();

        // using batch reconstruction
        for (i, (chunk_a, chunk_b)) in open_a_sub_x.chunks(t + 1).zip(open_b_sub_y.chunks(t + 1)).enumerate() {
            let session_id_a = SessionId::new(
                ProtocolType::Mul,
                session_id.exec_id(),
                1,
                (2 * i) as u8,
                session_id.instance_id(),
            );
            let session_id_b = SessionId::new(
                ProtocolType::Mul,
                session_id.exec_id(),
                1,
                (2 * i + 1) as u8,
                session_id.instance_id(),
            );

            let mut chunk_a_bytes = Vec::new();
            chunk_a
                .serialize_compressed(&mut chunk_a_bytes)
                .expect("serialization failed");
            let chunk_a_msg = MultMessage::new(
                node_id,
                session_id_a,
                chunk_a_bytes,
            );

            let mut chunk_b_bytes = Vec::new();
            chunk_b
                .serialize_compressed(&mut chunk_b_bytes)
                .expect("serialization failed");
            let chunk_b_msg = MultMessage::new(
                node_id,
                session_id_b,
                chunk_b_bytes,
            );

            mul_msgs.push(chunk_a_msg);
            mul_msgs.push(chunk_b_msg);
        }

        // using RBC
        for i in 0..n_parties {
            if i == node_id {
                continue;
            }

            let shared_a_sub_x = x_inputs_per_node[i][split_at..]
                .iter()
                .zip(beaver_triples[i][split_at..].iter())
                .map(|(x, triple)| triple.a.clone() - x.clone())
                .collect::<Result<Vec<RobustShare<Fr>>, ShareError>>().expect("share subtraction failed");
            let shared_b_sub_y = y_inputs_per_node[i][split_at..]
                .iter()
                .zip(beaver_triples[i][split_at..].iter())
                .map(|(y, triple)| triple.b.clone() - y.clone())
                .collect::<Result<Vec<RobustShare<Fr>>, ShareError>>().expect("share subtraction failed");

            if shared_a_sub_x.len() > 0 && shared_b_sub_y.len() > 0 {
                let rec_msg =
                    ReconstructionMessage::new(shared_a_sub_x.to_vec(), shared_b_sub_y.to_vec());
                let mut bytes_rec_msg = Vec::new();
                rec_msg.serialize_compressed(&mut bytes_rec_msg).expect("serialization failed");
            
                let shared_session_id = SessionId::new(
                    ProtocolType::Mul,
                    session_id.exec_id(),
                    2,
                    mul_node.id as u8,
                    session_id.instance_id()
                );
            
                mul_msgs.push(MultMessage::new(i, shared_session_id, bytes_rec_msg));
            }
        }

        // 6. Shuffle messages
        mul_msgs.shuffle(&mut thread_rng());

        // 7. Make node handle messages
        for msg in mul_msgs {
            let result = mul_node.process(msg).await;
            match result {
                Ok(()) => { }
                Err(MulError::WaitForOk) => { info!("waiting"); }
                Err(MulError::Duplicate(e)) => { panic!("duplicate detected: {e}") }
                Err(e) => { panic!("unexpected error during processing: {e}"); }
            }
        }

        let real_shares = match mul_node.wait_for_result(session_id, Duration::from_millis(1)).await {
            Err(MulError::ResultAlreadyReceived(_)) => { panic!("already received result"); }
            Err(e) => { panic!("unexpected error during waiting: {e}"); }
            Ok(shares) => { Some(shares) }
        };

        // 8. Check that shares are correct
        assert!(real_shares.is_some());
        for (real_share, correct_share) in real_shares.unwrap().into_iter().zip(correct_shares) {
            assert_eq!(real_share.degree, t);
            assert_eq!(real_share.id, node_id);
            assert_eq!(real_share.share[0], correct_share.share[0]);
        }
    }
}
