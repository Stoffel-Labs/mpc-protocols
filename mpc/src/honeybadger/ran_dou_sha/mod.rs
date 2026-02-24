pub mod messages;

use crate::{
    common::{
        rbc::RbcError,
        share::{apply_vandermonde, make_vandermonde, shamir::NonRobustShare, ShareError},
        ProtocolSessionId, SecretSharingScheme, RBC,
    },
    honeybadger::{
        double_share::DoubleShamirShare, ran_dou_sha::messages::RanDouShaPayload,
        robust_interpolate::InterpolateError, ProtocolType, SessionId, WrappedMessage,
    },
};
use ark_ff::FftField;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_serialize::{CanonicalSerialize, SerializationError};
use bincode::ErrorKind;
use messages::{RanDouShaMessage, RanDouShaMessageType, ReconstructionMessage};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};
use thiserror::Error;
use tokio::sync::{
    oneshot::{channel, Receiver, Sender},
    Mutex,
};
use tokio::time::{timeout, Duration};

use stoffelnet::network_utils::{Network, NetworkError, PartyId};
use tracing::info;

/// Error that occurs during the execution of the Random Double Share Error.
#[derive(Debug, Error)]
pub enum RanDouShaError {
    /// The error occurs when communicating using the network.
    #[error("there was an error in the network: {0:?}")]
    NetworkError(#[from] NetworkError),
    #[error("error while serializing an arkworks object: {0:?}")]
    ArkSerialization(#[from] SerializationError),
    #[error("error while serializing an arkworks object: {0:?}")]
    ArkDeserialization(SerializationError),
    #[error("error while serializing the object into bytes: {0:?}")]
    SerializationError(#[from] Box<ErrorKind>),
    #[error("Rbc error: {0}")]
    RbcError(#[from] RbcError),
    #[error("Interpolate error: {0}")]
    InterpolateError(#[from] InterpolateError),
    /// The protocol received an abort signal.
    #[error("received abort signal")]
    Abort,
    #[error("error sending the result: {0:?}")]
    SendError(SessionId),
    #[error("error receiving the result: {0:?}")]
    ReceiveError(SessionId),
    #[error("ShareError: {0}")]
    ShareError(#[from] ShareError),
    #[error("session ID {0:?} malformed")]
    SessionIdError(SessionId),
    #[error("limit reached")]
    LimitError,
    #[error("no such session ID exists: {0:?}")]
    NoSuchSessionId(SessionId),
    #[error("result already received: {0:?}")]
    ResultAlreadyReceived(SessionId),
    #[error("multiplication {0:?} did not complete in time")]
    Timeout(SessionId),
}

/// Storage for the Random Double Sharing protocol.
#[derive(Debug)]
pub struct RanDouShaStore<F: FftField> {
    /// Vector that stores the received degree t shares of r.
    pub received_r_shares_degree_t: HashMap<PartyId, NonRobustShare<F>>,
    /// Vector that stores the received degree 2t shares of r.
    pub received_r_shares_degree_2t: HashMap<PartyId, NonRobustShare<F>>,
    /// Vector of r shares of degree t computed as a result of multiplying the Vandermonde matrix
    /// with the shares of s.
    pub computed_r_shares_degree_t: Vec<NonRobustShare<F>>,
    /// Vector of r shares of degree 2t computed as a result of multiplying the Vandermonde matrix
    /// with the shares of s.
    pub computed_r_shares_degree_2t: Vec<NonRobustShare<F>>,
    /// Vector that stores the nodes who have sent the output ok msg.
    pub received_ok_msg: Vec<usize>,
    /// Current state of the protocol.
    pub state: RanDouShaState,
    pub protocol_output: Vec<DoubleShamirShare<F>>,
    pub output_sender: Option<Sender<Vec<DoubleShamirShare<F>>>>,
    pub output_receiver: Option<Receiver<Vec<DoubleShamirShare<F>>>>,
}

/// State of the Random Double Sharing protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RanDouShaState {
    /// The protocol has been initialized.
    Initialized,
    /// The protocol has been finished.
    Finished,
}

impl<F> RanDouShaStore<F>
where
    F: FftField,
{
    /// Creates a new empty store for the random double sharing node.
    pub fn empty() -> Self {
        let (output_sender, output_receiver) = channel();

        Self {
            received_r_shares_degree_t: HashMap::new(),
            received_r_shares_degree_2t: HashMap::new(),
            computed_r_shares_degree_t: Vec::new(),
            computed_r_shares_degree_2t: Vec::new(),
            received_ok_msg: Vec::new(),
            state: RanDouShaState::Initialized,
            protocol_output: Vec::new(),
            output_sender: Some(output_sender),
            output_receiver: Some(output_receiver),
        }
    }
}

/// Node representation for the Random Double Share protocol.
#[derive(Clone, Debug)]
pub struct RanDouShaNode<F: FftField, R: RBC> {
    /// ID of the node.
    pub id: PartyId,
    /// Number of parties involved in the protocol.
    pub n_parties: usize,
    /// Threshold of corrupted parties.
    pub threshold: usize,
    /// Storage of the node.
    pub store: Arc<Mutex<BTreeMap<SessionId, Arc<Mutex<RanDouShaStore<F>>>>>>,
    ///Avid instance for RBC
    pub rbc: R,
}

pub static MAX_RAN_DOU_SHA_SESSIONS: usize = 1024;

impl<F, R> RanDouShaNode<F, R>
where
    F: FftField,
    R: RBC<Id = SessionId>,
{
    pub fn new(
        id: PartyId,
        n_parties: usize,
        threshold: usize,
        k: usize, // for RBC init
    ) -> Result<Self, RanDouShaError> {
        let rbc = R::new(
            id,
            n_parties,
            threshold,
            k,
            Arc::new(WrappedMessage::rbc_wrap),
        )?;
        Ok(Self {
            id,
            n_parties,
            threshold,
            store: Arc::new(Mutex::new(BTreeMap::new())),
            rbc,
        })
    }
    pub async fn clear_store(&self, session_id: SessionId) -> bool {
        let mut store = self.store.lock().await;
        store.remove(&session_id).is_some()
    }

    /// Returns the storage for a node in the Random Double Sharing protocol. If the storage has
    /// not been created yet, the function will create an empty storage and return it.
    pub async fn get_or_create_store(
        &mut self,
        session_id: SessionId,
    ) -> Result<Arc<Mutex<RanDouShaStore<F>>>, RanDouShaError> {
        let mut storage = self.store.lock().await;

        if storage.len() == MAX_RAN_DOU_SHA_SESSIONS {
            return Err(RanDouShaError::LimitError);
        }

        Ok(storage
            .entry(session_id)
            .or_insert(Arc::new(Mutex::new(RanDouShaStore::empty())))
            .clone())
    }

    pub async fn wait_for_result(
        &self,
        session_id: SessionId,
        duration: Duration,
    ) -> Result<Vec<DoubleShamirShare<F>>, RanDouShaError> {
        let output_receiver = {
            let storage = self.store.lock().await;
            let storage_bind = match storage.get(&session_id) {
                Some(value) => value,
                None => return Err(RanDouShaError::NoSuchSessionId(session_id)),
            };
            let mut storage = storage_bind.lock().await;

            storage
                .output_receiver
                .take()
                .ok_or(RanDouShaError::ResultAlreadyReceived(session_id))?
        };

        match timeout(duration, output_receiver).await {
            Err(_) => Err(RanDouShaError::Timeout(session_id)),
            Ok(Err(_)) => Err(RanDouShaError::ReceiveError(session_id)),
            Ok(Ok(shares)) => Ok(shares),
        }
    }

    async fn try_finalize(
        &self,
        session_id: SessionId,
        store_mutex: Arc<Mutex<RanDouShaStore<F>>>,
    ) -> Result<bool, RanDouShaError> {
        let mut store = store_mutex.lock().await;

        // Already finished
        if store.state == RanDouShaState::Finished {
            return Ok(true);
        }

        // Must be initialized
        if store.computed_r_shares_degree_t.len() < self.threshold + 1
            || store.computed_r_shares_degree_2t.len() < self.threshold + 1
        {
            return Ok(false);
        }

        // Need enough OK messages
        if store.received_ok_msg.len() < self.n_parties - (self.threshold + 1) {
            return Ok(false);
        }

        // Construct output
        let output_r_t = store.computed_r_shares_degree_t[0..self.threshold + 1].to_vec();

        let output_r_2t = store.computed_r_shares_degree_2t[0..self.threshold + 1].to_vec();

        let output_double_share: Vec<DoubleShamirShare<F>> = output_r_t
            .into_iter()
            .zip(output_r_2t)
            .map(|(a, b)| DoubleShamirShare::new(a, b))
            .collect();

        store.state = RanDouShaState::Finished;
        store.protocol_output = output_double_share.clone();

        let sender = store.output_sender.take().unwrap();
        sender
            .send(output_double_share)
            .map_err(|_| RanDouShaError::SendError(session_id))?;

        Ok(true)
    }

    /// Implements the initialization phase of the Random double share protocol. In particular,
    /// this method implements from Step (1) to Step (3) before the reconstruction of the shares
    /// $\llbracket r_i \rrbracket$.
    ///
    /// # Warning
    ///
    /// This method assumes that the [`InitMessage`] contains the shares sorted in such a way that
    /// the share in position `k` is the share $\llbracket r_k \rrbracket_{t}^{(i)} where `i` is
    /// the ID of the current participant.
    ///
    /// # Errors
    ///
    /// If sending the shares through the network fails, the function returns a [`NetworkError`].
    pub async fn init<N>(
        &mut self,
        shares_deg_t: Vec<NonRobustShare<F>>,
        shares_deg_2t: Vec<NonRobustShare<F>>,
        session_id: SessionId,
        network: Arc<N>,
    ) -> Result<(), RanDouShaError>
    where
        N: Network,
    {
        info!(
            "Node {} (session {}) - Starting init_handler.",
            self.id,
            session_id.as_u64()
        );

        assert_eq!(session_id.sub_id(), 0);

        // todo - should check sender.id == self?
        let vandermonde_matrix = make_vandermonde(self.n_parties, self.n_parties - 1)?;
        // Implementation of Step 1.
        let r_deg_t = apply_vandermonde(&vandermonde_matrix, &shares_deg_t)?;

        // Implementation of Step 2.
        let r_deg_2t = apply_vandermonde(&vandermonde_matrix, &shares_deg_2t)?;

        // Save the shares of r of degree t and 2t into the storage.
        let bind_store = self.get_or_create_store(session_id).await?;
        let mut store = bind_store.lock().await;
        store.computed_r_shares_degree_t = r_deg_t.clone();
        store.computed_r_shares_degree_2t = r_deg_2t.clone();
        drop(store);
        // Check if pending OK messages are sufficient to finalize immediately
        self.try_finalize(session_id, bind_store.clone()).await?;

        // The current party with index i sends the share [r_j] to the party P_j so that P_j can
        // reconstruct the value r_j.
        for i in 0..self.n_parties {
            if i >= self.threshold + 1 && i < self.n_parties {
                let share_deg_t = r_deg_t[i].clone();
                let share_deg_2t = r_deg_2t[i].clone();
                let reconst_message = ReconstructionMessage::new(share_deg_t, share_deg_2t);

                // Serializing the reconstruction message and wrapping it into a generic message.
                let mut bytes_rec_message = Vec::new();
                reconst_message.serialize_compressed(&mut bytes_rec_message)?;
                let rds_message = RanDouShaMessage::new(
                    self.id,
                    RanDouShaMessageType::ReconstructMessage,
                    session_id,
                    RanDouShaPayload::Reconstruct(bytes_rec_message),
                );
                let wrapped = WrappedMessage::RanDouSha(rds_message);

                let bytes_wrapped = bincode::serialize(&wrapped)?;
                // Sending the generic message to the network.
                network.send(i, &bytes_wrapped).await?;
            }
        }
        Ok(())
    }

    /// Implements Step (3) Reconstruction of shares of RanDouSha Protocol
    /// https://eprint.iacr.org/2019/883.pdf.
    /// On receiving shares of r_i from each parties of degree t and 2t, the protocol privately reconstructs r_i for both degrees
    /// and checks that both shares are of the correct degree, and that their 0-evaluation is the same.
    /// Broadcast OK if the verification succeeds, ABORT otherwise
    ///
    /// # Errors
    ///
    /// If sending the shares through the network fails, the function returns a [`NetworkError`].
    pub async fn reconstruction_handler<N>(
        &mut self,
        msg: RanDouShaMessage,
        network: Arc<N>,
    ) -> Result<(), RanDouShaError>
    where
        N: Network + Send + Sync,
    {
        info!(
            "Node {} (session {}) - Starting reconstruction_handler for message from sender {}.",
            self.id,
            msg.session_id.as_u64(),
            msg.sender_id
        );

        if msg.session_id.sub_id() != 0 {
            return Err(RanDouShaError::SessionIdError(msg.session_id));
        }

        let payload = match msg.payload {
            RanDouShaPayload::Reconstruct(p) => p,
            RanDouShaPayload::Output(_) => return Err(RanDouShaError::Abort),
        };
        let rec_msg: ReconstructionMessage<F> =
            ark_serialize::CanonicalDeserialize::deserialize_compressed(payload.as_slice())?;
        // --- Step (3) Implementation ---
        // (1) Store the received shares.
        // Each party receives a ReconstructionMessage. This message contains two ShamirSecretSharing objects:
        // one for degree t and one for degree 2t.
        // These shares originate from the *sender* of the message, but they are components of the 'r_j'

        let binding = self.get_or_create_store(msg.session_id).await?;
        let mut store = binding.lock().await;

        let sender_id = msg.sender_id;
        store
            .received_r_shares_degree_t
            .insert(sender_id, rec_msg.r_share_deg_t.clone());
        store
            .received_r_shares_degree_2t
            .insert(sender_id, rec_msg.r_share_deg_2t.clone());

        // (2) Check if this party (self.id) is one of the designated checking parties.
        // Condition from the protocol: `t + 1 < i <= n`
        if self.id >= self.threshold + 1 && self.id < self.n_parties {
            // (3) Check if enough shares have been received to reconstruct.
            // To reconstruct a (t) degree polynomial, you need t+1 distinct shares.
            // To reconstruct a (2t) degree polynomial, you need 2t+1 distinct shares.

            if store.received_r_shares_degree_t.len() >= 2 * self.threshold + 1
                && store.received_r_shares_degree_2t.len() >= 2 * self.threshold + 1
            {
                let mut shares_t_for_recon: Vec<NonRobustShare<F>> = Vec::new();
                let mut shares_2t_for_recon: Vec<NonRobustShare<F>> = Vec::new();

                for (_, share) in store.received_r_shares_degree_t.iter() {
                    shares_t_for_recon.push(share.clone());
                }
                for (_, share) in store.received_r_shares_degree_2t.iter() {
                    shares_2t_for_recon.push(share.clone());
                }
                drop(store);
                // (5) Perform reconstruction for both degrees.
                // ShamirSecretSharing::reconstruct expects a vector of shares.
                let reconstructed_r_t =
                    NonRobustShare::recover_secret(&shares_t_for_recon, self.n_parties)?;
                let reconstructed_r_2t =
                    NonRobustShare::recover_secret(&shares_2t_for_recon, self.n_parties)?;
                let poly1 = DensePolynomial::from_coefficients_slice(&reconstructed_r_t.0);
                let poly2 = DensePolynomial::from_coefficients_slice(&reconstructed_r_2t.0);

                let ok = (self.threshold == poly1.degree())
                    && (2 * self.threshold == poly2.degree())
                    && (reconstructed_r_t.1 == reconstructed_r_2t.1);

                let wrapped = WrappedMessage::RanDouSha(RanDouShaMessage::new(
                    self.id,
                    RanDouShaMessageType::OutputMessage,
                    msg.session_id,
                    RanDouShaPayload::Output(ok),
                ));

                let bytes_wrapped = bincode::serialize(&wrapped)?;

                // if the verification succeeds, broadcast true (aka. OK)
                let sessionid = SessionId::new(
                    ProtocolType::Randousha,
                    SessionId::pack_slot24(
                        msg.session_id.exec_id(),
                        self.id as u8,
                        msg.session_id.round_id(),
                    ),
                    msg.session_id.instance_id(),
                );
                self.rbc
                    .init(
                        bytes_wrapped,
                        sessionid, // A unique session id per node
                        Arc::clone(&network),
                    )
                    .await?;
            }
        }

        Ok(())
    }

    /// Implements step (4) (5) of Protocol RanDouSha
    /// Wait to receive broadcast of output message from other party.
    /// Return [r_1]_t ... [r_t+1]_t & [r_1]_2t ... [r_t+1]_2t only if one receives more than
    /// (n - (t+1)) Ok message.
    pub async fn output_handler(&mut self, msg: RanDouShaMessage) -> Result<(), RanDouShaError> {
        let output = match msg.payload {
            RanDouShaPayload::Reconstruct(_) => return Err(RanDouShaError::Abort),
            RanDouShaPayload::Output(ok) => ok,
        };
        info!("Node {} (session {}) - Starting output_handler for message from sender {}. Status: {}.", self.id, msg.session_id.as_u64(), msg.sender_id, output);
        // todo - add randousha status so we can omit output_handler
        // abort randousha once received the abort message
        if !output {
            return Err(RanDouShaError::Abort);
        }
        let binding = self.get_or_create_store(msg.session_id).await?;
        let mut store = binding.lock().await;

        // push to received_ok_msg if sender doesn't exist
        if !store.received_ok_msg.contains(&msg.sender_id) {
            store.received_ok_msg.push(msg.sender_id);
        }

        drop(store);
        self.try_finalize(msg.session_id, binding.clone()).await?;
        Ok(())
    }

    pub async fn process<N>(
        &mut self,
        msg: RanDouShaMessage,
        network: Arc<N>,
    ) -> Result<(), RanDouShaError>
    where
        N: Network + Send + Sync,
    {
        match msg.msg_type {
            messages::RanDouShaMessageType::OutputMessage => {
                self.output_handler(msg).await?;
                return Ok(());
            }
            messages::RanDouShaMessageType::ReconstructMessage => {
                self.reconstruction_handler(msg, network).await?;
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::rbc::rbc::Avid;
    use crate::honeybadger::ran_dou_sha::messages::{
        RanDouShaMessage, RanDouShaMessageType, RanDouShaPayload, ReconstructionMessage,
    };
    use crate::honeybadger::SessionId;
    use ark_bls12_381::Fr;
    use ark_serialize::CanonicalSerialize;
    use std::sync::Arc;
    use stoffelmpc_network::fake_network::{FakeNetwork, FakeNetworkConfig};

    #[tokio::test]
    async fn test_randousha_storage_limit_in_reconstruction_handler() {
        let mut node = RanDouShaNode::<Fr, Avid<SessionId>>::new(0, 5, 1, 2).unwrap();
        let net = Arc::new(FakeNetwork::new(5, None, FakeNetworkConfig::new(10), 0).0);

        // Fill up the storage to the limit by calling reconstruction_handler with unique session IDs
        let mut exec = 0u8;
        let mut round = 0u8;
        for _ in 0..super::MAX_RAN_DOU_SHA_SESSIONS {
            let sid = SessionId::new(
                ProtocolType::Randousha,
                SessionId::pack_slot24(exec, 0, round),
                111,
            );
            let rec_msg = ReconstructionMessage::<Fr>::new(Default::default(), Default::default());
            let mut payload = Vec::new();
            rec_msg.serialize_compressed(&mut payload).unwrap();
            let msg = RanDouShaMessage::new(
                0,
                RanDouShaMessageType::ReconstructMessage,
                sid,
                RanDouShaPayload::Reconstruct(payload),
            );
            // Ignore the result, just fill up storage
            let _ = node.reconstruction_handler(msg, net.clone()).await;

            // Increment exec and round to ensure unique session IDs
            if round == u8::MAX {
                round = 0;
                exec = exec.wrapping_add(1);
            } else {
                round = round.wrapping_add(1);
            }
        }

        // Now try to process a message that would require a new session (should hit the limit)
        let over_sid = SessionId::new(
            ProtocolType::Randousha,
            SessionId::pack_slot24(255, 0, 255),
            0,
        );
        let rec_msg = ReconstructionMessage::<Fr>::new(Default::default(), Default::default());
        let mut payload = Vec::new();
        rec_msg.serialize_compressed(&mut payload).unwrap();
        let msg = RanDouShaMessage::new(
            0,
            RanDouShaMessageType::ReconstructMessage,
            over_sid,
            RanDouShaPayload::Reconstruct(payload),
        );

        let result = node.reconstruction_handler(msg, net).await;
        assert!(
            matches!(result, Err(RanDouShaError::LimitError)),
            "Should error on exceeding storage limit"
        );
    }

    #[tokio::test]
    async fn test_randousha_handle_invalid_sub_id() {
        let mut node = RanDouShaNode::<Fr, Avid<SessionId>>::new(0, 5, 1, 2).unwrap();
        let net = Arc::new(FakeNetwork::new(5, None, FakeNetworkConfig::new(10), 0).0);

        // Create a session id with sub_id != 0
        let session_id =
            SessionId::new(ProtocolType::Randousha, SessionId::pack_slot24(0, 1, 0), 0);

        // Create a dummy payload
        let rec_msg = ReconstructionMessage::<Fr>::new(Default::default(), Default::default());
        let mut payload = Vec::new();
        rec_msg.serialize_compressed(&mut payload).unwrap();
        let msg = RanDouShaMessage::new(
            0,
            RanDouShaMessageType::ReconstructMessage,
            session_id,
            RanDouShaPayload::Reconstruct(payload),
        );

        // Should return a SessionIdError due to sub_id != 0
        let result = node.reconstruction_handler(msg, net).await;
        match result {
            Err(RanDouShaError::SessionIdError(sid)) => assert_eq!(sid, session_id),
            _ => panic!("Expected SessionIdError for invalid sub_id"),
        }
    }
}
