use crate::{
    common::{rbc::RbcError, ShamirShare, RBC},
    honeybadger::{ProtocolType, SessionId, WrappedMessage},
};
use ark_ec::CurveGroup;
use ark_ff::FftField;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use bincode::ErrorKind;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, marker::PhantomData, sync::Arc};
use stoffelnet::network_utils::{Network, PartyId};
use tokio::sync::{mpsc::Sender, Mutex};

#[derive(Debug, thiserror::Error)]
pub enum AvssError {
    #[error("inner error: {0}")]
    RbcError(#[from] RbcError),
    #[error("sender mismatch")]
    SenderMismatch,
    #[error("invalid feldman share")]
    InvalidShare,
    #[error("commitments unavailable")]
    CommitmentsNotFound,
    #[error("serialization error")]
    Serialization(#[from] ark_serialize::SerializationError),
    #[error("error while serializing the object into bytes: {0:?}")]
    SerializationError(#[from] Box<ErrorKind>),
    #[error("network error")]
    Network(#[from] stoffelnet::network_utils::NetworkError),
    #[error("share error")]
    ShareError(#[from] crate::common::share::ShareError),
    #[error("send error")]
    SendError(#[from] tokio::sync::mpsc::error::SendError<SessionId>),
}

#[derive(Clone, Debug)]
pub struct Feldman;
pub type FeldmanShamirShare<T> = ShamirShare<T, 1, Feldman>;

impl<F: FftField> FeldmanShamirShare<F> {
    pub fn new(share: F, id: usize, degree: usize) -> Self {
        FeldmanShamirShare {
            share: [share],
            id,
            degree,
            commitments: None,
            _sharetype: PhantomData,
        }
    }
}
#[derive(Clone, PartialEq, Debug)]
pub enum ProtocolState {
    Initialized,
    Finished,
    NotInitialized,
}

#[derive(Clone, Debug)]
pub struct AvssStorage<F: FftField> {
    pub share: BTreeMap<PartyId, FeldmanShamirShare<F>>,
    pub protocol_output: Vec<FeldmanShamirShare<F>>,
    pub state: ProtocolState,
    pub reception_tracker: Vec<bool>,
}

impl<F: FftField> AvssStorage<F> {
    pub fn empty(n: usize) -> Self {
        Self {
            share: BTreeMap::new(),
            protocol_output: Vec::new(),
            reception_tracker: vec![false; n],
            state: ProtocolState::NotInitialized,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvssMessage {
    sender_id: PartyId,
    session_id: SessionId,
    shares: Vec<u8>,
    commitments: Vec<u8>,
}

impl AvssMessage {
    pub fn new(
        sender: PartyId,
        session_id: SessionId,
        shares: Vec<u8>,
        commitments: Vec<u8>,
    ) -> Self {
        Self {
            sender_id: sender,
            session_id,
            shares,
            commitments,
        }
    }
}

fn verify_feldman<F: FftField, G: CurveGroup<ScalarField = F>>(
    share: FeldmanShamirShare<F>,
    commitments: Vec<G>,
) -> bool {
    let x = F::from(share.id as u64);
    let mut rhs = G::zero();
    let mut pow = F::one();

    for c in commitments {
        rhs += c.mul(pow);
        pow *= x;
    }

    G::generator().mul(share.share[0]) == rhs
}

#[derive(Clone, Debug)]
pub struct AvssNode<F, R>
where
    F: FftField,
    R: RBC,
{
    pub id: PartyId,
    pub n_parties: usize,
    pub t: usize,
    pub storage: Arc<Mutex<BTreeMap<SessionId, Arc<Mutex<AvssStorage<F>>>>>>,
    pub rbc: R,
    pub output_sender: Sender<SessionId>,
}

impl<F, R> AvssNode<F, R>
where
    F: FftField,
    R: RBC,
{
    pub fn new(
        id: PartyId,
        n_parties: usize,
        t: usize,
        output_sender: Sender<SessionId>,
    ) -> Result<Self, AvssError> {
        let rbc = R::new(id, n_parties, t, t + 1)?;
        Ok(Self {
            id,
            n_parties,
            t,
            storage: Arc::new(Mutex::new(BTreeMap::new())),
            rbc,
            output_sender,
        })
    }
    pub async fn get_or_create_store(
        &mut self,
        session_id: SessionId,
    ) -> Arc<Mutex<AvssStorage<F>>> {
        let mut storage = self.storage.lock().await;
        storage
            .entry(session_id)
            .or_insert(Arc::new(Mutex::new(AvssStorage::empty(self.n_parties))))
            .clone()
    }

    pub async fn init<G, Rnd, N>(
        &mut self,
        session_id: SessionId,
        rng: &mut Rnd,
        net: Arc<N>,
    ) -> Result<(), AvssError>
    where
        N: Network + Sync + Send,
        Rnd: Rng,
        G: CurveGroup<ScalarField = F>,
    {
        let secret = F::rand(rng);
        // Generate the random polynomial of degree `degree` with `secret` as constant term
        let mut poly = DensePolynomial::rand(self.t, rng);
        poly[0] = secret;

        let shares: Vec<_> = (0..self.n_parties)
            .map(|party_id| {
                let x_id = party_id + 1;
                let x = F::from(x_id as u64);
                let y = poly.evaluate(&x);

                FeldmanShamirShare::new(y, x_id, self.t)
            })
            .collect();

        let commitments: Vec<_> = poly
            .coeffs
            .iter()
            .map(|a_j| G::generator().mul(a_j))
            .collect();

        let store = self.get_or_create_store(session_id).await;
        store.lock().await.state = ProtocolState::Initialized;

        //Todo: Encrypt the shares
        let mut shares_bytes = Vec::new();
        shares.serialize_compressed(&mut shares_bytes)?;
        let mut commitment_bytes = Vec::new();
        commitments.serialize_compressed(&mut commitment_bytes)?;

        let msg = AvssMessage::new(self.id, session_id, shares_bytes, commitment_bytes);

        let wrapped = WrappedMessage::Avss(msg);
        let bytes = bincode::serialize(&wrapped)?;
        //Broadcast to servers
        let sessionid = SessionId::new(
            ProtocolType::Avss,
            0,
            self.id as u8,
            0,
            session_id.instance_id(),
        );

        self.rbc.init(bytes, sessionid, net).await?;

        Ok(())
    }

    pub async fn receive_handler<G: CurveGroup<ScalarField = F>>(
        &mut self,
        recv: AvssMessage,
    ) -> Result<(), AvssError> {
        //Todo: Decrypt the shares
        let shares: Vec<FeldmanShamirShare<F>> =
            CanonicalDeserialize::deserialize_compressed(recv.shares.as_slice())?;
        let commitments: Vec<G> =
            CanonicalDeserialize::deserialize_compressed(recv.commitments.as_slice())?;

        let binding = self.get_or_create_store(recv.session_id).await;
        let mut store = binding.lock().await;

        if store.share.contains_key(&recv.sender_id) {
            return Ok(()); // ignore duplicates
        }

        if !verify_feldman(shares[self.id].clone(), commitments) {
            return Err(AvssError::InvalidShare);
        }

        let mut my_share = shares[self.id].clone();
        my_share.commitments = Some(recv.commitments);
        store.share.insert(recv.sender_id, my_share);
        store.reception_tracker[recv.sender_id] = true;

        if store.reception_tracker.iter().all(|&x| x) {
            store.protocol_output = store.share.values().cloned().collect();
            store.state = ProtocolState::Finished;
            self.output_sender.send(recv.session_id).await?;
        }

        Ok(())
    }

    pub async fn process<G: CurveGroup<ScalarField = F>>(
        &mut self,
        recv: AvssMessage,
    ) -> Result<(), AvssError> {
        self.receive_handler::<G>(recv).await
    }
}
