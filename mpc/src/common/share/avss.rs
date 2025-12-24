use crate::{
    common::{rbc::RbcError, share::shamir::Shamirshare, RBC},
    honeybadger::{SessionId, WrappedMessage},
};
use ark_ec::CurveGroup;
use ark_ff::FftField;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use bincode::ErrorKind;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};
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

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct FeldmanShamirShare<F: FftField, G: CurveGroup<ScalarField = F>> {
    pub feldmanshare: Shamirshare<F>,
    pub commitments: Vec<G>,
}

impl<F: FftField, G: CurveGroup<ScalarField = F>> FeldmanShamirShare<F, G> {
    pub fn new(share: F, id: usize, degree: usize, commitments: Vec<G>) -> Self {
        let shamirshare = Shamirshare::new(share, id, degree);
        FeldmanShamirShare {
            feldmanshare: shamirshare,
            commitments: commitments,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvssMessage {
    sender_id: PartyId,
    session_id: SessionId,
    shares: Vec<u8>,
}

impl AvssMessage {
    pub fn new(sender: PartyId, session_id: SessionId, shares: Vec<u8>) -> Self {
        Self {
            sender_id: sender,
            session_id,
            shares,
        }
    }
}

fn verify_feldman<F: FftField, G: CurveGroup<ScalarField = F>>(
    share: FeldmanShamirShare<F, G>,
) -> bool {
    let x = F::from(share.feldmanshare.id as u64);
    let mut rhs = G::zero();
    let mut pow = F::one();

    for c in share.commitments {
        rhs += c.mul(pow);
        pow *= x;
    }

    G::generator().mul(share.feldmanshare.share[0]) == rhs
}

#[derive(Clone, Debug)]
pub struct AvssNode<F, R, G>
where
    F: FftField,
    R: RBC,
    G: CurveGroup<ScalarField = F>,
{
    pub id: PartyId,
    pub n_parties: usize,
    pub t: usize,
    pub shares: Arc<Mutex<BTreeMap<SessionId, Option<FeldmanShamirShare<F, G>>>>>,
    pub rbc: R,
    pub output_sender: Sender<SessionId>,
}

impl<F, R, G> AvssNode<F, R, G>
where
    F: FftField,
    R: RBC,
    G: CurveGroup<ScalarField = F>,
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
            shares: Arc::new(Mutex::new(BTreeMap::new())),
            rbc,
            output_sender,
        })
    }

    pub async fn init<Rnd, N>(
        &mut self,
        session_id: SessionId,
        rng: &mut Rnd,
        net: Arc<N>,
    ) -> Result<(), AvssError>
    where
        N: Network + Sync + Send,
        Rnd: Rng,
    {
        let secret = F::rand(rng);
        // Generate the random polynomial of degree `degree` with `secret` as constant term
        let mut poly = DensePolynomial::rand(self.t, rng);
        poly[0] = secret;

        let commitments: Vec<_> = poly
            .coeffs
            .iter()
            .map(|a_j| G::generator().mul(a_j))
            .collect();

        let shares: Vec<_> = (0..self.n_parties)
            .map(|party_id| {
                let x_id = party_id + 1;
                let x = F::from(x_id as u64);
                let y = poly.evaluate(&x);

                FeldmanShamirShare::new(y, x_id, self.t, commitments.clone())
            })
            .collect();

        //Todo: Encrypt the shares
        let mut shares_bytes = Vec::new();
        shares.serialize_compressed(&mut shares_bytes)?;

        let msg = AvssMessage::new(self.id, session_id, shares_bytes);
        let wrapped = WrappedMessage::Avss(msg);
        let bytes = bincode::serialize(&wrapped)?;

        //Broadcast to servers
        let sessionid = SessionId::new(
            session_id.calling_protocol().unwrap(),
            0,
            0,
            self.id as u8,
            session_id.instance_id(),
        );

        self.rbc.init(bytes, sessionid, net).await?;

        Ok(())
    }

    pub async fn receive_handler(&mut self, recv: AvssMessage) -> Result<(), AvssError> {
        //Todo: Decrypt the shares
        let shares: Vec<FeldmanShamirShare<F, G>> =
            CanonicalDeserialize::deserialize_compressed(recv.shares.as_slice())?;

        let mut binding = self.shares.lock().await;
        if binding.contains_key(&recv.session_id) {
            return Ok(()); // ignore duplicates
        }
        let my_share = shares[self.id].clone();
        if !verify_feldman(my_share.clone()) {
            return Err(AvssError::InvalidShare);
        }

        binding.insert(recv.session_id, Some(my_share));
        self.output_sender.send(recv.session_id).await?;
        Ok(())
    }

    pub async fn process(&mut self, recv: AvssMessage) -> Result<(), AvssError> {
        self.receive_handler(recv).await
    }
}
