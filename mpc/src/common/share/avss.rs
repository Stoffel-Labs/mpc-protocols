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
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
    #[error("invalid feldman commitment length")]
    InvalidCommitmentLength,
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
    pub fn new(share: F, id: usize, degree: usize, commitments: Vec<G>) -> Result<Self, AvssError> {
        let shamirshare = Shamirshare::new(share, id, degree);
        if commitments.len() != degree + 1 {
            return Err(AvssError::InvalidCommitmentLength);
        }
        Ok(FeldmanShamirShare {
            feldmanshare: shamirshare,
            commitments: commitments,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvssMessage {
    sender_id: PartyId,
    session_id: SessionId,
    dealer_pk: Vec<u8>,
    encrypted_shares: Vec<Vec<u8>>,
}

impl AvssMessage {
    pub fn new(
        sender: PartyId,
        session_id: SessionId,
        dealer_pk: Vec<u8>,
        encrypted_shares: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            sender_id: sender,
            session_id,
            dealer_pk,
            encrypted_shares,
        }
    }
}

pub fn verify_feldman<F: FftField, G: CurveGroup<ScalarField = F>>(
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
fn kdf_from_point<G: CanonicalSerialize>(p: &G) -> [u8; 32] {
    let mut buf = Vec::new();
    p.serialize_compressed(&mut buf).unwrap();
    let hash = Sha256::digest(&buf);
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    key
}

fn encrypt(key: [u8; 32], plaintext: &[u8], rng: &mut impl Rng) -> Result<Vec<u8>, AvssError> {
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| AvssError::InvalidShare)?;

    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce =
        Nonce::from(<[u8; 12]>::try_from(nonce_bytes).map_err(|_| AvssError::InvalidShare)?);

    let mut ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| AvssError::InvalidShare)?;

    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.append(&mut ct);
    Ok(out)
}

fn decrypt(key32: [u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, AvssError> {
    if ciphertext.len() < 12 {
        return Err(AvssError::InvalidShare);
    }
    let (nonce_bytes, ct) = ciphertext.split_at(12);
    let cipher = ChaCha20Poly1305::new_from_slice(&key32).map_err(|_| AvssError::InvalidShare)?;
    let nonce =
        Nonce::from(<[u8; 12]>::try_from(nonce_bytes).map_err(|_| AvssError::InvalidShare)?);

    cipher
        .decrypt(&nonce, ct)
        .map_err(|_| AvssError::InvalidShare)
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
    pub sk_i: F,
    pub pk_map: Arc<Vec<G>>,
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
        sk_i: F,
        pk_map: Arc<Vec<G>>,
        output_sender: Sender<SessionId>,
    ) -> Result<Self, AvssError> {
        let rbc = R::new(id, n_parties, t, t + 1)?;
        Ok(Self {
            id,
            n_parties,
            t,
            sk_i,
            pk_map,
            shares: Arc::new(Mutex::new(BTreeMap::new())),
            rbc,
            output_sender,
        })
    }

    pub async fn init<Rnd, N>(
        &mut self,
        secret: F,
        session_id: SessionId,
        rng: &mut Rnd,
        net: Arc<N>,
    ) -> Result<(), AvssError>
    where
        N: Network + Sync + Send,
        Rnd: Rng,
    {
        // Generate the random polynomial of degree `degree` with `secret` as constant term
        let mut poly = DensePolynomial::rand(self.t, rng);
        poly[0] = secret;

        let commitments: Vec<_> = poly
            .coeffs
            .iter()
            .map(|a_j| G::generator().mul(a_j))
            .collect();

        // Dealer ephemeral keypair
        let sk_d = F::rand(rng);
        let pk_d = G::generator().mul(sk_d);

        let mut pk_d_bytes = Vec::new();
        pk_d.serialize_compressed(&mut pk_d_bytes)?;

        let mut encrypted = Vec::with_capacity(self.n_parties);

        for i in 0..self.n_parties {
            let x = F::from((i + 1) as u64);
            let y = poly.evaluate(&x);

            let share = FeldmanShamirShare::new(y, i + 1, self.t, commitments.clone())?;

            let mut pt = Vec::new();
            share.serialize_compressed(&mut pt)?;

            let ss = self.pk_map[i].mul(sk_d);
            let key = kdf_from_point(&ss);

            encrypted.push(encrypt(key, &pt, rng)?);
        }

        //Broadcast to servers
        let msg = AvssMessage {
            sender_id: self.id,
            session_id: session_id,
            dealer_pk: pk_d_bytes,
            encrypted_shares: encrypted,
        };

        let sessionid = SessionId::new(
            session_id.calling_protocol().unwrap(),
            0,
            0,
            self.id as u8,
            session_id.instance_id(),
        );
        let wrapped = WrappedMessage::Avss(msg);
        let bytes = bincode::serialize(&wrapped)?;

        self.rbc.init(bytes, sessionid, net).await?;

        Ok(())
    }

    pub async fn process(&mut self, msg: AvssMessage) -> Result<(), AvssError> {
        let mut map = self.shares.lock().await;
        if map.contains_key(&msg.session_id) {
            return Ok(()); // ignore duplicates
        }

        let pk_d: G = CanonicalDeserialize::deserialize_compressed(&msg.dealer_pk[..])?;
        let ct = &msg.encrypted_shares[self.id];

        let ss = pk_d.mul(self.sk_i);
        let key = kdf_from_point(&ss);

        let pt = decrypt(key, ct)?;
        let share: FeldmanShamirShare<F, G> =
            CanonicalDeserialize::deserialize_compressed(&pt[..])?;

        if !verify_feldman(share.clone()) {
            return Err(AvssError::InvalidShare);
        }

        map.insert(msg.session_id, Some(share));
        self.output_sender.send(msg.session_id).await?;
        Ok(())
    }
}
