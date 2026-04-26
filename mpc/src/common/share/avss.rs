use crate::common::{
    rbc::RbcError,
    share::{feldman::FeldmanShamirShare, shamir::Shamirshare, ShareError},
    ProtocolSessionId, RbcWrapFn, SecretSharingScheme, RBC,
};
use ark_ec::CurveGroup;
use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use bincode::{ErrorKind, Options};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc};
use stoffelnet::network_utils::{Network, PartyId};
use tokio::sync::{
    mpsc::{self, Receiver, Sender},
    Mutex,
};
use tracing::{info, warn};

const MAX_MESSAGE_SIZE: u64 = 10 * 1024 * 1024; // 10 MiB

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
    #[error("invalid share length")]
    InvalidShareLength,
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
    SendError,
    #[error("Channel closed")]
    Abort,
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AvssMessage<Id: ProtocolSessionId> {
    pub session_id: Id,
    pub dealer_pk: Vec<u8>,
    pub public_commitments: Vec<Vec<Vec<u8>>>,
    pub encrypted_shares: Vec<Vec<Vec<u8>>>,
}

impl<Id: ProtocolSessionId> AvssMessage<Id>
where
    Id: ProtocolSessionId,
{
    pub fn new(
        session_id: Id,
        dealer_pk: Vec<u8>,
        public_commitments: Vec<Vec<Vec<u8>>>,
        encrypted_shares: Vec<Vec<Vec<u8>>>,
    ) -> Self {
        Self {
            session_id,
            dealer_pk,
            public_commitments,
            encrypted_shares,
        }
    }
}

pub fn verify_feldman<F: FftField, G: CurveGroup<ScalarField = F>>(
    share: FeldmanShamirShare<F, G>,
) -> bool {
    if share.commitments.len() != share.feldmanshare.degree + 1 {
        return false;
    }
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

pub type AvssWrapFn<Id> =
    Arc<dyn Fn(AvssMessage<Id>) -> Result<Vec<u8>, RbcError> + Send + Sync + 'static>;

#[derive(Clone)]
pub struct AvssNode<F, R, G, Id>
where
    F: FftField,
    R: RBC,
    G: CurveGroup<ScalarField = F>,
    Id: ProtocolSessionId,
{
    pub id: PartyId,
    pub n_parties: usize,
    pub t: usize,
    pub sk_i: F,
    pub pk_map: Arc<Vec<G>>,
    pub shares: Arc<Mutex<BTreeMap<Id, Option<Vec<FeldmanShamirShare<F, G>>>>>>,
    pub rbc: R,
    pub rbc_output: Arc<Mutex<Receiver<Id>>>,
    pub output_sender: Sender<Id>,
    pub wrapper: AvssWrapFn<Id>,
}
impl<F, R, G, Id> std::fmt::Debug for AvssNode<F, R, G, Id>
where
    F: FftField,
    R: RBC + std::fmt::Debug,
    G: CurveGroup<ScalarField = F>,
    Id: ProtocolSessionId,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AvssNode")
            .field("id", &self.id)
            .field("n_parties", &self.n_parties)
            .field("t", &self.t)
            .field("shares", &self.shares)
            .field("rbc", &self.rbc)
            .field("wrapper", &"<fn>") // 👈 intentionally opaque
            .finish()
    }
}

impl<F, R, G, Id> AvssNode<F, R, G, Id>
where
    F: FftField,
    R: RBC<Id = Id>,
    G: CurveGroup<ScalarField = F>,
    Id: ProtocolSessionId + for<'a> Deserialize<'a> + Serialize,
{
    pub fn new(
        id: PartyId,
        n_parties: usize,
        t: usize,
        sk_i: F,
        pk_map: Arc<Vec<G>>,
        output_sender: Sender<Id>,
        rbc_wrapper: RbcWrapFn<Id>,
        avss_wrapper: AvssWrapFn<Id>,
    ) -> Result<Self, AvssError> {
        let (rbc_sender, rbc_receiver) = mpsc::channel(200);
        let rbc = R::new(id, n_parties, t, t + 1, rbc_sender, rbc_wrapper)?;
        Ok(Self {
            id,
            n_parties,
            t,
            sk_i,
            pk_map,
            shares: Arc::new(Mutex::new(BTreeMap::new())),
            rbc,
            rbc_output: Arc::new(Mutex::new(rbc_receiver)),
            output_sender,
            wrapper: avss_wrapper,
        })
    }

    pub async fn drain_rbc_output(&mut self) -> Result<(), AvssError> {
        loop {
            let id = {
                let mut rx = self.rbc_output.lock().await;
                match rx.try_recv() {
                    Ok(id) => id,
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        return Err(AvssError::Abort);
                    }
                }
            };

            let output = self.rbc.get_store(id).await?;
            let msg: AvssMessage<Id> = bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .allow_trailing_bytes()
                .with_limit(MAX_MESSAGE_SIZE)
                .deserialize(&output)?;

            if msg.session_id != id {
                warn!("Dropping RBC output: inner session_id does not match RBC session metadata");
                continue;
            }

            match self.process(msg).await {
                Ok(()) => {}
                Err(e) => {
                    return Err(e);
                }
            }
        }
        Ok(())
    }
    pub async fn init<Rnd, N>(
        &mut self,
        secrets: Vec<F>,
        session_id: Id,
        rng: &mut Rnd,
        net: Arc<N>,
    ) -> Result<(), AvssError>
    where
        N: Network + Sync + Send,
        Rnd: Rng,
    {
        info!("Receiving init for avss from {0:?}", self.id);
        // Generate the random polynomial of degree `degree` with `secret` as constant term

        let ids: Vec<usize> = (1..=self.n_parties).collect();
        let shares: Vec<Vec<FeldmanShamirShare<F, G>>> = secrets
            .into_iter()
            .map(|secret| {
                FeldmanShamirShare::compute_shares(secret, self.n_parties, self.t, Some(&ids), rng)
            })
            .collect::<Result<Vec<_>, ShareError>>()?;

        // Dealer ephemeral keypair
        let sk_d = F::rand(rng);
        let pk_d = G::generator().mul(sk_d);

        let mut pk_d_bytes = Vec::new();
        pk_d.serialize_compressed(&mut pk_d_bytes)?;

        let mut encrypted: Vec<Vec<Vec<u8>>> =
            vec![Vec::with_capacity(shares.len()); self.n_parties];

        let keys: Vec<_> = self
            .pk_map
            .iter()
            .map(|pk| {
                let ss = pk.mul(sk_d);
                kdf_from_point(&ss)
            })
            .collect();
        let mut public_commitments: Vec<Vec<Vec<u8>>> = Vec::with_capacity(shares.len());
        let mut pt = Vec::new();
        for x in &shares {
            assert_eq!(x.len(), self.n_parties);
            // commitments are identical across all parties for the same polynomial
            let commitment_bytes = x[0]
                .commitments
                .iter()
                .map(|c| {
                    let mut b = Vec::new();
                    c.serialize_compressed(&mut b).map(|_| b)
                })
                .collect::<Result<Vec<_>, _>>()?;
            public_commitments.push(commitment_bytes);

            for (i, share) in x.iter().enumerate() {
                pt.clear();
                share.feldmanshare.serialize_compressed(&mut pt)?; // scalar only
                encrypted[i].push(encrypt(keys[i].clone(), &pt, rng)?);
            }
        }

        //Broadcast to servers
        let msg = AvssMessage {
            session_id: session_id,
            dealer_pk: pk_d_bytes,
            public_commitments,
            encrypted_shares: encrypted,
        };

        let bytes = bincode::serialize(&msg)?;
        self.rbc.init(bytes, session_id, net).await?;

        Ok(())
    }

    pub async fn process(&mut self, msg: AvssMessage<Id>) -> Result<(), AvssError> {
        info!(
            party_id = ?self.id,
            session_id = msg.session_id.as_u64(),
            "Processing AVSS share"
        );
        match msg.session_id.calling_protocol() {
            Some(proto) => proto,
            None => {
                return Err(AvssError::InvalidInput(format!(
                    "Unknown calling protocol in session ID {:?}",
                    msg.session_id
                )));
            }
        };
        {
            let map = self.shares.lock().await;
            if map.contains_key(&msg.session_id) {
                return Ok(()); // ignore duplicates
            }
        };

        let pk_d: G = CanonicalDeserialize::deserialize_compressed(&msg.dealer_pk[..])?;
        let cts: &Vec<Vec<u8>> = msg
            .encrypted_shares
            .get(self.id)
            .ok_or(AvssError::InvalidShare)?;

        let ss = pk_d.mul(self.sk_i);
        let key = kdf_from_point(&ss);

        let all_commitments: Vec<Vec<G>> = msg
            .public_commitments
            .iter()
            .map(|cs| {
                cs.iter()
                    .map(|b| G::deserialize_compressed(&b[..]))
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;

        if cts.len() != all_commitments.len() {
            return Err(AvssError::InvalidShareLength);
        }

        let mut shares = Vec::with_capacity(cts.len());
        for (ct, commitments) in cts.iter().zip(all_commitments.iter()) {
            let pt = decrypt(key.clone(), ct)?;
            let shamirshare: Shamirshare<F> =
                CanonicalDeserialize::deserialize_compressed(&pt[..])?;

            let share = FeldmanShamirShare {
                feldmanshare: shamirshare,
                commitments: commitments.clone(),
            };

            if !verify_feldman(share.clone()) {
                return Err(AvssError::InvalidShare);
            }

            shares.push(share);
        }

        {
            let mut map = self.shares.lock().await;
            map.insert(msg.session_id, Some(shares));
        };
        self.output_sender
            .send(msg.session_id)
            .await
            .map_err(|_| AvssError::SendError)?;
        Ok(())
    }
}
