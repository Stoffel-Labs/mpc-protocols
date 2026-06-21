use crate::avss_mpc::input::{AvssInputError, AvssInputMessage};
use crate::avss_mpc::{deser_bounded_feldman_vec, AvssSessionId, AvssWrappedMessage, ProtocolType};
use crate::common::share::avss::verify_feldman;
use crate::common::share::feldman::FeldmanShamirShare;
use crate::common::{ProtocolSessionId, SecretSharingScheme, RBC};
use ark_ec::CurveGroup;
use ark_ff::FftField;
use ark_serialize::CanonicalSerialize;
use std::collections::HashMap;
use std::sync::Arc;
use stoffelnet::network_utils::{ClientId, Network, PartyId};
use tokio::{
    sync::{
        watch::{channel, Receiver, Sender},
        Mutex,
    },
    time::{timeout, Duration},
};
use tracing::info;

const MAX_INPUT_ELEMENTS: u64 = 65_536;

/// In the beginning of an MPC calculation, each node has to obtain a share of all clients' inputs.
/// This follows the same pattern as HoneyBadger's input protocol but uses FeldmanShamirShare
/// with Feldman commitment verification:
///   1. each server sends its random FeldmanShamirShare to the respective client,
///   2. once `t+1` verified shares received, the client reconstructs the random values per input
///      and broadcasts the input plus the random value to all nodes via RBC,
///   3. each server receives that masked value and subtracts their respective random share to
///      obtain a share of the input
///
/// The sending of random shares to clients does not use session IDs, since it only occurs once
/// before the computation has started. The RBC call to send masked inputs uses the session ID
///   `[caller=Input, exec=0, sub=client ID, round=0, instance=instance ID]`

#[derive(PartialEq, Clone, Debug)]
enum InputType {
    Empty,
    RandomShares,
    MaskedInputs,
    InputShares,
}

#[derive(Clone, Debug)]
pub struct AvssInputServer<F: FftField, R: RBC, G: CurveGroup<ScalarField = F>> {
    pub id: usize,
    pub n: usize,
    pub t: usize,
    pub rbc: R,
    pub rbc_output: Arc<Mutex<tokio::sync::mpsc::Receiver<AvssSessionId>>>,
    status_sender: Sender<HashMap<ClientId, (InputType, Vec<FeldmanShamirShare<F, G>>)>>,
    status_receiver: Receiver<HashMap<ClientId, (InputType, Vec<FeldmanShamirShare<F, G>>)>>,
}

/// Calculate input shares by subtracting random shares from masked inputs.
/// Given masked_value `m = input + r` (a public field element) and random share `r_i`
/// (a FeldmanShamirShare of `r`), computes `m - r_i` which is a share of `input`.
///
/// For FeldmanShamirShare: the share value becomes `m - r_i.value`, and the commitments
/// become `[m*G - C_0, -C_1, ..., -C_t]` since the new polynomial is `m - f_r(x)`.
fn calculate_input_shares<F: FftField, G: CurveGroup<ScalarField = F>>(
    masked_inputs: &[F],
    random_shares: &[FeldmanShamirShare<F, G>],
) -> Vec<FeldmanShamirShare<F, G>> {
    masked_inputs
        .iter()
        .zip(random_shares)
        .map(|(masked_value, random_share)| {
            let neg_share = (random_share.clone() * (-F::one())).unwrap();
            (neg_share + *masked_value).unwrap()
        })
        .collect()
}

impl<F: FftField, R: RBC<Id = AvssSessionId>, G: CurveGroup<ScalarField = F>>
    AvssInputServer<F, R, G>
{
    pub fn new(
        id: usize,
        n: usize,
        t: usize,
        input_ids: Vec<ClientId>,
    ) -> Result<Self, AvssInputError> {
        let (rbc_sender, rbc_receiver) = tokio::sync::mpsc::channel(200);
        let rbc = R::new(
            id,
            n,
            t,
            t + 1,
            rbc_sender,
            Arc::new(AvssWrappedMessage::rbc_wrap),
        )?;
        let (status_sender, status_receiver) = channel(
            input_ids
                .into_iter()
                .map(|id| (id, (InputType::Empty, vec![])))
                .collect(),
        );

        Ok(Self {
            id,
            n,
            t,
            rbc,
            rbc_output: Arc::new(Mutex::new(rbc_receiver)),
            status_sender,
            status_receiver,
        })
    }

    pub async fn drain_rbc_output(&mut self) -> Result<(), AvssInputError> {
        loop {
            let id = {
                let mut rx = self.rbc_output.lock().await;
                match rx.try_recv() {
                    Ok(id) => id,
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        return Err(AvssInputError::Abort);
                    }
                }
            };

            let output = self.rbc.get_store(id).await?;
            match self.input_handler(id.sub_id().into(), output).await {
                Ok(()) => {}
                Err(e) => {
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// Called by each server to send its share of `r_i` to the client.
    pub async fn init<N: Network>(
        &mut self,
        client_id: usize,
        shares: Vec<FeldmanShamirShare<F, G>>,
        input_len: usize,
        net: Arc<N>,
    ) -> Result<(), AvssInputError> {
        if shares.len() != input_len {
            return Err(AvssInputError::InvalidInput(
                "Incorrect number of shares".to_string(),
            ));
        }

        let mut send_over_network = false;
        let mut already_rand_shares = false;
        let mut unknown_client = false;
        let mut invalid_length = false;

        self.status_sender.send_if_modified(|status| {
            match status.get(&client_id) {
                Some((InputType::RandomShares | InputType::InputShares, _)) => {
                    already_rand_shares = true;
                    false
                }
                Some((InputType::MaskedInputs, masked_inputs_shares)) => {
                    // masked_inputs_shares contain F values stored as FeldmanShamirShares
                    // but actually they are plain F values. We stored them as shares for type
                    // compatibility. Extract the F values.
                    let masked_values: Vec<F> = masked_inputs_shares
                        .iter()
                        .map(|s| s.feldmanshare.share[0])
                        .collect();
                    if masked_values.len() != shares.len() {
                        invalid_length = true;
                        return false;
                    }
                    let input_shares = calculate_input_shares(&masked_values, &shares);

                    status.insert(client_id, (InputType::InputShares, input_shares));
                    info!("Calculated inputs for client {}", client_id);

                    true
                }
                Some((InputType::Empty, _)) => {
                    // update status before sending via network!
                    status.insert(client_id, (InputType::RandomShares, shares.clone()));
                    info!("Stored local mask shares for client {}", client_id);

                    send_over_network = true;
                    true
                }
                None => {
                    unknown_client = true;
                    false
                }
            }
        });

        if unknown_client {
            return Err(AvssInputError::InvalidInput(
                "Unknown client {client_id}".to_string(),
            ));
        }
        if invalid_length {
            return Err(AvssInputError::InvalidInput(
                "masked_inputs length does not match shares length".to_string(),
            ));
        }
        if already_rand_shares {
            return Err(AvssInputError::Duplicate(format!(
                "random shares already obtained for client {}",
                client_id
            )));
        }
        if send_over_network {
            let mut payload = Vec::new();
            shares.serialize_compressed(&mut payload)?;
            let msg = AvssInputMessage::new(self.id, payload);
            let wrapped = AvssWrappedMessage::Input(msg);
            let bytes = bincode::serialize(&wrapped)?;
            net.send_to_client(client_id, &bytes).await?;
            info!("Server {} sent MaskShare to client {}", self.id, client_id);
        }

        Ok(())
    }

    /// Called by each server: receives masked m_i, subtracts r_i to get share of m_i.
    pub async fn input_handler(
        &mut self,
        sender_id: PartyId,
        payload: Vec<u8>,
    ) -> Result<(), AvssInputError> {
        info!(
            "Server {} received MaskedInput from client {}",
            self.id, sender_id
        );

        if payload.len() < 8 {
            return Err(AvssInputError::InvalidInput(
                "Payload too short".to_string(),
            ));
        }
        let declared_len = u64::from_le_bytes(payload[..8].try_into().unwrap());
        if declared_len > MAX_INPUT_ELEMENTS {
            return Err(AvssInputError::InvalidInput(
                "Declared input length exceeds maximum".to_string(),
            ));
        }
        let masked_inputs: Vec<F> =
            ark_serialize::CanonicalDeserialize::deserialize_compressed(payload.as_slice())?;

        let mut unknown_client = false;
        let mut already_masked_inputs = false;
        let mut invalid_length = false;

        self.status_sender
            .send_if_modified(|status| match status.get(&sender_id) {
                Some((InputType::MaskedInputs | InputType::InputShares, _)) => {
                    already_masked_inputs = true;
                    false
                }
                Some((InputType::RandomShares, random_shares)) => {
                    if masked_inputs.len() != random_shares.len() {
                        invalid_length = true;
                        return false;
                    }
                    let input_shares = calculate_input_shares(&masked_inputs, random_shares);

                    status.insert(sender_id, (InputType::InputShares, input_shares));
                    info!(
                        "Server {} stored input shares from client {}",
                        self.id, sender_id
                    );

                    true
                }
                Some((InputType::Empty, _)) => {
                    // Store masked inputs as FeldmanShamirShare with dummy degree/commitments
                    // so they fit in the HashMap. We use a sentinel representation.
                    let masked_as_shares: Vec<FeldmanShamirShare<F, G>> = masked_inputs
                        .iter()
                        .map(|m| {
                            FeldmanShamirShare::new(
                                *m,
                                0,                         // dummy id
                                0,                         // dummy degree
                                vec![G::generator() * *m], // dummy commitment
                            )
                            .unwrap()
                        })
                        .collect();
                    status.insert(sender_id, (InputType::MaskedInputs, masked_as_shares));
                    info!(
                        "Server {} stored masked inputs from client {}",
                        self.id, sender_id
                    );

                    true
                }
                None => {
                    unknown_client = true;
                    false
                }
            });

        if invalid_length {
            return Err(AvssInputError::InvalidInput(format!(
                "masked_inputs length {} does not match expected {}",
                masked_inputs.len(),
                sender_id
            )));
        }
        if already_masked_inputs {
            return Err(AvssInputError::Duplicate(format!(
                "Server {} already received masked inputs from {}",
                self.id, sender_id
            )));
        }
        if unknown_client {
            return Err(AvssInputError::InvalidInput(
                "Unknown client {client_id}".to_string(),
            ));
        }

        Ok(())
    }

    pub async fn wait_for_all_inputs(
        &mut self,
        duration: Duration,
    ) -> Result<HashMap<ClientId, Vec<FeldmanShamirShare<F, G>>>, AvssInputError> {
        let status_future = self.status_receiver.wait_for(|statuses| {
            statuses
                .iter()
                .map(|(_, (status, _))| status)
                .all(|status| *status == InputType::InputShares)
        });

        match timeout(duration, status_future).await {
            Err(elapsed_err) => Err(AvssInputError::Timeout(elapsed_err)),
            Ok(Err(recv_err)) => Err(AvssInputError::WaitingError(recv_err)),
            Ok(Ok(statuses)) => {
                info!("Server {} has inputs from all clients", self.id);
                let input_shares = statuses
                    .iter()
                    .map(|(id, (_, shares))| (*id, shares.clone()))
                    .collect();

                Ok(input_shares)
            }
        }
    }
}

struct AvssInputClientData<F: FftField, R: RBC, G: CurveGroup<ScalarField = F>> {
    pub rbc: R,
    pub inputs: Vec<F>,
    pub rbc_done: bool,
    pub received_shares: HashMap<usize, Vec<FeldmanShamirShare<F, G>>>,
}

pub struct AvssInputClient<F: FftField, R: RBC, G: CurveGroup<ScalarField = F>> {
    pub client_id: usize,
    pub n: usize,
    pub t: usize,
    pub instance_id: u32,
    client_data: Arc<Mutex<AvssInputClientData<F, R, G>>>,
}

// implement manually because derive(Clone) requires R: Clone, which is not needed at all
impl<F: FftField, R: RBC, G: CurveGroup<ScalarField = F>> Clone for AvssInputClient<F, R, G> {
    fn clone(&self) -> Self {
        Self {
            client_id: self.client_id,
            n: self.n,
            t: self.t,
            instance_id: self.instance_id,
            client_data: Arc::clone(&self.client_data),
        }
    }
}

impl<F: FftField, R: RBC<Id = AvssSessionId>, G: CurveGroup<ScalarField = F>>
    AvssInputClient<F, R, G>
{
    pub fn new(
        id: usize,
        n: usize,
        t: usize,
        instance_id: u32,
        inputs: Vec<F>,
    ) -> Result<Self, AvssInputError> {
        let (rbc_sender, _) = tokio::sync::mpsc::channel(200);
        let rbc = R::new(
            id,
            n,
            t,
            t + 1,
            rbc_sender,
            Arc::new(AvssWrappedMessage::rbc_wrap),
        )?;
        Ok(Self {
            client_id: id,
            n,
            t,
            instance_id,
            client_data: Arc::new(Mutex::new(AvssInputClientData::<F, R, G> {
                rbc,
                inputs,
                received_shares: HashMap::new(),
                rbc_done: false,
            })),
        })
    }

    pub async fn init_handler<N: Network + Send + Sync>(
        &self,
        msg: AvssInputMessage,
        net: Arc<N>,
    ) -> Result<(), AvssInputError> {
        if msg.payload.len() < 8 {
            return Err(AvssInputError::InvalidInput(
                "Payload too short".to_string(),
            ));
        }
        let declared_len = u64::from_le_bytes(msg.payload[..8].try_into().unwrap()) as usize;
        let input_len = self.client_data.lock().await.inputs.len();
        if declared_len != input_len {
            return Err(AvssInputError::InvalidInput(
                "Mismatch in input and share length".to_string(),
            ));
        }

        let shares: Vec<FeldmanShamirShare<F, G>> = {
            let mut r = msg.payload.as_slice();
            deser_bounded_feldman_vec::<F, G>(&mut r, input_len, self.t + 1)?
        };
        let mut d = self.client_data.lock().await;

        if shares.len() != input_len {
            return Err(AvssInputError::InvalidInput(
                "Mismatch in input and share length".to_string(),
            ));
        }

        // Verify Feldman commitments on received shares
        for share in &shares {
            if share.feldmanshare.degree != self.t {
                return Err(AvssInputError::InvalidInput(format!(
                    "Invalid share degree from server {}",
                    msg.sender_id
                )));
            }
            if !verify_feldman(share.clone()) {
                return Err(AvssInputError::VerificationFailed(format!(
                    "Feldman verification failed for share from server {}",
                    msg.sender_id
                )));
            }
        }

        // happens if less than `n` messages were sufficient for reconstruction
        if d.rbc_done {
            return Ok(());
        }

        if d.received_shares.contains_key(&msg.sender_id) {
            return Err(AvssInputError::Duplicate(format!(
                "Already random shares received from {}",
                msg.sender_id
            )));
        }
        if d.received_shares.len() == self.n {
            return Err(AvssInputError::InvalidInput(format!(
                "Cannot receive from more than {} parties",
                self.n
            )));
        }
        d.received_shares.insert(msg.sender_id, shares.clone());
        info!(
            "Client {} received MaskShare from server {}",
            self.client_id, msg.sender_id
        );

        if d.received_shares.len() >= self.t + 1 {
            let mut masks = vec![];
            let mut output = vec![];
            let mut consistent_groups: Vec<Option<Vec<FeldmanShamirShare<F, G>>>> =
                vec![None; input_len];

            for i in 0..input_len {
                let mut by_commitment: HashMap<Vec<u8>, Vec<FeldmanShamirShare<F, G>>> =
                    HashMap::new();
                for (_, shares) in d.received_shares.iter() {
                    let share = &shares[i];
                    let mut key = Vec::new();
                    share.commitments.serialize_compressed(&mut key)?;
                    by_commitment.entry(key).or_default().push(share.clone());
                }
                match by_commitment.into_values().find(|g| g.len() >= self.t + 1) {
                    Some(group) => consistent_groups[i] = Some(group),
                    None => return Ok(()), // not enough consistent shares yet, wait for more
                }
            }

            info!("Received enough consistent shares to reconstruct");
            for group in consistent_groups.into_iter().flatten() {
                let secret = FeldmanShamirShare::<F, G>::recover_secret(&group, self.n, self.t)?;
                masks.push(secret.1);
            }

            for (i, r) in masks.iter().enumerate() {
                output.push(d.inputs[i] + r);
            }

            let mut payload = Vec::new();
            output.serialize_compressed(&mut payload)?;
            // Broadcast to servers
            let sessionid = AvssSessionId::new(
                ProtocolType::Input,
                AvssSessionId::pack_slot(
                    0, // subprotocol ID not needed because only called once
                    self.client_id as u8,
                    0,
                ),
                self.instance_id,
            );

            d.rbc.init(payload, sessionid, net).await?;
            d.rbc_done = true;
            info!(
                "Client {} initialized broadcasting of masked input to all servers",
                self.client_id
            );
        }

        Ok(())
    }

    /// Process any message (used for both client and server roles).
    pub async fn process<N: Network + Send + Sync>(
        &mut self,
        msg: AvssInputMessage,
        net: Arc<N>,
    ) -> Result<(), AvssInputError> {
        self.init_handler(msg, net).await
    }
}
