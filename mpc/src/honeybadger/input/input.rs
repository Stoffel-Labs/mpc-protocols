use crate::common::{SecretSharingScheme, RBC};
use crate::honeybadger::input::InputMessage;
use crate::honeybadger::input::{InputError, InputMessageType};
use crate::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use crate::honeybadger::{ProtocolType, SessionId, WrappedMessage};
use ark_ff::FftField;
use ark_serialize::CanonicalSerialize;
use std::collections::HashMap;
use std::sync::Arc;
use stoffelnet::network_utils::{ClientId, Network};
use tokio::{time::{timeout, Duration}, sync::{watch::{channel, Sender, Receiver}, Mutex}};
use tracing::info;

/// In the beginning of an MPC calculation, each node has to obtain a share of all clients' inputs.
/// This happens via the mechanism described in Section 4.1 in the paper: given one random sharing
/// per client input,
///   1. at least `2t+1` nodes send their random share to the respective client,
///   2. once `2t+1` shares received, the client reconstructs the random values per input and
///      broadcasts the input plus the random value to all nodes via RBC,
///   3. each server receives that masked value and subtracts their respective random share to
///      obtain a share of the input
/// 
///   InputServer                                            InputClient     
///                                                                          
/// ┌──────────────────────────┐ one random share per input                  
/// │         init             │ ─────────────────────────► ┌──────────────────┐
/// │                          │                            │ init_handler     │
/// │store local random shares;│                            │                  │
/// │if input_handler not      │                            │if broadcast has  │
/// │called, send them to the  │                            │not happened yet  │
/// │client (1);               │                            │and reconstruction│
/// │if input_handler called,  │                            │succeeds, then    │
/// │calculate input shares (3)│                            │broadcast masked  │
/// │                          │                            │inputs (2)        │
/// └──────────────────────────┘                            │                  │
///      ┌─────────────────────┐                            │                  │
///      │ input_handler       │   broadcast masked inputs  │                  │
///      │                     │  ◄───────────────────────  └──────────────────┘
///      │store masked inputs; │                     
///      │if init called,      │
///      │calculate input      │                         
///      │shares (3)           │
///      └─────────────────────┘                                          
///                   
///
/// Synchronization between the accesses to random shares or masked inputs and the notification
/// that all expected input shares have been received is implemented using a `tokio::sync::watch`
/// channel.
///
/// Each client with an input is expected to send it in time, otherwise the computation cannot
/// proceed.
///
/// The sending of random shares to clients does not use session IDs, since it only occurs once
/// before the computation has started. The RBC call to send masked inputs uses the session ID
///   `[caller=Input, sub=client ID, round=0, instance=instance ID]`

#[derive(PartialEq, Clone, Debug)]
enum InputType {
    Empty,
    RandomShares,
    MaskedInputs,
    InputShares
}

#[derive(Clone, Debug)]
pub struct InputServer<F: FftField, R: RBC> {
    pub id: usize,
    pub n: usize,
    pub rbc: R,
    status_sender: Sender<HashMap<ClientId, (InputType, Vec<RobustShare<F>>)>>,
    status_receiver: Receiver<HashMap<ClientId, (InputType, Vec<RobustShare<F>>)>>
}

fn calculate_input_shares<F: FftField>(masked_inputs: &[RobustShare<F>], random_shares: &Vec<RobustShare<F>>) -> Vec<RobustShare<F>> {
    masked_inputs.iter().zip(random_shares).map(|(masked_input, random_share)| {
        // masked inputs become input shares
        RobustShare::new(
            masked_input.share[0] - random_share.share[0],
            random_share.id,
            random_share.degree
        )
    }).collect()
}

impl<F: FftField, R: RBC> InputServer<F, R> {
    pub fn new(id: usize, n: usize, t: usize, input_ids: Vec<ClientId>) -> Result<Self, InputError> {
        let rbc = R::new(id, n, t, t + 1)?;
        let (status_sender, status_receiver) = channel(input_ids.into_iter().map(|id| (id, (InputType::Empty, vec![]))).collect());

        Ok(Self {
            id,
            n,
            rbc,
            status_sender,
            status_receiver
        })
    }

    /// Called by each server to send its share of `r_i` to the client.
    pub async fn init<N: Network>(
        &mut self,
        client_id: usize,
        shares: Vec<RobustShare<F>>,
        input_len: usize,
        net: Arc<N>,
    ) -> Result<(), InputError> {
        if shares.len() != input_len {
            return Err(InputError::InvalidInput(
                "Incorrect number of shares".to_string(),
            ));
        }

        let mut send_over_network = false;
        let mut already_rand_shares = false;
        let mut unknown_client = false;

        self.status_sender.send_if_modified(|status| {
            match status.get(&client_id) {
                Some((InputType::RandomShares | InputType::InputShares, _)) => {
                    already_rand_shares = true;
                    false
                }
                Some((InputType::MaskedInputs, masked_inputs)) => {
                    let input_shares = calculate_input_shares(masked_inputs, &shares);

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
            return Err(InputError::InvalidInput(
                "Unknown client {client_id}".to_string(),
            ));
        }
        if already_rand_shares {
            return Err(InputError::Duplicate(format!(
                "random shares already obtained for client {}",
                client_id
            )));
        }
        if send_over_network {
            let mut payload = Vec::new();
            shares.serialize_compressed(&mut payload)?;
            let msg = InputMessage::new(self.id, InputMessageType::MaskShare, payload);
            let wrapped = WrappedMessage::Input(msg);
            let bytes = bincode::serialize(&wrapped)?;
            net.send_to_client(client_id, &bytes).await?;
            info!("Server {} sent MaskShare to client {}", self.id, client_id);
        }

        Ok(())
    }

    /// Called by each server: receives masked m_i, subtracts r_i to get share of m_i.
    pub async fn input_handler(&mut self, msg: InputMessage) -> Result<(), InputError> {
        //handler for server
        //accepts the m+r values and then subtracts the r' local share from it to get m' shares
        // and stores it
        info!("Server {} received MaskedInput from client {}", self.id, msg.sender_id);

        let masked_inputs_as_shares: Vec<RobustShare<F>> = {
            let masked_inputs: Vec<F> =
                ark_serialize::CanonicalDeserialize::deserialize_compressed(msg.payload.as_slice())?;
            masked_inputs.iter()
                         .map(|m| RobustShare::new(*m, 0, 0))
                         .collect()
        };

        let mut unknown_client = false;
        let mut already_masked_inputs = false;

        self.status_sender.send_if_modified(|status| {
            match status.get(&msg.sender_id) {
                Some((InputType::MaskedInputs | InputType::InputShares, _)) => {
                    already_masked_inputs = true;
                    false
                }
                Some((InputType::RandomShares, random_shares)) => {
                    let input_shares = calculate_input_shares(&masked_inputs_as_shares, random_shares);

                    status.insert(msg.sender_id, (InputType::InputShares, input_shares));
                    info!(
                        "Server {} stored input shares from client {}",
                        self.id,
                        msg.sender_id
                    );

                    true
                }
                Some((InputType::Empty, _)) => {
                    status.insert(msg.sender_id, (InputType::MaskedInputs, masked_inputs_as_shares));
                    info!(
                        "Server {} stored masked inputs from client {}",
                        self.id,
                        msg.sender_id
                    );

                    true
                }
                None => {
                    unknown_client = true;
                    false
                }
            }
        });

        if already_masked_inputs {
            return Err(InputError::Duplicate(format!(
                "Server {} already received masked inputs from {}",
                self.id,
                msg.sender_id
            )));
        }
        if unknown_client {
            return Err(InputError::InvalidInput(
                "Unknown client {client_id}".to_string(),
            ));
        }

        Ok(())
    }

    /// Process any message (used for both client and server roles).
    pub async fn process(&mut self, msg: InputMessage) -> Result<(), InputError> {
        match msg.msg_type {
            InputMessageType::MaskShare => {
                Err(InputError::InvalidInput(
                    "Incorrect message type".to_string(),
                ))
            }
            InputMessageType::MaskedInput => self.input_handler(msg).await,
        }
    }

    pub async fn wait_for_all_inputs(&mut self, duration: Duration) -> Result<HashMap<ClientId, Vec<RobustShare<F>>>, InputError> {
        let status_future = self.status_receiver.wait_for(|statuses| {
            statuses
                .iter()
                .map(|(_, (status, _))| status).all(|status| *status == InputType::InputShares)
        });

        match timeout(duration, status_future).await {
            Err(elapsed_err) => {
                Err(InputError::Timeout(elapsed_err))
            }
            Ok(Err(recv_err)) => {
                Err(InputError::WaitingError(recv_err))
            }
            Ok(Ok(statuses)) => {
                info!("Server {} has inputs from all clients", self.id);
                let input_shares = statuses.iter().map(|(id, (_, shares))| (*id, shares.clone())).collect();

                Ok(input_shares)
            }
        }
    }
}

struct InputClientData<F: FftField, R: RBC> {
    pub rbc: R,
    pub inputs: Vec<F>,
    pub rbc_done: bool,
    pub received_shares: HashMap<usize, Vec<RobustShare<F>>>,
}

pub struct InputClient<F: FftField, R: RBC> {
    pub client_id: usize,
    pub n: usize,
    pub t: usize,
    pub instance_id: u64,
    client_data: Arc<Mutex<InputClientData<F, R>>>
}

impl<F: FftField, R: RBC> InputClient<F, R> {
    pub fn new(
        id: usize,
        n: usize,
        t: usize,
        instance_id: u64,
        inputs: Vec<F>,
    ) -> Result<Self, InputError> {
        let rbc = R::new(id, n, t, t + 1)?;
        Ok(Self {
            client_id: id,
            n,
            t,
            instance_id,
            client_data: Arc::new(Mutex::new(InputClientData::<F, R> {
                rbc,
                inputs,
                received_shares: HashMap::new(),
                rbc_done: false
            }))
        })
    }

    pub async fn init_handler<N: Network + Send + Sync>(
        &self,
        msg: InputMessage,
        net: Arc<N>,
    ) -> Result<(), InputError> {
        let shares: Vec<RobustShare<F>> =
            ark_serialize::CanonicalDeserialize::deserialize_compressed(msg.payload.as_slice())?;

        let mut d = self.client_data.lock().await;

        let input_len = d.inputs.len();

        if shares.len() != input_len {
            return Err(InputError::InvalidInput(
                "Mismatch in input and share length".to_string(),
            ));
        }

        // happens if less than `n` messages were sufficient for reconstruction
        if d.rbc_done {
            return Ok(());
        }

        if d.received_shares.contains_key(&msg.sender_id) {
            return Err(InputError::Duplicate(format!(
                "Already random shares received from {}",
                msg.sender_id
            )));
        }
        if d.received_shares.len() == self.n {
            return Err(InputError::InvalidInput(format!(
                "Cannot receive from more than {} parties", self.n)
            ));
        }
        d.received_shares.insert(msg.sender_id, shares.clone());
        info!("Client {} received MaskShare from server {}", self.client_id, msg.sender_id);

        let mut r_shares = vec![vec![]; input_len];
        let mut masks = vec![];
        let mut output = vec![];
        if d.received_shares.len() >= 2 * self.t + 1 {
            info!("Received enough shares to reconstruct");
            for (_, r_share) in d.received_shares.iter() {
                for i in 0..input_len {
                    r_shares[i].push(r_share[i].clone());
                }
            }
            for recon in r_shares {
                let secret = RobustShare::recover_secret(&recon, self.n)?;
                masks.push(secret.1);
            }

            for (i, r) in masks.iter().enumerate() {
                output.push(d.inputs[i] + r);
            }

            let mut payload = Vec::new();
            output.serialize_compressed(&mut payload)?;
            let msg = InputMessage::new(self.client_id, InputMessageType::MaskedInput, payload);
            //wrap it in protocol wide enum
            let wrapped = WrappedMessage::Input(msg);
            let bytes = bincode::serialize(&wrapped)?;
            //Broadcast to servers
            let sessionid = SessionId::new(
                ProtocolType::Input,
                self.client_id as u8,
                0,
                self.instance_id,
            );

            d.rbc.init(bytes, sessionid, net).await?;
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
        msg: InputMessage,
        net: Arc<N>,
    ) -> Result<(), InputError> {
        match msg.msg_type {
            InputMessageType::MaskedInput => {
                Err(InputError::InvalidInput(
                    "Incorrect message type".to_string(),
                ))
            }
            InputMessageType::MaskShare => { self.init_handler(msg, net).await },
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_std::test_rng;
    use ark_bls12_381::Fr;
    use crate::{
        common::{rbc::rbc::Avid, SecretSharingScheme},
        honeybadger::{
            robust_interpolate::robust_interpolate::RobustShare,
            WrappedMessage,
        },
    };
    use tokio::time::{sleep, Duration};
    use stoffelmpc_network::fake_network::{FakeNetwork, FakeNetworkConfig};

    /// `2t+1` nodes send random shares to the client, which reconstructs the random value and
    /// broadcasts the masked input. Some node, which is not one of the `2t+1` has not sent its
    /// random share and receives the masked input before even having called `InputServer::init`.
    #[tokio::test]
    async fn test_init_before_input_handler() {
        let n = 4;
        let t = 1;
        let clientid = 100;
        let rand_secret = Fr::from(1);
        let input = Fr::from(10);
    
        let config = FakeNetworkConfig::new(500);
        let (network, mut receivers, mut client_recv_map) = FakeNetwork::new(n, Some(vec![clientid]), config);
        let mut client_recv = client_recv_map.remove(&clientid).unwrap();
        let network = Arc::new(network);

        let mut rng = test_rng();
        let rand_shares = RobustShare::compute_shares(rand_secret, n, t, None, &mut rng).unwrap();

        let mut client =
            InputClient::<Fr, Avid>::new(clientid, n, t, 111, vec![input].clone()).unwrap();
        let mut nodes: Vec<_> = (0..n).map(|i| { InputServer::<Fr, Avid>::new(i, n, t, vec![clientid]).unwrap() }).collect();

        // all but one node call init
        for i in 0..nodes.len()-1 {
            assert!(nodes[i]
                .init(clientid, vec![rand_shares[i].clone()], 1, network.clone())
                .await
                .is_ok());

            // check that nodes that called init have random shares now
            let status = nodes[i].status_receiver.borrow();
            let client_status = status.get(&clientid);
            assert!(client_status.is_some() && client_status.unwrap().0 == InputType::RandomShares);
        }

        // check that node that did not call init has no data
        {
           let status = nodes[3].status_receiver.borrow();
           let client_status = status.get(&clientid);
           assert!(client_status.is_some() && client_status.unwrap().0 == InputType::Empty);
        }

        // receive random shares to send masked input
        for _ in 0..3 {
            let received = client_recv.recv().await.unwrap();
            if let Ok(WrappedMessage::Input(msg)) = bincode::deserialize(&received) {
                assert!(client.process(msg, network.clone()).await.is_ok());
            } else { panic!(); }
        }

        // run RBC for masked input and eventually process it
        for node in nodes.iter_mut() {
            let network = network.clone();
            let mut node = node.clone();
            let mut receiver = receivers.remove(0);

            tokio::spawn(async move {
                while let Some(raw_msg) = receiver.recv().await {
                    let wrapped: WrappedMessage = bincode::deserialize(&raw_msg).expect("deserialization error");

                    let _ = match wrapped {
                        WrappedMessage::Rbc(rbc_msg) =>
                            node.rbc.process(rbc_msg, network.clone()).await,
                        WrappedMessage::Input(input_msg) => {
                            let _ = node.process(input_msg).await;
                            return;
                        }
                        _ => { panic!(); }
                    };
                }
            });
        }

        // wait for client to reconstruct and broadcast masked input
        sleep(Duration::from_millis(200)).await;

        // check that node that did not call init has received masked input
        {
           let status = nodes[3].status_receiver.borrow();
           let client_status = status.get(&clientid);
           assert!(client_status.is_some() && client_status.unwrap().0 == InputType::MaskedInputs);
        }
        nodes[3].init(clientid, vec![rand_shares[3].clone()], 1, network.clone()).await.unwrap();
        // check that node that called init last now also has input share
        {
           let status = nodes[3].status_receiver.borrow();
           let client_status = status.get(&clientid);
           assert!(client_status.is_some() && client_status.unwrap().0 == InputType::InputShares);
        }
    
        let mut recovered_shares = vec![];
        for node in &mut nodes {
            let shares = node.wait_for_all_inputs(Duration::from_millis(1)).await.expect("input error");
            let client_shares = shares.get(&clientid).unwrap();
            recovered_shares.push(client_shares[0].clone());
        }
    
        let (_, r) = RobustShare::recover_secret(&recovered_shares, n).unwrap();
        assert_eq!(r, input);
    }
}
