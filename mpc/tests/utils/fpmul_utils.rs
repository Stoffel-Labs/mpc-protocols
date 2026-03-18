use crate::utils::test_utils::fan_in_inboxes;
use ark_ff::{FftField, PrimeField};
use ark_std::test_rng;
use std::sync::Arc;
use std::time::Duration;
use stoffelmpc_mpc::common::types::fixed::SecretFixedPoint;
use stoffelmpc_mpc::common::{ProtocolSessionId, SecretSharingScheme, RBC};
use stoffelmpc_mpc::honeybadger::fpmul::fpmul::FPMulNode;
use stoffelmpc_mpc::honeybadger::mul::MulError;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::triple_gen::ShamirBeaverTriple;
use stoffelmpc_mpc::honeybadger::{ProtocolType, SessionId, WrappedMessage};
use stoffelmpc_network::fake_network::{FakeNetwork, SenderId};
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinSet;
use tracing::{error, warn};

pub async fn spawn_receiver_tasks<F, R>(
    num_parties: usize,
    mut receivers: Vec<Vec<Receiver<Vec<u8>>>>,
    nodes: Vec<FPMulNode<F, R>>,
    network: Vec<Arc<FakeNetwork>>,
) -> JoinSet<()>
where
    F: FftField + PrimeField,
    R: RBC<Id = SessionId> + Clone + 'static,
{
    let mut set = JoinSet::new();
    for i in 0..num_parties {
        let mut node = nodes[i].clone();
        let receiver = receivers.remove(0);
        let net = network[i].clone();
        let inbox: Vec<(SenderId, Receiver<Vec<u8>>)> = receiver
            .into_iter() // MOVE the receivers
            .enumerate()
            .map(|(i, r)| (SenderId::Node(i), r))
            .collect();
        let mut merge_rx = fan_in_inboxes(inbox);

        set.spawn(async move {
            while let Some((_, bytes)) = merge_rx.recv().await {
                let wrapped: WrappedMessage = bincode::deserialize(&bytes).unwrap();
                match wrapped {
                    // WrappedMessage::Trunc(msg) => {
                    //     node.trunc_node.process(msg, net.clone()).await.unwrap();
                    // }
                    WrappedMessage::Rbc(msg) => match msg.session_id.calling_protocol() {
                        Some(ProtocolType::FpMul) => {
                            if msg.session_id.sub_id() == 2 {
                                node.mult_node.rbc.process(msg, net.clone()).await.unwrap();
                                node.mult_node.drain_rbc_output().await.unwrap();
                            } else if msg.session_id.sub_id() == 0 {
                                node.trunc_node.rbc.process(msg, net.clone()).await.unwrap();
                                node.trunc_node.drain_rbc_output().await.unwrap();
                            } else {
                                panic!("Unexpected sub-id in RBC message: {:?}", msg.session_id);
                            }
                        }
                        Some(other) => panic!("Unexpected protocol in RBC message: {:?}", other),
                        None => {
                            panic!("Received RBC message without calling protocol: {:?}", msg);
                        }
                    },
                    // WrappedMessage::Mul(msg) => match node.mult_node.process(msg).await {
                    //     Ok(()) => {}
                    //     Err(e) => panic!("Error processing Mul message: {:?}", e),
                    // },
                    message => {
                        error!("Unexpected message type: {:?}", message)
                    }
                }
            }
        });
    }
    set
}

pub fn generate_beaver_triple<F>(num_parties: usize, threshold: usize) -> Vec<ShamirBeaverTriple<F>>
where
    F: FftField + PrimeField,
{
    let mut rng = test_rng();

    // Computation of multiplication triple.
    let x = F::rand(&mut rng);
    let y = F::rand(&mut rng);
    let mult = x * y;
    let x_shares =
        RobustShare::<F>::compute_shares(x, num_parties, threshold, None, &mut rng).unwrap();
    let y_shares =
        RobustShare::<F>::compute_shares(y, num_parties, threshold, None, &mut rng).unwrap();
    let mult_shares =
        RobustShare::<F>::compute_shares(mult, num_parties, threshold, None, &mut rng).unwrap();
    (0..num_parties)
        .map(|node_id| {
            ShamirBeaverTriple::new(
                x_shares[node_id].clone(),
                y_shares[node_id].clone(),
                mult_shares[node_id].clone(),
            )
        })
        .collect()
}
