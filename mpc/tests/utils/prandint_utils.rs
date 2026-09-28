use crate::utils::test_utils::fan_in_inboxes;
use ark_ff::PrimeField;
use std::sync::Arc;
use stoffelcrypto::common::RBC;
use stoffelcrypto::honeybadger::fpmul::prandint::PRandIntNode;
use stoffelcrypto::honeybadger::{SessionId, WrappedMessage};
use stoffelmpc_network::fake_network::{FakeNetwork, SenderId};
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinSet;

pub async fn spawn_receiver_tasks<G, R>(
    num_parties: usize,
    mut receivers: Vec<Vec<Receiver<Vec<u8>>>>,
    nodes: Vec<PRandIntNode<G, R>>,
    network: Vec<Arc<FakeNetwork>>,
) -> JoinSet<()>
where
    G: PrimeField,
    R: RBC<Id = SessionId> + Clone + Send + Sync + 'static,
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
                    WrappedMessage::PRandInt(msg) => {
                        node.process(msg).await.unwrap();
                    }
                    WrappedMessage::Rbc(msg) => {
                        node.rbc.process(msg, net.clone()).await.unwrap();
                        node.drain_rbc_output(net.clone()).await.unwrap();
                    }
                    _ => {}
                }
            }
        });
    }
    set
}
