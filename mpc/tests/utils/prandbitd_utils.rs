use crate::utils::test_utils::fan_in_inboxes;
use ark_ff::PrimeField;
use ark_std::rand::Rng;
use ark_std::test_rng;
use std::sync::Arc;
use stoffelcrypto::common::SecretSharingScheme;
use stoffelcrypto::honeybadger::fpmul::prandbitd::PRandBitDNode;
use stoffelcrypto::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelcrypto::honeybadger::WrappedMessage;
use stoffelmpc_network::fake_network::{FakeNetwork, SenderId};
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinSet;

pub async fn spawn_receiver_tasks<F, G>(
    num_parties: usize,
    mut receivers: Vec<Vec<Receiver<Vec<u8>>>>,
    nodes: Vec<PRandBitDNode<F, G>>,
    network: Vec<Arc<FakeNetwork>>,
) -> JoinSet<()>
where
    F: PrimeField,
    G: PrimeField,
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
                    WrappedMessage::PRandBitD(msg) => {
                        node.process(msg, net.clone()).await.unwrap();
                    }
                    WrappedMessage::BatchRecon(msg) => {
                        node.batch_recon.process(msg, net.clone()).await.unwrap();
                        node.drain_batch_recon_output().await.unwrap();
                    }
                    _ => {}
                }
            }
        });
    }
    set
}

pub fn generate_small_field_bits<F>(
    num_parties: usize,
    threshold: usize,
    batch_size: usize,
) -> Vec<Vec<RobustShare<F>>>
where
    F: PrimeField,
{
    let mut small_field_bits: Vec<Vec<RobustShare<F>>> = vec![vec![]; num_parties];
    let mut rng = test_rng();
    for _ in 0..batch_size {
        let random_bit = F::from(rng.gen::<u32>() & 1);
        let shares_bit =
            RobustShare::compute_shares(random_bit, num_parties, threshold, None, &mut rng)
                .unwrap();
        for party_id in 0..num_parties {
            small_field_bits[party_id].push(shares_bit[party_id].clone());
        }
    }
    small_field_bits
}
