use ark_ff::PrimeField;
use ark_std::rand::Rng;
use ark_std::test_rng;
use std::sync::Arc;
use stoffelmpc_mpc::common::SecretSharingScheme;
use stoffelmpc_mpc::honeybadger::fpmul::prandbitd::PRandBitDNode;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::WrappedMessage;
use stoffelmpc_network::fake_network::FakeNetwork;
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinSet;

pub async fn spawn_receiver_tasks<F, G>(
    num_parties: usize,
    mut receivers: Vec<Receiver<Vec<u8>>>,
    nodes: Vec<PRandBitDNode<F, G>>,
    network: Arc<FakeNetwork>,
) -> JoinSet<()>
where
    F: PrimeField,
    G: PrimeField,
{
    let mut set = JoinSet::new();
    for i in 0..num_parties {
        let mut receiver = receivers.remove(0);
        let mut node = nodes[i].clone();
        let net = network.clone();

        set.spawn(async move {
            while let Some(bytes) = receiver.recv().await {
                let wrapped: WrappedMessage = bincode::deserialize(&bytes).unwrap();
                match wrapped {
                    WrappedMessage::PRandBit(msg) => {
                        node.process(msg, net.clone()).await.unwrap();
                    }
                    WrappedMessage::BatchRecon(msg) => {
                        node.batch_recon.process(msg, net.clone()).await.unwrap();
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
