use ark_ff::PrimeField;
use ark_std::rand::Rng;
use ark_std::test_rng;
use num_integer::binomial;
use std::sync::Arc;
use stoffelmpc_mpc::common::{SecretSharingScheme, RBC};
use stoffelmpc_mpc::honeybadger::fpmul::truncpr::TruncPrNode;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::WrappedMessage;
use stoffelmpc_network::fake_network::FakeNetwork;
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinSet;
use tracing::{error, warn};

pub async fn spawn_receiver_tasks<F, R>(
    num_parties: usize,
    mut receivers: Vec<Receiver<Vec<u8>>>,
    nodes: Vec<TruncPrNode<F, R>>,
    network: Arc<FakeNetwork>,
) -> JoinSet<()>
where
    F: PrimeField,
    R: RBC + Clone + 'static,
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
                    WrappedMessage::Trunc(msg) => {
                        node.process(msg, net.clone()).await.unwrap();
                    }
                    WrappedMessage::Rbc(msg) => match node.rbc.process(msg, net.clone()).await {
                        Ok(()) => {}
                        Err(e) => warn!("Error processing RBC message: {:?}", e),
                    },
                    message => {
                        error!("Unexpected message type: {:?}", message)
                    }
                }
            }
        });
    }
    set
}

/// Generates shares of m random bits.
pub fn generate_random_shared_bits<F>(
    num_parties: usize,
    threshold: usize,
    m: usize,
) -> Vec<Vec<RobustShare<F>>>
where
    F: PrimeField,
{
    let mut shares_bit_all_parties: Vec<Vec<RobustShare<F>>> = vec![vec![]; num_parties];
    let mut rng = test_rng();
    for _ in 0..m {
        let random_bit = F::from(rng.gen::<u32>() & 1);
        let shares_bit =
            RobustShare::compute_shares(random_bit, num_parties, threshold, None, &mut rng)
                .unwrap();
        for party_id in 0..num_parties {
            shares_bit_all_parties[party_id].push(shares_bit[party_id].clone());
        }
    }
    shares_bit_all_parties
}

/// Generates shares of a random integer in the range [0, 2^{k + nu}), where nu = ceil(log(C(n, t)))
pub fn generate_random_shared_int<F>(
    num_parties: usize,
    threshold: usize,
    k: u64,
) -> Vec<RobustShare<F>>
where
    F: PrimeField,
{
    let nu = f64::log2(binomial(num_parties, threshold) as f64).ceil() as u64;
    let mut rng = test_rng();
    let rand_int = rng.gen_range(0..(1 << k + nu));
    let rand_int_field = F::from(rand_int as u64);
    let shares =
        RobustShare::compute_shares(rand_int_field, num_parties, threshold, None, &mut rng)
            .unwrap();
    shares
}

pub fn generate_input_integer<F>(
    num_parties: usize,
    threshold: usize,
    k: usize,
) -> (u32, Vec<RobustShare<F>>)
where
    F: PrimeField,
{
    let mut rng = test_rng();
    let rand_int = rng.gen_range(0..(1 << (k - 1) - 1));
    let rand_int_field = F::from(rand_int as u32);
    let shares =
        RobustShare::compute_shares(rand_int_field, num_parties, threshold, None, &mut rng)
            .unwrap();
    (rand_int, shares)
}
