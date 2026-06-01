use crate::utils::test_utils::fan_in_inboxes;
use ark_ff::FftField;
use ark_std::test_rng;
use std::sync::Arc;
use std::time::Duration;
use stoffelmpc_mpc::common::SecretSharingScheme;
use stoffelmpc_mpc::honeybadger::fpmul::rand_bit::RandBit;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::{SessionId, WrappedMessage};
use stoffelmpc_network::fake_network::{FakeNetwork, SenderId};
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinSet;

/// Creates inputs for the RandBit protocol: random `a` shares and degree-2t zero shares.
pub fn create_rand_bit_input<F>(
    n_parties: usize,
    threshold: usize,
    batch_size: usize,
) -> (Vec<Vec<RobustShare<F>>>, Vec<Vec<RobustShare<F>>>)
where
    F: FftField,
{
    let mut a_shares = vec![vec![]; n_parties];
    let mut zero_shares = vec![vec![]; n_parties];

    let mut rng = test_rng();

    for _ in 0..batch_size {
        // Computation of the value a.
        let a = F::rand(&mut rng);
        let shares_a =
            RobustShare::<F>::compute_shares(a, n_parties, threshold, None, &mut rng).unwrap();

        let shares_zero =
            RobustShare::<F>::compute_shares(F::zero(), n_parties, 2 * threshold, None, &mut rng)
                .unwrap();
        for party_id in 0..n_parties {
            a_shares[party_id].push(shares_a[party_id].clone());
            zero_shares[party_id].push(shares_zero[party_id].clone());
        }
    }
    (a_shares, zero_shares)
}

/// Spawn receiver tasks for the RandBit protocol.
pub async fn spawn_receiver_tasks<F>(
    num_parties: usize,
    mut receivers: Vec<Vec<Receiver<Vec<u8>>>>,
    nodes: Vec<RandBit<F>>,
    network: Vec<Arc<FakeNetwork>>,
) -> JoinSet<()>
where
    F: FftField + 'static,
{
    let mut set = JoinSet::new();

    for i in 0..num_parties {
        let mut node = nodes[i].clone();
        let receiver = receivers.remove(0);
        let net = network[i].clone();
        let inbox: Vec<(SenderId, Receiver<Vec<u8>>)> = receiver
            .into_iter()
            .enumerate()
            .map(|(i, r)| (SenderId::Node(i), r))
            .collect();
        let mut merge_rx = fan_in_inboxes(inbox);

        set.spawn(async move {
            while let Some((_, bytes)) = merge_rx.recv().await {
                let wrapped: WrappedMessage = bincode::deserialize(&bytes).unwrap();
                match wrapped {
                    WrappedMessage::BatchRecon(msg) => {
                        let _ = node.mul_pub.batch_recon.process(msg, net.clone()).await;
                        node.mul_pub.drain_batch_recon_output().await.unwrap();
                    }
                    _ => {}
                }
            }
        });
    }
    set
}

pub async fn initialize_nodes<F>(
    num_parties: usize,
    a_shares: Vec<Vec<RobustShare<F>>>,
    zero_shares: Vec<Vec<RobustShare<F>>>,
    session_id: SessionId,
    nodes: Vec<RandBit<F>>,
    network: Arc<FakeNetwork>,
    duration: Duration,
) -> JoinSet<()>
where
    F: FftField + 'static,
{
    let mut init_set = JoinSet::new();
    for i in 0..num_parties {
        let mut node = nodes[i].clone();
        let net = network.clone();
        let a = a_shares[i].clone();
        let zeros = zero_shares[i].clone();

        init_set.spawn(async move {
            node.init(a, zeros, session_id, duration, net)
                .await
                .unwrap();
        });
    }
    init_set
}
