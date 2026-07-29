use crate::utils::test_utils::fan_in_inboxes;
use ark_ff::FftField;
use ark_std::test_rng;
use std::sync::Arc;
use stoffelcrypto::common::SecretSharingScheme;
use stoffelcrypto::honeybadger::fpmul::rand_bit::RandBit;
use stoffelcrypto::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelcrypto::honeybadger::WrappedMessage;
use stoffelmpc_network::fake_network::{FakeNetwork, SenderId};
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinSet;

/// Creates dummy inputs for the RandBit protocol.
///
/// # Returns
///
/// - A vector of shares of `a` for each party.
/// - A vector of degree-2t zero-sharings for each party (feeds MulPub's reveal of `a^2`).
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

        // Degree-2t sharing of 0, masking the local product before reveal.
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
    F: FftField,
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
