use crate::utils::test_utils::fan_in_inboxes;
use ark_ff::FftField;
use ark_std::test_rng;
use std::sync::Arc;
use std::time::Duration;
use stoffelmpc_mpc::common::{SecretSharingScheme, RBC};
use stoffelmpc_mpc::honeybadger::fpmul::rand_bit::RandBit;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::triple_gen::ShamirBeaverTriple;
use stoffelmpc_mpc::honeybadger::{SessionId, WrappedMessage};
use stoffelmpc_network::fake_network::{FakeNetwork, SenderId};
use tokio::sync::mpsc::Receiver;
use tokio::sync::Mutex;
use tokio::task::JoinSet;

/// Creates dummy inputs for the RandBit protocol.
///
/// # Returns
///
/// - A vector of shares of `a` for each party.
/// - A vector of Beaver triples for each party.
pub fn create_rand_bit_input<F>(
    n_parties: usize,
    threshold: usize,
    batch_size: usize,
) -> (Vec<Vec<RobustShare<F>>>, Vec<Vec<ShamirBeaverTriple<F>>>)
where
    F: FftField,
{
    let mut a_shares = vec![vec![]; n_parties];
    let mut mult_triples = vec![vec![]; n_parties];

    let mut rng = test_rng();

    for _ in 0..batch_size {
        // Computation of the value a.
        let a = F::rand(&mut rng);
        let shares_a =
            RobustShare::<F>::compute_shares(a, n_parties, threshold, None, &mut rng).unwrap();

        // Computation of multiplication triple.
        let x = F::rand(&mut rng);
        let y = F::rand(&mut rng);
        let mult = x * y;
        let x_shares =
            RobustShare::<F>::compute_shares(x, n_parties, threshold, None, &mut rng).unwrap();
        let y_shares =
            RobustShare::<F>::compute_shares(y, n_parties, threshold, None, &mut rng).unwrap();
        let mult_shares =
            RobustShare::<F>::compute_shares(mult, n_parties, threshold, None, &mut rng).unwrap();
        for party_id in 0..n_parties {
            a_shares[party_id].push(shares_a[party_id].clone());
            let mult_triple = ShamirBeaverTriple::new(
                x_shares[party_id].clone(),
                y_shares[party_id].clone(),
                mult_shares[party_id].clone(),
            );
            mult_triples[party_id].push(mult_triple);
        }
    }
    (a_shares, mult_triples)
}

/// Spawn receiver tasks for the RandBit protocol.
pub async fn spawn_receiver_tasks<F, R>(
    num_parties: usize,
    mut receivers: Vec<Vec<Receiver<Vec<u8>>>>,
    nodes: Vec<RandBit<F, R>>,
    network: Vec<Arc<FakeNetwork>>,
) -> JoinSet<()>
where
    F: FftField,
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
                    // WrappedMessage::RandBit(msg) => {
                    //     let _ = node.process(msg).await;
                    // }
                    WrappedMessage::BatchRecon(msg) => {
                        if msg.session_id.sub_id() == 0 {
                            let _ = node.batch_recon.process(msg, net.clone()).await;
                        } else {
                            let _ = node.mult_node.batch_recon.process(msg, net.clone()).await;
                        }
                    }
                    // WrappedMessage::Mul(msg) => {
                    //     let _ = node.mult_node.process(msg).await;
                    // }
                    _ => {}
                }
            }
        });
    }
    set
}

pub async fn initialize_nodes<F, R>(
    num_parties: usize,
    a_shares: Vec<Vec<RobustShare<F>>>,
    mult_triples: Vec<Vec<ShamirBeaverTriple<F>>>,
    session_id: SessionId,
    nodes: Vec<RandBit<F, R>>,
    network: Arc<FakeNetwork>,
    duration: Duration,
) -> JoinSet<()>
where
    F: FftField,
    R: RBC<Id = SessionId> + Clone + 'static,
{
    let mut init_set = JoinSet::new();
    for i in 0..num_parties {
        let mut node = nodes[i].clone();
        let net = network.clone();
        let a = a_shares[i].clone();
        let triples = mult_triples[i].clone();

        init_set.spawn(async move {
            node.init(a, triples, session_id, duration, net)
                .await
                .unwrap();
        });
    }
    init_set
}
