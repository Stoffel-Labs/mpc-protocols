use ark_ff::{FftField, PrimeField};
use ark_std::rand::Rng;
use ark_std::test_rng;
use std::sync::Arc;
use stoffelmpc_mpc::common::types::fixed::SecretFixedPoint;
use stoffelmpc_mpc::common::{SecretSharingScheme, RBC};
use stoffelmpc_mpc::honeybadger::fpmul::fpmul::FPMulNode;
use stoffelmpc_mpc::honeybadger::fpmul::rand_bit::RandBit;
use stoffelmpc_mpc::honeybadger::mul::MulError;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::triple_gen::ShamirBeaverTriple;
use stoffelmpc_mpc::honeybadger::{SessionId, WrappedMessage};
use stoffelmpc_network::fake_network::FakeNetwork;
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinSet;
use tracing::{error, warn};

pub async fn spawn_receiver_tasks<F, R>(
    num_parties: usize,
    mut receivers: Vec<Receiver<Vec<u8>>>,
    nodes: Vec<FPMulNode<F, R>>,
    network: Arc<FakeNetwork>,
) -> JoinSet<()>
where
    F: FftField + PrimeField,
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
                        node.trunc_node.process(msg, net.clone()).await.unwrap();
                    }
                    WrappedMessage::Rbc(msg) => {
                        match node.trunc_node.rbc.process(msg, net.clone()).await {
                            Ok(()) => {}
                            Err(e) => warn!("Error processing RBC message: {:?}", e),
                        }
                    }
                    WrappedMessage::Mul(msg) => match node.mult_node.process(msg).await {
                        Ok(()) => {}
                        Err(MulError::WaitForOk) => warn!("Waiting for OK in Mult"),
                        Err(e) => panic!("Error processing Mul message: {:?}", e),
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

pub async fn initialize_nodes<F, R>(
    num_parties: usize,
    a_shares: Vec<SecretFixedPoint<F, RobustShare<F>>>,
    b_shares: Vec<SecretFixedPoint<F, RobustShare<F>>>,
    mult_triples: Vec<ShamirBeaverTriple<F>>,
    r_bit_shares: Vec<Vec<RobustShare<F>>>,
    r_int_shares: Vec<RobustShare<F>>,
    session_id: SessionId,
    nodes: Vec<FPMulNode<F, R>>,
    network: Arc<FakeNetwork>,
) -> JoinSet<()>
where
    F: FftField + PrimeField,
    R: RBC + Clone + 'static,
{
    let mut init_set = JoinSet::new();
    for i in 0..num_parties {
        let mut node = nodes[i].clone();
        let net = network.clone();
        let a = a_shares[i].clone();
        let b = b_shares[i].clone();
        let r_bit_shares = r_bit_shares[i].clone();
        let r_int_share = r_int_shares[i].clone();
        let triple = mult_triples[i].clone();

        init_set.spawn(async move {
            node.init(a, b, triple, r_bit_shares, r_int_share, session_id, net)
                .await
                .unwrap();
        });
    }
    init_set
}

pub fn generate_random_input<F, S>(
    num_parties: usize,
    threshold: usize,
    k: usize,
) -> (u32, Vec<SecretFixedPoint<F, S>>)
where
    F: FftField + PrimeField,
    S: SecretSharingScheme<F, SecretType = F>,
{
    let mut rng = test_rng();
    let rand_int = rng.gen_range(0..(1 << k));
    let rand_int_field = F::from(rand_int as u32);
    let shares = S::compute_shares(rand_int_field, num_parties, threshold, None, &mut rng).unwrap();
    let fp_shares = shares
        .into_iter()
        .map(|s| SecretFixedPoint::new(s))
        .collect();
    (rand_int, fp_shares)
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
