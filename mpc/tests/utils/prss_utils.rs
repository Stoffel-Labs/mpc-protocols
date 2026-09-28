use ark_std::rand::Rng;
use stoffelcrypto::honeybadger::prss::prss::held_ranks;
use stoffelcrypto::honeybadger::prss::PRSS_KEY_LEN;

/// Deals every PRSS key centrally and hands each party the keys for the sets it is outside of.
///
/// Lives in the test utilities rather than the library because it is a total break of the privacy
/// guarantee: the caller sees every `r_T`, and so could predict every value the pool will ever
/// produce. Real nodes establish keys with `HoneyBadgerMPCNode::setup_prss_keys`, which derives
/// them from one distributed RISS run instead.
pub fn deal_keys<R: Rng>(n: usize, t: usize, rng: &mut R) -> Vec<Vec<(usize, [u8; PRSS_KEY_LEN])>> {
    let n_tsets = num_integer::binomial(n as u64, t as u64) as usize;
    let all: Vec<[u8; PRSS_KEY_LEN]> = (0..n_tsets)
        .map(|_| {
            let mut k = [0u8; PRSS_KEY_LEN];
            rng.fill_bytes(&mut k);
            k
        })
        .collect();

    (0..n)
        .map(|id| {
            held_ranks(n, t, id)
                .into_iter()
                .map(|rank| (rank, all[rank]))
                .collect()
        })
        .collect()
}
