use utils::test_utils::{construct_e2e_input, setup_tracing, test_setup};

pub mod utils;

#[test]
fn generate_shares() {
    setup_tracing();
    let n_parties = 10;
    let threshold = 3;
    let session_id = 1111;

    let (params, network, receivers) = test_setup(n_parties, threshold, session_id);
}
