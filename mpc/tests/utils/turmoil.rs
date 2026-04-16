use std::time::Duration;

use stoffelmpc_network::{fake_network::FakeNetworkConfig, turmoil_network::TurmoilInnerNetwork};
use stoffelnet::network_utils::ClientId;
use turmoil::{Builder, Sim};

pub fn add_driver(sim: &mut Sim, secs: u64) {
    sim.client("driver", async move {
        tokio::time::sleep(Duration::from_secs(secs)).await;
        Ok::<(), Box<dyn std::error::Error>>(())
    });
}

pub fn collect_results(
    mut sim: Sim,
    rx_done: std::sync::mpsc::Receiver<Result<(), String>>,
    expected: usize,
) {
    sim.run().unwrap();
    let results: Vec<_> = std::iter::from_fn(|| rx_done.try_recv().ok()).collect();
    assert_eq!(
        results.len(),
        expected,
        "not all nodes reported: got {}/{}",
        results.len(),
        expected
    );
    for r in results {
        assert!(r.is_ok(), "node failed: {}", r.unwrap_err());
    }
}

pub fn turmoil_setup(
    n_nodes: usize,
    client_ids: Vec<ClientId>,
    latency: Option<(u64, u64)>,
) -> (turmoil::Sim<'static>, TurmoilInnerNetwork) {
    let sim = if let Some((min, max)) = latency {
        Builder::new()
            .min_message_latency(Duration::from_millis(min))
            .max_message_latency(Duration::from_millis(max))
            .simulation_duration(Duration::from_mins(5))
            .build()
    } else {
        Builder::new()
            .simulation_duration(Duration::from_mins(5))
            .build()
    };

    let inner = TurmoilInnerNetwork::new(
        n_nodes,
        if client_ids.is_empty() {
            None
        } else {
            Some(client_ids)
        },
        FakeNetworkConfig::new(100),
        7000,
        8000,
    );

    (sim, inner)
}
