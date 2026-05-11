use std::time::{Duration, Instant};
use zaprun::doctor::probe_target_reachability;

/// Reachability probe MUST time out within ~5s + epsilon when the target is a
/// blackhole address.  This protects the doctor's per-probe resource bound.
#[test]
fn probe_target_reachability_respects_5s_per_probe_budget() {
    let start = Instant::now();
    // 10.255.255.1 is reserved unallocated space inside RFC1918 -- packets are
    // dropped on most systems, producing the slow-path we want to time-bound.
    let outcome = probe_target_reachability("http://10.255.255.1:65000", Duration::from_secs(5));
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(7),
        "probe took {elapsed:?}, must be bounded under 5s + epsilon"
    );
    assert!(
        !outcome.reachable,
        "blackhole address must report reachable=false"
    );
}
