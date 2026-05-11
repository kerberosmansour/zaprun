use std::time::{Duration, Instant};
use zaprun::supervisor::{LogRingBuffer, Supervisor, SupervisorTimeout};

#[test]
fn ring_buffer_caps_at_10000_lines() {
    let mut buf = LogRingBuffer::new(10_000);
    for i in 0..12_000 {
        buf.push(format!("line {i}"));
    }
    let snapshot = buf.snapshot();
    assert_eq!(snapshot.len(), 10_000);
    // First retained line is the 2000th input (0-indexed: index 2000).
    assert_eq!(snapshot.first().expect("first"), "line 2000");
    assert_eq!(snapshot.last().expect("last"), "line 11999");
    assert!(buf.truncated(), "buffer must record truncation");
}

#[test]
fn ring_buffer_under_cap_not_truncated() {
    let mut buf = LogRingBuffer::new(100);
    for i in 0..10 {
        buf.push(format!("line {i}"));
    }
    assert_eq!(buf.snapshot().len(), 10);
    assert!(!buf.truncated());
}

#[test]
fn supervisor_startup_timeout_fires_within_budget() {
    let supervisor = Supervisor::new(Duration::from_millis(100), Duration::from_secs(60));
    let start = Instant::now();
    let result = supervisor.wait_ready_synthetic(|_| false); // never-ready predicate
    let elapsed = start.elapsed();
    assert!(matches!(result, Err(SupervisorTimeout::Startup)));
    assert!(
        elapsed < Duration::from_millis(500),
        "startup timeout exceeded budget: {elapsed:?}"
    );
}

#[test]
fn supervisor_scan_timeout_fires_within_budget() {
    let supervisor = Supervisor::new(Duration::from_secs(60), Duration::from_millis(100));
    let start = Instant::now();
    let result = supervisor.wait_complete_synthetic(|_| false); // never-done predicate
    let elapsed = start.elapsed();
    assert!(matches!(result, Err(SupervisorTimeout::Scan)));
    assert!(
        elapsed < Duration::from_millis(500),
        "scan timeout exceeded budget: {elapsed:?}"
    );
}
