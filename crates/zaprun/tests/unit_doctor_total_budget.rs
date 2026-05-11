use std::time::{Duration, Instant};
use tempfile::tempdir;
use zaprun::doctor::{run_doctor, DoctorOptions};

/// Doctor's *total* wall-clock budget (across all probes) MUST be bounded around 10s.
/// A real Docker presence probe is fast; the reachability probe (configured with a
/// blackhole) bounds the slow path.  The whole sequence must finish within 11s.
#[test]
fn doctor_total_budget_under_11s() {
    let dir = tempdir().unwrap();
    let opts = DoctorOptions {
        backend: "docker".into(),
        image: None,
        probe_target: Some("http://10.255.255.1:65000".into()),
        output: dir.path().to_path_buf(),
    };

    let start = Instant::now();
    let _ = run_doctor(&opts);
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(11),
        "doctor took {elapsed:?}, must be bounded under ~10s"
    );
}
