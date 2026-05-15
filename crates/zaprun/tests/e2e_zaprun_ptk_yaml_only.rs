use assert_cmd::Command;
use predicates::str::contains;
use tempfile::tempdir;

fn cmd() -> Command {
    Command::cargo_bin("zaprun").expect("zaprun binary built")
}

#[test]
fn e2e_ptk_dry_run_writes_phase1_plan_and_run_json() {
    let dir = tempdir().unwrap();
    cmd()
        .arg("ptk")
        .arg("http://localhost:4000")
        .arg("--dry-run")
        .arg("--output")
        .arg(dir.path())
        .assert()
        .success();

    let plan = dir.path().join("plan.yaml");
    let run = dir.path().join("run.json");
    assert!(plan.exists(), "plan.yaml must be written");
    assert!(run.exists(), "run.json must be written");

    let yaml = std::fs::read_to_string(&plan).expect("read plan");
    for expected in [
        "ptk.automatedScanning.enabled: true",
        "ptk.scanrules.SAST.enabled: true",
        "ptk.scanrules.IAST.enabled: true",
        "ptk.scanrules.DAST.enabled: true",
        "type: spiderClient",
        "browserId: firefox-headless",
        "numberOfBrowsers: 1",
    ] {
        assert!(yaml.contains(expected), "missing `{expected}` in:\n{yaml}");
    }
    assert!(
        !yaml.contains("type: addOns"),
        "PTK CLI must not install Marketplace add-ons at runtime"
    );

    let run_json = std::fs::read_to_string(&run).expect("read run.json");
    let parsed: serde_json::Value = serde_json::from_str(&run_json).expect("parse");
    assert_eq!(parsed["schema_version"], "1.0");
    assert!(parsed["api_key"].as_str().map(|s| s.len()) == Some(64));
}

#[test]
fn e2e_ptk_refuses_non_http_targets() {
    let dir = tempdir().unwrap();
    cmd()
        .arg("ptk")
        .arg("file:///tmp/app.html")
        .arg("--dry-run")
        .arg("--output")
        .arg(dir.path())
        .assert()
        .failure()
        .stderr(contains("target_scheme_unsupported"));
}
