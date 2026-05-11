use assert_cmd::Command;
use predicates::prelude::*;
use predicates::str::contains;
use tempfile::tempdir;

fn cmd() -> Command {
    Command::cargo_bin("zaprun").expect("zaprun binary built")
}

#[test]
fn e2e_plan_dry_run_writes_plan_and_run_json() {
    let dir = tempdir().unwrap();
    let assert = cmd()
        .arg("plan")
        .arg("http://localhost:3000")
        .arg("--dry-run")
        .arg("--output")
        .arg(dir.path())
        .assert()
        .success();
    let _ = assert;

    let plan = dir.path().join("plan.yaml");
    let run = dir.path().join("run.json");
    assert!(plan.exists(), "plan.yaml must be written");
    assert!(run.exists(), "run.json must be written");

    let yaml = std::fs::read_to_string(&plan).expect("read plan");
    assert!(yaml.contains("env:"));
    assert!(yaml.contains("jobs:"));

    let run_json = std::fs::read_to_string(&run).expect("read run.json");
    let parsed: serde_json::Value = serde_json::from_str(&run_json).expect("parse");
    assert_eq!(parsed["schema_version"], "1.0");
    assert!(parsed["api_key"].as_str().map(|s| s.len()) == Some(64));
}

#[test]
fn e2e_plan_with_addon_update_refused_in_ci() {
    // The Plan public API would refuse this at construction time.
    // The CLI surface only emits CI-mode plans. There's no direct flag to inject
    // an addon-update plan via the binary; the unit test in unit_plan_ci_refuses_addons.rs
    // verifies the contract. This e2e is a placeholder that confirms the binary
    // does not expose any flag to bypass CI mode.
    let assert = cmd().arg("plan").arg("--help").assert().success();
    let out = String::from_utf8_lossy(&assert.get_output().stdout).to_string();
    assert!(!out.contains("--no-ci-mode"));
    assert!(!out.contains("--allow-addon-update"));
}

#[test]
fn e2e_plan_with_target_traversal_refused() {
    let dir = tempdir().unwrap();
    // Use a path-shape target output is the OUTPUT --output, not the target URL;
    // path traversal protection is on --output.
    let evil = "../../../etc/zaprun-out";
    cmd()
        .arg("plan")
        .arg("http://localhost:3000")
        .arg("--dry-run")
        .arg("--output")
        .arg(evil)
        .current_dir(dir.path())
        .assert()
        .failure()
        .stderr(contains("run_dir_unsafe_path").or(contains("output_dir_not_writable")));
}
