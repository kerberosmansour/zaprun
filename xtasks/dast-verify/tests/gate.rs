use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn fixture(path: &str) -> PathBuf {
    repo_root().join(path)
}

fn temp_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("zaprun-dast-verify-{name}-{nanos}"));
    fs::create_dir_all(&path).unwrap();
    path
}

fn run_gate(candidate: &Path, output: &Path, extra: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_dast-verify"));
    cmd.arg("gate")
        .arg("--candidate")
        .arg(candidate)
        .arg("--fixtures")
        .arg(fixture("tests/synthetic-mocks"))
        .arg("--output")
        .arg(output);
    for arg in extra {
        cmd.arg(arg);
    }
    cmd.output().unwrap()
}

#[test]
fn generic_rule_passes_synthetic_corpus() {
    let temp = temp_dir("generic-pass");
    let output = temp.join("gate-result.json");
    let result = run_gate(
        &fixture("tests/synthetic-mocks/rules/generic-xss.js"),
        &output,
        &[],
    );

    assert!(result.status.success(), "{result:?}");
    let report = fs::read_to_string(output).unwrap();
    assert!(
        report.contains(r#""decision":"generic-accepted""#),
        "{report}"
    );
    assert!(report.contains(r#""generic_eligible":true"#), "{report}");
}

#[test]
fn rule_with_polyglot_eval_is_rejected() {
    let temp = temp_dir("polyglot");
    let output = temp.join("gate-result.json");
    let result = run_gate(
        &fixture("tests/synthetic-mocks/rules/bad-polyglot.js"),
        &output,
        &[],
    );

    assert_eq!(result.status.code(), Some(1), "{result:?}");
    let report = fs::read_to_string(output).unwrap();
    assert!(
        report.contains("forbidden-token: Polyglot.eval"),
        "{report}"
    );
}

#[test]
fn rule_missing_metadata_is_rejected() {
    let temp = temp_dir("missing-metadata");
    let output = temp.join("gate-result.json");
    let result = run_gate(
        &fixture("tests/synthetic-mocks/rules/missing-metadata.js"),
        &output,
        &[],
    );

    assert_eq!(result.status.code(), Some(1), "{result:?}");
    let report = fs::read_to_string(output).unwrap();
    assert!(report.contains("missing-metadata: cwe"), "{report}");
}

#[test]
fn app_specific_literal_is_rejected_for_generic_gate() {
    let temp = temp_dir("app-literal");
    let output = temp.join("gate-result.json");
    let result = run_gate(
        &fixture("tests/synthetic-mocks/rules/app-specific.js"),
        &output,
        &[],
    );

    assert_eq!(result.status.code(), Some(1), "{result:?}");
    let report = fs::read_to_string(output).unwrap();
    assert!(report.contains("app-specific-literal"), "{report}");
}

#[test]
fn target_owned_rule_can_use_app_literal_but_writes_to_target_output() {
    let temp = temp_dir("target-owned");
    let output = temp.join("gate-result.json");
    let scripts = temp.join(".zaprun/scripts");
    let scripts_arg = scripts.to_string_lossy().to_string();
    let result = run_gate(
        &fixture("tests/synthetic-mocks/rules/app-specific.js"),
        &output,
        &["--target-owned", "--target-output", &scripts_arg],
    );

    assert!(result.status.success(), "{result:?}");
    let report = fs::read_to_string(output).unwrap();
    assert!(
        report.contains(r#""decision":"target-owned-accepted""#),
        "{report}"
    );
    assert!(scripts.join("app-specific.js").is_file(), "{report}");
}
