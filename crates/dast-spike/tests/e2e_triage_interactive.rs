use assert_cmd::Command;

#[test]
fn triage_creates_suppression_with_default_90day_expiry_non_interactive_flags() {
    let temp = tempfile::tempdir().unwrap();
    let baseline = temp.path().join(".dast-spike/baseline.json");
    let mut cmd = Command::cargo_bin("dast-spike").unwrap();
    cmd.env("DAST_SPIKE_TEST_DATE", "2026-05-06")
        .arg("triage")
        .arg("10015")
        .arg("--baseline")
        .arg(&baseline)
        .arg("--scope-url-pattern")
        .arg("^/health$")
        .arg("--justification")
        .arg("Health endpoint; no data")
        .arg("--author")
        .arg("security@example.test");
    cmd.assert().success();

    let text = std::fs::read_to_string(baseline).unwrap();
    assert!(text.contains("\"expires_at\": \"2026-08-04\""));
}
