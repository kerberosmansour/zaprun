use assert_cmd::Command;

#[test]
fn scanner_failure_isolated_when_extra_scanner_missing() {
    let temp = tempfile::tempdir().unwrap();
    let spec = temp.path().join("openapi.yaml");
    std::fs::write(
        &spec,
        r#"
openapi: "3.1.0"
servers:
  - url: http://127.0.0.1:3001
paths: {}
"#,
    )
    .unwrap();
    let mut cmd = Command::cargo_bin("dast-spike").unwrap();
    cmd.env("DAST_SPIKE_FAKE_SCAN", "1")
        .arg("scan")
        .arg("--target")
        .arg(&spec)
        .arg("--image")
        .arg("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .arg("--output")
        .arg(temp.path().join("output"))
        .arg("--enable-scanner")
        .arg("nuclei");
    cmd.assert().success();
    let summary = std::fs::read_to_string(temp.path().join("output/run-summary.json")).unwrap();
    assert!(summary.contains("\"scanner\": \"zap\""));
    assert!(summary.contains("\"scanner\": \"nuclei\""));
}
