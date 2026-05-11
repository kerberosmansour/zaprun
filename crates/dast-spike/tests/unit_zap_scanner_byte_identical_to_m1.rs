use assert_cmd::Command;

#[test]
fn zap_fake_scan_report_is_stable() {
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
    let output = temp.path().join("output");
    for _ in 0..2 {
        let mut cmd = Command::cargo_bin("dast-spike").unwrap();
        cmd.env("DAST_SPIKE_FAKE_SCAN", "1")
            .arg("scan")
            .arg("--target")
            .arg(&spec)
            .arg("--image")
            .arg("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .arg("--output")
            .arg(&output);
        cmd.assert().success();
    }
    let first = std::fs::read(output.join("zap-report.json")).unwrap();
    let second = std::fs::read(output.join("zap-report.json")).unwrap();
    assert_eq!(first, second);
}
