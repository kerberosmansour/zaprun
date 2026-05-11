use assert_cmd::Command;

#[test]
fn idempotent_scan_byte_identical_summary() {
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

    for _ in 0..2 {
        let mut cmd = Command::cargo_bin("dast-spike").unwrap();
        cmd.env("DAST_SPIKE_FAKE_SCAN", "1")
            .env("DAST_SPIKE_TEST_TIME", "fixed")
            .arg("scan")
            .arg("--target")
            .arg(&spec)
            .arg("--image")
            .arg("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .arg("--output")
            .arg(temp.path().join("output"));
        cmd.assert().success();
    }
    let first = std::fs::read(temp.path().join("output/run-summary.json")).unwrap();
    let second = std::fs::read(temp.path().join("output/run-summary.json")).unwrap();
    assert_eq!(first, second);
}

#[test]
fn symlink_traversal_attack_refused() {
    let temp = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("/etc", temp.path().join(".dast-spike")).unwrap();
        let err = dast_spike_rules::safe_write(
            temp.path(),
            std::path::Path::new(".dast-spike/manifest.json"),
            b"{}",
        )
        .unwrap_err();
        assert!(err.to_string().contains("symlink"));
    }
}

#[test]
#[ignore = "requires a locally running secure_smoke_service and Docker image publish"]
fn smoke_service_scan_zero_high_findings() {
    let mut cmd = Command::cargo_bin("dast-spike").unwrap();
    cmd.arg("scan")
        .arg("--target")
        .arg("../SunLitSecurityLibraries/crates/secure_smoke_service/openapi.yaml");
    cmd.assert().success();
}
