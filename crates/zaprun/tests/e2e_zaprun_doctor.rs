use assert_cmd::Command;
use predicates::str::contains;
use tempfile::tempdir;

fn cmd() -> Command {
    Command::cargo_bin("zaprun").expect("zaprun binary built")
}

#[test]
fn e2e_doctor_writes_capabilities_json_to_tempdir() {
    let dir = tempdir().unwrap();
    let out = dir.path().join("run");
    let assert = cmd().arg("doctor").arg("--output").arg(&out).assert();

    let exit = assert
        .get_output()
        .status
        .code()
        .expect("exit code present");
    // Either pass (0) or tool-error (2) is acceptable here -- environment-dependent.
    assert!(
        matches!(exit, 0 | 2),
        "expected exit 0 or 2 for doctor in unknown env, got {exit}"
    );

    let path = out.join("capabilities.json");
    let raw = std::fs::read_to_string(&path).expect("capabilities.json must exist");
    let parsed: serde_json::Value = serde_json::from_str(&raw).expect("valid JSON");
    assert_eq!(parsed["schema_version"], "1.0");
    assert!(parsed.get("backend").is_some());
    assert!(parsed.get("docker").is_some());
    assert!(parsed.get("image").is_some());
}

#[test]
fn e2e_doctor_refuses_floating_tag_image() {
    let dir = tempdir().unwrap();
    let out = dir.path().join("run");
    let assert = cmd()
        .arg("doctor")
        .arg("--image")
        .arg("owasp/zap2docker:stable")
        .arg("--output")
        .arg(&out)
        .assert()
        .failure();

    let code = assert
        .get_output()
        .status
        .code()
        .expect("exit code present");
    assert_eq!(code, 2, "floating-tag image must exit 2");

    // capabilities.json may or may not be written depending on probe order,
    // but if present it MUST report image.pinned=false.
    let path = out.join("capabilities.json");
    if path.exists() {
        let raw = std::fs::read_to_string(&path).expect("readable");
        let parsed: serde_json::Value = serde_json::from_str(&raw).expect("valid JSON");
        assert_eq!(parsed["image"]["pinned"], false);
    }
}

#[test]
fn e2e_doctor_help_lists_full_subcommand_surface() {
    cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("scan"))
        .stdout(contains("api"))
        .stdout(contains("doctor"))
        .stdout(contains("observe"))
        .stdout(contains("plan"))
        .stdout(contains("explain"))
        .stdout(contains("calibrate"));
}

#[test]
fn e2e_subcommand_stub_for_unimplemented_milestone_exits_2() {
    // `api`, `observe`, `calibrate`, `explain` remain stubs until M4-M5.  Use
    // `explain` which has a stable surface and no side effects.
    let dir = tempdir().unwrap();
    let assert = cmd().arg("explain").arg(dir.path()).assert().failure();
    assert_eq!(assert.get_output().status.code(), Some(2));
}
