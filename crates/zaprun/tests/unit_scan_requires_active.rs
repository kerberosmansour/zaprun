use assert_cmd::Command;
use predicates::str::contains;
use tempfile::tempdir;

fn cmd() -> Command {
    Command::cargo_bin("zaprun").expect("zaprun binary built")
}

#[test]
fn scan_without_active_or_passive_flag_exits_2() {
    let dir = tempdir().unwrap();
    let assert = cmd()
        .arg("scan")
        .arg("http://127.0.0.1:65534")
        .arg("--output")
        .arg(dir.path())
        .assert()
        .failure();
    assert_eq!(assert.get_output().status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&assert.get_output().stderr).to_string();
    assert!(
        stderr.contains("--active is required") || stderr.contains("active_required"),
        "expected --active-required guidance, got {stderr}"
    );
}

#[test]
fn scan_help_advertises_active_flag() {
    cmd()
        .arg("scan")
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("--active"))
        .stdout(contains("--profile"))
        .stdout(contains("--browser-id"));
}
