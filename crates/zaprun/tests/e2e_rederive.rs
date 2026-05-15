use assert_cmd::Command;
use predicates::str::contains;
use serde_json::Value as JsonValue;
use std::fs;
use std::path::Path;

#[test]
fn rederive_no_drift_no_pr() {
    let temp = tempfile::tempdir().unwrap();
    write_target_fixture(temp.path());
    init_target(temp.path());

    let mut cmd = Command::cargo_bin("zaprun").unwrap();
    cmd.arg("rederive").arg("--target-dir").arg(temp.path());
    cmd.assert()
        .success()
        .stderr(contains("zaprun: no drift detected"));
}

#[test]
fn rederive_max_one_pr() {
    let temp = tempfile::tempdir().unwrap();
    write_target_fixture(temp.path());
    init_target(temp.path());

    fs::write(
        temp.path().join("docs/slo/design/fixture-threat-model.md"),
        "# Threat model\n\nThe web surface includes CWE-79, CWE-89, and CWE-918.\n",
    )
    .unwrap();

    let manifest_path = temp.path().join(".zaprun/manifest.json");
    let mut manifest: JsonValue =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["image_digest"] = JsonValue::String(
        "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string(),
    );
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let fake_bin = temp.path().join("bin");
    fs::create_dir_all(&fake_bin).unwrap();
    let gh_log = temp.path().join("gh.log");
    let gh = fake_bin.join("gh");
    fs::write(
        &gh,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nexit 0\n",
            gh_log.display()
        ),
    )
    .unwrap();
    make_executable(&gh);

    let old_path = std::env::var("PATH").unwrap_or_default();
    let mut cmd = Command::cargo_bin("zaprun").unwrap();
    cmd.env("PATH", format!("{}:{old_path}", fake_bin.display()))
        .arg("rederive")
        .arg("--target-dir")
        .arg(temp.path());
    cmd.assert().success();

    let gh_calls = fs::read_to_string(&gh_log).unwrap();
    let pr_create_count = gh_calls
        .lines()
        .filter(|line| line.contains("pr create"))
        .count();
    assert_eq!(pr_create_count, 1, "{gh_calls}");
    assert!(
        gh_calls.contains("[zaprun] re-derive DAST config"),
        "{gh_calls}"
    );
    assert!(!gh_calls.contains("--repo"), "{gh_calls}");
    assert!(!gh_calls.contains("--auto"), "{gh_calls}");
    assert!(!gh_calls.contains("--squash"), "{gh_calls}");
    assert!(!gh_calls.contains("--rebase"), "{gh_calls}");
}

fn init_target(root: &Path) {
    let mut cmd = Command::cargo_bin("zaprun").unwrap();
    cmd.arg("init").arg("--target-dir").arg(root);
    cmd.assert().success();
}

fn write_target_fixture(root: &Path) {
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    fs::write(
        root.join("openapi.yaml"),
        "openapi: 3.0.0\ninfo:\n  title: Fixture\n  version: 1.0.0\npaths:\n  /health:\n    get:\n      responses:\n        '200':\n          description: ok\n",
    )
    .unwrap();
    let design = root.join("docs/slo/design");
    fs::create_dir_all(&design).unwrap();
    fs::write(
        design.join("fixture-threat-model.md"),
        "# Threat model\n\nThe web surface includes CWE-79 and CWE-89.\n",
    )
    .unwrap();
}

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) {}
