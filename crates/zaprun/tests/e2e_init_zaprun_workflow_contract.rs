use assert_cmd::Command;
use predicates::str::contains;
use regex::Regex;
use serde_json::Value as JsonValue;
use serde_yaml_ng::Value as YamlValue;
use std::fs;
use std::path::Path;

#[test]
fn init_zaprun_workflow_contract() {
    let temp = tempfile::tempdir().unwrap();
    write_target_fixture(temp.path(), true, true);

    let mut cmd = Command::cargo_bin("zaprun").unwrap();
    cmd.arg("init")
        .arg("--target-dir")
        .arg(temp.path())
        .arg("--deployment-target")
        .arg("https://staging.example.test");
    cmd.assert().success();

    let workflow = fs::read_to_string(temp.path().join(".github/workflows/dast.yml")).unwrap();
    assert_workflow_safety_contract(&workflow);
    assert!(workflow.contains("zaprun api"), "{workflow}");
    assert!(workflow.contains("--target https://staging.example.test"));
    assert!(workflow.contains("openapi.yaml"));

    let policy = fs::read_to_string(temp.path().join(".zaprun/policy-pr.yml")).unwrap();
    assert!(policy.contains("passiveScan-config"));
    assert!(temp.path().join(".zaprun/rules.tsv").exists());
    assert!(temp.path().join(".zaprun/baseline.json").exists());
}

#[test]
fn init_openapi_uses_api() {
    let temp = tempfile::tempdir().unwrap();
    write_target_fixture(temp.path(), true, true);

    let mut cmd = Command::cargo_bin("zaprun").unwrap();
    cmd.arg("init").arg("--target-dir").arg(temp.path());
    cmd.assert().success();

    let workflow = fs::read_to_string(temp.path().join(".github/workflows/dast.yml")).unwrap();
    assert!(workflow.contains("zaprun api"), "{workflow}");
    assert!(!workflow.contains("zaprun scan"), "{workflow}");
}

#[test]
fn init_web_uses_scan() {
    let temp = tempfile::tempdir().unwrap();
    write_target_fixture(temp.path(), false, true);

    let mut cmd = Command::cargo_bin("zaprun").unwrap();
    cmd.arg("init")
        .arg("--target-dir")
        .arg(temp.path())
        .arg("--deployment-target")
        .arg("https://web.example.test");
    cmd.assert().success();

    let workflow = fs::read_to_string(temp.path().join(".github/workflows/dast.yml")).unwrap();
    assert!(
        workflow.contains("zaprun scan https://web.example.test"),
        "{workflow}"
    );
    assert!(workflow.contains("--profile web-pr"), "{workflow}");
    assert!(!workflow.contains("zaprun api"), "{workflow}");
}

#[test]
fn init_missing_threat_model_falls_back_safely() {
    let temp = tempfile::tempdir().unwrap();
    write_target_fixture(temp.path(), false, false);

    let mut cmd = Command::cargo_bin("zaprun").unwrap();
    cmd.arg("init").arg("--target-dir").arg(temp.path());
    cmd.assert().success().stderr(contains("default-fallback"));

    let manifest: JsonValue = serde_json::from_str(
        &fs::read_to_string(temp.path().join(".zaprun/manifest.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(manifest["selection_strategy"], "default-fallback");
    assert_eq!(manifest["cwes_claimed"].as_array().unwrap().len(), 0);
    assert!(manifest.get("generated_by_zaprun_version").is_some());
    assert!(manifest.get("generated_by_dast_spike_version").is_none());
}

fn write_target_fixture(root: &Path, openapi: bool, threat_model: bool) {
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    if openapi {
        fs::write(
            root.join("openapi.yaml"),
            "openapi: 3.0.0\ninfo:\n  title: Fixture\n  version: 1.0.0\npaths:\n  /health:\n    get:\n      responses:\n        '200':\n          description: ok\n",
        )
        .unwrap();
    }
    if threat_model {
        let design = root.join("docs/slo/design");
        fs::create_dir_all(&design).unwrap();
        fs::write(
            design.join("fixture-threat-model.md"),
            "# Threat model\n\nThe web surface includes CWE-79 and CWE-89.\n\n<!-- CWE-22 should be ignored later -->\n",
        )
        .unwrap();
    }
}

fn assert_workflow_safety_contract(text: &str) {
    assert!(text.contains("pull_request:"));
    assert!(!text.contains("pull_request_target"));
    assert!(!text.contains("issues: write"));
    assert!(!text.contains("secrets."));
    assert!(!text.contains("zaproxy/action-baseline"));
    assert!(!text.contains("zaproxy/action-full-scan"));
    assert!(!text.contains("zaproxy/action-api-scan"));
    assert!(!text.contains("zap-api-scan.py"));
    assert!(!text.contains("zap-baseline.py"));
    assert!(!text.contains("zap-full-scan.py"));
    assert!(text.contains("--user 1000:1000"));
    assert!(text.contains(" zaprun "));

    let yaml: YamlValue = serde_yaml_ng::from_str(text).unwrap();
    let permissions = yaml.get("permissions").expect("permissions");
    assert_eq!(permissions.as_mapping().unwrap().len(), 0);

    let action_re = Regex::new(r"uses:\s+[^@\s]+@[0-9a-f]{40}").unwrap();
    for line in text
        .lines()
        .filter(|line| line.trim_start().starts_with("uses:"))
    {
        assert!(action_re.is_match(line.trim()), "{line}");
    }

    let image_re = Regex::new(r"ghcr\.io/kerberosmansour/zaprun@sha256:[0-9a-f]{64}").unwrap();
    assert!(image_re.is_match(text), "{text}");
}
