use regex::Regex;
use serde_yaml_ng::Value;

#[test]
fn workflow_pull_request_only() {
    let (text, yaml) = workflow();
    assert!(text.contains("pull_request:"));
    assert!(!text.contains("pull_request_target"));
    assert!(yaml.as_mapping().is_some());
}

#[test]
fn workflow_zero_top_level_permissions() {
    let (_, yaml) = workflow();
    let permissions = yaml.get("permissions").expect("permissions");
    assert_eq!(permissions.as_mapping().unwrap().len(), 0);
}

#[test]
fn workflow_no_issues_write() {
    let (text, _) = workflow();
    assert!(!text.contains("issues: write"), "No issues: write");
}

#[test]
fn workflow_every_uses_is_40_char_sha() {
    let (text, _) = workflow();
    let re = Regex::new(r"uses:\s+[^@\s]+@[0-9a-f]{40}").unwrap();
    for line in text
        .lines()
        .filter(|line| line.trim_start().starts_with("uses:"))
    {
        assert!(
            re.is_match(line.trim()),
            "every uses must pin a 40-character SHA: {line}"
        );
    }
}

#[test]
fn workflow_image_digest_only() {
    let (text, _) = workflow();
    let re = Regex::new(r"ghcr\.io/kerberosmansour/zaprun@sha256:[0-9a-f]{64}").unwrap();
    assert!(
        re.is_match(&text),
        "image must be referenced by @sha256:<digest>"
    );
    assert!(!text.contains(":latest"));
    assert!(!text.contains(":stable"));
}

#[test]
fn workflow_user_1000_in_docker_run() {
    let (text, _) = workflow();
    assert!(text.contains("--user 1000:1000"));
}

#[test]
fn workflow_no_zaproxy_action_shims() {
    let (text, _) = workflow();
    assert!(!text.contains("zaproxy/action-baseline"));
    assert!(!text.contains("zaproxy/action-full-scan"));
    assert!(!text.contains("zaproxy/action-api-scan"));
}

#[test]
fn workflow_no_severity_or_config_flags() {
    let (text, _) = workflow();
    assert!(!text.contains("--severity"));
    assert!(!text.contains("--config"));
    assert!(!text.contains("--autofix"));
}

#[test]
fn workflow_no_secrets_in_pr_jobs() {
    let (text, _) = workflow();
    assert!(!text.contains("secrets."));
}

#[test]
fn workflow_concurrency_cancels() {
    let (_, yaml) = workflow();
    let cancel = yaml
        .get("concurrency")
        .and_then(|v| v.get("cancel-in-progress"))
        .and_then(Value::as_bool);
    assert_eq!(cancel, Some(true));
}

#[test]
fn workflow_timeout_minutes_le_30_pr() {
    let (_, yaml) = workflow();
    let jobs = yaml.get("jobs").and_then(Value::as_mapping).unwrap();
    for (_, job) in jobs {
        let timeout = job.get("timeout-minutes").and_then(Value::as_i64).unwrap();
        assert!(timeout <= 30, "PR timeout must be <= 30");
    }
}

fn workflow() -> (String, Value) {
    let text = std::fs::read_to_string(repo_root().join("templates/dast-workflow.yml")).unwrap();
    let yaml = serde_yaml_ng::from_str(&text).unwrap();
    (text, yaml)
}

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .to_path_buf()
}
