use assert_cmd::Command;
use serde_json::{json, Value as JsonValue};
use std::fs;
use std::path::Path;

#[test]
fn sarif_xss_route_maps_to_dast_detectable() {
    let temp = tempfile::tempdir().unwrap();
    write_target_fixture(temp.path());
    let sarif = write_sarif(
        temp.path(),
        vec![sarif_result(
            "semgrep.xss",
            "CWE-79",
            Some("/api/search"),
            Some("GET"),
            false,
            false,
        )],
    );
    let output = run_triage(temp.path(), &sarif);
    let report = read_json(&output.join("triage-report.json"));

    let finding = &report["findings"][0];
    assert_eq!(finding["classification"], "dast-detectable");
    assert_eq!(finding["cwe"], "CWE-79");
    assert_eq!(finding["recommended_zap_policy"], "policy-CWE-79");
    assert!(
        finding["recommended_action"]
            .as_str()
            .unwrap()
            .contains("zaprun observe"),
        "{finding}"
    );
}

#[test]
fn sarif_internal_panic_not_dast_applicable() {
    let temp = tempfile::tempdir().unwrap();
    write_target_fixture(temp.path());
    let sarif = write_sarif(
        temp.path(),
        vec![sarif_result(
            "rust.panic",
            "CWE-755",
            None,
            None,
            false,
            false,
        )],
    );
    let output = run_triage(temp.path(), &sarif);
    let report = read_json(&output.join("triage-report.json"));

    assert_eq!(
        report["findings"][0]["classification"],
        "dast-not-applicable"
    );
    assert!(
        report["findings"][0]["rationale"]
            .as_str()
            .unwrap()
            .contains("no HTTP route"),
        "{report}"
    );
}

#[test]
fn sarif_ssrf_requires_live_request() {
    let temp = tempfile::tempdir().unwrap();
    write_target_fixture(temp.path());
    let sarif = write_sarif(
        temp.path(),
        vec![sarif_result(
            "semgrep.ssrf",
            "CWE-918",
            None,
            None,
            false,
            false,
        )],
    );
    let output = run_triage(temp.path(), &sarif);
    let report = read_json(&output.join("triage-report.json"));

    assert_eq!(report["findings"][0]["classification"], "needs-human-input");
    assert!(
        report["findings"][0]["rationale"]
            .as_str()
            .unwrap()
            .contains("live request"),
        "{report}"
    );
}

#[test]
fn sarif_no_overclaiming() {
    let temp = tempfile::tempdir().unwrap();
    write_target_fixture(temp.path());
    let sarif = write_sarif(
        temp.path(),
        vec![sarif_result(
            "semgrep.xss",
            "CWE-79",
            None,
            None,
            false,
            false,
        )],
    );
    let output = run_triage(temp.path(), &sarif);
    let report = read_json(&output.join("triage-report.json"));
    let guided = read_json(&output.join("guided-scan-map.json"));

    assert_ne!(report["findings"][0]["classification"], "dast-detectable");
    assert!(guided["targets"].as_array().unwrap().is_empty());
}

#[test]
fn sarif_endpoint_method_guided_map() {
    let temp = tempfile::tempdir().unwrap();
    write_target_fixture(temp.path());
    let sarif = write_sarif(
        temp.path(),
        vec![sarif_result(
            "semgrep.sql",
            "CWE-89",
            Some("/api/users/{id}"),
            Some("GET"),
            false,
            false,
        )],
    );
    let output = run_triage(temp.path(), &sarif);
    let guided = read_json(&output.join("guided-scan-map.json"));
    let target = &guided["targets"][0];

    assert_eq!(guided["schema_version"], "1.0");
    assert_eq!(guided["mode"], "guided-pr");
    assert_eq!(target["path"], "/api/users/{id}");
    assert_eq!(target["method"], "GET");
    assert_eq!(target["cwe"], "CWE-89");
    assert_eq!(target["zap_policy"], "policy-CWE-89");
    assert_eq!(target["confidence"], "route-confirmed");
}

#[test]
fn sarif_validated_filter_output() {
    let temp = tempfile::tempdir().unwrap();
    write_target_fixture(temp.path());
    let sarif = write_sarif(
        temp.path(),
        vec![
            sarif_result(
                "semgrep.validated",
                "CWE-79",
                Some("/api/search"),
                Some("GET"),
                true,
                false,
            ),
            sarif_result(
                "semgrep.unvalidated",
                "CWE-79",
                Some("/api/search"),
                Some("GET"),
                false,
                false,
            ),
        ],
    );
    let output = run_triage(temp.path(), &sarif);
    let filtered = read_json(&output.join("filtered.sarif"));
    let results = filtered["runs"][0]["results"].as_array().unwrap();

    assert_eq!(results.len(), 1, "{filtered}");
    assert_eq!(results[0]["ruleId"], "semgrep.validated");
    assert!(fs::read_to_string(&sarif)
        .unwrap()
        .contains("semgrep.unvalidated"));
}

#[test]
fn sarif_auth_required_needs_auth_config() {
    let temp = tempfile::tempdir().unwrap();
    write_target_fixture(temp.path());
    let sarif = write_sarif(
        temp.path(),
        vec![sarif_result(
            "semgrep.auth-xss",
            "CWE-79",
            Some("/api/private"),
            Some("GET"),
            false,
            true,
        )],
    );
    let output = run_triage(temp.path(), &sarif);
    let report = read_json(&output.join("triage-report.json"));
    let guided = read_json(&output.join("guided-scan-map.json"));

    assert_eq!(report["findings"][0]["classification"], "needs-human-input");
    assert!(
        report["findings"][0]["rationale"]
            .as_str()
            .unwrap()
            .contains("auth"),
        "{report}"
    );
    assert!(guided["targets"].as_array().unwrap().is_empty());
}

fn run_triage(target: &Path, sarif: &Path) -> std::path::PathBuf {
    let output = target.join("triage-output");
    let mut cmd = Command::cargo_bin("zaprun").unwrap();
    cmd.arg("triage-sarif")
        .arg("--target-dir")
        .arg(target)
        .arg("--sarif")
        .arg(sarif)
        .arg("--output")
        .arg(&output);
    cmd.assert().success();
    output
}

fn write_target_fixture(root: &Path) {
    fs::write(
        root.join("openapi.yaml"),
        "openapi: 3.0.0\ninfo:\n  title: Fixture\n  version: 1.0.0\npaths:\n  /api/search:\n    get:\n      responses:\n        '200':\n          description: ok\n  /api/users/{id}:\n    get:\n      responses:\n        '200':\n          description: ok\n  /api/private:\n    get:\n      security:\n        - bearerAuth: []\n      responses:\n        '200':\n          description: ok\n",
    )
    .unwrap();
    fs::create_dir_all(root.join(".zaprun")).unwrap();
    fs::write(
        root.join(".zaprun/manifest.json"),
        r#"{
  "$schema": "https://github.com/kerberosmansour/zaprun/blob/main/schema/manifest-v1.json",
  "schema_version": "1.0",
  "generated_at": "2026-05-15T00:00:00Z",
  "generated_by_zaprun_version": "0.1.0",
  "image_digest": "sha256:1caa4c454beac1a5ca67bb06484282b94e43a5cd01ba772ec1a2b78a6ed4c649",
  "upstream_image_digest": "sha256:31da6565f35af6401031c1d7aa91dc84ac76c5c48edd17fb90f0ed9e3173c7a9",
  "cwes_claimed": ["CWE-79", "CWE-89"],
  "cwes_actually_covered": ["CWE-79", "CWE-89"],
  "cwes_uncovered": [],
  "detected_stack": ["rust"],
  "detected_surface": "api-openapi",
  "detected_auth": "unknown",
  "selected_scanners": ["zap"],
  "selected_rules": [],
  "selection_strategy": "threat-model-cwe"
}"#,
    )
    .unwrap();
}

fn write_sarif(root: &Path, results: Vec<JsonValue>) -> std::path::PathBuf {
    let path = root.join("sast.sarif");
    let sarif = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "semgrep",
                    "rules": []
                }
            },
            "results": results
        }]
    });
    fs::write(&path, serde_json::to_vec_pretty(&sarif).unwrap()).unwrap();
    path
}

fn sarif_result(
    rule_id: &str,
    cwe: &str,
    endpoint: Option<&str>,
    method: Option<&str>,
    validated: bool,
    auth_required: bool,
) -> JsonValue {
    let mut properties = json!({
        "tags": [cwe],
        "zap_validated": validated,
        "auth_required": auth_required
    });
    if let Some(endpoint) = endpoint {
        properties["endpoint"] = JsonValue::String(endpoint.to_string());
    }
    if let Some(method) = method {
        properties["method"] = JsonValue::String(method.to_string());
    }
    json!({
        "ruleId": rule_id,
        "message": { "text": format!("{rule_id} found {cwe}") },
        "fingerprints": { "primaryLocationLineHash": format!("{rule_id}:{cwe}") },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": { "uri": "src/lib.rs" },
                "region": { "startLine": 42 }
            }
        }],
        "properties": properties
    })
}

fn read_json(path: &Path) -> JsonValue {
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}
