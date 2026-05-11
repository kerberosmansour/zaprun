use assert_cmd::Command;
use serde_json::json;

#[test]
fn check_fails_on_expired_suppression() {
    let temp = tempfile::tempdir().unwrap();
    let report = temp.path().join("zap-report.json");
    let baseline = temp.path().join("baseline.json");
    std::fs::write(
        &report,
        json!({
          "site": [{ "alerts": [{
            "pluginid": "10015",
            "alertRef": "10015",
            "name": "Cache header",
            "riskcode": "3",
            "instances": [{ "uri": "http://127.0.0.1/health", "evidence": "cache" }]
          }]}]
        })
        .to_string(),
    )
    .unwrap();
    std::fs::write(
        &baseline,
        r#"{
          "$schema": "https://github.com/kerberosmansour/Dast.Spike/blob/main/schema/baseline-v1.json",
          "schema_version": "1.0",
          "suppressions": [{
            "scanner": "zap",
            "plugin_id": "10015",
            "alert_ref": "10015",
            "scope": { "url_pattern": "health" },
            "justification": "fixture suppression",
            "author": "security@example.test",
            "added_at": "2026-01-01",
            "expires_at": "2026-04-01",
            "linked_finding": null,
            "review_count": 0
          }]
        }"#,
    )
    .unwrap();
    let mut cmd = Command::cargo_bin("dast-spike").unwrap();
    cmd.env("DAST_SPIKE_TEST_DATE", "2026-05-06")
        .arg("check")
        .arg("--report")
        .arg(&report)
        .arg("--baseline")
        .arg(&baseline);
    cmd.assert().failure().code(1);
}
