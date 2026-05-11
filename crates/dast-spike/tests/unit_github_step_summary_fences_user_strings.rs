use assert_cmd::Command;
use serde_json::json;

#[test]
fn github_summary_uses_text_fence() {
    let temp = tempfile::tempdir().unwrap();
    let report = temp.path().join("zap-report.json");
    let summary = temp.path().join("summary.md");
    std::fs::write(&report, json!({ "site": [{ "alerts": [] }] }).to_string()).unwrap();

    let mut cmd = Command::cargo_bin("dast-spike").unwrap();
    cmd.env("GITHUB_STEP_SUMMARY", &summary)
        .arg("check")
        .arg("--report")
        .arg(&report)
        .arg("--baseline")
        .arg(temp.path().join("missing-baseline.json"))
        .arg("--github-summary");
    cmd.assert().success();

    let text = std::fs::read_to_string(summary).unwrap();
    assert!(text.contains("~~~text"));
}
