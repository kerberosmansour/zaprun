use chrono::NaiveDate;
use dast_spike_rules::{BaselineDocument, Suppression, SuppressionScope};

#[test]
fn valid_baseline_schema_loads() {
    let json = r#"{
      "$schema": "https://github.com/kerberosmansour/Dast.Spike/blob/main/schema/baseline-v1.json",
      "schema_version": "1.0",
      "suppressions": [{
        "scanner": "zap",
        "plugin_id": "10015",
        "alert_ref": "10015",
        "scope": { "url_pattern": "^/health$" },
        "justification": "Health endpoint no data",
        "author": "security@example.test",
        "added_at": "2026-05-06",
        "expires_at": "2026-08-04",
        "linked_finding": null,
        "review_count": 0
      }]
    }"#;
    let baseline: BaselineDocument = serde_json::from_str(json).unwrap();
    let summary = baseline
        .validate(NaiveDate::from_ymd_opt(2026, 5, 6).unwrap(), false)
        .unwrap();
    assert_eq!(summary.total_suppressions, 1);
}

#[test]
fn unknown_field_rejects_baseline_load() {
    let json = r#"{
      "$schema": "x",
      "schema_version": "1.0",
      "suppressions": [],
      "foo": true
    }"#;
    let err = serde_json::from_str::<BaselineDocument>(json).unwrap_err();
    assert!(err.to_string().contains("unknown field"));
}

#[test]
fn global_suppression_requires_long_justification() {
    let suppression = Suppression {
        scanner: "zap".to_string(),
        plugin_id: "10063".to_string(),
        alert_ref: Some("10063".to_string()),
        scope: SuppressionScope::Global { global: true },
        justification: "broken".to_string(),
        author: "security@example.test".to_string(),
        added_at: NaiveDate::from_ymd_opt(2026, 5, 6).unwrap(),
        expires_at: NaiveDate::from_ymd_opt(2026, 8, 4).unwrap(),
        linked_finding: None,
        review_count: 0,
    };
    let err = suppression.validate().unwrap_err();
    assert!(err
        .to_string()
        .contains("global suppression requires justification >= 80 chars"));
}
