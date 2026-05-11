use chrono::NaiveDate;
use dast_spike_rules::{BaselineDocument, Suppression, SuppressionScope};

#[test]
fn duplicate_natural_key_fails() {
    let suppression = Suppression {
        scanner: "zap".to_string(),
        plugin_id: "10015".to_string(),
        alert_ref: Some("10015".to_string()),
        scope: SuppressionScope::UrlPattern {
            url_pattern: "^/health$".to_string(),
        },
        justification: "fixture suppression".to_string(),
        author: "security@example.test".to_string(),
        added_at: NaiveDate::from_ymd_opt(2026, 5, 6).unwrap(),
        expires_at: NaiveDate::from_ymd_opt(2026, 8, 4).unwrap(),
        linked_finding: None,
        review_count: 0,
    };
    let mut baseline = BaselineDocument::empty();
    baseline.suppressions.push(suppression.clone());
    baseline.suppressions.push(suppression);
    let err = baseline
        .validate(NaiveDate::from_ymd_opt(2026, 5, 6).unwrap(), false)
        .unwrap_err();
    assert!(err.to_string().contains("natural key collision"));
}
