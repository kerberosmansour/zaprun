use chrono::NaiveDate;
use dast_spike_rules::{BaselineDocument, Suppression, SuppressionScope};

#[test]
fn baseline_refuses_entries_over_hard_limit() {
    let mut baseline = BaselineDocument::empty();
    for idx in 0..201 {
        baseline.suppressions.push(Suppression {
            scanner: "zap".to_string(),
            plugin_id: format!("10{idx:03}"),
            alert_ref: Some(format!("10{idx:03}")),
            scope: SuppressionScope::UrlPattern {
                url_pattern: format!("^/{idx}$"),
            },
            justification: "fixture suppression".to_string(),
            author: "security@example.test".to_string(),
            added_at: NaiveDate::from_ymd_opt(2026, 5, 6).unwrap(),
            expires_at: NaiveDate::from_ymd_opt(2026, 8, 4).unwrap(),
            linked_finding: None,
            review_count: 0,
        });
    }
    let err = baseline
        .validate(NaiveDate::from_ymd_opt(2026, 5, 6).unwrap(), false)
        .unwrap_err();
    assert!(err.to_string().contains("hard limit 200"));
}
