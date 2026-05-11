use dast_spike::report::normalize::{parse_zap_report, PER_RULE_ALERT_HARD_LIMIT};
use serde_json::json;

#[test]
fn truncates_alerts_after_per_rule_limit() {
    let alerts = (0..150)
        .map(|idx| {
            json!({
                "pluginid": "40012",
                "alertRef": "40012",
                "name": "Reflected XSS",
                "riskcode": "3",
                "instances": [{ "uri": format!("http://example.test/{idx}"), "evidence": "x" }]
            })
        })
        .collect::<Vec<_>>();
    let report = json!({ "site": [{ "alerts": alerts }] });
    let parsed = parse_zap_report(&report.to_string()).unwrap();

    assert_eq!(parsed.alerts.len(), PER_RULE_ALERT_HARD_LIMIT);
    assert_eq!(parsed.truncated_alerts.get("40012"), Some(&50));
}
