use dast_spike::report::normalize::{NormalizedAlert, NormalizedReport};
use dast_spike::report::sarif::emit_sarif;
use dast_spike::types::Severity;

#[test]
fn sarif_emission_has_required_shape() {
    let report = NormalizedReport {
        scanner: "zap".to_string(),
        alerts: vec![NormalizedAlert {
            scanner: "zap".to_string(),
            plugin_id: "40012".to_string(),
            alert_ref: "40012".to_string(),
            name: "Reflected XSS".to_string(),
            severity: Severity::High,
            url: "http://example.test".to_string(),
            param: None,
            evidence_hash: "abc".to_string(),
            cwes: vec!["CWE-79".to_string()],
        }],
        truncated_alerts: Default::default(),
    };
    let sarif = emit_sarif(&[report]);
    assert_eq!(sarif["version"], "2.1.0");
    assert!(
        sarif["runs"].as_array().unwrap()[0]["results"]
            .as_array()
            .unwrap()
            .len()
            == 1
    );
}
