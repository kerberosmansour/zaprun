use dast_spike::report::normalize::parse_zap_report;
use serde_json::json;

#[test]
#[should_panic(expected = "converter emitted severity outside enum")]
fn unknown_zap_severity_panics_in_debug() {
    let report = json!({
      "site": [{ "alerts": [{
        "pluginid": "40012",
        "alertRef": "40012",
        "name": "Bad severity",
        "riskcode": "99",
        "instances": [{ "uri": "http://example.test", "evidence": "x" }]
      }]}]
    });
    let _ = parse_zap_report(&report.to_string()).unwrap();
}
