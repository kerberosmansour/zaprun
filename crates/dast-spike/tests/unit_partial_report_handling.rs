use dast_spike::report::normalize::parse_zap_report;

#[test]
fn truncated_json_returns_named_scanner_error() {
    let err = parse_zap_report(r#"{"site":[{"alerts":["#).unwrap_err();
    assert!(err
        .to_string()
        .contains("report file appears truncated; ZAP scan likely killed mid-write"));
}
