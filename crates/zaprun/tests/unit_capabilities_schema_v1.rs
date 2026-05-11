use zaprun::capabilities::{CapabilitiesReport, SCHEMA_VERSION};

#[test]
fn schema_version_constant_is_one_dot_zero() {
    assert_eq!(SCHEMA_VERSION, "1.0");
}

#[test]
fn capabilities_round_trips_through_serde() {
    let report = CapabilitiesReport::sample_for_tests();
    let json = serde_json::to_string(&report).expect("serialize");
    let parsed: CapabilitiesReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(report, parsed);
    assert_eq!(parsed.schema_version, "1.0");
}

#[test]
fn capabilities_rejects_unsupported_schema_version() {
    let bad = r#"{"schema_version":"2.0","backend":"docker","docker":{"available":true},"image":{"pinned":false},"output_dir":{"writable":true},"target":null,"java":null,"browser":null,"partial":false,"started_at":"2026-05-06T00:00:00Z","finished_at":"2026-05-06T00:00:00Z"}"#;
    let parse_err = CapabilitiesReport::from_json_strict(bad).unwrap_err();
    let msg = format!("{parse_err:?}");
    assert!(
        msg.contains("UnsupportedSchemaVersion") || msg.contains("schema_version"),
        "expected schema-version rejection, got {msg}"
    );
}

#[test]
fn capabilities_serialized_size_under_16_kib() {
    let report = CapabilitiesReport::sample_for_tests();
    let json = serde_json::to_string_pretty(&report).expect("serialize");
    assert!(
        json.len() < 16 * 1024,
        "capabilities.json sample is {} bytes, must be < 16 KiB",
        json.len()
    );
}
