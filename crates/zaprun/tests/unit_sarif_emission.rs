use zaprun::report::sarif::{emit_sarif, SARIF_MAX_BYTES};

#[test]
fn sarif_includes_canonical_runs_tool_driver() {
    let sarif = emit_sarif("zaprun", "0.1.0", &[]).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();
    assert_eq!(parsed["version"], "2.1.0");
    assert!(parsed["runs"][0]["tool"]["driver"]["name"]
        .as_str()
        .map(|s| s.contains("zaprun"))
        .unwrap_or(false));
}

#[test]
fn sarif_size_capped_at_4_mib_and_records_truncation() {
    // Synthesize many alerts to push past the cap.
    use zaprun::report::normalize::RawAlert;
    let mut alerts = Vec::new();
    for i in 0..100_000 {
        alerts.push(RawAlert {
            risk: "Low".to_string(),
            instances_count: 1,
            count: String::new(),
            plugin_id: format!("{i}"),
            name: format!(
                "alert with a fairly verbose description -- {}",
                "x".repeat(200)
            ),
            instances: Vec::new(),
        });
    }
    let sarif = emit_sarif("zaprun", "0.1.0", &alerts).unwrap();
    assert!(
        sarif.len() <= SARIF_MAX_BYTES,
        "SARIF must be capped at 4 MiB, got {} bytes",
        sarif.len()
    );
    // The cap-marker is the truncation flag in the report.
    let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();
    let truncated = parsed["runs"][0]["properties"]["truncated"].as_bool();
    assert_eq!(
        truncated,
        Some(true),
        "must record truncation in properties"
    );
}
