use zaprun::report::normalize::{normalize_zap_report, RawZapReport, Summary};

#[test]
fn summary_schema_v1_round_trips() {
    let s = Summary::sample_for_tests();
    let json = serde_json::to_string(&s).unwrap();
    let parsed: Summary = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, s);
    assert_eq!(parsed.schema_version, "1.0");
}

#[test]
fn normalize_counts_high_medium_warn_correctly() {
    let raw = RawZapReport {
        site: vec![raw_site_with_alerts(vec![
            ("High", 2),
            ("Medium", 1),
            ("Low", 4),
        ])],
    };
    let s = normalize_zap_report(&raw, 100, 200, 60);
    assert_eq!(s.high_count, 2);
    assert_eq!(s.medium_count, 1);
    // warn = Low + Informational; here just 4
    assert_eq!(s.warn_count, 4);
    assert_eq!(s.urls_imported, 100);
    assert_eq!(s.urls_scanned, 200);
    assert_eq!(s.duration_seconds, 60);
}

#[test]
fn empty_report_yields_zero_counts() {
    let raw = RawZapReport { site: vec![] };
    let s = normalize_zap_report(&raw, 0, 0, 0);
    assert_eq!(s.high_count, 0);
    assert_eq!(s.medium_count, 0);
    assert_eq!(s.warn_count, 0);
    assert_eq!(s.status, "passed");
}

#[test]
fn high_count_implies_failed_status() {
    let raw = RawZapReport {
        site: vec![raw_site_with_alerts(vec![("High", 1)])],
    };
    let s = normalize_zap_report(&raw, 0, 0, 0);
    assert_eq!(s.status, "failed");
}

fn raw_site_with_alerts(alerts: Vec<(&str, u32)>) -> zaprun::report::normalize::RawSite {
    use zaprun::report::normalize::{RawAlert, RawSite};
    RawSite {
        alerts: alerts
            .into_iter()
            .map(|(risk, count)| RawAlert {
                risk: risk.to_string(),
                instances_count: count,
                count: String::new(),
                plugin_id: "0".to_string(),
                name: "n".to_string(),
                instances: Vec::new(),
            })
            .collect(),
    }
}
