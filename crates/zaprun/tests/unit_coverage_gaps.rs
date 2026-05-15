use zaprun::coverage::{Coverage, CoverageGapKind};

#[test]
fn coverage_schema_v1() {
    let c = Coverage::for_web_pr_traditional(123, 0, 0);
    assert_eq!(c.schema_version, "1.0");
    assert_eq!(c.profile, "web-pr");
}

#[test]
fn web_pr_browser_required_false_no_gap() {
    let c = Coverage::for_web_pr_traditional(50, 0, 0);
    assert!(!c
        .coverage_gaps
        .iter()
        .any(|g| g.kind == CoverageGapKind::BrowserMissing));
}

#[test]
fn spa_pr_records_browser_attempt_and_seed_gap() {
    let c = Coverage::for_spa_pr_browser(118, 304);
    assert_eq!(c.profile, "spa-pr");
    assert!(c.browser.required);
    assert!(c.browser.available);
    assert_eq!(c.crawl.traditional_urls, 118);
    assert_eq!(c.crawl.ajax_urls, 304);
    assert!(c
        .coverage_gaps
        .iter()
        .any(|g| g.kind == CoverageGapKind::SeededJourneysNotConfigured));
}

#[test]
fn ptk_phase1_records_browser_attempt_and_seed_gap() {
    let c = Coverage::for_ptk_phase1_browser(42);
    assert_eq!(c.profile, "ptk-phase1");
    assert!(c.browser.required);
    assert!(c.browser.available);
    assert_eq!(c.browser.status, "attempted");
    assert_eq!(c.crawl.ajax_urls, 42);
    assert!(c
        .coverage_gaps
        .iter()
        .any(|g| g.kind == CoverageGapKind::SeededJourneysNotConfigured));
}

#[test]
fn passive_only_records_gap() {
    let c = Coverage::for_web_pr_passive_only(20);
    assert!(c
        .coverage_gaps
        .iter()
        .any(|g| g.kind == CoverageGapKind::PassiveOnly));
}

#[test]
fn target_unreachable_records_gap() {
    let c = Coverage::for_target_unreachable("http://10.255.255.1:65000");
    assert!(c
        .coverage_gaps
        .iter()
        .any(|g| g.kind == CoverageGapKind::TargetUnreachable));
}

#[test]
fn active_did_not_complete_records_gap() {
    let c = Coverage::for_active_scan_failed("ZAP startup failed");
    assert!(c
        .coverage_gaps
        .iter()
        .any(|g| g.kind == CoverageGapKind::ActiveScanDidNotComplete));
}
