use zaprun::plan::{Job, Plan, PlanError, PtkConfig};

fn min_plan() -> Plan {
    Plan::builder()
        .context("default", "http://localhost:3000")
        .job(Job::PassiveScanWait {
            max_duration_seconds: 60,
        })
        .job(Job::ActiveScan {
            policy_inline: true,
            dom_xss_enabled: false,
        })
        .job(Job::Report {
            template: "traditional-json".to_string(),
            file: "zap-report.json".to_string(),
        })
        .job(Job::ExitStatus {
            error_level: "high".to_string(),
            warn_level: "medium".to_string(),
        })
        .build()
        .expect("min_plan builds")
}

#[test]
fn plan_serializes_to_yaml() {
    let yaml = min_plan().to_yaml().expect("serializes");
    assert!(yaml.contains("env:"));
    assert!(yaml.contains("jobs:"));
    assert!(yaml.contains("activeScan"));
    assert!(yaml.contains("zap-report.json"));
    assert!(
        !yaml.contains("configs:"),
        "existing scan plans must not grow PTK config"
    );
}

#[test]
fn plan_serialization_is_deterministic() {
    let a = min_plan().to_yaml().expect("a");
    let b = min_plan().to_yaml().expect("b");
    assert_eq!(a, b, "same plan must serialize byte-stable");
}

#[test]
fn plan_caps_at_32_jobs() {
    let mut b = Plan::builder().context("default", "http://localhost:3000");
    for _ in 0..33 {
        b = b.job(Job::PassiveScanWait {
            max_duration_seconds: 1,
        });
    }
    let err = b.build().unwrap_err();
    assert!(matches!(err, PlanError::TooManyJobs));
}

#[test]
fn plan_refuses_empty_contexts() {
    let err = Plan::builder()
        .job(Job::PassiveScanWait {
            max_duration_seconds: 1,
        })
        .build()
        .unwrap_err();
    assert!(matches!(err, PlanError::EnvNoContexts));
}

#[test]
fn ptk_phase1_plan_serializes() {
    let plan = Plan::builder()
        .context("default", "http://localhost:4000")
        .ptk_config(PtkConfig::phase1())
        .job(Job::SpiderClient {
            url: "http://localhost:4000".to_string(),
            browser_id: "firefox-headless".to_string(),
            max_duration_seconds: 180,
            number_of_browsers: 1,
        })
        .job(Job::PassiveScanWait {
            max_duration_seconds: 60,
        })
        .job(Job::Report {
            template: "traditional-json".to_string(),
            file: "zap-report.json".to_string(),
        })
        .build()
        .expect("ptk plan builds");

    let yaml = plan.to_yaml().expect("serializes");
    for expected in [
        "configs:",
        "ptk.automatedScanning.enabled: true",
        "ptk.scanrules.SAST.enabled: true",
        "ptk.scanrules.IAST.enabled: true",
        "ptk.scanrules.DAST.enabled: true",
        "type: spiderClient",
        "url: http://localhost:4000",
        "browserId: firefox-headless",
        "maxDuration: 3",
        "numberOfBrowsers: 1",
        "scopeCheck: Strict",
    ] {
        assert!(yaml.contains(expected), "missing `{expected}` in:\n{yaml}");
    }
    assert!(
        !yaml.contains("type: addOns"),
        "PTK plans must rely on baked add-ons, not runtime addOns jobs"
    );
}

#[test]
fn ptk_phase1_plan_rejects_zero_client_spider_browsers() {
    let err = Plan::builder()
        .context("default", "http://localhost:4000")
        .ptk_config(PtkConfig::phase1())
        .job(Job::SpiderClient {
            url: "http://localhost:4000".to_string(),
            browser_id: "firefox-headless".to_string(),
            max_duration_seconds: 180,
            number_of_browsers: 0,
        })
        .build()
        .unwrap_err();
    assert!(matches!(
        err,
        PlanError::ClientSpiderBrowserCountOutOfBounds
    ));
}

#[test]
fn ptk_phase1_plan_rejects_unbounded_client_spider_browsers() {
    let err = Plan::builder()
        .context("default", "http://localhost:4000")
        .ptk_config(PtkConfig::phase1())
        .job(Job::SpiderClient {
            url: "http://localhost:4000".to_string(),
            browser_id: "firefox-headless".to_string(),
            max_duration_seconds: 180,
            number_of_browsers: 3,
        })
        .build()
        .unwrap_err();
    assert!(matches!(
        err,
        PlanError::ClientSpiderBrowserCountOutOfBounds
    ));
}
