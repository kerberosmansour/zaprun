use zaprun::plan::{Job, Plan, PlanError};

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
