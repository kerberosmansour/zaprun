use zaprun::plan::{Job, Plan, PlanError};

#[test]
fn ci_mode_refuses_addon_install() {
    let err = Plan::builder()
        .context("default", "http://localhost:3000")
        .ci_mode(true)
        .job(Job::AddOns {
            install: vec!["beta".to_string()],
            update: false,
        })
        .build()
        .unwrap_err();
    assert!(matches!(err, PlanError::AddonUpdateInCi));
}

#[test]
fn ci_mode_refuses_addon_update_true() {
    let err = Plan::builder()
        .context("default", "http://localhost:3000")
        .ci_mode(true)
        .job(Job::AddOns {
            install: vec![],
            update: true,
        })
        .build()
        .unwrap_err();
    assert!(matches!(err, PlanError::AddonUpdateInCi));
}

#[test]
fn ci_mode_accepts_empty_addon_block() {
    Plan::builder()
        .context("default", "http://localhost:3000")
        .ci_mode(true)
        .job(Job::AddOns {
            install: vec![],
            update: false,
        })
        .job(Job::PassiveScanWait {
            max_duration_seconds: 60,
        })
        .build()
        .expect("empty addons block is fine in CI");
}

#[test]
fn non_ci_mode_allows_addons() {
    Plan::builder()
        .context("default", "http://localhost:3000")
        .ci_mode(false)
        .job(Job::AddOns {
            install: vec!["beta".to_string()],
            update: true,
        })
        .build()
        .expect("non-CI lets users opt in to addons");
}
