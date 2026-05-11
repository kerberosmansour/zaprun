use zaprun::calibrate::{evaluate_calibration, CalibrationProfile, ExpectedClass};

#[test]
fn missing_class_fails_with_exit_5() {
    let profile = CalibrationProfile {
        target: "nodegoat-substitute".to_string(),
        image: None,
        expected: vec![ExpectedClass {
            plugin_id: "40012".to_string(),
            name: "Reflected XSS".to_string(),
            min_count: 1,
            routes: vec![],
        }],
        known_misses: vec![],
    };
    // Synthetic observed counts: plugin 40012 has 0 instances => fail.
    let observed: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    let result = evaluate_calibration(&profile, &observed);
    assert!(!result.passed);
    assert_eq!(result.failed_classes.len(), 1);
    assert_eq!(result.failed_classes[0].plugin_id, "40012");
}

#[test]
fn all_classes_present_passes() {
    let profile = CalibrationProfile {
        target: "nodegoat".to_string(),
        image: None,
        expected: vec![
            ExpectedClass {
                plugin_id: "40012".to_string(),
                name: "Reflected XSS".to_string(),
                min_count: 1,
                routes: vec![],
            },
            ExpectedClass {
                plugin_id: "10028".to_string(),
                name: "Off-site Redirect".to_string(),
                min_count: 1,
                routes: vec![],
            },
        ],
        known_misses: vec![],
    };
    let mut observed = std::collections::HashMap::new();
    observed.insert("40012".to_string(), 3);
    observed.insert("10028".to_string(), 1);
    let result = evaluate_calibration(&profile, &observed);
    assert!(result.passed);
    assert!(result.failed_classes.is_empty());
}

#[test]
fn min_count_threshold_enforced() {
    let profile = CalibrationProfile {
        target: "any".to_string(),
        image: None,
        expected: vec![ExpectedClass {
            plugin_id: "40018".to_string(),
            name: "SQLi".to_string(),
            min_count: 2,
            routes: vec![],
        }],
        known_misses: vec![],
    };
    let mut observed = std::collections::HashMap::new();
    observed.insert("40018".to_string(), 1); // below threshold
    let result = evaluate_calibration(&profile, &observed);
    assert!(!result.passed);
    assert_eq!(result.failed_classes[0].plugin_id, "40018");
}

#[test]
fn profile_parses_from_toml() {
    let toml_str = r#"
target = "nodegoat"
image = "nirocr/nodegoat@sha256:1384d404f1eb89ba218a5988cccde902bb6b606e3ec70f60b185183f9639c392"

[[expected]]
plugin_id = "40012"
name = "Cross Site Scripting (Reflected)"
min_count = 1
routes = ["/learn", "/benefits"]
"#;
    let profile: CalibrationProfile = toml::from_str(toml_str).expect("parse");
    assert_eq!(profile.target, "nodegoat");
    assert_eq!(profile.expected.len(), 1);
    assert_eq!(profile.expected[0].plugin_id, "40012");
}

#[test]
fn nodegoat_fixture_parses_as_calibration_profile() {
    let profile: CalibrationProfile =
        toml::from_str(include_str!("../../../tests/targets/nodegoat.toml")).expect("parse");
    assert_eq!(profile.target, "nodegoat");
    assert_eq!(
        profile.image.as_deref(),
        Some("nirocr/nodegoat@sha256:1384d404f1eb89ba218a5988cccde902bb6b606e3ec70f60b185183f9639c392")
    );
    assert_eq!(profile.expected.len(), 3);
    assert!(profile.expected.iter().any(|c| c.plugin_id == "40026"));
    assert_eq!(profile.known_misses.len(), 1);
}
