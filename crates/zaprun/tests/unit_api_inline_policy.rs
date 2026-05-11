use zaprun::scan_api::{api_pr_openapi_plan, API_MINIMAL_POLICY_INLINE_HASH};

#[test]
fn plan_yaml_does_not_reference_disk_policy() {
    let plan = api_pr_openapi_plan("/tmp/spec.yaml", "http://target:3000").unwrap();
    let yaml = plan.to_yaml().unwrap();
    assert!(
        !yaml.contains("API-Minimal.policy"),
        "AF plan must not reference the on-disk policy filename"
    );
    assert!(
        !yaml.contains(".ZAP_D"),
        "AF plan must not reference .ZAP_D"
    );
    assert!(!yaml.contains("/home/zap/.ZAP"));
    assert!(yaml.contains("openapi"), "must include openapi import job");
    assert!(yaml.contains("activeScan"));
}

#[test]
fn inline_policy_constant_hash_pinned() {
    use sha2::{Digest, Sha256};
    use zaprun::scan_api::API_MINIMAL_POLICY_INLINE;
    let mut h = Sha256::new();
    h.update(API_MINIMAL_POLICY_INLINE.as_bytes());
    let actual: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        actual, API_MINIMAL_POLICY_INLINE_HASH,
        "drift in API_MINIMAL_POLICY_INLINE -- update the pinned hash deliberately"
    );
}
