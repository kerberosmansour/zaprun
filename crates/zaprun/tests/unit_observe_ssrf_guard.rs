use zaprun::observe::{validate_observe_target, ObserveTargetError};

#[test]
fn refuses_imds_unconditionally() {
    let err = validate_observe_target("http://169.254.169.254/", false).unwrap_err();
    assert!(matches!(err, ObserveTargetError::ImdsBlocked));
    let err = validate_observe_target("http://169.254.169.254/latest/meta-data", true).unwrap_err();
    assert!(
        matches!(err, ObserveTargetError::ImdsBlocked),
        "IMDS must be refused even with --allow-internal-target"
    );
}

#[test]
fn refuses_private_ranges_without_flag() {
    for url in [
        "http://10.0.0.5:8080",
        "http://172.16.0.1",
        "http://192.168.1.1",
        "http://127.0.0.1:3000",
    ] {
        let err = validate_observe_target(url, false).unwrap_err();
        assert!(
            matches!(err, ObserveTargetError::PrivateNetBlocked),
            "expected PrivateNetBlocked for {url:?}, got {err:?}"
        );
    }
}

#[test]
fn accepts_private_ranges_with_flag() {
    for url in [
        "http://10.0.0.5:8080",
        "http://127.0.0.1:3000",
        "http://192.168.1.1",
    ] {
        validate_observe_target(url, true).expect("must accept with --allow-internal-target");
    }
}

#[test]
fn refuses_link_local() {
    let err = validate_observe_target("http://169.254.0.1", true).unwrap_err();
    assert!(
        matches!(err, ObserveTargetError::ImdsBlocked),
        "169.254/16 is link-local; refuse without override"
    );
}

#[test]
fn refuses_non_http_scheme() {
    let err = validate_observe_target("file:///etc/passwd", true).unwrap_err();
    assert!(matches!(err, ObserveTargetError::SchemeUnsupported));
}

#[test]
fn accepts_public_target() {
    validate_observe_target("https://api.example.com/v1/users", false)
        .expect("public target must be accepted");
}
