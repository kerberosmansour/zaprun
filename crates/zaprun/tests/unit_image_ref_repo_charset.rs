use zaprun::image_ref::{ImageRef, ImageRefError};

const VALID_HEX_64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn with_digest(repo: &str) -> String {
    format!("{repo}@sha256:{VALID_HEX_64}")
}

#[test]
fn refuses_argv_smuggling_double_dash_prefix() {
    let err = ImageRef::parse(&with_digest("--privileged docker.io/owasp/zap")).unwrap_err();
    assert!(matches!(err, ImageRefError::RepoCharset));
}

#[test]
fn refuses_repo_with_space() {
    let err = ImageRef::parse(&with_digest("owasp/zap with space")).unwrap_err();
    assert!(matches!(err, ImageRefError::RepoCharset));
}

#[test]
fn refuses_repo_with_shell_metachar() {
    for bad in [
        "owasp/zap;rm",
        "owasp/zap`id`",
        "owasp/zap$(id)",
        "owasp/zap|id",
    ] {
        let err = ImageRef::parse(&with_digest(bad)).unwrap_err();
        assert!(
            matches!(err, ImageRefError::RepoCharset),
            "expected RepoCharset for {bad:?}, got {err:?}"
        );
    }
}

#[test]
fn refuses_repo_starting_with_dash() {
    let err = ImageRef::parse(&with_digest("-evil/repo")).unwrap_err();
    assert!(matches!(err, ImageRefError::RepoCharset));
}

#[test]
fn refuses_repo_starting_with_dot() {
    let err = ImageRef::parse(&with_digest(".evil/repo")).unwrap_err();
    assert!(matches!(err, ImageRefError::RepoCharset));
}

#[test]
fn refuses_uppercase_in_repo() {
    let err = ImageRef::parse(&with_digest("OWASP/zap2docker")).unwrap_err();
    assert!(matches!(err, ImageRefError::RepoCharset));
}

#[test]
fn refuses_repo_over_255_chars() {
    let long_repo = "a".repeat(260);
    let err = ImageRef::parse(&with_digest(&long_repo)).unwrap_err();
    assert!(matches!(err, ImageRefError::RepoTooLong));
}

#[test]
fn accepts_lowercase_dotted_underscore_repo_with_port() {
    let s = with_digest("registry.example.com:5000/team_one/sub.repo-name");
    ImageRef::parse(&s).expect("valid repo must parse");
}

#[test]
fn accepts_simple_repo() {
    ImageRef::parse(&with_digest("owasp/zap2docker")).expect("simple repo must parse");
}
