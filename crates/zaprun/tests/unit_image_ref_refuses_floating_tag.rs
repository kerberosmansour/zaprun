use zaprun::image_ref::{ImageRef, ImageRefError};

#[test]
fn refuses_tag_only_reference() {
    let err = ImageRef::parse("owasp/zap2docker:stable").unwrap_err();
    assert!(matches!(err, ImageRefError::NotDigest));
}

#[test]
fn refuses_repo_only_reference() {
    let err = ImageRef::parse("owasp/zap2docker").unwrap_err();
    assert!(matches!(err, ImageRefError::NotDigest));
}

#[test]
fn refuses_short_digest() {
    let err = ImageRef::parse("owasp/zap2docker@sha256:abc").unwrap_err();
    assert!(matches!(err, ImageRefError::DigestMalformed));
}

#[test]
fn refuses_non_hex_digest() {
    let s = format!("owasp/zap2docker@sha256:{}", "z".repeat(64));
    let err = ImageRef::parse(&s).unwrap_err();
    assert!(matches!(err, ImageRefError::DigestMalformed));
}

#[test]
fn accepts_valid_digest_reference() {
    let s = format!("ghcr.io/kerberosmansour/zaprun@sha256:{}", "a".repeat(64));
    let parsed = ImageRef::parse(&s).expect("valid digest reference must parse");
    let ImageRef::Digest { repo, sha256_hex } = parsed;
    assert_eq!(repo, "ghcr.io/kerberosmansour/zaprun");
    assert_eq!(sha256_hex.len(), 64);
}
