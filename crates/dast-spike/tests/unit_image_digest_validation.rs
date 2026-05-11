use dast_spike::types::ImageDigest;

#[test]
fn accepts_valid_sha256_digest() {
    let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    assert!(ImageDigest::try_from(digest).is_ok());
}

#[test]
fn rejects_invalid_sha256_digest() {
    let err = ImageDigest::try_from("not-a-sha").unwrap_err();
    assert!(err.contains("^sha256:[0-9a-f]{64}$"));
}
