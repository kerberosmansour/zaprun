use zaprun::backend::DockerBackend;
use zaprun::error::ZapshootError;
use zaprun::image_ref::ImageRef;

#[test]
fn backend_constructor_only_takes_image_ref_digest() {
    // The type system enforces this -- DockerBackend::new takes ImageRef, and the
    // only constructor for ImageRef is `parse`, which refuses tag-only inputs.
    let err = ImageRef::parse("owasp/zap2docker:stable").unwrap_err();
    let zerr: ZapshootError = err.into();
    assert!(matches!(zerr, ZapshootError::ImageRefNotDigest));
}

#[test]
fn backend_accepts_pinned_digest() {
    let s = format!("ghcr.io/zap@sha256:{}", "a".repeat(64));
    let r = ImageRef::parse(&s).expect("parses");
    let _backend = DockerBackend::new(r);
}
