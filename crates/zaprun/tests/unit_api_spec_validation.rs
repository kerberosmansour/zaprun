use std::io::Write;
use tempfile::NamedTempFile;
use zaprun::error::ZapshootError;
use zaprun::scan_api::validate_openapi_spec;

#[test]
fn refuses_missing_spec() {
    let err = validate_openapi_spec("/nonexistent/path/petstore.yaml").unwrap_err();
    assert!(
        matches!(err, ZapshootError::Io(ref s) if s.contains("spec_not_found"))
            || matches!(err, ZapshootError::Io(_))
    );
}

#[test]
fn refuses_oversized_spec() {
    let mut tmp = NamedTempFile::new().unwrap();
    let chunk = vec![b'a'; 1024];
    for _ in 0..(9 * 1024) {
        tmp.write_all(&chunk).unwrap();
    }
    tmp.flush().unwrap();
    let err = validate_openapi_spec(tmp.path().to_str().unwrap()).unwrap_err();
    let msg = match err {
        ZapshootError::Io(s) => s,
        _ => panic!("unexpected variant"),
    };
    assert!(msg.contains("spec_too_large"), "got: {msg}");
}

#[test]
fn accepts_small_spec_file() {
    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(b"openapi: 3.0.0\n").unwrap();
    tmp.flush().unwrap();
    validate_openapi_spec(tmp.path().to_str().unwrap()).expect("valid small spec");
}
