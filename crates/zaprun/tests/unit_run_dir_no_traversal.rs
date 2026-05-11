use std::path::Path;
use zaprun::error::ZapshootError;
use zaprun::run_meta::canonicalize_run_dir;

#[test]
fn refuses_relative_with_parent_traversal() {
    let err = canonicalize_run_dir(Path::new("../../etc")).unwrap_err();
    assert!(matches!(
        err,
        ZapshootError::OutputDirNotWritable | ZapshootError::Io(_)
    ));
}

#[test]
fn accepts_absolute_path() {
    let tmp = std::env::temp_dir().join("zaprun-no-traversal-test");
    let _ = std::fs::create_dir_all(&tmp);
    let canonical = canonicalize_run_dir(&tmp).expect("ok");
    assert!(canonical.is_absolute());
    let _ = std::fs::remove_dir_all(&tmp);
}
