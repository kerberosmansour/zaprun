//! Regression tests for ImageRef parsing — both bare digest and full
//! `<repo>@<digest>` forms must work, since CI workflows emit the full form
//! when resolving from a local-build path and the pin file emits the bare
//! form.

use dast_spike::types::ImageRef;

const VALID_HEX: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn accepts_bare_digest() {
    let r = ImageRef::try_from(format!("sha256:{VALID_HEX}").as_str()).unwrap();
    assert_eq!(r.repo(), None);
    assert_eq!(r.digest().as_str(), format!("sha256:{VALID_HEX}"));
    assert_eq!(
        r.full_ref("ghcr.io/example/img"),
        format!("ghcr.io/example/img@sha256:{VALID_HEX}")
    );
}

#[test]
fn accepts_full_ref_with_repo_at_digest() {
    let input = format!("ghcr.io/kerberosmansour/zaprun@sha256:{VALID_HEX}");
    let r = ImageRef::try_from(input.as_str()).unwrap();
    assert_eq!(r.repo(), Some("ghcr.io/kerberosmansour/zaprun"));
    assert_eq!(r.digest().as_str(), format!("sha256:{VALID_HEX}"));
    // full_ref MUST use the parsed repo, not the default.
    assert_eq!(r.full_ref("ignored.default/repo"), input);
}

#[test]
fn accepts_local_repo_for_ci_local_build() {
    let input = format!("localhost:5000/zaprun@sha256:{VALID_HEX}");
    let r = ImageRef::try_from(input.as_str()).unwrap();
    assert_eq!(r.repo(), Some("localhost:5000/zaprun"));
    assert_eq!(r.full_ref("ghcr.io/canonical/repo"), input);
}

#[test]
fn rejects_empty_repo_before_at_sign() {
    let err = ImageRef::try_from(format!("@sha256:{VALID_HEX}").as_str()).unwrap_err();
    assert!(err.contains("repo"), "error should mention repo: {err}");
}

#[test]
fn rejects_invalid_digest_in_bare_form() {
    let err = ImageRef::try_from("not-a-sha").unwrap_err();
    assert!(err.contains("^sha256:"));
}

#[test]
fn rejects_invalid_digest_in_full_form() {
    let err = ImageRef::try_from("ghcr.io/example/img@not-a-sha").unwrap_err();
    assert!(err.contains("^sha256:"));
}

#[test]
fn rejects_digest_with_wrong_hex_length() {
    let short = "sha256:aaaa";
    let err = ImageRef::try_from(short).unwrap_err();
    assert!(err.contains("^sha256:"));
}

#[test]
fn last_at_sign_is_the_separator_so_repo_containing_at_is_handled() {
    // While image repos with '@' are uncommon, rsplit_once('@') means the
    // last '@' is the separator; everything before is the repo. This is the
    // correct OCI ref behavior.
    let input = format!("registry@example/img@sha256:{VALID_HEX}");
    let r = ImageRef::try_from(input.as_str()).unwrap();
    assert_eq!(r.repo(), Some("registry@example/img"));
    assert_eq!(r.digest().as_str(), format!("sha256:{VALID_HEX}"));
}
