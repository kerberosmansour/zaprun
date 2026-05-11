use std::fs;
use tempfile::tempdir;
use zaprun::run_meta::{RunMeta, SCHEMA_VERSION};

#[test]
fn run_meta_generates_random_api_key_per_run() {
    let m1 = RunMeta::new_with_random_api_key("ghcr.io/zap@sha256:aaa");
    let m2 = RunMeta::new_with_random_api_key("ghcr.io/zap@sha256:aaa");
    assert_eq!(m1.api_key.expose_secret().len(), 64); // 32 bytes -> 64 hex chars
    assert_ne!(
        m1.api_key.expose_secret(),
        m2.api_key.expose_secret(),
        "API keys must be unique per run"
    );
}

#[test]
fn run_meta_api_key_is_lowercase_hex() {
    let m = RunMeta::new_with_random_api_key("ghcr.io/zap@sha256:aaa");
    let key = m.api_key.expose_secret();
    assert!(key
        .chars()
        .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
}

#[test]
fn run_meta_api_key_redacted_in_debug_output() {
    let m = RunMeta::new_with_random_api_key("ghcr.io/zap@sha256:aaa");
    let dbg = format!("{:?}", m.api_key);
    let key = m.api_key.expose_secret();
    assert!(
        !dbg.contains(key),
        "Debug output must not leak the API key. Got: {dbg}"
    );
}

#[test]
fn run_meta_writes_with_mode_0600() {
    let dir = tempdir().unwrap();
    let m = RunMeta::new_with_random_api_key("ghcr.io/zap@sha256:aaa");
    let path = dir.path().join("run.json");
    m.write_to(&path).expect("write succeeds");
    let meta = fs::metadata(&path).expect("metadata");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "run.json must be mode 0600 (got {:o})", mode);
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
    }
}

#[test]
fn run_meta_round_trips_schema_v1() {
    let m = RunMeta::new_with_random_api_key("ghcr.io/zap@sha256:aaa");
    assert_eq!(m.schema_version, SCHEMA_VERSION);
    let json = serde_json::to_string(&m).expect("serialize");
    let parsed: RunMeta = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed.schema_version, "1.0");
    assert_eq!(parsed.api_key.expose_secret(), m.api_key.expose_secret());
}

#[test]
fn run_meta_serialized_form_does_not_double_redact() {
    // While Debug redacts the SecretString, the persisted JSON for run.json
    // must contain the actual key (because the observe client reads it back).
    // Confidentiality comes from the file mode (0600), not from the JSON shape.
    let m = RunMeta::new_with_random_api_key("ghcr.io/zap@sha256:aaa");
    let json = serde_json::to_string(&m).expect("serialize");
    let key = m.api_key.expose_secret();
    assert!(
        json.contains(key),
        "JSON must include the actual API key for the observe client; \
         confidentiality is provided by file mode 0600"
    );
}
