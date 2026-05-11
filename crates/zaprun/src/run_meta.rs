//! `run.json` writer + ZAP API key generator.
//!
//! Every run gets a fresh 32-byte cryptographically-random ZAP API key
//! (CWE-306 mitigation).  The key is wrapped in a `secure_data::SecretString`
//! so debug/display formatters auto-redact; the only callers that ever read
//! the cleartext are the supervisor (passes `-config api.key=<hex>` to ZAP)
//! and the M5 observe client (sends `X-ZAP-API-Key` header).
//!
//! Confidentiality of the persisted form comes from the file mode (`0600`)
//! enforced in `RunMeta::write_to`, NOT from a redacted JSON shape.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use secure_data::secret::SecretString;
use serde::{Deserialize, Serialize};

use crate::error::ZapshootError;

pub const SCHEMA_VERSION: &str = "1.0";

#[derive(Debug, Serialize, Deserialize)]
pub struct RunMeta {
    pub schema_version: String,
    pub image: String,
    /// 32-byte hex-encoded ZAP API key.  Confidentiality is provided by the
    /// `0600` file mode of `run.json`; redaction in `Debug` is provided by
    /// `SecretString`.
    #[serde(with = "secret_string_hex")]
    pub api_key: SecretString,
    pub addons: Vec<String>,
    pub plan_path: Option<PathBuf>,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub exit_code: Option<i32>,
    pub exit_reason: Option<String>,
}

impl RunMeta {
    pub fn new_with_random_api_key(image: &str) -> Self {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).expect("invariant: OS CSPRNG always available");
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let key = SecretString::new(hex);
        RunMeta {
            schema_version: SCHEMA_VERSION.to_string(),
            image: image.to_string(),
            api_key: key,
            addons: Vec::new(),
            plan_path: None,
            started_at: Utc::now(),
            finished_at: None,
            exit_code: None,
            exit_reason: None,
        }
    }

    pub fn write_to(&self, path: &Path) -> Result<(), ZapshootError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json =
            serde_json::to_string_pretty(self).map_err(|e| ZapshootError::Io(e.to_string()))?;
        std::fs::write(path, json)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(path, perms)?;
        }
        Ok(())
    }
}

/// Canonicalize `--output` and refuse traversals.
///
/// Rules: must be absolute OR a child of the current working directory.
/// Empty paths and paths whose canonical form leaves the workspace root are
/// rejected with `OutputDirNotWritable`.
pub fn canonicalize_run_dir(p: &Path) -> Result<PathBuf, ZapshootError> {
    if p.as_os_str().is_empty() {
        return Err(ZapshootError::OutputDirNotWritable);
    }
    // If the path doesn't exist yet, create it; canonicalize requires existence.
    std::fs::create_dir_all(p)?;
    let canonical = p.canonicalize().map_err(ZapshootError::from)?;
    if !canonical.is_absolute() {
        return Err(ZapshootError::OutputDirNotWritable);
    }
    // If path is relative-with-traversal, it'll either fail to create above or
    // canonicalize to a path that escapes CWD; guard that case.
    if !p.is_absolute() {
        let cwd = std::env::current_dir().map_err(ZapshootError::from)?;
        let cwd_canon = cwd.canonicalize().map_err(ZapshootError::from)?;
        if !canonical.starts_with(&cwd_canon) {
            return Err(ZapshootError::OutputDirNotWritable);
        }
    }
    Ok(canonical)
}

mod secret_string_hex {
    use secure_data::secret::SecretString;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &SecretString, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(v.expose_secret())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SecretString, D::Error> {
        let s = String::deserialize(d)?;
        Ok(SecretString::new(s))
    }
}
