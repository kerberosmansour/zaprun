use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::ZapshootError;

pub const SCHEMA_VERSION: &str = "1.0";

/// Snapshot of what the runtime can do, written to `<run-dir>/capabilities.json`.
/// Schema is stable for MVP1 (v1.0); every field is required to be serializable
/// with default values for missing optional probes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitiesReport {
    pub schema_version: String,
    pub backend: String,
    pub docker: DockerProbe,
    pub image: ImageProbe,
    pub output_dir: OutputDirProbe,
    pub target: Option<TargetProbe>,
    pub java: Option<JavaProbe>,
    pub browser: Option<BrowserProbe>,
    pub partial: bool,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DockerProbe {
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageProbe {
    pub pinned: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputDirProbe {
    pub writable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetProbe {
    pub url: String,
    pub reachable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JavaProbe {
    pub available: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserProbe {
    pub firefox_in_path: bool,
    pub geckodriver_in_path: bool,
}

impl CapabilitiesReport {
    pub fn from_json_strict(s: &str) -> Result<Self, ZapshootError> {
        let raw: serde_json::Value =
            serde_json::from_str(s).map_err(|e| ZapshootError::Io(e.to_string()))?;
        let version = raw
            .get("schema_version")
            .and_then(|v| v.as_str())
            .ok_or(ZapshootError::UnsupportedSchemaVersion)?;
        if version != SCHEMA_VERSION {
            return Err(ZapshootError::UnsupportedSchemaVersion);
        }
        serde_json::from_value(raw).map_err(|e| ZapshootError::Io(e.to_string()))
    }

    /// Sample value used by tests; contains realistic shape under the 16 KiB cap.
    pub fn sample_for_tests() -> Self {
        let now = Utc::now();
        CapabilitiesReport {
            schema_version: SCHEMA_VERSION.to_string(),
            backend: "docker".to_string(),
            docker: DockerProbe {
                available: true,
                error: None,
            },
            image: ImageProbe {
                pinned: true,
                repo: Some("ghcr.io/kerberosmansour/zaprun".to_string()),
                sha256: Some("a".repeat(64)),
                error: None,
            },
            output_dir: OutputDirProbe {
                writable: true,
                error: None,
            },
            target: Some(TargetProbe {
                url: "http://127.0.0.1:3000".into(),
                reachable: true,
                error: None,
            }),
            java: Some(JavaProbe { available: false }),
            browser: Some(BrowserProbe {
                firefox_in_path: false,
                geckodriver_in_path: false,
            }),
            partial: false,
            started_at: now,
            finished_at: now,
        }
    }
}
