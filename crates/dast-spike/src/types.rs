use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ImageDigest(String);

impl ImageDigest {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for ImageDigest {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let re = Regex::new(r"^sha256:[0-9a-f]{64}$")
            .map_err(|err| format!("internal digest regex failed: {err}"))?;
        if re.is_match(value) {
            Ok(Self(value.to_string()))
        } else {
            Err("image digest must match ^sha256:[0-9a-f]{64}$".to_string())
        }
    }
}

impl fmt::Display for ImageDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A complete OCI image reference: optional repo + required digest.
///
/// Accepts two input forms via `TryFrom<&str>`:
/// * Bare digest `sha256:<64-hex>` — `repo` is `None`; callers combine with a
///   canonical default repo via `full_ref(default_repo)`.
/// * Full ref `<repo>@sha256:<64-hex>` — `repo` is `Some(repo)` and is used
///   verbatim. This is the form CI workflows emit when the canonical pin is
///   not yet available and the image lives at a non-canonical location
///   (local-only build, local registry, mirror).
///
/// The bare-digest form preserves backwards compatibility with
/// `references/zap-image-pin.toml`, where `digest = "sha256:..."` is stored
/// without a repo prefix.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ImageRef {
    repo: Option<String>,
    digest: ImageDigest,
}

impl ImageRef {
    pub fn from_digest(digest: ImageDigest) -> Self {
        Self { repo: None, digest }
    }

    pub fn digest(&self) -> &ImageDigest {
        &self.digest
    }

    pub fn repo(&self) -> Option<&str> {
        self.repo.as_deref()
    }

    /// Render as `<repo>@<digest>`. If `self.repo` is `None`, falls back to
    /// the provided `default_repo`. The result is suitable for passing to
    /// `docker run`.
    pub fn full_ref(&self, default_repo: &str) -> String {
        let repo = self.repo.as_deref().unwrap_or(default_repo);
        format!("{repo}@{}", self.digest.as_str())
    }
}

impl TryFrom<&str> for ImageRef {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if let Some((repo, digest_str)) = value.rsplit_once('@') {
            if repo.is_empty() {
                return Err("image reference repo (before '@') must not be empty".to_string());
            }
            let digest = ImageDigest::try_from(digest_str)?;
            Ok(Self {
                repo: Some(repo.to_string()),
                digest,
            })
        } else {
            let digest = ImageDigest::try_from(value)?;
            Ok(Self::from_digest(digest))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ZapRuleId(String);

impl TryFrom<&str> for ZapRuleId {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if !value.is_empty() && value.chars().all(|ch| ch.is_ascii_digit()) {
            Ok(Self(value.to_string()))
        } else {
            Err("ZAP rule id must be a non-empty digit string".to_string())
        }
    }
}

impl fmt::Display for ZapRuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn from_zap_risk_code(code: i64) -> Option<Self> {
        match code {
            0 => Some(Self::Info),
            1 => Some(Self::Low),
            2 => Some(Self::Medium),
            3 => Some(Self::High),
            4 => Some(Self::Critical),
            _ => None,
        }
    }

    pub fn is_high_or_worse(self) -> bool {
        matches!(self, Self::High | Self::Critical)
    }

    pub fn as_sarif_level(self) -> &'static str {
        match self {
            Self::Critical | Self::High => "error",
            Self::Medium => "warning",
            Self::Low | Self::Info => "note",
        }
    }
}

impl FromStr for Severity {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "informational" | "info" => Ok(Self::Info),
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            other => Err(format!("unsupported severity: {other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Surface {
    ApiOpenapi,
    ApiGraphql,
    WebSpa,
    WebMpa,
    UnknownFallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Stack {
    Rust,
    Javascript,
    Typescript,
    Python,
    Go,
    Java,
    Ruby,
    Php,
    Swift,
}
