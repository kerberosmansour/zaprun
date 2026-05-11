use crate::{Result, RulesError};
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub schema_version: String,
    pub generated_at: String,
    pub generated_by_dast_spike_version: String,
    pub image_digest: String,
    pub upstream_image_digest: String,
    #[serde(default)]
    pub threat_model_sha: Option<String>,
    #[serde(default)]
    pub cwes_claimed: Vec<String>,
    #[serde(default)]
    pub cwes_actually_covered: Vec<String>,
    #[serde(default)]
    pub cwes_uncovered: Vec<String>,
    #[serde(default)]
    pub coverage_gaps: Vec<CoverageGap>,
    #[serde(default)]
    pub detected_stack: Vec<String>,
    pub detected_surface: String,
    pub detected_auth: String,
    #[serde(default)]
    pub selected_scanners: Vec<String>,
    #[serde(default)]
    pub selected_rules: Vec<SelectedRule>,
    pub selection_strategy: String,
    #[serde(default)]
    pub findings_summary: Option<FindingsSummary>,
    #[serde(default)]
    pub baseline_summary: Option<BaselineManifestSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoverageGap {
    pub cwe: String,
    pub reason: String,
    pub stack: String,
    pub candidate_scripts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SelectedRule {
    pub id: String,
    pub source: String,
    pub level: String,
    #[serde(default)]
    pub metadata_cwe: Vec<String>,
    #[serde(default)]
    pub script_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct FindingsSummary {
    pub total: usize,
    pub dast_detectable: usize,
    pub dast_now_covered: usize,
    pub dast_not_applicable: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BaselineManifestSummary {
    pub total_suppressions: usize,
    pub expired: usize,
    pub expiring_within_30_days: usize,
}

impl Manifest {
    pub fn m1(image_digest: String, upstream_image_digest: String, generated_at: String) -> Self {
        Self {
            schema:
                "https://github.com/kerberosmansour/zaprun/blob/main/schema/manifest-v1.json"
                    .to_string(),
            schema_version: "1.0".to_string(),
            generated_at,
            generated_by_dast_spike_version: env!("CARGO_PKG_VERSION").to_string(),
            image_digest,
            upstream_image_digest,
            threat_model_sha: None,
            cwes_claimed: Vec::new(),
            cwes_actually_covered: Vec::new(),
            cwes_uncovered: Vec::new(),
            coverage_gaps: Vec::new(),
            detected_stack: vec!["rust".to_string()],
            detected_surface: "api-openapi".to_string(),
            detected_auth: "jwt-bearer".to_string(),
            selected_scanners: vec!["zap".to_string()],
            selected_rules: Vec::new(),
            selection_strategy: "default-fallback".to_string(),
            findings_summary: None,
            baseline_summary: None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        let digest_re = Regex::new(r"^sha256:[0-9a-f]{64}$").map_err(|err| {
            RulesError::Validation(format!("internal digest regex failed to compile: {err}"))
        })?;
        if !digest_re.is_match(&self.image_digest) {
            return Err(RulesError::Validation(
                "image_digest must match ^sha256:[0-9a-f]{64}$".to_string(),
            ));
        }
        if !digest_re.is_match(&self.upstream_image_digest) {
            return Err(RulesError::Validation(
                "upstream_image_digest must match ^sha256:[0-9a-f]{64}$".to_string(),
            ));
        }
        if let Some(sha) = &self.threat_model_sha {
            let sha_re = Regex::new(r"^[0-9a-f]{40}$").map_err(|err| {
                RulesError::Validation(format!("internal sha regex failed to compile: {err}"))
            })?;
            if !sha_re.is_match(sha) {
                return Err(RulesError::Validation(
                    "threat_model_sha must match ^[0-9a-f]{40}$".to_string(),
                ));
            }
        }
        Ok(())
    }
}
