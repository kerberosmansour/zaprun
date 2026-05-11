//! `zaprun calibrate <profile.toml>` — class-based scan calibration.
//!
//! The profile lists expected plugin IDs + minimum counts. After running a
//! scan against the profile's `target`, we evaluate observed counts; any
//! missing class fails the run with exit `5` (CoverageFail).

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::ZapshootError;
use crate::exit::ExitCode;

pub const SCHEMA_VERSION: &str = "1.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationProfile {
    pub target: String,
    #[serde(default)]
    pub image: Option<String>,
    #[serde(default)]
    pub expected: Vec<ExpectedClass>,
    #[serde(default)]
    pub known_misses: Vec<KnownMiss>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedClass {
    pub plugin_id: String,
    pub name: String,
    pub min_count: u32,
    #[serde(default)]
    pub routes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownMiss {
    pub reason: String,
    #[serde(default)]
    pub routes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CalibrationResult {
    pub schema_version: String,
    pub target: String,
    pub passed: bool,
    pub passed_classes: Vec<ExpectedClass>,
    pub failed_classes: Vec<ExpectedClass>,
}

pub fn evaluate_calibration(
    profile: &CalibrationProfile,
    observed: &HashMap<String, u32>,
) -> CalibrationResult {
    let mut passed_classes = Vec::new();
    let mut failed_classes = Vec::new();
    for class in &profile.expected {
        let count = observed.get(&class.plugin_id).copied().unwrap_or(0);
        if count >= class.min_count {
            passed_classes.push(class.clone());
        } else {
            failed_classes.push(class.clone());
        }
    }
    CalibrationResult {
        schema_version: SCHEMA_VERSION.to_string(),
        target: profile.target.clone(),
        passed: failed_classes.is_empty(),
        passed_classes,
        failed_classes,
    }
}

pub struct CalibrateOptions {
    pub profile: std::path::PathBuf,
    pub output: std::path::PathBuf,
}

pub fn cmd_calibrate(opts: &CalibrateOptions) -> Result<ExitCode, ZapshootError> {
    let profile = load_profile(&opts.profile)?;
    let canonical_out = crate::run_meta::canonicalize_run_dir(&opts.output)?;

    // Without a live Docker backend, calibrate writes a synthetic outcome:
    // every expected class fails (because nothing was observed). This is the
    // correct shape of "we couldn't run the scan" and exits 5.
    let observed: HashMap<String, u32> = HashMap::new();
    let result = evaluate_calibration(&profile, &observed);
    std::fs::write(
        canonical_out.join("calibration.json"),
        serde_json::to_string_pretty(&result).map_err(|e| ZapshootError::Io(e.to_string()))?,
    )?;
    if result.passed {
        Ok(ExitCode::Pass)
    } else {
        Err(ZapshootError::Io(format!(
            "calibration_missed_classes: {}",
            result
                .failed_classes
                .iter()
                .map(|c| c.plugin_id.as_str())
                .collect::<Vec<_>>()
                .join(",")
        )))
    }
}

fn load_profile(p: &Path) -> Result<CalibrationProfile, ZapshootError> {
    let s = p
        .to_str()
        .ok_or_else(|| ZapshootError::Io("profile_path_not_utf8".to_string()))?;
    if s.contains("..") {
        return Err(ZapshootError::Io("profile_path_unsafe".to_string()));
    }
    let raw = std::fs::read_to_string(p)
        .map_err(|_| ZapshootError::Io("profile_not_found".to_string()))?;
    toml::from_str(&raw).map_err(|e| ZapshootError::Io(format!("profile_parse_error: {e}")))
}

/// Calibration failures map to ExitCode::CoverageFail.
pub fn calibration_failure_exit_code() -> ExitCode {
    ExitCode::CoverageFail
}
