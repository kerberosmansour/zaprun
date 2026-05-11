use crate::report::normalize::NormalizedReport;
use crate::types::Surface;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Target {
    pub url: String,
    pub openapi_path: Option<PathBuf>,
    pub auth: Option<AuthConfig>,
    pub host_network: NetworkConfig,
}

#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub bearer_token: String,
}

#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub add_host_gateway: bool,
}

#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Policy {
    pub rules_tsv_path: PathBuf,
    pub policy_yaml_path: Option<PathBuf>,
    pub custom_scripts_dir: Option<PathBuf>,
    pub timeout: Duration,
}

pub trait Scanner: Send + Sync {
    fn name(&self) -> &'static str;
    fn supported_cwes(&self) -> &[&'static str];
    fn supported_surfaces(&self) -> &[Surface];
    fn run(&self, target: &Target, policy: &Policy) -> Result<NormalizedReport, ScanError>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScannerRunSummary {
    pub scanner: String,
    pub status: ScannerStatus,
    pub alert_count: usize,
    pub high_count: usize,
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScannerStatus {
    Passed,
    Findings,
    Errored,
    TimedOut,
}

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("{0}")]
    Usage(String),
    #[error("{0}")]
    Runtime(String),
    #[error("scanner timed out after {seconds}s")]
    Timeout { seconds: u64 },
}
