//! `zaprun observe --request <file> --target <url>` — typed evidence.
//!
//! Owns the SSRF/IMDS guard for `--target` URLs (per critique F-SEC-4).
//! The actual ZAP-API call happens via reqwest behind the validated boundary.

use std::net::IpAddr;
use std::path::Path;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::error::ZapshootError;
use crate::exit::ExitCode;
use crate::run_meta::canonicalize_run_dir;

const MAX_REQUEST_BODY_BYTES: u64 = 1024 * 1024;
pub const SCHEMA_VERSION: &str = "1.0";

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ObserveTargetError {
    #[error("scheme_unsupported")]
    SchemeUnsupported,
    #[error("imds_blocked")]
    ImdsBlocked,
    #[error("private_net_blocked")]
    PrivateNetBlocked,
    #[error("target_url_parse_error")]
    UrlParseError,
}

#[derive(Debug, Serialize)]
pub struct Observation {
    pub schema_version: String,
    pub finding: Option<String>,
    pub target_url: String,
    pub request_sent: bool,
    pub response_observed: bool,
    pub zap_alerts: Vec<ZapAlert>,
    pub decision_hint: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ZapAlert {
    pub plugin_id: String,
    pub name: String,
    pub risk: String,
    pub confidence: String,
    pub evidence_hash: String,
}

pub struct ObserveOptions {
    pub request: Option<std::path::PathBuf>,
    pub finding: Option<std::path::PathBuf>,
    pub target: String,
    pub output: std::path::PathBuf,
    pub allow_internal_target: bool,
}

pub fn cmd_observe(opts: &ObserveOptions) -> Result<ExitCode, ZapshootError> {
    // Validate the target URL (CWE-918 SSRF + IMDS unconditional block).
    if let Err(e) = validate_observe_target(&opts.target, opts.allow_internal_target) {
        eprintln!("zaprun: {e}");
        return Err(ZapshootError::Io(
            format!("target_host_{e:?}").to_lowercase(),
        ));
    }

    // Spec/file validation for `--request` -- size cap + traversal guard.
    if let Some(p) = &opts.request {
        validate_request_file(p)?;
    }

    let canonical_out = canonicalize_run_dir(&opts.output)?;

    // Without a live ZAP, observe writes a typed "request_sent: false,
    // response_observed: false" outcome.  This is the M5-deferred path; the
    // real reqwest+ZAP-API call lands when a live ZAP is reachable.
    let observation = Observation {
        schema_version: SCHEMA_VERSION.to_string(),
        finding: opts
            .finding
            .as_ref()
            .map(|p| p.to_string_lossy().to_string()),
        target_url: opts.target.clone(),
        request_sent: false,
        response_observed: false,
        zap_alerts: Vec::new(),
        decision_hint: "no_live_zap".to_string(),
        timestamp: Utc::now(),
    };
    std::fs::write(
        canonical_out.join("observations.json"),
        serde_json::to_string_pretty(&observation).map_err(|e| ZapshootError::Io(e.to_string()))?,
    )?;

    // Without a successful request, exit code is `3` (target unavailable).
    Err(ZapshootError::TargetUnreachable)
}

pub fn validate_observe_target(url: &str, allow_internal: bool) -> Result<(), ObserveTargetError> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or(ObserveTargetError::UrlParseError)?;
    if scheme != "http" && scheme != "https" {
        return Err(ObserveTargetError::SchemeUnsupported);
    }
    let host_part = rest.split('/').next().unwrap_or(rest);
    let host = host_part
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(host_part);

    // Try to parse the host as an IP literal.  If it parses, apply the
    // SSRF/IMDS guard.  If not, it is a hostname -- accept (resolution-time
    // checks are out of scope; doing them in MVP1 would require DNS calls
    // here and would slow the CLI; the doctor command is the right place).
    if let Ok(ip) = host.parse::<IpAddr>() {
        return classify_ip(&ip, allow_internal);
    }
    Ok(())
}

fn classify_ip(ip: &IpAddr, allow_internal: bool) -> Result<(), ObserveTargetError> {
    match ip {
        IpAddr::V4(v4) => {
            // 169.254/16 -- link-local + IMDS.  ALWAYS blocked.
            if v4.octets()[0] == 169 && v4.octets()[1] == 254 {
                return Err(ObserveTargetError::ImdsBlocked);
            }
            // RFC1918 + loopback -- blocked unless --allow-internal-target.
            let is_private = v4.is_loopback()
                || v4.octets()[0] == 10
                || (v4.octets()[0] == 172 && (16..32).contains(&v4.octets()[1]))
                || (v4.octets()[0] == 192 && v4.octets()[1] == 168);
            if is_private && !allow_internal {
                return Err(ObserveTargetError::PrivateNetBlocked);
            }
        }
        IpAddr::V6(v6) => {
            // Loopback + link-local + ULA -- blocked unless --allow-internal-target.
            let is_private = v6.is_loopback()
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || (v6.segments()[0] & 0xfe00) == 0xfc00;
            if is_private && !allow_internal {
                return Err(ObserveTargetError::PrivateNetBlocked);
            }
        }
    }
    Ok(())
}

fn validate_request_file(p: &Path) -> Result<(), ZapshootError> {
    let s = p
        .to_str()
        .ok_or_else(|| ZapshootError::Io("request_path_not_utf8".to_string()))?;
    if s.contains("..") {
        return Err(ZapshootError::Io("request_path_unsafe".to_string()));
    }
    let meta =
        std::fs::metadata(p).map_err(|_| ZapshootError::Io("request_not_found".to_string()))?;
    if !meta.is_file() {
        return Err(ZapshootError::Io("request_not_a_file".to_string()));
    }
    if meta.len() > MAX_REQUEST_BODY_BYTES {
        return Err(ZapshootError::Io("request_too_large".to_string()));
    }
    Ok(())
}
