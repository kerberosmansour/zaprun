//! `zaprun observe --request <file> --target <url>` — typed evidence.
//!
//! Owns the SSRF/IMDS guard for `--target` URLs (per critique F-SEC-4).
//! The actual ZAP-API call happens via reqwest behind the validated boundary.

use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

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
    pub request_path: Option<String>,
    pub http_status: Option<u16>,
    pub response_body_hash: Option<String>,
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

    let replay = if let Some(p) = &opts.request {
        let request = parse_raw_request(&std::fs::read(p)?)?;
        Some(replay_raw_request(&opts.target, &request)?)
    } else {
        None
    };

    let observation = Observation {
        schema_version: SCHEMA_VERSION.to_string(),
        finding: opts
            .finding
            .as_ref()
            .map(|p| p.to_string_lossy().to_string()),
        target_url: opts.target.clone(),
        request_sent: replay.is_some(),
        response_observed: replay.is_some(),
        request_path: replay.as_ref().map(|replay| replay.request_path.clone()),
        http_status: replay.as_ref().map(|replay| replay.status),
        response_body_hash: replay
            .as_ref()
            .map(|replay| evidence_hash(&replay.response_body)),
        zap_alerts: Vec::new(),
        decision_hint: if replay.is_some() {
            "http_observed".to_string()
        } else {
            "no_request_fixture".to_string()
        },
        timestamp: Utc::now(),
    };
    std::fs::write(
        canonical_out.join("observations.json"),
        serde_json::to_string_pretty(&observation).map_err(|e| ZapshootError::Io(e.to_string()))?,
    )?;

    if replay.is_some() {
        Ok(ExitCode::Pass)
    } else {
        Err(ZapshootError::TargetUnreachable)
    }
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

#[derive(Debug)]
struct RawRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

#[derive(Debug)]
struct ReplayOutcome {
    request_path: String,
    status: u16,
    response_body: Vec<u8>,
}

fn parse_raw_request(bytes: &[u8]) -> Result<RawRequest, ZapshootError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| ZapshootError::Io("request_not_utf8".to_string()))?;
    let (head, body) = text
        .split_once("\r\n\r\n")
        .or_else(|| text.split_once("\n\n"))
        .unwrap_or((text, ""));
    let mut lines = head.lines();
    let request_line = lines
        .next()
        .ok_or_else(|| ZapshootError::Io("request_line_missing".to_string()))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| ZapshootError::Io("request_method_missing".to_string()))?;
    let path = parts
        .next()
        .ok_or_else(|| ZapshootError::Io("request_path_missing".to_string()))?;
    if !path.starts_with('/') || path.contains("://") {
        return Err(ZapshootError::Io(
            "request_path_must_be_origin_form".to_string(),
        ));
    }

    let mut headers = Vec::new();
    for line in lines {
        let line = line.trim_end_matches('\r');
        if line.trim().is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(ZapshootError::Io("request_header_invalid".to_string()));
        };
        let name = name.trim();
        if name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("connection")
        {
            continue;
        }
        headers.push((name.to_string(), value.trim().to_string()));
    }

    Ok(RawRequest {
        method: method.to_string(),
        path: path.to_string(),
        headers,
        body: body.as_bytes().to_vec(),
    })
}

fn replay_raw_request(target: &str, request: &RawRequest) -> Result<ReplayOutcome, ZapshootError> {
    let mut url = reqwest::Url::parse(target)
        .map_err(|_| ZapshootError::Io("target_url_parse_error".to_string()))?;
    let (path, query) = request
        .path
        .split_once('?')
        .map(|(path, query)| (path, Some(query)))
        .unwrap_or((request.path.as_str(), None));
    url.set_path(path);
    url.set_query(query);

    let method = reqwest::Method::from_bytes(request.method.as_bytes())
        .map_err(|_| ZapshootError::Io("request_method_invalid".to_string()))?;
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|err| ZapshootError::Io(err.to_string()))?;
    let mut builder = client.request(method, url);
    for (name, value) in &request.headers {
        let header_name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| ZapshootError::Io("request_header_invalid".to_string()))?;
        let header_value = reqwest::header::HeaderValue::from_str(value)
            .map_err(|_| ZapshootError::Io("request_header_invalid".to_string()))?;
        builder = builder.header(header_name, header_value);
    }
    let response = builder
        .body(request.body.clone())
        .send()
        .map_err(|_| ZapshootError::TargetUnreachable)?;
    let status = response.status().as_u16();
    let response_body = response
        .bytes()
        .map_err(|err| ZapshootError::Io(err.to_string()))?
        .to_vec();

    Ok(ReplayOutcome {
        request_path: request.path.clone(),
        status,
        response_body,
    })
}

fn evidence_hash(bytes: &[u8]) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    bytes.hash(&mut hasher);
    format!("hash:{:016x}", hasher.finish())
}
