//! `zaprun ptk <url>` -- OWASP PTK Phase 1 orchestration.
//!
//! PTK Phase 1 runs through ZAP's Client Spider. The image must already have
//! the Client Side Integration and PTK add-ons baked in; this module never
//! emits runtime Marketplace install jobs.

use std::path::Path;
use std::time::Duration;

use chrono::Utc;
use secure_data::secret::SecretString;

use crate::backend::{Backend, DockerBackend, RunOptions};
use crate::coverage::Coverage;
use crate::doctor::{run_doctor, DoctorOptions};
use crate::error::ZapshootError;
use crate::exit::ExitCode;
use crate::image_ref::ImageRef;
use crate::plan::{Job, Plan, PtkConfig};
use crate::report::normalize::{normalize_zap_report, RawZapReport, Summary};
use crate::report::sarif::emit_sarif;
use crate::run_meta::{canonicalize_run_dir, RunMeta};

const DEFAULT_ZAP_IMAGE: &str =
    "zaprun@sha256:9a0f117fa3be7e6493a4f81268742174758f91604e1d948074204cb0bef40711";

pub struct PtkOptions {
    pub url: String,
    pub browser_id: String,
    pub browsers: u64,
    pub max_duration: String,
    pub output: std::path::PathBuf,
    pub image: Option<String>,
    pub scan_timeout: String,
    pub dry_run: bool,
}

pub fn cmd_ptk(opts: &PtkOptions) -> Result<ExitCode, ZapshootError> {
    if !crate::scan_url::validate_scheme_only(opts.url.as_str()) {
        eprintln!("zaprun: target_scheme_unsupported: only http(s) targets are accepted");
        return Err(ZapshootError::Io("target_scheme_unsupported".to_string()));
    }

    let canonical_out = canonicalize_run_dir(&opts.output)?;
    let max_duration = parse_duration(&opts.max_duration)?;
    let plan = ptk_phase1_plan(
        &opts.url,
        &opts.browser_id,
        max_duration.as_secs(),
        opts.browsers,
    )?;
    let yaml = plan
        .to_yaml()
        .map_err(|e| ZapshootError::Io(e.to_string()))?;
    std::fs::write(canonical_out.join("plan.yaml"), yaml)?;

    let image = ImageRef::parse(opts.image.as_deref().unwrap_or(DEFAULT_ZAP_IMAGE))?;
    let scan_timeout = parse_duration(&opts.scan_timeout)?;

    let mut meta = RunMeta::new_with_random_api_key(&image.as_canonical_string());
    meta.plan_path = Some(canonical_out.join("plan.yaml"));
    meta.write_to(&canonical_out.join("run.json"))?;

    if opts.dry_run {
        return Ok(ExitCode::Pass);
    }

    let _ = run_doctor(&DoctorOptions {
        backend: "docker".to_string(),
        image: Some(image.as_canonical_string()),
        probe_target: None,
        output: canonical_out.clone(),
    });

    let backend = DockerBackend::new(image);
    let outcome = backend.run(
        &canonical_out.join("plan.yaml"),
        &canonical_out,
        &RunOptions {
            api_key: expose_secret(&meta.api_key),
            scan_timeout,
            browser_id: Some(opts.browser_id.clone()),
        },
    )?;

    meta.finished_at = Some(Utc::now());
    meta.exit_code = Some(outcome.exit_code);
    meta.exit_reason = Some(outcome.exit_reason.clone());
    meta.write_to(&canonical_out.join("run.json"))?;

    let report_bytes = std::fs::read(canonical_out.join("zap-report.json"))
        .map_err(|e| ZapshootError::Io(format!("zap_report_missing: {e}")))?;
    let raw = RawZapReport::from_slice(&report_bytes)
        .map_err(|e| ZapshootError::Io(format!("zap_report_parse: {e}")))?;
    let duration_seconds = meta
        .finished_at
        .map(|finished| (finished - meta.started_at).num_seconds().max(0) as u64)
        .unwrap_or(0);
    let fallback_url_count = raw.unique_instance_url_count();
    let client_urls = parse_client_spider_count(&canonical_out.join("zap.log"), fallback_url_count);

    let mut summary = normalize_zap_report(&raw, client_urls, client_urls, duration_seconds);
    summary.warnings.push("ptk_phase1=true".to_string());
    if outcome.log_truncated {
        summary
            .warnings
            .push("zap_log_ring_truncated=true".to_string());
    }
    write_summary(&canonical_out, &summary)?;

    let coverage = Coverage::for_ptk_phase1_browser(client_urls);
    write_coverage(&canonical_out, &coverage)?;

    let alerts = raw.flattened_alerts();
    let sarif = emit_sarif("zaprun", env!("CARGO_PKG_VERSION"), &alerts)
        .map_err(|e| ZapshootError::Io(e.to_string()))?;
    std::fs::write(canonical_out.join("zap.sarif"), sarif)?;

    if summary.high_count > 0 || outcome.exit_code == 1 {
        Ok(ExitCode::PolicyFail)
    } else {
        Ok(ExitCode::Pass)
    }
}

pub fn ptk_phase1_plan(
    target: &str,
    browser_id: &str,
    max_duration_seconds: u64,
    number_of_browsers: u64,
) -> Result<Plan, ZapshootError> {
    Plan::builder()
        .context("default", target)
        .ci_mode(true)
        .ptk_config(PtkConfig::phase1())
        .job(Job::SpiderClient {
            url: target.to_string(),
            browser_id: browser_id.to_string(),
            max_duration_seconds,
            number_of_browsers,
        })
        .job(Job::PassiveScanWait {
            max_duration_seconds: 60,
        })
        .job(Job::Report {
            template: "traditional-json".to_string(),
            file: "zap-report.json".to_string(),
        })
        .job(Job::Report {
            template: "traditional-html".to_string(),
            file: "zap-report.html".to_string(),
        })
        .job(Job::ExitStatus {
            error_level: "high".to_string(),
            warn_level: "medium".to_string(),
        })
        .build()
        .map_err(Into::into)
}

fn parse_client_spider_count(log_path: &Path, fallback_urls: u32) -> u32 {
    let log = std::fs::read_to_string(log_path).unwrap_or_default();
    parse_last_count(&log, "Job spiderClient found ").unwrap_or(fallback_urls)
}

fn parse_last_count(log: &str, prefix: &str) -> Option<u32> {
    log.lines().rev().find_map(|line| {
        let rest = line.strip_prefix(prefix)?;
        let count = rest.strip_suffix(" URLs")?;
        count.parse::<u32>().ok()
    })
}

fn write_summary(run_dir: &Path, summary: &Summary) -> Result<(), ZapshootError> {
    std::fs::write(
        run_dir.join("summary.json"),
        serde_json::to_string_pretty(summary).map_err(|e| ZapshootError::Io(e.to_string()))?,
    )?;
    Ok(())
}

fn write_coverage(run_dir: &Path, coverage: &Coverage) -> Result<(), ZapshootError> {
    std::fs::write(
        run_dir.join("coverage.json"),
        serde_json::to_string_pretty(coverage).map_err(|e| ZapshootError::Io(e.to_string()))?,
    )?;
    Ok(())
}

fn expose_secret(secret: &SecretString) -> String {
    secret.expose_secret().to_string()
}

fn parse_duration(s: &str) -> Result<Duration, ZapshootError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(ZapshootError::Io("duration_empty".to_string()));
    }
    let (number, multiplier) = match s.as_bytes().last().copied() {
        Some(b's') | Some(b'S') => (&s[..s.len() - 1], 1),
        Some(b'm') | Some(b'M') => (&s[..s.len() - 1], 60),
        Some(b'h') | Some(b'H') => (&s[..s.len() - 1], 60 * 60),
        Some(b'0'..=b'9') => (s, 1),
        _ => return Err(ZapshootError::Io("duration_invalid".to_string())),
    };
    let value = number
        .parse::<u64>()
        .map_err(|_| ZapshootError::Io("duration_invalid".to_string()))?;
    Ok(Duration::from_secs(value.saturating_mul(multiplier)))
}
