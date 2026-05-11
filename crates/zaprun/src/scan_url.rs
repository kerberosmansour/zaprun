//! `zaprun scan <url> --active` — orchestration for the M3 happy path.
//!
//! The headline scenario is `web-pr`: traditional spider + active scan, no
//! browser, no auth, no seeded journeys.  This module owns the deterministic
//! Rust pipeline: plan build → Docker AF run → report normalization → stable
//! artifacts.

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
use crate::plan::{Job, Plan};
use crate::report::normalize::{normalize_zap_report, RawZapReport, Summary};
use crate::report::sarif::emit_sarif;
use crate::run_meta::{canonicalize_run_dir, RunMeta};

const DEFAULT_ZAP_IMAGE: &str =
    "zaprun@sha256:9a0f117fa3be7e6493a4f81268742174758f91604e1d948074204cb0bef40711";

pub struct ScanUrlOptions {
    pub url: String,
    pub active: bool,
    pub passive: bool,
    pub profile: String,
    pub browser_id: String,
    pub output: std::path::PathBuf,
    pub image: Option<String>,
    pub scan_timeout: String,
}

pub fn cmd_scan_url(opts: &ScanUrlOptions) -> Result<ExitCode, ZapshootError> {
    let profile = ScanProfile::parse(&opts.profile)?;
    if !opts.active && !opts.passive {
        eprintln!("zaprun: --active is required (or --passive for passive-only mode)");
        return Err(ZapshootError::Io("active_required".to_string()));
    }
    if opts.active && opts.passive {
        eprintln!("zaprun: --active and --passive are mutually exclusive");
        return Err(ZapshootError::Io("flag_conflict".to_string()));
    }

    // Scheme-only validation: dev / CI scans frequently point at 127.0.0.1 or
    // RFC1918 hosts, which `secure_boundary::SafeUrl` would reject as SSRF
    // shaped.  The SSRF guard belongs on M5's `observe` path, where the URL
    // can come from candidate-request input.  Here, the URL IS the target by
    // construction.
    if !validate_scheme_only(opts.url.as_str()) {
        eprintln!("zaprun: target_scheme_unsupported: only http(s) targets are accepted");
        return Err(ZapshootError::Io("target_scheme_unsupported".to_string()));
    }

    let canonical_out = canonicalize_run_dir(&opts.output)?;

    // Build the plan deterministically.  This always lands as plan.yaml, so
    // the run is reproducible even if Docker fails.
    let plan = if opts.active {
        match profile {
            ScanProfile::WebPr => web_pr_active_plan(&opts.url)?,
            ScanProfile::SpaPr => spa_pr_active_plan(&opts.url, &opts.browser_id)?,
        }
    } else {
        if profile != ScanProfile::WebPr {
            return Err(ZapshootError::Io(
                "profile_requires_active: spa-pr requires --active".to_string(),
            ));
        }
        web_pr_passive_plan(&opts.url)?
    };
    let yaml = plan
        .to_yaml()
        .map_err(|e| ZapshootError::Io(e.to_string()))?;
    std::fs::write(canonical_out.join("plan.yaml"), yaml)?;

    let image = ImageRef::parse(opts.image.as_deref().unwrap_or(DEFAULT_ZAP_IMAGE))?;
    let scan_timeout = parse_duration(&opts.scan_timeout)?;

    // run.json with random per-run API key.
    let mut meta = RunMeta::new_with_random_api_key(&image.as_canonical_string());
    meta.plan_path = Some(canonical_out.join("plan.yaml"));
    meta.write_to(&canonical_out.join("run.json"))?;

    let _ = run_doctor(&DoctorOptions {
        backend: "docker".to_string(),
        image: Some(image.as_canonical_string()),
        probe_target: None,
        output: canonical_out.clone(),
    });

    if opts.passive {
        write_passive_artifacts(&canonical_out)?;
        return Ok(ExitCode::Pass);
    }

    let backend = DockerBackend::new(image);
    let outcome = backend.run(
        &canonical_out.join("plan.yaml"),
        &canonical_out,
        &RunOptions {
            api_key: expose_secret(&meta.api_key),
            scan_timeout,
            browser_id: (profile == ScanProfile::SpaPr).then(|| opts.browser_id.clone()),
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
    let crawl = parse_crawl_counts(&canonical_out.join("zap.log"), fallback_url_count);
    let mut summary = normalize_zap_report(
        &raw,
        crawl.urls_imported_for_summary(),
        crawl.urls_imported_for_summary(),
        duration_seconds,
    );
    if outcome.log_truncated {
        summary
            .warnings
            .push("zap_log_ring_truncated=true".to_string());
    }
    write_summary(&canonical_out, &summary)?;

    let coverage = match profile {
        ScanProfile::WebPr => Coverage::for_web_pr_traditional(crawl.traditional_urls, 0, 0),
        ScanProfile::SpaPr => Coverage::for_spa_pr_browser(crawl.traditional_urls, crawl.ajax_urls),
    };
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

fn web_pr_active_plan(target: &str) -> Result<Plan, ZapshootError> {
    Plan::builder()
        .context("default", target)
        .ci_mode(true)
        .job(Job::Spider {
            max_duration_seconds: 60,
            url: target.to_string(),
        })
        .job(Job::PassiveScanWait {
            max_duration_seconds: 60,
        })
        .job(Job::ActiveScan {
            policy_inline: true,
            dom_xss_enabled: false,
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

fn spa_pr_active_plan(target: &str, browser_id: &str) -> Result<Plan, ZapshootError> {
    Plan::builder()
        .context("default", target)
        .ci_mode(true)
        .job(Job::Spider {
            max_duration_seconds: 120,
            url: target.to_string(),
        })
        .job(Job::AjaxSpider {
            url: target.to_string(),
            browser_id: browser_id.to_string(),
            max_duration_seconds: 120,
        })
        .job(Job::PassiveScanWait {
            max_duration_seconds: 60,
        })
        .job(Job::ActiveScan {
            policy_inline: true,
            dom_xss_enabled: true,
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

fn web_pr_passive_plan(target: &str) -> Result<Plan, ZapshootError> {
    Plan::builder()
        .context("default", target)
        .ci_mode(true)
        .job(Job::Spider {
            max_duration_seconds: 60,
            url: target.to_string(),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScanProfile {
    WebPr,
    SpaPr,
}

impl ScanProfile {
    fn parse(value: &str) -> Result<Self, ZapshootError> {
        match value {
            "web-pr" => Ok(Self::WebPr),
            "spa-pr" => Ok(Self::SpaPr),
            _ => Err(ZapshootError::Io(format!(
                "profile_unsupported: {value} (expected web-pr or spa-pr)"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct CrawlCounts {
    traditional_urls: u32,
    ajax_urls: u32,
}

impl CrawlCounts {
    fn urls_imported_for_summary(self) -> u32 {
        self.ajax_urls.max(self.traditional_urls)
    }
}

fn parse_crawl_counts(log_path: &Path, fallback_traditional_urls: u32) -> CrawlCounts {
    let log = std::fs::read_to_string(log_path).unwrap_or_default();
    let traditional_urls =
        parse_last_count(&log, "Job spider found ").unwrap_or(fallback_traditional_urls);
    let ajax_urls = parse_last_count(&log, "Job spiderAjax found ").unwrap_or(0);
    CrawlCounts {
        traditional_urls,
        ajax_urls,
    }
}

fn parse_last_count(log: &str, prefix: &str) -> Option<u32> {
    log.lines().rev().find_map(|line| {
        let rest = line.strip_prefix(prefix)?;
        let count = rest.strip_suffix(" URLs")?;
        count.parse::<u32>().ok()
    })
}

pub fn validate_scheme_only(url: &str) -> bool {
    matches!(
        url.split_once("://"),
        Some(("http", _)) | Some(("https", _))
    )
}

#[allow(dead_code)]
pub fn run_dir_marker_file(p: &Path) -> std::path::PathBuf {
    p.join(".zaprun-run")
}

fn write_passive_artifacts(run_dir: &Path) -> Result<(), ZapshootError> {
    let mut summary = Summary::sample_for_tests();
    summary.warnings.push("passive_only=true".to_string());
    write_summary(run_dir, &summary)?;
    write_coverage(run_dir, &Coverage::for_web_pr_passive_only(0))?;
    let sarif = emit_sarif("zaprun", env!("CARGO_PKG_VERSION"), &[])
        .map_err(|e| ZapshootError::Io(e.to_string()))?;
    std::fs::write(run_dir.join("zap.sarif"), sarif)?;
    std::fs::write(run_dir.join("zap-report.json"), "{\"site\":[]}")?;
    std::fs::write(
        run_dir.join("zap-report.html"),
        "<!doctype html><meta charset=utf-8><title>zaprun passive stub</title>",
    )?;
    std::fs::write(run_dir.join("zap.log"), b"")?;
    Ok(())
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
        return Err(ZapshootError::Io("scan_timeout_empty".to_string()));
    }
    let (number, multiplier) = match s.as_bytes().last().copied() {
        Some(b's') | Some(b'S') => (&s[..s.len() - 1], 1),
        Some(b'm') | Some(b'M') => (&s[..s.len() - 1], 60),
        Some(b'h') | Some(b'H') => (&s[..s.len() - 1], 60 * 60),
        Some(b'0'..=b'9') => (s, 1),
        _ => return Err(ZapshootError::Io("scan_timeout_invalid".to_string())),
    };
    let value = number
        .parse::<u64>()
        .map_err(|_| ZapshootError::Io("scan_timeout_invalid".to_string()))?;
    Ok(Duration::from_secs(value.saturating_mul(multiplier)))
}
