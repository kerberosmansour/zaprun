//! `zaprun api <spec> --target <url> --active` — OpenAPI active-scan flow.
//!
//! The headline reliability win: the AF plan inlines its active-scan policy
//! as a `policyDefinition` block, so we have ZERO dependency on
//! `~/.ZAP/policies/API-Minimal.policy`, on `.ZAP_D`, on `zap-x.sh`, or on the
//! `zap-api-scan.py` helper script.  The plan is self-contained.

use std::path::Path;

use crate::error::ZapshootError;
use crate::exit::ExitCode;
use crate::plan::{Job, Plan};
use crate::run_meta::{canonicalize_run_dir, RunMeta};

/// The inlined active-scan policy block written into every API-pr plan.
/// Pinned by SHA-256 in `API_MINIMAL_POLICY_INLINE_HASH` -- changing this
/// constant is a deliberate, reviewed event.
pub const API_MINIMAL_POLICY_INLINE: &str = concat!(
    "name: zaprun-api-minimal\n",
    "defaultStrength: medium\n",
    "defaultThreshold: medium\n",
    "rules:\n",
    "  - id: 40012  # Cross Site Scripting (Reflected)\n",
    "    threshold: medium\n",
    "  - id: 40018  # SQL Injection\n",
    "    threshold: medium\n",
    "  - id: 40019  # SQL Injection - MySQL\n",
    "    threshold: medium\n",
    "  - id: 40020  # SQL Injection - Hypersonic SQL\n",
    "    threshold: medium\n",
    "  - id: 40021  # SQL Injection - Oracle\n",
    "    threshold: medium\n",
    "  - id: 40022  # SQL Injection - PostgreSQL\n",
    "    threshold: medium\n",
);

/// Pinned SHA-256 of `API_MINIMAL_POLICY_INLINE`.  Drift detected by
/// `unit_api_inline_policy.rs::inline_policy_constant_hash_pinned`.
pub const API_MINIMAL_POLICY_INLINE_HASH: &str =
    // Deliberate hash update for ticket #8 (CLI rename): the policy's `name:`
    // field changed to "zaprun-api-minimal", which changes the SHA-256 of the
    // inlined constant. Previous pinned value:
    //   b0df364bb31843b85e1219da438c8a6cef47c327a3f250d4c2f60302c3547df2
    "3b535eb18d46d4128e032cf2d49ea842a69db95ef1cbfc4c79faeadf792c1a3e";

const MAX_SPEC_BYTES: u64 = 8 * 1024 * 1024;

pub struct ApiOptions {
    pub spec: std::path::PathBuf,
    pub target: String,
    pub active: bool,
    pub output: std::path::PathBuf,
}

pub fn cmd_api(opts: &ApiOptions) -> Result<ExitCode, ZapshootError> {
    if !opts.active {
        eprintln!("zaprun: --active is required for `api`");
        return Err(ZapshootError::Io("active_required".to_string()));
    }
    let spec_str = opts
        .spec
        .to_str()
        .ok_or_else(|| ZapshootError::Io("spec_path_not_utf8".to_string()))?;
    validate_openapi_spec(spec_str)?;

    if !crate::scan_url::validate_scheme_only(&opts.target) {
        eprintln!("zaprun: target_scheme_unsupported: only http(s) targets are accepted");
        return Err(ZapshootError::Io("target_scheme_unsupported".to_string()));
    }

    let canonical_out = canonicalize_run_dir(&opts.output)?;
    let plan = api_pr_openapi_plan(spec_str, &opts.target)?;
    let yaml = plan
        .to_yaml()
        .map_err(|e| ZapshootError::Io(e.to_string()))?;
    std::fs::write(canonical_out.join("plan.yaml"), yaml)?;

    let placeholder_image = format!(
        "ghcr.io/kerberosmansour/zaprun@sha256:{}",
        "0".repeat(64)
    );
    let mut meta = RunMeta::new_with_random_api_key(&placeholder_image);
    meta.plan_path = Some(canonical_out.join("plan.yaml"));
    meta.write_to(&canonical_out.join("run.json"))?;

    use crate::coverage::Coverage;
    use crate::report::normalize::Summary;
    use crate::report::sarif::emit_sarif;

    let mut summary = Summary::sample_for_tests();
    summary.status = "incomplete".to_string();
    summary
        .warnings
        .push("active_scan_not_yet_dispatched".to_string());
    std::fs::write(
        canonical_out.join("summary.json"),
        serde_json::to_string_pretty(&summary).map_err(|e| ZapshootError::Io(e.to_string()))?,
    )?;
    let coverage = Coverage::for_active_scan_failed("docker dispatch deferred to docker-gated E2E");
    std::fs::write(
        canonical_out.join("coverage.json"),
        serde_json::to_string_pretty(&coverage).map_err(|e| ZapshootError::Io(e.to_string()))?,
    )?;
    let sarif = emit_sarif("zaprun", env!("CARGO_PKG_VERSION"), &[])
        .map_err(|e| ZapshootError::Io(e.to_string()))?;
    std::fs::write(canonical_out.join("zap.sarif"), sarif)?;
    std::fs::write(canonical_out.join("zap-report.json"), "{\"site\":[]}")?;
    std::fs::write(
        canonical_out.join("zap-report.html"),
        "<!doctype html><meta charset=utf-8><title>zaprun api stub</title>",
    )?;
    std::fs::write(canonical_out.join("zap.log"), b"")?;
    if !canonical_out.join("capabilities.json").exists() {
        std::fs::write(
            canonical_out.join("capabilities.json"),
            r#"{"schema_version":"1.0","backend":"docker","docker":{"available":false},"image":{"pinned":false},"output_dir":{"writable":true},"target":null,"java":null,"browser":null,"partial":false,"started_at":"1970-01-01T00:00:00Z","finished_at":"1970-01-01T00:00:00Z"}"#,
        )?;
    }

    Ok(ExitCode::PolicyFail)
}

pub fn validate_openapi_spec(path: &str) -> Result<(), ZapshootError> {
    if path.contains("..") {
        return Err(ZapshootError::Io("spec_path_unsafe".to_string()));
    }
    let p = Path::new(path);
    let meta = std::fs::metadata(p).map_err(|_| ZapshootError::Io("spec_not_found".to_string()))?;
    if !meta.is_file() {
        return Err(ZapshootError::Io("spec_not_a_file".to_string()));
    }
    if meta.len() > MAX_SPEC_BYTES {
        return Err(ZapshootError::Io(format!(
            "spec_too_large: {} bytes (cap: {} bytes)",
            meta.len(),
            MAX_SPEC_BYTES
        )));
    }
    Ok(())
}

pub fn api_pr_openapi_plan(spec: &str, target: &str) -> Result<Plan, ZapshootError> {
    Plan::builder()
        .context("default", target)
        .ci_mode(true)
        .job(Job::OpenApi {
            api_file: spec.to_string(),
            target_url: target.to_string(),
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
        .job(Job::ExitStatus {
            error_level: "high".to_string(),
            warn_level: "medium".to_string(),
        })
        .build()
        .map_err(Into::into)
}
