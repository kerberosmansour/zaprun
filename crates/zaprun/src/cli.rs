use std::path::PathBuf;
use std::process::ExitCode as StdExit;

use clap::{Args, Parser, Subcommand};

use crate::calibrate::{cmd_calibrate, CalibrateOptions};
use crate::doctor::{run_doctor, DoctorOptions};
use crate::error::ZapshootError;
use crate::exit::ExitCode;
use crate::observe::{cmd_observe, ObserveOptions};
use crate::plan::{Job, Plan};
use crate::run_meta::{canonicalize_run_dir, RunMeta};
use crate::scan_api::{cmd_api, ApiOptions};
use crate::scan_url::{cmd_scan_url, ScanUrlOptions};

const ROOT_LONG_ABOUT: &str = "\
Point-and-shoot ZAP CLI: deterministic Automation Framework runs with a stable
artifact contract.

zaprun drives an OWASP ZAP container through a pinned image digest, writes a
predictable set of files to the output directory, and exits with a stable code
so CI gates and humans can both reason about the result.

Artifact contract (every successful run writes these under --output):
  plan.yaml          ZAP Automation Framework plan that was executed
  run.json           run metadata (image digest, per-run API key envelope)
  summary.json       normalised finding summary (severity counts + samples)
  capabilities.json  doctor pre-flight result (backend, image, browser)
  coverage.json      coverage ledger (URLs discovered vs scanned)
  observations.json  observe-mode replay record (when 'observe' is used)
  zap-report.json    raw ZAP traditional-JSON report
  zap-report.html    raw ZAP HTML report

Exit codes:
  0  scan completed and policy gate passed
  1  scan completed and policy gate failed
  2  tool or environment error (bad args, missing docker, unsafe path)
  3  target unavailable or scan could not start
  4  timeout or resource budget exceeded
  5  coverage contract failed";

const ROOT_AFTER_HELP: &str = "\
Examples:
  # Active scan a web URL with the default web-pr profile
  zaprun scan https://example.test --active

  # SPA-aware scan with Firefox-backed Ajax spider + DOM XSS rule
  zaprun scan http://host.docker.internal:4000 --active --profile spa-pr

  # Active scan an OpenAPI spec
  zaprun api ./openapi.yaml --target http://localhost:3001 --active

  # Bootstrap target-owned DAST config and workflow
  zaprun init --target-dir /path/to/webapp --deployment-target https://staging.example.test

  # Re-derive target-owned config when the threat model or image pin changes
  zaprun rederive --target-dir /path/to/webapp

  # Pre-flight: confirm docker, image digest, and target reachability
  zaprun doctor --probe-target http://localhost:3001

  # Run from inside the hardened ZAP image (CLI baked in at /usr/local/bin/zaprun)
  docker run --rm ghcr.io/kerberosmansour/zaprun@sha256:<digest> \\
    zaprun scan http://host.docker.internal:4000 --active

See docs/zaprun-cli.md for the full manual.";

#[derive(Debug, Parser)]
#[command(
    name = "zaprun",
    version,
    about = "Point-and-shoot ZAP CLI: deterministic Automation Framework runs with stable artifacts",
    long_about = ROOT_LONG_ABOUT,
    after_help = ROOT_AFTER_HELP,
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Run an active web URL scan (M3).
    Scan(ScanArgs),
    /// Run an OpenAPI active scan (M4).
    Api(ApiArgs),
    /// Pre-flight check (M1).
    Doctor(DoctorArgs),
    /// Build an Automation Framework plan (M2).
    Plan(PlanArgs),
    /// Send a candidate request and observe ZAP alerts (M5).
    Observe(ObserveArgs),
    /// Class-based calibration against expected plugin IDs (M5).
    Calibrate(CalibrateArgs),
    /// Bootstrap target-owned DAST config and workflow.
    Init(InitArgs),
    /// Re-derive target-owned DAST config when inputs drift.
    #[command(name = "rederive")]
    ReDerive(ReDeriveArgs),
    /// Triage SAST SARIF into a guided DAST map.
    #[command(name = "triage-sarif")]
    TriageSarif(TriageSarifArgs),
    /// Explain a previous run directory (MVP2).
    Explain(ExplainArgs),
}

const SCAN_LONG_ABOUT: &str = "\
Run an active or passive web URL scan against a target.

Profiles:
  web-pr   conservative traditional spider + active scan (default)
  spa-pr   web-pr plus Firefox-backed Ajax spider with DOM XSS rule 40026

The scan writes plan.yaml, run.json, summary.json, coverage.json, zap-report.json,
and zap-report.html under --output.";

const SCAN_AFTER_HELP: &str = "\
Examples:
  # Active scan with the default web-pr profile
  zaprun scan https://example.test --active

  # SPA-aware scan with Firefox-backed Ajax spider
  zaprun scan http://host.docker.internal:4000 --active --profile spa-pr

  # Pin the scanner image digest explicitly
  zaprun scan https://example.test --active \\
    --image ghcr.io/kerberosmansour/zaprun@sha256:<64-hex>

  # Long-running calibration scan with a 12-minute budget
  zaprun scan http://host.docker.internal:4000 --active \\
    --profile spa-pr --scan-timeout 12m --output output/zaprun-spa";

#[derive(Debug, Args)]
#[command(long_about = SCAN_LONG_ABOUT, after_help = SCAN_AFTER_HELP)]
pub struct ScanArgs {
    /// Target URL to scan (http or https).
    pub url: String,
    /// Run the active scanner (in addition to spidering and passive rules).
    #[arg(long)]
    pub active: bool,
    /// Run only passive rules (mutually exclusive with --active in practice).
    #[arg(long)]
    pub passive: bool,
    /// Scan profile: `web-pr` (default, traditional) or `spa-pr` (Ajax + DOM XSS).
    #[arg(long, default_value = "web-pr")]
    pub profile: String,
    /// Selenium browser ID for browser-backed rules (e.g. DOM XSS).
    #[arg(long, default_value = "firefox-headless")]
    pub browser_id: String,
    /// Output directory for plan.yaml/run.json/summary.json/zap-report.*.
    #[arg(long, default_value = "./output/zaprun")]
    pub output: PathBuf,
    /// Optional image reference (`<repo>@sha256:<64-hex>`); defaults to the pinned digest.
    #[arg(long)]
    pub image: Option<String>,
    /// Scan timeout (e.g. `8m`, `30m`).
    #[arg(long, default_value = "8m")]
    pub scan_timeout: String,
}

const API_LONG_ABOUT: &str = "\
Run an active scan against an OpenAPI spec.

zaprun loads the spec, rewrites the host so the scanner container can reach
the target via host.docker.internal, and runs the ZAP API scan flow.";

const API_AFTER_HELP: &str = "\
Examples:
  # Active scan a local API behind a generated OpenAPI doc
  zaprun api ./openapi.yaml --target http://localhost:3001 --active

  # Pin output dir for a smoke service run
  zaprun api ./crates/secure_smoke_service/openapi.yaml \\
    --target http://localhost:3001 --active \\
    --output output/zaprun-smoke";

#[derive(Debug, Args)]
#[command(long_about = API_LONG_ABOUT, after_help = API_AFTER_HELP)]
pub struct ApiArgs {
    /// Path to the OpenAPI spec (YAML or JSON).
    pub spec: PathBuf,
    /// Target base URL the spec describes (http or https).
    #[arg(long)]
    pub target: String,
    /// Run the active scanner (passive-only is the default).
    #[arg(long)]
    pub active: bool,
    /// Output directory for plan.yaml/run.json/summary.json/zap-report.*.
    #[arg(long, default_value = "./output/zaprun")]
    pub output: PathBuf,
    /// Optional image reference (`<repo>@sha256:<64-hex>`); defaults to the pinned digest.
    #[arg(long)]
    pub image: Option<String>,
    /// Scan timeout (e.g. `8m`, `30m`).
    #[arg(long, default_value = "8m")]
    pub scan_timeout: String,
}

const DOCTOR_LONG_ABOUT: &str = "\
Pre-flight check: confirm the chosen backend can run zaprun, the scanner image
digest is valid, and (optionally) the target is reachable.

Writes capabilities.json under --output describing what was probed and what
passed. Exits 0 when all required probes pass, 2 when any required probe fails.";

const DOCTOR_AFTER_HELP: &str = "\
Examples:
  # Default docker pre-flight
  zaprun doctor

  # Probe a target URL for reachability before scanning
  zaprun doctor --probe-target http://localhost:3001

  # Validate a specific image digest is well-formed and pullable
  zaprun doctor --image ghcr.io/kerberosmansour/zaprun@sha256:<64-hex>";

#[derive(Debug, Args)]
#[command(long_about = DOCTOR_LONG_ABOUT, after_help = DOCTOR_AFTER_HELP)]
pub struct DoctorArgs {
    /// Backend to probe.  `docker` (default) or `local-zap` (stubbed).
    #[arg(long, default_value = "docker")]
    pub backend: String,
    /// Optional image reference.  When provided, must be `<repo>@sha256:<64-hex>`.
    #[arg(long)]
    pub image: Option<String>,
    /// Optional target URL to probe for reachability.
    #[arg(long = "probe-target")]
    pub probe_target: Option<String>,
    /// Output directory for `capabilities.json`.
    #[arg(long, default_value = "./output/zaprun")]
    pub output: PathBuf,
}

const PLAN_LONG_ABOUT: &str = "\
Build a ZAP Automation Framework plan and write it to plan.yaml under --output.

In MVP1, plan supports --dry-run only: it materialises the plan and the run.json
metadata so a human can inspect what would be executed, without actually running
the scanner.";

const PLAN_AFTER_HELP: &str = "\
Examples:
  # Materialise a plan for inspection (no scan)
  zaprun plan https://example.test --dry-run

  # Plan into a custom directory
  zaprun plan http://localhost:3001 --dry-run --output output/zaprun-plan";

#[derive(Debug, Args)]
#[command(long_about = PLAN_LONG_ABOUT, after_help = PLAN_AFTER_HELP)]
pub struct PlanArgs {
    /// Target URL the plan should describe.
    pub target: String,
    /// Materialise the plan but do not run the scanner (only mode in MVP1).
    #[arg(long)]
    pub dry_run: bool,
    /// Output directory for plan.yaml and run.json.
    #[arg(long, default_value = "./output/zaprun")]
    pub output: PathBuf,
}

const OBSERVE_LONG_ABOUT: &str = "\
Replay a candidate request through ZAP and capture the alerts it raises.

The SSRF guard refuses RFC1918 and loopback targets by default. Link-local /
IMDS (169.254.0.0/16) is ALWAYS refused regardless of any flag.";

const OBSERVE_AFTER_HELP: &str = "\
Examples:
  # Replay a request file against an internal target (loopback/RFC1918 opt-in)
  zaprun observe --request ./req.http --target http://localhost:3001 \\
    --allow-internal-target

  # Replay a finding fixture and write observations.json
  zaprun observe --finding ./finding.json --target https://example.test";

#[derive(Debug, Args)]
#[command(long_about = OBSERVE_LONG_ABOUT, after_help = OBSERVE_AFTER_HELP)]
pub struct ObserveArgs {
    /// Path to a candidate raw HTTP request to replay.
    #[arg(long)]
    pub request: Option<PathBuf>,
    /// Path to a candidate finding JSON to replay.
    #[arg(long)]
    pub finding: Option<PathBuf>,
    /// Target URL the request should be sent to.
    #[arg(long)]
    pub target: String,
    /// Output directory for observations.json.
    #[arg(long, default_value = "./output/zaprun")]
    pub output: PathBuf,
    /// Opt out of the SSRF guard for RFC1918 + loopback targets.
    /// Link-local / IMDS (169.254/16) is ALWAYS refused regardless of this flag.
    #[arg(long)]
    pub allow_internal_target: bool,
}

const CALIBRATE_LONG_ABOUT: &str = "\
Class-based calibration against expected plugin IDs.

Reads a calibration profile (TOML) describing expected plugin classes for a
target, evaluates a produced zap-report.json against those expectations, and
exits non-zero with a class-by-class diff when any class is missed.

In MVP1 the orchestration is shape-only; full scan-and-evaluate is tracked in
issue #5.";

const CALIBRATE_AFTER_HELP: &str = "\
Examples:
  # Evaluate a calibration profile (scan orchestration is issue #5)
  zaprun calibrate ./calibration/nodegoat.toml \\
    --output output/zaprun-calibrate";

#[derive(Debug, Args)]
#[command(long_about = CALIBRATE_LONG_ABOUT, after_help = CALIBRATE_AFTER_HELP)]
pub struct CalibrateArgs {
    /// Calibration profile TOML describing expected plugin classes.
    pub profile: PathBuf,
    /// Output directory for calibration evaluation results.
    #[arg(long, default_value = "./output/zaprun")]
    pub output: PathBuf,
}

const INIT_LONG_ABOUT: &str = "\
Bootstrap target-owned DAST configuration for a web app or web service.

This command inspects the target repository, chooses zaprun-backed DAST policy,
writes .zaprun/ config plus .github/workflows/dast.yml, and pins the generated
workflow to the latest approved digest-pinned zaprun image.";

const INIT_AFTER_HELP: &str = "\
Examples:
  zaprun init --target-dir /path/to/webapp \\
    --deployment-target https://staging.example.test

  zaprun init --target-dir /path/to/api \\
    --deployment-target http://host.docker.internal:3001";

#[derive(Debug, Args)]
#[command(long_about = INIT_LONG_ABOUT, after_help = INIT_AFTER_HELP)]
pub struct InitArgs {
    /// Target repository to receive .zaprun/ config and .github/workflows/dast.yml.
    #[arg(long, default_value = ".")]
    pub target_dir: PathBuf,
    /// Runtime base URL the workflow should scan.
    #[arg(long)]
    pub deployment_target: Option<String>,
    /// Optional image reference (`<repo>@sha256:<64-hex>`); defaults to the pinned digest.
    #[arg(long)]
    pub image: Option<String>,
}

const REDERIVE_LONG_ABOUT: &str = "\
Re-derive target-owned DAST configuration when threat-model CWEs or the approved
zaprun image digest drift from .zaprun/manifest.json.";

const REDERIVE_AFTER_HELP: &str = "\
Examples:
  zaprun rederive --target-dir /path/to/webapp";

#[derive(Debug, Args)]
#[command(long_about = REDERIVE_LONG_ABOUT, after_help = REDERIVE_AFTER_HELP)]
pub struct ReDeriveArgs {
    /// Target repository containing .zaprun/manifest.json.
    #[arg(long, default_value = ".")]
    pub target_dir: PathBuf,
}

const TRIAGE_SARIF_LONG_ABOUT: &str = "\
Triage SAST SARIF into endpoint x CWE guided DAST inputs.

Reads SARIF 2.1.0 plus target route/OpenAPI context, then writes a conservative
triage report, endpoint x CWE guided scan map, and filtered SARIF containing
only findings already validated by ZAP.";

#[derive(Debug, Args)]
#[command(long_about = TRIAGE_SARIF_LONG_ABOUT)]
pub struct TriageSarifArgs {
    /// Target repository containing route/OpenAPI context.
    #[arg(long, default_value = ".")]
    pub target_dir: PathBuf,
    /// SARIF file to classify.
    #[arg(long)]
    pub sarif: PathBuf,
    /// Output directory for triage-report.json/guided-scan-map.json/filtered.sarif.
    #[arg(long, default_value = "./output/zaprun-triage-sarif")]
    pub output: PathBuf,
}

const EXPLAIN_LONG_ABOUT: &str = "\
Explain a previous run directory in human-readable terms (MVP2 stub).

Currently exits 2 with `subcommand not yet implemented`. The shape is fixed so
that future invocations remain compatible.";

const EXPLAIN_AFTER_HELP: &str = "\
Examples:
  # Will be supported in MVP2
  zaprun explain ./output/zaprun";

#[derive(Debug, Args)]
#[command(long_about = EXPLAIN_LONG_ABOUT, after_help = EXPLAIN_AFTER_HELP)]
pub struct ExplainArgs {
    /// Path to a previous zaprun output directory.
    pub run_dir: PathBuf,
}

/// Parse args, dispatch, and return a stable process exit code.
pub fn run() -> StdExit {
    let cli = Cli::parse();
    let result: Result<ExitCode, ZapshootError> = match cli.command {
        Commands::Doctor(a) => cmd_doctor(a),
        Commands::Plan(a) => cmd_plan(a),
        Commands::Scan(a) => cmd_scan_url(&ScanUrlOptions {
            url: a.url,
            active: a.active,
            passive: a.passive,
            profile: a.profile,
            browser_id: a.browser_id,
            output: a.output,
            image: a.image,
            scan_timeout: a.scan_timeout,
        }),
        Commands::Api(a) => cmd_api(&ApiOptions {
            spec: a.spec,
            target: a.target,
            active: a.active,
            output: a.output,
        }),
        Commands::Observe(a) => cmd_observe(&ObserveOptions {
            request: a.request,
            finding: a.finding,
            target: a.target,
            output: a.output,
            allow_internal_target: a.allow_internal_target,
        }),
        Commands::Calibrate(a) => cmd_calibrate(&CalibrateOptions {
            profile: a.profile,
            output: a.output,
        }),
        Commands::Init(a) => cmd_init(a),
        Commands::ReDerive(a) => cmd_rederive(a),
        Commands::TriageSarif(a) => cmd_triage_sarif(a),
        // Explain stays a stub; MVP2.
        Commands::Explain(_) => Err(ZapshootError::SubcommandNotYetImplemented),
    };

    let code = match result {
        Ok(c) => c as i32,
        Err(e) => {
            eprintln!("zaprun: {e}");
            ExitCode::from(&e) as i32
        }
    };
    StdExit::from(code as u8)
}

fn cmd_init(a: InitArgs) -> Result<ExitCode, ZapshootError> {
    dast_spike::init::run(dast_spike::cli::InitArgs {
        target_dir: a.target_dir,
        deployment_target: a.deployment_target,
        image: a.image,
    })
    .map_err(|err| ZapshootError::Io(err.to_string()))?;
    Ok(ExitCode::Pass)
}

fn cmd_rederive(a: ReDeriveArgs) -> Result<ExitCode, ZapshootError> {
    dast_spike::rederive::run(dast_spike::cli::ReDeriveArgs {
        target_dir: a.target_dir,
    })
    .map_err(|err| ZapshootError::Io(err.to_string()))?;
    Ok(ExitCode::Pass)
}

fn cmd_triage_sarif(a: TriageSarifArgs) -> Result<ExitCode, ZapshootError> {
    dast_spike::triage_sarif::run(dast_spike::triage_sarif::TriageSarifOptions {
        target_dir: a.target_dir,
        sarif: a.sarif,
        output: a.output,
    })
    .map_err(|err| ZapshootError::Io(err.to_string()))?;
    Ok(ExitCode::Pass)
}

fn cmd_plan(a: PlanArgs) -> Result<ExitCode, ZapshootError> {
    let canonical = canonicalize_run_dir(&a.output)
        .map_err(|_| ZapshootError::Io("run_dir_unsafe_path".to_string()))?;
    let plan = Plan::builder()
        .context("default", &a.target)
        .ci_mode(true)
        .job(Job::Spider {
            max_duration_seconds: 60,
            url: a.target.clone(),
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
        .build()?;
    let yaml = plan
        .to_yaml()
        .map_err(|e| ZapshootError::Io(e.to_string()))?;
    std::fs::write(canonical.join("plan.yaml"), yaml)?;
    let placeholder_image = format!("ghcr.io/kerberosmansour/zaprun@sha256:{}", "0".repeat(64));
    let meta = RunMeta::new_with_random_api_key(&placeholder_image);
    meta.write_to(&canonical.join("run.json"))?;
    if !a.dry_run {
        // M2 only supports --dry-run; full run is M3.
        eprintln!("zaprun: only --dry-run is supported in this milestone");
        return Err(ZapshootError::SubcommandNotYetImplemented);
    }
    Ok(ExitCode::Pass)
}

fn cmd_doctor(a: DoctorArgs) -> Result<ExitCode, ZapshootError> {
    let opts = DoctorOptions {
        backend: a.backend,
        image: a.image,
        probe_target: a.probe_target,
        output: a.output,
    };
    let outcome = run_doctor(&opts)?;
    if outcome.all_required_ok {
        Ok(ExitCode::Pass)
    } else {
        Err(outcome
            .first_error
            .unwrap_or(ZapshootError::OutputDirNotWritable))
    }
}
