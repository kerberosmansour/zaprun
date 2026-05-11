use crate::cli::{ScanArgs, ScannerName};
use crate::image_pin;
use crate::report::normalize::NormalizedReport;
use crate::report::sarif::emit_sarif;
use crate::scan::{infer_target_url, parse_duration};
use crate::scanner::{
    NetworkConfig, Policy, ScanError, Scanner, ScannerRunSummary, ScannerStatus, Target,
};
use crate::scanners::nuclei::NucleiScanner;
use crate::scanners::wapiti::WapitiScanner;
use crate::scanners::zap::ZapScanner;
use crate::{DastSpikeError, Result};
use serde::Serialize;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Serialize)]
struct RunSummary {
    high_count: usize,
    total_count: usize,
    scanner_oom_count: usize,
    per_scanner_summary: Vec<ScannerRunSummary>,
}

pub fn run_scan(args: ScanArgs) -> Result<()> {
    fs::create_dir_all(&args.output)?;
    let image_ref = image_pin::resolve_image_ref(args.image.as_deref())?;
    let timeout = parse_duration(&args.health_timeout).unwrap_or(Duration::from_secs(30 * 60));
    let target_url = infer_target_url(&args.target)?;
    let openapi_path = if Path::new(&args.target).exists() {
        Some(PathBuf::from(&args.target))
    } else {
        None
    };
    let target = Target {
        url: target_url,
        openapi_path,
        auth: None,
        host_network: NetworkConfig {
            add_host_gateway: true,
        },
    };
    let policy = Policy {
        rules_tsv_path: args.rules.clone(),
        policy_yaml_path: Some(args.policy.clone()),
        custom_scripts_dir: Some(PathBuf::from(".dast-spike/scripts")),
        timeout,
    };

    let mut selected = BTreeSet::new();
    selected.insert(args.scanner);
    selected.extend(args.enable_scanner.iter().copied());

    let mut reports = Vec::<NormalizedReport>::new();
    let mut summaries = Vec::<ScannerRunSummary>::new();
    let primary = args.scanner;

    for scanner_name in selected {
        let scanner = build_scanner(scanner_name, &args, image_ref.clone());
        match scanner.run(&target, &policy) {
            Ok(report) => {
                let high_count = report.high_count();
                summaries.push(ScannerRunSummary {
                    scanner: scanner.name().to_string(),
                    status: if high_count > 0 {
                        ScannerStatus::Findings
                    } else {
                        ScannerStatus::Passed
                    },
                    alert_count: report.alerts.len(),
                    high_count,
                    message: None,
                });
                write_report(scanner.name(), &args.output, &report)?;
                reports.push(report);
            }
            Err(err) => {
                if scanner_name == primary {
                    return Err(map_scan_error(err));
                }
                summaries.push(ScannerRunSummary {
                    scanner: scanner.name().to_string(),
                    status: match err {
                        ScanError::Timeout { .. } => ScannerStatus::TimedOut,
                        _ => ScannerStatus::Errored,
                    },
                    alert_count: 0,
                    high_count: 0,
                    message: Some(err.to_string()),
                });
            }
        }
    }

    let high_count: usize = reports.iter().map(NormalizedReport::high_count).sum();
    let total_count: usize = reports.iter().map(|report| report.alerts.len()).sum();
    let summary = RunSummary {
        high_count,
        total_count,
        scanner_oom_count: 0,
        per_scanner_summary: summaries,
    };
    let summary_text = serde_json::to_string_pretty(&summary)?;
    fs::write(
        args.output.join("run-summary.json"),
        format!("{summary_text}\n"),
    )?;
    if !reports.is_empty() {
        fs::write(
            args.output.join("sarif.json"),
            serde_json::to_vec_pretty(&emit_sarif(&reports))?,
        )?;
    }
    Ok(())
}

fn build_scanner(
    name: ScannerName,
    args: &ScanArgs,
    image_ref: crate::types::ImageRef,
) -> Box<dyn Scanner> {
    match name {
        ScannerName::Zap => Box::new(ZapScanner {
            image_ref,
            output_dir: args.output.clone(),
            enable_dom_xss: args.enable_dom_xss,
            auth_replacer_config: args.auth_replacer_config.clone(),
        }),
        ScannerName::Nuclei => Box::new(NucleiScanner {
            output_dir: args.output.clone(),
            pin_file: PathBuf::from("references/nuclei-templates-pinned-sha.toml"),
        }),
        ScannerName::Wapiti => Box::new(WapitiScanner {
            output_dir: args.output.clone(),
        }),
    }
}

fn write_report(scanner: &str, output: &Path, report: &NormalizedReport) -> Result<()> {
    let filename = match scanner {
        "zap" => "zap-normalized-report.json",
        "nuclei" => "nuclei-normalized-report.json",
        "wapiti" => "wapiti-normalized-report.json",
        other => return Err(DastSpikeError::Usage(format!("unknown scanner {other}"))),
    };
    fs::write(output.join(filename), serde_json::to_vec_pretty(report)?)?;
    Ok(())
}

fn map_scan_error(err: ScanError) -> DastSpikeError {
    match err {
        ScanError::Usage(message) => DastSpikeError::Usage(message),
        ScanError::Runtime(message) => DastSpikeError::Scanner(message),
        ScanError::Timeout { seconds } => {
            DastSpikeError::Scanner(format!("scan timed out after {seconds}s"))
        }
    }
}
