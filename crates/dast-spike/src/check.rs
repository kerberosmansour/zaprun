use crate::baseline;
use crate::cli::CheckArgs;
use crate::report::normalize::load_zap_report;
use crate::report::sarif::emit_sarif;
use crate::{DastSpikeError, Result};
use serde::Serialize;
use std::fs;

#[derive(Debug, Serialize)]
struct CheckSummary {
    total_count: usize,
    high_count: usize,
    suppressed_count: usize,
    truncated_alerts: usize,
    baseline_summary: dast_spike_rules::BaselineSummary,
}

pub fn run(args: CheckArgs) -> Result<()> {
    if !args.report.exists() {
        return Err(DastSpikeError::MissingFile(args.report));
    }
    let report = load_zap_report(&args.report)?;
    let (baseline_doc, baseline_summary) = baseline::load_or_empty(&args.baseline, false)?;
    let mut high_count = 0;
    let mut suppressed_count = 0;
    for alert in &report.alerts {
        if alert.severity.is_high_or_worse() {
            if baseline::is_suppressed(alert, &baseline_doc) {
                suppressed_count += 1;
            } else {
                high_count += 1;
            }
        }
    }
    let summary = CheckSummary {
        total_count: report.alerts.len(),
        high_count,
        suppressed_count,
        truncated_alerts: report.truncated_alerts.values().sum(),
        baseline_summary,
    };
    if let Some(parent) = args.report.parent() {
        let summary_path = parent.join("run-summary.json");
        fs::write(summary_path, serde_json::to_vec_pretty(&summary)?)?;
    }
    if let Some(sarif_path) = args.sarif {
        fs::write(
            sarif_path,
            serde_json::to_vec_pretty(&emit_sarif(&[report]))?,
        )?;
    }
    if args.github_summary {
        write_github_summary(&summary)?;
    }
    if high_count > 0 {
        Err(DastSpikeError::Gate(format!(
            "{high_count} high/critical finding(s) detected"
        )))
    } else {
        println!(
            "DAST gate passed: {} alerts, {} high, {} suppressed",
            summary.total_count, summary.high_count, summary.suppressed_count
        );
        Ok(())
    }
}

fn write_github_summary(summary: &CheckSummary) -> Result<()> {
    let Ok(path) = std::env::var("GITHUB_STEP_SUMMARY") else {
        return Ok(());
    };
    let body = format!(
        "## DAST Summary\n\n~~~text\nhigh_count={}\nsuppressed_count={}\nbaseline_expired={}\n~~~\n",
        summary.high_count, summary.suppressed_count, summary.baseline_summary.expired
    );
    fs::write(path, body)?;
    Ok(())
}
