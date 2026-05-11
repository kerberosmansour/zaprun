use crate::{DastSpikeError, Result};
use chrono::{Duration, NaiveDate, Utc};
use dast_spike_rules::{
    BaselineDocument, BaselineSummary, Suppression, SuppressionScope, BASELINE_HARD_LIMIT,
};
use std::fs;
use std::path::Path;

pub fn today() -> NaiveDate {
    if let Ok(value) = std::env::var("DAST_SPIKE_TEST_DATE") {
        if let Ok(date) = NaiveDate::parse_from_str(&value, "%Y-%m-%d") {
            return date;
        }
    }
    Utc::now().date_naive()
}

pub fn load_or_empty(
    path: &Path,
    allow_expired: bool,
) -> Result<(BaselineDocument, BaselineSummary)> {
    if !path.exists() {
        let baseline = BaselineDocument::empty();
        let summary = validate_for_gate(&baseline, allow_expired)?;
        return Ok((baseline, summary));
    }
    let text = fs::read_to_string(path)?;
    let baseline: BaselineDocument = serde_json::from_str(&text)?;
    let summary = validate_for_gate(&baseline, allow_expired)?;
    Ok((baseline, summary))
}

fn validate_for_gate(baseline: &BaselineDocument, allow_expired: bool) -> Result<BaselineSummary> {
    baseline.validate(today(), allow_expired).map_err(|err| {
        let message = err.to_string();
        if message.contains("expired") || message.contains("natural key collision") {
            DastSpikeError::Gate(message)
        } else {
            DastSpikeError::Rules(err)
        }
    })
}

pub fn save(path: &Path, baseline: &BaselineDocument) -> Result<()> {
    if baseline.suppressions.len() > BASELINE_HARD_LIMIT {
        return Err(DastSpikeError::Usage(format!(
            "baseline at hard limit {BASELINE_HARD_LIMIT} - run 'dast-spike triage --review' first"
        )));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let text = serde_json::to_string_pretty(baseline)?;
    fs::write(path, format!("{text}\n"))?;
    Ok(())
}

pub fn is_suppressed(
    alert: &crate::report::normalize::NormalizedAlert,
    baseline: &BaselineDocument,
) -> bool {
    baseline.suppressions.iter().any(|suppression| {
        if suppression.scanner != alert.scanner || suppression.plugin_id != alert.plugin_id {
            return false;
        }
        if let Some(alert_ref) = &suppression.alert_ref {
            if alert_ref != &alert.alert_ref {
                return false;
            }
        }
        match &suppression.scope {
            SuppressionScope::Global { global } => *global,
            SuppressionScope::UrlPattern { url_pattern } => regex::Regex::new(url_pattern)
                .map(|re| re.is_match(&alert.url))
                .unwrap_or(false),
        }
    })
}

pub fn new_suppression(
    scanner: String,
    plugin_id: String,
    scope: SuppressionScope,
    justification: String,
    author: String,
    expires_in_days: i64,
) -> Suppression {
    let added_at = today();
    Suppression {
        scanner,
        plugin_id: plugin_id.clone(),
        alert_ref: Some(plugin_id),
        scope,
        justification,
        author,
        added_at,
        expires_at: added_at + Duration::days(expires_in_days),
        linked_finding: None,
        review_count: 0,
    }
}
