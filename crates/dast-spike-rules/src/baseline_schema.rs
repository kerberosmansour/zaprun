use crate::{Result, RulesError};
use chrono::{Duration, NaiveDate};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const BASELINE_HARD_LIMIT: usize = 200;
pub const BASELINE_WARN_LIMIT: usize = 50;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BaselineDocument {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub schema_version: String,
    #[serde(default)]
    pub suppressions: Vec<Suppression>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Suppression {
    pub scanner: String,
    pub plugin_id: String,
    #[serde(default)]
    pub alert_ref: Option<String>,
    pub scope: SuppressionScope,
    pub justification: String,
    pub author: String,
    pub added_at: NaiveDate,
    pub expires_at: NaiveDate,
    #[serde(default)]
    pub linked_finding: Option<String>,
    #[serde(default)]
    pub review_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged, deny_unknown_fields)]
pub enum SuppressionScope {
    UrlPattern { url_pattern: String },
    Global { global: bool },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BaselineSummary {
    pub total_suppressions: usize,
    pub expired: usize,
    pub expiring_within_30_days: usize,
}

impl BaselineDocument {
    pub fn empty() -> Self {
        Self {
            schema: "https://github.com/kerberosmansour/zaprun/blob/main/schema/baseline-v1.json"
                .to_string(),
            schema_version: "1.0".to_string(),
            suppressions: Vec::new(),
        }
    }

    pub fn validate(&self, today: NaiveDate, allow_expired: bool) -> Result<BaselineSummary> {
        if self.schema_version != "1.0" {
            return Err(RulesError::Validation(
                "baseline schema_version must be 1.0".to_string(),
            ));
        }
        if self.suppressions.len() > BASELINE_HARD_LIMIT {
            return Err(RulesError::Validation(format!(
                "baseline at hard limit {BASELINE_HARD_LIMIT}"
            )));
        }

        let mut natural_keys = BTreeSet::new();
        let mut expired = 0;
        let mut expiring_within_30_days = 0;
        for suppression in &self.suppressions {
            suppression.validate()?;
            let key = suppression.natural_key();
            if !natural_keys.insert(key.clone()) {
                return Err(RulesError::Validation(format!(
                    "baseline natural key collision: {key}"
                )));
            }
            if suppression.expires_at < today {
                expired += 1;
                if !allow_expired {
                    return Err(RulesError::Validation(format!(
                        "suppression expired: {} (expired {}); run 'dast-spike triage --review' to re-justify",
                        suppression.plugin_id, suppression.expires_at
                    )));
                }
            } else if suppression.expires_at <= today + Duration::days(30) {
                expiring_within_30_days += 1;
            }
        }

        Ok(BaselineSummary {
            total_suppressions: self.suppressions.len(),
            expired,
            expiring_within_30_days,
        })
    }
}

impl Suppression {
    pub fn validate(&self) -> Result<()> {
        let scanner_ok = matches!(self.scanner.as_str(), "zap" | "nuclei" | "wapiti");
        if !scanner_ok {
            return Err(RulesError::Validation(format!(
                "scanner must be zap, nuclei, or wapiti: {}",
                self.scanner
            )));
        }
        let plugin_re = Regex::new(r"^[A-Za-z0-9._:-]+$").map_err(|err| {
            RulesError::Validation(format!("internal plugin id regex failed: {err}"))
        })?;
        if !plugin_re.is_match(&self.plugin_id) {
            return Err(RulesError::Validation(format!(
                "invalid plugin_id: {}",
                self.plugin_id
            )));
        }
        if self.justification.trim().is_empty() {
            return Err(RulesError::Validation(
                "suppression justification must be non-empty".to_string(),
            ));
        }
        match &self.scope {
            SuppressionScope::UrlPattern { url_pattern } => {
                Regex::new(url_pattern).map_err(|err| {
                    RulesError::Validation(format!("invalid suppression url_pattern: {err}"))
                })?;
            }
            SuppressionScope::Global { global } => {
                if !*global {
                    return Err(RulesError::Validation(
                        "global suppression scope must be true".to_string(),
                    ));
                }
                if self.justification.chars().count() < 80 {
                    return Err(RulesError::Validation(format!(
                        "global suppression requires justification >= 80 chars; got {}",
                        self.justification.chars().count()
                    )));
                }
            }
        }
        Ok(())
    }

    pub fn natural_key(&self) -> String {
        let alert_ref = self.alert_ref.clone().unwrap_or_default();
        let scope = match &self.scope {
            SuppressionScope::UrlPattern { url_pattern } => url_pattern.clone(),
            SuppressionScope::Global { .. } => "global".to_string(),
        };
        format!(
            "{}:{}:{}:{}",
            self.scanner, self.plugin_id, alert_ref, scope
        )
    }
}
