use crate::types::Severity;
use crate::{DastSpikeError, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

pub const PER_RULE_ALERT_HARD_LIMIT: usize = 100;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalizedReport {
    pub scanner: String,
    pub alerts: Vec<NormalizedAlert>,
    #[serde(default)]
    pub truncated_alerts: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalizedAlert {
    pub scanner: String,
    pub plugin_id: String,
    pub alert_ref: String,
    pub name: String,
    pub severity: Severity,
    pub url: String,
    #[serde(default)]
    pub param: Option<String>,
    #[serde(default)]
    pub evidence_hash: String,
    #[serde(default)]
    pub cwes: Vec<String>,
}

impl NormalizedReport {
    pub fn empty(scanner: &str) -> Self {
        Self {
            scanner: scanner.to_string(),
            alerts: Vec::new(),
            truncated_alerts: BTreeMap::new(),
        }
    }

    pub fn sort_alerts(&mut self) {
        self.alerts.sort_by(|a, b| {
            (
                &a.scanner,
                &a.plugin_id,
                &a.alert_ref,
                &a.url,
                &a.param,
                &a.evidence_hash,
            )
                .cmp(&(
                    &b.scanner,
                    &b.plugin_id,
                    &b.alert_ref,
                    &b.url,
                    &b.param,
                    &b.evidence_hash,
                ))
        });
    }

    pub fn high_count(&self) -> usize {
        self.alerts
            .iter()
            .filter(|alert| alert.severity.is_high_or_worse())
            .count()
    }
}

pub fn load_zap_report(path: &Path) -> Result<NormalizedReport> {
    let text = fs::read_to_string(path)?;
    parse_zap_report(&text)
}

pub fn parse_zap_report(text: &str) -> Result<NormalizedReport> {
    let value: Value = serde_json::from_str(text).map_err(|err| {
        if err.is_eof() {
            DastSpikeError::Scanner(
                "report file appears truncated; ZAP scan likely killed mid-write".to_string(),
            )
        } else {
            DastSpikeError::Json(err)
        }
    })?;
    Ok(parse_zap_value(&value))
}

pub fn parse_zap_value(value: &Value) -> NormalizedReport {
    let mut report = NormalizedReport::empty("zap");
    let mut per_rule = BTreeMap::<String, usize>::new();

    for alert in zap_alert_values(value) {
        let plugin_id = string_field(alert, &["pluginid", "pluginId", "id"])
            .unwrap_or_else(|| "unknown".to_string());
        let current = per_rule.entry(plugin_id.clone()).or_insert(0);
        if *current >= PER_RULE_ALERT_HARD_LIMIT {
            *report.truncated_alerts.entry(plugin_id).or_insert(0) += 1;
            continue;
        }
        *current += 1;

        let risk_code = int_field(alert, &["riskcode", "riskCode"]).unwrap_or_else(|| {
            string_field(alert, &["risk", "riskdesc", "riskDesc"])
                .and_then(|risk| risk.parse::<Severity>().ok())
                .map_or(0, |severity| match severity {
                    Severity::Info => 0,
                    Severity::Low => 1,
                    Severity::Medium => 2,
                    Severity::High => 3,
                    Severity::Critical => 4,
                })
        });
        let Some(severity) = Severity::from_zap_risk_code(risk_code) else {
            debug_assert!(false, "converter emitted severity outside enum");
            continue;
        };
        let alert_ref = string_field(alert, &["alertRef"]).unwrap_or_else(|| plugin_id.clone());
        let name = string_field(alert, &["name", "alert"]).unwrap_or_else(|| "Unknown".to_string());
        let cwe = string_field(alert, &["cweid", "cweId"]).and_then(|id| {
            if id == "0" || id.is_empty() {
                None
            } else {
                Some(format!("CWE-{id}"))
            }
        });

        let instances = alert.get("instances").and_then(Value::as_array);
        if let Some(instances) = instances {
            if instances.is_empty() {
                report.alerts.push(NormalizedAlert {
                    scanner: "zap".to_string(),
                    plugin_id,
                    alert_ref,
                    name,
                    severity,
                    url: String::new(),
                    param: None,
                    evidence_hash: stable_hash(""),
                    cwes: cwe.into_iter().collect(),
                });
            } else {
                for instance in instances {
                    let url = string_field(instance, &["uri", "url"]).unwrap_or_default();
                    let param =
                        string_field(instance, &["param"]).filter(|value| !value.is_empty());
                    let evidence = string_field(instance, &["evidence"]).unwrap_or_default();
                    report.alerts.push(NormalizedAlert {
                        scanner: "zap".to_string(),
                        plugin_id: plugin_id.clone(),
                        alert_ref: alert_ref.clone(),
                        name: name.clone(),
                        severity,
                        url,
                        param,
                        evidence_hash: stable_hash(&evidence),
                        cwes: cwe.clone().into_iter().collect(),
                    });
                }
            }
        } else {
            let url = string_field(alert, &["url", "matched-at"]).unwrap_or_default();
            report.alerts.push(NormalizedAlert {
                scanner: "zap".to_string(),
                plugin_id,
                alert_ref,
                name,
                severity,
                url,
                param: None,
                evidence_hash: stable_hash(""),
                cwes: cwe.into_iter().collect(),
            });
        }
    }

    report.sort_alerts();
    report
}

pub fn parse_nuclei_report(text: &str) -> Result<NormalizedReport> {
    let mut report = NormalizedReport::empty("nuclei");
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let value: Value = serde_json::from_str(line)?;
        let template_id = string_field(&value, &["template-id", "templateID", "id"])
            .unwrap_or_else(|| "unknown".to_string());
        let severity = string_field(&value, &["info.severity", "severity"])
            .and_then(|s| s.parse::<Severity>().ok())
            .unwrap_or(Severity::Info);
        report.alerts.push(NormalizedAlert {
            scanner: "nuclei".to_string(),
            plugin_id: template_id.clone(),
            alert_ref: template_id,
            name: string_field(&value, &["info.name", "name"])
                .unwrap_or_else(|| "Nuclei finding".to_string()),
            severity,
            url: string_field(&value, &["matched-at", "host"]).unwrap_or_default(),
            param: None,
            evidence_hash: stable_hash(&value.to_string()),
            cwes: Vec::new(),
        });
    }
    report.sort_alerts();
    Ok(report)
}

pub fn parse_wapiti_report(text: &str) -> Result<NormalizedReport> {
    let value: Value = serde_json::from_str(text)?;
    let mut report = NormalizedReport::empty("wapiti");
    if let Some(vulns) = value.get("vulnerabilities").and_then(Value::as_object) {
        for (category, entries) in vulns {
            let Some(entries) = entries.as_array() else {
                continue;
            };
            for entry in entries {
                let severity = string_field(entry, &["level", "severity"])
                    .and_then(|s| s.parse::<Severity>().ok())
                    .unwrap_or(Severity::Medium);
                report.alerts.push(NormalizedAlert {
                    scanner: "wapiti".to_string(),
                    plugin_id: category.clone(),
                    alert_ref: category.clone(),
                    name: category.clone(),
                    severity,
                    url: string_field(entry, &["path", "url"]).unwrap_or_default(),
                    param: string_field(entry, &["parameter"]).filter(|value| !value.is_empty()),
                    evidence_hash: stable_hash(&entry.to_string()),
                    cwes: Vec::new(),
                });
            }
        }
    }
    report.sort_alerts();
    Ok(report)
}

fn zap_alert_values(value: &Value) -> Vec<&Value> {
    let mut alerts = Vec::new();
    if let Some(top) = value.get("alerts").and_then(Value::as_array) {
        alerts.extend(top);
    }
    if let Some(sites) = value.get("site") {
        match sites {
            Value::Array(site_values) => {
                for site in site_values {
                    if let Some(site_alerts) = site.get("alerts").and_then(Value::as_array) {
                        alerts.extend(site_alerts);
                    }
                }
            }
            Value::Object(_) => {
                if let Some(site_alerts) = sites.get("alerts").and_then(Value::as_array) {
                    alerts.extend(site_alerts);
                }
            }
            _ => {}
        }
    }
    alerts
}

fn int_field(value: &Value, names: &[&str]) -> Option<i64> {
    for name in names {
        if let Some(field) = dotted_field(value, name) {
            if let Some(number) = field.as_i64() {
                return Some(number);
            }
            if let Some(text) = field.as_str() {
                if let Ok(number) = text.parse::<i64>() {
                    return Some(number);
                }
            }
        }
    }
    None
}

fn string_field(value: &Value, names: &[&str]) -> Option<String> {
    for name in names {
        if let Some(field) = dotted_field(value, name) {
            if let Some(text) = field.as_str() {
                return Some(text.to_string());
            }
            if field.is_number() || field.is_boolean() {
                return Some(field.to_string());
            }
        }
    }
    None
}

fn dotted_field<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for part in path.split('.') {
        current = current.get(part)?;
    }
    Some(current)
}

fn stable_hash(input: &str) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}
