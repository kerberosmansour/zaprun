use crate::{Result, RulesError};
use regex::Regex;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
pub struct SarifDocument {
    pub original: Value,
    pub findings: Vec<SarifFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SarifFinding {
    pub run_index: usize,
    pub result_index: usize,
    pub rule_id: String,
    pub message: String,
    pub severity: Option<String>,
    pub cwes: Vec<String>,
    pub endpoint: Option<String>,
    pub method: Option<String>,
    pub auth_required: bool,
    pub zap_validated: bool,
    pub location_uri: Option<String>,
    pub location_line: Option<u64>,
    pub fingerprint: String,
}

pub fn parse_sarif(text: &str) -> Result<SarifDocument> {
    let original: Value = serde_json::from_str(text)?;
    let version = original
        .get("version")
        .and_then(Value::as_str)
        .ok_or_else(|| RulesError::Validation("SARIF document missing version".to_string()))?;
    if version != "2.1.0" {
        return Err(RulesError::Validation(format!(
            "unsupported SARIF version {version}; expected 2.1.0"
        )));
    }

    let cwe_re = Regex::new(r"(?i)\bCWE[-_ ]?0*([0-9]{1,5})\b")
        .map_err(|err| RulesError::Validation(format!("internal SARIF CWE regex failed: {err}")))?;
    let mut findings = Vec::new();
    let runs = original
        .get("runs")
        .and_then(Value::as_array)
        .ok_or_else(|| RulesError::Validation("SARIF document missing runs".to_string()))?;

    for (run_index, run) in runs.iter().enumerate() {
        let rules_by_id = rules_by_id(run);
        let Some(results) = run.get("results").and_then(Value::as_array) else {
            continue;
        };
        for (result_index, result) in results.iter().enumerate() {
            let rule_id = result
                .get("ruleId")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            let rule = rules_by_id.get(&rule_id);
            findings.push(parse_result(
                run_index,
                result_index,
                result,
                rule.copied(),
                &rule_id,
                &cwe_re,
            ));
        }
    }

    Ok(SarifDocument { original, findings })
}

fn parse_result(
    run_index: usize,
    result_index: usize,
    result: &Value,
    rule: Option<&Value>,
    rule_id: &str,
    cwe_re: &Regex,
) -> SarifFinding {
    let message = result
        .pointer("/message/text")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let properties = result.get("properties").unwrap_or(&Value::Null);
    let severity = string_property(properties, &["severity"]).or_else(|| {
        result
            .get("level")
            .and_then(Value::as_str)
            .map(str::to_string)
    });
    let endpoint = string_property(
        properties,
        &["endpoint", "path", "route", "http.path", "request.path"],
    );
    let method = string_property(
        properties,
        &["method", "http.method", "request.method", "verb"],
    )
    .map(|method| method.to_ascii_uppercase());
    let auth_required = bool_property(
        properties,
        &[
            "auth_required",
            "requires_auth",
            "authenticated",
            "authentication_required",
        ],
    ) || tags_contain(properties, "auth-required");
    let zap_validated = bool_property(
        properties,
        &["zap_validated", "dast_validated", "validated_by_zap"],
    );
    let location = first_location(result);
    let fingerprint = fingerprint(result, rule_id, location.as_ref());

    let mut cwes = BTreeSet::new();
    collect_cwes_from_text(rule_id, cwe_re, &mut cwes);
    collect_cwes_from_text(&message, cwe_re, &mut cwes);
    collect_cwes_from_value(properties, cwe_re, &mut cwes);
    if let Some(rule) = rule {
        collect_cwes_from_value(rule, cwe_re, &mut cwes);
    }

    SarifFinding {
        run_index,
        result_index,
        rule_id: rule_id.to_string(),
        message,
        severity,
        cwes: cwes.into_iter().collect(),
        endpoint,
        method,
        auth_required,
        zap_validated,
        location_uri: location.as_ref().and_then(|location| location.uri.clone()),
        location_line: location.as_ref().and_then(|location| location.line),
        fingerprint,
    }
}

fn rules_by_id(run: &Value) -> BTreeMap<String, &Value> {
    let mut out = BTreeMap::new();
    let Some(rules) = run.pointer("/tool/driver/rules").and_then(Value::as_array) else {
        return out;
    };
    for rule in rules {
        if let Some(id) = rule.get("id").and_then(Value::as_str) {
            out.insert(id.to_string(), rule);
        }
    }
    out
}

fn collect_cwes_from_value(value: &Value, cwe_re: &Regex, out: &mut BTreeSet<String>) {
    match value {
        Value::String(text) => collect_cwes_from_text(text, cwe_re, out),
        Value::Array(items) => {
            for item in items {
                collect_cwes_from_value(item, cwe_re, out);
            }
        }
        Value::Object(map) => {
            for value in map.values() {
                collect_cwes_from_value(value, cwe_re, out);
            }
        }
        _ => {}
    }
}

fn collect_cwes_from_text(text: &str, cwe_re: &Regex, out: &mut BTreeSet<String>) {
    for cap in cwe_re.captures_iter(text) {
        if let Ok(id) = cap[1].parse::<u32>() {
            out.insert(format!("CWE-{id}"));
        }
    }
}

fn string_property(properties: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(value) = dotted_get(properties, key).and_then(Value::as_str) {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn bool_property(properties: &Value, keys: &[&str]) -> bool {
    keys.iter().any(|key| {
        dotted_get(properties, key)
            .and_then(|value| {
                value.as_bool().or_else(|| {
                    value
                        .as_str()
                        .and_then(|text| match text.to_ascii_lowercase().as_str() {
                            "true" | "yes" | "1" => Some(true),
                            "false" | "no" | "0" => Some(false),
                            _ => None,
                        })
                })
            })
            .unwrap_or(false)
    })
}

fn dotted_get<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    if let Some(direct) = value.get(key) {
        return Some(direct);
    }
    let mut cursor = value;
    for segment in key.split('.') {
        cursor = cursor.get(segment)?;
    }
    Some(cursor)
}

fn tags_contain(properties: &Value, needle: &str) -> bool {
    let Some(tags) = properties.get("tags").and_then(Value::as_array) else {
        return false;
    };
    tags.iter().any(|tag| {
        tag.as_str()
            .map(|tag| tag.eq_ignore_ascii_case(needle))
            .unwrap_or(false)
    })
}

#[derive(Debug)]
struct Location {
    uri: Option<String>,
    line: Option<u64>,
}

fn first_location(result: &Value) -> Option<Location> {
    let location = result.get("locations")?.as_array()?.first()?;
    Some(Location {
        uri: location
            .pointer("/physicalLocation/artifactLocation/uri")
            .and_then(Value::as_str)
            .map(str::to_string),
        line: location
            .pointer("/physicalLocation/region/startLine")
            .and_then(Value::as_u64),
    })
}

fn fingerprint(result: &Value, rule_id: &str, location: Option<&Location>) -> String {
    for key in ["fingerprints", "partialFingerprints"] {
        if let Some(map) = result.get(key).and_then(Value::as_object) {
            if let Some(value) = map.values().find_map(Value::as_str) {
                if !value.trim().is_empty() {
                    return value.to_string();
                }
            }
        }
    }
    let uri = location
        .and_then(|location| location.uri.as_deref())
        .unwrap_or("");
    let line = location.and_then(|location| location.line).unwrap_or(0);
    format!("{rule_id}:{uri}:{line}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sarif_extracts_endpoint_method_cwe_and_flags() {
        let doc = json!({
            "version": "2.1.0",
            "runs": [{
                "tool": { "driver": { "rules": [] } },
                "results": [{
                    "ruleId": "semgrep.xss",
                    "level": "warning",
                    "message": { "text": "reflected CWE-079" },
                    "fingerprints": { "primary": "stable" },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": { "uri": "src/lib.rs" },
                            "region": { "startLine": 7 }
                        }
                    }],
                    "properties": {
                        "tags": ["CWE-79"],
                        "endpoint": "/api/search",
                        "method": "get",
                        "auth_required": true,
                        "zap_validated": true
                    }
                }]
            }]
        });
        let parsed = parse_sarif(&doc.to_string()).expect("parse");
        let finding = &parsed.findings[0];

        assert_eq!(finding.cwes, vec!["CWE-79"]);
        assert_eq!(finding.endpoint.as_deref(), Some("/api/search"));
        assert_eq!(finding.method.as_deref(), Some("GET"));
        assert_eq!(finding.severity.as_deref(), Some("warning"));
        assert!(finding.auth_required);
        assert!(finding.zap_validated);
        assert_eq!(finding.fingerprint, "stable");
    }

    #[test]
    fn sarif_extracts_cwe_from_rule_metadata() {
        let doc = json!({
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "rules": [{
                            "id": "rust.panic",
                            "properties": { "tags": ["CWE-755"] }
                        }]
                    }
                },
                "results": [{
                    "ruleId": "rust.panic",
                    "message": { "text": "panic" }
                }]
            }]
        });
        let parsed = parse_sarif(&doc.to_string()).expect("parse");

        assert_eq!(parsed.findings[0].cwes, vec!["CWE-755"]);
    }
}
