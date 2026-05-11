use crate::report::normalize::NormalizedReport;
use serde_json::{json, Value};

pub fn emit_sarif(reports: &[NormalizedReport]) -> Value {
    let mut rules = Vec::new();
    let mut results = Vec::new();

    for report in reports {
        for alert in &report.alerts {
            let rule_id = format!("{}:{}", alert.scanner, alert.plugin_id);
            if !rules.iter().any(|rule: &Value| rule["id"] == rule_id) {
                rules.push(json!({
                    "id": rule_id,
                    "name": alert.name,
                    "shortDescription": { "text": alert.name },
                    "properties": {
                        "scanner": alert.scanner,
                        "cwes": alert.cwes,
                    }
                }));
            }
            results.push(json!({
                "ruleId": rule_id,
                "level": alert.severity.as_sarif_level(),
                "message": { "text": alert.name },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": alert.url },
                        "region": { "startLine": 1 }
                    }
                }],
                "partialFingerprints": {
                    "dastSpikeEvidence": alert.evidence_hash
                }
            }));
        }
    }

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "dast-spike",
                    "informationUri": "https://github.com/kerberosmansour/zaprun",
                    "rules": rules
                }
            },
            "results": results
        }]
    })
}
