//! Report normalization + SARIF emission.

pub mod normalize {
    use serde::{Deserialize, Serialize};

    pub const SCHEMA_VERSION: &str = "1.0";

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct Summary {
        pub schema_version: String,
        pub status: String,
        pub high_count: u32,
        pub medium_count: u32,
        pub warn_count: u32,
        pub urls_imported: u32,
        pub urls_scanned: u32,
        pub duration_seconds: u64,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub warnings: Vec<String>,
    }

    impl Summary {
        pub fn sample_for_tests() -> Self {
            Summary {
                schema_version: SCHEMA_VERSION.to_string(),
                status: "passed".to_string(),
                high_count: 0,
                medium_count: 0,
                warn_count: 0,
                urls_imported: 0,
                urls_scanned: 0,
                duration_seconds: 0,
                warnings: Vec::new(),
            }
        }
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct RawZapReport {
        #[serde(default)]
        pub site: Vec<RawSite>,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct RawSite {
        #[serde(default)]
        pub alerts: Vec<RawAlert>,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct RawAlert {
        #[serde(rename = "riskdesc", default)]
        pub risk: String,
        #[serde(rename = "instancesCount", default)]
        pub instances_count: u32,
        #[serde(default)]
        pub count: String,
        #[serde(rename = "pluginid", default)]
        pub plugin_id: String,
        #[serde(default)]
        pub name: String,
        #[serde(default)]
        pub instances: Vec<RawInstance>,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct RawInstance {
        #[serde(default)]
        pub uri: String,
    }

    pub fn normalize_zap_report(
        raw: &RawZapReport,
        urls_imported: u32,
        urls_scanned: u32,
        duration_seconds: u64,
    ) -> Summary {
        let mut high = 0u32;
        let mut medium = 0u32;
        let mut warn = 0u32;
        for site in &raw.site {
            for alert in &site.alerts {
                let bucket = classify_risk(&alert.risk);
                let count = alert.instance_count().max(1);
                match bucket {
                    Risk::High => high = high.saturating_add(count),
                    Risk::Medium => medium = medium.saturating_add(count),
                    Risk::Warn => warn = warn.saturating_add(count),
                }
            }
        }
        let status = if high > 0 { "failed" } else { "passed" };
        Summary {
            schema_version: SCHEMA_VERSION.to_string(),
            status: status.to_string(),
            high_count: high,
            medium_count: medium,
            warn_count: warn,
            urls_imported,
            urls_scanned,
            duration_seconds,
            warnings: Vec::new(),
        }
    }

    enum Risk {
        High,
        Medium,
        Warn,
    }

    fn classify_risk(s: &str) -> Risk {
        let l = s.to_ascii_lowercase();
        if l.starts_with("high") {
            Risk::High
        } else if l.starts_with("medium") {
            Risk::Medium
        } else {
            Risk::Warn
        }
    }

    impl RawZapReport {
        pub fn from_slice(bytes: &[u8]) -> Result<Self, serde_json::Error> {
            serde_json::from_slice(bytes)
        }

        pub fn flattened_alerts(&self) -> Vec<RawAlert> {
            self.site
                .iter()
                .flat_map(|site| site.alerts.iter().cloned())
                .collect()
        }

        pub fn unique_instance_url_count(&self) -> u32 {
            use std::collections::BTreeSet;
            let mut urls = BTreeSet::new();
            for alert in self.site.iter().flat_map(|site| &site.alerts) {
                for instance in &alert.instances {
                    if !instance.uri.is_empty() {
                        urls.insert(instance.uri.as_str());
                    }
                }
            }
            urls.len().try_into().unwrap_or(u32::MAX)
        }
    }

    impl RawAlert {
        pub fn instance_count(&self) -> u32 {
            if self.instances_count > 0 {
                return self.instances_count;
            }
            if let Ok(count) = self.count.parse::<u32>() {
                return count;
            }
            self.instances.len().try_into().unwrap_or(u32::MAX)
        }
    }
}

pub mod sarif {
    use serde_json::{json, Value};

    use crate::report::normalize::RawAlert;

    /// SARIF size cap (4 MiB).  When the rendered SARIF would exceed this,
    /// the function truncates the `runs[0].results` array and records
    /// `runs[0].properties.truncated = true`.
    pub const SARIF_MAX_BYTES: usize = 4 * 1024 * 1024;

    pub fn emit_sarif(
        tool_name: &str,
        tool_version: &str,
        alerts: &[RawAlert],
    ) -> Result<String, serde_json::Error> {
        let mut results: Vec<Value> = Vec::new();
        let mut truncated = false;
        for alert in alerts {
            let entry = json!({
                "ruleId": alert.plugin_id,
                "level": sarif_level(&alert.risk),
                "message": { "text": alert.name },
            });
            results.push(entry);
            // Cheap pre-check: every ~200 entries, render and see if we are about to bust.
            if results.len() % 256 == 0 {
                let probe = render(tool_name, tool_version, &results, false)?;
                if probe.len() > SARIF_MAX_BYTES {
                    results.pop();
                    truncated = true;
                    break;
                }
            }
        }
        // Final render.  If we are still over the cap (rare; only if a single record blew it),
        // drop tail until we fit and mark truncated.
        let mut sarif = render(tool_name, tool_version, &results, truncated)?;
        while sarif.len() > SARIF_MAX_BYTES && !results.is_empty() {
            results.pop();
            truncated = true;
            sarif = render(tool_name, tool_version, &results, truncated)?;
        }
        Ok(sarif)
    }

    fn render(
        tool_name: &str,
        tool_version: &str,
        results: &[Value],
        truncated: bool,
    ) -> Result<String, serde_json::Error> {
        let value = json!({
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": tool_name,
                            "version": tool_version,
                            "informationUri": "https://github.com/kerberosmansour/Dast.Spike"
                        }
                    },
                    "results": results,
                    "properties": {
                        "truncated": truncated
                    }
                }
            ]
        });
        serde_json::to_string(&value)
    }

    fn sarif_level(risk: &str) -> &'static str {
        let l = risk.to_ascii_lowercase();
        if l.starts_with("high") {
            "error"
        } else if l.starts_with("medium") {
            "warning"
        } else {
            "note"
        }
    }
}
