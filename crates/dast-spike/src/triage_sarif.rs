use crate::{DastSpikeError, Result};
use dast_spike_rules::cwe_to_rules::CweRuleMappingDocument;
use dast_spike_rules::manifest::{FindingsSummary, Manifest};
use dast_spike_rules::safe_write;
use dast_spike_rules::sarif::{parse_sarif, SarifDocument, SarifFinding};
use serde::Serialize;
use serde_json::Value as JsonValue;
use serde_yaml_ng::Value as YamlValue;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const CWE_TO_RULES: &str = include_str!("../../../references/dast-tuner/cwe-to-rules.toml");

#[derive(Debug, Serialize)]
pub struct TriageReport {
    pub schema_version: String,
    pub summary: TriageSummary,
    pub findings: Vec<TriageFinding>,
}

#[derive(Debug, Default, Serialize)]
pub struct TriageSummary {
    pub total: usize,
    pub dast_detectable: usize,
    pub dast_partial: usize,
    pub dast_not_applicable: usize,
    pub needs_human_input: usize,
    pub zap_validated: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct TriageFinding {
    pub rule_id: String,
    pub cwe: String,
    pub classification: String,
    pub path: Option<String>,
    pub method: Option<String>,
    pub sarif_result_fingerprint: String,
    pub confidence: String,
    pub recommended_zap_policy: Option<String>,
    pub recommended_action: String,
    pub rationale: String,
    pub validated_by_zap: bool,
    pub source_location: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct GuidedScanMap {
    pub schema_version: String,
    pub mode: String,
    pub targets: Vec<GuidedTarget>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GuidedTarget {
    pub path: String,
    pub method: String,
    pub cwe: String,
    pub sarif_result_fingerprint: String,
    pub zap_policy: String,
    pub confidence: String,
}

#[derive(Debug, Clone)]
pub struct TriageSarifOptions {
    pub target_dir: PathBuf,
    pub sarif: PathBuf,
    pub output: PathBuf,
}

#[derive(Debug, Clone)]
struct RouteInfo {
    auth_required: bool,
}

#[derive(Debug, Clone)]
struct Decision {
    classification: &'static str,
    confidence: &'static str,
    recommended_zap_policy: Option<String>,
    recommended_action: String,
    rationale: String,
}

pub fn run(args: TriageSarifOptions) -> Result<()> {
    let target_root = args
        .target_dir
        .canonicalize()
        .map_err(|err| DastSpikeError::Usage(format!("target-dir not found: {err}")))?;
    if !target_root.is_dir() {
        return Err(DastSpikeError::Usage(format!(
            "target-dir is not a directory: {}",
            target_root.display()
        )));
    }
    if !args.sarif.is_file() {
        return Err(DastSpikeError::MissingFile(args.sarif));
    }

    std::fs::create_dir_all(&args.output)?;
    let output_root = args.output.canonicalize()?;

    let sarif_text = std::fs::read_to_string(&args.sarif)?;
    let sarif = parse_sarif(&sarif_text)?;
    let routes = load_route_inventory(&target_root)?;
    let known_cwes = load_known_zap_cwes()?;

    let report = build_report(&sarif, &routes, &known_cwes);
    let guided = build_guided_map(&report);
    let filtered = build_filtered_sarif(&sarif);

    safe_write(
        &output_root,
        Path::new("triage-report.json"),
        serde_json::to_vec_pretty(&report)?.as_slice(),
    )?;
    safe_write(
        &output_root,
        Path::new("guided-scan-map.json"),
        serde_json::to_vec_pretty(&guided)?.as_slice(),
    )?;
    safe_write(
        &output_root,
        Path::new("filtered.sarif"),
        serde_json::to_vec_pretty(&filtered)?.as_slice(),
    )?;
    update_manifest_summary(&target_root, &report, &guided)?;

    println!("zaprun: triaged SARIF into {}", output_root.display());
    Ok(())
}

fn build_report(
    sarif: &SarifDocument,
    routes: &BTreeMap<(String, String), RouteInfo>,
    known_cwes: &BTreeSet<String>,
) -> TriageReport {
    let mut findings = Vec::new();
    let mut summary = TriageSummary::default();

    for finding in &sarif.findings {
        let cwes = if finding.cwes.is_empty() {
            vec!["CWE-unknown".to_string()]
        } else {
            finding.cwes.clone()
        };
        for cwe in cwes {
            let decision = classify(finding, &cwe, routes, known_cwes);
            let triaged = TriageFinding {
                rule_id: finding.rule_id.clone(),
                cwe,
                classification: decision.classification.to_string(),
                path: finding.endpoint.clone(),
                method: finding.method.clone(),
                sarif_result_fingerprint: finding.fingerprint.clone(),
                confidence: decision.confidence.to_string(),
                recommended_zap_policy: decision.recommended_zap_policy,
                recommended_action: decision.recommended_action,
                rationale: decision.rationale,
                validated_by_zap: finding.zap_validated,
                source_location: render_source_location(finding),
            };
            bump_summary(&mut summary, &triaged);
            findings.push(triaged);
        }
    }
    summary.total = findings.len();

    TriageReport {
        schema_version: "1.0".to_string(),
        summary,
        findings,
    }
}

fn classify(
    finding: &SarifFinding,
    cwe: &str,
    routes: &BTreeMap<(String, String), RouteInfo>,
    known_cwes: &BTreeSet<String>,
) -> Decision {
    let Some(path) = finding.endpoint.as_deref() else {
        return classify_without_route(cwe);
    };
    let Some(method) = finding.method.as_deref() else {
        return classify_without_route(cwe);
    };

    let route = routes.get(&(path.to_string(), method.to_string()));
    if finding.auth_required || route.map(|route| route.auth_required).unwrap_or(false) {
        return Decision {
            classification: "needs-human-input",
            confidence: "auth-required",
            recommended_zap_policy: None,
            recommended_action: "Configure zaprun auth and prove logged-in reachability before guided DAST validation".to_string(),
            rationale: "auth required; the tuner will not mark this DAST-detectable until auth mode and logged-in verification are configured".to_string(),
        };
    }

    if route.is_none() {
        return Decision {
            classification: "needs-human-input",
            confidence: "endpoint-method-provided",
            recommended_zap_policy: None,
            recommended_action:
                "Confirm the endpoint exists in route/OpenAPI inventory before guided scanning"
                    .to_string(),
            rationale:
                "endpoint/method was provided by SARIF but the route inventory did not confirm it"
                    .to_string(),
        };
    }

    if !known_cwes.contains(cwe) {
        return Decision {
            classification: "dast-partial",
            confidence: "route-confirmed",
            recommended_zap_policy: None,
            recommended_action: "Review whether a generic ZAP rule, observe replay, or target-owned custom rule is needed".to_string(),
            rationale: format!("{cwe} has route evidence, but no generic ZAP policy mapping is available"),
        };
    }

    Decision {
        classification: "dast-detectable",
        confidence: "route-confirmed",
        recommended_zap_policy: Some(policy_for_cwe(cwe)),
        recommended_action: "Run zaprun observe with a concrete HTTP request, then run the guided zaprun scan lane for this endpoint x CWE".to_string(),
        rationale: format!("{cwe} has SARIF CWE evidence, a confirmed route, and a generic ZAP policy mapping"),
    }
}

fn classify_without_route(cwe: &str) -> Decision {
    if cwe == "CWE-918" {
        return Decision {
            classification: "needs-human-input",
            confidence: "no-route-evidence",
            recommended_zap_policy: None,
            recommended_action: "Provide a raw HTTP request or staging URL that proves the SSRF sink is reachable before tuning DAST".to_string(),
            rationale: "CWE-918 requires a concrete live request or reachable route before zaprun can validate it dynamically".to_string(),
        };
    }
    Decision {
        classification: "dast-not-applicable",
        confidence: "no-route-evidence",
        recommended_zap_policy: None,
        recommended_action:
            "Keep as SAST-only evidence unless route/request reachability is later provided"
                .to_string(),
        rationale:
            "no HTTP route or request evidence links this SARIF result to a DAST-reachable surface"
                .to_string(),
    }
}

fn bump_summary(summary: &mut TriageSummary, finding: &TriageFinding) {
    match finding.classification.as_str() {
        "dast-detectable" => summary.dast_detectable += 1,
        "dast-partial" => summary.dast_partial += 1,
        "dast-not-applicable" => summary.dast_not_applicable += 1,
        "needs-human-input" => summary.needs_human_input += 1,
        _ => {}
    }
    if finding.validated_by_zap {
        summary.zap_validated += 1;
    }
}

fn build_guided_map(report: &TriageReport) -> GuidedScanMap {
    let targets = report
        .findings
        .iter()
        .filter(|finding| finding.classification == "dast-detectable")
        .filter_map(|finding| {
            Some(GuidedTarget {
                path: finding.path.clone()?,
                method: finding.method.clone()?,
                cwe: finding.cwe.clone(),
                sarif_result_fingerprint: finding.sarif_result_fingerprint.clone(),
                zap_policy: finding.recommended_zap_policy.clone()?,
                confidence: finding.confidence.clone(),
            })
        })
        .collect();

    GuidedScanMap {
        schema_version: "1.0".to_string(),
        mode: "guided-pr".to_string(),
        targets,
    }
}

fn build_filtered_sarif(sarif: &SarifDocument) -> JsonValue {
    let validated = sarif
        .findings
        .iter()
        .filter(|finding| finding.zap_validated)
        .map(|finding| (finding.run_index, finding.result_index))
        .collect::<BTreeSet<_>>();
    let mut filtered = sarif.original.clone();
    let Some(runs) = filtered.get_mut("runs").and_then(JsonValue::as_array_mut) else {
        return filtered;
    };

    for (run_index, run) in runs.iter_mut().enumerate() {
        let Some(results_value) = run.get_mut("results") else {
            continue;
        };
        let Some(results) = results_value.as_array() else {
            continue;
        };
        let retained = results
            .iter()
            .enumerate()
            .filter(|(result_index, _)| validated.contains(&(run_index, *result_index)))
            .map(|(_, result)| result.clone())
            .collect::<Vec<_>>();
        *results_value = JsonValue::Array(retained);
    }
    filtered
}

fn update_manifest_summary(
    target_root: &Path,
    report: &TriageReport,
    guided: &GuidedScanMap,
) -> Result<()> {
    let manifest_path = target_root.join(".zaprun/manifest.json");
    if !manifest_path.is_file() {
        return Ok(());
    }
    let mut manifest: Manifest = serde_json::from_str(&std::fs::read_to_string(&manifest_path)?)?;
    manifest.findings_summary = Some(FindingsSummary {
        total: report.summary.total,
        dast_detectable: report.summary.dast_detectable,
        dast_now_covered: guided.targets.len(),
        dast_not_applicable: report.summary.dast_not_applicable,
    });
    manifest.validate()?;
    safe_write(
        target_root,
        Path::new(".zaprun/manifest.json"),
        serde_json::to_vec_pretty(&manifest)?.as_slice(),
    )?;
    Ok(())
}

fn load_known_zap_cwes() -> Result<BTreeSet<String>> {
    let doc: CweRuleMappingDocument = toml::from_str(CWE_TO_RULES)?;
    doc.validate(Default::default())?;
    Ok(doc
        .mappings
        .into_iter()
        .filter(|mapping| !mapping.zap_rules.is_empty())
        .map(|mapping| mapping.cwe)
        .collect())
}

fn load_route_inventory(target_root: &Path) -> Result<BTreeMap<(String, String), RouteInfo>> {
    let Some(openapi_path) = find_openapi(target_root) else {
        return Ok(BTreeMap::new());
    };
    let text = std::fs::read_to_string(openapi_path)?;
    let value: YamlValue = serde_yaml_ng::from_str(&text)?;
    let global_auth = mapping_get(&value, "security")
        .and_then(YamlValue::as_sequence)
        .map(|security| !security.is_empty())
        .unwrap_or(false);
    let Some(paths) = mapping_get(&value, "paths").and_then(YamlValue::as_mapping) else {
        return Ok(BTreeMap::new());
    };

    let mut routes = BTreeMap::new();
    for (path_key, path_value) in paths {
        let Some(path) = path_key.as_str() else {
            continue;
        };
        let path_auth = mapping_get(path_value, "security")
            .and_then(YamlValue::as_sequence)
            .map(|security| !security.is_empty())
            .unwrap_or(false);
        let Some(methods) = path_value.as_mapping() else {
            continue;
        };
        for (method_key, operation) in methods {
            let Some(method) = method_key.as_str() else {
                continue;
            };
            if !is_http_method(method) {
                continue;
            }
            let auth_required = mapping_get(operation, "security")
                .and_then(YamlValue::as_sequence)
                .map(|security| !security.is_empty())
                .unwrap_or(path_auth || global_auth);
            routes.insert(
                (path.to_string(), method.to_ascii_uppercase()),
                RouteInfo { auth_required },
            );
        }
    }
    Ok(routes)
}

fn mapping_get<'a>(value: &'a YamlValue, key: &str) -> Option<&'a YamlValue> {
    value.as_mapping()?.get(YamlValue::String(key.to_string()))
}

fn is_http_method(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "get" | "post" | "put" | "patch" | "delete" | "head" | "options" | "trace"
    )
}

fn find_openapi(root: &Path) -> Option<PathBuf> {
    ["openapi.yaml", "openapi.yml", "openapi.json"]
        .iter()
        .map(|name| root.join(name))
        .find(|path| path.is_file())
}

fn render_source_location(finding: &SarifFinding) -> Option<String> {
    let uri = finding.location_uri.as_deref()?;
    match finding.location_line {
        Some(line) => Some(format!("{uri}:{line}")),
        None => Some(uri.to_string()),
    }
}

fn policy_for_cwe(cwe: &str) -> String {
    format!("policy-{cwe}")
}
