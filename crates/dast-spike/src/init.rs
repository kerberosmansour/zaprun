use crate::cli::InitArgs;
use crate::image_pin::ZapImagePin;
use crate::types::ImageRef;
use crate::{DastSpikeError, Result};
use chrono::Utc;
use dast_spike_rules::cwe_to_rules::{RuleLevel, RuleSurface};
use dast_spike_rules::manifest::SelectedRule;
use dast_spike_rules::{safe_write, BaselineDocument, CweRuleMappingDocument, Manifest};
use regex::Regex;
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

const POLICY_PR: &str = include_str!("../../../docker/zap/policies/policy-pr.yml");
const POLICY_NIGHTLY: &str = include_str!("../../../docker/zap/policies/policy-nightly.yml");
const CWE_TO_RULES: &str = include_str!("../../../references/dast-tuner/cwe-to-rules.toml");
const ZAP_IMAGE_PIN: &str = include_str!("../../../references/zap-image-pin.toml");
const DEFAULT_TARGET: &str = "http://host.docker.internal:3001";
const DEFAULT_IMAGE_REPO: &str = "ghcr.io/kerberosmansour/zaprun";

#[derive(Debug, Clone)]
pub struct InitOutcome {
    pub manifest: Manifest,
    pub target_root: PathBuf,
}

#[derive(Debug, Clone)]
struct InitPlan {
    target_root: PathBuf,
    openapi_path: Option<PathBuf>,
    deployment_target: String,
    image_ref: ImageRef,
    image_full_ref: String,
    upstream_digest: String,
    threat_model_sha: Option<String>,
    cwes_claimed: Vec<String>,
    detected_stack: Vec<String>,
    detected_surface: String,
}

pub fn run(args: InitArgs) -> Result<()> {
    let outcome = run_inner(&args)?;
    if outcome.manifest.selection_strategy == "default-fallback" {
        eprintln!("zaprun: default-fallback rule selection");
    }
    println!(
        "zaprun: initialized DAST config in {}",
        outcome.target_root.display()
    );
    Ok(())
}

pub fn run_inner(args: &InitArgs) -> Result<InitOutcome> {
    let plan = build_plan(args)?;
    emit(&plan)
}

fn build_plan(args: &InitArgs) -> Result<InitPlan> {
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

    let openapi_path = find_openapi(&target_root);
    let deployment_target = args
        .deployment_target
        .clone()
        .unwrap_or_else(|| DEFAULT_TARGET.to_string());
    validate_target_url(&deployment_target)?;

    let pin: ZapImagePin = toml::from_str(ZAP_IMAGE_PIN)?;
    pin.validate()?;
    let image_ref = if let Some(image) = args.image.as_deref() {
        ImageRef::try_from(image).map_err(DastSpikeError::Usage)?
    } else {
        ImageRef::from_digest(pin.our_digest()?)
    };
    let image_full_ref = image_ref.full_ref(DEFAULT_IMAGE_REPO);
    let upstream_digest = pin.upstream_digest()?.to_string();

    let threat_model_path = find_threat_model(&target_root);
    let (threat_model_sha, cwes_claimed) = if let Some(path) = &threat_model_path {
        (Some(hash_file(path)?), parse_cwes_from_threat_model(path)?)
    } else {
        (None, Vec::new())
    };

    let detected_stack = detect_stack(&target_root);
    let detected_surface = if openapi_path.is_some() {
        "api-openapi".to_string()
    } else {
        "web-mpa".to_string()
    };

    Ok(InitPlan {
        target_root,
        openapi_path,
        deployment_target,
        image_ref,
        image_full_ref,
        upstream_digest,
        threat_model_sha,
        cwes_claimed,
        detected_stack,
        detected_surface,
    })
}

fn emit(plan: &InitPlan) -> Result<InitOutcome> {
    safe_write(
        &plan.target_root,
        Path::new(".zaprun/policy-pr.yml"),
        POLICY_PR.as_bytes(),
    )?;
    safe_write(
        &plan.target_root,
        Path::new(".zaprun/policy-nightly.yml"),
        POLICY_NIGHTLY.as_bytes(),
    )?;
    safe_write(
        &plan.target_root,
        Path::new(".zaprun/baseline.json"),
        serde_json::to_vec_pretty(&BaselineDocument::empty())?.as_slice(),
    )?;

    let mappings = selected_mappings(&plan.cwes_claimed)?;
    let rules_tsv = render_rules_tsv(&mappings);
    safe_write(
        &plan.target_root,
        Path::new(".zaprun/rules.tsv"),
        rules_tsv.as_bytes(),
    )?;

    let workflow = render_workflow(plan);
    safe_write(
        &plan.target_root,
        Path::new(".github/workflows/dast.yml"),
        workflow.as_bytes(),
    )?;

    let manifest = build_manifest(plan, &mappings)?;
    safe_write(
        &plan.target_root,
        Path::new(".zaprun/manifest.json"),
        serde_json::to_vec_pretty(&manifest)?.as_slice(),
    )?;

    Ok(InitOutcome {
        manifest,
        target_root: plan.target_root.clone(),
    })
}

fn build_manifest(plan: &InitPlan, mappings: &[SelectedMapping]) -> Result<Manifest> {
    let cwes_actually_covered = mappings
        .iter()
        .map(|mapping| mapping.cwe.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let covered_set = cwes_actually_covered.iter().collect::<BTreeSet<_>>();
    let cwes_uncovered = plan
        .cwes_claimed
        .iter()
        .filter(|cwe| !covered_set.contains(cwe))
        .cloned()
        .collect::<Vec<_>>();
    let selected_rules = mappings
        .iter()
        .flat_map(|mapping| {
            mapping.zap_rules.iter().map(|rule| SelectedRule {
                id: rule.id.clone(),
                source: "zap".to_string(),
                level: level_as_str(&rule.level).to_string(),
                metadata_cwe: vec![mapping.cwe.clone()],
                script_path: None,
            })
        })
        .collect::<Vec<_>>();

    let mut manifest = Manifest {
        schema: "https://github.com/kerberosmansour/zaprun/blob/main/schema/manifest-v1.json"
            .to_string(),
        schema_version: "1.0".to_string(),
        generated_at: Utc::now().to_rfc3339(),
        generated_by_zaprun_version: env!("CARGO_PKG_VERSION").to_string(),
        image_digest: plan.image_ref.digest().to_string(),
        upstream_image_digest: plan.upstream_digest.clone(),
        threat_model_sha: plan.threat_model_sha.clone(),
        cwes_claimed: plan.cwes_claimed.clone(),
        cwes_actually_covered,
        cwes_uncovered,
        coverage_gaps: Vec::new(),
        detected_stack: plan.detected_stack.clone(),
        detected_surface: plan.detected_surface.clone(),
        detected_auth: "unknown".to_string(),
        selected_scanners: vec!["zap".to_string()],
        selected_rules,
        selection_strategy: if plan.cwes_claimed.is_empty() {
            "default-fallback".to_string()
        } else {
            "threat-model-cwe".to_string()
        },
        findings_summary: Some(Default::default()),
        baseline_summary: Some(Default::default()),
    };
    if manifest.detected_stack.is_empty() {
        manifest.detected_stack.push("unknown".to_string());
    }
    manifest.validate()?;
    Ok(manifest)
}

#[derive(Debug, Clone)]
struct SelectedMapping {
    cwe: String,
    zap_rules: Vec<SelectedZapRule>,
}

#[derive(Debug, Clone)]
struct SelectedZapRule {
    id: String,
    level: RuleLevel,
}

fn selected_mappings(cwes_claimed: &[String]) -> Result<Vec<SelectedMapping>> {
    let doc: CweRuleMappingDocument = toml::from_str(CWE_TO_RULES)?;
    doc.validate(Default::default())?;
    let wanted = if cwes_claimed.is_empty() {
        ["CWE-79", "CWE-89"]
            .iter()
            .map(|s| s.to_string())
            .collect::<BTreeSet<_>>()
    } else {
        cwes_claimed.iter().cloned().collect::<BTreeSet<_>>()
    };

    let mut selected = Vec::new();
    for mapping in doc.mappings {
        if !wanted.contains(&mapping.cwe) {
            continue;
        }
        let zap_rules = mapping
            .zap_rules
            .into_iter()
            .filter(|rule| {
                matches!(
                    rule.surface,
                    RuleSurface::Both | RuleSurface::Api | RuleSurface::Web
                )
            })
            .map(|rule| SelectedZapRule {
                id: rule.id,
                level: rule.level,
            })
            .collect::<Vec<_>>();
        selected.push(SelectedMapping {
            cwe: mapping.cwe,
            zap_rules,
        });
    }
    Ok(selected)
}

fn render_rules_tsv(mappings: &[SelectedMapping]) -> String {
    let mut out = String::from("# scanner\tplugin_id\tlevel\tcwe\n");
    for mapping in mappings {
        for rule in &mapping.zap_rules {
            out.push_str(&format!(
                "zap\t{}\t{}\t{}\n",
                rule.id,
                level_as_str(&rule.level),
                mapping.cwe
            ));
        }
    }
    out
}

fn render_workflow(plan: &InitPlan) -> String {
    let zaprun_command = if let Some(spec) = &plan.openapi_path {
        let spec_name = spec
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("openapi.yaml");
        format!(
            "zaprun api /work/{spec_name} --target {} --active --output /zap/wrk/output",
            plan.deployment_target
        )
    } else {
        format!(
            "zaprun scan {} --active --profile web-pr --output /zap/wrk/output",
            plan.deployment_target
        )
    };
    format!(
        r#"name: zaprun DAST

on:
  pull_request:
  workflow_dispatch:

permissions: {{}}

concurrency:
  group: ${{{{ github.workflow }}}}-${{{{ github.ref }}}}
  cancel-in-progress: true

jobs:
  dast:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    permissions:
      contents: read
    steps:
      - name: Checkout
        uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd
        with:
          fetch-depth: 0
          persist-credentials: false
      - name: Run DAST
        run: |
          mkdir -p output
          docker run --rm --user 1000:1000 \
            --add-host=host.docker.internal:host-gateway \
            -v "$PWD:/work:ro" \
            -v "$PWD/output:/zap/wrk/output:rw" \
            {} \
            {}
      - name: Upload ZAP report
        if: always()
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
        with:
          name: zaprun-report
          path: output/
          retention-days: 30
"#,
        plan.image_full_ref, zaprun_command
    )
}

fn find_openapi(root: &Path) -> Option<PathBuf> {
    ["openapi.yaml", "openapi.yml", "openapi.json"]
        .iter()
        .map(|name| root.join(name))
        .find(|path| path.is_file())
}

fn find_threat_model(root: &Path) -> Option<PathBuf> {
    let design_dir = root.join("docs/slo/design");
    let entries = std::fs::read_dir(design_dir).ok()?;
    let mut candidates = entries
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.ends_with("-threat-model.md"))
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    candidates.sort();
    candidates.into_iter().next()
}

fn detect_stack(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    if root.join("Cargo.toml").is_file() {
        out.push("rust".to_string());
    }
    if root.join("package.json").is_file() {
        out.push("javascript".to_string());
    }
    if root.join("requirements.txt").is_file() || root.join("pyproject.toml").is_file() {
        out.push("python".to_string());
    }
    out
}

pub fn parse_cwes_from_threat_model(path: &Path) -> Result<Vec<String>> {
    let text = std::fs::read_to_string(path)?;
    let cwe_re = Regex::new(r"\bCWE-(\d+)\b")?;
    let mut in_html_comment = false;
    let mut in_fence = false;
    let mut out = BTreeSet::<u32>::new();

    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            in_fence = !in_fence;
            continue;
        }
        let mut visible = line.to_string();
        if in_html_comment {
            if let Some((_, rest)) = visible.split_once("-->") {
                visible = rest.to_string();
                in_html_comment = false;
            } else {
                continue;
            }
        }
        while let Some((before, after_open)) = visible.split_once("<!--") {
            let after_open = after_open.to_string();
            visible = before.to_string();
            if let Some((_, after_close)) = after_open.split_once("-->") {
                visible.push_str(after_close);
            } else {
                in_html_comment = true;
                break;
            }
        }
        if in_fence || in_html_comment {
            continue;
        }
        for cap in cwe_re.captures_iter(&visible) {
            if let Ok(id) = cap[1].parse::<u32>() {
                out.insert(id);
            }
        }
    }
    Ok(out.into_iter().map(|id| format!("CWE-{id}")).collect())
}

pub fn hash_file(path: &Path) -> Result<String> {
    if let Ok(output) = Command::new("git").arg("hash-object").arg(path).output() {
        if output.status.success() {
            let sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if sha.len() == 40 && sha.chars().all(|ch| ch.is_ascii_hexdigit()) {
                return Ok(sha);
            }
        }
    }
    let text = std::fs::read(path)?;
    Ok(fallback_hash_40(&text))
}

fn fallback_hash_40(bytes: &[u8]) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut h1 = DefaultHasher::new();
    bytes.hash(&mut h1);
    let a = h1.finish();
    let mut h2 = DefaultHasher::new();
    bytes.len().hash(&mut h2);
    bytes
        .iter()
        .rev()
        .take(32)
        .collect::<Vec<_>>()
        .hash(&mut h2);
    let b = h2.finish();
    format!("{a:016x}{b:016x}{:08x}", bytes.len() as u32)
}

fn validate_target_url(url: &str) -> Result<()> {
    let valid = (url.starts_with("http://") || url.starts_with("https://"))
        && !url.chars().any(|ch| matches!(ch, '\n' | '\r' | '\t'));
    if valid {
        Ok(())
    } else {
        Err(DastSpikeError::Usage(
            "deployment-target must be an http(s) URL without control characters".to_string(),
        ))
    }
}

fn level_as_str(level: &RuleLevel) -> &'static str {
    match level {
        RuleLevel::Fail => "FAIL",
        RuleLevel::Warn => "WARN",
        RuleLevel::Ignore => "IGNORE",
    }
}

#[derive(Debug, Serialize)]
pub struct ReDeriveSnapshot {
    pub threat_model_sha: Option<String>,
    pub cwes_claimed: Vec<String>,
    pub image_digest: String,
}

pub fn current_snapshot(target_root: &Path) -> Result<ReDeriveSnapshot> {
    let args = InitArgs {
        target_dir: target_root.to_path_buf(),
        deployment_target: None,
        image: None,
    };
    let plan = build_plan(&args)?;
    Ok(ReDeriveSnapshot {
        threat_model_sha: plan.threat_model_sha,
        cwes_claimed: plan.cwes_claimed,
        image_digest: plan.image_ref.digest().to_string(),
    })
}
