use crate::cli::{InitArgs, ReDeriveArgs};
use crate::init::{current_snapshot, run_inner, ReDeriveSnapshot};
use crate::{DastSpikeError, Result};
use dast_spike_rules::Manifest;
use std::path::Path;
use std::process::Command;

pub fn run(args: ReDeriveArgs) -> Result<()> {
    let target_root = args
        .target_dir
        .canonicalize()
        .map_err(|err| DastSpikeError::Usage(format!("target-dir not found: {err}")))?;
    let manifest_path = target_root.join(".zaprun/manifest.json");
    let manifest: Manifest = serde_json::from_str(&std::fs::read_to_string(&manifest_path)?)?;
    let snapshot = current_snapshot(&target_root)?;
    let drift = detect_drift(&manifest, &snapshot);
    if drift.is_empty() {
        eprintln!("zaprun: no drift detected");
        return Ok(());
    }

    let init_args = InitArgs {
        target_dir: target_root.clone(),
        deployment_target: None,
        image: None,
    };
    run_inner(&init_args)?;
    open_rederive_pr(&target_root, &drift)?;
    Ok(())
}

fn detect_drift(manifest: &Manifest, snapshot: &ReDeriveSnapshot) -> Vec<String> {
    let mut drift = Vec::new();
    if manifest.threat_model_sha != snapshot.threat_model_sha {
        drift.push("threat model changed".to_string());
    }
    if manifest.cwes_claimed != snapshot.cwes_claimed {
        drift.push("CWEs claimed changed".to_string());
    }
    if manifest.image_digest != snapshot.image_digest {
        drift.push("zaprun image digest changed".to_string());
    }
    drift
}

fn open_rederive_pr(target_root: &Path, drift: &[String]) -> Result<()> {
    let title = "[zaprun] re-derive DAST config";
    let body = format!(
        "Re-derived DAST config from zaprun-dast-tuner M1.\n\nDrift detected:\n{}\n",
        drift
            .iter()
            .map(|item| format!("- {item}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    let status = Command::new("gh")
        .current_dir(target_root)
        .arg("pr")
        .arg("create")
        .arg("--title")
        .arg(title)
        .arg("--body")
        .arg(body)
        .status()
        .map_err(|err| DastSpikeError::Usage(format!("failed to run gh: {err}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(DastSpikeError::Usage(format!(
            "gh pr create failed with status {status}"
        )))
    }
}
