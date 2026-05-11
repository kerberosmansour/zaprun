use crate::{Result, RulesError};
use regex::Regex;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct ActionShas {
    pub actions: BTreeMap<String, String>,
}

pub fn load_action_shas(path: &Path) -> Result<ActionShas> {
    let text = fs::read_to_string(path)?;
    let pins: ActionShas = toml::from_str(&text)?;
    validate_action_shas(&pins)?;
    Ok(pins)
}

pub fn validate_action_shas(pins: &ActionShas) -> Result<()> {
    let re = Regex::new(r"^[0-9a-f]{40}$")
        .map_err(|err| RulesError::Validation(format!("internal sha regex failed: {err}")))?;
    for (name, sha) in &pins.actions {
        if !re.is_match(sha) {
            return Err(RulesError::Validation(format!(
                "action pin {name} must be a 40-character SHA"
            )));
        }
    }
    Ok(())
}

pub fn render_template(template: &str, pins: &ActionShas, image_digest: &str) -> Result<String> {
    let digest_re = Regex::new(r"^sha256:[0-9a-f]{64}$").map_err(|err| {
        RulesError::Validation(format!("internal digest regex failed to compile: {err}"))
    })?;
    if !digest_re.is_match(image_digest) {
        return Err(RulesError::Validation(
            "image digest must match ^sha256:[0-9a-f]{64}$".to_string(),
        ));
    }

    let mut rendered = template.replace("{{DAST_SPIKE_IMAGE_DIGEST}}", image_digest);
    for (name, sha) in &pins.actions {
        let placeholder = format!(
            "{{{{{}_SHA}}}}",
            name.to_ascii_uppercase().replace('-', "_")
        );
        rendered = rendered.replace(&placeholder, sha);
    }
    if rendered.contains("{{") {
        return Err(RulesError::Validation(
            "workflow template contains unresolved placeholders".to_string(),
        ));
    }
    Ok(rendered)
}
