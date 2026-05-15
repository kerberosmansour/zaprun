use super::{Result, TunerError};
use regex::Regex;
use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy)]
pub struct MappingBudget {
    pub zap_rules: usize,
    pub nuclei_templates: usize,
    pub custom_scripts: usize,
}

impl Default for MappingBudget {
    fn default() -> Self {
        Self {
            zap_rules: 8,
            nuclei_templates: 6,
            custom_scripts: 2,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CweRuleMappingDocument {
    #[serde(default)]
    pub mappings: Vec<CweRuleMapping>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CweRuleMapping {
    pub cwe: String,
    #[serde(default)]
    pub zap_rules: Vec<ZapRuleSelection>,
    #[serde(default)]
    pub nuclei_templates: Vec<String>,
    #[serde(default)]
    pub custom_scripts: Vec<String>,
    #[serde(default)]
    pub sqlmap_profile: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZapRuleSelection {
    pub id: String,
    pub level: RuleLevel,
    pub surface: RuleSurface,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub wstg_ref: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum RuleLevel {
    Fail,
    Warn,
    Ignore,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RuleSurface {
    Both,
    Api,
    Web,
}

impl CweRuleMappingDocument {
    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)?;
        let doc: Self = toml::from_str(&text)?;
        doc.validate(MappingBudget::default())?;
        Ok(doc)
    }

    pub fn validate(&self, budget: MappingBudget) -> Result<()> {
        let cwe_re = Regex::new(r"^CWE-\d+$")
            .map_err(|err| TunerError::Validation(format!("internal cwe regex failed: {err}")))?;
        let zap_re = Regex::new(r"^\d+$")
            .map_err(|err| TunerError::Validation(format!("internal zap regex failed: {err}")))?;

        for mapping in &self.mappings {
            if !cwe_re.is_match(&mapping.cwe) {
                return Err(TunerError::Validation(format!(
                    "{} must match ^CWE-\\d+$",
                    mapping.cwe
                )));
            }
            if mapping.zap_rules.len() > budget.zap_rules {
                return Err(TunerError::Validation(format!(
                    "{}: {} ZAP rules exceeds budget {}",
                    mapping.cwe,
                    mapping.zap_rules.len(),
                    budget.zap_rules
                )));
            }
            if mapping.nuclei_templates.len() > budget.nuclei_templates {
                return Err(TunerError::Validation(format!(
                    "{}: {} Nuclei templates exceeds budget {}",
                    mapping.cwe,
                    mapping.nuclei_templates.len(),
                    budget.nuclei_templates
                )));
            }
            if mapping.custom_scripts.len() > budget.custom_scripts {
                return Err(TunerError::Validation(format!(
                    "{}: {} custom scripts exceeds budget {}",
                    mapping.cwe,
                    mapping.custom_scripts.len(),
                    budget.custom_scripts
                )));
            }
            for zap_rule in &mapping.zap_rules {
                if !zap_re.is_match(&zap_rule.id) {
                    return Err(TunerError::Validation(format!(
                        "{} has invalid ZAP rule id {}",
                        mapping.cwe, zap_rule.id
                    )));
                }
            }
        }
        Ok(())
    }
}
