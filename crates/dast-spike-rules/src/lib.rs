pub mod baseline_schema;
pub mod cwe_to_rules;
pub mod manifest;
pub mod path_safety;
pub mod workflow_template;

pub use baseline_schema::{
    BaselineDocument, BaselineSummary, Suppression, SuppressionScope, BASELINE_HARD_LIMIT,
};
pub use cwe_to_rules::{CweRuleMappingDocument, MappingBudget};
pub use manifest::Manifest;
pub use path_safety::{safe_write, validate_path_for_write};

#[derive(Debug, thiserror::Error)]
pub enum RulesError {
    #[error("{0}")]
    Validation(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("toml error: {0}")]
    TomlDe(#[from] toml::de::Error),
    #[error("toml serialize error: {0}")]
    TomlSer(#[from] toml::ser::Error),
}

pub type Result<T> = std::result::Result<T, RulesError>;
