pub mod baseline_schema;
pub mod cwe_to_rules;
pub mod manifest;
pub mod path_safety;
pub mod sarif;

pub use baseline_schema::BaselineDocument;
pub use cwe_to_rules::CweRuleMappingDocument;
pub use manifest::Manifest;
pub use path_safety::{safe_write, validate_path_for_write};

use std::path::PathBuf;

use crate::error::ZapshootError;

#[derive(Debug, thiserror::Error)]
pub enum TunerError {
    #[error("{0}")]
    Validation(String),
    #[error("{0}")]
    Usage(String),
    #[error("missing file: {0}")]
    MissingFile(PathBuf),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yaml_ng::Error),
    #[error("toml error: {0}")]
    TomlDe(#[from] toml::de::Error),
    #[error("regex error: {0}")]
    Regex(#[from] regex::Error),
}

pub type Result<T> = std::result::Result<T, TunerError>;

impl From<TunerError> for ZapshootError {
    fn from(err: TunerError) -> Self {
        ZapshootError::Io(err.to_string())
    }
}
