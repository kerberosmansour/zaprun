use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum DastSpikeError {
    #[error("{0}")]
    Usage(String),
    #[error("{0}")]
    Gate(String),
    #[error("{0}")]
    Scanner(String),
    #[error("{0}")]
    FilesystemSafety(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yaml_ng::Error),
    #[error("toml error: {0}")]
    TomlDe(#[from] toml::de::Error),
    #[error("rules error: {0}")]
    Rules(#[from] dast_spike_rules::RulesError),
    #[error("regex error: {0}")]
    Regex(#[from] regex::Error),
    #[error("missing file: {0}")]
    MissingFile(PathBuf),
}

pub type Result<T> = std::result::Result<T, DastSpikeError>;

impl DastSpikeError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Gate(_) => 1,
            Self::Usage(_) | Self::Json(_) | Self::Yaml(_) | Self::TomlDe(_) | Self::Regex(_) => 2,
            Self::Scanner(_) => 3,
            Self::FilesystemSafety(_) => 4,
            Self::Io(_) | Self::Rules(_) | Self::MissingFile(_) => {
                if self.to_string().contains("symlink") {
                    4
                } else if self.to_string().contains("digest")
                    || self.to_string().contains("schema")
                    || self.to_string().contains("baseline")
                {
                    2
                } else {
                    3
                }
            }
        }
    }
}
