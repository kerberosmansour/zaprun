use thiserror::Error;

#[derive(Debug, Error)]
pub enum ZapshootError {
    #[error("image_ref_not_digest: image reference must include @sha256:<64-hex>")]
    ImageRefNotDigest,
    #[error("image_ref_digest_malformed: digest portion must be exactly 64 lowercase hex chars")]
    ImageRefDigestMalformed,
    #[error("image_ref_repo_charset: repo contains characters outside the safe set")]
    ImageRefRepoCharset,
    #[error("image_ref_repo_too_long: repo length exceeds 255 chars")]
    ImageRefRepoTooLong,
    #[error("docker_not_in_path: docker binary not found in PATH")]
    DockerNotInPath,
    #[error("output_dir_not_writable: output directory cannot be created or written")]
    OutputDirNotWritable,
    #[error("target_unreachable: probe could not reach the target within the budget")]
    TargetUnreachable,
    #[error("probe_timeout: a doctor probe exceeded its per-probe budget")]
    ProbeTimeout,
    #[error("total_budget_exceeded: doctor exceeded its total wall-clock budget")]
    TotalBudgetExceeded,
    #[error("unsupported_schema_version: artifact schema version is not supported in MVP1")]
    UnsupportedSchemaVersion,
    #[error("subcommand_not_yet_implemented: this subcommand is reserved for a later milestone")]
    SubcommandNotYetImplemented,
    #[error("io: {0}")]
    Io(String),
}

impl From<std::io::Error> for ZapshootError {
    fn from(e: std::io::Error) -> Self {
        ZapshootError::Io(e.to_string())
    }
}
