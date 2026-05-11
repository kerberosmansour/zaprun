use crate::error::ZapshootError;

/// Stable exit-code contract for the zaprun CLI.  These values are part of the
/// public interface and MUST NOT change in MVP1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    /// scan completed and policy gate passed
    Pass = 0,
    /// scan completed and policy gate failed
    PolicyFail = 1,
    /// tool or environment error
    ToolError = 2,
    /// target unavailable or scan could not start
    TargetUnavailable = 3,
    /// timeout or resource budget exceeded
    Timeout = 4,
    /// coverage contract failed
    CoverageFail = 5,
}

impl From<&ZapshootError> for ExitCode {
    fn from(err: &ZapshootError) -> Self {
        match err {
            // Configuration / input -> tool error
            ZapshootError::ImageRefNotDigest
            | ZapshootError::ImageRefDigestMalformed
            | ZapshootError::ImageRefRepoCharset
            | ZapshootError::ImageRefRepoTooLong
            | ZapshootError::DockerNotInPath
            | ZapshootError::OutputDirNotWritable
            | ZapshootError::UnsupportedSchemaVersion
            | ZapshootError::SubcommandNotYetImplemented
            | ZapshootError::Io(_) => ExitCode::ToolError,
            // Target side
            ZapshootError::TargetUnreachable => ExitCode::TargetUnavailable,
            // Time / resource bounds
            ZapshootError::ProbeTimeout | ZapshootError::TotalBudgetExceeded => ExitCode::Timeout,
        }
    }
}
