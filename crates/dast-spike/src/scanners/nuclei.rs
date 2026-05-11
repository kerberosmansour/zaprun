use crate::report::normalize::{parse_nuclei_report, NormalizedReport};
use crate::scan::run_command_with_timeout;
use crate::scanner::{Policy, ScanError, Scanner, Target};
use crate::types::Surface;
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct NucleiScanner {
    pub output_dir: PathBuf,
    pub pin_file: PathBuf,
}

impl Scanner for NucleiScanner {
    fn name(&self) -> &'static str {
        "nuclei"
    }

    fn supported_cwes(&self) -> &[&'static str] {
        &[
            "CWE-22", "CWE-79", "CWE-89", "CWE-200", "CWE-287", "CWE-352", "CWE-601", "CWE-918",
        ]
    }

    fn supported_surfaces(&self) -> &[Surface] {
        &[Surface::WebMpa, Surface::WebSpa, Surface::ApiOpenapi]
    }

    fn run(&self, target: &Target, policy: &Policy) -> Result<NormalizedReport, ScanError> {
        validate_nuclei_pin(&self.pin_file)?;
        fs::create_dir_all(&self.output_dir).map_err(|err| ScanError::Runtime(err.to_string()))?;
        let output = self.output_dir.join("nuclei-report.json");
        let mut command = Command::new("nuclei");
        command
            .arg("-target")
            .arg(&target.url)
            .arg("-jsonl")
            .arg("-o")
            .arg(&output);
        let status = run_command_with_timeout(&mut command, policy.timeout).map_err(|err| {
            if err.kind() == std::io::ErrorKind::TimedOut {
                ScanError::Timeout {
                    seconds: policy.timeout.as_secs(),
                }
            } else {
                ScanError::Runtime(format!("failed to run nuclei: {err}"))
            }
        })?;
        if !status.success() {
            return Err(ScanError::Runtime(format!(
                "nuclei exited with status {status}"
            )));
        }
        let text =
            fs::read_to_string(&output).map_err(|err| ScanError::Runtime(err.to_string()))?;
        parse_nuclei_report(&text).map_err(|err| ScanError::Runtime(err.to_string()))
    }
}

pub fn validate_nuclei_pin(path: &Path) -> Result<String, ScanError> {
    let text = fs::read_to_string(path).map_err(|err| ScanError::Runtime(err.to_string()))?;
    let value: toml::Value =
        toml::from_str(&text).map_err(|err| ScanError::Runtime(err.to_string()))?;
    let sha = value
        .get("commit_sha")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| ScanError::Runtime("nuclei templates commit_sha is missing".to_string()))?;
    let re = Regex::new(r"^[0-9a-f]{40}$")
        .map_err(|err| ScanError::Runtime(format!("internal sha regex failed: {err}")))?;
    if !re.is_match(sha) {
        return Err(ScanError::Runtime(
            "nuclei templates commit_sha must be 40 hex chars".to_string(),
        ));
    }
    Ok(sha.to_string())
}
